"""
reachability.py — the Phase-3 reachability gate (Slice 4).

A declarative attack path declares where the attacker STARTS (`initial_access`)
and what they want to ACHIEVE (`objective`). Between those two ends sits a graph
of generic primitives (ownership, group membership, Azure RBAC, planted
credentials, ...). This module answers one question per path:

    starting from initial_access, can the attacker actually REACH the objective
    by traversing the edges this lab deploys?

If yes, the build proceeds (and, when the author didn't write `steps:`, we hand
back an ordered list of hops derived from the walk). If no, the path is rejected
BEFORE `terraform apply` so we never deploy a lab whose advertised attack path is
a dead end.

How "reach" is modelled
-----------------------
We compute a CONTROL set by fixpoint: the identities (and compute resources) the
attacker comes to control, seeded with the initial-access principal. Edges that
grow the set:
  - app / group OWNERSHIP and group MEMBERSHIP -> you wield that principal's grants
  - an Azure RBAC role that confers CODE EXECUTION on a compute resource -> you
    control that resource, and therefore its managed identity
  - a planted credential (`data_inject`) sitting in a data resource you can READ ->
    you loot it and control the app it belongs to (the classic KV-secret theft hop)

The OBJECTIVE is a `(capability, target)` predicate evaluated against the final
CONTROL set (see capabilities.py). "Become Global Administrator" = a controlled
principal holds that Entra role; "code execution on vm01" = vm01 is controlled;
"read secrets from kv01" = a controlled principal can read kv01. An objective has
MULTIPLE ways to be satisfied and the walk can reach the satisfying node by many
paths — both fall out of "is the predicate true over the reachable set", not "did
we hit one named node".

Bypass
------
To deploy WITHOUT this gate while iterating on a technique whose graph semantics
aren't modelled yet, either set the env var BADZURE_SKIP_REACHABILITY=1, flip
`ENFORCE_REACHABILITY` below to False, or comment out the single `enforce(...)`
call in scenario_loader.load. Analysis (and step derivation) still runs; only the
hard failure is suppressed.

This module is READ-ONLY over the model: it inspects primitives, never mutates
them. It deliberately holds no Terraform knowledge.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from src import capabilities
from src.primitives import (
    DeploymentModel,
    AzureRbacAssignment, AppCredential, DataInject,
    GroupMembership, GroupOwnership, AppOwnership, EntraRoleAssignment, ApiPermission,
)
from src.primitive_handlers import SCOPE_RESOURCE_TO_MAP, INJECT_LOCATION_TO_MAP
from src.constants import RESOURCE_SEED_VECTORS

# Flip to False (or export BADZURE_SKIP_REACHABILITY=1) to deploy chains without
# the reachability gate. Analysis still runs and still derives steps — only the
# hard rejection is suppressed.
ENFORCE_REACHABILITY = True

# entity-map attr -> resource_type token (inverse of SCOPE_RESOURCE_TO_MAP).
_MAP_TO_RESOURCE_TYPE = {v: k for k, v in SCOPE_RESOURCE_TO_MAP.items()}

# Verdict statuses.
REACHED = "reached"          # objective is provably reachable
BLOCKED = "blocked"          # objective declared but NOT reachable -> fail
UNVERIFIED = "unverified"    # objective not machine-checkable -> pass with a note
INVALID = "invalid"          # objective malformed (e.g. missing target) -> fail


class ReachabilityError(ValueError):
    """Raised by enforce() when one or more declared objectives are unreachable."""


@dataclass
class PathVerdict:
    name: str
    status: str
    reason: str
    terminal_node: Optional[str] = None
    derived_steps: List[Dict] = field(default_factory=list)
    # Populated only for BLOCKED verdicts: WHY the objective is unreachable, so an
    # operator (or the Adversary self-repair loop / Gatekeeper subagent) can fix the
    # chain without re-deriving the walk. Keys: `reached` (the frontier the attacker
    # actually controls), `dead_ends` (planted credentials that loot to nothing),
    # `blocked_edges` (edges toward the objective whose source is never controlled).
    diagnostics: Optional[Dict] = None

    @property
    def ok(self) -> bool:
        return self.status in (REACHED, UNVERIFIED)


@dataclass
class ReachabilityReport:
    verdicts: List[PathVerdict] = field(default_factory=list)

    def failing(self) -> List[PathVerdict]:
        return [v for v in self.verdicts if v.status in (BLOCKED, INVALID)]

    def unverified(self) -> List[PathVerdict]:
        return [v for v in self.verdicts if v.status == UNVERIFIED]


# =============================================================================
# Public API
# =============================================================================
def analyze(model: DeploymentModel, overlays: List, resolver) -> ReachabilityReport:
    """Run the reachability gate over every attack-path overlay against the full
    (mixed-origin) primitive set. Returns a report; never raises on a dead end —
    call enforce() for that."""
    analyzer = _Analyzer(model, resolver)
    return ReachabilityReport(
        verdicts=[analyzer.evaluate_path(ov) for ov in overlays]
    )


def attach_derived_steps(overlays: List, report: ReachabilityReport) -> None:
    """Fold the report back into the overlays: stamp each overlay's `reachability`
    ({status, reason}) for the operator output, and — for any path that did NOT
    author `steps:` — fill in the steps the walk derived (authored steps are left
    untouched; decision #1: derive-when-absent)."""
    by_name = {v.name: v for v in report.verdicts}
    for ov in overlays:
        v = by_name.get(ov.name)
        if not v:
            continue
        ov.reachability = {"status": v.status, "reason": v.reason}
        if v.diagnostics:
            ov.reachability["diagnostics"] = v.diagnostics
        if not ov.steps and v.derived_steps:
            ov.steps = v.derived_steps


def enforce(report: ReachabilityReport) -> None:
    """Raise ReachabilityError if any declared objective is unreachable/invalid —
    unless the gate is bypassed (env var / module flag). UNVERIFIED objectives
    never fail; they only carry a note for the operator."""
    if not _enforcing():
        return
    failing = report.failing()
    if not failing:
        return
    lines = [f"  - {v.name}: {v.reason}" for v in failing]
    raise ReachabilityError(
        "Reachability gate rejected the following attack path(s) - the objective "
        "is not reachable from initial_access through the deployed graph:\n"
        + "\n".join(lines)
        + "\n\nFix the chain, or bypass the gate (BADZURE_SKIP_REACHABILITY=1 / "
        "ENFORCE_REACHABILITY=False / comment out the enforce() call) to deploy "
        "anyway."
    )


def _enforcing() -> bool:
    if os.environ.get("BADZURE_SKIP_REACHABILITY"):
        return False
    return ENFORCE_REACHABILITY


# =============================================================================
# The analyzer
# =============================================================================
class _Analyzer:
    def __init__(self, model: DeploymentModel, resolver):
        self.model = model
        self.resolver = resolver
        self.primitives = model.primitives
        # Indexes reused across the walk.
        self.rbac = [p for p in self.primitives if isinstance(p, AzureRbacAssignment)]
        self.creds = {p.key: p for p in self.primitives if isinstance(p, AppCredential)}
        # Apps with a REGISTERED certificate credential (emits
        # azuread_application_certificate — the public key on the app registration).
        # Looting a planted .pfx only authenticates as an app if its cert is registered
        # here; without it the pfx is an orphaned file, not a working credential.
        self.cert_registered_apps = {
            p.app_ref for p in self.creds.values() if p.type == "certificate"
        }

    # -- per-path entry point -------------------------------------------------
    def evaluate_path(self, overlay) -> PathVerdict:
        objective = overlay.objective or {}
        seed = (overlay.initial_access or {}).get("principal_ref")
        name = overlay.name

        capability = objective.get("capability")
        if not capability:
            return PathVerdict(
                name, UNVERIFIED,
                "objective has no machine-checkable `capability:` - gate skipped "
                "(add one, e.g. capability: entra_role / read_secrets / "
                "code_execution, to enable validation).",
            )
        if capability not in capabilities.KNOWN_CAPABILITIES:
            return PathVerdict(
                name, UNVERIFIED,
                f"capability '{capability}' is not modelled yet in capabilities.py "
                f"- gate skipped. Known: {sorted(capabilities.KNOWN_CAPABILITIES)}.",
            )
        if not seed:
            return PathVerdict(
                name, INVALID,
                "initial_access.principal_ref is missing, so there is no start node.",
            )

        control, parent = self._reachable(seed)
        verdict = self._evaluate_objective(name, capability, objective, control)
        if verdict.status == REACHED and verdict.terminal_node is not None:
            verdict.derived_steps = self._derive_steps(
                seed, verdict.terminal_node, parent, overlay, capability, objective)
        elif verdict.status == BLOCKED:
            verdict.diagnostics = self._diagnose(seed, capability, objective, control)
        return verdict

    # -- the fixpoint walk ----------------------------------------------------
    def _reachable(self, seed: str) -> Tuple[set, Dict[str, Tuple]]:
        """Grow the CONTROL set to a fixpoint. Returns (control, parent) where
        parent[node] = (primitive, source_node) records the edge that first added
        `node` — used to reconstruct ordered steps."""
        control = {seed}
        parent: Dict[str, Tuple] = {}
        changed = True
        while changed:
            changed = False
            for p in self.primitives:
                for src, dst in self._edges(p, control):
                    if dst and dst not in control:
                        control.add(dst)
                        parent[dst] = (p, src)
                        changed = True
        return control, parent

    def _edges(self, p, control: set) -> List[Tuple[str, str]]:
        """Edges (source_node, gained_node) this primitive contributes GIVEN the
        current control set. Only edges whose source is already controlled fire."""
        if isinstance(p, AppOwnership):
            if p.principal_ref in control:
                return [(p.principal_ref, p.app_ref)]
        elif isinstance(p, (GroupOwnership, GroupMembership)):
            if p.principal_ref in control:
                return [(p.principal_ref, p.group_ref)]
        elif isinstance(p, EntraRoleAssignment):
            # Application / Cloud Application Administrator -> you can add credentials
            # to applications and authenticate as them. A directory-wide assignment
            # confers takeover of EVERY app; one scoped to a single app (scope_app_ref)
            # confers takeover of just that app. (Other Entra roles grow nothing here —
            # an `entra_role` objective is checked against the final control set.)
            if p.principal_ref in control \
                    and capabilities.entra_role_controls_apps(p.role):
                if p.scope_app_ref:
                    return [(p.principal_ref, p.scope_app_ref)]
                return [(p.principal_ref, app) for app in self.model.applications]
        elif isinstance(p, AzureRbacAssignment):
            # A control-conferring RBAC role -> you own the covered compute
            # resource(s), hence their managed identity.
            if p.principal_ref in control:
                return [(p.principal_ref, res) for res in self._controlled_resources(p)]
        elif isinstance(p, DataInject):
            # A planted credential in a data resource you can read -> loot it ->
            # control the app it belongs to. The edge source is the principal who
            # does the reading (so step derivation connects back to the seed).
            app = self._loot_app(p)
            if app:
                reader = self._reader_of(p.location_ref, self._inject_rtype(p), control)
                if reader:
                    return [(reader, app)]
        return []

    # -- diagnostics (only computed for BLOCKED paths) ------------------------
    def _diagnose(self, seed: str, capability: str, objective: Dict,
                  control: set) -> Dict:
        """Explain WHY a blocked objective is unreachable. Returns a dict with any
        of: `reached` (the control frontier), `dead_ends` (planted credentials that
        loot to nothing / sit in an unreadable resource), `blocked_edges` (edges on a
        path to the objective whose source is never controlled). Best-effort and
        read-only — it never changes the verdict, only annotates it."""
        diag: Dict = {"reached": sorted(control)}
        dead_ends = self._dead_end_injects(control)
        if dead_ends:
            diag["dead_ends"] = dead_ends

        blocked: List[str] = []
        target = objective.get("target_ref")
        if target:
            blocked.extend(self._blocked_edges_toward(target, control))
        # A read objective can also be blocked because a principal HOLDS a read role
        # on the target but was never controlled — that's not a control-set edge, so
        # surface it explicitly.
        if capability in capabilities.READ_CAPABILITY_RESOURCE and target:
            rtype = capabilities.READ_CAPABILITY_RESOURCE[capability]
            for r in self.rbac:
                if r.principal_ref not in control \
                        and capabilities.rbac_reads_resource(r.role, rtype) \
                        and self._scope_covers(r, target, rtype):
                    blocked.append(
                        f"{r.principal_ref} holds read role '{r.role}' on '{target}', "
                        f"but {r.principal_ref} is never controlled.")
        if blocked:
            diag["blocked_edges"] = blocked
        return diag

    def _dead_end_injects(self, control: set) -> List[str]:
        """Planted credentials whose loot hop cannot fire: an orphaned cert/secret
        (nothing authenticates), or a valid credential in a resource no controlled
        principal can read."""
        out: List[str] = []
        for p in self.primitives:
            if not isinstance(p, DataInject) \
                    or p.material not in ("app_secret", "app_certificate"):
                continue
            app = self._loot_app(p)
            if app is None:
                if p.material == "app_certificate":
                    intended = p.source_ref or (
                        self.creds[p.credential_ref].app_ref
                        if p.credential_ref in self.creds else None)
                    if intended:
                        out.append(
                            f"planted certificate '{p.name}' targets app "
                            f"'{intended}', but no certificate is registered on "
                            f"'{intended}' — add a `type: certificate` credential "
                            f"so the looted .pfx authenticates.")
                    else:
                        out.append(
                            f"planted certificate '{p.name}' has no resolvable "
                            f"target app (set source_ref or a valid credential_ref).")
                else:  # app_secret
                    out.append(
                        f"planted secret '{p.name}' references credential "
                        f"'{p.credential_ref}', which is not registered on any app — "
                        f"the loot yields nothing.")
            elif app not in control:
                rtype = self._inject_rtype(p)
                if self._reader_of(p.location_ref, rtype, control) is None:
                    out.append(
                        f"planted credential '{p.name}' -> '{app}' sits in "
                        f"'{p.location_ref}', which no controlled principal can read.")
        return out

    def _blocked_edges_toward(self, target: str, control: set) -> List[str]:
        """Edges (ownership / membership / RBAC-control / app-takeover) that lie on
        SOME path to `target` but whose source is never controlled — the frontier of
        why the walk stalled. Computed by backward reachability over potential edges
        (control ignored), then filtered to uncontrolled sources."""
        edges = [e for p in self.primitives for e in self._potential_edges(p)]
        can_reach = {target}
        changed = True
        while changed:
            changed = False
            for src, dst, _ in edges:
                if dst in can_reach and src not in can_reach:
                    can_reach.add(src)
                    changed = True
        out: List[str] = []
        seen = set()
        for src, dst, prim in edges:
            if dst in can_reach and src not in control and (src, dst) not in seen:
                seen.add((src, dst))
                rel = _RELATION.get(type(prim), "reaches")
                out.append(f"{src} {rel} {dst}, but {src} is never controlled.")
        return out

    def _potential_edges(self, p) -> List[Tuple[str, str, object]]:
        """Like `_edges`, but ignores the control set — the edges this primitive
        COULD contribute if its source were controlled. DataInject loot is excluded
        (its failures are reported by `_dead_end_injects`, not as a graph edge)."""
        if isinstance(p, AppOwnership):
            return [(p.principal_ref, p.app_ref, p)]
        if isinstance(p, (GroupOwnership, GroupMembership)):
            return [(p.principal_ref, p.group_ref, p)]
        if isinstance(p, EntraRoleAssignment) \
                and capabilities.entra_role_controls_apps(p.role):
            if p.scope_app_ref:
                return [(p.principal_ref, p.scope_app_ref, p)]
            return [(p.principal_ref, app, p) for app in self.model.applications]
        if isinstance(p, AzureRbacAssignment):
            return [(p.principal_ref, res, p)
                    for res in self._controlled_resources(p)]
        return []

    # -- resource-control / read helpers --------------------------------------
    def _controlled_resources(self, rbac: AzureRbacAssignment) -> List[str]:
        """Compute resources whose CONTROL `rbac` confers (code-exec roles), across
        every resource type the role grants and every resource its scope covers."""
        out: List[str] = []
        for rtype in capabilities.CONTROL_ROLES:
            if capabilities.rbac_controls_resource(rbac.role, rtype):
                out.extend(self._covered_resources(rbac, rtype))
        return out

    def _resource_readable(self, resource_ref: str, rtype: Optional[str],
                           control: set) -> bool:
        """Can the attacker read the loot out of `resource_ref`?"""
        return self._reader_of(resource_ref, rtype, control) is not None

    def _reader_of(self, resource_ref: str, rtype: Optional[str],
                   control: set) -> Optional[str]:
        """The principal through which the attacker can read `resource_ref` — the
        resource itself if controlled, else a controlled principal holding an RBAC
        read role whose scope covers it. None if unreadable."""
        if resource_ref in control:
            return resource_ref
        if not rtype:
            return None
        for r in self.rbac:
            if r.principal_ref in control \
                    and capabilities.rbac_reads_resource(r.role, rtype) \
                    and self._scope_covers(r, resource_ref, rtype):
                return r.principal_ref
        return None

    def _covered_resources(self, rbac: AzureRbacAssignment, rtype: str) -> List[str]:
        """All declared resources of `rtype` that this assignment's scope covers."""
        attr = SCOPE_RESOURCE_TO_MAP.get(rtype)
        emap = getattr(self.model, attr, {}) if attr else {}
        if rbac.scope_type == "subscription":
            return list(emap)
        if rbac.scope_type == "resource_group":
            return [k for k, v in emap.items()
                    if v.get("resource_group_name") == rbac.scope_ref]
        if rbac.scope_type == "resource":
            # scope_resource_type, when set, must match the type we're asking about.
            if rbac.scope_resource_type and rbac.scope_resource_type != rtype:
                return []
            return [rbac.scope_ref] if rbac.scope_ref in emap else []
        return []

    def _scope_covers(self, rbac: AzureRbacAssignment, resource_ref: str,
                      rtype: str) -> bool:
        if rbac.scope_type == "subscription":
            return True
        if rbac.scope_type == "resource":
            return rbac.scope_ref == resource_ref
        if rbac.scope_type == "resource_group":
            attr = SCOPE_RESOURCE_TO_MAP.get(rtype)
            emap = getattr(self.model, attr, {}) if attr else {}
            entry = emap.get(resource_ref)
            return bool(entry) and entry.get("resource_group_name") == rbac.scope_ref
        return False

    def _loot_app(self, d: DataInject) -> Optional[str]:
        """The app an attacker gains control of by looting this data_inject (None
        if the material isn't a usable credential)."""
        if d.material == "app_secret" and d.credential_ref in self.creds:
            return self.creds[d.credential_ref].app_ref
        if d.material == "app_certificate":
            # A planted .pfx only confers control if its cert is REGISTERED on the app
            # (a companion `type: certificate` credential -> azuread_application_certificate).
            # Without that registration the loot authenticates as nothing, so the hop is
            # NOT traversable — the gate must report the path unreachable rather than
            # deploy a tenant whose final cert-auth hop silently fails.
            app = d.source_ref
            if not app and d.credential_ref in self.creds:
                app = self.creds[d.credential_ref].app_ref
            if app and app in self.cert_registered_apps:
                return app
        return None

    @staticmethod
    def _inject_rtype(d: DataInject) -> Optional[str]:
        attr = INJECT_LOCATION_TO_MAP.get(d.location_type)
        return _MAP_TO_RESOURCE_TYPE.get(attr)

    # -- objective evaluation -------------------------------------------------
    def _evaluate_objective(self, name: str, capability: str, objective: Dict,
                            control: set) -> PathVerdict:
        target = objective.get("target_ref")

        if capability == "control_principal":
            return self._verdict_target_in_control(name, target, control)

        if capability == "code_execution":
            # The walk already adds a controlled compute resource to `control`.
            return self._verdict_target_in_control(name, target, control)

        if capability in capabilities.READ_CAPABILITY_RESOURCE:
            rtype = capabilities.READ_CAPABILITY_RESOURCE[capability]
            if not target:
                return PathVerdict(name, INVALID,
                                   f"capability '{capability}' needs a target_ref "
                                   f"(the resource to read).")
            # Terminal node is the READER principal (the controlled identity that can
            # read the resource), NOT the resource itself — the resource is reached by
            # a readability check, not a control-set edge, so it has no parent to trace.
            # Tracing to the reader recovers the real intermediate hops (group
            # membership inheritance, the managed-identity pivot, ...).
            reader = self._reader_of(target, rtype, control)
            if reader is not None:
                return PathVerdict(name, REACHED,
                                   f"a controlled principal can read '{target}'.",
                                   terminal_node=reader)
            return PathVerdict(name, BLOCKED,
                               f"no controlled principal can read '{target}'.",
                               terminal_node=target)

        if capability == "entra_role":
            return self._verdict_entra_role(name, objective, control)

        if capability == "read_mail":
            return self._verdict_read_mail(name, objective, control)

        return PathVerdict(name, UNVERIFIED,
                           f"capability '{capability}' has no evaluator.")

    def _verdict_target_in_control(self, name, target, control) -> PathVerdict:
        if not target:
            return PathVerdict(name, INVALID,
                               "objective needs a target_ref naming the node to reach.")
        if target in control:
            return PathVerdict(name, REACHED,
                               f"'{target}' is controlled by the attacker.",
                               terminal_node=target)
        return PathVerdict(name, BLOCKED,
                           f"'{target}' is never reached from initial_access.",
                           terminal_node=target)

    def _verdict_entra_role(self, name, objective, control) -> PathVerdict:
        role = objective.get("role") or objective.get("name")
        if not role:
            return PathVerdict(name, INVALID,
                               "capability 'entra_role' needs a `role:` (or name).")
        try:
            guids = set(self.resolver.resolve_entra_role(role))
        except Exception as e:  # NameResolutionError -> objective names a junk role
            return PathVerdict(name, INVALID,
                               f"objective role '{role}' did not resolve: {e}")
        for p in self.primitives:
            if isinstance(p, EntraRoleAssignment) and p.role in guids \
                    and p.principal_ref in control:
                return PathVerdict(name, REACHED,
                                   f"controlled principal '{p.principal_ref}' holds "
                                   f"the target Entra role.",
                                   terminal_node=p.principal_ref)
        return PathVerdict(name, BLOCKED,
                           f"no controlled principal ends up holding Entra role "
                           f"'{role}'.")

    def _verdict_read_mail(self, name, objective, control) -> PathVerdict:
        target = objective.get("target_ref")
        if target and target in control:
            return PathVerdict(name, REACHED,
                               f"the mailbox owner '{target}' is controlled.",
                               terminal_node=target)
        mail_guids = capabilities.mail_permission_guids()
        for p in self.primitives:
            if isinstance(p, ApiPermission) and p.permission_id in mail_guids \
                    and p.principal_ref in control:
                return PathVerdict(name, REACHED,
                                   f"controlled app '{p.principal_ref}' holds a mail "
                                   f"read permission.",
                                   terminal_node=p.principal_ref)
        return PathVerdict(name, BLOCKED,
                           "no controlled principal can read the target mailbox.")

    # -- step derivation ------------------------------------------------------
    def _derive_steps(self, seed, terminal, parent, overlay, capability,
                      objective) -> List[Dict]:
        """Reconstruct an ordered step list from the walk: the initial-access hop,
        then each edge from seed to the terminal node, then a final 'gain' note."""
        ia = overlay.initial_access or {}
        method = ia.get("method", "compromised_identity")
        if method in RESOURCE_SEED_VECTORS:
            # Resource-seed foothold: the seed is the host/app, not an identity.
            first_name = f"Initial access via {method}: code execution on {seed}"
        else:
            first_name = f"Compromise {seed}"
        steps: List[Dict] = [{
            "name": first_name,
            "source_ref": seed,
            "action": method,
            "mitre": _merge_mitre(_INITIAL_ACCESS_MITRE.get(method), ia.get("mitre")),
            "derived": True,
        }]
        for src, dst, prim in self._trace(terminal, parent, seed):
            # The name is a human-readable phrase; the formatter renders the "-> target"
            # arrow from target_ref (so the name must NOT embed it, or it double-arrows).
            step = {
                "name": _HOP_PHRASE.get(type(prim), "Traverse to"),
                "source_ref": src,
                "target_ref": dst,
                "uses": [prim.key],
                "action": _ACTIONS.get(type(prim), "traverse"),
                "mitre": _mitre_for_hop(prim),
                "derived": True,
            }
            # A credential loot is read OUT of a data resource — name it so the step
            # shows WHERE the credential was stolen from (e.g. the storage account the
            # managed identity read), not just the app it yields.
            if isinstance(prim, DataInject) and getattr(prim, "location_ref", None):
                step["reads"] = [prim.location_ref]
            steps.append(step)
        gain = objective.get("role") or objective.get("name") or capability
        steps.append({
            "name": f"Achieve objective: {gain}",
            "source_ref": terminal,
            "action": capability,
            "gains": [gain],
            "derived": True,
        })
        return steps

    @staticmethod
    def _trace(terminal, parent, seed) -> List[Tuple]:
        """Edges from seed -> terminal, in order. Empty if the objective is met by
        the initial-access principal alone."""
        chain: List[Tuple] = []
        node = terminal
        guard = 0
        while node != seed and node in parent and guard < 1000:
            prim, src = parent[node]
            chain.append((src, node, prim))
            node = src
            guard += 1
        chain.reverse()
        return chain


# Primitive type -> the action verb used in a derived step (machine-readable token).
_ACTIONS = {
    AppOwnership: "app_credential_addition",
    GroupOwnership: "group_membership_modification",
    GroupMembership: "group_membership_inheritance",
    EntraRoleAssignment: "app_admin_credential_addition",
    AzureRbacAssignment: "resource_control",
    DataInject: "credential_loot",
}

# MITRE ATT&CK IDs derived from the traversal itself, so every path — atomic or
# chained — is mapped without an author writing `mitre:` by hand. A path's author
# may still supply `mitre:` to augment (union) these. IDs are intentionally
# per-primitive; refine the table here and it flows to every report and doc.
# Azure RBAC scopes that are compute hosts: controlling one yields its attached
# managed-identity token (the pivot ManagedIdentityAbuse turns on).
_COMPUTE_SCOPE_TYPES = {
    "virtual_machine", "logic_app", "automation_account", "function_app", "app_service",
}

_INITIAL_ACCESS_MITRE = {
    "compromised_identity": ["T1078.004"],    # Valid Accounts: Cloud Accounts
    "compromised_credential": ["T1078.004"],
    "exposed_rdp": ["T1133", "T1110.001"],     # External Remote Services + Password Guessing
    "exposed_ssh": ["T1133", "T1110.001"],
    "vulnerable_web_app": ["T1190"],           # Exploit Public-Facing Application
}


def _merge_mitre(*sources) -> Optional[List[str]]:
    """Union ATT&CK IDs from several sources (derived + author-supplied), order
    preserved, duplicates dropped. Returns None when empty so the field stays
    absent rather than an empty list."""
    merged: List[str] = []
    for source in sources:
        if not source:
            continue
        items = [source] if isinstance(source, str) else source
        for item in items:
            if item and item not in merged:
                merged.append(item)
    return merged or None


def _mitre_for_hop(prim) -> List[str]:
    """The ATT&CK technique(s) a single traversal hop performs. Some primitives
    branch on their fields (an RBAC role over a compute resource abuses that
    resource's managed identity; a data inject's location decides the theft
    technique)."""
    if isinstance(prim, (AppOwnership, EntraRoleAssignment)):
        return ["T1098.001"]                   # Additional Cloud Credentials (add creds to an app)
    if isinstance(prim, (GroupOwnership, GroupMembership)):
        return ["T1098.003"]                   # Additional Cloud Roles (self-add to a privileged group)
    if isinstance(prim, AzureRbacAssignment):
        if prim.scope_resource_type in _COMPUTE_SCOPE_TYPES:
            # Controlling a compute host yields its managed-identity token.
            return ["T1078.004", "T1528"]      # + Steal Application Access Token
        return ["T1078.004"]                   # use the granted role directly
    if isinstance(prim, DataInject):
        if prim.location_type in ("key_vault_secret", "key_vault_certificate"):
            return ["T1555.006"]               # Cloud Secrets Management Stores
        if prim.location_type == "storage_blob":
            return ["T1552.001"]               # Unsecured Credentials: Credentials In Files
        return ["T1552"]                       # cosmos_document — Unsecured Credentials
    return []

# Primitive type -> a short relation verb for the blocked-edge diagnostic
# ("<src> <verb> <dst>, but <src> is never controlled.").
_RELATION = {
    AppOwnership: "owns app",
    GroupOwnership: "owns group",
    GroupMembership: "is a member of",
    EntraRoleAssignment: "can take over app",
    AzureRbacAssignment: "controls resource",
}

# Primitive type -> a human-readable phrase for the derived step's name. The hop's
# `target_ref` (the gained node) is rendered as a "-> <node>" arrow by the formatter,
# so the entity name is named by the arrow, not repeated here.
_HOP_PHRASE = {
    AppOwnership: "Take over application via ownership",
    GroupOwnership: "Take over group via ownership",
    GroupMembership: "Inherit access via group membership",
    AzureRbacAssignment: "Control resource (gain its managed identity)",
    DataInject: "Loot planted credential",
}
