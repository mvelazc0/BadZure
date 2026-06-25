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
from src.constants import RESOURCE_FOOTHOLD_VECTORS

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
            if d.source_ref:
                return d.source_ref
            if d.credential_ref in self.creds:
                return self.creds[d.credential_ref].app_ref
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
        if method in RESOURCE_FOOTHOLD_VECTORS:
            # Exposed-host foothold: the seed is the host, not an identity.
            first_name = f"Initial access via {method}: code execution on {seed}"
        else:
            first_name = f"Compromise {seed}"
        steps: List[Dict] = [{
            "name": first_name,
            "source_ref": seed,
            "action": method,
            "mitre": ia.get("mitre"),
            "derived": True,
        }]
        for src, dst, prim in self._trace(terminal, parent, seed):
            # The name is a human-readable phrase; the formatter renders the "-> target"
            # arrow from target_ref (so the name must NOT embed it, or it double-arrows).
            steps.append({
                "name": _HOP_PHRASE.get(type(prim), "Traverse to"),
                "source_ref": src,
                "target_ref": dst,
                "uses": [prim.key],
                "action": _ACTIONS.get(type(prim), "traverse"),
                "derived": True,
            })
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
    AppOwnership: "app_takeover",
    GroupOwnership: "group_takeover",
    GroupMembership: "group_membership_inheritance",
    AzureRbacAssignment: "resource_control",
    DataInject: "credential_loot",
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
