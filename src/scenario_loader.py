"""
scenario_loader.py — parse the declarative graph config into a DeploymentModel.

This is the Phase-3 analog of the Phase-2 macro (`macro_keyvault_secret_theft`):
where the macro hard-codes ONE technique's chain as generic building blocks, this
loader reads an *arbitrary* attack chain the operator wrote declaratively and emits
the same generic building blocks. A "technique" is no longer a Python method — it's
a few lines of YAML describing identities, resources and the assignments wired
between them.

Slice 1 scope (intentionally narrow — see dev-docs/redesign/phase-3-yaml-ir.md):
  - Parse `attack_paths.<name>` blocks with INLINE-declared identities / resources /
    assignments / credentials / data_injects.
  - Emit primitives with origin=attack_path and hand back a DeploymentModel that
    `terraform_builder.build_tfvars` can deploy directly.
  - Entra-role / API-permission values are resolved through `name_resolver.py`
    (Slice 2): a GUID, a friendly name, a list, or `random` all work. Azure RBAC
    role names pass through verbatim (Terraform takes the role name directly).
  - The random `baseline:` layer + `from: baseline` ref-picking (Slice 3): a
    `baseline:` section generates origin=random entities and noise via
    `baseline_generator.py`; `{ref: x, from: baseline}` binds an attack-path ref to
    a baseline entity. Baseline noise avoids the groups attack paths rely on, but
    borrowed baseline users keep their noise (a victim that already looks like a
    normal employee).

BadZure has ONE config shape now — this declarative graph IR. cli rejects any retired
legacy `mode:`/`privilege_escalation:` config before the loader runs.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import random

from src import reachability
from src.entity_generator import EntityGenerator
from src.name_resolver import NameResolver
from src.baseline_generator import BaselineGenerator
from src.attack_path_manager import AttackPathManager
from src.primitives import (
    DeploymentModel, ATTACK_PATH, RANDOM,
    EntraRoleAssignment, AzureRbacAssignment, ApiPermission, AppCredential,
    DataInject, GroupMembership, GroupOwnership, AppOwnership, AuMembership,
    InitialAccessVector,
)
from src.primitive_handlers import SCOPE_RESOURCE_TO_MAP, MI_SOURCE_TO_MAP
from src.constants import VALID_TECHNIQUES, RESOURCE_FOOTHOLD_VECTORS


class ScenarioConfigError(ValueError):
    """Raised when a declarative scenario config is malformed or uses a feature
    not yet implemented in the current slice."""


# Entity-map attribute -> the EntityGenerator *_targeted method that builds it.
# resource_groups is handled separately (built first, no parent resource group),
# and service_principals fold into applications (an SP is backed by an app).
_IDENTITY_BUILDERS = {
    "users": "generate_users_targeted",
    "groups": "generate_groups_targeted",
    "applications": "generate_applications_targeted",
    "administrative_units": "generate_administrative_units_targeted",
}
_RESOURCE_BUILDERS = {
    "key_vaults": "generate_key_vaults_targeted",
    "storage_accounts": "generate_storage_accounts_targeted",
    "virtual_machines": "generate_virtual_machines_targeted",
    "logic_apps": "generate_logic_apps_targeted",
    "automation_accounts": "generate_automation_accounts_targeted",
    "function_apps": "generate_function_apps_targeted",
    "app_services": "generate_app_services_targeted",
    "cosmos_dbs": "generate_cosmos_dbs_targeted",
}

# Symbolic principal_type -> entity-map attr (for inferring principal_type from
# which map a ref lives in). Mirrors PRINCIPAL_TYPE_TO_MAP, inverted.
_MAP_TO_PRINCIPAL_TYPE = {
    "users": "user",
    "applications": "service_principal",
    "groups": "group",
}
# entity-map attr -> resource_type token (inverse of SCOPE_RESOURCE_TO_MAP) for
# inferring an azure_rbac scope_type/scope_resource_type from the scope ref.
_MAP_TO_RESOURCE_TYPE = {v: k for k, v in SCOPE_RESOURCE_TO_MAP.items()}

# The assignment `type` tokens the declarative config accepts — the single source
# of truth for both `_emit_assignment` (below) and `scenario_validator`. Each maps
# 1:1 to a primitive (see the target-schema table in the Phase-3 doc).
ASSIGNMENT_TYPES = frozenset({
    "entra_role", "azure_rbac", "api_permission",
    "group_membership", "group_ownership", "app_ownership", "au_membership",
})

# Default resource group synthesized for inline resources that don't name one.
_DEFAULT_RG = "badzure-default-rg"
_DEFAULT_RG_LOCATION = "West US"

# -- Tier-1 `technique:` sugar -------------------------------------------------
# A technique path fires a macro that wires the whole chain; the loader then
# synthesizes a (capability, target) objective from the macro's summary so the
# reachability gate validates it exactly like a hand-authored explicit path.
# technique -> (objective capability, summary key naming the target).
_TECHNIQUE_OBJECTIVES = {
    "KeyVaultSecretTheft":           ("read_secrets",      "key_vault"),
    "StorageCertificateTheft":       ("read_storage",      "storage_account"),
    "CosmosDBSecretTheft":           ("read_cosmos",       "cosmos_db"),
    "ApplicationOwnershipAbuse":     ("control_principal", "app_name"),
    "ApplicationAdministratorAbuse": ("control_principal", "app_name"),
    "CloudAppAdministratorAbuse":    ("control_principal", "app_name"),
    # ManagedIdentityAbuse's capability depends on the target resource type — see
    # _MI_TARGET_CAPABILITY (the objective targets the looted resource).
}
_MI_TARGET_CAPABILITY = {
    "key_vault": "read_secrets", "storage_account": "read_storage",
    "cosmos_db": "read_cosmos",
}
# Baseline entity map required (for mode=random) per resource-anchored technique.
_TECHNIQUE_REQUIRED_RESOURCE = {
    "KeyVaultSecretTheft":     ("key_vaults", "a key_vault"),
    "StorageCertificateTheft": ("storage_accounts", "a storage_account"),
    "CosmosDBSecretTheft":     ("cosmos_dbs", "a cosmos_db"),
}
_MI_SOURCE_MAP = {
    "vm": "virtual_machines", "logic_app": "logic_apps",
    "automation_account": "automation_accounts", "function_app": "function_apps",
    "app_service": "app_services",
}
_MI_TARGET_MAP = {
    "key_vault": "key_vaults", "storage_account": "storage_accounts",
    "cosmos_db": "cosmos_dbs",
}


@dataclass
class AttackPathOverlay:
    """The non-deployable overlay of one declarative attack path — the narrative
    layer (objective / initial_access / steps / metadata) plus the operator
    credentials surfaced for that path. Carried alongside the DeploymentModel for
    output and (later slices) reachability; the builder never sees it."""
    name: str
    objective: Dict = field(default_factory=dict)
    initial_access: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    steps: List = field(default_factory=list)
    credentials: Dict = field(default_factory=dict)
    summary: Dict = field(default_factory=dict)
    # Stamped by the reachability gate: {status, reason}. Surfaced in the operator
    # output so they see WHY a path was accepted (reached / unverified).
    reachability: Dict = field(default_factory=dict)


@dataclass
class ScenarioModel:
    """What the loader returns: the deployable DeploymentModel + one overlay per
    declarative attack path."""
    model: DeploymentModel
    attack_paths: List[AttackPathOverlay] = field(default_factory=list)


class ScenarioLoader:
    """Turns a declarative graph config into a ScenarioModel."""

    def __init__(self, entity_generator: Optional[EntityGenerator] = None,
                 name_resolver: Optional[NameResolver] = None,
                 baseline_generator: Optional[BaselineGenerator] = None,
                 attack_path_mgr: Optional[AttackPathManager] = None):
        self.generator = entity_generator or EntityGenerator()
        self.resolver = name_resolver or NameResolver()
        self.baseline = baseline_generator or BaselineGenerator(self.generator)
        # Drives `technique:` paths — the on-ramp tier that fires the macro library
        # (the SAME macros the legacy mode used) instead of an explicit assignment graph.
        self.attack_path_mgr = attack_path_mgr or AttackPathManager(self.generator)

    # -- public API -----------------------------------------------------------
    def load(self, config: Dict, tenant_id: str = "", domain: str = "",
             subscription_id: str = "", public_ip: str = "",
             azure_config_dir: str = "") -> ScenarioModel:
        # 0. Structural validation up front (registry-driven). Aggregates malformed
        #    objectives / unknown assignment types / dangling step links into one
        #    error before we build anything. Lazy import avoids an import cycle
        #    (the validator imports this module's ASSIGNMENT_TYPES / error type).
        from src import scenario_validator
        scenario_validator.validate(config)

        baseline_config = config.get("baseline") or {}
        # `enabled: false` parks a path (defined but not deployed); default is true.
        # Disabled paths are dropped HERE so they build no entities and emit no edges.
        attack_paths = {
            name: path
            for name, path in (config.get("attack_paths") or {}).items()
            if not (isinstance(path, dict) and path.get("enabled") is False)
        }
        if not attack_paths and not baseline_config:
            raise ScenarioConfigError(
                "Declarative config declares neither a baseline nor any (enabled) "
                "attack_paths."
            )

        # 1. The org-baseline. Built FIRST so attack paths can pick from it.
        #    Two forms, which may coexist per kind: COUNT-driven random entities
        #    (baseline_generator) and EXPLICIT named entities (the declarative form,
        #    built via the shared targeted path). Explicit entities make a baseline
        #    realistic (named users in departmental groups, etc.) and are directly
        #    referenceable by attack-path assignments.
        baseline_entities = (self.baseline.generate_entities(baseline_config)
                             if baseline_config else {})
        if baseline_config:
            explicit_specs = self._collect_explicit_baseline_specs(baseline_config)
            if explicit_specs:
                baseline_entities = self._merge_baseline_explicit(
                    baseline_entities, self._build_targeted_entities(explicit_specs))

        # 2. Attack-path entities: inline-declared ones built fresh; `from: baseline`
        #    refs bound to existing baseline entities (alias ref -> real baseline key).
        inline_entities, alias = self._build_attack_entities(
            attack_paths, baseline_entities)

        # 3. One merged entity set (symbolic-keyed) the assignments resolve against.
        entities = self._merge_entities(baseline_entities, inline_entities)
        ref_kind = self._index_refs(entities)

        primitives: List = []

        # 3a. Explicit baseline assignments + credentials + data_injects -> origin=
        #     random primitives, resolved against the merged entity set. (Count-driven
        #     noise comes in step 5.) Credentials/injects make a baseline complete:
        #     SPs with client secrets, vaults/storage holding (benign) material.
        if baseline_config:
            self._emit_baseline_assignments(baseline_config, ref_kind, primitives)
            self._emit_baseline_credentials_and_injects(baseline_config, primitives)

        # 4. Compile each path -> origin=attack_path primitives. Two authoring tiers:
        #    a `technique:` path fires the macro library (Tier 1, on-ramp); an explicit
        #    `assignments:` path compiles the graph directly (Tier 2). Paths are rewritten
        #    so `from: baseline` aliases point at their real baseline keys before emit.
        #    used_apps/used_users/used_sources dedup victim/target/source picks across
        #    technique paths (two MI paths sharing a source collide on apply).
        overlays: List[AttackPathOverlay] = []
        used_apps: set = set()
        used_users: set = set()
        used_sources: set = set()
        technique_creds: Dict[str, Dict] = {}
        for path_name, path in attack_paths.items():
            resolved = self._resolve_aliases_in_path(path, alias)
            if "privilege_escalation" in path:
                overlay = self._compile_technique_path(
                    path_name, resolved, ref_kind, entities, primitives, domain,
                    used_apps, used_users, used_sources)
                technique_creds[path_name] = overlay.credentials
            else:
                overlay = self._compile_path(path_name, resolved, ref_kind, entities,
                                             primitives, domain)
            overlays.append(overlay)

        # 4a. Recon access for technique-path initial-access identities (parity with
        #     legacy: Directory.Read.All for SPs + subscription Reader). Done ONCE over
        #     all technique paths so a shared initial-access identity dedups its grants.
        if technique_creds:
            primitives.extend(
                self.attack_path_mgr.build_recon_primitives(technique_creds))

        # 5. Baseline noise LAST: it samples baseline entities but avoids the groups
        #    the attack paths rely on (so random members don't dilute a group-based
        #    chain). Borrowed baseline users keep their noise — that's the realism.
        if baseline_config:
            excluded = self._attack_referenced_groups(primitives)
            primitives.extend(
                self.baseline.generate_noise(baseline_config, baseline_entities, excluded))

        model = DeploymentModel(
            tenant_id=tenant_id, domain=domain, subscription_id=subscription_id,
            public_ip=public_ip, azure_config_dir=azure_config_dir,
            primitives=primitives, **entities,
        )

        # 6. Reachability gate: confirm each attack path's objective is actually
        #    reachable from its initial_access through the deployed graph, and fill
        #    in derived steps for paths that didn't author any. Runs on the FULL
        #    mixed-origin primitive set (an attack can leverage baseline edges too).
        report = reachability.analyze(model, overlays, self.resolver)
        reachability.attach_derived_steps(overlays, report)
        reachability.enforce(report)  # <- comment out this line to bypass the gate

        return ScenarioModel(model=model, attack_paths=overlays)

    # -- entity construction --------------------------------------------------
    def _build_attack_entities(self, attack_paths: Dict,
                               baseline_entities: Dict[str, Dict]):
        """Build the attack paths' inline entities and bind their `from: baseline` refs.

        Returns (inline_entities, alias) where:
          - inline_entities: entity maps for the freshly-declared (non-baseline) refs,
            built via EntityGenerator's *_targeted methods (default attrs reused).
          - alias: ref -> real baseline key, for every `{ref: x, from: baseline}` spec,
            so the loader can rewrite assignments before emitting primitives.
        """
        specs: Dict[str, List[Dict]] = {}
        seen: Dict[str, set] = {}
        alias: Dict[str, str] = {}
        picked: Dict[str, set] = {}  # per-kind baseline keys already bound (no reuse)

        def add_spec(kind: str, raw: Dict):
            ref = self._spec_name(raw)
            source = raw.get("from")
            if source == "baseline":
                alias[ref] = self._pick_from_baseline(kind, baseline_entities, picked, ref)
                return
            if source:
                raise ScenarioConfigError(
                    f"Entity '{ref}' has unknown source `from: {source}` "
                    f"(only 'baseline' is supported)."
                )
            seen.setdefault(kind, set())
            if ref in seen[kind]:
                return
            seen[kind].add(ref)
            specs.setdefault(kind, []).append(self._to_targeted_spec(raw))

        for path in attack_paths.values():
            identities = path.get("identities") or {}
            for kind in list(_IDENTITY_BUILDERS):
                for raw in identities.get(kind, []):
                    add_spec(kind, raw)
            for raw in identities.get("service_principals", []):
                add_spec("applications", raw)

            resources = path.get("resources") or {}
            for raw in resources.get("resource_groups", []):
                add_spec("resource_groups", raw)
            for kind in list(_RESOURCE_BUILDERS):
                for raw in resources.get(kind, []):
                    add_spec(kind, raw)

        return self._build_targeted_entities(specs), alias

    def _build_targeted_entities(self, specs: Dict[str, List[Dict]]) -> Dict[str, Dict]:
        """Turn a `{kind: [targeted-form spec, ...]}` map (specs already in the
        `{name: X, ...}` shape the EntityGenerator *_targeted methods expect) into
        symbolic-keyed entity maps. Shared by the attack-path inline entities and
        the explicit baseline entities — both build the same way."""
        # Resource groups first — resources need a parent RG to attach to.
        resource_groups = self.generator.generate_resource_groups_targeted(
            specs.get("resource_groups", [])
        )
        # Synthesize a default RG for any resource spec that didn't name one, so
        # the operator can declare `key_vaults: [{ref: kv01}]` without boilerplate.
        if self._needs_default_rg(specs) and _DEFAULT_RG not in resource_groups:
            resource_groups[_DEFAULT_RG] = {
                "name": _DEFAULT_RG, "location": _DEFAULT_RG_LOCATION,
            }

        entities: Dict[str, Dict] = {"resource_groups": resource_groups}
        for kind, method in _IDENTITY_BUILDERS.items():
            entities[kind] = getattr(self.generator, method)(specs.get(kind, []))
        for kind, method in _RESOURCE_BUILDERS.items():
            kind_specs = [self._with_default_rg(s) for s in specs.get(kind, [])]
            entities[kind] = getattr(self.generator, method)(kind_specs, resource_groups)
        return entities

    def _collect_explicit_baseline_specs(self, baseline_config: Dict) -> Dict[str, List[Dict]]:
        """Gather the EXPLICIT (list-of-specs) baseline identities/resources into a
        targeted-form `{kind: [spec]}` map. Count-form kinds (integers) are ignored
        here — baseline_generator builds those. Returns {} when the baseline declares
        no explicit specs (the pure count-driven case)."""
        specs: Dict[str, List[Dict]] = {}

        def collect(kind: str, raw_list) -> None:
            if not isinstance(raw_list, list):
                return  # int (count) or absent -> not built here
            for raw in raw_list:
                specs.setdefault(kind, []).append(self._to_targeted_spec(raw))

        identities = baseline_config.get("identities") or {}
        for kind in _IDENTITY_BUILDERS:
            collect(kind, identities.get(kind))
        collect("applications", identities.get("service_principals"))

        resources = baseline_config.get("resources") or {}
        collect("resource_groups", resources.get("resource_groups"))
        for kind in _RESOURCE_BUILDERS:
            collect(kind, resources.get(kind))
        return specs

    @staticmethod
    def _merge_baseline_explicit(count_entities: Dict[str, Dict],
                                 explicit_entities: Dict[str, Dict]) -> Dict[str, Dict]:
        """Union the count-driven and explicit baseline entity maps per kind. Both
        are baseline; cross-kind ref collisions are caught later by `_index_refs`."""
        merged: Dict[str, Dict] = {}
        for attr in DeploymentModel.ENTITY_MAPS:
            merged[attr] = {**count_entities.get(attr, {}),
                            **explicit_entities.get(attr, {})}
        return merged

    @staticmethod
    def _pick_from_baseline(kind: str, baseline_entities: Dict[str, Dict],
                            picked: Dict[str, set], ref: str) -> str:
        """Bind a `from: baseline` ref to a random, not-yet-bound baseline entity of
        `kind`."""
        available = [k for k in baseline_entities.get(kind, {})
                     if k not in picked.get(kind, set())]
        if not available:
            raise ScenarioConfigError(
                f"`{ref}` requests a {kind} from the baseline, but the baseline has "
                f"no (unused) {kind} to pick. Increase baseline.{kind} or declare it "
                f"inline."
            )
        chosen = random.choice(available)
        picked.setdefault(kind, set()).add(chosen)
        return chosen

    @staticmethod
    def _merge_entities(baseline_entities: Dict[str, Dict],
                        inline_entities: Dict[str, Dict]) -> Dict[str, Dict]:
        """Combine baseline + inline entity maps per kind. Inline refs are explicit,
        so a clash with a (random) baseline key is almost certainly a mistake."""
        merged: Dict[str, Dict] = {}
        for attr in DeploymentModel.ENTITY_MAPS:
            baseline_map = baseline_entities.get(attr, {})
            inline_map = inline_entities.get(attr, {})
            clash = set(baseline_map) & set(inline_map)
            if clash:
                raise ScenarioConfigError(
                    f"Inline {attr} ref(s) {sorted(clash)} collide with baseline "
                    f"entity keys; rename the inline ref(s)."
                )
            merged[attr] = {**baseline_map, **inline_map}
        return merged

    @staticmethod
    def _spec_name(raw: Dict) -> str:
        ref = raw.get("ref")
        if not ref:
            raise ScenarioConfigError(f"Entity spec is missing required 'ref': {raw}")
        return ref

    @classmethod
    def _to_targeted_spec(cls, raw: Dict) -> Dict:
        """Translate a declarative `{ref: X, ...}` entity into the `{name: X, ...}`
        shape the EntityGenerator *_targeted methods expect."""
        spec = {k: v for k, v in raw.items() if k not in ("ref", "from")}
        spec["name"] = cls._spec_name(raw)
        return spec

    @staticmethod
    def _needs_default_rg(specs: Dict[str, List[Dict]]) -> bool:
        for kind in _RESOURCE_BUILDERS:
            for s in specs.get(kind, []):
                if not s.get("resource_group"):
                    return True
        return False

    @staticmethod
    def _with_default_rg(spec: Dict) -> Dict:
        if spec.get("resource_group"):
            return spec
        out = dict(spec)
        out["resource_group"] = _DEFAULT_RG
        return out

    @staticmethod
    def _index_refs(entities: Dict[str, Dict]) -> Dict[str, str]:
        """Symbolic ref -> entity-map attr it was declared in (for type inference)."""
        ref_kind: Dict[str, str] = {}
        for attr, emap in entities.items():
            for key in emap:
                if key in ref_kind:
                    raise ScenarioConfigError(
                        f"Duplicate entity ref '{key}' declared as both "
                        f"{ref_kind[key]} and {attr}; refs must be unique."
                    )
                ref_kind[key] = attr
        return ref_kind

    # -- from: baseline alias resolution --------------------------------------
    # The *_ref fields in a path that may name a `from: baseline` alias. Rewriting
    # only these (not entity declarations, ids, or path-local credential refs) keeps
    # the substitution precise.
    _ASSIGNMENT_REF_FIELDS = (
        "principal_ref", "scope_ref", "group_ref", "app_ref", "au_ref",
        "scope_app_ref",
    )

    @classmethod
    def _resolve_aliases_in_path(cls, path: Dict, alias: Dict[str, str]) -> Dict:
        """Return a shallow path copy with `from: baseline` alias refs rewritten to
        their real baseline keys across assignments / credentials / data_injects /
        initial_access. No-op when there are no aliases."""
        if not alias:
            return path
        out = dict(path)

        def sub(value):
            return alias.get(value, value)

        out["assignments"] = [
            {**a, **{f: sub(a[f]) for f in cls._ASSIGNMENT_REF_FIELDS if f in a}}
            for a in path.get("assignments", [])
        ]
        out["credentials"] = [
            {**c, **({"app_ref": sub(c["app_ref"])} if "app_ref" in c else {})}
            for c in path.get("credentials", [])
        ]
        out["data_injects"] = [
            {**d, **{f: sub(d[f]) for f in ("location_ref", "source_ref") if f in d}}
            for d in path.get("data_injects", [])
        ]
        ia = path.get("initial_access")
        if isinstance(ia, dict) and "principal_ref" in ia:
            out["initial_access"] = {**ia, "principal_ref": sub(ia["principal_ref"])}
        # The objective's target_ref/principal_ref may also name a `from: baseline`
        # alias (e.g. `read_secrets` on a borrowed baseline vault) — rewrite so the
        # reachability gate checks against the real baseline key.
        obj = path.get("objective")
        if isinstance(obj, dict):
            out["objective"] = {
                **obj,
                **{f: sub(obj[f]) for f in ("target_ref", "principal_ref") if f in obj},
            }
        return out

    @staticmethod
    def _attack_referenced_groups(primitives: List) -> set:
        """Group keys an attack path uses as a role/RBAC principal or a membership
        target — these are excluded from random group-membership noise so baseline
        members don't dilute a group-based chain (mirrors legacy random mode)."""
        groups = set()
        for p in primitives:
            if isinstance(p, (EntraRoleAssignment, AzureRbacAssignment)) \
                    and p.principal_type == "group":
                groups.add(p.principal_ref)
            elif isinstance(p, (GroupMembership, GroupOwnership)):
                groups.add(p.group_ref)
        return groups

    # -- explicit baseline assignments ----------------------------------------
    def _emit_baseline_assignments(self, baseline_config: Dict,
                                   ref_kind: Dict[str, str], primitives: List) -> None:
        """Compile the EXPLICIT baseline assignments (the LIST form of
        `baseline.assignments`) into origin=random primitives, keyed under a
        `baseline__` namespace and resolved against the merged entity set. The DICT
        form (counts) is handled separately by baseline_generator.generate_noise."""
        assignments = baseline_config.get("assignments")
        if not isinstance(assignments, list):
            return
        for idx, a in enumerate(assignments):
            aid = a.get("id") or f"a{idx}"
            primitives.extend(
                self._emit_assignment(self._key("baseline", aid), a, ref_kind,
                                      "baseline", origin=RANDOM))

    def _emit_baseline_credentials_and_injects(self, baseline_config: Dict,
                                               primitives: List) -> None:
        """Compile baseline `credentials` -> AppCredential and `data_injects` ->
        DataInject, both origin=random. Mirrors `_compile_path`'s handling but for
        the org baseline (a realistic tenant has SP secrets + material in its
        vaults/storage). data_injects' credential_ref binds to a baseline credential
        key when it names one (the app_secret join)."""
        cred_ref_to_key: Dict[str, str] = {}
        for idx, cred in enumerate(baseline_config.get("credentials") or []):
            ref = cred.get("ref") or f"cred{idx}"
            key = self._key("baseline", ref)
            cred_ref_to_key[ref] = key
            primitives.append(AppCredential(
                key, RANDOM,
                app_ref=cred["app_ref"], type=cred.get("type", "password"),
                certificate_path=cred.get("certificate_path"),
                display_name=cred.get("display_name", "BadZureBaselineCredential"),
            ))
        for idx, d in enumerate(baseline_config.get("data_injects") or []):
            did = d.get("id") or f"d{idx}"
            cref = d.get("credential_ref")
            primitives.append(DataInject(
                self._key("baseline", did), RANDOM,
                material=d["material"],
                location_type=d.get("location_type") or d.get("location"),
                location_ref=d["location_ref"], name=d["name"],
                source_ref=d.get("source_ref"),
                credential_ref=cred_ref_to_key.get(cref, cref) if cref else None,
                literal_value=d.get("literal_value"), file_path=d.get("file_path"),
                pfx_password=d.get("pfx_password", ""),
            ))

    # -- per-path compilation -------------------------------------------------
    def _compile_path(self, path_name: str, path: Dict, ref_kind: Dict[str, str],
                      entities: Dict[str, Dict], primitives: List,
                      domain: str) -> AttackPathOverlay:
        # credentials -> AppCredential. Namespaced key keeps refs unique across
        # paths; data_injects below resolve their credential_ref against this map.
        cred_ref_to_key: Dict[str, str] = {}
        for cred in path.get("credentials", []):
            ref = cred.get("ref")
            if not ref:
                raise ScenarioConfigError(
                    f"{path_name}: credential is missing required 'ref': {cred}"
                )
            key = self._key(path_name, ref)
            cred_ref_to_key[ref] = key
            primitives.append(AppCredential(
                key, ATTACK_PATH,
                app_ref=cred["app_ref"], type=cred.get("type", "password"),
                certificate_path=cred.get("certificate_path"),
                display_name=cred.get("display_name", "BadZureCredential"),
            ))

        # assignments -> the matching assignment primitive(s). A role/permission
        # that resolves to several GUIDs (a list, or a name list) fans out to one
        # primitive per GUID.
        for idx, a in enumerate(path.get("assignments", [])):
            aid = a.get("id") or f"a{idx}"
            primitives.extend(
                self._emit_assignment(self._key(path_name, aid), a, ref_kind, path_name)
            )

        # data_injects -> DataInject (credential_ref rewritten to the namespaced key).
        for idx, d in enumerate(path.get("data_injects", [])):
            did = d.get("id") or f"d{idx}"
            cred_ref = d.get("credential_ref")
            primitives.append(DataInject(
                self._key(path_name, did), ATTACK_PATH,
                material=d["material"],
                location_type=d.get("location_type") or d.get("location"),
                location_ref=d["location_ref"], name=d["name"],
                source_ref=d.get("source_ref"),
                credential_ref=cred_ref_to_key.get(cred_ref, cred_ref) if cred_ref else None,
                literal_value=d.get("literal_value"), file_path=d.get("file_path"),
                pfx_password=d.get("pfx_password", ""),
            ))

        # initial_access: an exposed-host foothold (`vector:`) emits an
        # InitialAccessVector + seeds the walk at the host; otherwise it names a
        # compromised identity whose operator credentials we surface.
        foothold = self._compile_initial_access_vector(path_name, path, entities, primitives)
        if foothold is not None:
            initial_access, credentials = foothold
        else:
            initial_access = path.get("initial_access", {})
            credentials = self._operator_credentials(
                path_name, path, ref_kind, entities, primitives, cred_ref_to_key, domain
            )
        return AttackPathOverlay(
            name=path_name,
            objective=path.get("objective", {}),
            initial_access=initial_access,
            metadata=path.get("metadata", {}),
            steps=path.get("steps", []),
            credentials=credentials,
            summary={"path_name": path_name,
                     "objective": path.get("objective", {}).get("name"),
                     "initial_access_vector": initial_access.get("vector")},
        )

    def _compile_initial_access_vector(self, path_name: str, path: Dict,
                                       entities: Dict[str, Dict], primitives: List):
        """If a chained path's `initial_access:` declares a `vector:` (an exposed-host
        foothold), emit the InitialAccessVector primitive and return
        (normalized_initial_access, operator_credentials). The seed (`principal_ref`)
        is set to the foothold host so the reachability walk starts there. Returns
        None for the identity (compromised-credentials) shape — handled the old way."""
        ia = path.get("initial_access") or {}
        vector = ia.get("vector")
        if not vector:
            return None
        if vector not in RESOURCE_FOOTHOLD_VECTORS:
            raise ScenarioConfigError(
                f"{path_name}: initial_access vector '{vector}' is not implemented "
                f"(supported: {', '.join(RESOURCE_FOOTHOLD_VECTORS)}).")
        target = ia.get("target_ref")
        if not target:
            raise ScenarioConfigError(
                f"{path_name}: initial_access vector '{vector}' needs a `target_ref` "
                f"(the host the attacker lands on).")
        target_type = ia.get("target_type", "virtual_machine")
        primitives.append(InitialAccessVector(
            self._key(path_name, "foothold"), ATTACK_PATH, method=vector,
            target_ref=target, target_type=target_type,
            grants=ia.get("grants", "code_execution"),
            variant=ia.get("variant"),
            expose_to_internet=bool(ia.get("expose_to_internet", False)),
            credential=ia.get("credential", "known")))
        # Seed the walk at the host; keep `vector`/`target_ref` for the narrative.
        initial_access = {**ia, "principal_ref": target, "method": vector}
        credentials = {
            "initial_access": vector,
            "foothold_resource": target,
            "foothold_type": target_type,
            "entry_point": vector,
        }
        return initial_access, credentials

    @staticmethod
    def _key(path_name: str, local: str) -> str:
        """Namespace a path-local id into a globally-unique Terraform variable key."""
        return f"{path_name}__{local}"

    # -- assignment -> primitive(s) -------------------------------------------
    def _emit_assignment(self, key: str, a: Dict, ref_kind: Dict[str, str],
                         path_name: str, origin: str = ATTACK_PATH) -> List:
        """Compile one declarative assignment into primitive(s). `origin` is
        ATTACK_PATH for attack-path assignments (default) and RANDOM for explicit
        baseline assignments — the only difference between the two is bookkeeping."""
        atype = a.get("type")
        if atype == "entra_role":
            # Names/lists/`random` -> GUIDs; one EntraRoleAssignment per GUID.
            roles = self.resolver.resolve_entra_role(a["role"])
            ptype = self._principal_type(a, ref_kind, path_name)
            return [
                EntraRoleAssignment(
                    k, origin,
                    principal_ref=a["principal_ref"], principal_type=ptype,
                    role=role, scope_app_ref=a.get("scope_app_ref"),
                )
                for k, role in zip(self._fanout_keys(key, len(roles)), roles)
            ]
        if atype == "azure_rbac":
            # Azure RBAC takes the role NAME directly — passthrough, no resolution.
            scope_type, scope_resource_type = self._scope(a, ref_kind, path_name)
            return [AzureRbacAssignment(
                key, origin,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                role=a["role"], scope_type=scope_type,
                mi_source_type=a.get("mi_source") or a.get("mi_source_type"),
                scope_ref=a.get("scope_ref"),
                scope_resource_type=scope_resource_type,
                data_plane=a.get("data_plane"),
            )]
        if atype == "api_permission":
            api_type = a.get("api_type", "graph")
            perms = self.resolver.resolve_api_permission(
                a.get("permission_id") or a.get("app_role"), api_type
            )
            return [
                ApiPermission(
                    k, origin,
                    principal_ref=a["principal_ref"],
                    permission_id=perm, api_type=api_type,
                )
                for k, perm in zip(self._fanout_keys(key, len(perms)), perms)
            ]
        if atype == "group_membership":
            return [GroupMembership(
                key, origin,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                group_ref=a["group_ref"],
            )]
        if atype == "group_ownership":
            return [GroupOwnership(
                key, origin,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                group_ref=a["group_ref"],
            )]
        if atype == "app_ownership":
            return [AppOwnership(
                key, origin,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                app_ref=a["app_ref"],
            )]
        if atype == "au_membership":
            return [AuMembership(
                key, origin,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                au_ref=a["au_ref"],
            )]
        raise ScenarioConfigError(
            f"{path_name}: assignment '{key}' has unknown type '{atype}'."
        )

    @staticmethod
    def _fanout_keys(base: str, n: int) -> List[str]:
        """Unique Terraform keys when one assignment fans out to N primitives.
        A single primitive keeps the bare key; multiples get a positional suffix."""
        return [base] if n == 1 else [f"{base}_{i}" for i in range(n)]

    @staticmethod
    def _principal_type(a: Dict, ref_kind: Dict[str, str], path_name: str) -> str:
        """Explicit principal_type wins; otherwise infer from which entity map the
        principal_ref lives in. Managed identities (the principal is a resource)
        MUST be declared explicitly since a resource ref can't disambiguate."""
        explicit = a.get("principal_type")
        if explicit:
            return explicit
        ref = a.get("principal_ref")
        ptype = _MAP_TO_PRINCIPAL_TYPE.get(ref_kind.get(ref))
        if ptype is None:
            raise ScenarioConfigError(
                f"{path_name}: cannot infer principal_type for principal_ref "
                f"'{ref}'. Declare it explicitly (e.g. principal_type: "
                f"managed_identity with mi_source)."
            )
        return ptype

    @staticmethod
    def _scope(a: Dict, ref_kind: Dict[str, str], path_name: str):
        """Resolve (scope_type, scope_resource_type) for an azure_rbac assignment.
        Explicit values win; otherwise infer from the scope_ref's entity kind:
        a resource_group ref -> resource_group scope, a resource ref -> resource
        scope (with the resource_type derived), no scope_ref -> subscription."""
        scope_type = a.get("scope_type")
        scope_ref = a.get("scope_ref")
        scope_resource_type = a.get("scope_resource_type")
        if scope_type:
            return scope_type, scope_resource_type
        if scope_ref is None:
            return "subscription", scope_resource_type
        kind = ref_kind.get(scope_ref)
        if kind == "resource_groups":
            return "resource_group", scope_resource_type
        rtype = _MAP_TO_RESOURCE_TYPE.get(kind)
        if rtype is None:
            raise ScenarioConfigError(
                f"{path_name}: cannot infer scope for scope_ref '{scope_ref}'. "
                f"Declare scope_type/scope_resource_type explicitly."
            )
        return "resource", scope_resource_type or rtype

    # -- operator credentials -------------------------------------------------
    def _operator_credentials(self, path_name: str, path: Dict,
                              ref_kind: Dict[str, str], entities: Dict[str, Dict],
                              primitives: List, cred_ref_to_key: Dict[str, str],
                              domain: str) -> Dict:
        """The credentials handed to the operator for the initial-access identity.
        A user: its UPN + password. A service principal: a client secret surfaced
        via the generic_app_credentials Terraform output (an existing declared
        credential on that app, or one minted here)."""
        ia = path.get("initial_access") or {}
        principal_ref = ia.get("principal_ref")
        entry_point = ia.get("method", "compromised_identity")
        if not principal_ref:
            return {}
        kind = ref_kind.get(principal_ref)
        if kind == "users":
            return {
                "initial_access": "user",
                "user_principal_name": f"{principal_ref}@{domain}",
                "password": entities["users"][principal_ref]["password"],
                "entry_point": entry_point,
            }
        if kind == "applications":
            sp_cred_key = next(
                (cred_ref_to_key[c["ref"]] for c in path.get("credentials", [])
                 if c.get("app_ref") == principal_ref), None
            )
            if sp_cred_key is None:  # mint a secret so the operator can authenticate
                sp_cred_key = self._key(path_name, "initial_sp")
                primitives.append(AppCredential(
                    sp_cred_key, ATTACK_PATH, app_ref=principal_ref,
                    type="password", display_name="BadZureInitialAccess",
                ))
            return {
                "initial_access": "service_principal",
                "service_principal_name": principal_ref,
                "entry_point": entry_point,
                "generic_credential_key": f"ap:{sp_cred_key}",
            }
        raise ScenarioConfigError(
            f"{path_name}: initial_access principal_ref '{principal_ref}' must be a "
            f"declared user or application."
        )

    # -- Tier-1 technique-path compilation ------------------------------------
    def _compile_technique_path(self, path_name: str, path: Dict,
                                ref_kind: Dict[str, str], entities: Dict[str, Dict],
                                primitives: List, domain: str,
                                used_apps: set, used_users: set,
                                used_sources: set) -> AttackPathOverlay:
        """Compile a `technique:` path: fire the matching macro (the SAME library the
        legacy mode used), fold its generic primitives into the model, and synthesize
        a first-class graph overlay (objective + initial_access) so it renders and
        validates identically to an explicit path.

        Entity sourcing (decision #1): a path with inline `identities:`/`resources:`
        runs the macro in `targeted` mode against those named entities; otherwise it
        runs `random` and the macro picks victims/targets from the baseline."""
        technique = path["privilege_escalation"]
        if technique not in VALID_TECHNIQUES:
            raise ScenarioConfigError(
                f"{path_name}: unknown technique '{technique}'. "
                f"Valid: {', '.join(VALID_TECHNIQUES)}.")
        has_inline = bool(path.get("identities") or path.get("resources"))
        mode = "targeted" if has_inline else "random"
        macro_entities = self._legacy_entities_from_path(path) if has_inline else None
        if mode == "random":
            self._require_baseline_entities(technique, path, entities, path_name)

        result = self._dispatch_macro(
            technique, path, entities, domain, mode, macro_entities, path_name,
            used_apps, used_users, used_sources)

        primitives.extend(result["primitives"])
        # Macro-minted attack GROUPS join the model groups map (so Terraform creates
        # them and refs resolve) and ref_kind. They carry is_attack_path_group=True,
        # which keeps them out of the random membership noise.
        for gname, gspec in (result.get("groups") or {}).items():
            entities["groups"][gname] = gspec
            ref_kind.setdefault(gname, "groups")

        summary = result["summary"]
        if summary.get("app_name"):
            used_apps.add(summary["app_name"])
        if summary.get("principal_name"):
            used_users.add(summary["principal_name"])
        # ManagedIdentityAbuse random paths must each take a DISTINCT source resource:
        # two paths sharing one grant its managed identity the same roles on the same
        # target -> identical Azure role assignments -> 409 on apply. The selector
        # prefers an unused source; if it was forced to reuse one (baseline too small),
        # fail clearly here instead of mid-apply.
        source_name = summary.get("source_name")
        if source_name:
            if mode == "random" and source_name in used_sources:
                src_type = summary.get("source_type", "source")
                count_knob = _MI_SOURCE_MAP.get(src_type, src_type)
                raise ScenarioConfigError(
                    f"{path_name}: not enough distinct '{src_type}' resources in the "
                    f"baseline for the number of ManagedIdentityAbuse paths. Each path "
                    f"needs its own source (sharing one collides on apply). Increase the "
                    f"baseline '{count_knob}' count or reduce the number of MI paths.")
            used_sources.add(source_name)

        credentials = result["credentials"]
        objective = self._synthesize_objective(technique, summary)
        initial_access = {
            "principal_ref": self._seed_from_credentials(credentials),
            "method": credentials.get("entry_point", "compromised_identity"),
        }
        return AttackPathOverlay(
            name=path_name, objective=objective, initial_access=initial_access,
            metadata=path.get("metadata", {}), credentials=credentials,
            summary=summary)

    def _dispatch_macro(self, technique: str, attack_config: Dict,
                        entities: Dict[str, Dict], domain: str, mode: str,
                        macro_entities: Optional[Dict], path_name: str,
                        used_apps: set, used_users: set,
                        used_sources: set) -> Dict:
        """Dispatch to the matching macro with the entity maps it needs (mirrors the
        legacy cli dispatch). `attack_config` is the raw path dict — macros read their
        knobs via .get(), ignoring the technique/identities/resources keys."""
        mgr = self.attack_path_mgr
        E = entities
        common = dict(mode=mode, entities=macro_entities, path_name=path_name)
        if technique == "ApplicationOwnershipAbuse":
            return mgr.macro_application_ownership_abuse(
                attack_config, E["users"], E["applications"], domain,
                used_apps=used_apps, used_users=used_users, **common)
        if technique == "ApplicationAdministratorAbuse":
            return mgr.macro_application_administrator_abuse(
                attack_config, E["users"], E["applications"], domain,
                used_apps=used_apps, used_users=used_users, **common)
        if technique == "CloudAppAdministratorAbuse":
            return mgr.macro_cloud_app_administrator_abuse(
                attack_config, E["users"], E["applications"], domain,
                used_apps=used_apps, used_users=used_users, **common)
        if technique == "KeyVaultSecretTheft":
            return mgr.macro_keyvault_secret_theft(
                attack_config, E["applications"], E["key_vaults"], E["users"],
                E["applications"], domain, used_apps=used_apps, **common)
        if technique == "StorageCertificateTheft":
            return mgr.macro_storage_certificate_theft(
                attack_config, E["applications"], E["storage_accounts"], E["users"],
                E["applications"], domain, used_apps=used_apps, **common)
        if technique == "CosmosDBSecretTheft":
            return mgr.macro_cosmosdb_secret_theft(
                attack_config, E["applications"], E["cosmos_dbs"], E["users"],
                E["applications"], domain, used_apps=used_apps, **common)
        if technique == "ManagedIdentityAbuse":
            return mgr.macro_managed_identity_abuse(
                attack_config, E["applications"], E["key_vaults"],
                E["storage_accounts"], E["users"], domain, E["virtual_machines"],
                E["logic_apps"], E["automation_accounts"], E["function_apps"],
                used_apps=used_apps, used_users=used_users, used_sources=used_sources,
                cosmos_dbs=E["cosmos_dbs"], app_services=E["app_services"], **common)
        raise ScenarioConfigError(
            f"{path_name}: unknown technique '{technique}'.")

    @staticmethod
    def _legacy_entities_from_path(path: Dict) -> Dict[str, List[Dict]]:
        """Flatten a technique path's inline `identities:`/`resources:` into the legacy
        `entities:` shape the macros' targeted selectors expect ({kind: [{name, ...}]}),
        translating each entity's `ref` -> `name`. Order is preserved (the targeted
        selectors are positional — e.g. applications[0] is the looted app)."""
        out: Dict[str, List[Dict]] = {}
        for section in ("identities", "resources"):
            for kind, specs in (path.get(section) or {}).items():
                out[kind] = [
                    {("name" if k == "ref" else k): v
                     for k, v in spec.items() if k != "from"}
                    for spec in specs
                ]
        return out

    @staticmethod
    def _require_baseline_entities(technique: str, path: Dict,
                                   entities: Dict[str, Dict], path_name: str) -> None:
        """mode=random sources victims/targets from the baseline; if a required entity
        type is absent, fail clearly (the baseline-first contract) instead of letting
        the macro's random.choice blow up on an empty map."""
        needs: List = [("applications", "an application")]
        if path.get("initial_access", "user") == "user":
            needs.append(("users", "a user"))
        if technique in _TECHNIQUE_REQUIRED_RESOURCE:
            needs.append(_TECHNIQUE_REQUIRED_RESOURCE[technique])
        if technique == "ManagedIdentityAbuse":
            src = _MI_SOURCE_MAP.get(path.get("source_type", "vm"))
            tgt = _MI_TARGET_MAP.get(path.get("target_resource_type"))
            if src:
                needs.append((src, f"a {path.get('source_type', 'vm')}"))
            if tgt:
                needs.append((tgt, f"a {path.get('target_resource_type')}"))
        missing = [human for attr, human in needs if not entities.get(attr)]
        if missing:
            raise ScenarioConfigError(
                f"{path_name}: technique '{technique}' needs {', '.join(missing)} in "
                f"the baseline (mode=random picks victims/targets from it). Add the "
                f"count(s) to `baseline:` or declare the entities inline under the path."
            )

    @staticmethod
    def _synthesize_objective(technique: str, summary: Dict) -> Dict:
        """Build a (capability, target) objective from the macro summary so the
        reachability gate adjudicates the technique path like an explicit one."""
        if technique == "ManagedIdentityAbuse":
            capability = _MI_TARGET_CAPABILITY.get(summary.get("target_resource_type"))
            target = summary.get("target_name")
        else:
            capability, target_key = _TECHNIQUE_OBJECTIVES[technique]
            target = summary.get(target_key)
        return {
            "name": f"{technique} ({target})" if target else technique,
            "impact": "high",
            "capability": capability,
            "target_ref": target,
        }

    @staticmethod
    def _seed_from_credentials(credentials: Dict) -> Optional[str]:
        """The symbolic ref of the initial-access node — the reachability seed.
        For an exposed-host foothold it's the host the attacker lands on (controlling
        it already implies controlling its managed identity). For the credential
        vectors it's the compromised identity (user = UPN local part = var.users key;
        SP = app display_name)."""
        ia = credentials.get("initial_access")
        if ia in RESOURCE_FOOTHOLD_VECTORS:
            return credentials.get("foothold_resource")
        if ia == "user":
            upn = credentials.get("user_principal_name", "")
            return upn.split("@")[0] if "@" in upn else upn
        return credentials.get("service_principal_name")
