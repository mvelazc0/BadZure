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
  - Role / permission values are taken VERBATIM (GUID passthrough). Name -> GUID
    resolution arrives in Slice 2 (`name_resolver.py`).
  - The random `pool:` layer and `from: pool` ref-picking arrive in Slice 3; a
    pool section or a `from: pool` ref raises a clear "not yet" error here.

The declarative-vs-legacy discriminator lives in cli.py (`_is_declarative_config`);
by the time the loader runs we already know the config is the new shape.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.entity_generator import EntityGenerator
from src.primitives import (
    DeploymentModel, ATTACK_PATH,
    EntraRoleAssignment, AzureRbacAssignment, ApiPermission, AppCredential,
    DataInject, GroupMembership, GroupOwnership, AppOwnership, AuMembership,
)
from src.primitive_handlers import SCOPE_RESOURCE_TO_MAP, MI_SOURCE_TO_MAP


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

# Default resource group synthesized for inline resources that don't name one.
_DEFAULT_RG = "badzure-default-rg"
_DEFAULT_RG_LOCATION = "West US"


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


@dataclass
class ScenarioModel:
    """What the loader returns: the deployable DeploymentModel + one overlay per
    declarative attack path."""
    model: DeploymentModel
    attack_paths: List[AttackPathOverlay] = field(default_factory=list)


class ScenarioLoader:
    """Turns a declarative graph config into a ScenarioModel."""

    def __init__(self, entity_generator: Optional[EntityGenerator] = None):
        self.generator = entity_generator or EntityGenerator()

    # -- public API -----------------------------------------------------------
    def load(self, config: Dict, tenant_id: str = "", domain: str = "",
             subscription_id: str = "", public_ip: str = "",
             azure_config_dir: str = "") -> ScenarioModel:
        if config.get("pool"):
            raise ScenarioConfigError(
                "The 'pool' (random org-baseline) layer is not implemented yet — "
                "it arrives in Slice 3. Remove the 'pool:' section for now."
            )
        attack_paths = config.get("attack_paths") or {}
        if not attack_paths:
            raise ScenarioConfigError(
                "Declarative config declares no attack_paths to build."
            )

        # 1. Build every inline-declared entity across all paths into symbolic-keyed
        #    maps (the same keys the assignments below reference).
        entities = self._build_entities(attack_paths)
        ref_kind = self._index_refs(entities)

        # 2. Walk each path, emitting primitives + collecting the narrative overlay.
        primitives: List = []
        overlays: List[AttackPathOverlay] = []
        for path_name, path in attack_paths.items():
            overlay = self._compile_path(path_name, path, ref_kind, entities,
                                         primitives, domain)
            overlays.append(overlay)

        model = DeploymentModel(
            tenant_id=tenant_id, domain=domain, subscription_id=subscription_id,
            public_ip=public_ip, azure_config_dir=azure_config_dir,
            primitives=primitives, **entities,
        )
        return ScenarioModel(model=model, attack_paths=overlays)

    # -- entity construction --------------------------------------------------
    def _build_entities(self, attack_paths: Dict) -> Dict[str, Dict]:
        """Collect inline identities/resources across paths and build the symbolic
        entity maps via EntityGenerator's *_targeted methods (reusing their default
        attributes: VM os_type, KV sku, ...). Returns a dict of entity-map attr ->
        entity dict, ready to splat into DeploymentModel."""
        # Gather raw specs per entity kind, deduped by ref (declared once, used
        # by many assignments). Service principals fold into applications.
        specs: Dict[str, List[Dict]] = {}
        seen: Dict[str, set] = {}

        def add_spec(kind: str, raw: Dict):
            ref = self._spec_name(raw)
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

    @staticmethod
    def _spec_name(raw: Dict) -> str:
        ref = raw.get("ref")
        if not ref:
            raise ScenarioConfigError(f"Entity spec is missing required 'ref': {raw}")
        if raw.get("from"):
            raise ScenarioConfigError(
                f"Entity '{ref}' uses `from: {raw['from']}` (pool-picking), which "
                "is not implemented yet — it arrives in Slice 3."
            )
        return ref

    @classmethod
    def _to_targeted_spec(cls, raw: Dict) -> Dict:
        """Translate a declarative `{ref: X, ...}` entity into the `{name: X, ...}`
        shape the EntityGenerator *_targeted methods expect."""
        spec = {k: v for k, v in raw.items() if k != "ref"}
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

        # assignments -> the matching assignment primitive.
        for idx, a in enumerate(path.get("assignments", [])):
            aid = a.get("id") or f"a{idx}"
            primitives.append(
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

        credentials = self._operator_credentials(
            path_name, path, ref_kind, entities, primitives, cred_ref_to_key, domain
        )
        return AttackPathOverlay(
            name=path_name,
            objective=path.get("objective", {}),
            initial_access=path.get("initial_access", {}),
            metadata=path.get("metadata", {}),
            steps=path.get("steps", []),
            credentials=credentials,
            summary={"path_name": path_name,
                     "objective": path.get("objective", {}).get("name")},
        )

    @staticmethod
    def _key(path_name: str, local: str) -> str:
        """Namespace a path-local id into a globally-unique Terraform variable key."""
        return f"{path_name}__{local}"

    # -- assignment -> primitive ----------------------------------------------
    def _emit_assignment(self, key: str, a: Dict, ref_kind: Dict[str, str],
                         path_name: str):
        atype = a.get("type")
        if atype == "entra_role":
            return EntraRoleAssignment(
                key, ATTACK_PATH,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                role=a["role"], scope_app_ref=a.get("scope_app_ref"),
            )
        if atype == "azure_rbac":
            scope_type, scope_resource_type = self._scope(a, ref_kind, path_name)
            return AzureRbacAssignment(
                key, ATTACK_PATH,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                role=a["role"], scope_type=scope_type,
                mi_source_type=a.get("mi_source") or a.get("mi_source_type"),
                scope_ref=a.get("scope_ref"),
                scope_resource_type=scope_resource_type,
                data_plane=a.get("data_plane"),
            )
        if atype == "api_permission":
            return ApiPermission(
                key, ATTACK_PATH,
                principal_ref=a["principal_ref"],
                permission_id=a.get("permission_id") or a.get("app_role"),
                api_type=a.get("api_type", "graph"),
            )
        if atype == "group_membership":
            return GroupMembership(
                key, ATTACK_PATH,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                group_ref=a["group_ref"],
            )
        if atype == "group_ownership":
            return GroupOwnership(
                key, ATTACK_PATH,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                group_ref=a["group_ref"],
            )
        if atype == "app_ownership":
            return AppOwnership(
                key, ATTACK_PATH,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                app_ref=a["app_ref"],
            )
        if atype == "au_membership":
            return AuMembership(
                key, ATTACK_PATH,
                principal_ref=a["principal_ref"],
                principal_type=self._principal_type(a, ref_kind, path_name),
                au_ref=a["au_ref"],
            )
        raise ScenarioConfigError(
            f"{path_name}: assignment '{key}' has unknown type '{atype}'."
        )

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
