"""
primitive_handlers.py — how each building block maps to Terraform.

For every building block defined in primitives.py, this file answers two
questions:

  - base_family: which terraform/generic.tf variable does it feed? (e.g.
    "azure_rbac_assignments"). The Terraform builder prepends "random_" /
    "attack_path_" based on the block's origin to get the full variable name.
  - refs(instance): which entities does this block point at? (its principal,
    its scope, the credential it plants, ...). The builder uses this to check
    that every reference resolves to a real entity BEFORE deploying.

This lookup is what replaced the old `if technique == 'KeyVaultSecretTheft':
... elif ...` ladders that used to be copy-pasted across cli.py,
config_manager.py and attack_path_manager.py. Adding a brand-new attack surface
(Intune, Purview, Kubernetes) is now just: define a building block in
primitives.py and add one entry to the table at the bottom of this file — no
changes to the builder itself.

Writing each block's Terraform value is uniform (every field except the
bookkeeping key/origin), so that lives in the builder via
primitives.value_fields() rather than being repeated here — these handlers only
carry what is genuinely block-specific.
"""
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple, Type

from src.primitives import (
    Primitive,
    EntraRoleAssignment,
    AzureRbacAssignment,
    ApiPermission,
    AppCredential,
    DataInject,
    GroupMembership,
    AuMembership,
    GroupOwnership,
    AppOwnership,
)

# Special ref-kind: the value names another building block (an AppCredential
# key), not an entity in one of the entity maps.
CREDENTIAL = "__credential__"


# --- principal_type / source-type / scope-type -> entity-map attribute --------
PRINCIPAL_TYPE_TO_MAP = {
    "user": "users",
    "group": "groups",
    "service_principal": "applications",  # SPs are backed by an app; ref is the app key
}

MI_SOURCE_TO_MAP = {
    "vm": "virtual_machines",
    "logic_app": "logic_apps",
    "automation_account": "automation_accounts",
    "function_app": "function_apps",
}

SCOPE_RESOURCE_TO_MAP = {
    "key_vault": "key_vaults",
    "storage_account": "storage_accounts",
    "cosmos_db": "cosmos_dbs",
    "virtual_machine": "virtual_machines",
    "logic_app": "logic_apps",
    "automation_account": "automation_accounts",
    "function_app": "function_apps",
}

INJECT_LOCATION_TO_MAP = {
    "key_vault_secret": "key_vaults",
    "key_vault_certificate": "key_vaults",
    "storage_blob": "storage_accounts",
    # Data-plane-only (no Terraform resource): planted by the Python post-apply
    # data-plane phase (src/dataplane.py), not generic.tf. Listed here so
    # location_ref still ref-validates against the cosmos_dbs entity map.
    "cosmos_document": "cosmos_dbs",
}

# location_types that have NO Terraform resource — the builder keeps them out of
# the data_injects tfvars families, and src/dataplane.py plants them after apply.
DATAPLANE_LOCATION_TYPES = frozenset({"cosmos_document"})


@dataclass(frozen=True)
class Ref:
    """One reference a building block makes. `kinds` is the tuple of entity-map
    attribute names the value may resolve against (or the CREDENTIAL sentinel).
    `value` of None means the ref is absent (optional, skip)."""
    field: str
    value: Optional[str]
    kinds: Tuple[str, ...]


def _principal_map(principal_type: str, mi_source_type: Optional[str]) -> Tuple[str, ...]:
    if principal_type == "managed_identity":
        m = MI_SOURCE_TO_MAP.get(mi_source_type)
        return (m,) if m else ()
    m = PRINCIPAL_TYPE_TO_MAP.get(principal_type)
    return (m,) if m else ()


# --- refs() per building block ------------------------------------------------
def _refs_entra_role(i: EntraRoleAssignment) -> List[Ref]:
    return [
        Ref("principal_ref", i.principal_ref, _principal_map(i.principal_type, None)),
        Ref("scope_app_ref", i.scope_app_ref, ("applications",)),
    ]


def _refs_azure_rbac(i: AzureRbacAssignment) -> List[Ref]:
    refs = [Ref("principal_ref", i.principal_ref,
                _principal_map(i.principal_type, i.mi_source_type))]
    if i.scope_type == "resource_group":
        refs.append(Ref("scope_ref", i.scope_ref, ("resource_groups",)))
    elif i.scope_type == "resource":
        kinds = SCOPE_RESOURCE_TO_MAP.get(i.scope_resource_type)
        refs.append(Ref("scope_ref", i.scope_ref, (kinds,) if kinds else ()))
    # subscription scope -> no scope_ref
    return refs


def _refs_api_permission(i: ApiPermission) -> List[Ref]:
    return [Ref("principal_ref", i.principal_ref, ("applications",))]


def _refs_app_credential(i: AppCredential) -> List[Ref]:
    return [Ref("app_ref", i.app_ref, ("applications",))]


def _refs_data_inject(i: DataInject) -> List[Ref]:
    refs = [
        Ref("source_ref", i.source_ref, ("applications",)),
        Ref("credential_ref", i.credential_ref, (CREDENTIAL,)),
        Ref("location_ref", i.location_ref,
            (INJECT_LOCATION_TO_MAP.get(i.location_type),)
            if INJECT_LOCATION_TO_MAP.get(i.location_type) else ()),
    ]
    return refs


def _refs_group_membership(i: GroupMembership) -> List[Ref]:
    return [
        Ref("principal_ref", i.principal_ref, _principal_map(i.principal_type, None)),
        Ref("group_ref", i.group_ref, ("groups",)),
    ]


def _refs_au_membership(i: AuMembership) -> List[Ref]:
    return [
        Ref("principal_ref", i.principal_ref, _principal_map(i.principal_type, None)),
        Ref("au_ref", i.au_ref, ("administrative_units",)),
    ]


def _refs_group_ownership(i: GroupOwnership) -> List[Ref]:
    return [
        Ref("principal_ref", i.principal_ref, _principal_map(i.principal_type, None)),
        Ref("group_ref", i.group_ref, ("groups",)),
    ]


def _refs_app_ownership(i: AppOwnership) -> List[Ref]:
    return [
        Ref("principal_ref", i.principal_ref, _principal_map(i.principal_type, None)),
        Ref("app_ref", i.app_ref, ("applications",)),
    ]


@dataclass(frozen=True)
class Handler:
    base_family: str
    refs: Callable[[Primitive], List[Ref]]


# The handler table — looked up by building-block type. This is the seam where
# new attack surfaces plug in.
PRIMITIVE_HANDLERS: Dict[Type[Primitive], Handler] = {
    EntraRoleAssignment: Handler("entra_role_assignments", _refs_entra_role),
    AzureRbacAssignment: Handler("azure_rbac_assignments", _refs_azure_rbac),
    ApiPermission:       Handler("api_permission_assignments", _refs_api_permission),
    AppCredential:       Handler("app_credentials", _refs_app_credential),
    DataInject:          Handler("data_injects", _refs_data_inject),
    GroupMembership:     Handler("group_membership_assignments", _refs_group_membership),
    AuMembership:        Handler("au_membership_assignments", _refs_au_membership),
    GroupOwnership:      Handler("group_ownership_assignments", _refs_group_ownership),
    AppOwnership:        Handler("app_ownership_assignments", _refs_app_ownership),
}


def handler_for(instance: Primitive) -> Handler:
    h = PRIMITIVE_HANDLERS.get(type(instance))
    if h is None:
        raise KeyError(f"No handler for building block type {type(instance).__name__}")
    return h


# Reverse map: full Terraform variable name (with origin prefix) -> building-block
# class. Lets callers (e.g. the golden test) line a variable's entries up against
# the right class schema.
FAMILY_TO_CLASS: Dict[str, Type[Primitive]] = {}
for _cls, _h in PRIMITIVE_HANDLERS.items():
    FAMILY_TO_CLASS[f"random_{_h.base_family}"] = _cls
    FAMILY_TO_CLASS[f"attack_path_{_h.base_family}"] = _cls

# All 18 generic Terraform variable names (9 building blocks x 2 origins).
GENERIC_FAMILIES = tuple(FAMILY_TO_CLASS.keys())
