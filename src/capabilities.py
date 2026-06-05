"""
capabilities.py — the goal->primitive interpretation layer for reachability.

A reachability OBJECTIVE is a `(capability, target)` predicate: "obtain code
execution on vm01", "read secrets from kv01", "become Global Administrator",
"exfiltrate mail from the finance mailbox". A capability is the high-level thing
an attacker wants; it is satisfied by a SET of concrete primitives / roles /
permissions — and there is usually MORE THAN ONE WAY to achieve it (Owner OR
Contributor OR "Virtual Machine Contributor" all confer code execution on a VM).

This module is that mapping. It is deliberately the place where the OPINIONS live
("Virtual Machine Contributor implies code execution"), kept separate from the raw
role / permission GUID catalogs in `constants.py` (which are FACTS Microsoft
publishes, not interpretations). `reachability.py` consumes the helpers below; it
never hard-codes a role name.

It is intentionally SMALL and INCOMPLETE right now — it models only the
capabilities the labs we deploy today actually exercise. It WILL grow as we add
attack surfaces and construct more complex chains; growth is just adding role
names to the sets below (or a new capability token + a `_dispatch` arm in
reachability.py). Until a capability is modeled here, an objective that uses it is
reported "unverified" rather than failing the build (see reachability.enforce).

Two structural notions the reachability walk leans on:
  - CONTROL_ROLES: an Azure RBAC role that lets you run code on / fully operate a
    compute resource. Holding it means you also gain that resource's MANAGED
    IDENTITY (the basis of every ManagedIdentityAbuse chain).
  - READ_ROLES: an Azure RBAC role that lets you read the loot OUT of a data
    resource (Key Vault secret, storage blob, Cosmos document). This is what makes
    a planted `data_inject` lootable mid-walk, and what a `read_secrets`-style
    objective checks at the end.
"""
from typing import Set

from src.constants import GRAPH_API_PERMISSIONS, EXCHANGE_API_PERMISSIONS

# Resource-type tokens here MUST match the keys of
# primitive_handlers.SCOPE_RESOURCE_TO_MAP (key_vault, storage_account, ...).

# --- CONTROL: roles that grant code execution / full operation of a resource ---
# Holding one of these over a compute resource lets the attacker run code on it
# and therefore act as its managed identity. Owner/Contributor are universal;
# the rest are the resource-specific "contributor" roles.
CONTROL_ROLES = {
    "virtual_machine": {
        "Owner", "Contributor", "Virtual Machine Contributor",
        "Virtual Machine Administrator Login", "Virtual Machine User Login",
    },
    "logic_app": {"Owner", "Contributor", "Logic App Contributor"},
    "automation_account": {"Owner", "Contributor", "Automation Contributor"},
    "function_app": {"Owner", "Contributor", "Website Contributor"},
}

# --- READ: roles that let you read the secrets/data OUT of a data resource ------
# (Permissive on purpose — in access-policy mode a control-plane "Contributor" can
# grant itself data-plane access, so it counts as a reader for lab simulation.)
READ_ROLES = {
    "key_vault": {
        "Owner", "Contributor", "Key Vault Contributor",
        "Key Vault Administrator", "Key Vault Secrets User",
        "Key Vault Secrets Officer", "Key Vault Certificates Officer",
    },
    "storage_account": {
        "Owner", "Contributor", "Storage Account Contributor",
        "Storage Blob Data Reader", "Storage Blob Data Contributor",
        "Storage Blob Data Owner",
    },
    "cosmos_db": {
        "Owner", "Contributor", "Cosmos DB Account Reader Role",
        "DocumentDB Account Contributor",
    },
}

# --- Capability token -> the data-resource read it checks ----------------------
# `read_secrets`/`read_storage`/`read_cosmos` are the loot-objective tokens; each
# maps to the resource type whose READ_ROLES satisfy it.
READ_CAPABILITY_RESOURCE = {
    "read_secrets": "key_vault",
    "read_storage": "storage_account",
    "read_cosmos": "cosmos_db",
}


def _mail_permission_guids() -> Set[str]:
    """GUIDs of the Graph/Exchange permissions that let an app read mailbox
    contents (the `read_mail` capability). Pulled from constants so a catalog
    override flows through automatically."""
    wanted = {
        "Mail.Read", "Mail.ReadWrite", "Mail.Read.All", "Mail.ReadWrite.All",
        "Mail.ReadBasic", "Mail.ReadBasic.All",
    }
    guids: Set[str] = set()
    for catalog in (GRAPH_API_PERMISSIONS, EXCHANGE_API_PERMISSIONS):
        for name, meta in catalog.items():
            if name in wanted or "Mail.Read" in name or name == "ApplicationImpersonation":
                guid = meta.get("id") if isinstance(meta, dict) else None
                if guid:
                    guids.add(guid)
    return guids


MAIL_PERMISSION_GUIDS = _mail_permission_guids()


# --- helpers the reachability walk calls --------------------------------------
def rbac_controls_resource(role: str, resource_type: str) -> bool:
    """Does this Azure RBAC role let the holder run code on / operate a resource
    of `resource_type` (and thus inherit its managed identity)?"""
    return role in CONTROL_ROLES.get(resource_type, ())


def rbac_reads_resource(role: str, resource_type: str) -> bool:
    """Does this Azure RBAC role let the holder read secrets/data out of a
    resource of `resource_type`?"""
    return role in READ_ROLES.get(resource_type, ())


def mail_permission_guids() -> Set[str]:
    return MAIL_PERMISSION_GUIDS


# Objective capability tokens this module can adjudicate. An objective whose
# `capability` is not in here is reported "unverified" (non-fatal) by the gate.
KNOWN_CAPABILITIES = (
    {"entra_role", "read_mail", "code_execution", "control_principal"}
    | set(READ_CAPABILITY_RESOURCE)
)
