"""
vocabulary.py — the data-driven registry of what a BadZure lab can deploy.

This is the SINGLE source of the deployable vocabulary, read by three consumers so
they never drift:
  - the org-design JSON schema the LLM emits (`org_generator.py`),
  - the system prompt's "bounded vocabulary contract" (what the LLM is allowed to
    reference), and
  - validation (names that must resolve).

Why a registry (locked decision #9 of the LLM-org-baseline phase): the richer Azure
resource catalog + archetypes + custom roles are deferred to a later slice. Keeping
the vocabulary as DATA means adding a resource type later is a registry entry +
Terraform — not a rewrite of the generation layer. Everything the generator knows
about "what exists" flows from here.

Nothing in here is attack-path-specific; it describes the org-baseline surface.
"""
from typing import Dict, List

from src.scenario_loader import ASSIGNMENT_TYPES  # the 7 assignment-type tokens
from src.constants import (
    ENTRA_ROLES, HIGH_PRIVILEGED_ENTRA_ROLES, GRAPH_API_PERMISSIONS,
)


# =============================================================================
# Entity kinds the substrate can create + the fields a spec may set.
# `ref` (the symbolic name) is implicit on every kind. Resource kinds attach to a
# resource_group. These mirror EntityGenerator's *_targeted spec fields.
# =============================================================================
IDENTITY_KINDS: Dict[str, Dict] = {
    "users": {"fields": ["ref"]},
    "groups": {"fields": ["ref"]},
    "applications": {"fields": ["ref"], "note": "a service principal (app registration)"},
    "administrative_units": {"fields": ["ref"]},
}

RESOURCE_KINDS: Dict[str, Dict] = {
    "resource_groups": {"fields": ["ref", "location"]},
    "key_vaults": {"fields": ["ref", "resource_group"]},
    "storage_accounts": {"fields": ["ref", "resource_group"]},
    "virtual_machines": {"fields": ["ref", "resource_group", "os_type"]},
    "logic_apps": {"fields": ["ref", "resource_group"]},
    "automation_accounts": {"fields": ["ref", "resource_group"]},
    "function_apps": {"fields": ["ref", "resource_group", "os_type"]},
    "cosmos_dbs": {"fields": ["ref", "resource_group", "database_name", "container_name"]},
}

# Assignment type -> the fields the org-design may set (beyond `type`). Mirrors
# scenario_loader._emit_assignment. principal_type/scope are inferred from refs.
ASSIGNMENT_FIELDS: Dict[str, List[str]] = {
    "group_membership": ["principal_ref", "group_ref"],
    "group_ownership": ["principal_ref", "group_ref"],
    "app_ownership": ["principal_ref", "app_ref"],
    "au_membership": ["principal_ref", "au_ref"],
    "entra_role": ["principal_ref", "role"],
    "azure_rbac": ["principal_ref", "role", "scope_ref"],
    "api_permission": ["principal_ref", "app_role", "api_type"],
}

# A curated set of common Azure built-in RBAC role NAMES (Azure RBAC roles pass
# through verbatim — Terraform takes the name directly). This is the realistic
# baseline palette the LLM should draw from; it is NOT exhaustive of Azure's
# hundreds of roles. Expanding this is part of the deferred catalog slice.
COMMON_AZURE_RBAC_ROLES: List[str] = [
    "Owner", "Contributor", "Reader",
    "Storage Blob Data Owner", "Storage Blob Data Contributor", "Storage Blob Data Reader",
    "Storage Account Contributor", "Storage Queue Data Contributor",
    "Key Vault Administrator", "Key Vault Secrets User", "Key Vault Secrets Officer",
    "Key Vault Reader", "Key Vault Certificates Officer",
    "Virtual Machine Contributor", "Virtual Machine Administrator Login",
    "Website Contributor", "Web Plan Contributor",
    "Cosmos DB Account Reader Role", "DocumentDB Account Contributor",
    "Network Contributor", "Monitoring Reader", "Monitoring Contributor",
    "User Access Administrator",
]

# A curated set of common, realistic Graph application permissions (delegated/app
# roles). Validation accepts ANY permission the resolver knows; this list is what
# the prompt advertises so generated orgs stay believable rather than exotic.
COMMON_GRAPH_PERMISSIONS: List[str] = [
    "User.Read.All", "User.ReadWrite.All",
    "Group.Read.All", "GroupMember.Read.All",
    "Directory.Read.All",
    "Application.Read.All",
    "Mail.Read", "Mail.Send",
    "Files.Read.All", "Sites.Read.All",
    "Calendars.Read", "People.Read.All",
    "AuditLog.Read.All", "Reports.Read.All",
]


def entra_role_names() -> List[str]:
    """Low-privileged Entra role names for the baseline (the high-privileged roles
    are reserved for attack paths — baseline noise must not look like the escalation
    a defender is hunting)."""
    high = set(HIGH_PRIVILEGED_ENTRA_ROLES)
    return sorted(n for n, guid in ENTRA_ROLES.items()
                  if n not in high and guid not in high)


def graph_permission_names() -> List[str]:
    """Curated common Graph permissions that are known to the resolver."""
    return [p for p in COMMON_GRAPH_PERMISSIONS if p in GRAPH_API_PERMISSIONS]


def render_for_prompt() -> str:
    """A compact text block describing the deployable vocabulary, embedded in the
    system prompt so the LLM only references things that can actually deploy."""
    lines: List[str] = []
    lines.append("IDENTITY KINDS (each entity has a unique `ref`):")
    for kind, meta in IDENTITY_KINDS.items():
        note = f"  — {meta['note']}" if meta.get("note") else ""
        lines.append(f"  - {kind}: fields {meta['fields']}{note}")
    lines.append("")
    lines.append("RESOURCE KINDS (attach to a resource_group via `resource_group`):")
    for kind, meta in RESOURCE_KINDS.items():
        lines.append(f"  - {kind}: fields {meta['fields']}")
    lines.append("")
    lines.append("ASSIGNMENT TYPES (principal_type/scope are inferred from the refs):")
    for atype in sorted(ASSIGNMENT_TYPES):
        lines.append(f"  - {atype}: fields {ASSIGNMENT_FIELDS.get(atype, [])}")
    lines.append("")
    lines.append("ENTRA ROLE NAMES (low-privileged, for realistic delegation):")
    lines.append("  " + ", ".join(entra_role_names()))
    lines.append("")
    lines.append("AZURE RBAC ROLE NAMES (common built-ins):")
    lines.append("  " + ", ".join(COMMON_AZURE_RBAC_ROLES))
    lines.append("")
    lines.append("GRAPH PERMISSION NAMES (common app roles):")
    lines.append("  " + ", ".join(graph_permission_names()))
    return "\n".join(lines)
