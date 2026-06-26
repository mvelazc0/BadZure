"""
primitives.py — the generic building blocks a BadZure lab is made of.

Every BadZure lab — no matter which attack technique it simulates — is built
from the same small set of generic actions: "assign an Entra role", "assign
Azure RBAC", "grant an API permission", "mint an app credential", "plant a
secret", "add a group member", and so on. This file defines those building
blocks (we call them PRIMITIVES) as plain Python classes, plus one container
(`DeploymentModel`) that holds an entire lab: its users / groups / apps /
resources and the list of building blocks wired between them.

This replaces the old technique-shaped approach where each attack path
(KeyVaultSecretTheft, StorageCertificateTheft, ...) had its own bespoke data
shape. Now a technique is just a recipe that produces these generic building
blocks, and the Terraform builder turns them into a real deployment. Each
building block below maps 1:1 to a variable family in terraform/generic.tf.

Two bookkeeping fields ride on every building block:
  - key:    the name of this entry in the Terraform variables (e.g.
            "automation_secret"). generic.tf adds the "random:" / "ap:" prefix
            to keys internally, so we keep them bare here. (The ONE place we add
            a prefix ourselves is a data_inject's credential_ref — see
            terraform_builder.py.)
  - origin: "random" (organizational baseline — the realistic decoys/noise that
            make the tenant look like a real org) or "attack_path" (a deliberate
            edge that supports one step of a simulated attack). Keeping these two
            apart is load-bearing: it drives reachability analysis, the narrative
            layer, and what defenders see in telemetry. It only decides which of
            the two Terraform variable families an entry lands in.

The field names and defaults below mirror the variable schemas in
terraform/generic.tf EXACTLY. Optional fields carry the same default generic.tf
declares via optional(...), so this file is the single source of truth for
"what does Terraform fill in when this field is omitted."
"""
from dataclasses import dataclass, field, fields, MISSING
from typing import Dict, List, Optional

RANDOM = "random"
ATTACK_PATH = "attack_path"


# =============================================================================
# Building blocks (primitives) — one class per generic.tf variable family.
# =============================================================================
@dataclass
class Primitive:
    """Shared base for every building block. `key`/`origin` are bookkeeping
    fields and are NOT written into the per-entry Terraform value (the builder
    strips them)."""
    key: str
    origin: str  # RANDOM | ATTACK_PATH


@dataclass
class EntraRoleAssignment(Primitive):
    """-> azuread_directory_role_assignment. Directory-wide unless scope_app_ref."""
    principal_ref: str
    principal_type: str                    # user | service_principal | group
    role: str                              # Entra role_definition_id (GUID)
    scope_app_ref: Optional[str] = None    # scope to this app's object; else directory


@dataclass
class AzureRbacAssignment(Primitive):
    """-> azurerm_role_assignment (control plane) or azurerm_cosmosdb_sql_role_assignment
    (data_plane=cosmos_sql). The universal substrate: KV/Storage/Cosmos/VM/etc."""
    principal_ref: str
    principal_type: str                          # user | service_principal | group | managed_identity
    role: str                                    # role_definition_name OR cosmos sql role GUID
    scope_type: str                              # subscription | resource_group | resource
    mi_source_type: Optional[str] = None         # managed_identity: vm|logic_app|automation_account|function_app|app_service
    scope_ref: Optional[str] = None              # rg name or resource key; ignored for subscription
    scope_resource_type: Optional[str] = None    # key_vault|storage_account|cosmos_db|virtual_machine|logic_app|automation_account|function_app|app_service
    data_plane: Optional[str] = None             # None (control plane) | cosmos_sql


@dataclass
class ApiPermission(Primitive):
    """-> azuread_app_role_assignment. Grant a Graph/Exchange app role to an SP."""
    principal_ref: str           # the SP (app key) receiving the permission
    permission_id: str           # app role / permission GUID
    api_type: str = "graph"      # graph | exchange


@dataclass
class AppCredential(Primitive):
    """-> azuread_application_password / azuread_application_certificate."""
    app_ref: str
    type: str                                          # password | certificate
    certificate_path: Optional[str] = None             # required for type=certificate
    display_name: str = "BadZureCredential"


@dataclass
class DataInject(Primitive):
    """-> azurerm_key_vault_secret / _certificate / storage_blob, OR (for
    location_type=cosmos_document) a document planted by the Python post-apply
    data-plane phase (src/dataplane.py) rather than Terraform. Plant material an
    attacker can loot. The app_secret join references an AppCredential by
    credential_ref (BARE key here; the builder origin-prefixes it to match
    g_inject_value indexing in generic.tf / the data-plane resolver)."""
    material: str                              # app_secret | app_certificate | app_client_id | literal
    location_type: str                         # key_vault_secret | key_vault_certificate | storage_blob | cosmos_document
    location_ref: str                          # key_vault / storage_account / cosmos_db ref
    name: str                                  # secret / certificate / blob name
    source_ref: Optional[str] = None           # app_ref for app_client_id / app_certificate
    credential_ref: Optional[str] = None       # AppCredential key for material=app_secret (bare)
    literal_value: Optional[str] = None        # for material=literal
    file_path: Optional[str] = None            # PFX/PEM/key for app_certificate / kv-cert import
    pfx_password: str = ""                      # PFX password for key_vault_certificate import


@dataclass
class GroupMembership(Primitive):
    """-> azuread_group_member."""
    principal_ref: str
    principal_type: str   # user | service_principal | group
    group_ref: str


@dataclass
class AuMembership(Primitive):
    """-> azuread_administrative_unit_member. Members may be users or groups."""
    principal_ref: str
    principal_type: str   # user | group
    au_ref: str


@dataclass
class GroupOwnership(Primitive):
    """-> azuread_group.owners (set in main.tf; no standalone owner resource)."""
    principal_ref: str
    principal_type: str   # user | service_principal
    group_ref: str


@dataclass
class AppOwnership(Primitive):
    """-> azuread_application_owner (users / SPs only; groups can't own apps)."""
    principal_ref: str
    principal_type: str   # user | service_principal
    app_ref: str


@dataclass
class InitialAccessVector(Primitive):
    """The attacker's ENTRY point — how they first land in the lab. Unlike the
    nine edge primitives above, this one does NOT map to a generic.tf variable
    family: for the resource-foothold methods (exposed_rdp/exposed_ssh) it is
    consumed by the Terraform builder as a PROJECTION onto the target VM's spec
    (an `expose_to_internet` flag + optional weak admin password the existing
    main.tf NSG reads), the same way is_attack_path_group is derived onto groups.
    It also seeds the reachability walk: the seed node is `target_ref` (a compute
    resource for footholds), and controlling that host already implies controlling
    its managed identity, so existing MI chains continue from it unchanged.

    The identity methods (compromised_credentials) are the historical default and
    do not emit this primitive — the seed is simply the identity. This primitive is
    minted only for the non-credential vectors. See
    dev-docs/redesign/initial-access-vectors.md.
    """
    method: str                          # exposed_rdp | exposed_ssh | vulnerable_web_app
                                         #   | exposed_credentials | compromised_credentials
    target_ref: str                      # node the attacker lands on (a VM for rdp/ssh)
    target_type: str                     # virtual_machine | function_app | storage_account
                                         #   | user | service_principal
    grants: str                          # capability at the foothold: code_execution
                                         #   | read_blob | control_principal
    variant: Optional[str] = None        # future per-method sub-type (windows|linux, sqli|lfi|rce)
    expose_to_internet: bool = False     # False -> NSG source = operator IP (default, safe)
                                         #   True -> add a 0.0.0.0/0 (Internet) allow rule
    credential: str = "known"            # known (strong, operator-known) | weak (brute-forceable)
    loot_ref: Optional[str] = None       # exposed_credentials: the DataInject this reads


# =============================================================================
# Deployment model — a whole lab: its entities + the building blocks between them.
# =============================================================================
@dataclass
class DeploymentModel:
    """Everything needed to write a complete terraform.tfvars.json for one lab.

    Entity maps are keyed by SYMBOLIC name (e.g. "alice", "app_highpriv") — the
    same key generic.tf's principal_ref/scope_ref/etc. resolve against. They are
    NOT re-keyed by UPN/display_name (that legacy behavior detaches refs from
    their Terraform resource address). Entity dict VALUES reuse EntityGenerator's
    output shapes verbatim.
    """
    # Environment scalars (passthrough)
    tenant_id: str = ""
    domain: str = ""
    subscription_id: str = ""
    public_ip: str = ""
    azure_config_dir: str = ""

    # Entity maps (symbolic-keyed) — reuse EntityGenerator output shapes
    users: Dict = field(default_factory=dict)
    groups: Dict = field(default_factory=dict)
    applications: Dict = field(default_factory=dict)
    administrative_units: Dict = field(default_factory=dict)
    resource_groups: Dict = field(default_factory=dict)
    key_vaults: Dict = field(default_factory=dict)
    storage_accounts: Dict = field(default_factory=dict)
    virtual_machines: Dict = field(default_factory=dict)
    logic_apps: Dict = field(default_factory=dict)
    automation_accounts: Dict = field(default_factory=dict)
    function_apps: Dict = field(default_factory=dict)
    app_services: Dict = field(default_factory=dict)
    cosmos_dbs: Dict = field(default_factory=dict)

    # The building blocks wired between the entities above — a flat list.
    primitives: List[Primitive] = field(default_factory=list)

    # Convenience entity-map registry: symbolic entity-kind -> attribute name.
    ENTITY_MAPS = (
        "users", "groups", "applications", "administrative_units",
        "resource_groups", "key_vaults", "storage_accounts",
        "virtual_machines", "logic_apps", "automation_accounts",
        "function_apps", "app_services", "cosmos_dbs",
    )

    def entity_keys(self, attr: str):
        """Symbolic keys declared for one entity map (for ref validation)."""
        return set(getattr(self, attr).keys())


# =============================================================================
# Schema helpers — read each building block's value fields + optional defaults
# straight from the class definition (single source of truth).
# =============================================================================
_BOOKKEEPING_FIELDS = {"key", "origin"}


def value_fields(cls) -> List[str]:
    """Ordered per-entry Terraform value-field names for a building block
    (everything except the bookkeeping fields key/origin)."""
    return [f.name for f in fields(cls) if f.name not in _BOOKKEEPING_FIELDS]


def optional_defaults(cls) -> Dict[str, object]:
    """Map of {optional_field: declared_default} for a building block — the
    values Terraform's optional(...) fills in when the field is omitted. Used to
    canonicalize hand-written fixtures before comparison."""
    out = {}
    for f in fields(cls):
        if f.name in _BOOKKEEPING_FIELDS:
            continue
        if f.default is not MISSING:
            out[f.name] = f.default
        elif f.default_factory is not MISSING:  # type: ignore[attr-defined]
            out[f.name] = f.default_factory()   # type: ignore[attr-defined]
    return out
