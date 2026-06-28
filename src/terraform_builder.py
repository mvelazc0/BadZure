"""
terraform_builder.py — turns a described lab into Terraform input.

Takes a DeploymentModel (the building-block description of a lab) and produces
the complete terraform.tfvars.json that Terraform consumes, targeting the
generic primitives in terraform/generic.tf. Pair this with terraform_manager.py:
the BUILDER writes the Terraform variables, the MANAGER runs terraform
init/apply/destroy.

It knows nothing about specific attack techniques (KeyVaultSecretTheft etc.) —
only the generic building blocks. That's the whole point: techniques become
recipes that produce building blocks, and this one file deploys any of them.

Three cross-block jobs that don't belong to a single handler live here:

  1. is_attack_path_group DERIVATION — a group is "role-assignable" only if some
     EntraRoleAssignment (random OR attack_path) targets it. (Azure RBAC
     targeting a group does NOT count.) Azure fixes this flag at group creation
     time, so we must work it out up front rather than letting the operator
     hand-set it.

  2. Reference checking — every *_ref must point at a real entity of the right
     kind, and each data_inject material (app_secret / app_client_id /
     app_certificate / literal) must carry its companion field. We catch this in
     Python in milliseconds instead of 8 minutes into a terraform apply.

  3. credential_ref origin-prefixing — when a data_inject plants an app secret,
     its credential_ref must be rewritten to the ORIGIN-PREFIXED name of the
     credential it plants (e.g. "automation_secret" -> "ap:automation_secret"),
     because g_inject_value in generic.tf looks the secret up in an
     already-merged map. The prefix comes from the *referenced credential's*
     origin, not the inject's — hence a cross-block lookup.
"""
from typing import Dict, List
import logging

from src.primitives import (
    DeploymentModel, Primitive, EntraRoleAssignment, AzureRbacAssignment, ApiPermission,
    AppCredential, DataInject, GroupMembership, GroupOwnership, AppOwnership, AuMembership,
    InitialAccessVector, RANDOM, ATTACK_PATH, value_fields,
)
from src.primitive_handlers import handler_for, CREDENTIAL, DATAPLANE_LOCATION_TYPES
from src.constants import (
    RESOURCE_FOOTHOLD_VECTORS, WEAK_FOOTHOLD_PASSWORD, FOOTHOLD_VECTOR_PROTOCOL,
    WEBAPP_FOOTHOLD_VECTORS, WEBAPP_VARIANT_DIR, WEBAPP_DEFAULT_VARIANT,
)


class LabValidationError(ValueError):
    """Raised when a lab description has a broken reference or structural flaw."""


_ORIGIN_FAMILY_PREFIX = {RANDOM: "random", ATTACK_PATH: "attack_path"}
_ORIGIN_KEY_PREFIX = {RANDOM: "random:", ATTACK_PATH: "ap:"}

# Relationship assignments whose Azure/Terraform resource is FULLY defined by their
# value-fields, and which Azure rejects as a duplicate if emitted twice (e.g. an
# azure_rbac role assignment -> 409 RoleAssignmentExists; a repeated group membership /
# ownership / Entra-role / API permission). Two of these with identical value-fields
# create the SAME resource, so they are collapsed to one before emit — making any config
# robust no matter how it was authored (LLM, agent, or by hand). They are idempotent, so
# dropping the duplicate is a no-op semantically. Credentials / data_injects / initial-
# access vectors are NOT deduped (a credential_ref binds to one by key, and identical-
# looking injects/creds can be legitimately distinct).
_DEDUPE_TYPES = (
    EntraRoleAssignment, AzureRbacAssignment, ApiPermission,
    GroupMembership, GroupOwnership, AppOwnership, AuMembership,
)


def dedupe_assignments(primitives: List[Primitive]) -> "tuple[List[Primitive], int]":
    """Return (deduped_primitives, n_removed): collapse relationship assignments that
    would create the SAME Azure resource (same type + identical value-fields, regardless
    of origin), keeping the first occurrence. Non-relationship primitives pass through."""
    seen = set()
    out: List[Primitive] = []
    removed = 0
    for p in primitives:
        if isinstance(p, _DEDUPE_TYPES):
            identity = (type(p).__name__,
                        tuple((f, getattr(p, f)) for f in value_fields(type(p))))
            if identity in seen:
                removed += 1
                continue
            seen.add(identity)
        out.append(p)
    return out, removed



def origin_prefixed_key(bare_key: str, origin: str) -> str:
    """Origin-prefix a credential key the way generic.tf keys credentials (and the
    TF generic_app_credentials output): 'foo' + attack_path -> 'ap:foo'. Shared so
    the Python data-plane phase (src/dataplane.py) resolves an app_secret inject
    against the SAME key the builder writes."""
    return _ORIGIN_KEY_PREFIX[origin] + bare_key


def credential_origin_map(model: DeploymentModel) -> Dict[str, str]:
    """Map of bare AppCredential key -> origin, for credential_ref prefixing.
    Shared between the builder and the data-plane resolver."""
    out: Dict[str, str] = {}
    for p in model.primitives:
        if isinstance(p, AppCredential):
            out[p.key] = p.origin
    return out

# Required companion field for each data_inject material.
_MATERIAL_REQUIRES = {
    "app_secret": "credential_ref",
    "app_client_id": "source_ref",
    "app_certificate": "file_path",
    "literal": "literal_value",
}


class TerraformBuilder:
    def __init__(self, model: DeploymentModel):
        self.model = model
        # Collapse semantically-duplicate relationship assignments BEFORE any pass reads
        # the primitives, so a duplicate role assignment can never reach `terraform apply`
        # (where Azure 409s with RoleAssignmentExists). Idempotent: safe to run repeatedly.
        deduped, n_removed = dedupe_assignments(model.primitives)
        if n_removed:
            model.primitives = deduped
            logging.info(
                f"Collapsed {n_removed} duplicate assignment(s) before emit ")
        # bare AppCredential key -> origin, for credential_ref prefixing.
        self._credential_origin: Dict[str, str] = {}
        for p in model.primitives:
            if isinstance(p, AppCredential):
                if p.key in self._credential_origin:
                    raise LabValidationError(
                        f"Duplicate app_credential key '{p.key}' across origins; "
                        f"credential keys must be unique so data_inject credential_ref "
                        f"is unambiguous."
                    )
                self._credential_origin[p.key] = p.origin

    # -- public API -----------------------------------------------------------
    def build(self) -> Dict:
        """Validate the lab and produce the full terraform.tfvars.json dict."""
        self.validate()
        groups = self._derive_attack_path_groups()
        exposed_vms = self._derive_exposed_vms()
        webapp_apps = self._derive_webapp_footholds()
        families = self._build_families()

        tfvars: Dict = {
            "tenant_id": self.model.tenant_id,
            "domain": self.model.domain,
            "subscription_id": self.model.subscription_id,
            "public_ip": self.model.public_ip,
            "azure_config_dir": self.model.azure_config_dir,
        }
        for attr in DeploymentModel.ENTITY_MAPS:
            if attr == "groups":
                tfvars[attr] = groups
            elif attr == "virtual_machines":
                tfvars[attr] = exposed_vms
            elif attr == "app_services":
                tfvars[attr] = webapp_apps
            else:
                tfvars[attr] = getattr(self.model, attr)
        tfvars.update(families)
        # Only the Cosmos accounts a cosmos_document inject targets need their
        # master key surfaced to the data-plane phase; the cosmos_db_connections
        # output iterates exactly this allowlist (baseline accounts are excluded).
        tfvars["cosmos_dataplane_refs"] = self._cosmos_dataplane_refs()
        # VMs that are an exposed-host foothold — the vm_foothold_access output
        # surfaces exactly these (public IP + creds the operator logs in with).
        tfvars["foothold_vm_refs"] = self._foothold_vm_refs()
        # App Services that are a vulnerable-web-app foothold — the
        # app_service_foothold_access output surfaces exactly these (URL + vuln path).
        tfvars["webapp_foothold_refs"] = self._webapp_foothold_refs()
        return tfvars

    def _cosmos_dataplane_refs(self) -> List[str]:
        """Sorted cosmos_db refs targeted by a cosmos_document inject — the only
        accounts whose endpoint+master key the data-plane phase reads back. Baseline
        Cosmos accounts with no inject are left out of the connections output."""
        refs = {
            p.location_ref
            for p in self.model.primitives
            if isinstance(p, DataInject) and p.location_type == "cosmos_document"
        }
        return sorted(refs)

    # -- step 1: is_attack_path_group derivation ------------------------------
    def _role_assignable_groups(self) -> set:
        return {
            p.principal_ref
            for p in self.model.primitives
            if isinstance(p, EntraRoleAssignment) and p.principal_type == "group"
        }

    def _derive_attack_path_groups(self) -> Dict:
        """Return a fresh groups map with is_attack_path_group set where derived.
        Does not mutate the input model. Unflagged groups omit the key entirely
        (matching the generic.tf default + the hand-written fixtures)."""
        derived = self._role_assignable_groups()
        out: Dict = {}
        for gkey, gval in self.model.groups.items():
            entry = dict(gval)
            if entry.get("is_attack_path_group") or gkey in derived:
                entry["is_attack_path_group"] = True
            out[gkey] = entry
        return out

    # -- step 1b: exposed-host foothold projection ----------------------------
    def _derive_exposed_vms(self) -> Dict:
        """A fresh virtual_machines map with exposed-host footholds projected onto
        the target VM spec: an `expose_to_internet` flag (read by the main.tf NSG),
        an `assign_public_ip` flag (footholds are the only VMs given a public IP —
        baseline VMs stay private) and, for credential=weak, a brute-forceable admin
        password. The host OS is
        coerced to match the vector (exposed_rdp -> Windows, exposed_ssh -> Linux) so
        the open port is consistent with the box — baseline VMs are always generated
        Linux, so without this an exposed_rdp foothold would land on a Linux host.
        Mirrors _derive_attack_path_groups — an InitialAccessVector is consumed here,
        NOT as a generic.tf family. Does not mutate the model; VMs that no foothold
        targets are copied through unchanged (so the golden fixture stays untouched)."""
        out: Dict = {k: dict(v) for k, v in self.model.virtual_machines.items()}
        for p in self.model.primitives:
            if not (isinstance(p, InitialAccessVector)
                    and p.method in RESOURCE_FOOTHOLD_VECTORS):
                continue
            vm = out.get(p.target_ref)
            if vm is None:  # ref-validated in validate(); defensive
                continue
            vm["expose_to_internet"] = bool(p.expose_to_internet)
            # Foothold VMs are the only VMs that get a public IP — the operator
            # needs it to reach the host (RDP/SSH). Baseline VMs stay private.
            vm["assign_public_ip"] = True
            os_type = FOOTHOLD_VECTOR_PROTOCOL.get(p.method, {}).get("os_type")
            if os_type:
                vm["os_type"] = os_type
            if p.credential == "weak":
                vm["admin_password"] = WEAK_FOOTHOLD_PASSWORD
        return out

    def _foothold_vm_refs(self) -> List[str]:
        """Sorted VM refs that are an exposed-host foothold — the vm_foothold_access
        output iterates exactly these (its public IP is only known after apply)."""
        return sorted({
            p.target_ref for p in self.model.primitives
            if isinstance(p, InitialAccessVector) and p.method in RESOURCE_FOOTHOLD_VECTORS
        })

    # -- step 1c: vulnerable-web-app foothold projection ----------------------
    def _derive_webapp_footholds(self) -> Dict:
        """A fresh app_services map with vulnerable-web-app footholds projected onto
        the target App Service spec: an `app_variant` (the in-repo app dir under
        terraform/webapp/ that main.tf zip-deploys, planting the code-exec bug). The
        vector's `variant` (e.g. rce) maps to the dir via WEBAPP_VARIANT_DIR. Mirrors
        _derive_exposed_vms — an InitialAccessVector is consumed here, NOT as a
        generic.tf family. Does not mutate the model; apps no foothold targets are
        copied through unchanged (so baseline App Services stay on the default page)."""
        out: Dict = {k: dict(v) for k, v in self.model.app_services.items()}
        for p in self.model.primitives:
            if not (isinstance(p, InitialAccessVector)
                    and p.method in WEBAPP_FOOTHOLD_VECTORS):
                continue
            app = out.get(p.target_ref)
            if app is None:  # ref-validated in validate(); defensive
                continue
            variant = p.variant or WEBAPP_DEFAULT_VARIANT
            app["app_variant"] = WEBAPP_VARIANT_DIR.get(variant, variant)
            # Access restriction: false (default) -> the app's main site allows only
            # the operator IP; true -> open to the internet. Mirrors the VM NSG.
            app["expose_to_internet"] = bool(p.expose_to_internet)
        return out

    def _webapp_foothold_refs(self) -> List[str]:
        """Sorted app_service refs that are a vulnerable-web-app foothold — the
        app_service_foothold_access output iterates exactly these (its URL is only
        known after apply)."""
        return sorted({
            p.target_ref for p in self.model.primitives
            if isinstance(p, InitialAccessVector) and p.method in WEBAPP_FOOTHOLD_VECTORS
        })

    # -- step 2: reference checking -------------------------------------------
    def validate(self) -> None:
        credential_keys = set(self._credential_origin.keys())
        for p in self.model.primitives:
            if isinstance(p, InitialAccessVector):
                self._validate_initial_access_vector(p)
                continue
            self._validate_refs(p, credential_keys)
            if isinstance(p, DataInject):
                self._validate_inject_material(p)

    def _validate_initial_access_vector(self, p: InitialAccessVector) -> None:
        """An InitialAccessVector has no generic.tf handler, so ref-check it here.
        Two foothold families: exposed-host (target_type=virtual_machine) and
        vulnerable-web-app (target_type=app_service)."""
        if p.method in WEBAPP_FOOTHOLD_VECTORS:
            if p.target_type != "app_service":
                raise LabValidationError(
                    f"InitialAccessVector '{p.key}': method '{p.method}' requires "
                    f"target_type 'app_service' (got '{p.target_type}')."
                )
            if p.target_ref not in self.model.entity_keys("app_services"):
                raise LabValidationError(
                    f"InitialAccessVector '{p.key}': target_ref '{p.target_ref}' is not "
                    f"a declared app_service."
                )
            return
        if p.method not in RESOURCE_FOOTHOLD_VECTORS:
            raise LabValidationError(
                f"InitialAccessVector '{p.key}': method '{p.method}' is not "
                f"implemented yet (supported: "
                f"{', '.join(RESOURCE_FOOTHOLD_VECTORS + WEBAPP_FOOTHOLD_VECTORS)})."
            )
        if p.target_type != "virtual_machine":
            raise LabValidationError(
                f"InitialAccessVector '{p.key}': method '{p.method}' requires "
                f"target_type 'virtual_machine' (got '{p.target_type}')."
            )
        if p.target_ref not in self.model.entity_keys("virtual_machines"):
            raise LabValidationError(
                f"InitialAccessVector '{p.key}': target_ref '{p.target_ref}' is not "
                f"a declared virtual_machine."
            )

    def _validate_refs(self, p: Primitive, credential_keys: set) -> None:
        for ref in handler_for(p).refs(p):
            if ref.value is None:
                continue
            if ref.kinds == (CREDENTIAL,):
                if ref.value not in credential_keys:
                    raise LabValidationError(
                        f"{type(p).__name__} '{p.key}': {ref.field}='{ref.value}' "
                        f"names no declared app_credential."
                    )
                continue
            if not ref.kinds:
                raise LabValidationError(
                    f"{type(p).__name__} '{p.key}': cannot resolve {ref.field}="
                    f"'{ref.value}' — unknown principal/scope/resource type."
                )
            valid = set()
            for kind in ref.kinds:
                valid |= self.model.entity_keys(kind)
            if ref.value not in valid:
                kinds = " | ".join(ref.kinds)
                raise LabValidationError(
                    f"{type(p).__name__} '{p.key}': {ref.field}='{ref.value}' "
                    f"is not a declared {kinds}."
                )

    def _validate_inject_material(self, p: DataInject) -> None:
        required = _MATERIAL_REQUIRES.get(p.material)
        if required is None:
            raise LabValidationError(
                f"DataInject '{p.key}': unknown material '{p.material}'."
            )
        if getattr(p, required) in (None, ""):
            raise LabValidationError(
                f"DataInject '{p.key}': material '{p.material}' requires "
                f"'{required}' to be set."
            )

    # -- step 3: write the Terraform variables (with credential_ref prefixing) -
    def _build_families(self) -> Dict[str, Dict]:
        families: Dict[str, Dict] = {}
        for p in self.model.primitives:
            # Data-plane-only injects (e.g. cosmos_document) have no Terraform
            # resource — they're planted by src/dataplane.py after apply, so keep
            # them out of the tfvars families. They are still ref-validated above.
            if isinstance(p, DataInject) and p.location_type in DATAPLANE_LOCATION_TYPES:
                continue
            # InitialAccessVector has no generic.tf family — it is projected onto the
            # target VM spec by _derive_exposed_vms, not emitted as a primitive var.
            if isinstance(p, InitialAccessVector):
                continue

            base = handler_for(p).base_family
            family = f"{_ORIGIN_FAMILY_PREFIX[p.origin]}_{base}"
            value = {f: getattr(p, f) for f in value_fields(type(p))}

            if isinstance(p, DataInject) and p.material == "app_secret" and p.credential_ref:
                cred_origin = self._credential_origin[p.credential_ref]
                value["credential_ref"] = origin_prefixed_key(p.credential_ref, cred_origin)

            bucket = families.setdefault(family, {})
            if p.key in bucket:
                raise LabValidationError(
                    f"Duplicate key '{p.key}' in Terraform variable '{family}'."
                )
            bucket[p.key] = value
        return families


def build_tfvars(model: DeploymentModel) -> Dict:
    """Convenience entrypoint: validate + build the terraform.tfvars.json dict."""
    return TerraformBuilder(model).build()
