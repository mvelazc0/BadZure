"""
test_macro_managed_identity_abuse.py — offline test of the Phase-4 MI macro.

Drives the real `macro_managed_identity_abuse` (no Azure) through the Terraform
builder and asserts the emitted generic families model the chain: source-Contributor
-> the source's managed identity -> grants on the target -> the looted app's
credential planted there. Covers KV (secret + certificate), storage, cosmos
(data-plane-only document injects, kept out of the TF data_injects family), group
assignment, and SP initial access.

The cert generator is monkeypatched (no file I/O).

Runs two ways:
    python tests/test_macro_managed_identity_abuse.py
    pytest tests/test_macro_managed_identity_abuse.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.attack_path_manager as apm  # noqa: E402
from src.attack_path_manager import AttackPathManager  # noqa: E402
from src.primitives import DeploymentModel  # noqa: E402
from src.terraform_builder import build_tfvars as _build_tfvars  # noqa: E402


# Cert generation is monkeypatched to fake paths (no file I/O), so skip the on-disk
# cert-existence check the real preflight enforces — this suite tests var emission.
def build_tfvars(model):
    return _build_tfvars(model, verify_files=False)

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"
COSMOS_ROLE = "00000000-0000-0000-0000-000000000002"

apm.generate_certificate_and_key = lambda app: (
    f"{app}-cert.pem", f"{app}-key.key", f"{app}-cert.pfx")


def _base_entities():
    return dict(
        users={"alice": {"user_principal_name": "alice", "display_name": "Alice",
                         "mail_nickname": "alice", "password": "P@ss"}},
        applications={"app-hp": {"display_name": "app-hp"}},
        virtual_machines={"vm01": {"name": "vm01", "location": "West US",
                                   "resource_group_name": "rg1", "os_type": "Linux"}},
        key_vaults={"kv01": {"name": "kv01", "location": "West US",
                             "resource_group_name": "rg1", "sku_name": "standard"}},
        storage_accounts={"sa01": {"name": "sa01", "location": "West US",
                                   "resource_group_name": "rg1",
                                   "account_tier": "Standard",
                                   "account_replication_type": "LRS"}},
        cosmos_dbs={"cos01": {"name": "cos01", "location": "West US",
                              "resource_group_name": "rg1"}},
        app_services={"as01": {"name": "as01", "location": "West US",
                               "resource_group_name": "rg1", "os_type": "linux"}},
    )


def _run(cfg, groups_out=None):
    ents = _base_entities()
    result = AttackPathManager().macro_managed_identity_abuse(
        cfg, ents["applications"], ents["key_vaults"], ents["storage_accounts"],
        ents["users"], "contoso.com", ents["virtual_machines"], {}, {}, {},
        mode="random", path_name="mi", cosmos_dbs=ents["cosmos_dbs"],
        app_services=ents["app_services"])
    model = DeploymentModel(domain="contoso.com", groups=result["groups"],
                            primitives=result["primitives"], **ents)
    return result, build_tfvars(model)


def _rbac(out):
    return list(out["attack_path_azure_rbac_assignments"].values())


# ---------------------------------------------------------------------------
def test_vm_to_keyvault_secret():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
           "target_resource_type": "key_vault", "initial_access": "user",
           "credential_type": "secret", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    rbac = _rbac(out)
    # source Contributor on the VM, to the user
    src = next(r for r in rbac if r["role"] == "Virtual Machine Contributor")
    assert src["principal_type"] == "user" and src["scope_ref"] == "vm01"
    assert src["scope_resource_type"] == "virtual_machine"
    # the VM's MI gets the 3 KV roles
    mi = [r for r in rbac if r["principal_type"] == "managed_identity"]
    assert {r["role"] for r in mi} == {"Key Vault Contributor", "Key Vault Secrets User",
                                       "Key Vault Reader"}
    assert all(r["mi_source_type"] == "vm" and r["principal_ref"] == "vm01"
               and r["scope_ref"] == "kv01" for r in mi)
    # one password credential + two KV-secret injects (secret + client id)
    assert next(iter(out["attack_path_app_credentials"].values()))["type"] == "password"
    injects = out["attack_path_data_injects"]
    assert {i["name"] for i in injects.values()} == {"mi-client-secret-app-hp", "mi-client-id-app-hp"}
    assert {i["material"] for i in injects.values()} == {"app_secret", "app_client_id"}
    assert result["summary"]["technique"] == "ManagedIdentityAbuse"


def test_vm_to_keyvault_certificate():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
           "target_resource_type": "key_vault", "initial_access": "user",
           "credential_type": "certificate", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    mi = [r for r in _rbac(out) if r["principal_type"] == "managed_identity"]
    assert "Key Vault Certificate User" in {r["role"] for r in mi}   # 4th role for cert
    assert next(iter(out["attack_path_app_credentials"].values()))["type"] == "certificate"
    injects = out["attack_path_data_injects"]
    names = {i["name"] for i in injects.values()}
    assert names == {"mi-certificate-app-hp", "mi-client-id-app-hp"}
    cert = next(i for i in injects.values() if i["name"] == "mi-certificate-app-hp")
    assert cert["location_type"] == "key_vault_certificate" and cert["file_path"] == "app-hp-cert.pfx"


def test_vm_to_storage_secret():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
           "target_resource_type": "storage_account", "initial_access": "user",
           "credential_type": "secret", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    mi = [r for r in _rbac(out) if r["principal_type"] == "managed_identity"]
    assert {r["role"] for r in mi} == {"Storage Blob Data Reader", "Storage Account Contributor"}
    injects = out["attack_path_data_injects"]
    assert {i["name"] for i in injects.values()} == {"app-hp-app-id.txt", "app-hp-secret.txt"}
    assert all(i["location_type"] == "storage_blob" for i in injects.values())


def _cosmos_document_injects(result):
    return [p for p in result["primitives"]
            if getattr(p, "location_type", None) == "cosmos_document"]


def test_vm_to_cosmos_plants_secret_documents():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
           "target_resource_type": "cosmos_db", "initial_access": "user",
           "credential_type": "secret", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    mi = [r for r in _rbac(out) if r["principal_type"] == "managed_identity"]
    assert len(mi) == 1 and mi[0]["role"] == COSMOS_ROLE and mi[0]["data_plane"] == "cosmos_sql"
    # cosmos_document injects are data-plane-only — kept OUT of the TF family; the
    # Python data-plane phase plants secret + client id as documents after apply.
    assert not out.get("attack_path_data_injects")
    injects = _cosmos_document_injects(result)
    assert {p.material for p in injects} == {"app_secret", "app_client_id"}
    assert {p.name for p in injects} == {"mi-client-secret-app-hp", "mi-client-id-app-hp"}
    assert next(iter(out["attack_path_app_credentials"].values()))["type"] == "password"


def test_vm_to_cosmos_cert_plants_certificate_document():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
           "target_resource_type": "cosmos_db", "initial_access": "user",
           "credential_type": "certificate", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    assert not out.get("attack_path_data_injects")
    injects = _cosmos_document_injects(result)
    assert {p.material for p in injects} == {"app_certificate", "app_client_id"}
    cert = next(p for p in injects if p.material == "app_certificate")
    assert cert.file_path and cert.name == "mi-certificate-app-hp"   # the PEM the phase uploads
    assert next(iter(out["attack_path_app_credentials"].values()))["type"] == "certificate"


def test_group_member_routes_source_contributor_to_group():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
           "target_resource_type": "key_vault", "initial_access": "user",
           "assignment_type": "group_member", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    assert len(result["groups"]) == 1
    src = next(r for r in _rbac(out) if r["role"] == "Virtual Machine Contributor")
    assert src["principal_type"] == "group"
    mem = next(iter(out["attack_path_group_membership_assignments"].values()))
    assert mem["group_ref"] == src["principal_ref"]


def test_sp_initial_access_mints_secret():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
           "target_resource_type": "key_vault", "initial_access": "service_principal",
           "credential_type": "secret", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    sp_key = result["credentials"]["generic_credential_key"]
    assert sp_key.startswith("ap:") and sp_key.split("ap:", 1)[1] in out["attack_path_app_credentials"]
    src = next(r for r in _rbac(out) if r["role"] == "Virtual Machine Contributor")
    assert src["principal_type"] == "service_principal"


def test_app_service_to_keyvault_secret():
    cfg = {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "app_service",
           "target_resource_type": "key_vault", "initial_access": "user",
           "credential_type": "secret", "objective": {"entra_role": GA_ROLE}}
    result, out = _run(cfg)
    rbac = _rbac(out)
    # source Website Contributor on the App Service, to the user
    src = next(r for r in rbac if r["role"] == "Website Contributor")
    assert src["principal_type"] == "user" and src["scope_ref"] == "as01"
    assert src["scope_resource_type"] == "app_service"
    # the App Service's MI gets the 3 KV roles, resolved via mi_source_type app_service
    mi = [r for r in rbac if r["principal_type"] == "managed_identity"]
    assert {r["role"] for r in mi} == {"Key Vault Contributor", "Key Vault Secrets User",
                                       "Key Vault Reader"}
    assert all(r["mi_source_type"] == "app_service" and r["principal_ref"] == "as01"
               and r["scope_ref"] == "kv01" for r in mi)
    assert result["summary"]["source_type"] == "app_service"
    assert result["summary"]["technique"] == "ManagedIdentityAbuse"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
