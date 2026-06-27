"""
test_macro_storage_certificate_theft.py — offline test of the Phase-4 macro.

Drives the real `macro_storage_certificate_theft` (no Azure) through the Terraform
builder and asserts the emitted generic families model the storage-cert-theft chain
correctly across its variants: user vs service_principal initial access, direct vs
group_member vs group_owner assignment, AzureADRole vs APIPermission app privileges.

The real cert generator writes .pem/.key/.pfx files to disk; we monkeypatch it to
return fake paths (the builder only passes the paths through to Terraform, it
doesn't read them), so the test does no file I/O.

Runs two ways:
    python tests/test_macro_storage_certificate_theft.py
    pytest tests/test_macro_storage_certificate_theft.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.attack_path_manager as apm  # noqa: E402
from src.attack_path_manager import AttackPathManager  # noqa: E402
from src.primitives import DeploymentModel  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator

# Make cert generation deterministic + side-effect-free for the macro under test.
apm.generate_certificate_and_key = lambda app: (
    f"{app}-cert.pem", f"{app}-key.key", f"{app}-cert.pfx")


def _entities(applications=None):
    users = {"alice": {"user_principal_name": "alice", "display_name": "Alice",
                       "mail_nickname": "alice", "password": "P@ss-alice"}}
    if applications is None:
        applications = {"app-highpriv": {"display_name": "app-highpriv"}}
    storage_accounts = {"safixture": {"name": "safixture", "location": "West US",
                                      "resource_group_name": "rg1",
                                      "account_tier": "Standard",
                                      "account_replication_type": "LRS"}}
    return users, applications, storage_accounts


def _model(primitives, groups=None, applications=None):
    users, applications, storage_accounts = _entities(applications)
    return DeploymentModel(
        domain="contoso.com",
        users=users, applications=applications, storage_accounts=storage_accounts,
        groups=groups or {}, primitives=primitives,
    )


def _mgr():
    return AttackPathManager()


def _run_macro(cfg, applications=None, used_apps=None):
    users, apps, storage_accounts = _entities(applications)
    return _mgr().macro_storage_certificate_theft(
        cfg, apps, storage_accounts, users, apps, "contoso.com",
        mode="random", path_name="sapath", used_apps=used_apps,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_user_direct_azureadrole():
    cfg = {"privilege_escalation": "StorageCertificateTheft", "initial_access": "user",
           "assignment_type": "direct", "objective": {"entra_role": GA_ROLE}}
    result = _run_macro(cfg)
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    # one certificate app_credential on the looted app
    creds = out["attack_path_app_credentials"]
    assert len(creds) == 1
    cred = next(iter(creds.values()))
    assert cred["app_ref"] == "app-highpriv" and cred["type"] == "certificate"
    assert cred["certificate_path"] == "app-highpriv-cert.pem"

    # three storage-blob injects (.key/.pem/.pfx), all app_certificate from file_path
    injects = out["attack_path_data_injects"]
    assert len(injects) == 3
    assert all(i["location_type"] == "storage_blob" for i in injects.values())
    assert all(i["material"] == "app_certificate" for i in injects.values())
    assert all(i["location_ref"] == "safixture" for i in injects.values())
    assert all(i["source_ref"] == "app-highpriv" for i in injects.values())
    names = {i["name"] for i in injects.values()}
    assert names == {"app-highpriv-private-key.key", "app-highpriv-certificate.pem",
                     "app-highpriv-certificate.pfx"}
    files = {i["file_path"] for i in injects.values()}
    assert files == {"app-highpriv-key.key", "app-highpriv-cert.pem", "app-highpriv-cert.pfx"}

    # Storage Blob Data Reader to the user directly
    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["role"] == "Storage Blob Data Reader"
    assert rbac["principal_ref"] == "alice" and rbac["principal_type"] == "user"
    assert rbac["scope_type"] == "resource"
    assert rbac["scope_resource_type"] == "storage_account"
    assert rbac["scope_ref"] == "safixture"

    # app privilege = one Entra role on the looted app's SP
    roles = list(out["attack_path_entra_role_assignments"].values())
    assert len(roles) == 1 and roles[0]["role"] == GA_ROLE
    assert roles[0]["principal_ref"] == "app-highpriv"
    assert roles[0]["principal_type"] == "service_principal"
    assert not out.get("attack_path_api_permission_assignments")
    assert result["credentials"]["password"] == "P@ss-alice"
    assert result["summary"]["technique"] == "StorageCertificateTheft"


def test_user_apipermission_list():
    perms = ["06b708a9-e830-4db3-a914-8e69da51d44f",
             "19dbc75e-c2e2-444c-a770-ec69d8559fc7"]
    cfg = {"privilege_escalation": "StorageCertificateTheft", "initial_access": "user",
           "assignment_type": "direct", "objective": {"api_permission": {"graph": perms}}}
    result = _run_macro(cfg)
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    api = list(out["attack_path_api_permission_assignments"].values())
    assert len(api) == 2
    assert {a["permission_id"] for a in api} == set(perms)
    assert all(a["principal_ref"] == "app-highpriv" for a in api)
    assert not out.get("attack_path_entra_role_assignments")


def test_sp_initial_access_mints_surfaced_credential():
    cfg = {"privilege_escalation": "StorageCertificateTheft",
           "initial_access": "service_principal", "assignment_type": "direct",
           "objective": {"entra_role": GA_ROLE}}
    two_apps = {"app-highpriv": {"display_name": "app-highpriv"},
                "app-initial": {"display_name": "app-initial"}}
    result = _run_macro(cfg, applications=two_apps, used_apps={"app-initial"})
    out = build_tfvars(_model(result["primitives"], result["groups"], two_apps))

    # two app_credentials: the looted app's cert + the initial-access SP's password
    creds = out["attack_path_app_credentials"]
    assert len(creds) == 2
    types = sorted(c["type"] for c in creds.values())
    assert types == ["certificate", "password"]
    sp_key = result["credentials"]["generic_credential_key"]
    assert sp_key.startswith("ap:") and sp_key.split("ap:", 1)[1] in creds
    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["principal_type"] == "service_principal"


def test_group_member_routes_rbac_to_group():
    cfg = {"privilege_escalation": "StorageCertificateTheft", "initial_access": "user",
           "assignment_type": "group_member", "objective": {"entra_role": GA_ROLE}}
    result = _run_macro(cfg)
    assert len(result["groups"]) == 1
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["principal_type"] == "group"
    group_name = rbac["principal_ref"]
    mem = next(iter(out["attack_path_group_membership_assignments"].values()))
    assert mem["principal_ref"] == "alice" and mem["group_ref"] == group_name
    assert not out.get("attack_path_group_ownership_assignments")


def test_group_owner_routes_rbac_to_group():
    cfg = {"privilege_escalation": "StorageCertificateTheft", "initial_access": "user",
           "assignment_type": "group_owner", "objective": {"entra_role": GA_ROLE}}
    result = _run_macro(cfg)
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["principal_type"] == "group"
    own = next(iter(out["attack_path_group_ownership_assignments"].values()))
    assert own["principal_ref"] == "alice" and own["group_ref"] == rbac["principal_ref"]
    assert not out.get("attack_path_group_membership_assignments")


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
