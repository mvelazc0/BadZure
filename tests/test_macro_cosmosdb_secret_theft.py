"""
test_macro_cosmosdb_secret_theft.py — offline test of the Phase-4 macro.

Drives the real `macro_cosmosdb_secret_theft` (no Azure) through the Terraform
builder and asserts the emitted generic families model the Cosmos-secret-theft
chain correctly across its variants. The looted secret is planted as a
cosmos_document DataInject, but that is a data-plane-only inject: the builder
keeps it OUT of the Terraform data_injects family (the Python post-apply
data-plane phase plants it), so it lives on the model's primitives instead.

Runs two ways:
    python tests/test_macro_cosmosdb_secret_theft.py
    pytest tests/test_macro_cosmosdb_secret_theft.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attack_path_manager import AttackPathManager  # noqa: E402
from src.primitives import DeploymentModel  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
COSMOS_ROLE = "00000000-0000-0000-0000-000000000002"  # Cosmos DB Built-in Data Contributor


def _entities(applications=None):
    users = {"alice": {"user_principal_name": "alice", "display_name": "Alice",
                       "mail_nickname": "alice", "password": "P@ss-alice"}}
    if applications is None:
        applications = {"app-highpriv": {"display_name": "app-highpriv"}}
    cosmos_dbs = {"cosmosfixture": {"name": "cosmosfixture", "location": "West US",
                                    "resource_group_name": "rg1"}}
    return users, applications, cosmos_dbs


def _model(primitives, groups=None, applications=None):
    users, applications, cosmos_dbs = _entities(applications)
    return DeploymentModel(
        domain="contoso.com",
        users=users, applications=applications, cosmos_dbs=cosmos_dbs,
        groups=groups or {}, primitives=primitives,
    )


def _run_macro(cfg, applications=None, used_apps=None):
    users, apps, cosmos_dbs = _entities(applications)
    return AttackPathManager().macro_cosmosdb_secret_theft(
        cfg, apps, cosmos_dbs, users, apps, "contoso.com",
        mode="random", path_name="cospath", used_apps=used_apps,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_user_direct_azureadrole():
    cfg = {"privilege_escalation": "CosmosDBSecretTheft", "initial_access": "user",
           "assignment_type": "direct", "method": "AzureADRole", "entra_role": GA_ROLE}
    result = _run_macro(cfg)
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    # one password app_credential on the looted app
    creds = out["attack_path_app_credentials"]
    assert len(creds) == 1
    cred_key, cred = next(iter(creds.items()))
    assert cred["app_ref"] == "app-highpriv" and cred["type"] == "password"

    # the secret is planted as a cosmos_document inject — but as a data-plane-only
    # inject it is NOT emitted into the Terraform data_injects family; it lives on
    # the model's primitives for the Python data-plane phase to plant after apply.
    assert not out.get("attack_path_data_injects")
    injects = [p for p in result["primitives"]
               if getattr(p, "location_type", None) == "cosmos_document"]
    assert len(injects) == 1
    inj = injects[0]
    assert inj.material == "app_secret"
    assert inj.location_ref == "cosmosfixture"
    assert inj.name == "client-secret-app-highpriv"
    assert inj.credential_ref == cred_key

    # Cosmos data-plane grant to the user directly
    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["role"] == COSMOS_ROLE
    assert rbac["data_plane"] == "cosmos_sql"
    assert rbac["principal_ref"] == "alice" and rbac["principal_type"] == "user"
    assert rbac["scope_type"] == "resource"
    assert rbac["scope_resource_type"] == "cosmos_db"
    assert rbac["scope_ref"] == "cosmosfixture"

    roles = list(out["attack_path_entra_role_assignments"].values())
    assert len(roles) == 1 and roles[0]["role"] == GA_ROLE
    assert roles[0]["principal_ref"] == "app-highpriv"
    assert result["credentials"]["password"] == "P@ss-alice"
    assert result["summary"]["technique"] == "CosmosDBSecretTheft"


def test_user_apipermission_list():
    perms = ["06b708a9-e830-4db3-a914-8e69da51d44f",
             "19dbc75e-c2e2-444c-a770-ec69d8559fc7"]
    cfg = {"privilege_escalation": "CosmosDBSecretTheft", "initial_access": "user",
           "assignment_type": "direct", "method": "APIPermission",
           "api_type": "graph", "app_role": perms}
    result = _run_macro(cfg)
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    api = list(out["attack_path_api_permission_assignments"].values())
    assert len(api) == 2
    assert {a["permission_id"] for a in api} == set(perms)
    assert not out.get("attack_path_entra_role_assignments")


def test_sp_initial_access_mints_surfaced_credential():
    cfg = {"privilege_escalation": "CosmosDBSecretTheft",
           "initial_access": "service_principal", "assignment_type": "direct",
           "method": "AzureADRole", "entra_role": GA_ROLE}
    two_apps = {"app-highpriv": {"display_name": "app-highpriv"},
                "app-initial": {"display_name": "app-initial"}}
    result = _run_macro(cfg, applications=two_apps, used_apps={"app-initial"})
    out = build_tfvars(_model(result["primitives"], result["groups"], two_apps))

    # two password app_credentials: the looted app + the initial-access SP
    creds = out["attack_path_app_credentials"]
    assert len(creds) == 2
    sp_key = result["credentials"]["generic_credential_key"]
    assert sp_key.startswith("ap:") and sp_key.split("ap:", 1)[1] in creds
    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["principal_type"] == "service_principal"
    assert rbac["data_plane"] == "cosmos_sql"


def test_group_member_routes_rbac_to_group():
    cfg = {"privilege_escalation": "CosmosDBSecretTheft", "initial_access": "user",
           "assignment_type": "group_member", "method": "AzureADRole",
           "entra_role": GA_ROLE}
    result = _run_macro(cfg)
    assert len(result["groups"]) == 1
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["principal_type"] == "group" and rbac["data_plane"] == "cosmos_sql"
    group_name = rbac["principal_ref"]
    mem = next(iter(out["attack_path_group_membership_assignments"].values()))
    assert mem["principal_ref"] == "alice" and mem["group_ref"] == group_name
    assert not out.get("attack_path_group_ownership_assignments")


def test_group_owner_routes_rbac_to_group():
    cfg = {"privilege_escalation": "CosmosDBSecretTheft", "initial_access": "user",
           "assignment_type": "group_owner", "method": "AzureADRole",
           "entra_role": GA_ROLE}
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
