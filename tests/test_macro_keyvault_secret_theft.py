"""
test_macro_keyvault_secret_theft.py — offline test of the Phase-2 macro.

Drives the real `macro_keyvault_secret_theft` (no Azure) through the Terraform
builder and asserts the emitted generic families model the KV-theft chain
correctly across its variants: user vs service_principal initial access,
direct vs group_member vs group_owner assignment, and AzureADRole vs
APIPermission app privileges.

No live tenant: this exercises the building-block decomposition + builder
validation only. The actual `terraform apply` is the live acceptance step.

Runs two ways:
    python tests/test_macro_keyvault_secret_theft.py
    pytest tests/test_macro_keyvault_secret_theft.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attack_path_manager import AttackPathManager  # noqa: E402
from src.primitives import DeploymentModel  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator


def _entities(applications=None):
    """Minimal symbolic-keyed entity maps (same keying the real pipeline uses:
    users by UPN, apps/groups by display_name, KVs by name). A single app by
    default so random entity selection is deterministic for assertions."""
    users = {"alice": {"user_principal_name": "alice", "display_name": "Alice",
                       "mail_nickname": "alice", "password": "P@ss-alice"}}
    if applications is None:
        applications = {"app-highpriv": {"display_name": "app-highpriv"}}
    key_vaults = {"kv-fixture": {"name": "kv-fixture", "location": "West US",
                                 "resource_group_name": "rg1", "sku_name": "standard"}}
    return users, applications, key_vaults


def _model(primitives, groups=None, applications=None):
    users, applications, key_vaults = _entities(applications)
    return DeploymentModel(
        domain="contoso.com",
        users=users, applications=applications, key_vaults=key_vaults,
        groups=groups or {}, primitives=primitives,
    )


def _mgr():
    return AttackPathManager()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_user_direct_azureadrole():
    """Direct user access + Entra-role app privilege → the four core blocks,
    and the builder produces a valid tfvars (refs all resolve)."""
    cfg = {"privilege_escalation": "KeyVaultSecretTheft", "initial_access": "user",
           "assignment_type": "direct", "objective": {"entra_role": GA_ROLE}}
    users, applications, key_vaults = _entities()
    result = _mgr().macro_keyvault_secret_theft(
        cfg, applications, key_vaults, users, applications, "contoso.com",
        mode="random", path_name="kvpath",
    )
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    # one app_credential (the looted secret) + one data_inject planting it
    creds = out["attack_path_app_credentials"]
    assert len(creds) == 1
    cred_key, cred = next(iter(creds.items()))
    assert cred["app_ref"] == "app-highpriv" and cred["type"] == "password"

    injects = out["attack_path_data_injects"]
    assert len(injects) == 1
    inj = next(iter(injects.values()))
    assert inj["material"] == "app_secret"
    assert inj["location_type"] == "key_vault_secret"
    assert inj["location_ref"] == "kv-fixture"
    assert inj["name"] == "client-secret-app-highpriv"
    # credential_ref is origin-prefixed to the looted credential
    assert inj["credential_ref"] == f"ap:{cred_key}"

    # Key Vault Contributor goes to the user directly
    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["role"] == "Key Vault Contributor"
    assert rbac["principal_ref"] == "alice" and rbac["principal_type"] == "user"
    assert rbac["scope_type"] == "resource" and rbac["scope_resource_type"] == "key_vault"
    assert rbac["scope_ref"] == "kv-fixture"

    # app privilege = one Entra role on the looted app's SP
    roles = list(out["attack_path_entra_role_assignments"].values())
    assert len(roles) == 1 and roles[0]["role"] == GA_ROLE
    assert roles[0]["principal_ref"] == "app-highpriv"
    assert roles[0]["principal_type"] == "service_principal"

    # no API permissions, no groups, user creds carry the password
    assert not out.get("attack_path_api_permission_assignments")
    assert result["credentials"]["password"] == "P@ss-alice"


def test_user_apipermission_list():
    """APIPermission with a list of two perms → two ApiPermission blocks."""
    perms = ["06b708a9-e830-4db3-a914-8e69da51d44f",
             "19dbc75e-c2e2-444c-a770-ec69d8559fc7"]
    cfg = {"privilege_escalation": "KeyVaultSecretTheft", "initial_access": "user",
           "assignment_type": "direct", "objective": {"api_permission": {"graph": perms}}}
    users, applications, key_vaults = _entities()
    result = _mgr().macro_keyvault_secret_theft(
        cfg, applications, key_vaults, users, applications, "contoso.com",
        mode="random", path_name="kvpath",
    )
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    api = list(out["attack_path_api_permission_assignments"].values())
    assert len(api) == 2
    assert {a["permission_id"] for a in api} == set(perms)
    assert all(a["api_type"] == "graph" and a["principal_ref"] == "app-highpriv" for a in api)
    assert not out.get("attack_path_entra_role_assignments")


def test_sp_initial_access_mints_surfaced_credential():
    """service_principal initial access mints a second app_credential (the SP's
    own secret) and records the origin-prefixed key for the TF output read-back."""
    cfg = {"privilege_escalation": "KeyVaultSecretTheft",
           "initial_access": "service_principal", "assignment_type": "direct",
           "objective": {"entra_role": GA_ROLE}}
    two_apps = {"app-highpriv": {"display_name": "app-highpriv"},
                "app-initial": {"display_name": "app-initial"}}
    users, applications, key_vaults = _entities(two_apps)
    # used_apps forces the LOOTED app to 'app-highpriv' (app-initial excluded);
    # the SP principal is picked from all apps independently.
    result = _mgr().macro_keyvault_secret_theft(
        cfg, applications, key_vaults, users, applications, "contoso.com",
        mode="random", path_name="kvpath", used_apps={"app-initial"},
    )
    out = build_tfvars(_model(result["primitives"], result["groups"], two_apps))

    # two app_credentials now: the looted app + the initial-access SP
    creds = out["attack_path_app_credentials"]
    assert len(creds) == 2
    sp_key = result["credentials"]["generic_credential_key"]
    assert sp_key.startswith("ap:")
    # the recorded key (minus the ap: prefix) is a real credential entry
    assert sp_key.split("ap:", 1)[1] in creds
    # RBAC principal is the SP (an application-backed principal)
    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["principal_type"] == "service_principal"


def test_group_member_routes_rbac_to_group():
    """group_member: KV Contributor goes to the group, and the principal is a
    member of it. The group is created as an entity."""
    cfg = {"privilege_escalation": "KeyVaultSecretTheft", "initial_access": "user",
           "assignment_type": "group_member", "objective": {"entra_role": GA_ROLE}}
    users, applications, key_vaults = _entities()
    result = _mgr().macro_keyvault_secret_theft(
        cfg, applications, key_vaults, users, applications, "contoso.com",
        mode="random", path_name="kvpath",
    )
    assert len(result["groups"]) == 1
    out = build_tfvars(_model(result["primitives"], result["groups"]))

    rbac = next(iter(out["attack_path_azure_rbac_assignments"].values()))
    assert rbac["principal_type"] == "group"
    group_name = rbac["principal_ref"]

    mem = next(iter(out["attack_path_group_membership_assignments"].values()))
    assert mem["principal_ref"] == "alice" and mem["principal_type"] == "user"
    assert mem["group_ref"] == group_name
    assert not out.get("attack_path_group_ownership_assignments")
    # Parity with legacy: generate_attack_path_group hand-flags every attack-path
    # group as role-assignable (is_attack_path_group -> assignable_to_role in
    # main.tf), so the builder preserves it. (Phase 4 may revisit this dual use.)
    assert out["groups"][group_name].get("is_attack_path_group") is True


def test_group_owner_routes_rbac_to_group():
    """group_owner: KV Contributor goes to the group, principal owns it."""
    cfg = {"privilege_escalation": "KeyVaultSecretTheft", "initial_access": "user",
           "assignment_type": "group_owner", "objective": {"entra_role": GA_ROLE}}
    users, applications, key_vaults = _entities()
    result = _mgr().macro_keyvault_secret_theft(
        cfg, applications, key_vaults, users, applications, "contoso.com",
        mode="random", path_name="kvpath",
    )
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
