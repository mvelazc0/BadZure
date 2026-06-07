"""
test_macro_identity_abuses.py — offline tests of the Phase-4 identity-based macros:
ApplicationOwnershipAbuse, Application/Cloud Application Administrator Abuse.

Drives the real macros (no Azure) through the Terraform builder and asserts the
emitted generic families model each chain. These techniques touch no resources
(only identities), so they exercise app_ownership / entra_role(admin) / group links.

Runs two ways:
    python tests/test_macro_identity_abuses.py
    pytest tests/test_macro_identity_abuses.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attack_path_manager import AttackPathManager  # noqa: E402
from src.constants import APP_ADMIN_ROLE_ID, CLOUD_APP_ADMIN_ROLE_ID  # noqa: E402
from src.primitives import DeploymentModel  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"
HELPDESK_ROLE = "729827e3-9c14-49f7-bb1b-9608f156bbb8"


def _users(n=2):
    return {f"u{i}": {"user_principal_name": f"u{i}", "display_name": f"U{i}",
                      "mail_nickname": f"u{i}", "password": f"P@ss-{i}"} for i in range(n)}


def _apps(names):
    return {n: {"display_name": n} for n in names}


def _model(primitives, groups=None, users=None, applications=None):
    return DeploymentModel(
        domain="contoso.com",
        users=users or _users(), applications=applications or _apps(["app-hp"]),
        groups=groups or {}, primitives=primitives,
    )


def _mgr():
    return AttackPathManager()


# ---------------------------------------------------------------------------
# ApplicationOwnershipAbuse
# ---------------------------------------------------------------------------
def test_ownership_user_direct():
    cfg = {"privilege_escalation": "ApplicationOwnershipAbuse", "initial_access": "user",
           "assignment_type": "direct", "method": "AzureADRole", "entra_role": GA_ROLE}
    users, apps = _users(1), _apps(["app-hp"])
    result = _mgr().macro_application_ownership_abuse(
        cfg, users, apps, "contoso.com", mode="random", path_name="own")
    out = build_tfvars(_model(result["primitives"], users=users, applications=apps))

    own = next(iter(out["attack_path_app_ownership_assignments"].values()))
    assert own["principal_type"] == "user" and own["app_ref"] == "app-hp"
    roles = list(out["attack_path_entra_role_assignments"].values())
    assert len(roles) == 1 and roles[0]["role"] == GA_ROLE
    assert roles[0]["principal_ref"] == "app-hp"  # privilege on the owned app's SP
    assert result["summary"]["technique"] == "ApplicationOwnershipAbuse"
    assert result["credentials"]["initial_access"] == "user"


def test_ownership_group_falls_back_to_direct():
    cfg = {"privilege_escalation": "ApplicationOwnershipAbuse", "initial_access": "user",
           "assignment_type": "group_member", "method": "AzureADRole", "entra_role": GA_ROLE}
    users, apps = _users(1), _apps(["app-hp"])
    result = _mgr().macro_application_ownership_abuse(
        cfg, users, apps, "contoso.com", mode="random", path_name="own")
    assert result["groups"] == {}                      # no group created
    assert result["summary"]["assignment_type"] == "direct"
    out = build_tfvars(_model(result["primitives"], users=users, applications=apps))
    assert not out.get("attack_path_group_membership_assignments")


def test_ownership_sp_mints_secret():
    cfg = {"privilege_escalation": "ApplicationOwnershipAbuse",
           "initial_access": "service_principal", "assignment_type": "direct",
           "method": "AzureADRole", "entra_role": GA_ROLE}
    apps = _apps(["app-hp", "app-owner"])
    result = _mgr().macro_application_ownership_abuse(
        {**cfg}, _users(1), apps, "contoso.com", mode="random", path_name="own",
        used_apps=set())
    out = build_tfvars(_model(result["primitives"], applications=apps))
    own = next(iter(out["attack_path_app_ownership_assignments"].values()))
    assert own["principal_type"] == "service_principal"
    sp_key = result["credentials"]["generic_credential_key"]
    assert sp_key.startswith("ap:") and sp_key.split("ap:", 1)[1] in out["attack_path_app_credentials"]


def test_ownership_helpdesk_adds_second_user():
    cfg = {"privilege_escalation": "ApplicationOwnershipAbuse", "initial_access": "user",
           "scenario": "helpdesk", "assignment_type": "direct",
           "method": "AzureADRole", "entra_role": GA_ROLE}
    users, apps = _users(3), _apps(["app-hp"])
    result = _mgr().macro_application_ownership_abuse(
        cfg, users, apps, "contoso.com", mode="random", path_name="own")
    out = build_tfvars(_model(result["primitives"], users=users, applications=apps))
    # one entra role is the Helpdesk Administrator on a user; the other is the app's GA
    entra = list(out["attack_path_entra_role_assignments"].values())
    helpdesk = [r for r in entra if r["role"] == HELPDESK_ROLE]
    assert len(helpdesk) == 1 and helpdesk[0]["principal_type"] == "user"
    assert any(r["role"] == GA_ROLE and r["principal_ref"] == "app-hp" for r in entra)


# ---------------------------------------------------------------------------
# Application / Cloud Application Administrator Abuse
# ---------------------------------------------------------------------------
def test_app_admin_user_direct():
    cfg = {"privilege_escalation": "ApplicationAdministratorAbuse", "initial_access": "user",
           "assignment_type": "direct", "method": "AzureADRole", "entra_role": GA_ROLE}
    users, apps = _users(1), _apps(["app-hp"])
    result = _mgr().macro_application_administrator_abuse(
        cfg, users, apps, "contoso.com", mode="random", path_name="adm")
    out = build_tfvars(_model(result["primitives"], users=users, applications=apps))
    entra = list(out["attack_path_entra_role_assignments"].values())
    admin = [r for r in entra if r["role"] == APP_ADMIN_ROLE_ID]
    assert len(admin) == 1
    assert admin[0]["principal_type"] == "user" and admin[0]["scope_app_ref"] is None
    # target app still gets its GA privilege
    assert any(r["role"] == GA_ROLE and r["principal_ref"] == "app-hp" for r in entra)


def test_app_admin_scoped_to_application():
    cfg = {"privilege_escalation": "ApplicationAdministratorAbuse", "initial_access": "user",
           "assignment_type": "direct", "scope": "application",
           "method": "AzureADRole", "entra_role": GA_ROLE}
    users, apps = _users(1), _apps(["app-hp"])
    result = _mgr().macro_application_administrator_abuse(
        cfg, users, apps, "contoso.com", mode="random", path_name="adm")
    out = build_tfvars(_model(result["primitives"], users=users, applications=apps))
    admin = next(r for r in out["attack_path_entra_role_assignments"].values()
                 if r["role"] == APP_ADMIN_ROLE_ID)
    assert admin["scope_app_ref"] == "app-hp"


def test_app_admin_group_member():
    cfg = {"privilege_escalation": "ApplicationAdministratorAbuse", "initial_access": "user",
           "assignment_type": "group_member", "method": "AzureADRole", "entra_role": GA_ROLE}
    users, apps = _users(1), _apps(["app-hp"])
    result = _mgr().macro_application_administrator_abuse(
        cfg, users, apps, "contoso.com", mode="random", path_name="adm")
    assert len(result["groups"]) == 1
    out = build_tfvars(_model(result["primitives"], result["groups"], users=users, applications=apps))
    admin = next(r for r in out["attack_path_entra_role_assignments"].values()
                 if r["role"] == APP_ADMIN_ROLE_ID)
    assert admin["principal_type"] == "group"
    mem = next(iter(out["attack_path_group_membership_assignments"].values()))
    assert mem["group_ref"] == admin["principal_ref"]


def test_cloud_app_admin_uses_cloud_role():
    cfg = {"privilege_escalation": "CloudAppAdministratorAbuse", "initial_access": "user",
           "assignment_type": "direct", "method": "AzureADRole", "entra_role": GA_ROLE}
    users, apps = _users(1), _apps(["app-hp"])
    result = _mgr().macro_cloud_app_administrator_abuse(
        cfg, users, apps, "contoso.com", mode="random", path_name="cadm")
    out = build_tfvars(_model(result["primitives"], users=users, applications=apps))
    assert any(r["role"] == CLOUD_APP_ADMIN_ROLE_ID
               for r in out["attack_path_entra_role_assignments"].values())
    assert result["summary"]["technique"] == "CloudAppAdministratorAbuse"


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
