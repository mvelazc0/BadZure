"""
test_terraform_builder_validation.py — reference/structural checks.

These prove the Terraform builder REJECTS a broken lab in milliseconds (clear
Python error) rather than emitting Terraform that explodes minutes into `apply`.
Each test builds a deliberately-broken DeploymentModel and asserts
LabValidationError.

Runs two ways:
    python tests/test_terraform_builder_validation.py
    pytest tests/test_terraform_builder_validation.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.primitives import (  # noqa: E402
    DeploymentModel, RANDOM, ATTACK_PATH,
    EntraRoleAssignment, AzureRbacAssignment, AppCredential, DataInject,
)
from src.terraform_builder import build_tfvars, LabValidationError  # noqa: E402


def _base_model(**kw):
    """A minimal VALID lab; callers add a broken building block via primitives=."""
    defaults = dict(
        users={"alice": {"user_principal_name": "alice", "display_name": "Alice",
                         "mail_nickname": "alice", "password": "x"}},
        groups={"g1": {"display_name": "G1"}},
        applications={"app1": {"display_name": "App1"}},
        resource_groups={"rg1": {"name": "rg1", "location": "West US"}},
        key_vaults={"kv1": {"name": "kv1", "location": "West US",
                            "resource_group_name": "rg1", "sku_name": "standard"}},
        primitives=[],
    )
    defaults.update(kw)
    return DeploymentModel(**defaults)


def _assert_raises(fn):
    try:
        fn()
    except LabValidationError:
        return
    raise AssertionError("expected LabValidationError, none raised")


def test_dangling_principal_ref_rejected():
    m = _base_model(primitives=[
        EntraRoleAssignment("bad", ATTACK_PATH, "ghost", "user", "role-guid"),
    ])
    _assert_raises(lambda: build_tfvars(m))


def test_dangling_scope_ref_rejected():
    m = _base_model(primitives=[
        AzureRbacAssignment("bad", ATTACK_PATH, "alice", "user", "Key Vault Reader",
                            "resource", scope_resource_type="key_vault",
                            scope_ref="ghost_kv"),
    ])
    _assert_raises(lambda: build_tfvars(m))


def test_dangling_credential_ref_rejected():
    m = _base_model(primitives=[
        DataInject("bad", ATTACK_PATH, "app_secret", "key_vault_secret", "kv1",
                   "s", credential_ref="no_such_cred"),
    ])
    _assert_raises(lambda: build_tfvars(m))


def test_material_missing_companion_rejected():
    # material app_secret without credential_ref
    m = _base_model(primitives=[
        DataInject("bad", ATTACK_PATH, "app_secret", "key_vault_secret", "kv1", "s"),
    ])
    _assert_raises(lambda: build_tfvars(m))


def test_wrong_kind_ref_rejected():
    # group_ref must name a group; pointing it at an application is rejected
    m = _base_model(primitives=[
        # an entra_role whose principal is a 'group' but names an application key
        EntraRoleAssignment("bad", ATTACK_PATH, "app1", "group", "role-guid"),
    ])
    _assert_raises(lambda: build_tfvars(m))


def test_duplicate_credential_key_rejected():
    m = _base_model(primitives=[
        AppCredential("dup", RANDOM, "app1", "password"),
        AppCredential("dup", ATTACK_PATH, "app1", "password"),
    ])
    _assert_raises(lambda: build_tfvars(m))


def test_valid_model_compiles():
    m = _base_model(primitives=[
        AppCredential("cred", ATTACK_PATH, "app1", "password"),
        DataInject("inj", ATTACK_PATH, "app_secret", "key_vault_secret", "kv1",
                   "s", credential_ref="cred"),
    ])
    out = build_tfvars(m)
    assert out["attack_path_data_injects"]["inj"]["credential_ref"] == "ap:cred"


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
