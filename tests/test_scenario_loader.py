"""
test_scenario_loader.py — offline test of the Phase-3 declarative loader (Slice 1).

Drives the real ScenarioLoader (no Azure) through the Terraform builder and
asserts that a hand-written declarative attack_paths config compiles into the
right generic primitives and a valid terraform.tfvars.json. Covers:
  - a KV-theft-equivalent chain (credential + data_inject + azure_rbac + entra_role)
  - a 2-hop managed-identity chain (principal_type / scope inference)
  - operator-credential surfacing for user and service_principal initial access
  - clear errors for unimplemented pool features and un-inferable types

No live tenant: this exercises the YAML -> DeploymentModel decomposition and the
builder validation only. The actual `terraform apply` is the live acceptance step.

Runs two ways:
    python tests/test_scenario_loader.py
    pytest tests/test_scenario_loader.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import ScenarioLoader, ScenarioConfigError  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _loader():
    # Absolute entity_data dir so the test runs regardless of cwd.
    return ScenarioLoader(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def _load(config):
    return _loader().load(config, domain="contoso.com")


# ---------------------------------------------------------------------------
# KV-theft-equivalent chain (the macro's chain, written declaratively)
# ---------------------------------------------------------------------------
_KV_THEFT = {
    "schema": "graph",
    "attack_paths": {
        "kv_theft": {
            "objective": {"name": "Key Vault secrets", "impact": "high"},
            "initial_access": {"method": "compromised_identity", "principal_ref": "alice"},
            "identities": {
                "users": [{"ref": "alice"}],
                "applications": [{"ref": "app_highpriv"}],
            },
            "resources": {"key_vaults": [{"ref": "kv01"}]},
            "assignments": [
                {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                 "role": "Key Vault Contributor", "scope_ref": "kv01"},
                {"id": "a2", "type": "entra_role", "principal_ref": "app_highpriv",
                 "role": GA_ROLE},
            ],
            "credentials": [
                {"ref": "app_secret", "app_ref": "app_highpriv", "type": "password"},
            ],
            "data_injects": [
                {"id": "d1", "material": "app_secret", "credential_ref": "app_secret",
                 "location": "key_vault_secret", "location_ref": "kv01",
                 "name": "client-secret-app_highpriv"},
            ],
        }
    },
}


def test_kv_theft_chain_compiles_to_generic_families():
    scenario = _load(_KV_THEFT)
    model = scenario.model

    # Entities were built with symbolic keys (== the refs the assignments use).
    assert set(model.users) == {"alice"}
    assert set(model.applications) == {"app_highpriv"}
    assert set(model.key_vaults) == {"kv01"}
    # A default resource group was synthesized for the unparented key vault.
    assert model.key_vaults["kv01"]["resource_group_name"] in model.resource_groups

    out = build_tfvars(model)

    # one app_credential (the looted secret) + one data_inject planting it
    creds = out["attack_path_app_credentials"]
    assert set(creds) == {"kv_theft__app_secret"}
    assert creds["kv_theft__app_secret"]["app_ref"] == "app_highpriv"
    assert creds["kv_theft__app_secret"]["type"] == "password"

    injects = out["attack_path_data_injects"]
    inj = injects["kv_theft__d1"]
    assert inj["material"] == "app_secret"
    assert inj["location_type"] == "key_vault_secret"
    assert inj["location_ref"] == "kv01"
    assert inj["name"] == "client-secret-app_highpriv"
    # credential_ref is origin-prefixed to the looted credential's namespaced key
    assert inj["credential_ref"] == "ap:kv_theft__app_secret"

    # Key Vault Contributor: principal_type inferred (user), scope inferred (resource/kv)
    rbac = out["attack_path_azure_rbac_assignments"]["kv_theft__a1"]
    assert rbac["role"] == "Key Vault Contributor"
    assert rbac["principal_ref"] == "alice" and rbac["principal_type"] == "user"
    assert rbac["scope_type"] == "resource"
    assert rbac["scope_resource_type"] == "key_vault"
    assert rbac["scope_ref"] == "kv01"

    # app privilege = one Entra role on the looted app's SP (principal_type inferred)
    role = out["attack_path_entra_role_assignments"]["kv_theft__a2"]
    assert role["role"] == GA_ROLE
    assert role["principal_ref"] == "app_highpriv"
    assert role["principal_type"] == "service_principal"

    # user initial access -> operator gets UPN + password
    cred = scenario.attack_paths[0].credentials
    assert cred["initial_access"] == "user"
    assert cred["user_principal_name"] == "alice@contoso.com"
    assert cred["password"] == model.users["alice"]["password"]


# ---------------------------------------------------------------------------
# 2-hop managed-identity chain — VM MI reads a KV secret holding a GA app secret
# ---------------------------------------------------------------------------
_MI_CHAIN = {
    "attack_paths": {
        "vm_to_ga": {
            "objective": {"name": "Global Administrator", "impact": "critical"},
            "initial_access": {"method": "phishing", "principal_ref": "alice"},
            "identities": {
                "users": [{"ref": "alice"}],
                "applications": [{"ref": "automation"}],
            },
            "resources": {
                "virtual_machines": [{"ref": "vm01", "os_type": "Linux"}],
                "key_vaults": [{"ref": "kv01"}],
            },
            "assignments": [
                {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                 "role": "Virtual Machine Contributor", "scope_ref": "vm01"},
                {"id": "a2", "type": "azure_rbac", "principal_ref": "vm01",
                 "principal_type": "managed_identity", "mi_source": "vm",
                 "role": "Key Vault Secrets User", "scope_ref": "kv01"},
                {"id": "a3", "type": "entra_role", "principal_ref": "automation",
                 "role": GA_ROLE},
            ],
            "credentials": [
                {"ref": "automation_secret", "app_ref": "automation", "type": "password"},
            ],
            "data_injects": [
                {"id": "d1", "material": "app_secret", "credential_ref": "automation_secret",
                 "location_type": "key_vault_secret", "location_ref": "kv01", "name": "prod-sp"},
            ],
        }
    },
}


def test_managed_identity_chain_infers_types_and_scopes():
    scenario = _load(_MI_CHAIN)
    out = build_tfvars(scenario.model)

    rbac = out["attack_path_azure_rbac_assignments"]
    # a1: user -> VM (scope inferred as resource/virtual_machine)
    a1 = rbac["vm_to_ga__a1"]
    assert a1["principal_type"] == "user"
    assert a1["scope_resource_type"] == "virtual_machine" and a1["scope_ref"] == "vm01"
    # a2: VM managed identity -> KV (explicit principal_type + mi_source)
    a2 = rbac["vm_to_ga__a2"]
    assert a2["principal_type"] == "managed_identity"
    assert a2["mi_source_type"] == "vm"
    assert a2["scope_resource_type"] == "key_vault" and a2["scope_ref"] == "kv01"

    # entra role on the automation SP
    assert out["attack_path_entra_role_assignments"]["vm_to_ga__a3"]["role"] == GA_ROLE
    # data_inject planting the automation secret resolves to the namespaced cred key
    assert out["attack_path_data_injects"]["vm_to_ga__d1"]["credential_ref"] \
        == "ap:vm_to_ga__automation_secret"


# ---------------------------------------------------------------------------
# Service-principal initial access surfaces a minted credential
# ---------------------------------------------------------------------------
def test_sp_initial_access_mints_and_surfaces_credential():
    config = {
        "attack_paths": {
            "sp_path": {
                "initial_access": {"principal_ref": "attacker_sp"},
                "identities": {"applications": [{"ref": "attacker_sp"}]},
                "assignments": [
                    {"id": "a1", "type": "entra_role", "principal_ref": "attacker_sp",
                     "role": GA_ROLE},
                ],
            }
        }
    }
    scenario = _load(config)
    out = build_tfvars(scenario.model)

    cred = scenario.attack_paths[0].credentials
    assert cred["initial_access"] == "service_principal"
    assert cred["service_principal_name"] == "attacker_sp"
    sp_key = cred["generic_credential_key"]
    assert sp_key.startswith("ap:")
    # the minted credential exists in the app_credentials family
    assert sp_key.split("ap:", 1)[1] in out["attack_path_app_credentials"]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------
def test_pool_section_not_implemented_yet():
    config = {"pool": {"identities": {"users": 5}}, "attack_paths": {}}
    try:
        _load(config)
        assert False, "expected ScenarioConfigError for pool section"
    except ScenarioConfigError as e:
        assert "pool" in str(e).lower()


def test_from_pool_ref_not_implemented_yet():
    config = {
        "attack_paths": {
            "p": {
                "identities": {"users": [{"ref": "victim", "from": "pool"}]},
                "assignments": [],
            }
        }
    }
    try:
        _load(config)
        assert False, "expected ScenarioConfigError for from: pool"
    except ScenarioConfigError as e:
        assert "pool" in str(e).lower()


def test_uninferable_principal_type_errors():
    config = {
        "attack_paths": {
            "p": {
                "identities": {},
                "resources": {"virtual_machines": [{"ref": "vm01"}]},
                # principal is a resource with no explicit principal_type -> error
                "assignments": [
                    {"id": "a1", "type": "azure_rbac", "principal_ref": "vm01",
                     "role": "Reader", "scope_type": "subscription"},
                ],
            }
        }
    }
    try:
        _load(config)
        assert False, "expected ScenarioConfigError for un-inferable principal_type"
    except ScenarioConfigError as e:
        assert "principal_type" in str(e)


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
