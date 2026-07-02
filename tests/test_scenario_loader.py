"""
test_scenario_loader.py — offline test of the Phase-3 declarative loader (Slice 1).

Drives the real ScenarioLoader (no Azure) through the Terraform builder and
asserts that a hand-written declarative attack_paths config compiles into the
right generic primitives and a valid terraform.tfvars.json. Covers:
  - a KV-theft-equivalent chain (credential + data_inject + azure_rbac + entra_role)
  - a 2-hop managed-identity chain (principal_type / scope inference)
  - operator-credential surfacing for user and service_principal initial access
  - clear errors for empty-baseline picks and un-inferable types

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
import src.dataplane as dataplane  # noqa: E402

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
# Tier 2 explicit graph — cosmos_document injects (app_secret + arbitrary literal).
# In approach 2 these are DATA-PLANE-ONLY: they compile into the model's primitives
# and the Python data-plane phase plants them, but the builder keeps them OUT of the
# Terraform data_injects family. Exercises the loader -> planner -> resolver path.
# ---------------------------------------------------------------------------
_COSMOS_THEFT = {
    "schema": "graph",
    "attack_paths": {
        "cosmos_theft": {
            "objective": {"capability": "read_cosmos", "target_ref": "cos01"},
            "initial_access": {"method": "compromised_identity", "principal_ref": "alice"},
            "identities": {
                "users": [{"ref": "alice"}],
                "applications": [{"ref": "app_highpriv"}],
            },
            "resources": {"cosmos_dbs": [{"ref": "cos01"}]},
            "assignments": [
                {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                 "role": "00000000-0000-0000-0000-000000000002", "scope_ref": "cos01",
                 "scope_resource_type": "cosmos_db", "data_plane": "cosmos_sql"},
                {"id": "a2", "type": "entra_role", "principal_ref": "app_highpriv",
                 "role": GA_ROLE},
            ],
            "credentials": [
                {"ref": "app_secret", "app_ref": "app_highpriv", "type": "password"},
            ],
            "data_injects": [
                {"id": "d1", "material": "app_secret", "credential_ref": "app_secret",
                 "location_type": "cosmos_document", "location_ref": "cos01",
                 "name": "client-secret-app_highpriv"},
                {"id": "d2", "material": "literal", "literal_value": '{"k":"v"}',
                 "location_type": "cosmos_document", "location_ref": "cos01",
                 "name": "seed-doc"},
            ],
        }
    },
}


def test_explicit_cosmos_document_injects_compile_offline():
    scenario = _load(_COSMOS_THEFT)
    model = scenario.model
    out = build_tfvars(model)  # also runs ref-validation

    # cosmos_document injects are data-plane-only: NOT in the TF data_injects family.
    assert not out.get("attack_path_data_injects")

    # but they DO compile into the model's primitives, and the planner picks them up
    # with coordinates resolved from the synthesized cosmos entity.
    items = dataplane.collect_dataplane_injects(model)
    by_name = {it.inject.name: it for it in items}
    assert set(by_name) == {"client-secret-app_highpriv", "seed-doc"}
    secret_item = by_name["client-secret-app_highpriv"]
    assert secret_item.account_ref == "cos01"
    assert secret_item.database_name and secret_item.container_name
    assert secret_item.partition_key_path == "/id"

    # the cosmos data-plane RBAC grant still resolves against the cosmos_dbs map
    rbac = out["attack_path_azure_rbac_assignments"]["cosmos_theft__a1"]
    assert rbac["scope_resource_type"] == "cosmos_db" and rbac["scope_ref"] == "cos01"
    assert rbac["data_plane"] == "cosmos_sql"

    # value resolution: literal verbatim; app_secret via the SAME origin-prefixed
    # credential key the builder/TF output use.
    cred_origin = dataplane.credential_origin_map(model)
    literal_item = by_name["seed-doc"]
    assert dataplane.resolve_value(literal_item.inject, {}, cred_origin) == '{"k":"v"}'
    fake_outputs = {"generic_app_credentials":
                    {"ap:cosmos_theft__app_secret": {"client_secret": "S3cr3t!"}}}
    assert dataplane.resolve_value(secret_item.inject, fake_outputs, cred_origin) == "S3cr3t!"

    # build_document shape: {id, <pk field 'id'>, content}
    assert dataplane.build_document(literal_item, '{"k":"v"}') == \
        {"id": "seed-doc", "content": '{"k":"v"}'}


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
# Slice 2: name resolution through the loader
# ---------------------------------------------------------------------------
def test_loader_resolves_role_name_and_list_fans_out():
    config = {
        "attack_paths": {
            "p": {
                "initial_access": {"principal_ref": "alice"},
                "identities": {
                    "users": [{"ref": "alice"}],
                    "applications": [{"ref": "app1"}],
                },
                "assignments": [
                    # friendly name -> GUID
                    {"id": "r1", "type": "entra_role", "principal_ref": "app1",
                     "role": "Global Administrator"},
                    # a list fans out to one primitive per resolved GUID
                    {"id": "r2", "type": "entra_role", "principal_ref": "app1",
                     "role": ["User Administrator", "Security Administrator"]},
                    # graph permission by name
                    {"id": "perm", "type": "api_permission", "principal_ref": "app1",
                     "app_role": "RoleManagement.ReadWrite.Directory"},
                ],
            }
        }
    }
    out = build_tfvars(_load(config).model)

    roles = out["attack_path_entra_role_assignments"]
    assert roles["p__r1"]["role"] == GA_ROLE
    # r2 list -> two positional keys
    assert roles["p__r2_0"]["role"] == "fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Administrator
    assert roles["p__r2_1"]["role"] == "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Administrator

    perms = out["attack_path_api_permission_assignments"]
    assert perms["p__perm"]["permission_id"] == "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
    assert perms["p__perm"]["api_type"] == "graph"


# ---------------------------------------------------------------------------
# Slice 3: baseline layer + from: baseline + hybrid
# ---------------------------------------------------------------------------
def test_baseline_only_generates_random_entities_and_noise():
    config = {
        "schema": "graph",
        "baseline": {
            "identities": {"users": 12, "groups": 5, "applications": 6},
            "assignments": {"group_memberships": 8, "entra_roles": 4, "api_permissions": 3},
        },
    }
    model = _load(config).model
    assert len(model.users) == 12 and len(model.groups) == 5 and len(model.applications) == 6
    out = build_tfvars(model)
    # noise lands in the random_* families, with the requested counts
    assert len(out["random_group_membership_assignments"]) == 8
    assert len(out["random_entra_role_assignments"]) == 4
    assert len(out["random_api_permission_assignments"]) == 3
    # ...and NOT in the attack_path_* families
    assert not out.get("attack_path_entra_role_assignments")


def test_hybrid_from_baseline_binds_victim_and_keeps_attack_origin():
    config = {
        "baseline": {"identities": {"users": 10, "key_vaults": 0}},
        "attack_paths": {
            "opportunistic": {
                "objective": {"name": "KV secrets", "impact": "high"},
                "initial_access": {"principal_ref": "victim"},
                "identities": {"users": [{"ref": "victim", "from": "baseline"}]},
                "resources": {"key_vaults": [{"ref": "kv01"}]},
                "assignments": [
                    {"id": "a1", "type": "azure_rbac", "principal_ref": "victim",
                     "role": "Key Vault Contributor", "scope_ref": "kv01"},
                ],
            }
        },
    }
    scenario = _load(config)
    model = scenario.model
    out = build_tfvars(model)

    rbac = out["attack_path_azure_rbac_assignments"]["opportunistic__a1"]
    # victim was bound to a real baseline user key (not the literal alias "victim")
    assert rbac["principal_ref"] != "victim"
    assert rbac["principal_ref"] in model.users
    assert rbac["principal_type"] == "user"
    # operator creds resolve to the bound baseline user's password
    creds = scenario.attack_paths[0].credentials
    assert creds["user_principal_name"].split("@")[0] == rbac["principal_ref"]
    assert creds["password"] == model.users[rbac["principal_ref"]]["password"]


def test_from_baseline_without_baseline_entities_errors():
    config = {
        "attack_paths": {
            "p": {
                "identities": {"users": [{"ref": "victim", "from": "baseline"}]},
                "assignments": [],
            }
        }
    }
    try:
        _load(config)
        assert False, "expected ScenarioConfigError for empty baseline"
    except ScenarioConfigError as e:
        assert "baseline" in str(e).lower()


def _named_baseline_match_config(match_value):
    """A baseline with named users + one attack path that threads a NAMED baseline
    employee via `{from: baseline, match: ...}`."""
    return {
        "baseline": {
            "identities": {"users": [{"ref": "hannah.lee"}, {"ref": "raj.patel"}]},
        },
        "attack_paths": {
            "targeted": {
                "objective": {"name": "KV secrets", "impact": "high"},
                "initial_access": {"principal_ref": "victim"},
                "identities": {
                    "users": [{"ref": "victim", "from": "baseline",
                               "match": match_value}],
                },
                "resources": {"key_vaults": [{"ref": "kv01"}]},
                "assignments": [
                    {"id": "a1", "type": "azure_rbac", "principal_ref": "victim",
                     "role": "Key Vault Contributor", "scope_ref": "kv01"},
                ],
            }
        },
    }


def test_from_baseline_match_binds_named_employee_by_ref():
    scenario = _load(_named_baseline_match_config("hannah.lee"))
    out = build_tfvars(scenario.model)
    rbac = out["attack_path_azure_rbac_assignments"]["targeted__a1"]
    # the alias resolved to the SPECIFIC named baseline user, not a random pick
    assert rbac["principal_ref"] == "hannah.lee"


def test_from_baseline_match_resolves_display_name_case_insensitively():
    # explicit baseline users get display_name "Hannah Lee" from the "hannah.lee" ref
    scenario = _load(_named_baseline_match_config("hannah lee"))
    out = build_tfvars(scenario.model)
    rbac = out["attack_path_azure_rbac_assignments"]["targeted__a1"]
    assert rbac["principal_ref"] == "hannah.lee"


def test_from_baseline_match_unknown_errors_with_available_list():
    try:
        _load(_named_baseline_match_config("nope.nobody"))
        assert False, "expected ScenarioConfigError for unmatched baseline name"
    except ScenarioConfigError as e:
        msg = str(e)
        assert "nope.nobody" in msg and "hannah.lee" in msg  # lists what's available


def test_match_without_from_baseline_errors():
    config = {
        "baseline": {"identities": {"users": [{"ref": "hannah.lee"}]}},
        "attack_paths": {
            "p": {
                "identities": {"users": [{"ref": "victim", "match": "hannah.lee"}]},
                "assignments": [],
            }
        },
    }
    try:
        _load(config)
        assert False, "expected ScenarioConfigError for match without from: baseline"
    except ScenarioConfigError as e:
        assert "match" in str(e).lower() and "baseline" in str(e).lower()


def test_match_cannot_double_bind_one_baseline_entity():
    config = {
        "baseline": {"identities": {"users": [{"ref": "hannah.lee"}, {"ref": "raj.patel"}]}},
        "attack_paths": {
            "p": {
                "objective": {"name": "x", "impact": "high"},
                "initial_access": {"principal_ref": "v1"},
                "identities": {"users": [
                    {"ref": "v1", "from": "baseline", "match": "hannah.lee"},
                    {"ref": "v2", "from": "baseline", "match": "hannah.lee"},
                ]},
                "assignments": [
                    {"id": "a1", "type": "entra_role", "principal_ref": "v1",
                     "role": GA_ROLE},
                ],
            }
        },
    }
    try:
        _load(config)
        assert False, "expected ScenarioConfigError for double-bound baseline entity"
    except ScenarioConfigError as e:
        assert "already bound" in str(e).lower()


def test_attack_group_excluded_from_baseline_noise():
    # A baseline with one group, used as an attack-path role principal: noise must
    # NOT add random members to it (it's the only group, so 0 memberships result).
    config = {
        "baseline": {
            "identities": {"users": 8, "groups": 1},
            "assignments": {"group_memberships": 10},
        },
        "attack_paths": {
            "grp": {
                "identities": {"groups": [{"ref": "g", "from": "baseline"}]},
                "assignments": [
                    {"id": "a1", "type": "entra_role", "principal_ref": "g",
                     "principal_type": "group", "role": "Global Administrator"},
                ],
            }
        },
    }
    out = build_tfvars(_load(config).model)
    # the sole group is the attack group -> excluded -> no random memberships
    assert not out.get("random_group_membership_assignments")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------
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


def test_certificate_leg_auto_mints_real_files_and_builds():
    """A declarative path may DECLARE a certificate credential + app_certificate inject
    WITHOUT supplying files; the loader deterministically mints real cert/key/pfx files
    (Option A: in-memory at compile), fills the paths, and the full preflight
    build_tfvars(verify_files=True) then passes. The credential and inject for the same
    app share ONE minted cert triple."""
    from src.primitives import AppCredential, DataInject
    from src.terraform_builder import build_tfvars as _bt

    config = {
        "schema": "graph",
        "attack_paths": {
            "cert_theft": {
                "objective": {"name": "Signing cert theft", "impact": "high"},
                "initial_access": {"method": "compromised_identity",
                                   "principal_ref": "alice"},
                "identities": {
                    "users": [{"ref": "alice"}],
                    "applications": [{"ref": "app_highpriv"}],
                },
                "resources": {"storage_accounts": [{"ref": "sa01"}]},
                "assignments": [
                    {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                     "role": "Storage Blob Data Reader", "scope_ref": "sa01"},
                    {"id": "a2", "type": "entra_role", "principal_ref": "app_highpriv",
                     "role": GA_ROLE},
                ],
                "credentials": [
                    {"ref": "signing_cert", "app_ref": "app_highpriv",
                     "type": "certificate"},
                ],
                "data_injects": [
                    {"id": "d1", "material": "app_certificate",
                     "source_ref": "app_highpriv", "location": "storage_blob",
                     "location_ref": "sa01", "name": "app_highpriv-signing.pfx"},
                ],
            }
        },
    }
    scenario = _loader().load(config, domain="contoso.com", enforce_reachability=False)
    model = scenario.model

    cert_cred = next(p for p in model.primitives
                     if isinstance(p, AppCredential) and p.type == "certificate")
    cert_inject = next(p for p in model.primitives
                       if isinstance(p, DataInject) and p.material == "app_certificate")
    assert cert_cred.certificate_path, "certificate credential should be auto-minted a path"
    assert cert_inject.file_path and cert_inject.file_path.endswith(".pfx")
    # Same app -> one shared cert triple: <app>-<suffix>.pem / .key / .pfx.
    assert cert_cred.certificate_path[:-4] == cert_inject.file_path[:-4]

    key_sibling = cert_cred.certificate_path[:-4] + ".key"
    minted = [cert_cred.certificate_path, cert_inject.file_path, key_sibling]
    try:
        for path in (cert_cred.certificate_path, cert_inject.file_path):
            assert os.path.exists(os.path.join(_REPO, "terraform", path)), \
                f"minted file {path} should exist on disk"
        # Full preflight (verify_files=True) passes now that the files are real.
        _bt(model, verify_files=True)
    finally:
        for path in minted:
            fp = os.path.join(_REPO, "terraform", path)
            if os.path.exists(fp):
                os.remove(fp)


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
