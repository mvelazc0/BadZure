"""
test_explicit_baseline.py — offline test of the EXPLICIT baseline form (Slice 1 of
the LLM-org-baseline phase).

The declarative `baseline:` section used to accept only COUNTS. This slice lets it
also carry NAMED, explicit identities/resources/assignments (the same symbolic-ref
shape attack paths use), tagged origin=random — the shape the LLM org-generator will
emit. These tests drive the real ScenarioLoader (no Azure) and assert:
  - explicit baseline entities are built with their declared refs
  - explicit baseline assignments compile to origin=random primitives, with
    principal_type/scope inference working as for attack paths
  - counts and explicit specs coexist in one baseline
  - the hand-written examples/chained/chained_org_baseline.yml fixture compiles and
    builds a valid terraform.tfvars.json
  - the validator rejects malformed baselines (missing ref / bad assignment)

Runs two ways:
    python tests/test_explicit_baseline.py
    pytest tests/test_explicit_baseline.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import ScenarioLoader, ScenarioConfigError  # noqa: E402
from src import scenario_validator  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402
from src.primitives import (  # noqa: E402
    RANDOM, ATTACK_PATH, EntraRoleAssignment, AzureRbacAssignment, ApiPermission,
    GroupMembership, AuMembership, GroupOwnership, AppOwnership, AppCredential,
    DataInject,
)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FIXTURE = os.path.join(_REPO, "examples", "chained", "chained_org_baseline.yml")


def _loader():
    return ScenarioLoader(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def _load(config):
    return _loader().load(config, domain="contoso.com")


# ---------------------------------------------------------------------------
# A small explicit baseline (no attack paths).
# ---------------------------------------------------------------------------
_EXPLICIT = {
    "schema": "graph",
    "baseline": {
        "identities": {
            "users": [{"ref": "alice.chen"}, {"ref": "bob.singh"}],
            "groups": [{"ref": "Engineering"}],
            "applications": [{"ref": "cicd-pipeline"}],
            "administrative_units": [{"ref": "Finance-Unit"}],
        },
        "resources": {
            "resource_groups": [{"ref": "rg-prod", "location": "East US"}],
            "key_vaults": [{"ref": "kv-demo-prod", "resource_group": "rg-prod"}],
        },
        "assignments": [
            {"type": "group_membership", "principal_ref": "alice.chen",
             "group_ref": "Engineering"},
            {"type": "entra_role", "principal_ref": "bob.singh",
             "role": "Helpdesk Administrator"},
            {"type": "azure_rbac", "principal_ref": "cicd-pipeline",
             "role": "Reader", "scope_ref": "rg-prod"},
            {"type": "api_permission", "principal_ref": "cicd-pipeline",
             "app_role": "User.Read.All", "api_type": "graph"},
            {"type": "au_membership", "principal_ref": "alice.chen",
             "au_ref": "Finance-Unit"},
        ],
    },
}


def test_explicit_baseline_entities_built_with_refs():
    sm = _load(_EXPLICIT)
    m = sm.model
    assert set(m.users) == {"alice.chen", "bob.singh"}
    assert "Engineering" in m.groups
    assert "cicd-pipeline" in m.applications
    assert "Finance-Unit" in m.administrative_units
    assert "rg-prod" in m.resource_groups
    assert "kv-demo-prod" in m.key_vaults
    # the KV is attached to the declared RG, not a synthesized default
    assert m.key_vaults["kv-demo-prod"]["resource_group_name"] == "rg-prod"


def test_explicit_baseline_assignments_are_origin_random():
    sm = _load(_EXPLICIT)
    prims = sm.model.primitives
    assert prims, "expected baseline primitives"
    # every emitted baseline assignment is origin=random (not attack_path)
    assert all(p.origin == RANDOM for p in prims)
    assert not any(p.origin == ATTACK_PATH for p in prims)

    gm = [p for p in prims if isinstance(p, GroupMembership)]
    er = [p for p in prims if isinstance(p, EntraRoleAssignment)]
    rbac = [p for p in prims if isinstance(p, AzureRbacAssignment)]
    api = [p for p in prims if isinstance(p, ApiPermission)]
    au = [p for p in prims if isinstance(p, AuMembership)]
    assert len(gm) == 1 and gm[0].principal_ref == "alice.chen" and gm[0].group_ref == "Engineering"
    assert gm[0].principal_type == "user"  # inferred
    assert len(er) == 1 and er[0].principal_ref == "bob.singh"
    # azure_rbac scope inference: rg-prod is a resource_group -> resource_group scope
    assert len(rbac) == 1 and rbac[0].scope_type == "resource_group"
    assert rbac[0].principal_type == "service_principal"  # cicd-pipeline is an app
    assert len(api) == 1 and api[0].api_type == "graph"
    assert len(au) == 1 and au[0].au_ref == "Finance-Unit"


def test_explicit_baseline_builds_valid_tfvars():
    sm = _load(_EXPLICIT)
    tfvars = build_tfvars(sm.model)  # raises on dangling refs / bad schema
    assert isinstance(tfvars, dict)


def test_counts_and_explicit_coexist():
    # users explicit (named), groups as a COUNT -> both build into one baseline.
    sm = _load({
        "schema": "graph",
        "baseline": {
            "identities": {"users": [{"ref": "alice.chen"}], "groups": 3},
        },
    })
    assert "alice.chen" in sm.model.users        # explicit user present
    assert len(sm.model.groups) == 3             # count groups present


_FULL = {
    "schema": "graph",
    "baseline": {
        "identities": {
            "users": [{"ref": "lead.dev"}],
            "groups": [{"ref": "Engineering"}],
            "applications": [{"ref": "cicd"}],
            "administrative_units": [{"ref": "Finance-Unit"}],
        },
        "resources": {
            "resource_groups": [{"ref": "rg-prod", "location": "East US"}],
            "key_vaults": [{"ref": "kv-full01", "resource_group": "rg-prod"}],
            "storage_accounts": [{"ref": "stfull01", "resource_group": "rg-prod"}],
        },
        "assignments": [
            {"type": "group_membership", "principal_ref": "lead.dev", "group_ref": "Engineering"},
            {"type": "group_ownership", "principal_ref": "lead.dev", "group_ref": "Engineering"},
            {"type": "app_ownership", "principal_ref": "lead.dev", "app_ref": "cicd"},
            {"type": "au_membership", "principal_ref": "Engineering", "au_ref": "Finance-Unit"},
            {"type": "entra_role", "principal_ref": "lead.dev", "role": "Helpdesk Administrator"},
            {"type": "azure_rbac", "principal_ref": "cicd", "role": "Reader", "scope_ref": "rg-prod"},
            {"type": "api_permission", "principal_ref": "cicd", "app_role": "User.Read.All",
             "api_type": "graph"},
        ],
        "credentials": [{"ref": "cicd-secret", "app_ref": "cicd", "type": "password"}],
        "data_injects": [
            {"material": "literal", "location_type": "key_vault_secret",
             "location_ref": "kv-full01", "name": "db-conn", "literal_value": "FAKE-xyz"},
            {"material": "literal", "location_type": "storage_blob",
             "location_ref": "stfull01", "name": "cfg.json", "literal_value": "FAKE-blob"},
        ],
    },
}


def test_count_baseline_full_primitives_build():
    # The COUNT-driven baseline (Slice 3b) now emits all 9 primitive kinds; ensure
    # the random_* families build end-to-end through the loader + builder.
    sm = _load({
        "schema": "graph",
        "baseline": {
            "identities": {"users": 8, "groups": 3, "applications": 4,
                           "administrative_units": 2},
            "resources": {"resource_groups": 1, "key_vaults": 1, "storage_accounts": 1},
            "assignments": {
                "group_memberships": 5, "entra_roles": 3, "api_permissions": 2,
                "au_memberships": 2, "azure_rbac": 6, "group_ownerships": 2,
                "app_ownerships": 2, "app_credentials": 2, "data_injects": 3,
            },
        },
    })
    prims = sm.model.primitives
    assert all(p.origin == RANDOM for p in prims)
    present = {type(p) for p in prims}
    assert {AzureRbacAssignment, AppCredential, DataInject,
            GroupOwnership, AppOwnership} <= present
    build_tfvars(sm.model)  # random_* families for all 9 primitives must build


def test_baseline_exercises_all_nine_primitives():
    sm = _load(_FULL)
    prims = sm.model.primitives
    assert all(p.origin == RANDOM for p in prims)
    present = {type(p) for p in prims}
    for cls in (GroupMembership, GroupOwnership, AppOwnership, AuMembership,
                EntraRoleAssignment, AzureRbacAssignment, ApiPermission,
                AppCredential, DataInject):
        assert cls in present, f"missing {cls.__name__} in baseline primitives"
    # a group can be an AU member
    au = [p for p in prims if isinstance(p, AuMembership)]
    assert any(p.principal_type == "group" for p in au)
    build_tfvars(sm.model)  # all 9 primitive families build under origin=random


def test_fixture_compiles_and_builds():
    with open(_FIXTURE) as f:
        cfg = yaml.safe_load(f)
    sm = _load(cfg)
    m = sm.model
    # spot-check the realistic org came through
    assert "alice.chen" in m.users and "eve.martin" in m.users
    assert {"Engineering", "Sales", "Finance", "IT-Admins"} <= set(m.groups)
    assert "cicd-pipeline" in m.applications
    # exact resource names are tweaked for global uniqueness; just assert topology
    assert len(m.key_vaults) == 1 and len(m.storage_accounts) == 1
    assert all(p.origin == RANDOM for p in m.primitives)
    build_tfvars(m)  # must produce a valid tfvars dict


# ---------------------------------------------------------------------------
# Validator rejections
# ---------------------------------------------------------------------------
def _expect_validation_error(config, needle):
    try:
        scenario_validator.validate(config)
    except ScenarioConfigError as e:
        assert needle in str(e), f"expected '{needle}' in:\n{e}"
        return
    raise AssertionError(f"expected ScenarioConfigError mentioning '{needle}'")


def test_validator_rejects_missing_ref():
    _expect_validation_error(
        {"baseline": {"identities": {"users": [{"display_name": "no ref"}]}}},
        "missing a required `ref`",
    )


def test_validator_rejects_unknown_assignment_type():
    _expect_validation_error(
        {"baseline": {"assignments": [
            {"type": "teleportation", "principal_ref": "alice"}]}},
        "unknown type 'teleportation'",
    )


def test_validator_rejects_assignment_without_principal():
    _expect_validation_error(
        {"baseline": {"assignments": [{"type": "group_membership"}]}},
        "has no `principal_ref`",
    )


def test_validator_rejects_duplicate_ref():
    _expect_validation_error(
        {"baseline": {"identities": {
            "users": [{"ref": "dup"}], "groups": [{"ref": "dup"}]}}},
        "duplicate entity ref 'dup'",
    )


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
