"""
test_baseline_generator.py — offline test of the Phase-3 baseline layer (Slice 3).

Verifies that baseline COUNTS produce the right number of random entities and noise
primitives, that noise carries origin=random and the low-privileged catalogs, that
excluded groups are honored, and that resource groups are synthesized when baseline
resources need one.

Runs two ways:
    python tests/test_baseline_generator.py
    pytest tests/test_baseline_generator.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.entity_generator import EntityGenerator  # noqa: E402
from src.baseline_generator import BaselineGenerator  # noqa: E402
from src.primitives import (  # noqa: E402
    RANDOM, EntraRoleAssignment, ApiPermission, GroupMembership, AuMembership,
)
from src.constants import ENTRA_ROLES  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _gen():
    return BaselineGenerator(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def test_entity_counts():
    ents = _gen().generate_entities({
        "identities": {"users": 10, "groups": 4, "applications": 5, "administrative_units": 2},
    })
    assert len(ents["users"]) == 10
    assert len(ents["groups"]) == 4
    assert len(ents["applications"]) == 5
    assert len(ents["administrative_units"]) == 2


def test_resources_get_synthesized_rg():
    ents = _gen().generate_entities({"resources": {"key_vaults": 2}})
    # no resource_groups count given, but KVs need one -> synthesized
    assert len(ents["resource_groups"]) == 1
    assert len(ents["key_vaults"]) == 2
    rg = next(iter(ents["resource_groups"]))
    assert all(kv["resource_group_name"] == rg for kv in ents["key_vaults"].values())


def test_noise_counts_and_origin():
    g = _gen()
    ents = g.generate_entities({"identities": {"users": 12, "groups": 5, "applications": 6}})
    prims = g.generate_noise(
        {"assignments": {"group_memberships": 7, "entra_roles": 4,
                         "api_permissions": 3, "au_memberships": 0}},
        ents, excluded_groups=set())

    gms = [p for p in prims if isinstance(p, GroupMembership)]
    ers = [p for p in prims if isinstance(p, EntraRoleAssignment)]
    aps = [p for p in prims if isinstance(p, ApiPermission)]
    assert len(gms) == 7 and len(ers) == 4 and len(aps) == 3
    assert all(p.origin == RANDOM for p in prims)
    # baseline entra roles come from the LOW-priv catalog (noise != attack signal)
    assert all(p.role in set(ENTRA_ROLES.values()) for p in ers)
    # entra role principals carry the right type for users vs apps
    assert all(p.principal_type in ("user", "service_principal") for p in ers)


def test_noise_excludes_groups():
    g = _gen()
    ents = g.generate_entities({"identities": {"users": 8, "groups": 3}})
    all_groups = set(ents["groups"])
    excluded = {next(iter(all_groups))}
    prims = g.generate_noise(
        {"assignments": {"group_memberships": 50}}, ents, excluded_groups=excluded)
    used_groups = {p.group_ref for p in prims if isinstance(p, GroupMembership)}
    assert excluded.isdisjoint(used_groups)


def test_noise_pairs_are_distinct():
    g = _gen()
    ents = g.generate_entities({"identities": {"users": 3, "groups": 2}})
    # request more memberships than distinct (user,group) pairs (3*2=6)
    prims = g.generate_noise(
        {"assignments": {"group_memberships": 100}}, ents, excluded_groups=set())
    gms = [(p.principal_ref, p.group_ref) for p in prims if isinstance(p, GroupMembership)]
    assert len(gms) == len(set(gms))  # no duplicate memberships
    assert len(gms) <= 6


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
