"""
test_name_resolver.py — offline test of the Phase-3 name->GUID resolver (Slice 2).

Covers the four input forms (GUID passthrough / name / list / random) for both
Entra roles and API permissions, the case-insensitive fallback, clear errors for
unknown names and api_types, and the catalog-overrides merge.

Runs two ways:
    python tests/test_name_resolver.py
    pytest tests/test_name_resolver.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.name_resolver import NameResolver, NameResolutionError, is_guid  # noqa: E402
from src.constants import HIGH_PRIVILEGED_ENTRA_ROLES  # noqa: E402

GA = "62e90394-69f5-4237-9190-012177145e10"          # Global Administrator
ROLEMGMT = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"    # RoleManagement.ReadWrite.Directory (graph)
APPROLE = "06b708a9-e830-4db3-a914-8e69da51d44f"     # AppRoleAssignment.ReadWrite.All (graph)
EXCH_FULL = "dc890d15-9560-4a4c-9b7f-a736ec74ec40"   # full_access_as_app (exchange)


def _r():
    # load_overrides=False -> deterministic, ignores any local catalog_overrides.json
    return NameResolver(load_overrides=False)


# -- Entra roles -------------------------------------------------------------
def test_entra_name_resolves():
    assert _r().resolve_entra_role("Global Administrator") == [GA]


def test_entra_guid_passthrough():
    assert _r().resolve_entra_role(GA) == [GA]


def test_entra_case_insensitive():
    assert _r().resolve_entra_role("global administrator") == [GA]


def test_entra_list_mixes_name_and_guid_and_dedupes():
    out = _r().resolve_entra_role(["Global Administrator", GA, "User Administrator"])
    assert out == [GA, "fe930be7-5e62-47db-91af-98c3a49a38b1"]  # GA deduped


def test_entra_random_from_high_priv_pool():
    out = _r().resolve_entra_role("random")
    assert len(out) == 1 and out[0] in set(HIGH_PRIVILEGED_ENTRA_ROLES.values())


def test_entra_unknown_name_errors():
    try:
        _r().resolve_entra_role("Supreme Galactic Administrator")
        assert False, "expected NameResolutionError"
    except NameResolutionError as e:
        assert "Unknown Entra role" in str(e)


# -- API permissions ---------------------------------------------------------
def test_graph_permission_name_resolves():
    assert _r().resolve_api_permission("RoleManagement.ReadWrite.Directory", "graph") == [ROLEMGMT]


def test_graph_permission_guid_passthrough():
    assert _r().resolve_api_permission(APPROLE, "graph") == [APPROLE]


def test_exchange_permission_name_resolves():
    assert _r().resolve_api_permission("full_access_as_app", "exchange") == [EXCH_FULL]


def test_permission_list_resolves():
    out = _r().resolve_api_permission(
        ["RoleManagement.ReadWrite.Directory", APPROLE], "graph")
    assert out == [ROLEMGMT, APPROLE]


def test_permission_random_from_high_priv_pool():
    out = _r().resolve_api_permission("random", "graph")
    assert len(out) == 1 and is_guid(out[0])


def test_unknown_api_type_errors():
    try:
        _r().resolve_api_permission("anything", "sharepoint")
        assert False, "expected NameResolutionError"
    except NameResolutionError as e:
        assert "Unknown api_type" in str(e)


def test_unknown_permission_name_errors():
    try:
        _r().resolve_api_permission("Totally.Made.Up", "graph")
        assert False, "expected NameResolutionError"
    except NameResolutionError as e:
        assert "Unknown graph permission" in str(e)


# -- catalog overrides -------------------------------------------------------
def test_overrides_add_and_win():
    custom_role = "11111111-2222-3333-4444-555555555555"
    custom_perm = "66666666-7777-8888-9999-000000000000"
    payload = {
        "entra_roles": {"Imaginary Role": custom_role},
        "graph_permissions": {"Imaginary.Perm": custom_perm},
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        path = f.name
    try:
        r = NameResolver(overrides_path=path)
        assert r.resolve_entra_role("Imaginary Role") == [custom_role]
        assert r.resolve_api_permission("Imaginary.Perm", "graph") == [custom_perm]
        # built-ins still resolve alongside the overrides
        assert r.resolve_entra_role("Global Administrator") == [GA]
    finally:
        os.remove(path)


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
