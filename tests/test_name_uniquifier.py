"""
test_name_uniquifier.py — offline test of `badzure uniquify` + name_uniquifier
(Phase 3a). Asserts globally-unique resource names get a suffix, all references are
rewritten consistently, Azure naming rules hold, and a uniquified config STILL
compiles and stays reachable (proving no reference was missed). No Azure.

Runs two ways:
    python tests/test_name_uniquifier.py
    pytest tests/test_name_uniquifier.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import name_uniquifier  # noqa: E402
from src.cli import UniquifyCommand  # noqa: E402
from src.config_manager import ConfigManager  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import ScenarioLoader  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHAINED = os.path.join(_REPO, "examples", "chained")
_DATA = os.path.join(_REPO, "entity_data")

_SUFFIX = "z9k2q"


def _apex():
    return ConfigManager().load_config(os.path.join(_CHAINED, "chained_apex.yml"))


# ---------------------------------------------------------------------------
# Core transform
# ---------------------------------------------------------------------------
def test_renames_only_global_kinds():
    new, rename = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    # apex global resources: 2 KV + 2 storage + 1 cosmos + 1 function = 6.
    assert set(rename) == {
        "kv-bz-vault02", "kv-bz-vault04", "stbzdata01", "stbzdata03",
        "cosmos-bz-app01", "func-bz-api01",
    }
    # Non-global refs are untouched.
    assert "rg-data" not in rename
    assert "vm-build01" not in rename
    assert "g-engineering" not in rename


def test_naming_rules_respected():
    _, rename = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    kv = rename["kv-bz-vault02"]
    assert kv == "kv-bz-vault02-z9k2q" and len(kv) <= 24
    st = rename["stbzdata01"]
    assert st == "stbzdata01z9k2q"          # storage: lowercase alnum, NO hyphen
    assert st.isalnum() and st.islower() and len(st) <= 24
    assert rename["cosmos-bz-app01"] == "cosmos-bz-app01-z9k2q"
    assert rename["func-bz-api01"] == "func-bz-api01-z9k2q"


def test_references_rewritten():
    new, rename = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    # data_injects location_ref and assignment scope_ref must follow the rename.
    path = new["attack_paths"]["apex_to_global_admin"]
    injects = path["data_injects"]
    kv_targets = {d["location_ref"] for d in injects}
    assert rename["kv-bz-vault02"] in kv_targets
    assert rename["stbzdata01"] in kv_targets or rename["stbzdata01"] in {
        d["location_ref"] for d in injects}
    # No assignment still points at an OLD global ref.
    old_refs = set(rename)
    for a in path["assignments"]:
        assert a.get("scope_ref") not in old_refs


def test_storage_truncates_when_long():
    cfg = {"baseline": {"resources": {"storage_accounts": [
        {"ref": "averyveryverylongstorageaccountname"}]}}}
    _, rename = name_uniquifier.uniquify_config(cfg, suffix="abcde")
    new = rename["averyveryverylongstorageaccountname"]
    assert len(new) <= 24 and new.endswith("abcde") and new.isalnum()


def test_deterministic_with_suffix():
    a, ra = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    b, rb = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    assert ra == rb


# ---------------------------------------------------------------------------
# Azure naming-rule compliance (length, charset, start char, hyphens)
# ---------------------------------------------------------------------------
def test_function_app_storage_derivation_keeps_suffix():
    # main.tf derives the backing storage name: lower, "func-"->"fc", strip "-", [:24].
    _, rename = name_uniquifier.uniquify_config(
        {"baseline": {"resources": {"function_apps": [
            {"ref": "func-payments-processor-service"}]}}}, suffix="z9k2q")
    fa = rename["func-payments-processor-service"]
    assert len(fa) <= 24                                    # function-app name capped to 24
    derived = (fa.replace("func-", "fc").replace("-", "").lower())[:24]
    assert "z9k2q" in derived and len(derived) <= 24       # suffix survives front-truncation


def test_no_double_or_trailing_hyphen():
    ref = "kv-aaaaaaaaaaaaaa-bb"   # truncation would land on a hyphen
    _, rename = name_uniquifier.uniquify_config(
        {"baseline": {"resources": {"key_vaults": [{"ref": ref}]}}}, suffix="abcde")
    kv = rename[ref]
    assert "--" not in kv and not kv.endswith("-") and not kv.startswith("-")
    assert len(kv) <= 24


def test_key_vault_starts_with_letter():
    _, rename = name_uniquifier.uniquify_config(
        {"baseline": {"resources": {"key_vaults": [{"ref": "9-vault-x"}]}}}, suffix="abcde")
    assert rename["9-vault-x"][0].isalpha()


def test_all_apex_names_within_limits():
    _, rename = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    limits = {"kv-bz-vault02": 24, "kv-bz-vault04": 24, "stbzdata01": 24,
              "stbzdata03": 24, "cosmos-bz-app01": 44, "func-bz-api01": 24}
    for old, new in rename.items():
        assert len(new) <= limits[old]
        assert "--" not in new and not new.startswith("-") and not new.endswith("-")
    for old in ("stbzdata01", "stbzdata03"):   # storage: lowercase alnum only
        assert rename[old].isalnum() and rename[old].islower()


# ---------------------------------------------------------------------------
# Integration: a uniquified config still compiles AND stays reachable
# ---------------------------------------------------------------------------
def test_uniquified_config_still_reachable():
    new, _ = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    scenario = ScenarioLoader(EntityGenerator(data_dir=_DATA)).load(
        new, domain="example.com", enforce_reachability=False)
    statuses = [ov.reachability.get("status") for ov in scenario.attack_paths]
    assert statuses == ["reached"]


# ---------------------------------------------------------------------------
# Command round-trip
# ---------------------------------------------------------------------------
def test_command_writes_output(tmp_path):
    src = _apex()
    import yaml
    in_path = tmp_path / "in.yml"
    out_path = tmp_path / "out.yml"
    in_path.write_text(yaml.safe_dump(src, sort_keys=False))
    code = UniquifyCommand().execute(str(in_path), output=str(out_path), suffix=_SUFFIX)
    assert code == 0
    written = ConfigManager().load_config(str(out_path))
    refs = [r["ref"] for r in written["attack_paths"]["apex_to_global_admin"]
            ["resources"]["key_vaults"]]
    assert "kv-bz-vault02-z9k2q" in refs


# ---------------------------------------------------------------------------
# Idempotence marker (uniquified: true) — build can safely re-run uniquify
# ---------------------------------------------------------------------------
def test_marker_stamped_on_output():
    new, rename = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    assert new.get("uniquified") is True
    assert rename  # apex has global resources, so it actually renamed some


def test_idempotent_second_pass_is_noop():
    first, r1 = name_uniquifier.uniquify_config(_apex(), suffix=_SUFFIX)
    assert r1
    # A config already marked uniquified passes through untouched — NO second suffix.
    second, r2 = name_uniquifier.uniquify_config(first, suffix="xxxxx")
    assert r2 == {}
    kvs = [r["ref"] for r in
           second["attack_paths"]["apex_to_global_admin"]["resources"]["key_vaults"]]
    assert "kv-bz-vault02-z9k2q" in kvs
    assert not any(r.endswith("-xxxxx") for r in kvs)  # no stacked suffix


def test_build_ensure_uniquified_marks_and_persists(tmp_path):
    import yaml
    from src.cli import BuildCommand
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump(_apex(), sort_keys=False))
    cfg = ConfigManager().load_config(str(p))

    out = BuildCommand()._ensure_uniquified(cfg, str(p))
    assert out.get("uniquified") is True
    # Persisted to disk with the marker + suffixed names.
    on_disk = ConfigManager().load_config(str(p))
    assert on_disk.get("uniquified") is True
    kv_disk = [r["ref"] for r in
               on_disk["attack_paths"]["apex_to_global_admin"]["resources"]["key_vaults"]]
    assert any(r.startswith("kv-bz-vault02-") for r in kv_disk)

    # Second build call on the now-marked, persisted config is a no-op (same names).
    out2 = BuildCommand()._ensure_uniquified(on_disk, str(p))
    kv1 = sorted(r["ref"] for r in
                 out["attack_paths"]["apex_to_global_admin"]["resources"]["key_vaults"])
    kv2 = sorted(r["ref"] for r in
                 out2["attack_paths"]["apex_to_global_admin"]["resources"]["key_vaults"])
    assert kv1 == kv2


if __name__ == "__main__":
    import logging
    import tempfile
    from pathlib import Path
    logging.disable(logging.CRITICAL)

    failures = 0
    for fn in (test_renames_only_global_kinds, test_naming_rules_respected,
               test_references_rewritten, test_storage_truncates_when_long,
               test_deterministic_with_suffix,
               test_function_app_storage_derivation_keeps_suffix,
               test_no_double_or_trailing_hyphen, test_key_vault_starts_with_letter,
               test_all_apex_names_within_limits, test_uniquified_config_still_reachable,
               test_marker_stamped_on_output, test_idempotent_second_pass_is_noop):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")

    with tempfile.TemporaryDirectory() as d:
        try:
            test_command_writes_output(Path(d))
            print("PASS test_command_writes_output")
        except AssertionError as e:
            failures += 1
            print(f"FAIL test_command_writes_output: {e}")
        try:
            test_build_ensure_uniquified_marks_and_persists(Path(d))
            print("PASS test_build_ensure_uniquified_marks_and_persists")
        except AssertionError as e:
            failures += 1
            print(f"FAIL test_build_ensure_uniquified_marks_and_persists: {e}")

    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
