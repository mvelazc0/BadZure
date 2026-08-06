"""
test_compile_baseline_command.py — offline test of `badzure compile-baseline` (the
agent-authored org-baseline path: org-design YAML -> deterministic compile + validate ->
generated.yml, no LLM, no Azure). Mirrors the org_generator compiler tests.

Runs two ways:
    python tests/test_compile_baseline_command.py
    pytest tests/test_compile_baseline_command.py
"""
import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cli import CompileBaselineCommand  # noqa: E402
from src.config_manager import ConfigManager  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA = os.path.join(_REPO, "entity_data")

# A known-good org design (small headcounts so users are easy to count).
_DESIGN = {
    "company": {"name": "Acme Labs", "industry": "SaaS", "size": "small"},
    "departments": [
        {"name": "Engineering", "headcount": 3},
        {"name": "IT", "headcount": 1},
    ],
    "groups": [{"ref": "IT-Admins", "department": "IT"}],
    "service_principals": [
        {"ref": "cicd-pipeline", "api_permissions": ["User.Read.All"],
         "azure_roles": [{"role": "Contributor", "scope": "rg-prod"}],
         "credentials": [{"display_name": "github-actions"}]},
    ],
    "resources": {
        "resource_groups": [{"ref": "rg-prod", "location": "West US 2"}],
        "key_vaults": [{"ref": "kvacme01", "resource_group": "rg-prod"}],
    },
    "rbac": [{"principal": "IT-Admins", "role": "Reader", "scope": "rg-prod"}],
    "ownerships": [{"owner": "IT", "target": "cicd-pipeline"}],
}


def _cmd():
    cmd = CompileBaselineCommand()
    cmd.generator = EntityGenerator(data_dir=_DATA)
    return cmd


def _write(tmp_path, design):
    p = tmp_path / "design.yml"
    p.write_text(yaml.safe_dump(design))
    return str(p)


def test_compiles_and_validates(tmp_path):
    out = tmp_path / "generated.yml"
    code = _cmd().execute(_write(tmp_path, _DESIGN), output=str(out))
    assert code == 0
    config = ConfigManager().load_config(str(out))
    users = config["baseline"]["identities"]["users"]
    assert len(users) == 4                      # 3 Engineering + 1 IT
    groups = {g["ref"] for g in config["baseline"]["identities"]["groups"]}
    assert "IT-Admins" in groups
    assert config["baseline"]["resources"]["key_vaults"][0]["ref"] == "kvacme01"


def test_missing_file_exits_two():
    code = _cmd().execute(os.path.join(_REPO, "nope_design.yml"))
    assert code == 2


def test_invalid_yaml_exits_two(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text("{ not: valid: yaml: here")
    code = _cmd().execute(str(p))
    assert code == 2


def test_non_mapping_design_exits_two(tmp_path):
    # Valid YAML, but a scalar/list rather than a mapping -> rejected with a clear error.
    p = tmp_path / "scalar.yml"
    p.write_text("just a string")
    code = _cmd().execute(str(p))
    assert code == 2


def test_dangling_ref_exits_two(tmp_path):
    # RBAC scope references a resource group that was never declared -> validation fails.
    bad = {"departments": [{"name": "IT", "headcount": 1}],
           "rbac": [{"principal": "IT", "role": "Reader", "scope": "rg-does-not-exist"}]}
    code = _cmd().execute(_write(tmp_path, bad))
    assert code == 2


def test_unknown_role_exits_two(tmp_path):
    bad = {"departments": [{"name": "IT", "headcount": 1}],
           "entra_roles": [{"principal": "IT", "role": "Totally Made Up Role"}]}
    code = _cmd().execute(_write(tmp_path, bad))
    assert code == 2


if __name__ == "__main__":
    import logging
    import tempfile
    from pathlib import Path
    logging.disable(logging.CRITICAL)

    failures = 0
    with tempfile.TemporaryDirectory() as d:
        tp = Path(d)
        for fn in (test_compiles_and_validates, test_invalid_yaml_exits_two,
                   test_non_mapping_design_exits_two,
                   test_dangling_ref_exits_two, test_unknown_role_exits_two):
            try:
                fn(tp)
                print(f"PASS {fn.__name__}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {fn.__name__}: {e}")
        try:
            test_missing_file_exits_two()
            print("PASS test_missing_file_exits_two")
        except AssertionError as e:
            failures += 1
            print(f"FAIL test_missing_file_exits_two: {e}")

    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
