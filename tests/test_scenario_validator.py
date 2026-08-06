"""
test_scenario_validator.py — offline test of the declarative validator + the
enriched operator output (Phase-3 Slice 5).

The validator runs on raw YAML/dict config (no Azure, no entity generation), so
these are fast structural checks: malformed objective, unknown assignment type,
missing principal_ref, dangling step `uses:`/`reads:` links — and that the SOFT
cases (no objective, unknown-but-future capability) only warn. A second section
smoke-tests OutputFormatter.format_declarative_paths over a built overlay.

Runs two ways:
    python tests/test_scenario_validator.py
    pytest tests/test_scenario_validator.py
"""
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scenario_validator import validate  # noqa: E402
from src.scenario_loader import ScenarioConfigError, AttackPathOverlay  # noqa: E402
from src.output_formatter import OutputFormatter  # noqa: E402

GA = "62e90394-69f5-4237-9190-012177145e10"


def _expect_error(config, *needles):
    try:
        validate(config)
    except ScenarioConfigError as e:
        for n in needles:
            assert n in str(e), f"expected '{n}' in error, got: {e}"
        return
    assert False, "expected ScenarioConfigError, none raised"


def _expect_ok(config):
    validate(config)  # must not raise


# ---------------------------------------------------------------------------
# A fully valid path (the reachability fixture) passes.
# ---------------------------------------------------------------------------
_VALID = {
    "attack_paths": {
        "p": {
            "objective": {"name": "GA", "capability": "entra_role", "role": GA},
            "initial_access": {"principal_ref": "alice"},
            "identities": {"users": [{"ref": "alice"}],
                           "applications": [{"ref": "app"}]},
            "resources": {"key_vaults": [{"ref": "kv01"}]},
            "assignments": [
                {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                 "role": "Key Vault Contributor", "scope_ref": "kv01"},
                {"id": "a2", "type": "entra_role", "principal_ref": "app", "role": GA},
            ],
            "credentials": [{"ref": "sec", "app_ref": "app", "type": "password"}],
            "data_injects": [
                {"id": "d1", "material": "app_secret", "credential_ref": "sec",
                 "location": "key_vault_secret", "location_ref": "kv01", "name": "s"},
            ],
            "steps": [
                {"name": "loot", "uses": ["a1"], "reads": ["d1"]},
                {"name": "auth", "uses": ["a2"]},
            ],
        }
    }
}


def test_valid_config_passes():
    _expect_ok(_VALID)
    print("ok: valid config passes")


def test_baseline_only_config_is_noop():
    _expect_ok({"baseline": {"identities": {"users": 5}}})
    print("ok: baseline-only config is a no-op")


# ---------------------------------------------------------------------------
# Objective
# ---------------------------------------------------------------------------
def test_missing_objective_is_soft():
    _expect_ok({"attack_paths": {"p": {
        "initial_access": {"principal_ref": "alice"},
        "assignments": [{"id": "a1", "type": "entra_role",
                         "principal_ref": "alice", "role": GA}],
    }}})
    print("ok: missing objective only warns")


def test_objective_not_a_mapping_errors():
    _expect_error({"attack_paths": {"p": {"objective": "GA"}}},
                  "objective must be a mapping")
    print("ok: non-mapping objective rejected")


def test_entra_role_objective_without_role_errors():
    _expect_error({"attack_paths": {"p": {
        "objective": {"capability": "entra_role"},
        "assignments": [{"id": "a1", "type": "entra_role",
                         "principal_ref": "alice", "role": GA}],
    }}}, "entra_role", "needs a")
    print("ok: entra_role objective needs a role")


def test_read_secrets_objective_without_target_errors():
    _expect_error({"attack_paths": {"p": {
        "objective": {"capability": "read_secrets"},
        "assignments": [],
    }}}, "read_secrets", "target_ref")
    print("ok: read_secrets objective needs a target_ref")


def test_unknown_capability_is_soft():
    _expect_ok({"attack_paths": {"p": {
        "objective": {"capability": "exfiltrate_teams_chat", "target_ref": "x"},
        "assignments": [],
    }}})
    print("ok: unknown (future) capability only warns")


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------
def test_unknown_assignment_type_errors():
    _expect_error({"attack_paths": {"p": {
        "assignments": [{"id": "a1", "type": "nonsense", "principal_ref": "x"}],
    }}}, "unknown type 'nonsense'")
    print("ok: unknown assignment type rejected")


def test_assignment_missing_principal_ref_errors():
    _expect_error({"attack_paths": {"p": {
        "assignments": [{"id": "a1", "type": "entra_role", "role": GA}],
    }}}, "no `principal_ref`")
    print("ok: assignment without principal_ref rejected")


def test_assignment_missing_type_errors():
    _expect_error({"attack_paths": {"p": {
        "assignments": [{"id": "a1", "principal_ref": "x"}],
    }}}, "has no `type`")
    print("ok: assignment without type rejected")


def test_initial_access_without_principal_ref_errors():
    _expect_error({"attack_paths": {"p": {
        "initial_access": {"method": "phishing"},
        "assignments": [],
    }}}, "initial_access has no `principal_ref`")
    print("ok: initial_access without principal_ref rejected")


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def test_step_uses_unknown_assignment_errors():
    _expect_error({"attack_paths": {"p": {
        "assignments": [{"id": "a1", "type": "entra_role",
                         "principal_ref": "x", "role": GA}],
        "steps": [{"name": "s", "uses": ["a1", "ghost"]}],
    }}}, "uses unknown assignment id 'ghost'")
    print("ok: step uses unknown assignment id rejected")


def test_step_reads_unknown_id_errors():
    _expect_error({"attack_paths": {"p": {
        "assignments": [],
        "data_injects": [{"id": "d1", "material": "literal", "location": "x",
                          "location_ref": "y", "name": "z"}],
        "steps": [{"name": "s", "reads": ["d9"]}],
    }}}, "reads unknown data_inject/credential id 'd9'")
    print("ok: step reads unknown id rejected")


def test_step_reads_credential_ref_ok():
    _expect_ok({"attack_paths": {"p": {
        "assignments": [],
        "credentials": [{"ref": "sec", "app_ref": "app"}],
        "steps": [{"name": "s", "reads": ["sec"]}],
    }}})
    print("ok: step reads a credential ref")


def test_errors_are_aggregated():
    # Two distinct problems -> one error listing both.
    try:
        validate({"attack_paths": {"p": {
            "assignments": [{"id": "a1", "type": "bogus"}],
        }}})
        assert False
    except ScenarioConfigError as e:
        assert "unknown type 'bogus'" in str(e) and "no `principal_ref`" in str(e)
    print("ok: multiple problems aggregated into one error")


# ---------------------------------------------------------------------------
# Enriched output (smoke test)
# ---------------------------------------------------------------------------
class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def test_formatter_surfaces_richness():
    overlay = AttackPathOverlay(
        name="vm_to_ga",
        objective={"name": "GA via KV", "impact": "critical",
                   "capability": "entra_role", "role": "Global Administrator"},
        metadata={"complexity": "medium", "tags": ["key-vault"], "mitre": ["T1078"]},
        reachability={"status": "reached", "reason": "app holds the target role."},
        steps=[
            {"name": "Compromise alice", "source_ref": "alice",
             "action": "phishing", "derived": True},
            {"name": "Loot secret", "source_ref": "alice", "target_ref": "app",
             "action": "credential_loot", "uses": ["a1"], "reads": ["d1"],
             "derived": True},
            {"name": "Achieve objective", "action": "entra_role",
             "gains": ["Global Administrator"], "derived": True},
        ],
    )
    cap = _Capture()
    logger = logging.getLogger()
    prev_level = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(cap)
    try:
        OutputFormatter().format_declarative_paths(
            [overlay], {"vm_to_ga": {}}, "contoso.com")
    finally:
        logger.removeHandler(cap)
        logger.setLevel(prev_level)
    blob = "\n".join(cap.lines)
    for needle in ("vm_to_ga", "Goal: entra_role", "[reachable]", "Complexity: medium",
                   "MITRE: T1078", "Attack Steps (derived from graph)",
                   "credential_loot", "Gains: Global Administrator"):
        assert needle in blob, f"missing '{needle}' in output:\n{blob}"
    print("ok: formatter surfaces objective/reachability/metadata/steps")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nAll {len(tests)} validator/formatter tests passed.")


if __name__ == "__main__":
    _run_all()
