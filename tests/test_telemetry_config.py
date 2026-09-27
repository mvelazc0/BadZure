"""
test_telemetry_config.py: offline tests for the `telemetry:` config schema
(Phase 1 of dev-docs/redesign/telemetry-implementation-plan.md): parsing raw
YAML into a `TelemetryConfig`, validating it with the exact published error and
warning text, env-var precedence over a YAML `workspace:` string, and the
deterministic naming helpers (`setting_suffix` / `managed_workspace_id`).

No Azure, no Terraform, no network: `src/telemetry.py` is pure except for the
one `os.environ` read in `parse`/`validate_raw`, which every test here controls
explicitly (either via the `env` parameter or, where the code path under test
reads real `os.environ`, a scoped set/restore).

Runs two ways:
    python tests/test_telemetry_config.py
    pytest tests/test_telemetry_config.py
"""
import copy
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from src import telemetry  # noqa: E402
from src.telemetry import TelemetryConfig, WorkspaceSettings  # noqa: E402
from src.scenario_validator import validate  # noqa: E402
from src.scenario_loader import ScenarioConfigError, ScenarioLoader  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA = os.path.join(_REPO, "entity_data")

_ENV_WORKSPACE_ID = (
    "/subscriptions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/resourceGroups/rg/"
    "providers/Microsoft.OperationalInsights/workspaces/env-ws"
)
_YAML_WORKSPACE_ID = (
    "/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/resourceGroups/rg/"
    "providers/Microsoft.OperationalInsights/workspaces/yaml-ws"
)


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


class _EnvVar:
    """Temporarily set a real os.environ variable, restoring whatever was there
    (or its absence) afterward. Only needed for the one check
    (`telemetry.workspace settings are ignored`) that reads real os.environ
    through `scenario_validator.validate()`, rather than an injected `env` dict."""
    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value

    def __enter__(self):
        self._had = self.name in os.environ
        self._prev = os.environ.get(self.name)
        os.environ[self.name] = self.value
        return self

    def __exit__(self, *exc):
        if self._had:
            os.environ[self.name] = self._prev
        else:
            os.environ.pop(self.name, None)


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


# ---------------------------------------------------------------------------
# parse(): off / defaults / env precedence
# ---------------------------------------------------------------------------
def test_omitted_and_false_are_off():
    assert telemetry.parse(None, env={}) is None
    assert telemetry.parse(False, env={}) is None
    print("ok: omitted/false telemetry parses to None")


def test_true_is_all_defaults():
    cfg = telemetry.parse(True, env={})
    assert isinstance(cfg, TelemetryConfig)
    assert cfg.byo_workspace_id is None
    assert cfg.workspace_source == "managed"
    assert cfg.entra is True
    assert cfg.activity_log is True
    assert cfg.resources is True
    assert cfg.workspace_settings == WorkspaceSettings()
    print("ok: telemetry: true is all defaults, managed")


def test_mapping_defaults_fill_in():
    cfg = telemetry.parse({"entra": False}, env={})
    assert cfg.entra is False
    assert cfg.activity_log is True
    assert cfg.resources is True
    assert cfg.byo_workspace_id is None
    print("ok: mapping fills in omitted fields with defaults")


def test_byo_string():
    cfg = telemetry.parse({"workspace": _YAML_WORKSPACE_ID}, env={})
    assert cfg.byo_workspace_id == _YAML_WORKSPACE_ID
    assert cfg.workspace_source == "yaml"
    print("ok: a workspace string sets byo_workspace_id from yaml")


def test_env_overrides_yaml_string():
    cfg = telemetry.parse(
        {"workspace": _YAML_WORKSPACE_ID},
        env={telemetry.ENV_TELEMETRY_WORKSPACE: _ENV_WORKSPACE_ID})
    assert cfg.byo_workspace_id == _ENV_WORKSPACE_ID
    assert cfg.workspace_source == "env"
    print("ok: env var overrides a yaml workspace string")


def test_env_overrides_managed():
    cfg = telemetry.parse(
        True, env={telemetry.ENV_TELEMETRY_WORKSPACE: _ENV_WORKSPACE_ID})
    assert cfg.byo_workspace_id == _ENV_WORKSPACE_ID
    assert cfg.workspace_source == "env"
    print("ok: env var turns a managed config into bring-your-own")


def test_env_never_enables():
    assert telemetry.parse(
        None, env={telemetry.ENV_TELEMETRY_WORKSPACE: _ENV_WORKSPACE_ID}) is None
    print("ok: env var alone never turns telemetry on")


def test_daily_cap_null_vs_omitted():
    omitted = telemetry.parse({"workspace": {}}, env={})
    assert omitted.workspace_settings.daily_cap_gb is None
    assert omitted.workspace_settings.daily_cap_explicit is False

    explicit_null = telemetry.parse({"workspace": {"daily_cap_gb": None}}, env={})
    assert explicit_null.workspace_settings.daily_cap_gb is None
    assert explicit_null.workspace_settings.daily_cap_explicit is True
    print("ok: daily_cap_gb distinguishes omitted from explicit null")


# ---------------------------------------------------------------------------
# validate_raw(), through scenario_validator.validate(), one test per error row.
# ---------------------------------------------------------------------------
def test_invalid_top_level_value_errors():
    _expect_error(
        {"telemetry": "enabled"},
        "telemetry: 'enabled' is not a valid value. Use true (collect "
        "everything), false, or a mapping of fields.")
    print("ok: a non-bool/mapping/null telemetry value is rejected")


def test_unknown_telemetry_field_errors():
    _expect_error(
        {"telemetry": {"entra_logs": True}},
        "telemetry: unknown field 'entra_logs'. Supported fields: "
        "activity_log, entra, resources, workspace.")
    print("ok: an unknown telemetry field is rejected")


def test_bool_field_errors():
    cases = (
        ("entra", "With entra on, every Entra log category is collected."),
        ("activity_log",
         "With activity_log on, every Activity Log category is collected."),
        ("resources",
         "With resources on, every log the lab's resources support is collected."),
    )
    for field_name, hint in cases:
        _expect_error(
            {"telemetry": {field_name: "yes"}},
            f"telemetry.{field_name}: must be true or false. {hint}")
    print("ok: entra/activity_log/resources must be bool")


def test_workspace_string_not_matching_id_errors():
    _expect_error(
        {"telemetry": {"workspace": "lab-logs"}},
        "telemetry.workspace: 'lab-logs' is not a workspace resource ID. Use "
        "the full ID (/subscriptions/<sub>/resourceGroups/<rg>/providers/"
        "Microsoft.OperationalInsights/workspaces/<name>), or a mapping of "
        "managed-workspace settings.")
    print("ok: a workspace string that isn't a resource ID is rejected")


def test_workspace_wrong_type_errors():
    _expect_error(
        {"telemetry": {"workspace": 5}},
        "telemetry.workspace: 5 is not a workspace resource ID.")
    print("ok: a workspace that is neither string nor mapping is rejected")


def test_unknown_workspace_field_errors():
    _expect_error(
        {"telemetry": {"workspace": {"x": 1}}},
        "telemetry.workspace: unknown field 'x'. Supported fields: "
        "daily_cap_gb, location, retention_days.")
    print("ok: an unknown workspace field is rejected")


def test_retention_days_out_of_range_errors():
    _expect_error(
        {"telemetry": {"workspace": {"retention_days": 7}}},
        "telemetry.workspace.retention_days: 7 is out of range (30 to 730).")
    print("ok: an out-of-range retention_days is rejected")


def test_bool_is_not_int():
    _expect_error(
        {"telemetry": {"workspace": {"retention_days": True}}},
        "telemetry.workspace.retention_days: True is out of range (30 to 730).")
    _expect_error(
        {"telemetry": {"workspace": {"daily_cap_gb": True}}},
        "telemetry.workspace.daily_cap_gb: must be a positive number of GB, "
        "or null for no cap.")
    print("ok: retention_days: true / daily_cap_gb: true are rejected "
          "(bools are not ints)")


def test_daily_cap_not_positive_errors():
    _expect_error(
        {"telemetry": {"workspace": {"daily_cap_gb": -1}}},
        "telemetry.workspace.daily_cap_gb: must be a positive number of GB, "
        "or null for no cap.")
    print("ok: a non-positive daily_cap_gb is rejected")


def test_location_blank_errors():
    _expect_error(
        {"telemetry": {"workspace": {"location": "   "}}},
        "telemetry.workspace.location: must be an Azure region name, "
        "e.g. West US 2.")
    print("ok: a blank location is rejected")


def test_errors_aggregate_across_telemetry_and_baseline():
    config = {
        "baseline": {"assignments": [{"id": "a1", "type": "bogus"}]},
        "telemetry": {"entra": "yes", "workspace": {"x": 1}},
    }
    try:
        validate(config)
        assert False, "expected ScenarioConfigError"
    except ScenarioConfigError as e:
        msg = str(e)
        assert "unknown type 'bogus'" in msg
        assert "telemetry.entra: must be true or false" in msg
        assert "telemetry.workspace: unknown field 'x'" in msg
    print("ok: telemetry errors aggregate alongside a baseline error")


def test_valid_telemetry_configs_pass():
    _expect_ok({"telemetry": True})
    _expect_ok({"telemetry": False})
    _expect_ok({"telemetry": None})
    _expect_ok({"telemetry": {"entra": False, "workspace": _YAML_WORKSPACE_ID}})
    _expect_ok({"telemetry": {"workspace": {
        "location": "West US 2", "retention_days": 90, "daily_cap_gb": 5}}})
    print("ok: valid telemetry configs pass")


# ---------------------------------------------------------------------------
# Warnings (logged via logging.warning inside scenario_validator.validate()).
# ---------------------------------------------------------------------------
def test_warnings_are_logged():
    cap = _Capture()
    logger = logging.getLogger()
    prev_level = logger.level
    logger.setLevel(logging.WARNING)
    logger.addHandler(cap)
    try:
        with _EnvVar(telemetry.ENV_TELEMETRY_WORKSPACE, _ENV_WORKSPACE_ID):
            _expect_ok({"telemetry": {"workspace": {
                "daily_cap_gb": None, "location": "West US 2"}}})
    finally:
        logger.removeHandler(cap)
        logger.setLevel(prev_level)
    blob = "\n".join(cap.lines)
    assert ("telemetry.workspace.daily_cap_gb is null: ingestion is uncapped. "
            "Watch the workspace's usage page in the Azure portal.") in blob
    assert (f"telemetry.workspace settings are ignored: "
            f"{telemetry.ENV_TELEMETRY_WORKSPACE} sends telemetry to "
            f"{_ENV_WORKSPACE_ID}.") in blob
    print("ok: both telemetry warnings are logged")


# ---------------------------------------------------------------------------
# Naming helpers (section 3.1 of the plan).
# ---------------------------------------------------------------------------
def test_setting_suffix_is_stable_and_case_insensitive():
    wid = ("/subscriptions/AAAAAAAA-aaaa-aaaa-aaaa-aaaaaaaaaaaa/resourceGroups/"
           "rg/providers/Microsoft.OperationalInsights/workspaces/Ws")
    s1 = telemetry.setting_suffix(wid)
    s2 = telemetry.setting_suffix(wid.lower())
    s3 = telemetry.setting_suffix(wid.upper())
    assert s1 == s2 == s3
    assert len(s1) == 6
    print("ok: setting_suffix is stable and case-insensitive")


def test_managed_workspace_id_shape():
    sub = "11111111-1111-1111-1111-111111111111"
    wid = telemetry.managed_workspace_id(sub)
    assert telemetry.WORKSPACE_ID_RE.match(wid), wid
    assert sub in wid
    print("ok: managed_workspace_id matches WORKSPACE_ID_RE")


def test_new_lab_id_shape():
    import random as _random
    lab_id = telemetry.new_lab_id(_random.Random(0))
    assert len(lab_id) == 5
    assert all(c in "abcdefghijklmnopqrstuvwxyz0123456789" for c in lab_id)
    print("ok: new_lab_id is 5 lowercase-alphanumeric chars")


# ---------------------------------------------------------------------------
# ScenarioLoader wiring: model.telemetry set/absent.
# ---------------------------------------------------------------------------
def test_loader_sets_model_telemetry():
    with open(os.path.join(_REPO, "examples", "atomic",
                           "atomic_kv_theft_user.yml")) as f:
        base_config = yaml.safe_load(f)

    without_telemetry = copy.deepcopy(base_config)
    scenario = ScenarioLoader(EntityGenerator(data_dir=_DATA)).load(
        without_telemetry, domain="example.com", enforce_reachability=False)
    assert scenario.model.telemetry is None

    with_telemetry = copy.deepcopy(base_config)
    with_telemetry["telemetry"] = True
    scenario2 = ScenarioLoader(EntityGenerator(data_dir=_DATA)).load(
        with_telemetry, domain="example.com", enforce_reachability=False)
    assert isinstance(scenario2.model.telemetry, TelemetryConfig)
    print("ok: ScenarioLoader.load() sets model.telemetry from the config")


# ---------------------------------------------------------------------------
# Self-run support: `python tests/test_telemetry_config.py`
# ---------------------------------------------------------------------------
def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nAll {len(tests)} telemetry config tests passed.")


if __name__ == "__main__":
    _run_all()
