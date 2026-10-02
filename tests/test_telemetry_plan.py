"""
test_telemetry_plan.py: offline tests for deriving a TelemetryPlan from a
DeploymentModel (Phase 2 of dev-docs/redesign/telemetry-implementation-plan.md):
which resources get a diagnostic setting, which don't (and why), the exact
target keys and sort order, and the rendered `check` output (human + JSON).

Models are built directly (DeploymentModel(...) with small hand-written entity
maps) rather than through the loader, except for the two CheckCommand tests,
which drive the real CLI path against a temp copy of an example config.

No Azure, no Terraform, no network.

Runs two ways:
    python tests/test_telemetry_plan.py
    pytest tests/test_telemetry_plan.py
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from src import telemetry  # noqa: E402
from src.primitives import DeploymentModel  # noqa: E402
from src.cli import CheckCommand  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402
from src.constants import (  # noqa: E402
    TELEMETRY_LOGGED_KINDS,
    TELEMETRY_EXCLUDED_TYPES,
    TELEMETRY_NO_LOG_TYPES,
    TELEMETRY_VIA_WORKSPACE_TYPES,
    TELEMETRY_KIND_TF_TYPE,
)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA = os.path.join(_REPO, "entity_data")
_ATOMIC_KV = os.path.join(_REPO, "examples", "atomic", "atomic_kv_theft_user.yml")


def _on_model(**maps) -> DeploymentModel:
    """A DeploymentModel with telemetry on (managed, all defaults) and only the
    entity maps given (everything else defaults to an empty dict)."""
    model = DeploymentModel(subscription_id="11111111-1111-1111-1111-111111111111",
                            **maps)
    model.telemetry = telemetry.parse(True, env={})
    return model


# ---------------------------------------------------------------------------
# Off / resources:false
# ---------------------------------------------------------------------------
def test_off_returns_none():
    model = DeploymentModel()
    assert model.telemetry is None
    assert telemetry.derive_plan(model) is None
    print("ok: telemetry off -> derive_plan returns None")


def test_resources_false_emits_nothing():
    model = _on_model(key_vaults={"kv1": {"name": "kv-a"}},
                      virtual_machines={"vm1": {"name": "vm-a"}})
    model.telemetry = telemetry.parse({"resources": False}, env={})
    plan = telemetry.derive_plan(model)
    assert plan.targets == []
    assert plan.not_collected == []
    assert plan.site_logging is False
    lines = telemetry.render_plan_lines(plan)
    assert any(
        "Resources      off (coverage depends on your own policy or settings)"
        in l for l in lines)
    print("ok: resources:false emits no targets and no not_collected notes")


# ---------------------------------------------------------------------------
# Storage / function app fan-out
# ---------------------------------------------------------------------------
def test_storage_fans_out_to_four():
    model = _on_model(storage_accounts={"st1": {"name": "stfina1b2c"}})
    plan = telemetry.derive_plan(model)
    assert len(plan.targets) == 4
    suffixes = sorted(t.suffix for t in plan.targets)
    assert suffixes == sorted(("/blobServices/default", "/fileServices/default",
                               "/queueServices/default", "/tableServices/default"))
    assert all(t.kind == "storage_account" for t in plan.targets)
    assert all(t.key.startswith("st1/") for t in plan.targets)
    print("ok: a storage account fans out to exactly the four service suffixes")


def test_function_app_yields_app_and_storage():
    model = _on_model(function_apps={"fn1": {"name": "func-fin-a1b2c"}})
    plan = telemetry.derive_plan(model)
    kinds = sorted(t.kind for t in plan.targets)
    assert kinds == sorted(
        ["function_app"] + ["function_storage"] * 4)
    storage_targets = [t for t in plan.targets if t.kind == "function_storage"]
    assert len(storage_targets) == 4
    assert all(t.key.startswith("fn1/fnstorage-") for t in storage_targets)
    # Never collides with a real storage_account target sharing the entity key.
    assert all("fnstorage-" in t.key for t in storage_targets)
    print("ok: one Function App yields app + 4 function_storage targets (its plan has no logs)")


def test_app_service_yields_target_and_site_logging():
    model = _on_model(app_services={"app1": {"name": "app-portal-a1b2c"}})
    plan = telemetry.derive_plan(model)
    kinds = sorted(t.kind for t in plan.targets)
    assert kinds == ["app_service"]
    assert plan.site_logging is True
    print("ok: an App Service yields itself (its plan has no logs) and turns on site logging")


def test_no_site_logging_without_app_service():
    model = _on_model(key_vaults={"kv1": {"name": "kv-a"}})
    plan = telemetry.derive_plan(model)
    assert plan.site_logging is False
    print("ok: site_logging is off when there is no app_service")


# ---------------------------------------------------------------------------
# Every kind: empty map -> zero targets of that kind.
# ---------------------------------------------------------------------------
def test_no_cosmos_no_cosmos_target():
    model = _on_model(key_vaults={"kv1": {"name": "kv-a"}})
    plan = telemetry.derive_plan(model)
    assert not any(t.kind == "cosmos_db" for t in plan.targets)
    print("ok: no cosmos_dbs in the model -> no cosmos_db target")


def test_every_kind_empty_map_yields_zero_targets():
    # An entirely empty model (only telemetry on) must produce zero targets for
    # every kind in the table, one kind at a time is implied by construction.
    model = _on_model()
    plan = telemetry.derive_plan(model)
    assert plan.targets == []
    for kind, (map_attr, *_rest) in TELEMETRY_LOGGED_KINDS.items():
        assert not any(t.kind == kind for t in plan.targets), kind
    print("ok: every kind with an empty entity map produces zero targets")


# ---------------------------------------------------------------------------
# VMs: not collected, with a stable reason.
# ---------------------------------------------------------------------------
def test_vms_are_not_collected_with_reason():
    model = _on_model(virtual_machines={
        "vm1": {"name": "vm-fin-a1b2c"}, "vm2": {"name": "vm-hr-c3d4e"},
    })
    plan = telemetry.derive_plan(model)
    assert len(plan.not_collected) == 2
    names = {nc.display_name for nc in plan.not_collected}
    assert names == {"vm-fin-a1b2c", "vm-hr-c3d4e"}
    for nc in plan.not_collected:
        assert nc.reason_code == "vm_needs_guest_agent"
        assert "guest agent" in nc.reason
    # The VM's NSG still gets its own diagnostic target: the VM itself is
    # excluded, not its associated network security group.
    assert any(t.kind == "nsg" for t in plan.targets)
    lines = telemetry.render_plan_lines(plan)
    assert any("public IPs and VNets: no useful logs" in l for l in lines)
    print("ok: each VM yields exactly one NotCollected with the guest-agent reason")


def test_no_vms_no_public_ip_line():
    model = _on_model(key_vaults={"kv1": {"name": "kv-a"}})
    plan = telemetry.derive_plan(model)
    assert plan.not_collected == []
    lines = telemetry.render_plan_lines(plan)
    assert not any("public IPs and VNets" in l for l in lines)
    print("ok: no VMs -> no public IPs/VNets line")


# ---------------------------------------------------------------------------
# Keys: unique, stable, sorted.
# ---------------------------------------------------------------------------
def test_target_keys_unique_and_sorted():
    model = _on_model(
        key_vaults={"kv_z": {"name": "kv-z"}, "kv_a": {"name": "kv-a"}},
        storage_accounts={"st_m": {"name": "stm"}},
        app_services={"app_b": {"name": "app-b"}},
    )
    plan = telemetry.derive_plan(model)
    keys = [t.key for t in plan.targets]
    assert len(keys) == len(set(keys)), "target keys must be unique"
    # Re-derive the same model and confirm identical order (stability).
    plan2 = telemetry.derive_plan(model)
    assert [t.key for t in plan2.targets] == keys
    # Sorted by entity key first: kv_a's entries come before kv_z's.
    kv_a_idx = min(i for i, t in enumerate(plan.targets) if t.entity_key == "kv_a")
    kv_z_idx = min(i for i, t in enumerate(plan.targets) if t.entity_key == "kv_z")
    assert kv_a_idx < kv_z_idx
    print("ok: target keys are unique and their order is stable across runs")


# ---------------------------------------------------------------------------
# Destination types / log_mode.
# ---------------------------------------------------------------------------
def test_destination_types():
    model = _on_model(
        key_vaults={"kv1": {"name": "kv-a"}},
        cosmos_dbs={"cd1": {"name": "cosmos-a"}},
        storage_accounts={"st1": {"name": "st-a"}},
        app_services={"app1": {"name": "app-a"}},
    )
    plan = telemetry.derive_plan(model)
    by_kind = {}
    for t in plan.targets:
        by_kind.setdefault(t.kind, t.destination_type)
    assert by_kind["key_vault"] == "Dedicated"
    assert by_kind["cosmos_db"] == "Dedicated"
    assert by_kind["storage_account"] is None
    assert by_kind["app_service"] is None
    print("ok: key vault and cosmos get Dedicated destination type, rest None")


def test_log_mode_copied_from_constants():
    model = _on_model(
        key_vaults={"kv1": {"name": "kv-a"}},
        storage_accounts={"st1": {"name": "st-a"}},
        virtual_machines={"vm1": {"name": "vm-a"}},
    )
    plan = telemetry.derive_plan(model)
    for t in plan.targets:
        expected_log_mode = TELEMETRY_LOGGED_KINDS[t.kind][3]
        assert t.log_mode == expected_log_mode
    print("ok: every target carries its kind's log_mode from the constants table")


# ---------------------------------------------------------------------------
# Function App storage name transform.
# ---------------------------------------------------------------------------
def test_function_storage_name_transform():
    cases = [
        ("func-fin-a1b2c3", "fcfina1b2c3"),
        ("func-hr-payroll-service-x9y8z", "fchrpayrollservicex9y8z"[:24]),
        ("NoPrefixHere", "noprefixhere"),
    ]
    for raw, expected in cases:
        assert telemetry.function_storage_name_transform(raw) == expected, raw
    # Truncation to 24 chars, matching main.tf's substr(..., 0, 24).
    long_name = "func-" + "x" * 40
    transformed = telemetry.function_storage_name_transform(long_name)
    assert len(transformed) == 24
    print("ok: function_storage_name_transform matches the main.tf HCL transform")


# ---------------------------------------------------------------------------
# Every azurerm type in the lab Terraform is decided somewhere.
# ---------------------------------------------------------------------------
def test_every_azurerm_type_is_decided():
    decided = (set(TELEMETRY_KIND_TF_TYPE.values())
               | set(TELEMETRY_EXCLUDED_TYPES)
               | set(TELEMETRY_NO_LOG_TYPES)
               | set(TELEMETRY_VIA_WORKSPACE_TYPES))
    ignored = {"azurerm_monitor_diagnostic_setting"}

    undecided = []
    for path in ("terraform/main.tf", "terraform/generic.tf"):
        text = Path(_REPO, path).read_text()
        for m in re.finditer(r'resource\s+"(azurerm_[a-z_]+)"', text):
            rtype = m.group(1)
            if rtype in ignored:
                continue
            if rtype not in decided:
                undecided.append((path, rtype))

    assert not undecided, (
        "Undecided azurerm type(s) found in the lab Terraform; decide each one "
        "in src/constants.py (TELEMETRY_KIND_TF_TYPE, TELEMETRY_EXCLUDED_TYPES, "
        "TELEMETRY_NO_LOG_TYPES, or TELEMETRY_VIA_WORKSPACE_TYPES): " + str(undecided))
    print("ok: every azurerm_* resource type in main.tf/generic.tf is decided")


# ---------------------------------------------------------------------------
# CheckCommand: JSON has "telemetry" only when on; human snapshot.
# ---------------------------------------------------------------------------
def _write_config(dest_dir: str, telemetry_on: bool) -> str:
    with open(_ATOMIC_KV) as f:
        config = yaml.safe_load(f)
    if telemetry_on:
        config["telemetry"] = True
    path = os.path.join(dest_dir, f"cfg_{'on' if telemetry_on else 'off'}.yml")
    with open(path, "w") as f:
        yaml.safe_dump(config, f)
    return path


def _run_check_json(config_path: str) -> dict:
    cmd = CheckCommand()
    cmd.generator = EntityGenerator(data_dir=_DATA)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd.execute(config_path, json_output=True)
    return json.loads(buf.getvalue())


def test_check_json_has_telemetry_only_when_on(tmp_path=None):
    tmp = str(tmp_path) if tmp_path is not None else tempfile.mkdtemp()
    off_path = _write_config(tmp, telemetry_on=False)
    on_path = _write_config(tmp, telemetry_on=True)

    payload_off = _run_check_json(off_path)
    assert "telemetry" not in payload_off

    payload_on = _run_check_json(on_path)
    assert "telemetry" in payload_on
    assert payload_on["telemetry"]["managed"] is True
    print("ok: check --json carries \"telemetry\" only when telemetry is on")


# ---------------------------------------------------------------------------
# Human snapshot: a small, fixed model rendered to an exact expected list.
# ---------------------------------------------------------------------------
def test_check_human_snapshot():
    model = DeploymentModel(
        subscription_id="",
        key_vaults={"kv_fin": {"name": "kv-fin-a1b2c"}},
        storage_accounts={"st_fin": {"name": "stfina1b2c"}},
        app_services={"app_portal": {"name": "app-portal-a1b2c"}},
        virtual_machines={"vm_fin": {"name": "vm-fin-a1b2c"}},
    )
    model.telemetry = telemetry.parse(True, env={})
    plan = telemetry.derive_plan(model)
    lines = telemetry.render_plan_lines(plan)
    expected = [
        "Telemetry plan",
        "  Workspace      managed: badzure-telemetry/badzure-law-<subscription hash> "
        "(West US 2 unless already created)",
        "                 retention 30 days, daily cap 1 GB "
        "(applied when the workspace is created)",
        "  Entra          on: every category (tenant-wide; what has data "
        "depends on the licence)",
        "  Activity Log   on (all categories, free to ingest)",
        "  Resources      on, all logs: 7 settings on 4 resources",
        "                   app-portal-a1b2c  all logs + site logging",
        "                   kv-fin-a1b2c      all logs",
        "                   stfina1b2c        blob, file, queue, table: all logs",
        "                   vm_fin-nsg        all logs",
        "  Not collected  vm-fin-a1b2c        VMs need a guest agent for "
        "useful logs (not in v1)",
        "                 public IPs and VNets: no useful logs",
    ]
    assert lines == expected, "\n".join(lines)
    print("ok: human check output matches the fixed snapshot")


def test_managed_workspace_with_and_without_subscription():
    """check has no subscription: no hash is invented. With one, the ID and name
    are the deterministic managed ones (section 3.1)."""
    model = DeploymentModel(subscription_id="")
    model.telemetry = telemetry.parse(True, env={})
    plan = telemetry.derive_plan(model)
    assert plan.workspace_id == ""
    assert "badzure-law-<subscription hash>" in telemetry.render_plan_lines(plan)[1]

    sub = "11111111-1111-1111-1111-111111111111"
    model.subscription_id = sub
    plan = telemetry.derive_plan(model)
    assert plan.workspace_id == telemetry.managed_workspace_id(sub)
    assert plan.workspace_id.endswith("/" + plan.managed_workspace_name)
    assert plan.managed_workspace_name in telemetry.render_plan_lines(plan)[1]
    print("ok: managed workspace shown without inventing a subscription")


def test_display_names_follow_hcl():
    """Function App storage uses main.tf's name transform; NSGs are '<vm key>-nsg'."""
    model = DeploymentModel(
        app_services={"app_a": {"name": "app-a"}},
        function_apps={"fn_b": {"name": "func-b-x"}},
        virtual_machines={"vm_c": {"name": "vm-c-x"}},
    )
    model.telemetry = telemetry.parse(True, env={})
    names = {(t.kind, t.display_name) for t in telemetry.derive_plan(model).targets}
    assert ("app_service", "app-a") in names
    assert ("function_app", "func-b-x") in names
    assert ("function_storage", "fcbx") in names
    assert ("nsg", "vm_c-nsg") in names
    print("ok: display names follow the HCL name expressions")


def test_singular_counts():
    model = DeploymentModel(key_vaults={"kv": {"name": "kv-x"}})
    model.telemetry = telemetry.parse(True, env={})
    lines = telemetry.render_plan_lines(telemetry.derive_plan(model))
    assert "on, all logs: 1 setting on 1 resource" in "\n".join(lines)
    print("ok: counts of one are singular")


# ---------------------------------------------------------------------------
# Self-run support: `python tests/test_telemetry_plan.py`
# ---------------------------------------------------------------------------
def _run_all():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for name, t in tests:
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} telemetry plan tests passed.")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    _run_all()
