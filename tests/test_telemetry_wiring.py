"""
test_telemetry_wiring.py: offline tests for lab telemetry wiring (Phase 3 of
dev-docs/redesign/telemetry-implementation-plan.md): the tfvars a
TerraformBuilder emits for telemetry, and the Terraform HCL (terraform/main.tf,
terraform/telemetry.tf, terraform/variables.tf, terraform/outputs.tf) that
reads them.

Telemetry off must be invisible: no `telemetry` key in the tfvars, no change to
`check`, and every new Terraform resource a no-op under the variable default.
That is asserted here both from the Python side (build_tfvars) and by reading
the HCL text directly (no Terraform state, no Azure).

One test, test_terraform_validate, is opt-in: it runs `terraform init
-backend=false` and `terraform validate` in a TEMPORARY COPY of terraform/ (never
the repo's own terraform/ directory, which may hold real lab state) and needs
network access to download the pinned provider. It only runs when
BADZURE_TF_VALIDATE=1 is set and `terraform` is on PATH; otherwise it skips.

Runs two ways:
    python tests/test_telemetry_wiring.py
    pytest tests/test_telemetry_wiring.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from src.config_manager import ConfigManager  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402
from src.primitives import DeploymentModel  # noqa: E402
from src.scenario_loader import ScenarioLoader  # noqa: E402
from src import telemetry  # noqa: E402
from src.telemetry import TelemetryContext  # noqa: E402
from src.terraform_builder import build_tfvars, LabValidationError  # noqa: E402
from src.constants import TELEMETRY_LOGGED_KINDS  # noqa: E402

import tests.test_terraform_builder_golden as golden  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA = os.path.join(_REPO, "entity_data")
_TERRAFORM_DIR = os.path.join(_REPO, "terraform")

# A syntactically valid workspace id, used only as a stand-in TelemetryContext
# value in these tests. Never a real subscription (this module makes no Azure
# calls).
_FAKE_WORKSPACE_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/"
    "badzure-telemetry/providers/Microsoft.OperationalInsights/workspaces/"
    "badzure-law-abc123"
)


def _ctx():
    return TelemetryContext(workspace_id=_FAKE_WORKSPACE_ID, lab_id="ab12c")


def _on_model(**maps) -> DeploymentModel:
    """A DeploymentModel with telemetry on (managed, all defaults)."""
    model = DeploymentModel(subscription_id="11111111-1111-1111-1111-111111111111",
                             **maps)
    model.telemetry = telemetry.parse(True, env={})
    return model


# ---------------------------------------------------------------------------
# Telemetry off is invisible (every example, plus one explicit byte-identical
# check, plus the golden fixture).
# ---------------------------------------------------------------------------
def test_off_tfvars_unchanged_for_every_example():
    gen = EntityGenerator(data_dir=_DATA)
    cfg_mgr = ConfigManager()
    examples = sorted(Path(_REPO, "examples").rglob("*.yml"))
    assert examples, "no example configs found"

    checked = 0
    for path in examples:
        config = cfg_mgr.load_config(str(path))
        if not isinstance(config, dict):
            continue
        loader = ScenarioLoader(gen)
        try:
            scenario = loader.load(config, domain="example.com",
                                    enforce_reachability=False)
        except ValueError:
            # Not every example is a loadable declarative config on its own
            # (some are fragments); skip those, this test only cares about the
            # ones CheckCommand accepts today.
            continue

        tfvars = build_tfvars(scenario.model, verify_files=False)
        assert "telemetry" not in tfvars, path

        # Explicitly off, WITH a context given: still absent (the context alone
        # never turns telemetry on).
        scenario.model.telemetry = None
        tfvars_with_ctx = build_tfvars(scenario.model, verify_files=False,
                                        telemetry_ctx=_ctx())
        assert "telemetry" not in tfvars_with_ctx, path
        checked += 1

    assert checked > 0
    print(f"ok: telemetry absent from tfvars for {checked} example config(s)")


def test_off_is_byte_identical():
    model = _on_model(key_vaults={"kv_fin": {"name": "kv-fin-a1b2c"}})
    model.telemetry = None

    a = json.dumps(build_tfvars(model, verify_files=False), sort_keys=True)
    b = json.dumps(build_tfvars(model, verify_files=False, telemetry_ctx=_ctx()),
                    sort_keys=True)
    assert a == b
    assert '"telemetry"' not in a
    print("ok: tfvars byte-identical with telemetry off, context or not")


def test_golden_fixture_untouched():
    # The golden test (tests/test_terraform_builder_golden.py) is the real guard
    # here and is left untouched; this only confirms the golden model (which
    # has no `telemetry:` config) still emits no telemetry key.
    fixture = golden._load_fixture()
    model = golden._build_model(fixture)
    assert model.telemetry is None
    tfvars = build_tfvars(model, verify_files=False)
    assert "telemetry" not in tfvars
    print("ok: golden fixture model still emits no telemetry key")


# ---------------------------------------------------------------------------
# Telemetry on: symbolic parents, no categories, no leaked IDs.
# ---------------------------------------------------------------------------
def test_on_emits_symbolic_parents():
    model = _on_model(
        key_vaults={"kv_fin": {"name": "kv-fin-a1b2c"}},
        storage_accounts={"st_fin": {"name": "stfina1b2c"}},
        app_services={"app_portal": {"name": "app-portal-a1b2c"}},
    )
    tfvars = build_tfvars(model, verify_files=False, telemetry_ctx=_ctx())
    targets = tfvars["telemetry"]["diagnostic_targets"]
    assert targets

    blob = json.dumps(targets)
    assert "/subscriptions/" not in blob
    for entry in targets.values():
        assert re.match(r"^[a-z_]+:[^/]+$", entry["parent"]), entry
    print("ok: every diagnostic target parent is a symbolic ref, no leaked IDs")


def test_no_category_lists_in_tfvars():
    model = _on_model(key_vaults={"kv_fin": {"name": "kv-fin-a1b2c"}})
    tfvars = build_tfvars(model, verify_files=False, telemetry_ctx=_ctx())
    targets = tfvars["telemetry"]["diagnostic_targets"]
    assert targets
    for entry in targets.values():
        assert set(entry.keys()) == {"parent", "suffix", "destination_type", "log_mode"}
        assert entry["log_mode"] in ("allLogs", "discover")
    print("ok: diagnostic target dicts carry no hand-written category lists")


def test_storage_suffixes_in_tfvars():
    model = _on_model(storage_accounts={"st_fin": {"name": "stfina1b2c"}})
    tfvars = build_tfvars(model, verify_files=False, telemetry_ctx=_ctx())
    targets = tfvars["telemetry"]["diagnostic_targets"]
    suffixes = {e["suffix"] for e in targets.values()}
    from src.constants import STORAGE_SERVICE_SUFFIXES
    assert suffixes == set(STORAGE_SERVICE_SUFFIXES)
    print("ok: storage account fans out to exactly the four service suffixes")


def test_resources_false_emits_empty_targets_but_keeps_workspace():
    model = DeploymentModel(subscription_id="11111111-1111-1111-1111-111111111111",
                             key_vaults={"kv_fin": {"name": "kv-fin-a1b2c"}})
    model.telemetry = telemetry.parse({"resources": False}, env={})
    tfvars = build_tfvars(model, verify_files=False, telemetry_ctx=_ctx())
    t = tfvars["telemetry"]
    assert t["diagnostic_targets"] == {}
    assert t["workspace_id"] == _ctx().workspace_id
    assert t["lab_id"] == _ctx().lab_id
    print("ok: resources:false empties diagnostic_targets but keeps the workspace wiring")


def test_check_path_emits_no_telemetry():
    model = _on_model(key_vaults={"kv_fin": {"name": "kv-fin-a1b2c"}})
    tfvars = build_tfvars(model, verify_files=False)  # no telemetry_ctx: the check path
    assert "telemetry" not in tfvars
    print("ok: telemetry on with no context (the check preflight) emits nothing")


def test_reference_check_raises_lab_validation_error():
    # derive_plan always builds targets by walking the model's own entity maps,
    # so a real config can never hand it a target whose entity_key is missing.
    # The defensive check in TerraformBuilder._telemetry_tfvars exists for a
    # future bug in derive_plan, not a reachable user-facing state. Exercise it
    # directly by swapping in a plan with a dangling entity_key.
    model = _on_model(key_vaults={"kv_fin": {"name": "kv-fin-a1b2c"}})
    bogus_target = telemetry.DiagnosticTarget(
        key="ghost/key_vault", kind="key_vault", entity_key="ghost",
        suffix="", destination_type="Dedicated", log_mode="allLogs",
        display_name="ghost",
    )
    bogus_plan = telemetry.TelemetryPlan(
        config=model.telemetry, workspace_id=_ctx().workspace_id, managed=True,
        targets=[bogus_target],
    )

    original = telemetry.derive_plan
    telemetry.derive_plan = lambda m: bogus_plan
    try:
        try:
            build_tfvars(model, verify_files=False, telemetry_ctx=_ctx())
        except LabValidationError:
            pass
        else:
            raise AssertionError(
                "expected LabValidationError when a telemetry target's entity_key "
                "no longer names a declared entity"
            )
    finally:
        telemetry.derive_plan = original
    print("ok: a telemetry target whose entity_key is missing raises LabValidationError")


# ---------------------------------------------------------------------------
# HCL: read the files directly, no Terraform.
# ---------------------------------------------------------------------------
# The kind -> Terraform address table from the plan's section 2 (and mirrored
# in terraform/telemetry.tf's diag_parent_ids).
_KIND_TF_ADDRESS = {
    "key_vault": "azurerm_key_vault.kvaults",
    "storage_account": "azurerm_storage_account.sas",
    "function_storage": "azurerm_storage_account.function_storage",
    "cosmos_db": "azurerm_cosmosdb_account.cosmos_dbs",
    "app_service": "azurerm_linux_web_app.app_services",
    "function_app": "azurerm_linux_function_app.function_apps",
    "logic_app": "azurerm_logic_app_workflow.logic_apps",
    "automation_account": "azurerm_automation_account.automation_accounts",
    "nsg": "azurerm_network_security_group.vm_nsg",
}


def test_every_kind_has_hcl_parent():
    text = Path(_TERRAFORM_DIR, "telemetry.tf").read_text()
    found = {}
    for m in re.finditer(
            r'for\s+k,\s*v\s+in\s+(azurerm_[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)\s*:\s*'
            r'"([a-z_]+):\$\{k\}"',
            text):
        address, kind = m.group(1), m.group(2)
        found[kind] = address

    assert set(found) == set(TELEMETRY_LOGGED_KINDS), (
        set(found), set(TELEMETRY_LOGGED_KINDS))
    for kind, address in _KIND_TF_ADDRESS.items():
        assert found[kind] == address, (kind, found[kind], address)
    print("ok: every telemetry kind has a diag_parent_ids entry matching the §2 table")


def test_parent_keys_match_parent_ids():
    """diag_parent_keys (plan-time known, used to skip stale targets) must list
    the same kinds as diag_parent_ids, each from its resource's for_each var."""
    text = Path(_TERRAFORM_DIR, "telemetry.tf").read_text()
    main = Path(_TERRAFORM_DIR, "main.tf").read_text()
    keys = {m.group(2): m.group(1) for m in re.finditer(
        r'for\s+k\s+in\s+keys\((var\.[a-z_]+)\)\s*:\s*"([a-z_]+):\$\{k\}"', text)}
    assert set(keys) == set(TELEMETRY_LOGGED_KINDS), (set(keys), set(TELEMETRY_LOGGED_KINDS))
    for kind, address in _KIND_TF_ADDRESS.items():
        rtype, rname = address.split(".")
        m = re.search(r'resource\s+"%s"\s+"%s"\s*\{\s*for_each\s*=\s*(var\.[a-z_]+)'
                      % (rtype, rname), main)
        assert m and m.group(1) == keys[kind], (kind, m and m.group(1), keys[kind])
    assert "for_each                       = local.diag_targets" in text
    print("ok: diag_parent_keys mirrors diag_parent_ids and the resources' for_each vars")


def test_variable_default_is_off():
    text = Path(_TERRAFORM_DIR, "variables.tf").read_text()
    m = re.search(r'variable\s+"telemetry"\s*{.*?default\s*=\s*({.*?})\s*}\s*\n',
                  text, re.DOTALL)
    assert m, "telemetry variable default not found"
    default_text = m.group(1)
    assert re.search(r'workspace_id\s*=\s*""', default_text)
    assert re.search(r'diagnostic_targets\s*=\s*{\s*}', default_text)
    print("ok: telemetry variable defaults to off")


def test_provider_pin_unchanged():
    text = Path(_TERRAFORM_DIR, "main.tf").read_text()
    m = re.search(r'azurerm\s*=\s*{\s*source\s*=\s*"hashicorp/azurerm"\s*'
                  r'version\s*=\s*"([^"]+)"', text)
    assert m and m.group(1) == "4.57.0", m
    print("ok: azurerm provider pin unchanged (4.57.0)")


def test_web_app_logs_gated():
    text = Path(_TERRAFORM_DIR, "main.tf").read_text()
    web_app_start = text.index('resource "azurerm_linux_web_app" "app_services"')
    function_app_start = text.index('resource "azurerm_linux_function_app" "function_apps"')

    web_app_block = text[web_app_start:web_app_start + 3000]
    assert 'dynamic "logs"' in web_app_block
    assert "var.telemetry.site_logging" in web_app_block

    function_app_block = text[function_app_start:function_app_start + 3000]
    assert 'dynamic "logs"' not in function_app_block
    assert re.search(r'^\s*logs\s*{', function_app_block, re.MULTILINE) is None
    print("ok: web app site logging is gated on var.telemetry.site_logging; "
          "function app has no logs block")


# ---------------------------------------------------------------------------
# Opt-in: real Terraform validate against a temp copy of terraform/.
# ---------------------------------------------------------------------------
def _terraform_available() -> bool:
    return shutil.which("terraform") is not None


def test_terraform_validate():
    if os.environ.get("BADZURE_TF_VALIDATE") != "1":
        pytest.skip("set BADZURE_TF_VALIDATE=1 to run terraform validate")
    if not _terraform_available():
        pytest.skip("terraform not on PATH")

    with tempfile.TemporaryDirectory(prefix="badzure-tfvalidate-") as tmp:
        for name in os.listdir(_TERRAFORM_DIR):
            if name.endswith((".tfstate", ".tfvars.json", ".pem", ".key", ".pfx")):
                continue
            if name.startswith(".terraform"):
                continue
            src = os.path.join(_TERRAFORM_DIR, name)
            dst = os.path.join(tmp, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

        init = subprocess.run(
            ["terraform", "init", "-backend=false", "-input=false"],
            cwd=tmp, capture_output=True, text=True, timeout=300,
        )
        assert init.returncode == 0, init.stdout + init.stderr

        validate = subprocess.run(
            ["terraform", "validate"],
            cwd=tmp, capture_output=True, text=True, timeout=120,
        )
        assert validate.returncode == 0, validate.stdout + validate.stderr
        print("ok: terraform validate passed in a temp copy of terraform/")


def test_hub_terraform_validate():
    """Same opt-in validate as test_terraform_validate, but for the telemetry
    hub's own root (terraform/telemetry/) — a separate Terraform root with its
    own provider block and variables, never the lab's."""
    if os.environ.get("BADZURE_TF_VALIDATE") != "1":
        pytest.skip("set BADZURE_TF_VALIDATE=1 to run terraform validate")
    if not _terraform_available():
        pytest.skip("terraform not on PATH")

    hub_dir = os.path.join(_TERRAFORM_DIR, "telemetry")
    with tempfile.TemporaryDirectory(prefix="badzure-hub-tfvalidate-") as tmp:
        for name in os.listdir(hub_dir):
            if name.endswith((".tfstate", ".tfvars.json")):
                continue
            if name.startswith(".terraform"):
                continue
            src = os.path.join(hub_dir, name)
            dst = os.path.join(tmp, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

        init = subprocess.run(
            ["terraform", "init", "-backend=false", "-input=false"],
            cwd=tmp, capture_output=True, text=True, timeout=300,
        )
        assert init.returncode == 0, init.stdout + init.stderr

        validate = subprocess.run(
            ["terraform", "validate"],
            cwd=tmp, capture_output=True, text=True, timeout=120,
        )
        assert validate.returncode == 0, validate.stdout + validate.stderr
        print("ok: terraform validate passed in a temp copy of terraform/telemetry/")


# ---------------------------------------------------------------------------
# Self-run support: `python tests/test_telemetry_wiring.py`
# ---------------------------------------------------------------------------
def _run_all():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for name, t in tests:
        if name in ("test_terraform_validate", "test_hub_terraform_validate"):
            if os.environ.get("BADZURE_TF_VALIDATE") != "1" or not _terraform_available():
                print("skip")
                continue
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} telemetry wiring tests passed.")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    _run_all()
