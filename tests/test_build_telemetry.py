"""
test_build_telemetry.py: offline integration test for the telemetry hub step
inside BuildCommand (Phase 4 of dev-docs/redesign/telemetry-implementation-plan.md).

Everything that would touch Azure or real Terraform is faked: TelemetryHub
(monkeypatched onto src.cli), the lab TerraformManager (swapped for a fake that
records write_terraform_vars/init instead of writing terraform/terraform.tfvars.json
or running the real `terraform` binary), and the operator public-IP lookup
(monkeypatched to a fixed value, since utils.get_public_ip() is a real network
call). tenant/domain/subscription come from env vars, same as any BadZure run.

Runs two ways:
    python tests/test_build_telemetry.py
    pytest tests/test_build_telemetry.py
"""
import contextlib
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.cli as cli_module  # noqa: E402
from src.cli import BuildCommand  # noqa: E402
from src.telemetry_hub import HubError, HubResult  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG = os.path.join(_REPO, "examples", "atomic", "atomic_kv_theft_user.yml")

_FAKE_WORKSPACE_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/"
    "badzure-telemetry/providers/Microsoft.OperationalInsights/workspaces/"
    "badzure-law-abc123"
)


class FakeLabTerraformManager:
    """Stands in for the lab's TerraformManager: records the tfvars it was
    asked to write, and refuses to go any further than `init` so the test never
    reaches a real `terraform apply`."""

    def __init__(self):
        self.written = None
        self.init_calls = 0

    def write_terraform_vars(self, tfvars):
        self.written = tfvars

    def init(self):
        self.init_calls += 1
        return (1, "", "stub: stop here, the test only cares what got written")


class FakeHubSucceeds:
    def __init__(self, subscription_id, tenant_id, rest, tf, hub_dir):
        self.subscription_id = subscription_id
        self.calls = []

    def ensure(self, cfg):
        self.calls.append(cfg)
        return HubResult(
            workspace_id=_FAKE_WORKSPACE_ID, managed=True,
            workspace_name="badzure-law-abc123", location="West US 2",
            notes=[], warnings=[], activity_log="created",
        )


class FakeHubFails:
    def __init__(self, subscription_id, tenant_id, rest, tf, hub_dir):
        pass

    def ensure(self, cfg):
        raise HubError("fake hub failure for the test")


class ExplodingTelemetryHub:
    def __init__(self, *args, **kwargs):
        raise AssertionError("TelemetryHub must not be constructed when telemetry is off")


@contextlib.contextmanager
def _env(**values):
    previous = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, v in previous.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def _patched_hub(hub_cls):
    original = cli_module.TelemetryHub
    cli_module.TelemetryHub = hub_cls
    try:
        yield
    finally:
        cli_module.TelemetryHub = original


def _fresh_command() -> BuildCommand:
    cmd = BuildCommand()
    cmd.terraform_mgr = FakeLabTerraformManager()
    cmd._reachability_gate = lambda config_file: None   # offline gate already covered elsewhere
    cmd._resolve_public_ip = lambda: "203.0.113.5"
    return cmd


def _load_config_with_telemetry():
    import yaml
    with open(_CONFIG) as f:
        config = yaml.safe_load(f)
    config["telemetry"] = True
    return config


def test_telemetry_on_calls_hub_before_lab_init_and_wires_workspace_id():
    with _env(BADZURE_TENANT_ID="11111111-1111-1111-1111-111111111111",
              BADZURE_DOMAIN="example.com",
              BADZURE_SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"), \
         _patched_hub(FakeHubSucceeds):
        cmd = _fresh_command()
        config = _load_config_with_telemetry()

        cmd._build_declarative_mode(config, verbose=False)

        assert cmd.terraform_mgr.written is not None, "tfvars were never written"
        assert cmd.terraform_mgr.written["telemetry"]["workspace_id"] == _FAKE_WORKSPACE_ID
        assert cmd.terraform_mgr.init_calls == 1
        assert cmd.lab_id is not None
        assert cmd.build_started_at is not None
        print("ok: telemetry on calls hub.ensure and wires its workspace_id into the lab tfvars")


def test_hub_error_stops_before_lab_init():
    with _env(BADZURE_TENANT_ID="11111111-1111-1111-1111-111111111111",
              BADZURE_DOMAIN="example.com",
              BADZURE_SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"), \
         _patched_hub(FakeHubFails):
        cmd = _fresh_command()
        config = _load_config_with_telemetry()

        cmd._build_declarative_mode(config, verbose=False)   # must not raise

        assert cmd.terraform_mgr.written is None, "tfvars must not be written after a HubError"
        assert cmd.terraform_mgr.init_calls == 0, "lab init must never run after a HubError"
        print("ok: a HubError stops the build before terraform.tfvars.json is written or init runs")


def test_telemetry_off_never_constructs_hub():
    with _env(BADZURE_TENANT_ID="11111111-1111-1111-1111-111111111111",
              BADZURE_DOMAIN="example.com",
              BADZURE_SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"), \
         _patched_hub(ExplodingTelemetryHub):
        cmd = _fresh_command()
        import yaml
        with open(_CONFIG) as f:
            config = yaml.safe_load(f)   # no telemetry key

        cmd._build_declarative_mode(config, verbose=False)   # must not raise

        assert cmd.terraform_mgr.written is not None
        assert "telemetry" not in cmd.terraform_mgr.written
        assert cmd.terraform_mgr.init_calls == 1
        print("ok: telemetry off never constructs a TelemetryHub, tfvars carry no telemetry key")


# ---------------------------------------------------------------------------
# Self-run support: `python tests/test_build_telemetry.py`
# ---------------------------------------------------------------------------
def test_plan_does_not_use_detailed_exitcode():
    """Without this, `terraform plan` exits 2 whenever it has changes, which
    `plan` (lab and hub) would report as an error."""
    from python_terraform import IsNotFlagged
    from src.terraform_manager import TerraformManager
    mgr = TerraformManager("terraform/telemetry")
    seen = {}

    def fake_plan(*args, **kwargs):
        seen.update(kwargs)
        return (0, "", "")

    mgr.tf.plan = fake_plan
    assert mgr.plan()[0] == 0
    assert seen.get("detailed_exitcode") is IsNotFlagged
    print("ok: terraform plan runs without -detailed-exitcode")


def test_state_list_without_state_file_skips_terraform():
    """A first build has no hub state: state_list must return [] without
    running `terraform state list` (which fails and logs a warning)."""
    import tempfile
    from src.terraform_manager import TerraformManager
    mgr = TerraformManager("terraform/telemetry")
    mgr.terraform_dir = tempfile.mkdtemp(prefix="badzure-hub-")

    def fail(*args, **kwargs):
        raise AssertionError("terraform should not run without a state file")

    mgr.tf.cmd = fail
    assert mgr.state_list() == []
    os.rmdir(mgr.terraform_dir)
    print("ok: state_list skips terraform when there is no state file")


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
    print(f"\n{len(tests) - failures}/{len(tests)} build telemetry tests passed.")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    _run_all()
