"""
test_destroy_telemetry.py: offline tests for the CLI-level telemetry wiring
into DestroyCommand (Phase 4 of dev-docs/redesign/telemetry-implementation-plan.md):
`--telemetry` / `--yes`, and the plain-destroy retained-workspace reminder.

Terraform and the telemetry hub are both faked (FakeTerraformManager,
FakeTelemetryHub, monkeypatched onto src.cli), so nothing here shells out to
real Terraform or touches real Azure. `TerraformManager.ensure_installed` is
also patched out so the test doesn't depend on `terraform` being on PATH.

Runs two ways:
    python tests/test_destroy_telemetry.py
    pytest tests/test_destroy_telemetry.py
"""
import contextlib
import json
import logging
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.cli as cli_module  # noqa: E402
from src.cli import DestroyCommand  # noqa: E402
from src.terraform_manager import TerraformManager  # noqa: E402


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@contextlib.contextmanager
def _captured_logs():
    cap = _Capture()
    logger = logging.getLogger()
    prev_level = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(cap)
    try:
        yield cap
    finally:
        logger.removeHandler(cap)
        logger.setLevel(prev_level)


class FakeTerraformManager:
    """Stands in for TerraformManager: records every call, never shells out."""

    def __init__(self, terraform_dir, init_rc=0, destroy_rc=0, outputs=None):
        self.terraform_dir = terraform_dir
        self.init_rc = init_rc
        self.destroy_rc = destroy_rc
        self.init_calls = 0
        self.destroy_calls = 0
        self.cleanup_calls = 0
        self._outputs = dict(outputs or {})

    def init(self):
        self.init_calls += 1
        return (self.init_rc, "", "" if self.init_rc == 0 else "init error")

    def destroy(self, verbose=False):
        self.destroy_calls += 1
        return (self.destroy_rc, "", "" if self.destroy_rc == 0 else "destroy error")

    def cleanup_state_files(self):
        self.cleanup_calls += 1

    def get_outputs(self):
        return dict(self._outputs)


class FakeTelemetryHub:
    """Records every construction and every destroy() call/confirm result."""
    instances = []

    def __init__(self, subscription_id, tenant_id, rest, tf, hub_dir):
        self.subscription_id = subscription_id
        self.hub_dir = hub_dir
        self.destroy_calls = []
        FakeTelemetryHub.instances.append(self)

    def destroy(self, confirm):
        result = confirm("This will permanently remove BadZure's telemetry hub.")
        self.destroy_calls.append(result)
        return True


class ExplodingTelemetryHub:
    """Fails the test loudly if plain destroy ever constructs a TelemetryHub."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("TelemetryHub must not be constructed on plain destroy")


@contextlib.contextmanager
def _dirs():
    lab_dir = tempfile.mkdtemp(prefix="badzure-lab-")
    hub_dir = tempfile.mkdtemp(prefix="badzure-hub-")
    try:
        yield lab_dir, hub_dir
    finally:
        shutil.rmtree(lab_dir, ignore_errors=True)
        shutil.rmtree(hub_dir, ignore_errors=True)


@contextlib.contextmanager
def _patched(**attrs):
    """Monkeypatch module-level attributes on src.cli, restoring afterward.
    Works both under pytest and `python tests/test_destroy_telemetry.py`."""
    originals = {name: getattr(cli_module, name) for name in attrs}
    ensure_installed_original = TerraformManager.ensure_installed
    for name, value in attrs.items():
        setattr(cli_module, name, value)
    TerraformManager.ensure_installed = staticmethod(lambda: None)
    try:
        yield
    finally:
        for name, value in originals.items():
            setattr(cli_module, name, value)
        TerraformManager.ensure_installed = ensure_installed_original


def _cmd(lab_dir, hub_dir, lab_init_rc=0, lab_destroy_rc=0, hub_outputs=None):
    cmd = DestroyCommand()
    cmd.terraform_mgr = FakeTerraformManager(lab_dir, init_rc=lab_init_rc,
                                             destroy_rc=lab_destroy_rc)
    cmd.hub_terraform_mgr = FakeTerraformManager(hub_dir, outputs=hub_outputs)
    return cmd


def _touch_lab_state(lab_dir):
    with open(os.path.join(lab_dir, "terraform.tfstate"), "w") as f:
        f.write("{}")


def _write_hub_settings(hub_dir, **fields):
    settings = {"subscription_id": "11111111-1111-1111-1111-111111111111",
               "tenant_id": "22222222-2222-2222-2222-222222222222",
               "destination_workspace_id": "", "keep_managed_workspace": True,
               "entra_settings": []}
    settings.update(fields)
    with open(os.path.join(hub_dir, "hub_settings.json"), "w") as f:
        json.dump(settings, f)


# ---------------------------------------------------------------------------
# Plain destroy never touches the hub
# ---------------------------------------------------------------------------
def test_plain_destroy_never_constructs_telemetry_hub():
    with _dirs() as (lab_dir, hub_dir), _patched(TelemetryHub=ExplodingTelemetryHub):
        _touch_lab_state(lab_dir)
        cmd = _cmd(lab_dir, hub_dir)
        FakeTelemetryHub.instances.clear()

        cmd.execute()   # telemetry=False (default): must never construct TelemetryHub

        assert cmd.terraform_mgr.destroy_calls == 1
        print("ok: plain destroy never constructs a TelemetryHub")


def test_plain_destroy_prints_reminder_when_hub_present():
    with _dirs() as (lab_dir, hub_dir), _patched(TelemetryHub=ExplodingTelemetryHub):
        _touch_lab_state(lab_dir)
        _write_hub_settings(hub_dir)
        cmd = _cmd(lab_dir, hub_dir, hub_outputs={"workspace_name": "badzure-law-abc123",
                                                   "workspace_retention_days": 30})

        with _captured_logs() as cap:
            cmd.execute()

        blob = "\n".join(cap.lines)
        assert "Telemetry workspace retained: badzure-law-abc123 (retention 30d)" in blob
        assert "destroy --telemetry" in blob
        print("ok: plain destroy prints the retained-workspace reminder when a hub exists")


def test_plain_destroy_silent_when_no_hub():
    with _dirs() as (lab_dir, hub_dir), _patched(TelemetryHub=ExplodingTelemetryHub):
        _touch_lab_state(lab_dir)
        cmd = _cmd(lab_dir, hub_dir)   # no hub_settings.json written

        with _captured_logs() as cap:
            cmd.execute()

        blob = "\n".join(cap.lines)
        assert "Telemetry workspace retained" not in blob
        print("ok: plain destroy with no hub present prints no telemetry lines")


# ---------------------------------------------------------------------------
# --telemetry
# ---------------------------------------------------------------------------
def test_telemetry_flag_skips_hub_when_lab_destroy_fails():
    with _dirs() as (lab_dir, hub_dir), _patched(TelemetryHub=ExplodingTelemetryHub):
        _touch_lab_state(lab_dir)
        cmd = _cmd(lab_dir, hub_dir, lab_destroy_rc=1)

        cmd.execute(telemetry=True)   # must not raise (TelemetryHub never constructed)

        assert cmd.terraform_mgr.destroy_calls == 1
        print("ok: --telemetry with a failing lab destroy never touches the hub")


def test_telemetry_flag_skips_lab_destroy_when_no_state():
    with _dirs() as (lab_dir, hub_dir), _patched(TelemetryHub=FakeTelemetryHub):
        # No terraform.tfstate in lab_dir.
        FakeTelemetryHub.instances.clear()
        cmd = _cmd(lab_dir, hub_dir)

        with _captured_logs() as cap:
            cmd.execute(telemetry=True, yes=True)

        assert cmd.terraform_mgr.init_calls == 0
        assert cmd.terraform_mgr.destroy_calls == 0
        assert "No lab deployed." in "\n".join(cap.lines)
        assert len(FakeTelemetryHub.instances) == 1
        print("ok: --telemetry with no lab state skips the lab destroy but still runs the hub destroy")


def test_yes_flag_bypasses_confirmation_prompt():
    with _dirs() as (lab_dir, hub_dir), _patched(TelemetryHub=FakeTelemetryHub, click=_ClickThatMustNotBeCalled()):
        _touch_lab_state(lab_dir)
        FakeTelemetryHub.instances.clear()
        cmd = _cmd(lab_dir, hub_dir)

        cmd.execute(telemetry=True, yes=True)

        assert len(FakeTelemetryHub.instances) == 1
        assert FakeTelemetryHub.instances[0].destroy_calls == [True]
        print("ok: --yes passes a confirm that returns True without prompting")


class _ClickThatMustNotBeCalled:
    def confirm(self, *args, **kwargs):
        raise AssertionError("click.confirm must not be called when --yes is set")


# ---------------------------------------------------------------------------
# Self-run support: `python tests/test_destroy_telemetry.py`
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
    print(f"\n{len(tests) - failures}/{len(tests)} destroy telemetry tests passed.")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    logging.disable(logging.NOTSET)
    _run_all()
