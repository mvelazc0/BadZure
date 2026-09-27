"""
test_telemetry_hub.py: offline tests for src/telemetry_hub.py (Phase 4 of
dev-docs/redesign/telemetry-implementation-plan.md): TelemetryHub.ensure /
preview / destroy, and the hub's own Terraform (terraform/telemetry/).

Every collaborator is a fake: FakeRest stands in for AzureRest (keyed by URL,
never touches the network) and FakeTf stands in for TerraformManager (records
every call, never shells out to real Terraform). hub_dir is a fresh temp
directory per test so hub_settings.json reads/writes are real filesystem I/O
against throwaway files, never the repo's own terraform/telemetry/.

Runs two ways:
    python tests/test_telemetry_hub.py
    pytest tests/test_telemetry_hub.py
"""
import contextlib
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import telemetry  # noqa: E402
from src.azure_rest import AzureRestError  # noqa: E402
from src.constants import TELEMETRY_DIAG_SETTING_NAME, TELEMETRY_HUB_RG  # noqa: E402
from src.telemetry_hub import HubError, TelemetryHub  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SUB = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
_BYO_ID = ("/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/"
           "customer-rg/providers/Microsoft.OperationalInsights/workspaces/customer-law")

_MANAGED_WS_ID = telemetry.managed_workspace_id(SUB)
_MANAGED_SUFFIX = telemetry.setting_suffix(_MANAGED_WS_ID)
_ACTIVITY_NAME = f"badzure-activity-{_MANAGED_SUFFIX}"
_ACTIVITY_LIST_URL = f"/subscriptions/{SUB}/providers/Microsoft.Insights/diagnosticSettings"
_RG_ID = f"/subscriptions/{SUB}/resourceGroups/{TELEMETRY_HUB_RG}"
_AUDIT_URL = f"{_MANAGED_WS_ID}/providers/Microsoft.Insights/diagnosticSettings/{TELEMETRY_DIAG_SETTING_NAME}"
_AUDIT_ID = f"{_MANAGED_WS_ID}|{TELEMETRY_DIAG_SETTING_NAME}"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class FakeRest:
    """Fakes AzureRest, keyed by URL (the api-version is recorded but not used
    to select a response). A missing key behaves like a real 404 (get()
    returns None). A value that is an Exception instance is raised instead."""

    def __init__(self, responses=None, error_on_all=None):
        self.responses = dict(responses or {})
        self.error_on_all = error_on_all
        self.calls = []

    def get(self, url, api_version, resource=None):
        self.calls.append(("GET", url, api_version))
        if self.error_on_all is not None:
            raise self.error_on_all
        value = self.responses.get(url)
        if isinstance(value, Exception):
            raise value
        return value

    def put(self, url, api_version, body, resource=None):
        self.calls.append(("PUT", url, api_version))
        return {}

    def delete(self, url, api_version, resource=None):
        self.calls.append(("DELETE", url, api_version))


class FakeTf:
    """Fakes TerraformManager's subset TelemetryHub uses. Records every call
    (including ordering, in call_order) so tests can assert e.g. "imports
    happen before apply"."""

    def __init__(self, state=None, outputs=None, init_rc=0, apply_rc=0,
                 plan_rc=0, destroy_rc=0, import_rc=0):
        self.terraform_dir = "/fake/telemetry"
        self._state = list(state or [])
        self._outputs = dict(outputs or {})
        self.init_rc, self.apply_rc = init_rc, apply_rc
        self.plan_rc, self.destroy_rc, self.import_rc = plan_rc, destroy_rc, import_rc

        self.written_vars = None
        self.imported = []
        self.call_order = []
        self.init_calls = 0
        self.applied = 0
        self.planned = 0
        self.destroyed = 0
        self.cleaned = 0

    def state_list(self):
        return list(self._state)

    def write_terraform_vars(self, tfvars):
        self.written_vars = tfvars
        self.call_order.append("write_vars")

    def init(self):
        self.init_calls += 1
        self.call_order.append("init")
        return (self.init_rc, "", "" if self.init_rc == 0 else "init failed")

    def import_resource(self, address, resource_id):
        self.imported.append((address, resource_id))
        self.call_order.append(f"import:{address}")
        if self.import_rc != 0:
            return (self.import_rc, "", "import failed")
        return (0, "", "")

    def apply(self, verbose=False):
        self.applied += 1
        self.call_order.append("apply")
        return (self.apply_rc, "", "" if self.apply_rc == 0 else "apply failed")

    def plan(self, verbose=False):
        self.planned += 1
        self.call_order.append("plan")
        return (self.plan_rc, "", "" if self.plan_rc == 0 else "plan failed")

    def destroy(self, verbose=False):
        self.destroyed += 1
        self.call_order.append("destroy")
        return (self.destroy_rc, "", "" if self.destroy_rc == 0 else "destroy failed")

    def get_outputs(self):
        return dict(self._outputs)

    def cleanup_state_files(self):
        self.cleaned += 1
        self.call_order.append("cleanup")


@contextlib.contextmanager
def _hub_dir():
    d = tempfile.mkdtemp(prefix="badzure-hub-")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _managed_outputs(**overrides):
    outputs = {
        "workspace_id": _MANAGED_WS_ID,
        "workspace_name": _MANAGED_WS_ID.rsplit("/", 1)[-1],
        "workspace_location": telemetry.DEFAULT_LOCATION,
        "workspace_retention_days": telemetry.DEFAULT_RETENTION_DAYS,
        "workspace_daily_cap_gb": telemetry.DEFAULT_DAILY_CAP_GB,
    }
    outputs.update(overrides)
    return outputs


# ---------------------------------------------------------------------------
# ensure(): first build, managed
# ---------------------------------------------------------------------------
def test_first_build_managed_writes_tfvars_and_settings():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        result = hub.ensure(cfg)

        assert tf.written_vars["create_managed_workspace"] is True
        assert tf.written_vars["workspace_name"] == _MANAGED_WS_ID.rsplit("/", 1)[-1]
        assert tf.written_vars["location"] == telemetry.DEFAULT_LOCATION
        assert tf.written_vars["retention_days"] == telemetry.DEFAULT_RETENTION_DAYS
        assert tf.written_vars["daily_cap_gb"] == telemetry.DEFAULT_DAILY_CAP_GB
        assert tf.written_vars["destination_workspace_id"] == ""
        assert tf.applied == 1
        assert result.managed is True
        assert result.activity_log == "created"

        with open(os.path.join(hub_dir, "hub_settings.json")) as f:
            saved = json.load(f)
        assert saved["subscription_id"] == SUB
        assert saved["tenant_id"] == TENANT
        assert saved["destination_workspace_id"] == ""
        assert saved["keep_managed_workspace"] is True
        assert saved["entra_settings"] == []
        print("ok: first managed build writes tfvars, applies, and persists hub_settings.json")


def test_settings_from_config_or_defaults():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)

        cfg_explicit = telemetry.parse(
            {"workspace": {"location": "East US", "retention_days": 90, "daily_cap_gb": 5}}, env={})
        hub.ensure(cfg_explicit)
        assert tf.written_vars["location"] == "East US"
        assert tf.written_vars["retention_days"] == 90
        assert tf.written_vars["daily_cap_gb"] == 5

        tf2 = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        hub2 = TelemetryHub(SUB, TENANT, rest, tf2, hub_dir)
        cfg_default = telemetry.parse(True, env={})
        hub2.ensure(cfg_default)
        assert tf2.written_vars["location"] == telemetry.DEFAULT_LOCATION
        assert tf2.written_vars["retention_days"] == telemetry.DEFAULT_RETENTION_DAYS
        assert tf2.written_vars["daily_cap_gb"] == telemetry.DEFAULT_DAILY_CAP_GB
        print("ok: tfvars carry explicit config values, or defaults when omitted")


def test_daily_cap_null_is_uncapped():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse({"workspace": {"daily_cap_gb": None}}, env={})

        hub.ensure(cfg)

        assert tf.written_vars["daily_cap_gb"] == -1
        print("ok: an explicit null daily_cap_gb becomes -1 (uncapped) in tfvars")


def test_notes_only_for_explicit_differences():
    with _hub_dir() as hub_dir:
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})

        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"],
                    outputs=_managed_outputs(workspace_retention_days=30))
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg_explicit = telemetry.parse({"workspace": {"retention_days": 90}}, env={})
        result = hub.ensure(cfg_explicit)
        assert any("retention_days 90 ignored" in n for n in result.notes), result.notes

        tf2 = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"],
                     outputs=_managed_outputs(workspace_retention_days=30))
        hub2 = TelemetryHub(SUB, TENANT, rest, tf2, hub_dir)
        cfg_default = telemetry.parse(True, env={})
        result2 = hub2.ensure(cfg_default)
        assert result2.notes == []

        tf3 = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"],
                     outputs=_managed_outputs(workspace_location="West US 2"))
        hub3 = TelemetryHub(SUB, TENANT, rest, tf3, hub_dir)
        cfg_loc = telemetry.parse({"workspace": {"location": "East US"}}, env={})
        result3 = hub3.ensure(cfg_loc)
        assert any("location East US ignored" in n for n in result3.notes), result3.notes
        print("ok: notes appear only for explicitly-set fields that differ from the live workspace")


def test_hub_hcl_ignores_setting_changes():
    text = Path(_REPO, "terraform", "telemetry", "main.tf").read_text()
    start = text.index('resource "azurerm_log_analytics_workspace" "hub"')
    block = text[start:start + 1500]
    assert "ignore_changes" in block
    for field_name in ("location", "retention_in_days", "daily_quota_gb"):
        assert field_name in block, f"{field_name} missing from workspace ignore_changes block"
    print("ok: the hub's managed workspace ignores location/retention/cap changes")


# ---------------------------------------------------------------------------
# ensure(): BYO
# ---------------------------------------------------------------------------
def test_byo_not_found_is_fatal():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=[])
        rest = FakeRest({})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse({"workspace": _BYO_ID}, env={})
        try:
            hub.ensure(cfg)
        except HubError as e:
            assert "not found" in str(e)
        else:
            raise AssertionError("expected HubError")
        print("ok: a BYO workspace that doesn't exist is fatal")


def test_byo_forbidden_is_fatal_with_role_hint():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=[])
        rest = FakeRest({_BYO_ID: AzureRestError(403, "Forbidden")})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse({"workspace": _BYO_ID}, env={})
        try:
            hub.ensure(cfg)
        except HubError as e:
            assert "Log Analytics Contributor" in str(e)
        else:
            raise AssertionError("expected HubError")
        print("ok: a 403 on the BYO workspace is fatal and names the needed role")


def test_byo_sets_destination_and_no_managed():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=[], outputs={"workspace_id": _BYO_ID})
        rest = FakeRest({_BYO_ID: {"name": "customer-law", "location": "East US"}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse({"workspace": _BYO_ID, "activity_log": False}, env={})

        result = hub.ensure(cfg)

        assert tf.written_vars["create_managed_workspace"] is False
        assert tf.written_vars["destination_workspace_id"] == _BYO_ID
        assert tf.imported == []
        assert result.managed is False
        assert result.workspace_name == "customer-law"
        print("ok: a BYO config sets destination_workspace_id and never creates a managed workspace")


def test_switch_to_byo_keeps_managed_workspace():
    with _hub_dir() as hub_dir:
        with open(os.path.join(hub_dir, "hub_settings.json"), "w") as f:
            json.dump({"keep_managed_workspace": True, "entra_settings": []}, f)
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs={"workspace_id": _BYO_ID})
        rest = FakeRest({
            _BYO_ID: {"name": "customer-law", "location": "East US"},
            _ACTIVITY_LIST_URL: {"value": []},
        })
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse({"workspace": _BYO_ID}, env={})

        hub.ensure(cfg)

        assert tf.written_vars["create_managed_workspace"] is True
        assert tf.written_vars["destination_workspace_id"] == _BYO_ID
        print("ok: switching to BYO with keep_managed_workspace=true keeps create_managed_workspace true")


def test_hub_settings_preserves_entra_settings():
    with _hub_dir() as hub_dir:
        with open(os.path.join(hub_dir, "hub_settings.json"), "w") as f:
            json.dump({"entra_settings": ["badzure-entra-aaaaaa"]}, f)
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        hub.ensure(cfg)

        with open(os.path.join(hub_dir, "hub_settings.json")) as f:
            saved = json.load(f)
        assert saved["entra_settings"] == ["badzure-entra-aaaaaa"]

        hub.record_entra_setting("badzure-entra-bbbbbb")
        hub.record_entra_setting("badzure-entra-bbbbbb")   # no duplicate
        assert hub.known_entra_settings() == ["badzure-entra-aaaaaa", "badzure-entra-bbbbbb"]
        print("ok: a hub run preserves entra_settings; record_entra_setting appends without duplicates")


# ---------------------------------------------------------------------------
# Adoption
# ---------------------------------------------------------------------------
def test_adoption_on_empty_state():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=[], outputs=_managed_outputs())
        rest = FakeRest({
            _RG_ID: {"name": TELEMETRY_HUB_RG},
            _MANAGED_WS_ID: {"name": _MANAGED_WS_ID.rsplit("/", 1)[-1]},
            _AUDIT_URL: {"name": TELEMETRY_DIAG_SETTING_NAME},
            _ACTIVITY_LIST_URL: {"value": []},
        })
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        hub.ensure(cfg)

        assert ("azurerm_resource_group.hub[0]", _RG_ID) in tf.imported
        assert ("azurerm_log_analytics_workspace.hub[0]", _MANAGED_WS_ID) in tf.imported
        assert ("azurerm_monitor_diagnostic_setting.workspace_audit[0]", _AUDIT_ID) in tf.imported
        # Imports happen before apply.
        last_import = max(i for i, c in enumerate(tf.call_order) if c.startswith("import:"))
        apply_index = tf.call_order.index("apply")
        assert last_import < apply_index
        print("ok: an empty state adopts every existing hub resource before apply")


def test_no_adoption_when_state_present():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        hub.ensure(cfg)

        assert tf.imported == []
        assert not any(c[1] == _RG_ID for c in rest.calls)
        print("ok: a non-empty state skips adoption entirely")


# ---------------------------------------------------------------------------
# Activity Log cap and duplicates
# ---------------------------------------------------------------------------
def test_activity_cap_skips_and_warns():
    with _hub_dir() as hub_dir:
        existing = [{"name": f"other-{i}", "properties": {"workspaceId": "somewhere-else"}}
                    for i in range(5)]
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": existing}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        result = hub.ensure(cfg)

        assert result.activity_log == "skipped_cap"
        assert result.warnings, "expected a cap warning"
        assert tf.written_vars["activity_log_enabled"] is False
        print("ok: 5 existing Activity Log exports skip ours for this build and warn")


def test_activity_duplicate_warns():
    with _hub_dir() as hub_dir:
        existing = [{"name": "someone-elses-export", "properties": {"workspaceId": _MANAGED_WS_ID}}]
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": existing}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        result = hub.ensure(cfg)

        assert any("someone-elses-export" in w for w in result.warnings), result.warnings
        assert result.activity_log == "created"
        assert tf.written_vars["activity_log_enabled"] is True
        print("ok: another setting pointed at our destination warns, ours is still created")


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------
def test_apply_failure_raises_hub_error():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], apply_rc=1)
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        try:
            hub.ensure(cfg)
        except HubError as e:
            assert "apply" in str(e).lower()
        else:
            raise AssertionError("expected HubError")
        assert not os.path.exists(os.path.join(hub_dir, "hub_settings.json"))
        print("ok: a failed hub apply raises HubError and never writes hub_settings.json")


# ---------------------------------------------------------------------------
# preview()
# ---------------------------------------------------------------------------
def test_preview_never_writes_settings():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=[], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        result = hub.preview(cfg)

        assert not os.path.exists(os.path.join(hub_dir, "hub_settings.json"))
        assert tf.imported == []
        assert tf.planned == 1
        assert tf.applied == 0
        assert result.workspace_id == _MANAGED_WS_ID
        print("ok: preview never imports or writes hub_settings.json, only plans")


def test_preview_degrades_when_token_unavailable():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=[])
        rest = FakeRest(error_on_all=AzureRestError(0, "", "no credential available"))
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse(True, env={})

        result = hub.preview(cfg)

        assert result.workspace_id == _MANAGED_WS_ID
        assert tf.planned == 0
        assert result.warnings
        print("ok: preview degrades to the offline managed workspace id when no token is available")


def test_preview_byo_not_found_is_fatal():
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=[])
        rest = FakeRest({})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        cfg = telemetry.parse({"workspace": _BYO_ID}, env={})
        try:
            hub.preview(cfg)
        except HubError:
            pass
        else:
            raise AssertionError("expected HubError")
        print("ok: preview still fails fast on a genuinely missing BYO workspace")


# ---------------------------------------------------------------------------
# destroy()
# ---------------------------------------------------------------------------
def test_destroy_without_settings_uses_env_subscription():
    with _hub_dir() as hub_dir:
        rest = FakeRest({})
        tf = FakeTf(state=[])
        hub = TelemetryHub("", "", rest, tf, hub_dir)
        old = os.environ.pop("BADZURE_SUBSCRIPTION_ID", None)
        os.environ["BADZURE_SUBSCRIPTION_ID"] = SUB
        try:
            result = hub.destroy(lambda text: True)
        finally:
            if old is None:
                os.environ.pop("BADZURE_SUBSCRIPTION_ID", None)
            else:
                os.environ["BADZURE_SUBSCRIPTION_ID"] = old
        assert result is True
        assert any(c[1] == _RG_ID for c in rest.calls)
        print("ok: destroy without hub_settings.json falls back to BADZURE_SUBSCRIPTION_ID")


def test_destroy_without_settings_or_env_is_a_noop():
    with _hub_dir() as hub_dir:
        rest = FakeRest({})
        tf = FakeTf(state=[])
        hub = TelemetryHub("", "", rest, tf, hub_dir)
        old = os.environ.pop("BADZURE_SUBSCRIPTION_ID", None)
        try:
            result = hub.destroy(lambda text: True)
        finally:
            if old is not None:
                os.environ["BADZURE_SUBSCRIPTION_ID"] = old
        assert result is True
        assert rest.calls == []
        assert tf.destroyed == 0
        print("ok: destroy with no hub_settings.json and no env subscription is a clean no-op")


def test_destroy_confirm_declined_changes_nothing():
    with _hub_dir() as hub_dir:
        settings_path = os.path.join(hub_dir, "hub_settings.json")
        with open(settings_path, "w") as f:
            json.dump({"subscription_id": SUB, "tenant_id": TENANT,
                      "destination_workspace_id": "", "keep_managed_workspace": True,
                      "entra_settings": []}, f)
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"])
        rest = FakeRest({})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)

        result = hub.destroy(lambda text: False)

        assert result is False
        assert tf.destroyed == 0
        assert tf.cleaned == 0
        assert os.path.exists(settings_path)
        print("ok: declining the destroy confirmation changes nothing")


def test_destroy_removes_state_and_settings_keeps_labs_json():
    with _hub_dir() as hub_dir:
        settings_path = os.path.join(hub_dir, "hub_settings.json")
        labs_path = os.path.join(hub_dir, "labs.json")
        with open(settings_path, "w") as f:
            json.dump({"subscription_id": SUB, "tenant_id": TENANT,
                      "destination_workspace_id": "", "keep_managed_workspace": True,
                      "entra_settings": []}, f)
        with open(labs_path, "w") as f:
            json.dump([{"lab_id": "abcde"}], f)
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"])
        rest = FakeRest({})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)

        result = hub.destroy(lambda text: True)

        assert result is True
        assert tf.destroyed == 1
        assert tf.cleaned == 1
        assert not os.path.exists(settings_path)
        assert os.path.exists(labs_path)
        print("ok: destroy removes hub_settings.json and state, keeps labs.json")


def test_destroy_byo_text_says_workspace_untouched():
    with _hub_dir() as hub_dir:
        with open(os.path.join(hub_dir, "hub_settings.json"), "w") as f:
            json.dump({"subscription_id": SUB, "tenant_id": TENANT,
                      "destination_workspace_id": _BYO_ID, "keep_managed_workspace": False,
                      "entra_settings": []}, f)
        activity_name = f"badzure-activity-{telemetry.setting_suffix(_BYO_ID)}"
        activity_url = f"/subscriptions/{SUB}/providers/Microsoft.Insights/diagnosticSettings/{activity_name}"
        tf = FakeTf(state=[])
        rest = FakeRest({activity_url: {"name": activity_name}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)

        captured = {}

        def confirm(text):
            captured["text"] = text
            return True

        hub.destroy(confirm)

        assert "not touched" in captured["text"]
        assert "customer-law" in captured["text"]
        assert "Managed workspace" not in captured["text"]
        print("ok: a BYO destination's confirmation text says the workspace is not touched")


def test_destroy_adopts_on_fresh_clone_then_destroys():
    with _hub_dir() as hub_dir:
        old = os.environ.pop("BADZURE_SUBSCRIPTION_ID", None)
        os.environ["BADZURE_SUBSCRIPTION_ID"] = SUB
        try:
            tf = FakeTf(state=[])
            rest = FakeRest({
                _RG_ID: {"name": TELEMETRY_HUB_RG},
                _MANAGED_WS_ID: {"name": _MANAGED_WS_ID.rsplit("/", 1)[-1]},
                _AUDIT_URL: {"name": TELEMETRY_DIAG_SETTING_NAME},
            })
            hub = TelemetryHub("", "", rest, tf, hub_dir)

            result = hub.destroy(lambda text: True)

            assert result is True
            assert tf.destroyed == 1
            assert ("azurerm_resource_group.hub[0]", _RG_ID) in tf.imported
            assert ("azurerm_log_analytics_workspace.hub[0]", _MANAGED_WS_ID) in tf.imported
        finally:
            if old is None:
                os.environ.pop("BADZURE_SUBSCRIPTION_ID", None)
            else:
                os.environ["BADZURE_SUBSCRIPTION_ID"] = old
        print("ok: a fresh clone (no hub_settings.json, no local state) still adopts and destroys")


# ---------------------------------------------------------------------------
# Self-run support: `python tests/test_telemetry_hub.py`
# ---------------------------------------------------------------------------
def test_activity_log_false_disables_export():
    """activity_log: false must never create the subscription export, and must
    not read the subscription's settings either."""
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"], outputs=_managed_outputs())
        rest = FakeRest({_ACTIVITY_LIST_URL: {"value": []}})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        result = hub.ensure(telemetry.parse({"activity_log": False}, env={}))
        assert tf.written_vars["activity_log_enabled"] is False
        assert result.activity_log == "off"
        assert not any(url == _ACTIVITY_LIST_URL for _, url, _ in rest.calls)

        tf2 = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"])
        hub2 = TelemetryHub(SUB, TENANT, FakeRest(), tf2, hub_dir)
        hub2.preview(telemetry.parse({"activity_log": False}, env={}))
        assert tf2.written_vars["activity_log_enabled"] is False
    print("ok: activity_log: false disables the export in ensure and preview")


def test_preview_azure_error_is_hub_error():
    """A non-credential Azure failure in preview is a HubError (plan exits 1),
    not an uncaught AzureRestError."""
    with _hub_dir() as hub_dir:
        tf = FakeTf(state=["azurerm_log_analytics_workspace.hub[0]"])
        rest = FakeRest({_ACTIVITY_LIST_URL: AzureRestError(500, "boom")})
        hub = TelemetryHub(SUB, TENANT, rest, tf, hub_dir)
        try:
            hub.preview(telemetry.parse(True, env={}))
        except HubError:
            pass
        else:
            raise AssertionError("expected HubError")
        assert tf.planned == 0
    print("ok: preview wraps Azure errors in HubError")


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
    print(f"\n{len(tests) - failures}/{len(tests)} telemetry hub tests passed.")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    _run_all()
