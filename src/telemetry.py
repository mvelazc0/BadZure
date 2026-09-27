"""
telemetry.py: the offline half of the telemetry-onboarding feature (Phase 1 of
dev-docs/redesign/telemetry-implementation-plan.md).

Everything here is PURE: no Azure calls, no Terraform, no filesystem I/O. The
only environment read is `os.environ` inside `parse`, and only for one input
(`BADZURE_TELEMETRY_WORKSPACE`), and even that takes an `env` mapping so tests
never touch real process environment.

The optional top-level `telemetry:` config key makes BadZure send attack
telemetry into a Log Analytics workspace that survives `destroy`. This module
owns:
  - the schema (`TelemetryConfig` / `WorkspaceSettings`),
  - validating the raw YAML value with clear, exact error/warning text
    (`validate_raw`, called from `scenario_validator.validate`),
  - resolving it (YAML + env var precedence) into a `TelemetryConfig`
    (`parse`, called from `scenario_loader.ScenarioLoader.load`),
  - the deterministic naming helpers later phases and `check`/`plan` reuse so
    they can describe the telemetry hub without ever calling Azure
    (`setting_suffix`, `managed_workspace_id`, `new_lab_id`).

Telemetry off (`telemetry:` omitted, `false`, or `null`) must be invisible:
`parse` returns `None` and nothing downstream changes.
"""
import hashlib
import os
import random
import re
from dataclasses import dataclass
from typing import List, Mapping, Optional

from src.config_manager import ENV_TELEMETRY_WORKSPACE

# -- Schema --------------------------------------------------------------
TELEMETRY_KEYS = frozenset({"workspace", "entra", "activity_log", "resources"})
WORKSPACE_KEYS = frozenset({"location", "retention_days", "daily_cap_gb"})
WORKSPACE_ID_RE = re.compile(
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/"
    r"Microsoft\.OperationalInsights/workspaces/[^/]+$", re.IGNORECASE)

DEFAULT_RETENTION_DAYS = 30
DEFAULT_DAILY_CAP_GB = 1
# Same value as scenario_loader._DEFAULT_RG_LOCATION. Duplicated (not imported)
# so telemetry.py stays a leaf module: it must not import scenario_loader.
DEFAULT_LOCATION = "West US 2"

# The managed workspace's fixed resource group (see plan doc, section 3.1).
_MANAGED_HUB_RG = "badzure-telemetry"


@dataclass
class WorkspaceSettings:
    """Settings for a MANAGED workspace (meaningless when `byo_workspace_id` is
    set: bring-your-own reuses whatever the workspace already has)."""
    # None = not set in this config: the default applies when the workspace is created.
    location: Optional[str] = None
    retention_days: Optional[int] = None
    daily_cap_gb: Optional[float] = None   # explicit null in YAML => UNCAPPED sentinel
    daily_cap_explicit: bool = False       # True when daily_cap_gb key present (even if null)


@dataclass
class TelemetryConfig:
    """The resolved `telemetry:` config, carried on `DeploymentModel.telemetry`.
    `None` on the model means telemetry is off."""
    byo_workspace_id: Optional[str]        # set => bring-your-own; None => managed
    workspace_settings: WorkspaceSettings  # meaningful only when managed
    entra: bool = True
    activity_log: bool = True
    resources: bool = True
    workspace_source: str = "managed"      # "managed" | "yaml" | "env"


# -- Validation ------------------------------------------------------------
_BOOL_FIELD_HINTS = {
    "entra": "With entra on, every Entra log category is collected.",
    "activity_log": "With activity_log on, every Activity Log category is collected.",
    "resources": "With resources on, every log the lab's resources support is collected.",
}
_WORKSPACE_ID_HINT = (
    "is not a workspace resource ID. Use the full ID "
    "(/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/"
    "workspaces/<name>), or a mapping of managed-workspace settings."
)


def validate_raw(value, errors: List[str], warnings: List[str],
                  env: Optional[Mapping[str, str]] = None) -> None:
    """Validate the raw `telemetry:` YAML value, appending problems to `errors`
    (hard failures) and `warnings` (soft ones), the same aggregation contract
    `scenario_validator.validate` uses everywhere else. Call only when the
    `telemetry` key is present in the config; `value` may still legitimately be
    `None` (an explicit `telemetry: null`, same as omitting the key).

    Bools are ints in Python (`isinstance(True, int)` is `True`), so every
    numeric check below rejects `bool` explicitly before checking `int`/`float`:
    `retention_days: true` and `daily_cap_gb: true` must be errors, not silently
    coerced to 1.
    """
    if env is None:
        env = os.environ

    if value is None or isinstance(value, bool):
        return  # telemetry off (None / false) or fully on (true): nothing to check
    if not isinstance(value, dict):
        errors.append(
            f"telemetry: {value!r} is not a valid value. Use true (collect "
            f"everything), false, or a mapping of fields."
        )
        return

    for key in sorted(set(value) - TELEMETRY_KEYS):
        errors.append(
            f"telemetry: unknown field '{key}'. Supported fields: "
            + ", ".join(sorted(TELEMETRY_KEYS)) + "."
        )

    for field_name, hint in _BOOL_FIELD_HINTS.items():
        if field_name in value and not isinstance(value[field_name], bool):
            errors.append(f"telemetry.{field_name}: must be true or false. {hint}")

    ws = value.get("workspace")
    if isinstance(ws, str):
        if not WORKSPACE_ID_RE.match(ws):
            errors.append(f"telemetry.workspace: {ws!r} {_WORKSPACE_ID_HINT}")
    elif isinstance(ws, dict):
        _validate_workspace_mapping(ws, errors, warnings)
        env_workspace = env.get(ENV_TELEMETRY_WORKSPACE)
        if env_workspace:
            warnings.append(
                f"telemetry.workspace settings are ignored: "
                f"{ENV_TELEMETRY_WORKSPACE} sends telemetry to {env_workspace}."
            )
    elif ws is not None:
        errors.append(f"telemetry.workspace: {ws!r} {_WORKSPACE_ID_HINT}")


def _validate_workspace_mapping(ws: dict, errors: List[str], warnings: List[str]) -> None:
    for key in sorted(set(ws) - WORKSPACE_KEYS):
        errors.append(
            f"telemetry.workspace: unknown field '{key}'. Supported fields: "
            + ", ".join(sorted(WORKSPACE_KEYS)) + "."
        )

    if "retention_days" in ws:
        rd = ws["retention_days"]
        if isinstance(rd, bool) or not isinstance(rd, int) or not (30 <= rd <= 730):
            errors.append(
                f"telemetry.workspace.retention_days: {rd!r} is out of range (30 to 730)."
            )

    if "daily_cap_gb" in ws:
        cap = ws["daily_cap_gb"]
        if cap is None:
            warnings.append(
                "telemetry.workspace.daily_cap_gb is null: ingestion is uncapped. "
                "Watch the workspace's usage page in the Azure portal."
            )
        elif isinstance(cap, bool) or not isinstance(cap, (int, float)) or cap <= 0:
            errors.append(
                "telemetry.workspace.daily_cap_gb: must be a positive number of "
                "GB, or null for no cap."
            )

    if "location" in ws:
        loc = ws["location"]
        if not isinstance(loc, str) or not loc.strip():
            errors.append(
                "telemetry.workspace.location: must be an Azure region name, "
                "e.g. West US 2."
            )


# -- Resolution --------------------------------------------------------------
def parse(value, env: Optional[Mapping[str, str]] = None) -> Optional["TelemetryConfig"]:
    """Turn a raw `telemetry:` value into a resolved `TelemetryConfig`, or `None`
    when telemetry is off. Assumes `validate_raw` already accepted `value`: this
    function does no validation of its own, only defaulting and env resolution.

    Env precedence: a non-empty `BADZURE_TELEMETRY_WORKSPACE` becomes the
    bring-your-own workspace id whenever telemetry is on, overriding a YAML
    `workspace:` string. It never turns telemetry on by itself (that still
    needs `telemetry: true` or a mapping in the YAML).
    """
    if env is None:
        env = os.environ

    if value is None or value is False:
        return None
    if value is True:
        value = {}

    ws = value.get("workspace")
    byo_workspace_id: Optional[str] = None
    workspace_source = "managed"
    workspace_settings = WorkspaceSettings()

    if isinstance(ws, str):
        byo_workspace_id = ws
        workspace_source = "yaml"
    elif isinstance(ws, dict):
        workspace_settings = WorkspaceSettings(
            location=ws.get("location"),
            retention_days=ws.get("retention_days"),
            daily_cap_gb=ws.get("daily_cap_gb"),
            daily_cap_explicit="daily_cap_gb" in ws,
        )

    env_workspace = env.get(ENV_TELEMETRY_WORKSPACE)
    if env_workspace:
        byo_workspace_id = env_workspace
        workspace_source = "env"

    return TelemetryConfig(
        byo_workspace_id=byo_workspace_id,
        workspace_settings=workspace_settings,
        entra=value.get("entra", True),
        activity_log=value.get("activity_log", True),
        resources=value.get("resources", True),
        workspace_source=workspace_source,
    )


# -- Naming helpers (section 3.1 of the plan) --------------------------------
def _h6(x: str) -> str:
    return hashlib.sha256(x.lower().encode()).hexdigest()[:6]


def setting_suffix(workspace_id: str) -> str:
    """Deterministic 6-hex-char suffix for a destination workspace's diagnostic
    setting names. Two hubs in one tenant (different workspaces) never share a
    setting name; the same workspace (any casing) always yields the same suffix."""
    return _h6(workspace_id)


def managed_workspace_id(subscription_id: str) -> str:
    """The deterministic resource ID of BadZure's managed Log Analytics workspace
    for this subscription. Computed offline (no Azure call) so `check`/`plan` can
    show it before the hub is ever created."""
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{_MANAGED_HUB_RG}/"
        f"providers/Microsoft.OperationalInsights/workspaces/badzure-law-{_h6(subscription_id)}"
    )


def new_lab_id(rng: Optional[random.Random] = None) -> str:
    """A fresh 5-char `[a-z0-9]` lab id, minted once per build. Accepts an
    injected `random.Random` so callers can make it deterministic in tests."""
    rng = rng or random.Random()
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(5))
