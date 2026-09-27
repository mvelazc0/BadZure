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
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, TYPE_CHECKING

from src.config_manager import ENV_TELEMETRY_WORKSPACE
from src.constants import (
    TELEMETRY_EXCLUDED_TYPES,
    TELEMETRY_HUB_RG,
    TELEMETRY_LOGGED_KINDS,
)

if TYPE_CHECKING:
    # Type-checking only: primitives.py has no runtime import of telemetry.py, so
    # this direction is safe, but we still avoid it at runtime to keep telemetry.py
    # a leaf module.
    from src.primitives import DeploymentModel

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
        f"/subscriptions/{subscription_id}/resourceGroups/{TELEMETRY_HUB_RG}/"
        f"providers/Microsoft.OperationalInsights/workspaces/badzure-law-{_h6(subscription_id)}"
    )


def new_lab_id(rng: Optional[random.Random] = None) -> str:
    """A fresh 5-char `[a-z0-9]` lab id, minted once per build. Accepts an
    injected `random.Random` so callers can make it deterministic in tests."""
    rng = rng or random.Random()
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(5))


def function_storage_name_transform(name: str) -> str:
    """Mirror terraform/main.tf's azurerm_storage_account.function_storage name
    expression exactly, so `check`/`plan` can show the storage account name Azure
    will actually get without running Terraform:

        substr(lower(replace(replace(name, "func-", "fc"), "-", "")), 0, 24)

    Order matters: the "func-" -> "fc" replace happens before hyphens are
    stripped, and lowercasing happens after both replaces, before the truncate.
    """
    without_prefix = name.replace("func-", "fc")
    without_hyphens = without_prefix.replace("-", "")
    return without_hyphens.lower()[:24]


def _display_name(kind: str, entity_key: str, entity: dict) -> str:
    """The Azure name terraform/main.tf gives a target's parent resource. Most
    kinds use the entity's `name`; a few derive it (keep in sync with main.tf)."""
    name = entity.get("name", entity_key)
    if kind == "function_storage":
        return function_storage_name_transform(name)
    if kind in ("app_service_plan", "function_plan"):
        return f"{name}-plan"
    if kind == "nsg":
        return f"{entity_key}-nsg"
    return name


# -- Kind table / TelemetryPlan (Phase 2 of the plan) -------------------------
@dataclass
class DiagnosticTarget:
    """One `azurerm_monitor_diagnostic_setting` the lab will create. `key` is
    the symbolic key the Terraform builder's `diagnostic_targets` map (Phase 3)
    will use; it must be unique and stable across runs."""
    key: str               # "<entity_key>/<service>" e.g. "st_fin/blob", or "<entity_key>/<kind>"
    kind: str               # prefix from TELEMETRY_LOGGED_KINDS
    entity_key: str
    suffix: str
    destination_type: Optional[str]
    log_mode: str          # "allLogs" | "discover", from TELEMETRY_LOGGED_KINDS
    display_name: str      # the Azure name from the model (for check output)


@dataclass
class NotCollected:
    """A resource the lab creates that gets no diagnostic setting, and why."""
    display_name: str
    reason_code: str
    reason: str


@dataclass
class TelemetryPlan:
    """The offline-derivable telemetry outcome for one lab. Everything here is
    computable from a `DeploymentModel` alone (no Azure, no Terraform), which is
    what lets `check` show it before anything is built."""
    config: TelemetryConfig
    workspace_id: str                 # BYO id, or managed_workspace_id(sub) (§3.1)
    managed: bool
    targets: List[DiagnosticTarget] = field(default_factory=list)   # [] when resources is False
    not_collected: List[NotCollected] = field(default_factory=list)
    site_logging: bool = False        # resources and at least one app_service
    entra: bool = True                # categories are discovered at build (Phase 5)
    # Rendering-only: the managed workspace's name, badzure-law-<h6(subscription_id)>,
    # or badzure-law-<subscription hash> when `check` runs without a subscription
    # (workspace_id is "" then). "" when `managed` is False (BYO).
    managed_workspace_name: str = ""


def _service_label(suffix: str) -> str:
    """"/blobServices/default" -> "blob" (STORAGE_SERVICE_SUFFIXES shape only)."""
    return suffix.split("/")[1].replace("Services", "").lower()


def derive_plan(model: "DeploymentModel") -> Optional[TelemetryPlan]:
    """Derive exactly which diagnostic targets the lab gets and which resources
    are not collected, from the model alone. Returns None when telemetry is off.

    See "Rules for derive_plan" in the Phase 2 plan section for the contract
    (key formats, sort order, resources:False behavior, empty-subscription
    handling). Pure: no Azure, no Terraform, no filesystem I/O.
    """
    cfg = model.telemetry
    if cfg is None:
        return None

    managed = cfg.byo_workspace_id is None
    if managed:
        sub = model.subscription_id or ""
        # `check` runs with an empty subscription ID: don't invent one. The ID
        # stays blank and the name shows a placeholder for the hash.
        managed_workspace_name = (f"badzure-law-{_h6(sub)}" if sub
                                  else "badzure-law-<subscription hash>")
        workspace_id = managed_workspace_id(sub) if sub else ""
    else:
        managed_workspace_name = ""
        workspace_id = cfg.byo_workspace_id

    targets: List[DiagnosticTarget] = []
    not_collected: List[NotCollected] = []
    site_logging = False

    if cfg.resources:
        kind_order = {kind: i for i, kind in enumerate(TELEMETRY_LOGGED_KINDS)}
        for kind, (map_attr, suffixes, destination_type, log_mode) in TELEMETRY_LOGGED_KINDS.items():
            entity_map = getattr(model, map_attr)
            if not entity_map:
                continue
            for entity_key, entity in entity_map.items():
                display_name = _display_name(kind, entity_key, entity)
                for suffix in suffixes:
                    if suffix == "":
                        key = f"{entity_key}/{kind}"
                    elif kind == "function_storage":
                        key = f"{entity_key}/fnstorage-{_service_label(suffix)}"
                    else:
                        key = f"{entity_key}/{_service_label(suffix)}"
                    targets.append(DiagnosticTarget(
                        key=key, kind=kind, entity_key=entity_key, suffix=suffix,
                        destination_type=destination_type, log_mode=log_mode,
                        display_name=display_name,
                    ))
        targets.sort(key=lambda t: (t.entity_key, kind_order[t.kind], t.suffix))
        site_logging = bool(model.app_services)

        # Only meaningful when resources are collected at all: with resources
        # off, nothing is collected, so there is nothing to single out a VM for.
        vm_reason_code, vm_reason = TELEMETRY_EXCLUDED_TYPES["azurerm_linux_virtual_machine"]
        for vm_key, vm in (model.virtual_machines or {}).items():
            not_collected.append(NotCollected(
                display_name=vm.get("name", vm_key),
                reason_code=vm_reason_code, reason=vm_reason,
            ))

    return TelemetryPlan(
        config=cfg,
        workspace_id=workspace_id,
        managed=managed,
        targets=targets,
        not_collected=not_collected,
        site_logging=site_logging,
        entra=cfg.entra,
        managed_workspace_name=managed_workspace_name,
    )


# -- Rendering (human `check` output) -----------------------------------------
_LABEL_WIDTH = 15
_ITEM_INDENT = " " * (_LABEL_WIDTH + 4)   # resource rows sit 2 in from the value column


def _fmt_gb(n) -> str:
    n = float(n)
    return str(int(n)) if n.is_integer() else str(n)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _parse_workspace_id(workspace_id: str):
    m = re.match(
        r"^/subscriptions/[^/]+/resourceGroups/(?P<rg>[^/]+)/providers/"
        r"Microsoft\.OperationalInsights/workspaces/(?P<name>[^/]+)$",
        workspace_id, re.IGNORECASE)
    if m:
        return m.group("rg"), m.group("name")
    return workspace_id, ""


def _row(label: str, value: str) -> str:
    return f"  {label:<{_LABEL_WIDTH}}{value}"


def _cont(value: str) -> str:
    return " " * (_LABEL_WIDTH + 2) + value


def _grouped_target_rows(targets: List[DiagnosticTarget], site_logging: bool):
    """Group adjacent targets sharing (entity_key, kind) (the storage fan-out)
    into one display row each. `targets` must already be in derive_plan's sort
    order (entity_key, kind_order, suffix), which keeps a fan-out's rows adjacent."""
    rows = []
    i = 0
    while i < len(targets):
        t = targets[i]
        group = [t]
        j = i + 1
        while (j < len(targets) and targets[j].entity_key == t.entity_key
               and targets[j].kind == t.kind):
            group.append(targets[j])
            j += 1
        log_desc = "all logs" if t.log_mode == "allLogs" else "each supported category"
        if len(group) > 1:
            services = ", ".join(_service_label(g.suffix) for g in group)
            detail = f"{services}: {log_desc}"
        else:
            detail = log_desc
            if t.kind == "app_service" and site_logging:
                detail += " + site logging"
        rows.append((t.display_name, detail))
        i = j
    return rows


def render_plan_lines(plan: TelemetryPlan) -> List[str]:
    """Render the human `check` output for a telemetry plan. Column alignment is
    internal to this function (stable, snapshot-tested); nothing else depends on
    exact spacing."""
    cfg = plan.config
    lines = ["Telemetry plan"]
    target_rows = _grouped_target_rows(plan.targets, plan.site_logging)
    # One name column wide enough for the longest name, plus a 2-space gap.
    names = [n for n, _ in target_rows] + [nc.display_name for nc in plan.not_collected]
    name_width = max((len(n) for n in names), default=0) + 2

    if plan.managed:
        ws = cfg.workspace_settings
        location = ws.location or DEFAULT_LOCATION
        lines.append(_row("Workspace",
            f"managed: {TELEMETRY_HUB_RG}/{plan.managed_workspace_name} "
            f"({location} unless already created)"))
        retention = ws.retention_days or DEFAULT_RETENTION_DAYS
        if ws.daily_cap_explicit and ws.daily_cap_gb is None:
            cap_text = "no cap"
        else:
            cap = ws.daily_cap_gb if ws.daily_cap_gb is not None else DEFAULT_DAILY_CAP_GB
            cap_text = f"daily cap {_fmt_gb(cap)} GB"
        lines.append(_cont(f"retention {retention} days, {cap_text} "
                            f"(applied when the workspace is created)"))
    else:
        rg, name = _parse_workspace_id(plan.workspace_id)
        lines.append(_row("Workspace",
            f"yours: {rg}/{name}. BadZure will not modify or delete it."))

    lines.append(_row("Entra",
        "on: every category (tenant-wide; what has data depends on the licence)"
        if cfg.entra else "off"))
    lines.append(_row("Activity Log",
        "on (all categories, free to ingest)" if cfg.activity_log else "off"))

    if not cfg.resources:
        lines.append(_row("Resources",
            "off (coverage depends on your own policy or settings)"))
    else:
        n_settings = len(plan.targets)
        n_resources = len({(t.entity_key, t.kind) for t in plan.targets})
        lines.append(_row("Resources",
            f"on, all logs: {_plural(n_settings, 'setting')} on "
            f"{_plural(n_resources, 'resource')}"))
        for display_name, detail in target_rows:
            lines.append(f"{_ITEM_INDENT}{display_name.ljust(name_width)}{detail}")

    if plan.not_collected:
        # Not-collected names start 2 columns left of resource names, so pad 2
        # wider: both detail columns line up.
        first = True
        for nc in plan.not_collected:
            label = "Not collected" if first else ""
            first = False
            lines.append(_row(label, f"{nc.display_name.ljust(name_width + 2)}{nc.reason}"))
        lines.append(_cont("public IPs and VNets: no useful logs"))

    return lines


def plan_to_json(plan: TelemetryPlan) -> Dict:
    """JSON-serializable form of a telemetry plan, for `check --json`."""
    cfg = plan.config
    return {
        "managed": plan.managed,
        "workspace_id": plan.workspace_id,
        "entra": plan.entra,
        "activity_log": cfg.activity_log,
        "resources": cfg.resources,
        "site_logging": plan.site_logging,
        "targets": [
            {
                "key": t.key,
                "kind": t.kind,
                "entity_key": t.entity_key,
                "suffix": t.suffix,
                "destination_type": t.destination_type,
                "log_mode": t.log_mode,
                "display_name": t.display_name,
            }
            for t in plan.targets
        ],
        "not_collected": [
            {"display_name": n.display_name, "reason_code": n.reason_code,
             "reason": n.reason}
            for n in plan.not_collected
        ],
    }
