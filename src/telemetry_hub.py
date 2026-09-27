"""
telemetry_hub.py: the telemetry hub lifecycle (Phase 4 of
dev-docs/redesign/telemetry-implementation-plan.md).

The telemetry hub is a second, persistent Terraform root (terraform/telemetry/)
that survives `destroy`: the workspace (managed, or bring-your-own) and the
subscription Activity Log export. `TelemetryHub.ensure()` makes it exist (or
confirms it already matches what the config wants) before the lab is ever
touched; a failure here must stop the build before anything in the lab is
created. `TelemetryHub.preview()` is the read-only counterpart `plan` uses.
`TelemetryHub.destroy()` removes the hub on `destroy --telemetry`.

Every collaborator this module needs (an AzureRest client, a TerraformManager)
is constructor-injected, so tests pass fakes and never touch real Azure or run
real Terraform.

Adoption. A hub's resources have deterministic names and IDs (see
src/telemetry.py's managed_workspace_id / setting_suffix), so on an empty
Terraform state this module GETs each deterministic ID directly and, if it
already exists in Azure (a prior run, or a fresh clone that lost its state),
imports it instead of letting `apply` plan a duplicate create.
"""
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from src.azure_rest import AzureRest, AzureRestError
from src.config_manager import ENV_SUBSCRIPTION_ID
from src.constants import ACTIVITY_LOG_CATEGORIES, TELEMETRY_DIAG_SETTING_NAME, TELEMETRY_HUB_RG
from src import telemetry
from src.telemetry import TelemetryConfig
from src.terraform_manager import TerraformManager

# Verified with `terraform providers schema -json` against azurerm 4.57.0 in a
# temp dir (never against real state): a resource-group GET needs an
# api-version too, even though the plan didn't pin one. 2021-04-01 is a
# current stable Microsoft.Resources API version.
RG_API_VERSION = "2021-04-01"
# Per the plan: Log Analytics workspace GET/import.
WORKSPACE_API_VERSION = "2022-10-01"
# Per the plan: diagnostic settings GET/PUT/DELETE/list, resource-scoped and
# subscription-scoped alike.
DIAG_API_VERSION = "2021-05-01-preview"


class HubError(RuntimeError):
    """A fatal telemetry hub failure. Raised by `ensure()`/`preview()`/`destroy()`
    so the caller can stop before the lab (or, for destroy, the hub's own
    resources) is touched."""


@dataclass
class HubResult:
    """What `ensure()`/`preview()` learned about the hub, for the CLI to log and
    to hand the lab builder the workspace it should wire into tfvars."""
    workspace_id: str
    managed: bool
    workspace_name: str
    location: str
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    activity_log: str = "off"   # "created" | "exists" | "off" | "skipped_cap"


@dataclass
class _ResolvedInputs:
    """The hub's Terraform inputs, resolved from the config and any earlier
    hub_settings.json (internal to this module; not part of the public API)."""
    location: str
    retention_days: int
    daily_cap_gb: float
    destination_workspace_id: str      # BYO id, or "" for managed
    create_managed_workspace: bool
    effective_destination: str         # destination_workspace_id, or the managed id
    suffix: str                        # setting_suffix(effective_destination)


class TelemetryHub:
    """Owns the telemetry hub's Terraform root and its small local bookkeeping
    files (hub_settings.json, labs.json), both under `hub_dir`."""

    def __init__(self, subscription_id: str, tenant_id: str, rest: AzureRest,
                 tf: TerraformManager, hub_dir: str):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.rest = rest
        self.tf = tf
        self.hub_dir = hub_dir

    # -- Public API -----------------------------------------------------
    def ensure(self, cfg: TelemetryConfig) -> HubResult:
        """Make the hub match `cfg`, creating or adopting whatever is missing.
        Fatal on any failure (raises HubError): the caller must not create
        anything in the lab when this raises."""
        hub_settings = self._load_hub_settings()
        resolved = self._resolve_inputs(cfg, hub_settings)

        try:
            byo_info = self._verify_byo(cfg.byo_workspace_id) if cfg.byo_workspace_id else None

            found: List[Tuple[str, str, dict]] = []
            if not self.tf.state_list():
                found = self._discover(
                    check_managed=resolved.create_managed_workspace,
                    activity_suffix=resolved.suffix if cfg.activity_log else None,
                )

            activity_enabled, activity_status, activity_warnings = False, "off", []
            if cfg.activity_log:
                activity_enabled, activity_status, activity_warnings = \
                    self._activity_cap_and_duplicates(resolved)
        except HubError:
            raise
        except AzureRestError as e:
            raise HubError(f"Could not reach Azure to set up the telemetry hub: {e}")

        if activity_status == "skipped_cap":
            # A cap-skipped run never enables the activity resource (count=0
            # this apply), so importing a candidate found for it would fail:
            # there is no instance to import into.
            found = [f for f in found
                     if not f[0].startswith("azurerm_monitor_diagnostic_setting.activity")]

        tfvars = self._tfvars(resolved, activity_enabled)
        self.tf.write_terraform_vars(tfvars)

        return_code, stdout, stderr = self.tf.init()
        if return_code != 0:
            raise HubError(f"Telemetry hub `terraform init` failed: {stderr or stdout}")

        for address, resource_id, _ in found:
            return_code, stdout, stderr = self.tf.import_resource(address, resource_id)
            if return_code != 0:
                raise HubError(
                    f"Telemetry hub could not adopt existing resource {resource_id} "
                    f"into {address}: {stderr or stdout}"
                )

        return_code, stdout, stderr = self.tf.apply()
        if return_code != 0:
            raise HubError(f"Telemetry hub `terraform apply` failed: {stderr or stdout}")

        outputs = self.tf.get_outputs()
        notes = self._diff_notes(cfg, resolved, outputs)

        hub_settings["subscription_id"] = self.subscription_id
        hub_settings["tenant_id"] = self.tenant_id
        # Sticky once true: a later config pointing at a BYO workspace must not
        # make Terraform plan to destroy a managed workspace created earlier.
        hub_settings["keep_managed_workspace"] = (
            resolved.create_managed_workspace or bool(hub_settings.get("keep_managed_workspace"))
        )
        hub_settings["destination_workspace_id"] = resolved.destination_workspace_id
        hub_settings.setdefault("entra_settings", [])
        self._save_hub_settings(hub_settings)

        if resolved.create_managed_workspace:
            workspace_name = outputs.get("workspace_name") or tfvars["workspace_name"]
            location = outputs.get("workspace_location") or resolved.location
        else:
            workspace_name = (byo_info or {}).get("name") or cfg.byo_workspace_id.rsplit("/", 1)[-1]
            location = (byo_info or {}).get("location") or ""

        return HubResult(
            workspace_id=outputs.get("workspace_id") or resolved.effective_destination,
            managed=cfg.byo_workspace_id is None,
            workspace_name=workspace_name,
            location=location,
            notes=notes,
            warnings=activity_warnings,
            activity_log=activity_status,
        )

    def preview(self, cfg: TelemetryConfig) -> HubResult:
        """Read-only counterpart to `ensure()`, for `plan`: same resolution and
        read-only checks, then a hub `terraform plan` instead of `apply`. Never
        writes hub_settings.json, never imports. Degrades to the offline
        managed workspace id (with a warning, hub plan skipped) if a token
        can't be obtained at all, since that shouldn't block a preflight."""
        hub_settings = self._load_hub_settings()
        resolved = self._resolve_inputs(cfg, hub_settings)

        try:
            byo_info = self._verify_byo(cfg.byo_workspace_id) if cfg.byo_workspace_id else None
            if not self.tf.state_list():
                found = self._discover(
                    check_managed=resolved.create_managed_workspace,
                    activity_suffix=resolved.suffix if cfg.activity_log else None,
                )
                if found:
                    logging.info(
                        "Telemetry hub resources already exist in Azure but not "
                        "in local state; the next build will adopt them instead "
                        "of creating duplicates."
                    )
            activity_enabled, activity_status, activity_warnings = False, "off", []
            if cfg.activity_log:
                activity_enabled, activity_status, activity_warnings = \
                    self._activity_cap_and_duplicates(resolved)
        except AzureRestError as e:
            if e.status == 0:
                warning = (
                    f"Could not obtain an Azure token to preview the telemetry "
                    f"hub ({e}); showing the offline plan only."
                )
                logging.warning(warning)
                return HubResult(
                    workspace_id=resolved.effective_destination,
                    managed=cfg.byo_workspace_id is None,
                    workspace_name="", location="", notes=[], warnings=[warning],
                    activity_log="off",
                )
            raise HubError(f"Could not reach Azure to preview the telemetry hub: {e}")

        tfvars = self._tfvars(resolved, activity_enabled)
        self.tf.write_terraform_vars(tfvars)

        return_code, stdout, stderr = self.tf.init()
        if return_code != 0:
            raise HubError(f"Telemetry hub `terraform init` failed: {stderr or stdout}")

        return_code, stdout, stderr = self.tf.plan()
        if return_code != 0:
            raise HubError(f"Telemetry hub `terraform plan` failed: {stderr or stdout}")

        if cfg.byo_workspace_id:
            workspace_name = (byo_info or {}).get("name") or cfg.byo_workspace_id.rsplit("/", 1)[-1]
            location = (byo_info or {}).get("location") or ""
        else:
            workspace_name = telemetry.managed_workspace_id(self.subscription_id).rsplit("/", 1)[-1]
            location = resolved.location

        return HubResult(
            workspace_id=resolved.effective_destination,
            managed=cfg.byo_workspace_id is None,
            workspace_name=workspace_name,
            location=location,
            notes=[],
            warnings=activity_warnings,
            activity_log=activity_status,
        )

    def destroy(self, confirm: Callable[[str], bool]) -> bool:
        """Remove the telemetry hub: the managed workspace (if any) and
        BadZure's own Activity Log export. A BYO destination workspace is never
        touched, only BadZure's own settings on it. Returns True when nothing
        is left standing afterwards (including "there was nothing to do"),
        False when the operator declined the confirmation."""
        hub_settings = self._load_hub_settings()
        subscription_id = hub_settings.get("subscription_id") or os.environ.get(ENV_SUBSCRIPTION_ID)
        if not subscription_id:
            logging.info(
                "No BadZure telemetry hub found on this machine. Set "
                f"{ENV_SUBSCRIPTION_ID} to remove one created elsewhere."
            )
            return True
        self.subscription_id = subscription_id

        destination_workspace_id = hub_settings.get("destination_workspace_id") or ""
        effective_destination = destination_workspace_id or telemetry.managed_workspace_id(subscription_id)
        suffix = telemetry.setting_suffix(effective_destination)

        state = self.tf.state_list()
        found: List[Tuple[str, str, dict]] = []
        if not state:
            try:
                found = self._discover(check_managed=True, activity_suffix=suffix)
            except AzureRestError as e:
                logging.warning(f"Could not check Azure for an existing telemetry hub: {e}")
                found = []

        if not state and not found:
            logging.info("No BadZure telemetry hub found.")
            return True

        managed_present = (
            any(s.startswith("azurerm_log_analytics_workspace.hub") for s in state)
            or any(a.startswith("azurerm_log_analytics_workspace.hub") for a, _, _ in found)
        )
        activity_present = (
            any(s.startswith("azurerm_monitor_diagnostic_setting.activity") for s in state)
            or any(a.startswith("azurerm_monitor_diagnostic_setting.activity") for a, _, _ in found)
        )
        activity_name = f"badzure-activity-{suffix}"

        text = self._confirmation_text(subscription_id, destination_workspace_id,
                                        managed_present, activity_present, activity_name)
        if not confirm(text):
            return False

        # create_managed_workspace / activity_log_enabled are written True
        # unconditionally here: `terraform destroy` only ever removes what is
        # already in state, it never creates, so these gates only matter for
        # letting the imports below find a matching instance to import into.
        tfvars = {
            "subscription_id": subscription_id,
            "create_managed_workspace": True,
            "workspace_name": telemetry.managed_workspace_id(subscription_id).rsplit("/", 1)[-1],
            "location": telemetry.DEFAULT_LOCATION,
            "retention_days": telemetry.DEFAULT_RETENTION_DAYS,
            "daily_cap_gb": telemetry.DEFAULT_DAILY_CAP_GB,
            "destination_workspace_id": destination_workspace_id,
            "activity_log_enabled": True,
            "activity_log_categories": list(ACTIVITY_LOG_CATEGORIES),
            "setting_suffix": suffix,
        }
        self.tf.write_terraform_vars(tfvars)

        return_code, stdout, stderr = self.tf.init()
        if return_code != 0:
            raise HubError(f"Telemetry hub `terraform init` failed: {stderr or stdout}")

        for address, resource_id, _ in found:
            return_code, stdout, stderr = self.tf.import_resource(address, resource_id)
            if return_code != 0:
                raise HubError(
                    f"Telemetry hub could not adopt existing resource {resource_id} "
                    f"into {address}: {stderr or stdout}"
                )

        return_code, stdout, stderr = self.tf.destroy()
        if return_code != 0:
            raise HubError(f"Telemetry hub `terraform destroy` failed: {stderr or stdout}")

        self.tf.cleanup_state_files()
        self._remove_hub_settings()
        logging.info("Telemetry hub destroyed.")
        return True

    def known_entra_settings(self) -> List[str]:
        """Every Entra diagnostic setting name BadZure has created, so
        `destroy --telemetry` can remove all of them and a build can warn about
        one left over from an earlier destination."""
        return list(self._load_hub_settings().get("entra_settings", []))

    def record_entra_setting(self, name: str) -> None:
        """Append `name` to the known Entra settings list, no duplicates."""
        hub_settings = self._load_hub_settings()
        settings = hub_settings.setdefault("entra_settings", [])
        if name not in settings:
            settings.append(name)
        self._save_hub_settings(hub_settings)

    # -- Resolution -------------------------------------------------------
    def _resolve_inputs(self, cfg: TelemetryConfig, hub_settings: dict) -> _ResolvedInputs:
        ws = cfg.workspace_settings
        location = ws.location or telemetry.DEFAULT_LOCATION
        retention_days = ws.retention_days or telemetry.DEFAULT_RETENTION_DAYS
        if ws.daily_cap_explicit and ws.daily_cap_gb is None:
            daily_cap_gb = -1   # the provider's value for "no cap"
        else:
            daily_cap_gb = ws.daily_cap_gb if ws.daily_cap_gb is not None else telemetry.DEFAULT_DAILY_CAP_GB

        destination_workspace_id = cfg.byo_workspace_id or ""
        # A later BYO config must keep an already-created managed workspace
        # around (Terraform would otherwise plan to destroy the evidence);
        # only `destroy --telemetry` removes it.
        create_managed_workspace = (
            cfg.byo_workspace_id is None or bool(hub_settings.get("keep_managed_workspace"))
        )
        effective_destination = destination_workspace_id or telemetry.managed_workspace_id(self.subscription_id)
        suffix = telemetry.setting_suffix(effective_destination)

        return _ResolvedInputs(
            location=location, retention_days=retention_days, daily_cap_gb=daily_cap_gb,
            destination_workspace_id=destination_workspace_id,
            create_managed_workspace=create_managed_workspace,
            effective_destination=effective_destination, suffix=suffix,
        )

    def _tfvars(self, resolved: _ResolvedInputs, activity_log_enabled: bool) -> dict:
        return {
            "subscription_id": self.subscription_id,
            "create_managed_workspace": resolved.create_managed_workspace,
            "workspace_name": telemetry.managed_workspace_id(self.subscription_id).rsplit("/", 1)[-1],
            "location": resolved.location,
            "retention_days": resolved.retention_days,
            "daily_cap_gb": resolved.daily_cap_gb,
            "destination_workspace_id": resolved.destination_workspace_id,
            "activity_log_enabled": activity_log_enabled,
            "activity_log_categories": list(ACTIVITY_LOG_CATEGORIES),
            "setting_suffix": resolved.suffix,
        }

    # -- Azure reads --------------------------------------------------------
    def _verify_byo(self, workspace_id: str) -> dict:
        try:
            resp = self.rest.get(workspace_id, WORKSPACE_API_VERSION)
        except AzureRestError as e:
            if e.status == 0:
                raise   # credential problem: caller decides (ensure = fatal, preview = degrade)
            if e.status == 403:
                raise HubError(
                    f"No permission to read workspace {workspace_id}. Grant the "
                    f"current credential Log Analytics Contributor on the "
                    f"workspace, then retry."
                )
            raise HubError(f"Could not verify workspace {workspace_id}: {e}")
        if resp is None:
            raise HubError(
                f"Workspace {workspace_id} not found or not visible to the "
                f"current credential."
            )
        return resp

    def _discover(self, check_managed: bool,
                  activity_suffix: Optional[str]) -> List[Tuple[str, str, dict]]:
        """GET the hub's deterministic resource IDs (never anything else) and
        return (terraform_address, azure_id, body) for whichever already exist,
        so a caller with an empty state can import them instead of planning to
        create duplicates. `activity_suffix` is the setting_suffix for the
        destination this call cares about; None skips the activity lookup."""
        found: List[Tuple[str, str, dict]] = []
        if check_managed:
            rg_id = f"/subscriptions/{self.subscription_id}/resourceGroups/{TELEMETRY_HUB_RG}"
            rg = self.rest.get(rg_id, RG_API_VERSION)
            if rg is not None:
                found.append(("azurerm_resource_group.hub[0]", rg_id, rg))

            ws_id = telemetry.managed_workspace_id(self.subscription_id)
            ws = self.rest.get(ws_id, WORKSPACE_API_VERSION)
            if ws is not None:
                found.append(("azurerm_log_analytics_workspace.hub[0]", ws_id, ws))
                audit_url = (f"{ws_id}/providers/Microsoft.Insights/diagnosticSettings/"
                            f"{TELEMETRY_DIAG_SETTING_NAME}")
                audit = self.rest.get(audit_url, DIAG_API_VERSION)
                if audit is not None:
                    found.append((
                        "azurerm_monitor_diagnostic_setting.workspace_audit[0]",
                        f"{ws_id}|{TELEMETRY_DIAG_SETTING_NAME}", audit,
                    ))

        if activity_suffix is not None:
            activity_name = f"badzure-activity-{activity_suffix}"
            activity_target = f"/subscriptions/{self.subscription_id}"
            activity_url = (f"{activity_target}/providers/Microsoft.Insights/"
                            f"diagnosticSettings/{activity_name}")
            activity = self.rest.get(activity_url, DIAG_API_VERSION)
            if activity is not None:
                found.append((
                    "azurerm_monitor_diagnostic_setting.activity[0]",
                    f"{activity_target}|{activity_name}", activity,
                ))
        return found

    def _activity_cap_and_duplicates(self, resolved: _ResolvedInputs) -> Tuple[bool, str, List[str]]:
        """Read every Activity Log export on the subscription (never modify
        one) and decide: is BadZure's own export capped out (the tenant allows
        only 5), and does anything else already point at our destination.
        Returns (enabled_this_build, status, warnings)."""
        warnings: List[str] = []
        our_name = f"badzure-activity-{resolved.suffix}"
        list_url = f"/subscriptions/{self.subscription_id}/providers/Microsoft.Insights/diagnosticSettings"
        resp = self.rest.get(list_url, DIAG_API_VERSION)
        settings = (resp or {}).get("value", [])
        ours_exists = any(s.get("name") == our_name for s in settings)

        for s in settings:
            name = s.get("name")
            if name == our_name:
                continue
            workspace_id = (s.get("properties") or {}).get("workspaceId") or ""
            if workspace_id and workspace_id.lower() == resolved.effective_destination.lower():
                warnings.append(
                    f'existing export "{name}" already sends to '
                    f"{resolved.effective_destination}. Recommended: set activity_log: false."
                )

        if not ours_exists and len(settings) >= 5:
            names = ", ".join(sorted(s.get("name", "?") for s in settings))
            warnings.append(
                f"the tenant's 5 Activity Log export slots are already used "
                f"({names}); skipping BadZure's own export for this build."
            )
            return False, "skipped_cap", warnings

        return True, ("exists" if ours_exists else "created"), warnings

    def _diff_notes(self, cfg: TelemetryConfig, resolved: _ResolvedInputs, outputs: Dict) -> List[str]:
        """Notes for settings the config asked for EXPLICITLY that differ from
        what the (already-existing) managed workspace actually has. Omitted
        settings never produce a note; BYO workspaces are never compared."""
        if not resolved.create_managed_workspace:
            return []
        notes: List[str] = []
        ws = cfg.workspace_settings

        live_location = outputs.get("workspace_location")
        if ws.location is not None and live_location and ws.location != live_location:
            notes.append(
                f"location {ws.location} ignored: the workspace already exists "
                f"in {live_location}. Change it in the Azure portal."
            )

        live_retention = outputs.get("workspace_retention_days")
        if (ws.retention_days is not None and live_retention is not None
                and ws.retention_days != live_retention):
            notes.append(
                f"retention_days {ws.retention_days} ignored: the workspace "
                f"already exists with {live_retention} days. Change it in the "
                f"Azure portal."
            )

        if ws.daily_cap_explicit:
            requested = -1 if ws.daily_cap_gb is None else ws.daily_cap_gb
            live_cap = outputs.get("workspace_daily_cap_gb")
            if live_cap is not None and live_cap != requested:
                req_text = "no cap" if requested == -1 else f"{_fmt_gb(requested)} GB"
                live_text = "no cap" if live_cap == -1 else f"{_fmt_gb(live_cap)} GB"
                notes.append(
                    f"daily_cap_gb {req_text} ignored: the workspace already "
                    f"exists with {live_text}. Change it in the Azure portal."
                )
        return notes

    def _confirmation_text(self, subscription_id: str, destination_workspace_id: str,
                           managed_present: bool, activity_present: bool,
                           activity_name: str) -> str:
        lines = ["This will permanently remove BadZure's telemetry hub:"]
        if managed_present:
            name = telemetry.managed_workspace_id(subscription_id).rsplit("/", 1)[-1]
            lines.append(
                f"  Managed workspace {name}: all collected telemetry is "
                f"permanently deleted, no soft delete."
            )
        if activity_present:
            lines.append(f"  Activity Log export {activity_name}: removed.")
        if destination_workspace_id:
            byo_name = destination_workspace_id.rsplit("/", 1)[-1]
            lines.append(
                f"  Your workspace {byo_name} is not touched; only BadZure's "
                f"own settings are removed."
            )
        return "\n".join(lines)

    # -- Local bookkeeping files --------------------------------------------
    def _hub_settings_path(self) -> str:
        return os.path.join(self.hub_dir, "hub_settings.json")

    def _load_hub_settings(self) -> dict:
        path = self._hub_settings_path()
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            logging.warning(f"{path} is corrupt; treating the telemetry hub as unconfigured.")
            return {}

    def _save_hub_settings(self, data: dict) -> None:
        path = self._hub_settings_path()
        os.makedirs(self.hub_dir, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)

    def _remove_hub_settings(self) -> None:
        try:
            os.remove(self._hub_settings_path())
        except FileNotFoundError:
            pass


def _fmt_gb(n) -> str:
    n = float(n)
    return str(int(n)) if n.is_integer() else str(n)
