"""
CLI command handlers for BadZure.
Implements build, show, and destroy commands.
"""
import os
import logging
import time
import json
import tempfile
import webbrowser
from pathlib import Path
from typing import Dict, Optional
import yaml
from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.terraform_manager import TerraformManager, TerraformNotFoundError
from src.output_formatter import OutputFormatter
from src.terraform_builder import build_tfvars
from src.scenario_loader import ScenarioLoader
from src import reachability
from src import graph_builder
from src import name_uniquifier
from src.reporting import (
    assemble_report_model,
    build_attack_projections,
    build_environment_graphs,
    build_posture_panels,
    render_report,
)
import src.dataplane as dataplane
import src.utils as utils
from src.constants import WEBAPP_FOOTHOLD_VECTORS


class BuildCommand:
    """Handles the build command to create misconfigured tenants."""
    
    def __init__(self):
        self.config_mgr = ConfigManager()
        self.generator = EntityGenerator()
        self.terraform_mgr = TerraformManager()
        self.output_formatter = OutputFormatter()
    
    def execute(self, config_file: str, verbose: bool = False) -> None:
        """Execute the build. BadZure has ONE config shape now — the declarative
        graph IR. A retired legacy `mode:`/`privilege_escalation:` config is rejected
        with guidance to convert it.

        Args:
            config_file: Path to configuration file
            verbose: Enable verbose output
        """
        try:
            TerraformManager.ensure_installed()
        except TerraformNotFoundError as e:
            logging.error(str(e))
            return

        logging.info(f"Loading BadZure configuration from {config_file}")
        config = self.config_mgr.load_config(config_file)

        if self._is_legacy_config(config):
            logging.error(
                "This is a legacy 'mode:'/'privilege_escalation:' config, which is no "
                "longer supported. Convert it to the declarative shape (baseline: + "
                "attack_paths: with `technique:` sugar or an explicit `assignments:` "
                "graph). See badzure.yml and docs/configuration.md."
            )
            return

        # Make globally-unique Azure resource names (storage/cosmos/web-app/etc.) unique
        # BEFORE any deploy step, so a name clash can never reach `terraform apply`. This
        # is idempotent (a config already marked `uniquified: true` passes through
        # untouched), so it is safe whether or not the operator ran `uniquify` first —
        # the same reason the reachability gate runs here in code rather than trusting a
        # prior step. The result is persisted so the file, Terraform state and Azure all
        # agree, and a retry re-deploys the SAME names instead of orphaning the first.
        config = self._ensure_uniquified(config, config_file)

        # Code-enforced reachability gate (offline, BEFORE any network/Azure call):
        # build proves for ITSELF that every attack path is reachable and refuses to
        # create a tenant otherwise. It does not trust an upstream agent's claim that
        # the path was verified — the deterministic gate is the only authority.
        self._reachability_gate(config_file)

        self._build_declarative_mode(config, verbose)

    def _ensure_uniquified(self, config: Dict, config_file: str) -> Dict:
        """Ensure the config's globally-unique resource names are suffixed, persisting
        the result back to `config_file`. Idempotent: a config already carrying the
        `uniquified: true` marker is returned unchanged and the file is left alone.

        Persisting matters: it stamps the marker (so a rebuild reuses the SAME names
        rather than minting new ones and orphaning the first deploy) and keeps the file
        the operator sees in sync with what actually deploys."""
        new_config, rename = name_uniquifier.uniquify_config(config)
        if rename:
            with open(config_file, "w", encoding="utf-8") as f:
                yaml.safe_dump(new_config, f, sort_keys=False,
                               default_flow_style=False, width=100)
            logging.info(
                f"Made {len(rename)} globally-unique resource name(s) unique and marked "
                f"'{config_file}' as uniquified (so a rebuild reuses these names).")
        return new_config

    def _reachability_gate(self, config_file: str) -> None:
        """Refuse to deploy a config whose attack path isn't provably reachable.

        Runs the SAME deterministic verdict as `badzure check` (offline, no Azure),
        so build gates on exactly what the Gatekeeper reports — but verifies it here,
        in code, rather than relying on any subagent's word. On an unreachable (exit 1)
        or invalid (exit 2) config it logs a loud refusal and aborts with that exit
        code; a reachable or baseline-only config (exit 0) passes through silently.
        """
        logging.info("Verifying attack-path reachability before deploy (offline gate)...")
        code = CheckCommand().execute(config_file)
        if code == 0:
            return
        logging.error("=" * 60)
        if code == 1:
            logging.error("REFUSING TO DEPLOY - an attack path is NOT reachable.")
            logging.error(
                "BadZure will not create a tenant for a path it cannot prove traversable. "
                "Repair the failing hop shown above and retry; nothing was created."
            )
        else:
            logging.error("REFUSING TO DEPLOY - the config is invalid (see the error above). "
                          "Nothing was created.")
        logging.error("=" * 60)
        raise SystemExit(code)

    # Tenant-level entity-count keys that only the retired legacy shape used (the
    # declarative shape puts these under `baseline:`).
    _LEGACY_TENANT_COUNT_KEYS = (
        'users', 'applications', 'groups', 'administrative_units', 'resource_groups',
        'key_vaults', 'storage_accounts', 'virtual_machines', 'logic_apps',
        'automation_accounts', 'function_apps', 'app_services', 'cosmos_dbs',
    )

    @classmethod
    def _is_legacy_config(cls, config: Dict) -> bool:
        """Detect a retired legacy `mode:` config to reject it with guidance. The only
        markers absent from the declarative shape are a top-level `mode:` or `tenant:`
        entity COUNTS (the declarative shape puts counts under `baseline:`). NOTE:
        `privilege_escalation:` AND `enabled:` are both valid in the new shape, so
        neither is a discriminator."""
        if not isinstance(config, dict):
            return False
        if config.get('mode') in ('random', 'targeted'):
            return True
        tenant = config.get('tenant')
        if isinstance(tenant, dict) and any(k in tenant for k in cls._LEGACY_TENANT_COUNT_KEYS):
            return True
        return False

    # ------------------------------------------------------------------
    # Phase 3: declarative graph config -> generic primitives -> deploy.
    # Unlike the legacy paths, EVERYTHING here is generic, so we build the
    # DeploymentModel via the scenario loader and call build_tfvars directly
    # (no legacy-splice needed — legacy assignment variables default to {}).
    # ------------------------------------------------------------------
    def _build_declarative_mode(self, config: Dict, verbose: bool) -> None:
        """Build from a declarative graph config (Phase 3, Slice 1)."""
        start_time = time.time()

        azure_config_dir = os.path.expanduser('~/.azure')
        os.environ['AZURE_CONFIG_DIR'] = azure_config_dir

        # Resolve tenant config with environment variable fallback
        try:
            tenant_id, domain, subscription_id = self.config_mgr.resolve_tenant_config(config)
        except ValueError as e:
            logging.error(str(e))
            return

        public_ip = utils.get_public_ip()

        # Parse the declarative config into a deployable DeploymentModel.
        logging.info("Compiling declarative attack paths into generic primitives")
        loader = ScenarioLoader(self.generator)
        try:
            scenario = loader.load(
                config, tenant_id, domain, subscription_id,
                public_ip, azure_config_dir,
            )
        except ValueError as e:
            logging.error(f"Declarative config error: {e}")
            return

        model = scenario.model
        for overlay in scenario.attack_paths:
            logging.info(f"Compiled attack path '{overlay.name}'")

        # Everything is generic — produce the full tfvars directly.
        try:
            tf_vars = build_tfvars(model)
        except ValueError as e:
            logging.error(f"Failed to build Terraform variables: {e}")
            return
        self.terraform_mgr.write_terraform_vars(tf_vars)

        # Execute Terraform
        logging.info("Calling terraform init")
        return_code, stdout, stderr = self.terraform_mgr.init()
        if return_code != 0:
            logging.error(f"Terraform init failed: {stderr}")
            if verbose:
                logging.error(stdout)
                logging.error(stderr)
            return

        logging.info("Calling terraform apply to create resources, this may take several minutes ...")
        return_code, stdout, stderr = self.terraform_mgr.apply(verbose)
        if return_code != 0:
            logging.error(f"Terraform apply failed: {stderr}")
            if verbose:
                logging.error(stdout)
                logging.error(stderr)
            return

        # Read Terraform outputs once, then use them for both the SP-secret
        # read-back and the post-apply data-plane phase.
        outputs = self.terraform_mgr.get_outputs()

        # Surface SP secrets minted via the generic layer (same read-back the
        # Phase-2 macro path uses).
        user_creds = {ov.name: ov.credentials for ov in scenario.attack_paths}
        self._apply_generic_sp_credentials(user_creds, outputs)
        self._apply_foothold_access(user_creds, outputs)

        # Post-apply data-plane phase: plant injects Terraform can't (cosmos_document
        # today). Warn-and-continue — failures don't abort the build.
        self._inject_dataplane(model, outputs)

        logging.info("Azure AD tenant setup completed with assigned permissions and configurations!")
        self.output_formatter.write_users_file(model.users, domain)
        self.output_formatter.format_declarative_paths(scenario.attack_paths, user_creds, domain)

        # Display deployment statistics
        elapsed_time = time.time() - start_time
        self._display_deployment_stats(
            elapsed_time, model.users, model.groups, model.applications,
            model.administrative_units, model.resource_groups, model.key_vaults,
            model.storage_accounts, model.virtual_machines, model.logic_apps,
            model.automation_accounts, model.function_apps, model.cosmos_dbs,
            primitives=model.primitives, app_services=model.app_services
        )

        logging.info("Good bye.")

    def _apply_generic_sp_credentials(self, user_creds: Dict, outputs: Dict) -> None:
        """Read SP secrets minted via the generic layer back into user_creds.

        Initial-access service principals get their secret from the
        generic_app_credentials TF output (keyed by the origin-prefixed
        credential key the macro recorded as 'generic_credential_key').
        """
        needed = {ap: c['generic_credential_key']
                  for ap, c in user_creds.items() if c.get('generic_credential_key')}
        if not needed:
            return
        generic_creds = outputs.get('generic_app_credentials', {})
        for ap_name, cred_key in needed.items():
            entry = generic_creds.get(cred_key)
            if entry:
                user_creds[ap_name]['client_id'] = entry.get('client_id')
                user_creds[ap_name]['client_secret'] = entry.get('client_secret')

    def _apply_foothold_access(self, user_creds: Dict, outputs: Dict) -> None:
        """Fill resource-seed foothold paths' operator artifacts from the post-apply
        Terraform outputs (the public IP/URL is only known after apply). Exposed-host
        footholds read vm_foothold_access (public IP + admin creds); vulnerable-web-app
        footholds read app_service_foothold_access (the public URL + vuln endpoint).
        Both are keyed by the foothold_resource the loader/macro recorded."""
        needed = {name: c['foothold_resource']
                  for name, c in user_creds.items() if c.get('foothold_resource')}
        if not needed:
            return
        vm_foothold = outputs.get('vm_foothold_access', {})
        webapp_foothold = outputs.get('app_service_foothold_access', {})
        for name, ref in needed.items():
            if user_creds[name].get('initial_access') in WEBAPP_FOOTHOLD_VECTORS:
                entry = webapp_foothold.get(ref)
                if entry:
                    user_creds[name].update({
                        'app_service_url': entry.get('url'),
                        'vuln_path': entry.get('vuln_path'),
                    })
                continue
            entry = vm_foothold.get(ref)
            if entry:
                user_creds[name].update({
                    'public_ip': entry.get('public_ip'),
                    'admin_username': entry.get('admin_username'),
                    'admin_password': entry.get('admin_password'),
                    'os_type': entry.get('os_type'),
                    'expose_to_internet': entry.get('expose_to_internet'),
                })

    def _inject_dataplane(self, model, outputs: Dict) -> None:
        """Run the post-apply data-plane phase: plant injects Terraform can't
        deploy (cosmos_document today) by calling the data-plane APIs directly,
        using values read from the Terraform outputs."""
        items = dataplane.collect_dataplane_injects(model)
        if not items:
            return
        logging.info(f"Planting {len(items)} data-plane inject(s) after apply")
        result = dataplane.execute(
            items, outputs, model, self.terraform_mgr.terraform_dir)
        if result.failures:
            logging.warning(
                f"Data-plane phase: {result.planted} planted, "
                f"{len(result.failures)} failed:")
            for line in result.failures:
                logging.warning(f"  - {line}")
        else:
            logging.info(f"Data-plane phase: {result.planted} inject(s) planted")

    # Building-block class name -> human label, in display order. AppCredential /
    # DataInject aren't "assignments" but they ARE deployed edges/material, so we
    # surface them in the same block.
    _ASSIGNMENT_LABELS = (
        ("GroupMembership", "Group Memberships"),
        ("GroupOwnership", "Group Ownerships"),
        ("AppOwnership", "App Ownerships"),
        ("AuMembership", "AU Memberships"),
        ("EntraRoleAssignment", "Entra Role Assignments"),
        ("AzureRbacAssignment", "Azure RBAC Assignments"),
        ("ApiPermission", "API Permissions"),
        ("AppCredential", "App Credentials"),
        ("DataInject", "Data Injects"),
    )

    def _display_deployment_stats(self, elapsed_time: float, users: Dict, groups: Dict,
                                   applications: Dict, administrative_units: Dict,
                                   resource_groups: Dict, key_vaults: Dict,
                                   storage_accounts: Dict, virtual_machines: Dict, logic_apps: Dict,
                                   automation_accounts: Dict, function_apps: Dict,
                                   cosmos_dbs: Dict = None, primitives: list = None,
                                   app_services: Dict = None) -> None:
        """Display deployment statistics summary. When `primitives` is provided (the
        declarative path, where they are the complete picture), also break down the
        deployed assignments by type and origin."""
        cosmos_dbs = cosmos_dbs or {}
        app_services = app_services or {}
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)

        total_identities = len(users) + len(groups) + len(applications) + len(administrative_units)
        total_resources = len(resource_groups) + len(key_vaults) + len(storage_accounts) + len(virtual_machines) + len(logic_apps) + len(automation_accounts) + len(function_apps) + len(app_services) + len(cosmos_dbs)

        logging.info("")
        logging.info("=" * 70)
        logging.info("DEPLOYMENT STATISTICS")
        logging.info("=" * 70)
        logging.info(f"Total deployment time: {minutes}m {seconds}s")
        logging.info(f"Total identities created: {total_identities}")
        logging.info(f"  - Users: {len(users)}")
        logging.info(f"  - Groups: {len(groups)}")
        logging.info(f"  - Applications: {len(applications)}")
        logging.info(f"  - Administrative Units: {len(administrative_units)}")
        logging.info(f"Total Azure resources created: {total_resources}")
        logging.info(f"  - Resource Groups: {len(resource_groups)}")
        logging.info(f"  - Key Vaults: {len(key_vaults)}")
        logging.info(f"  - Storage Accounts: {len(storage_accounts)}")
        logging.info(f"  - Virtual Machines: {len(virtual_machines)}")
        logging.info(f"  - Logic Apps: {len(logic_apps)}")
        logging.info(f"  - Automation Accounts: {len(automation_accounts)}")
        logging.info(f"  - Function Apps: {len(function_apps)}")
        logging.info(f"  - App Services: {len(app_services)}")
        logging.info(f"  - Cosmos DB Accounts: {len(cosmos_dbs)}")

        if primitives:
            counts = {}
            origins = {"random": 0, "attack_path": 0}
            for p in primitives:
                counts[type(p).__name__] = counts.get(type(p).__name__, 0) + 1
                origins[getattr(p, "origin", "random")] = \
                    origins.get(getattr(p, "origin", "random"), 0) + 1
            total = len(primitives)
            logging.info(
                f"Total assignments created: {total} "
                f"(baseline: {origins.get('random', 0)}, "
                f"attack-path: {origins.get('attack_path', 0)})")
            for cls_name, label in self._ASSIGNMENT_LABELS:
                if counts.get(cls_name):
                    logging.info(f"  - {label}: {counts[cls_name]}")

        logging.info("=" * 70)
        logging.info("")


class CheckCommand:
    """Handles `check`: compile a declarative config and report attack-path
    reachability WITHOUT deploying (no Terraform, no Azure). This is the Gatekeeper
    tool and the offline-preview for the agentic demo — see
    dev-docs/demo/agentic-badzure-plan.md (Phase 0).

    Exit codes: 0 = all paths reachable (or none), 1 = at least one unreachable,
    2 = config/compile error.
    """

    # Verdict markers mirror OutputFormatter._declarative_reachability's vocabulary.
    _MARKERS = {
        reachability.REACHED: '[reachable]',
        reachability.UNVERIFIED: '[unverified]',
        reachability.BLOCKED: '[UNREACHABLE]',
        reachability.INVALID: '[INVALID]',
    }

    def __init__(self):
        self.config_mgr = ConfigManager()
        self.generator = EntityGenerator()

    def execute(self, config_file: str, json_output: bool = False,
                verbose: bool = False) -> int:
        # In JSON mode keep stdout clean: silence the info-level log stream so the
        # only thing on stdout is the verdict object the Gatekeeper subagent parses.
        if json_output:
            logging.getLogger().setLevel(logging.WARNING)

        try:
            config = self.config_mgr.load_config(config_file)
        except (FileNotFoundError, yaml.YAMLError) as e:
            return self._fail(config_file, f"Could not load config: {e}", json_output)

        if not isinstance(config, dict) or BuildCommand._is_legacy_config(config):
            return self._fail(
                config_file,
                "Not a declarative config (legacy 'mode:' shape or invalid). Convert it "
                "to the baseline:/attack_paths: shape — see badzure.yml.",
                json_output)

        # Compile + run the reachability gate, but DO NOT enforce: an unreachable
        # path must be reported, not raised. Placeholder domain — `check` never deploys.
        loader = ScenarioLoader(self.generator)
        try:
            scenario = loader.load(config, domain="example.com",
                                   enforce_reachability=False)
        except ValueError as e:  # ScenarioConfigError / validation errors subclass ValueError
            return self._fail(config_file, f"Config error: {e}", json_output)

        # Structural/semantic PREFLIGHT: run the same builder validation `build` runs,
        # offline (no Azure). This catches deploy-breaking authoring errors — a bad
        # ref, a missing credential companion, an app_secret pointing at a certificate
        # credential, a certificate with no file, an impossible location/material combo
        # — BEFORE `apply`, so the Adversary self-repair loop + the Gatekeeper see them
        # here instead of 8 minutes into a terraform apply.
        try:
            build_tfvars(scenario.model)
        except ValueError as e:  # LabValidationError subclasses ValueError
            return self._fail(config_file, f"Config error: {e}", json_output)

        results = [self._verdict(ov) for ov in (scenario.attack_paths or [])]
        reachable = sum(1 for r in results if r['reachable'])
        unreachable = len(results) - reachable
        ok = unreachable == 0

        if json_output:
            print(json.dumps({
                "config": config_file,
                "ok": ok,
                "summary": {"total": len(results),
                            "reachable": reachable, "unreachable": unreachable},
                "paths": results,
            }, indent=2))
        else:
            self._render_human(config_file, results, reachable, unreachable, verbose)

        return 0 if ok else 1

    @staticmethod
    def _verdict(overlay) -> Dict:
        reach = overlay.reachability or {}
        status = reach.get('status')
        objective = overlay.objective or {}
        target = objective.get('role') or objective.get('target_ref')
        steps = [
            {"name": s.get('name'), "target_ref": s.get('target_ref'),
             "action": s.get('action')}
            for s in (overlay.steps or [])
        ]
        return {
            "name": overlay.name,
            "objective": {"name": objective.get('name'),
                          "capability": objective.get('capability'), "target": target,
                          "description": objective.get('description')},
            "status": status,
            "reachable": status in (reachability.REACHED, reachability.UNVERIFIED),
            "reason": reach.get('reason', ''),
            "steps": steps,
        }

    @classmethod
    def _render_human(cls, config_file, results, reachable, unreachable, verbose) -> None:
        logging.info(f"Checking declarative config: {config_file}  (offline - no Azure)")
        logging.info("=" * 60)
        if not results:
            logging.info("No attack paths to check (baseline-only config).")
            logging.info("=" * 60)
            return
        for r in results:
            log = logging.info if r['reachable'] else logging.error
            log(f"{r['name']}")
            obj_name = r['objective'].get('name')
            if obj_name:
                log(f"  Objective: {obj_name}")
            cap = r['objective'].get('capability')
            if cap:
                tgt = r['objective'].get('target')
                log(f"  Goal: {cap}" + (f" -> {tgt}" if tgt else ""))
            desc = r['objective'].get('description')
            if desc:
                log(f"  Narrative: {desc}")
            marker = cls._MARKERS.get(r['status'], r['status'] or '[unknown]')
            log(f"  Reachability: {marker} {r['reason']}".rstrip())
            log(f"  Steps: {len(r['steps'])}")
            if verbose:
                for i, s in enumerate(r['steps'], 1):
                    arrow = f" -> {s['target_ref']}" if s.get('target_ref') else ""
                    act = f" [{s['action']}]" if s.get('action') else ""
                    log(f"    {i}. {s.get('name', 'step')}{arrow}{act}")
        logging.info("=" * 60)
        summary = (f"{len(results)} path(s) checked: "
                   f"{reachable} reachable, {unreachable} unreachable.")
        (logging.info if unreachable == 0 else logging.error)(summary)

    @staticmethod
    def _fail(config_file: str, message: str, json_output: bool) -> int:
        if json_output:
            print(json.dumps({"config": config_file, "ok": False, "error": message},
                             indent=2))
        else:
            logging.error(message)
        return 2


class GraphCommand:
    """Handles `graph`: render a declarative config as offline Mermaid diagrams
    (identity / resources / attack) in a standalone HTML page, then open it. The
    human-in-the-loop REVIEW SURFACE for the agentic demo (Phase 2) — see
    dev-docs/demo/agentic-badzure-plan.md. No Terraform, no Azure.

    Exit codes: 0 = rendered, 2 = config/compile error.
    """

    _SECTIONS = {
        "identity": ("Identity / Org structure", "identity_mermaid"),
        "resources": ("Resources", "resource_mermaid"),
        "attack": ("Attack paths", "attack_mermaid"),
    }

    def __init__(self):
        self.config_mgr = ConfigManager()
        self.generator = EntityGenerator()

    def execute(self, config_file: str, view: str = "all", output: Optional[str] = None,
                open_browser: bool = True, verbose: bool = False) -> int:
        try:
            config = self.config_mgr.load_config(config_file)
        except (FileNotFoundError, yaml.YAMLError) as e:
            logging.error(f"Could not load config: {e}")
            return 2

        if not isinstance(config, dict) or BuildCommand._is_legacy_config(config):
            logging.error("Not a declarative config (legacy 'mode:' shape or invalid).")
            return 2

        loader = ScenarioLoader(self.generator)
        try:
            scenario = loader.load(config, domain="example.com",
                                   enforce_reachability=False)
        except ValueError as e:
            logging.error(f"Config error: {e}")
            return 2

        model = scenario.model
        overlays = scenario.attack_paths or []

        wanted = list(self._SECTIONS) if view == "all" else [view]
        sections = []
        for key in wanted:
            heading, fn = self._SECTIONS[key]
            if key == "attack":
                mermaid = graph_builder.attack_mermaid(overlays)
            else:
                mermaid = getattr(graph_builder, fn)(model)
            sections.append((heading, mermaid))

        title = f"BadZure lab: {os.path.basename(config_file)}"
        page = graph_builder.render_html(title, sections)

        if not output:
            base = os.path.splitext(os.path.basename(config_file))[0]
            output = f"{base}.graph.html"
        with open(output, "w", encoding="utf-8") as f:
            f.write(page)
        logging.info(f"Wrote graph to {output} ({', '.join(wanted)})")

        if open_browser:
            try:
                webbrowser.open(Path(output).resolve().as_uri())
            except Exception as e:  # noqa: BLE001 — opening a browser must never fail the command
                logging.warning(f"Could not open browser automatically: {e}")
        return 0


class ReportCommand:
    """Generate the supported comprehensive offline lab report.

    Exit codes: 0 = rendered, 2 = config/compile/projection/render/write error.
    """

    def __init__(self):
        self.config_mgr = ConfigManager()
        self.generator = EntityGenerator()

    def execute(self, config_file: str, output: Optional[str] = None,
                open_browser: bool = True, verbose: bool = False) -> int:
        try:
            config = self.config_mgr.load_config(config_file)
            if not isinstance(config, dict) or BuildCommand._is_legacy_config(config):
                raise ValueError(
                    "Not a declarative config (legacy 'mode:' shape or invalid)."
                )
            metadata = self.config_mgr.validate_report_config(config)
            scenario = ScenarioLoader(self.generator).load(
                config, domain="example.com", enforce_reachability=False,
            )

            environment = build_environment_graphs(scenario.model)
            posture_panels = build_posture_panels(
                scenario.model, scenario.attack_paths or [],
            )
            attack_projections = build_attack_projections(
                scenario.model, scenario.attack_paths or [],
            )
            title = metadata.get(
                'title', f"BadZure lab: {os.path.basename(config_file)}",
            )
            lab_description = metadata.get(
                'lab_description',
                self._lab_description(environment, len(scenario.attack_paths or [])),
            )
            organization_description = metadata.get(
                'organization_description', self._organization_description(environment),
            )
            report = assemble_report_model(
                title=title,
                source_config=config_file,
                environment=environment,
                posture_panels=posture_panels,
                attack_projections=attack_projections,
                lab_description=lab_description,
                organization_description=organization_description,
            )
            page = render_report(report)
        except (FileNotFoundError, yaml.YAMLError, ValueError) as e:
            logging.error(f"Could not generate report: {e}")
            return 2
        except Exception as e:  # projection/render failures share the CLI error contract
            logging.error(f"Could not generate report: {e}")
            return 2

        if not output:
            output = f"{Path(config_file).stem}.report.html"
        try:
            self._write_atomic(output, page)
        except OSError as e:
            logging.error(f"Could not write report to {output}: {e}")
            return 2

        logging.info(f"Wrote comprehensive report to {output}")
        if verbose:
            logging.info(
                f"Rendered {len(report.panels)} graph panel(s) and "
                f"{len(report.paths)} attack path narrative(s)."
            )

        if open_browser:
            try:
                opened = webbrowser.open(Path(output).resolve().as_uri())
                if not opened:
                    logging.warning("Could not open browser automatically.")
            except Exception as e:  # browser launch is never report failure
                logging.warning(f"Could not open browser automatically: {e}")
        return 0

    @staticmethod
    def _write_atomic(output: str, page: str) -> None:
        destination = Path(output)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp",
            dir=str(destination.parent or Path('.')),
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(page)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _lab_description(environment, path_count: int) -> str:
        inventory = environment.inventory
        resources = sum(len(rows) for key, rows in inventory.items()
                        if key not in {'users', 'groups', 'applications',
                                      'administrative_units'})
        return (
            f"This lab contains {resources} Azure resource(s), "
            f"{len(environment.assignment_details)} assignment(s), and "
            f"{path_count} enabled attack path(s)."
        )

    @staticmethod
    def _organization_description(environment) -> str:
        inventory = environment.inventory
        return (
            f"The organization contains {len(inventory.get('users', []))} user(s), "
            f"{len(inventory.get('groups', []))} group(s), "
            f"{len(inventory.get('applications', []))} service principal(s), and "
            f"{len(inventory.get('administrative_units', []))} administrative unit(s)."
        )


class UniquifyCommand:
    """Handles `uniquify`: rewrite globally-unique Azure resource names (key vaults,
    storage, cosmos, function apps, app services) with a short suffix so a generated
    config builds first-try on a real tenant (Phase 3a). Pure config transform — no
    Terraform, no Azure.

    Exit codes: 0 = rewritten (or nothing to do), 2 = config/load error.
    """

    def __init__(self):
        self.config_mgr = ConfigManager()

    def execute(self, config_file: str, output: Optional[str] = None,
                suffix: Optional[str] = None, verbose: bool = False) -> int:
        try:
            config = self.config_mgr.load_config(config_file)
        except (FileNotFoundError, yaml.YAMLError) as e:
            logging.error(f"Could not load config: {e}")
            return 2
        if not isinstance(config, dict):
            logging.error("Config is not a valid YAML mapping.")
            return 2

        new_config, rename = name_uniquifier.uniquify_config(config, suffix=suffix)
        out_path = output or config_file
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(new_config, f, sort_keys=False, default_flow_style=False,
                           width=100)

        if rename:
            logging.info(f"Uniquified {len(rename)} globally-unique resource name(s) "
                         f"-> {out_path}")
            if verbose:
                for old, new in rename.items():
                    logging.info(f"  {old} -> {new}")
        else:
            logging.info(f"No globally-unique resource names to rewrite -> {out_path}")
        return 0


class ShowCommand:
    """Handles the show command to display created resources."""
    
    def __init__(self):
        self.terraform_mgr = TerraformManager()
    
    def execute(self, verbose: bool = False) -> None:
        """
        Execute the show command.
        
        Args:
            verbose: Enable verbose output
        """
        try:
            TerraformManager.ensure_installed()
        except TerraformNotFoundError as e:
            logging.error(str(e))
            return

        # Initialize Terraform
        return_code, stdout, stderr = self.terraform_mgr.init()
        if return_code != 0:
            logging.error(f"Terraform init failed: {stderr}")
            return

        logging.info("Calling terraform show to display the current state ...")
        
        # Execute terraform show
        return_code, stdout, stderr = self.terraform_mgr.show(verbose)
        
        if return_code != 0:
            logging.error(f"Terraform show failed: {stderr}")
            logging.error(stdout)
            logging.error(stderr)
            return
        
        if verbose:
            print(stdout)
        else:
            resources = self.terraform_mgr.parse_terraform_output(stdout)
            for resource in resources:
                logging.info(resource)
        
        logging.info("Current state of Azure AD tenant resources displayed successfully.")


class DestroyCommand:
    """Handles the destroy command to remove all created resources."""
    
    def __init__(self):
        self.terraform_mgr = TerraformManager()
    
    def execute(self, verbose: bool = False) -> None:
        """
        Execute the destroy command.
        
        Args:
            verbose: Enable verbose output
        """
        try:
            TerraformManager.ensure_installed()
        except TerraformNotFoundError as e:
            logging.error(str(e))
            return

        # Initialize Terraform
        return_code, stdout, stderr = self.terraform_mgr.init()
        if return_code != 0:
            logging.error(f"Terraform init failed: {stderr}")
            return

        logging.info("Calling terraform destroy, this may take several minutes ...")
        return_code, stdout, stderr = self.terraform_mgr.destroy(verbose)
        
        if return_code != 0:
            logging.error(f"Terraform apply failed: {stderr}")
            logging.error(stdout)
            logging.error(stderr)
            return
        
        logging.info("Azure AD tenant resources have been successfully destroyed!")

        # Cleanup state files
        self.terraform_mgr.cleanup_state_files()

        logging.info("Good bye.")


class GenerateCommand:
    """Handles `generate`: author a declarative config from natural language via an LLM,
    write it to disk for REVIEW, then deploy with `build`.

    `--prompt` authors the baseline org (OrgGenerator); `--attack-prompt` (+ optional
    `--input` to extend an existing config) authors a reachability-verified attack path
    into it (AttackPathGenerator). Either or both may be given.
    """

    def __init__(self):
        self.config_mgr = ConfigManager()
        self.generator = EntityGenerator()

    def execute(self, prompt: Optional[str] = None, attack_prompt: Optional[str] = None,
                input_config: Optional[str] = None, output: str = "generated.yml",
                model: Optional[str] = None, verbose: bool = False) -> None:
        if not prompt and not attack_prompt:
            logging.error("Provide --prompt (org baseline) and/or --attack-prompt "
                          "(attack path, with --input an existing config).")
            return

        # Resolve LLM settings (CLI --model > env > config llm: block).
        try:
            llm = self.config_mgr.resolve_llm_config(model_override=model)
        except ValueError as e:
            logging.error(str(e))
            return

        # Lazy imports: keep build/show/destroy free of the LLM dependency surface.
        from src.llm_provider import LLMProvider, LLMError
        from src.org_generator import OrgGenerator, OrgGenerationError
        from src.attack_generator import AttackPathGenerator, AttackGenerationError

        provider = LLMProvider(model=llm["model"], api_key=llm["api_key"],
                               base_url=llm["base_url"])

        # 1. Org baseline. From --prompt, or loaded from --input when only attacking.
        config: Optional[Dict] = None
        if prompt:
            logging.info(f"Generating an org baseline from your prompt using {llm['model']}")
            try:
                config = OrgGenerator(provider, self.generator).generate_baseline(prompt)
            except (OrgGenerationError, LLMError) as e:
                logging.error(f"Generation failed: {e}")
                return
        elif input_config:
            try:
                config = self.config_mgr.load_config(input_config)
            except (FileNotFoundError, Exception) as e:  # noqa: BLE001
                logging.error(f"Could not load --input config: {e}")
                return
        elif attack_prompt:
            logging.error("--attack-prompt needs a baseline: pass --prompt too, or "
                          "--input an existing config.")
            return

        # 2. Attack path layer (optional) — author a reachable chain into the config.
        if attack_prompt:
            logging.info(f"Generating an attack path from your prompt using {llm['model']}")
            try:
                config = AttackPathGenerator(provider, self.generator).generate_attack_paths(
                    config or {}, attack_prompt)
            except (AttackGenerationError, LLMError) as e:
                logging.error(f"Attack-path generation failed: {e}")
                return

        self._write_config(config, output, prompt or attack_prompt, llm["model"])
        logging.info(f"Wrote generated config to {output}")
        logging.info(f"Review it, then deploy with:  python BadZure.py build --config {output}")

    @staticmethod
    def _write_config(config: Dict, output: str, prompt: str, model: str) -> None:
        header = (
            "# BadZure config generated by `badzure generate`.\n"
            f"# Prompt: {prompt}\n"
            f"# Model:  {model}\n"
            "# Review/edit before deploying. Resource names (key vaults / storage)\n"
            "# must be globally unique for a live build.\n\n"
        )
        body = yaml.safe_dump(config, sort_keys=False, default_flow_style=False, width=100)
        with open(output, "w") as f:
            f.write(header + body)


class CompileBaselineCommand:
    """Handles `compile-baseline`: deterministically compile an org-design YAML into a
    declarative baseline config (no LLM, no Azure). This is the offline counterpart to
    `generate` for the agentic flow — a Claude Code agent (or any tool) authors the
    compact org-design YAML itself, then this command expands it into realistic named
    users/groups/etc. and validates it (the org-side equivalent of `check`).

    Exit codes: 0 = compiled + validated, 2 = malformed design / validation error.
    """

    def __init__(self):
        self.generator = EntityGenerator()

    def execute(self, design_file: str, output: str = "generated.yml",
                verbose: bool = False) -> int:
        from src.org_generator import OrgGenerator, OrgGenerationError

        try:
            with open(design_file, "r", encoding="utf-8") as f:
                design = yaml.safe_load(f)
        except FileNotFoundError:
            logging.error(f"Org-design file not found: {design_file}")
            return 2
        except yaml.YAMLError as e:
            logging.error(f"Org-design is not valid YAML: {e}")
            return 2
        if not isinstance(design, dict):
            logging.error("Org-design must be a YAML mapping (key: value structure).")
            return 2

        # No provider needed: compile_design + validate are pure/offline.
        org_gen = OrgGenerator(provider=None, entity_generator=self.generator)
        try:
            config = org_gen.compile_design(design)
            org_gen.validate(config)
        except (OrgGenerationError, ValueError) as e:
            logging.error(f"Org design invalid: {e}")
            return 2

        header = (
            "# BadZure baseline compiled by `badzure compile-baseline`.\n"
            f"# Source design: {design_file}\n"
            "# Review/edit before deploying. Run `uniquify` for globally-unique names.\n\n"
        )
        body = yaml.safe_dump(config, sort_keys=False, default_flow_style=False, width=100)
        with open(output, "w", encoding="utf-8") as f:
            f.write(header + body)
        n_users = len((config.get("baseline", {}).get("identities", {}) or {}).get("users", []))
        logging.info(f"Compiled org baseline -> {output} ({n_users} users)")
        return 0


class BaselineSpecCommand:
    """Handles `baseline-spec`: print the org-design authoring contract (vocabulary +
    schema + rules) that a design must follow — the SAME contract `generate`'s inner LLM
    is given. An agent reads this, authors an org-design JSON, then runs
    `compile-baseline`. Printing from the source avoids any drift from `vocabulary.py`."""

    @staticmethod
    def execute() -> int:
        from src.org_generator import OrgGenerator
        print(OrgGenerator._system_prompt())
        return 0
