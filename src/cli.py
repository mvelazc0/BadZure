"""
CLI command handlers for BadZure.
Implements build, show, and destroy commands.
"""
import os
import logging
import time
from typing import Dict, Optional
import yaml
from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.terraform_manager import TerraformManager
from src.output_formatter import OutputFormatter
from src.terraform_builder import build_tfvars
from src.scenario_loader import ScenarioLoader
import src.dataplane as dataplane
import src.utils as utils


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

        self._build_declarative_mode(config, verbose)

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
        """Fill exposed-host foothold paths' operator creds with the VM's public IP
        and admin credentials, read from the vm_foothold_access TF output (keyed by
        the foothold_resource the loader/macro recorded). The public IP is only known
        after apply, so it can't be set at planning time."""
        needed = {name: c['foothold_resource']
                  for name, c in user_creds.items() if c.get('foothold_resource')}
        if not needed:
            return
        foothold = outputs.get('vm_foothold_access', {})
        for name, vm_ref in needed.items():
            entry = foothold.get(vm_ref)
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
    """Handles `generate`: author a declarative config from a natural-language
    prompt via an LLM, write it to disk for REVIEW, then deploy with `build`.

    Composable / layer-aware (decision #8): `--prompt` authors the baseline org;
    `--attack-prompt` / `--input` are reserved for the later attack-path layer.
    """

    def __init__(self):
        self.config_mgr = ConfigManager()
        self.generator = EntityGenerator()

    def execute(self, prompt: Optional[str] = None, attack_prompt: Optional[str] = None,
                input_config: Optional[str] = None, output: str = "generated.yml",
                model: Optional[str] = None, verbose: bool = False) -> None:
        if attack_prompt:
            logging.warning("--attack-prompt is not implemented yet (attack-path "
                            "generation is a later slice); ignoring it.")
        if input_config:
            logging.warning("--input is reserved for extending an existing config with "
                            "generated attack paths (a later slice); ignoring it.")
        if not prompt:
            logging.error("Provide --prompt describing the organization to generate.")
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

        provider = LLMProvider(model=llm["model"], api_key=llm["api_key"],
                               base_url=llm["base_url"])
        org_gen = OrgGenerator(provider, self.generator)

        logging.info(f"Generating an org baseline from your prompt using {llm['model']}")
        try:
            config = org_gen.generate_baseline(prompt)
        except (OrgGenerationError, LLMError) as e:
            logging.error(f"Generation failed: {e}")
            return

        self._write_config(config, output, prompt, llm["model"])
        logging.info(f"Wrote generated config to {output}")
        logging.info(f"Review it, then deploy with:  python badzure.py build --config {output}")

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