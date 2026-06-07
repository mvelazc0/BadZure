"""
CLI command handlers for BadZure.
Implements build, show, and destroy commands.
"""
import os
import logging
import time
from typing import Dict
from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.assignment_manager import AssignmentManager
from src.attack_path_manager import AttackPathManager
from src.terraform_manager import TerraformManager
from src.output_formatter import OutputFormatter
from src.primitives import DeploymentModel
from src.primitive_handlers import GENERIC_FAMILIES
from src.terraform_builder import build_tfvars
from src.scenario_loader import ScenarioLoader
import src.utils as utils


class BuildCommand:
    """Handles the build command to create misconfigured tenants."""
    
    def __init__(self):
        self.config_mgr = ConfigManager()
        self.generator = EntityGenerator()
        self.assignment_mgr = AssignmentManager()
        self.attack_path_mgr = AttackPathManager()
        self.terraform_mgr = TerraformManager()
        self.output_formatter = OutputFormatter()
    
    def execute(self, config_file: str, verbose: bool = False) -> None:
        """
        Execute the build command.
        
        Args:
            config_file: Path to configuration file
            verbose: Enable verbose output
        """
        # Load configuration
        logging.info(f"Loading BadZure configuration from {config_file}")
        config = self.config_mgr.load_config(config_file)

        # Phase 3: the declarative graph config is a distinct shape. Detect it and
        # route to the generic builder; legacy random/targeted configs are untouched.
        if self._is_declarative_config(config):
            logging.info("Running in 'declarative' mode (graph config)")
            self._build_declarative_mode(config, verbose)
            return

        # Detect mode
        mode = config.get('mode', 'random')
        logging.info(f"Running in '{mode}' mode")

        if mode == 'targeted':
            self._build_targeted_mode(config, verbose)
        else:
            self._build_random_mode(config, verbose)

    @staticmethod
    def _is_declarative_config(config: Dict) -> bool:
        """Distinguish the Phase-3 declarative graph config from legacy
        random/targeted configs.

        An explicit top-level `schema: graph` forces the new path. Otherwise we
        detect structurally: a legacy attack path always carries
        `privilege_escalation`, while a declarative one carries an `assignments`
        list. The presence of any `privilege_escalation` key means legacy.
        """
        if not isinstance(config, dict):
            return False
        if config.get('schema') == 'graph':
            return True
        # `baseline:` is a Phase-3-only key (legacy uses `tenant:` counts).
        if config.get('baseline'):
            return True
        paths = config.get('attack_paths') or {}
        if not isinstance(paths, dict):
            return False
        path_dicts = [p for p in paths.values() if isinstance(p, dict)]
        if any('privilege_escalation' in p for p in path_dicts):
            return False
        return any('assignments' in p for p in path_dicts)

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

        # Surface SP secrets minted via the generic layer (same read-back the
        # Phase-2 macro path uses).
        user_creds = {ov.name: ov.credentials for ov in scenario.attack_paths}
        self._apply_generic_sp_credentials(user_creds)

        logging.info("Azure AD tenant setup completed with assigned permissions and configurations!")
        self.output_formatter.write_users_file(model.users, domain)
        self.output_formatter.format_declarative_paths(scenario.attack_paths, user_creds, domain)

        # Display deployment statistics
        elapsed_time = time.time() - start_time
        self._display_deployment_stats(
            elapsed_time, model.users, model.groups, model.applications,
            model.administrative_units, model.resource_groups, model.key_vaults,
            model.storage_accounts, model.virtual_machines, model.logic_apps,
            model.automation_accounts, model.function_apps, model.cosmos_dbs
        )

        logging.info("Good bye.")

    # ------------------------------------------------------------------
    # Phase 2: generic-primitive layer (currently KeyVaultSecretTheft).
    # Techniques expressed as macros emit building blocks; these helpers
    # compile them into the generic.tf variable families and read back any
    # credentials minted via the generic layer. Other techniques stay on the
    # legacy path until Phase 4.
    # ------------------------------------------------------------------
    def _compile_generic_families(self, generic_primitives, tenant_id, domain,
                                  subscription_id, public_ip, azure_config_dir,
                                  entity_dicts) -> Dict:
        """Compile generic building blocks into the 18 generic tfvars families.

        entity_dicts are the symbolic-keyed entity maps (users by UPN, groups/apps
        by display_name) — the SAME keys build_terraform_vars writes, so the refs
        in the emitted families resolve against var.users/var.groups/... unchanged.
        Returns only the non-empty generic family keys (entity/legacy vars untouched).
        """
        if not generic_primitives:
            return {}
        model = DeploymentModel(
            tenant_id=tenant_id, domain=domain, subscription_id=subscription_id,
            public_ip=public_ip, azure_config_dir=azure_config_dir,
            primitives=generic_primitives, **entity_dicts,
        )
        full = build_tfvars(model)
        return {family: full[family] for family in GENERIC_FAMILIES if family in full}

    def _apply_generic_sp_credentials(self, user_creds: Dict) -> None:
        """Read SP secrets minted via the generic layer back into user_creds.

        Initial-access service principals get their secret from the
        generic_app_credentials TF output (keyed by the origin-prefixed
        credential key the macro recorded as 'generic_credential_key').
        """
        needed = {ap: c['generic_credential_key']
                  for ap, c in user_creds.items() if c.get('generic_credential_key')}
        if not needed:
            return
        outputs = self.terraform_mgr.get_outputs()
        generic_creds = outputs.get('generic_app_credentials', {})
        for ap_name, cred_key in needed.items():
            entry = generic_creds.get(cred_key)
            if entry:
                user_creds[ap_name]['client_id'] = entry.get('client_id')
                user_creds[ap_name]['client_secret'] = entry.get('client_secret')

    def _build_random_mode(self, config: Dict, verbose: bool) -> None:
        """Build in random mode."""
        start_time = time.time()
        
        # Validate resource counts before proceeding
        is_valid, errors = self.config_mgr.validate_random_mode_resources(config)
        if not is_valid:
            logging.error("Configuration validation failed:")
            for error in errors:
                logging.error(f"  {error}")
            return
        elif errors:  # Warnings
            for error in errors:
                logging.warning(error)
        
        azure_config_dir = os.path.expanduser('~/.azure')
        os.environ['AZURE_CONFIG_DIR'] = azure_config_dir
        
        # Resolve tenant config with environment variable fallback
        try:
            tenant_id, domain, subscription_id = self.config_mgr.resolve_tenant_config(config)
        except ValueError as e:
            logging.error(str(e))
            return
        
        max_users = config['tenant']['users']
        max_groups = config['tenant']['groups']
        max_apps = config['tenant']['applications']
        max_aunits = config['tenant']['administrative_units']
        max_rgroups = config['tenant']['resource_groups']
        max_kvs = config['tenant']['key_vaults']
        max_sas = config['tenant']['storage_accounts']
        max_vms = config['tenant']['virtual_machines']
        max_logic_apps = config['tenant'].get('logic_apps', 0)
        max_automation_accounts = config['tenant'].get('automation_accounts', 0)
        max_function_apps = config['tenant'].get('function_apps', 0)
        max_cosmos_dbs = config['tenant'].get('cosmos_dbs', 0)

        public_ip = utils.get_public_ip()
        
        # Generate entities (only log when count > 0)
        if max_users > 0:
            logging.info(f"Generating {max_users} random users")
        users = self.generator.generate_users(max_users)
        
        if max_groups > 0:
            logging.info(f"Generating {max_groups} random groups")
        groups = self.generator.generate_groups(max_groups)
        
        if max_apps > 0:
            logging.info(f"Generating {max_apps} random application registrations/service principals")
        applications = self.generator.generate_applications(max_apps)
        
        if max_aunits > 0:
            logging.info(f"Generating {max_aunits} random administrative units")
        administrative_units = self.generator.generate_administrative_units(max_aunits)
        
        if max_rgroups > 0:
            logging.info(f"Generating {max_rgroups} resource groups")
        resource_groups = self.generator.generate_resource_groups(max_rgroups)
        
        if max_kvs > 0:
            logging.info(f"Generating {max_kvs} key vaults")
        key_vaults = self.generator.generate_key_vaults(max_kvs, resource_groups)
        
        if max_sas > 0:
            logging.info(f"Generating {max_sas} storage accounts")
        storage_accounts = self.generator.generate_storage_accounts(max_sas, resource_groups)
        
        if max_vms > 0:
            logging.info(f"Generating {max_vms} virtual machines")
        virtual_machines = self.generator.generate_virtual_machines(max_vms, resource_groups)
        
        if max_logic_apps > 0:
            logging.info(f"Generating {max_logic_apps} logic apps")
        logic_apps = self.generator.generate_logic_apps(max_logic_apps, resource_groups)
        
        if max_automation_accounts > 0:
            logging.info(f"Generating {max_automation_accounts} automation accounts")
        automation_accounts = self.generator.generate_automation_accounts(max_automation_accounts, resource_groups)
        
        if max_function_apps > 0:
            logging.info(f"Generating {max_function_apps} function apps")
        function_apps = self.generator.generate_function_apps(max_function_apps, resource_groups)

        if max_cosmos_dbs > 0:
            logging.info(f"Generating {max_cosmos_dbs} cosmos DB accounts")
        cosmos_dbs = self.generator.generate_cosmos_dbs(max_cosmos_dbs, resource_groups)

        # Check if there are any enabled attack paths
        enabled_attack_paths = [
            path for path in config.get('attack_paths', {}).values()
            if path.get('enabled', False)
        ]
        
        # Only show warnings if we have enabled attack paths or if users/apps are configured
        show_warnings = len(enabled_attack_paths) > 0 or max_users > 0 or max_apps > 0
        
        # Create attack paths FIRST to collect group assignments
        # This allows us to exclude attack path groups from random assignments.
        # attack_path_group_assignments holds the macro-created group ENTITIES (so
        # Terraform creates them and they're excluded from random membership noise).
        attack_path_group_assignments = {}
        user_creds = {}

        # Phase 2/4: building blocks emitted by macro-based techniques.
        generic_primitives = []
        generic_summaries = []

        # Track used resources to prevent conflicts
        used_apps = set()
        used_users = set()
        
        for attack_path_name, attack_path_data in config['attack_paths'].items():
            if not attack_path_data['enabled']:
                continue
            
            # Support both old and new names with deprecation warning
            priv_esc = attack_path_data['privilege_escalation']
            
            if priv_esc == 'ServicePrincipalAbuse':
                logging.warning(f"{attack_path_name}: 'ServicePrincipalAbuse' is deprecated. Please use 'ApplicationOwnershipAbuse' instead.")
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_application_ownership_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                used_apps.add(result['summary']['app_name'])
                used_users.add(result['summary']['principal_name'])
            
            elif priv_esc == 'ApplicationOwnershipAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_application_ownership_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                used_apps.add(result['summary']['app_name'])
                used_users.add(result['summary']['principal_name'])
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_application_administrator_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                used_apps.add(result['summary']['app_name'])
                used_users.add(result['summary']['principal_name'])

            elif priv_esc == 'CloudAppAdministratorAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_cloud_app_administrator_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                used_apps.add(result['summary']['app_name'])
                used_users.add(result['summary']['principal_name'])

            elif attack_path_data['privilege_escalation'] == 'KeyVaultSecretTheft':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 2 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_keyvault_secret_theft(
                    attack_path_data, applications, key_vaults, users, applications,
                    domain, mode='random', path_name=attack_path_name,
                    used_apps=used_apps
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                # Track the looted app so other paths don't reuse it
                used_apps.add(result['summary']['app_name'])

            elif attack_path_data['privilege_escalation'] == 'StorageCertificateTheft':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_storage_certificate_theft(
                    attack_path_data, applications, storage_accounts, users, applications,
                    domain, mode='random', path_name=attack_path_name,
                    used_apps=used_apps
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                used_apps.add(result['summary']['app_name'])
            
            elif attack_path_data['privilege_escalation'] == 'CosmosDBSecretTheft':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_cosmosdb_secret_theft(
                    attack_path_data, applications, cosmos_dbs, users, applications,
                    domain, mode='random', path_name=attack_path_name,
                    used_apps=used_apps
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                used_apps.add(result['summary']['app_name'])

            elif attack_path_data['privilege_escalation'] in ('ManagedIdentityTheft', 'ManagedIdentityAbuse'):
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_managed_identity_theft(
                    attack_path_data, applications, key_vaults, storage_accounts, users,
                    domain, virtual_machines, logic_apps, automation_accounts, function_apps,
                    mode='random', path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users, cosmos_dbs=cosmos_dbs
                )
                generic_primitives.extend(result['primitives'])
                attack_path_group_assignments.update(result['groups'])
                generic_summaries.append(result['summary'])
                user_creds[attack_path_name] = result['credentials']
                used_apps.add(result['summary']['app_name'])
                used_users.add(result['summary']['principal_name'])
        
        # Add attack path groups to the groups dictionary
        # These groups will be created by Terraform
        for group_name, group_spec in attack_path_group_assignments.items():
            groups[group_name] = group_spec
        
        # Get the set of attack path group names to exclude from random assignments
        attack_path_group_names = set(attack_path_group_assignments.keys())
        
        # Create random assignments AFTER attack paths to exclude attack path groups
        (user_group_assignments, user_au_assignments, user_role_assignments,
         app_role_assignments, app_api_permission_assignments) = \
            self.assignment_mgr.create_random_assignments(
                users, groups, administrative_units, applications,
                show_warnings=show_warnings,
                attack_path_groups=attack_path_group_names
            )
        
        # Recon access for initial-access identities, emitted as generic primitives
        # (Directory.Read.All for SPs + subscription Reader).
        generic_primitives.extend(self.attack_path_mgr.build_recon_primitives(user_creds))

        # Build and write Terraform variables (entities + random noise).
        tf_vars = self.terraform_mgr.build_terraform_vars(
            tenant_id, domain, subscription_id, public_ip, azure_config_dir,
            users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, logic_apps,
            automation_accounts, function_apps, cosmos_dbs,
            user_group_assignments, user_au_assignments, user_role_assignments,
            app_role_assignments, app_api_permission_assignments,
        )
        # Splice the generic-primitive families (all attack-path edges + recon) in.
        tf_vars.update(self._compile_generic_families(
            generic_primitives, tenant_id, domain, subscription_id, public_ip,
            azure_config_dir,
            {'users': users, 'groups': groups, 'applications': applications,
             'administrative_units': administrative_units,
             'resource_groups': resource_groups, 'key_vaults': key_vaults,
             'storage_accounts': storage_accounts, 'virtual_machines': virtual_machines,
             'logic_apps': logic_apps, 'automation_accounts': automation_accounts,
             'function_apps': function_apps, 'cosmos_dbs': cosmos_dbs},
        ))
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

        # SP secrets for macro-based paths come from the generic_app_credentials output.
        self._apply_generic_sp_credentials(user_creds)

        logging.info("Azure AD tenant setup completed with assigned permissions and configurations!")
        self.output_formatter.write_users_file(users, domain)
        # Phase 2/4: minimal printout for macro-based techniques
        # (rich narrative is the declarative path's job).
        self.output_formatter.format_generic_paths(generic_summaries, user_creds, domain)

        # Display deployment statistics
        elapsed_time = time.time() - start_time
        self._display_deployment_stats(
            elapsed_time, users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, logic_apps,
            automation_accounts, function_apps, cosmos_dbs
        )
        
        logging.info("Good bye.")
    
    def _build_targeted_mode(self, config: Dict, verbose: bool) -> None:
        """Build in targeted mode."""
        start_time = time.time()
        
        # Validate targeted configuration
        is_valid, errors = self.config_mgr.validate_targeted_config(config)
        if not is_valid:
            logging.error("Configuration validation failed:")
            for error in errors:
                logging.error(f"  - {error}")
            return
        
        azure_config_dir = os.path.expanduser('~/.azure')
        os.environ['AZURE_CONFIG_DIR'] = azure_config_dir
        
        # Resolve tenant config with environment variable fallback
        try:
            tenant_id, domain, subscription_id = self.config_mgr.resolve_tenant_config(config)
        except ValueError as e:
            logging.error(str(e))
            return
        
        public_ip = utils.get_public_ip()
        
        # Collect entities from attack paths
        logging.info("Collecting entities from attack paths")
        all_entities = self._collect_entities_from_attack_paths(config)
        
        # Generate entities
        logging.info("Generating entity details")
        users = self.generator.generate_users_targeted(all_entities.get('users', []))
        logging.info(f"Generated {len(users)} user(s)")
        groups = self.generator.generate_groups_targeted(all_entities.get('groups', []))
        logging.info(f"Generated {len(groups)} group(s)")
        applications = self.generator.generate_applications_targeted(all_entities.get('applications', []))
        logging.info(f"Generated {len(applications)} application(s)")
        administrative_units = self.generator.generate_administrative_units_targeted(
            all_entities.get('administrative_units', [])
        )
        resource_groups = self.generator.generate_resource_groups_targeted(
            all_entities.get('resource_groups', [])
        )
        logging.info(f"Generated {len(resource_groups)} resource group(s)")
        key_vaults = self.generator.generate_key_vaults_targeted(
            all_entities.get('key_vaults', []), resource_groups
        )
        logging.info(f"Generated {len(key_vaults)} key vault(s)")
        storage_accounts = self.generator.generate_storage_accounts_targeted(
            all_entities.get('storage_accounts', []), resource_groups
        )
        virtual_machines = self.generator.generate_virtual_machines_targeted(
            all_entities.get('virtual_machines', []), resource_groups
        )
        logging.info(f"Generated {len(virtual_machines)} virtual machine(s)")
        logic_apps = self.generator.generate_logic_apps_targeted(
            all_entities.get('logic_apps', []), resource_groups
        )
        automation_accounts = self.generator.generate_automation_accounts_targeted(
            all_entities.get('automation_accounts', []), resource_groups
        )
        function_apps = self.generator.generate_function_apps_targeted(
            all_entities.get('function_apps', []), resource_groups
        )
        cosmos_dbs = self.generator.generate_cosmos_dbs_targeted(
            all_entities.get('cosmos_dbs', []), resource_groups
        )

        # Create targeted attack path assignments
        logging.info("Creating attack path assignments")
        attack_path_assignments = self._create_targeted_assignments(
            config, users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, logic_apps,
            automation_accounts, function_apps, cosmos_dbs, domain
        )
        
        # Add attack path groups to the groups dictionary
        # These groups will be created by Terraform
        for group_name, group_spec in attack_path_assignments.get('group_assignments', {}).items():
            groups[group_name] = group_spec
        
        if attack_path_assignments.get('group_assignments'):
            logging.info(f"Generated {len(attack_path_assignments['group_assignments'])} attack path group(s)")

        user_creds = attack_path_assignments.get('user_creds', {})

        # Recon access for initial-access identities, emitted as generic primitives
        # (Directory.Read.All for SPs + subscription Reader).
        attack_path_assignments['generic_primitives'].extend(
            self.attack_path_mgr.build_recon_primitives(user_creds))

        # Build and write Terraform variables (entities only; targeted has no random noise).
        tf_vars = self.terraform_mgr.build_terraform_vars(
            tenant_id, domain, subscription_id, public_ip, azure_config_dir,
            users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, logic_apps,
            automation_accounts, function_apps, cosmos_dbs,
            {}, {}, {}, {}, {},  # no random noise in targeted mode
        )
        # Splice the generic-primitive families (all attack-path edges + recon) in.
        tf_vars.update(self._compile_generic_families(
            attack_path_assignments.get('generic_primitives', []),
            tenant_id, domain, subscription_id, public_ip, azure_config_dir,
            {'users': users, 'groups': groups, 'applications': applications,
             'administrative_units': administrative_units,
             'resource_groups': resource_groups, 'key_vaults': key_vaults,
             'storage_accounts': storage_accounts, 'virtual_machines': virtual_machines,
             'logic_apps': logic_apps, 'automation_accounts': automation_accounts,
             'function_apps': function_apps, 'cosmos_dbs': cosmos_dbs},
        ))
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

        logging.info("Calling terraform apply to create resources, this may take several minutes...")
        return_code, stdout, stderr = self.terraform_mgr.apply(verbose)
        if return_code != 0:
            logging.error(f"Terraform apply failed: {stderr}")
            if verbose:
                logging.error(stdout)
                logging.error(stderr)
            return

        # SP secrets for macro-based paths come from the generic_app_credentials output.
        self._apply_generic_sp_credentials(user_creds)

        logging.info("Azure AD tenant setup completed!")
        self.output_formatter.write_users_file(users, domain)
        # Phase 2/4: minimal printout for macro-based techniques.
        self.output_formatter.format_generic_paths(
            attack_path_assignments.get('generic_summaries', []), user_creds, domain)

        # Display deployment statistics
        elapsed_time = time.time() - start_time
        self._display_deployment_stats(
            elapsed_time, users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, logic_apps,
            automation_accounts, function_apps, cosmos_dbs
        )
        
        logging.info("Good bye.")
    
    def _create_targeted_assignments(
        self, config: Dict, users: Dict, groups: Dict, applications: Dict,
        administrative_units: Dict, resource_groups: Dict, key_vaults: Dict,
        storage_accounts: Dict, virtual_machines: Dict, logic_apps: Dict,
        automation_accounts: Dict, function_apps: Dict, cosmos_dbs: Dict, domain: str
    ) -> Dict:
        """Create targeted attack path assignments using consolidated AttackPathManager."""
        assignments = {
            # macro-created group ENTITIES (for creation + random-noise exclusion)
            'group_assignments': {},
            # generic building blocks emitted by the macros + recon
            'generic_primitives': [],
            'generic_summaries': []
        }

        user_creds = {}
        
        for path_name, path_config in config['attack_paths'].items():
            if not path_config.get('enabled', False):
                continue
            
            priv_esc = path_config.get('privilege_escalation')
            entities = path_config.get('entities', {})
            
            # Support both old and new names with deprecation warning
            if priv_esc == 'ServicePrincipalAbuse':
                logging.warning(f"{path_name}: 'ServicePrincipalAbuse' is deprecated. Please use 'ApplicationOwnershipAbuse' instead.")
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_application_ownership_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']
            
            elif priv_esc == 'ApplicationOwnershipAbuse':
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_application_ownership_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_application_administrator_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']

            elif priv_esc == 'CloudAppAdministratorAbuse':
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_cloud_app_administrator_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']

            elif priv_esc == 'KeyVaultSecretTheft':
                # Phase 2 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_keyvault_secret_theft(
                    path_config, applications, key_vaults, users, applications,
                    domain, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']

            elif priv_esc == 'StorageCertificateTheft':
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_storage_certificate_theft(
                    path_config, applications, storage_accounts, users, applications,
                    domain, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']
            
            elif priv_esc == 'CosmosDBSecretTheft':
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_cosmosdb_secret_theft(
                    path_config, applications, cosmos_dbs, users, applications,
                    domain, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']

            elif priv_esc in ('ManagedIdentityTheft', 'ManagedIdentityAbuse'):
                # Phase 4 macro: emit generic building blocks instead of legacy buckets.
                result = self.attack_path_mgr.macro_managed_identity_theft(
                    path_config, applications, key_vaults, storage_accounts, users,
                    domain, virtual_machines, logic_apps, automation_accounts, function_apps,
                    mode='targeted', entities=entities, path_name=path_name, cosmos_dbs=cosmos_dbs
                )
                assignments['generic_primitives'].extend(result['primitives'])
                assignments['group_assignments'].update(result['groups'])
                assignments['generic_summaries'].append(result['summary'])
                user_creds[path_name] = result['credentials']
        
        # Store user credentials for output
        assignments['user_creds'] = user_creds
        
        return assignments
    
    def _collect_entities_from_attack_paths(self, config: Dict) -> Dict:
        """Collect all entities from enabled attack paths."""
        all_entities = {
            'users': [], 'groups': [], 'applications': [], 'administrative_units': [],
            'resource_groups': [], 'key_vaults': [], 'storage_accounts': [], 'virtual_machines': [],
            'logic_apps': [], 'automation_accounts': [], 'function_apps': [], 'cosmos_dbs': []
        }
        
        seen_names = {key: set() for key in all_entities.keys()}
        
        for path_name, path_config in config['attack_paths'].items():
            if not path_config.get('enabled', False):
                continue

            entities = path_config.get('entities', {})

            for entity_type in all_entities.keys():
                if entity_type in entities:
                    for entity in entities[entity_type]:
                        entity_name = entity.get('name', 'random')

                        if entity_name == 'random':
                            all_entities[entity_type].append(entity)
                        else:
                            if entity_name in seen_names[entity_type]:
                                logging.warning(
                                    f"Duplicate {entity_type} name '{entity_name}' found in {path_name}, skipping duplicate"
                                )
                                continue

                            seen_names[entity_type].add(entity_name)
                            all_entities[entity_type].append(entity)

            # Service principals are backed by applications in Azure/Terraform,
            # so collect them into the applications list
            if 'service_principals' in entities:
                for sp in entities['service_principals']:
                    sp_name = sp.get('name', 'random')
                    if sp_name == 'random':
                        all_entities['applications'].append(sp)
                    elif sp_name not in seen_names['applications']:
                        seen_names['applications'].add(sp_name)
                        all_entities['applications'].append(sp)
        
        # Log collected entity counts for debugging
        logging.info("Collected entities from attack paths:")
        for entity_type, entities in all_entities.items():
            if entities:
                logging.info(f"  - {entity_type}: {len(entities)} entity specification(s)")
        
        return all_entities
    
    def _display_deployment_stats(self, elapsed_time: float, users: Dict, groups: Dict,
                                   applications: Dict, administrative_units: Dict,
                                   resource_groups: Dict, key_vaults: Dict,
                                   storage_accounts: Dict, virtual_machines: Dict, logic_apps: Dict,
                                   automation_accounts: Dict, function_apps: Dict,
                                   cosmos_dbs: Dict = None) -> None:
        """Display deployment statistics summary."""
        cosmos_dbs = cosmos_dbs or {}
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)

        total_identities = len(users) + len(groups) + len(applications) + len(administrative_units)
        total_resources = len(resource_groups) + len(key_vaults) + len(storage_accounts) + len(virtual_machines) + len(logic_apps) + len(automation_accounts) + len(function_apps) + len(cosmos_dbs)

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
        logging.info(f"  - Cosmos DB Accounts: {len(cosmos_dbs)}")
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