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
        
        # Detect mode
        mode = config.get('mode', 'random')
        logging.info(f"Running in '{mode}' mode")
        
        if mode == 'targeted':
            self._build_targeted_mode(config, verbose)
        else:
            self._build_random_mode(config, verbose)
    
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
        # This allows us to exclude attack path groups from random assignments
        attack_path_application_owner_assignments = {}
        attack_path_user_role_assignments = {}
        attack_path_application_role_assignments = {}
        attack_path_app_api_permission_assignments = {}
        attack_path_kv_abuse_assignments = {}
        attack_path_storage_abuse_assignments = {}
        attack_path_managed_identity_theft_assignments = {}
        attack_path_cosmos_abuse_assignments = {}
        attack_path_vm_contributor_assignments = {}
        attack_path_group_assignments = {}
        attack_path_group_membership_assignments = {}
        user_creds = {}
        
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
                result = self.attack_path_mgr.create_application_ownership_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                attack_path_application_owner_assignments.update(result['app_owner_assignments'])
                attack_path_user_role_assignments.update(result['user_role_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used resources from owner assignments
                for assignment in result['app_owner_assignments'].values():
                    used_apps.add(assignment['app_name'])
                    # Track principal (user or service principal)
                    if 'principal_name' in assignment:
                        used_users.add(assignment['principal_name'])
                for assignment in result['user_role_assignments'].values():
                    if 'principal_name' in assignment:
                        used_users.add(assignment['principal_name'])
                    elif 'user_name' in assignment:
                        used_users.add(assignment['user_name'])
            
            elif priv_esc == 'ApplicationOwnershipAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                result = self.attack_path_mgr.create_application_ownership_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                attack_path_application_owner_assignments.update(result['app_owner_assignments'])
                attack_path_user_role_assignments.update(result['user_role_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used resources from owner assignments
                for assignment in result['app_owner_assignments'].values():
                    used_apps.add(assignment['app_name'])
                    # Track principal (user or service principal)
                    if 'principal_name' in assignment:
                        used_users.add(assignment['principal_name'])
                for assignment in result['user_role_assignments'].values():
                    if 'principal_name' in assignment:
                        used_users.add(assignment['principal_name'])
                    elif 'user_name' in assignment:
                        used_users.add(assignment['user_name'])
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                result = self.attack_path_mgr.create_application_administrator_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                attack_path_user_role_assignments.update(result['user_role_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used resources from both role and API permission assignments
                for assignment in result['app_role_assignments'].values():
                    used_apps.add(assignment['app_name'])
                for assignment in result['app_api_permission_assignments'].values():
                    used_apps.add(assignment['app_name'])
                for assignment in result['user_role_assignments'].values():
                    if 'principal_name' in assignment:
                        used_users.add(assignment['principal_name'])
                    elif 'user_name' in assignment:
                        used_users.add(assignment['user_name'])

            elif priv_esc == 'CloudAppAdministratorAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                result = self.attack_path_mgr.create_cloud_app_administrator_abuse(
                    attack_path_data, users, applications, domain, mode='random',
                    path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users
                )
                attack_path_user_role_assignments.update(result['user_role_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used resources from both role and API permission assignments
                for assignment in result['app_role_assignments'].values():
                    used_apps.add(assignment['app_name'])
                for assignment in result['app_api_permission_assignments'].values():
                    used_apps.add(assignment['app_name'])
                for assignment in result['user_role_assignments'].values():
                    if 'principal_name' in assignment:
                        used_users.add(assignment['principal_name'])
                    elif 'user_name' in assignment:
                        used_users.add(assignment['user_name'])

            elif attack_path_data['privilege_escalation'] == 'KeyVaultSecretTheft':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                result = self.attack_path_mgr.create_keyvault_secret_theft(
                    attack_path_data, applications, key_vaults, users, applications,
                    virtual_machines, domain, mode='random', path_name=attack_path_name,
                    used_apps=used_apps
                )
                attack_path_kv_abuse_assignments.update(result['kv_abuse_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_vm_contributor_assignments.update(result['vm_contributor_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used apps
                for assignment in result['kv_abuse_assignments'].values():
                    used_apps.add(assignment['app_name'])
            
            elif attack_path_data['privilege_escalation'] == 'StorageCertificateTheft':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                result = self.attack_path_mgr.create_storage_certificate_theft(
                    attack_path_data, applications, storage_accounts, users, applications,
                    virtual_machines, domain, mode='random', path_name=attack_path_name,
                    used_apps=used_apps
                )
                attack_path_storage_abuse_assignments.update(result['storage_abuse_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_vm_contributor_assignments.update(result['vm_contributor_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used apps
                for assignment in result['storage_abuse_assignments'].values():
                    used_apps.add(assignment['app_name'])
            
            elif attack_path_data['privilege_escalation'] == 'CosmosDBSecretTheft':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                result = self.attack_path_mgr.create_cosmosdb_secret_theft(
                    attack_path_data, applications, cosmos_dbs, users, applications,
                    domain, mode='random', path_name=attack_path_name,
                    used_apps=used_apps
                )
                attack_path_cosmos_abuse_assignments.update(result['cosmos_abuse_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used apps
                for assignment in result['cosmos_abuse_assignments'].values():
                    used_apps.add(assignment['app_name'])

            elif attack_path_data['privilege_escalation'] == 'ManagedIdentityTheft':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                result = self.attack_path_mgr.create_managed_identity_theft(
                    attack_path_data, applications, key_vaults, storage_accounts, users,
                    domain, virtual_machines, logic_apps, automation_accounts, function_apps, mode='random', path_name=attack_path_name,
                    used_apps=used_apps, used_users=used_users,
                    cosmos_dbs=cosmos_dbs
                )
                attack_path_managed_identity_theft_assignments.update(result['mi_theft_assignments'])
                attack_path_application_role_assignments.update(result['app_role_assignments'])
                attack_path_app_api_permission_assignments.update(result['app_api_permission_assignments'])
                attack_path_vm_contributor_assignments.update(result['vm_contributor_assignments'])
                attack_path_group_assignments.update(result.get('group_assignments', {}))
                attack_path_group_membership_assignments.update(result.get('group_membership_assignments', {}))
                user_creds[attack_path_name] = result['credentials']
                # Track used apps and users/service principals
                for assignment in result['mi_theft_assignments'].values():
                    used_apps.add(assignment['app_name'])
                    # Track initial access principal (user or service principal)
                    if 'initial_access_principal' in assignment:
                        used_users.add(assignment['initial_access_principal'])
                    elif 'initial_access_user' in assignment:
                        # Backward compatibility
                        used_users.add(assignment['initial_access_user'])
        
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
        
        # Collect compromised SP credentials for Terraform
        compromised_sp_creds = {}
        for ap_name, creds in user_creds.items():
            if creds.get('initial_access') == 'service_principal':
                sp_name = creds.get('service_principal_name')
                if sp_name:
                    compromised_sp_creds[ap_name] = {'app_name': sp_name}

        # Add recon permissions to initial access identities
        recon_api_perms, attack_path_subscription_reader_assignments = \
            self.attack_path_mgr.build_recon_permissions(user_creds)
        attack_path_app_api_permission_assignments.update(recon_api_perms)

        # Build and write Terraform variables
        tf_vars = self.terraform_mgr.build_terraform_vars(
            tenant_id, domain, subscription_id, public_ip, azure_config_dir,
            users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, logic_apps,
            automation_accounts, function_apps, cosmos_dbs,
            user_group_assignments, user_au_assignments, user_role_assignments,
            app_role_assignments, app_api_permission_assignments,
            attack_path_application_owner_assignments, attack_path_user_role_assignments,
            attack_path_application_role_assignments, attack_path_app_api_permission_assignments,
            attack_path_kv_abuse_assignments, attack_path_storage_abuse_assignments,
            attack_path_managed_identity_theft_assignments,
            attack_path_vm_contributor_assignments,
            attack_path_cosmos_abuse_assignments,
            attack_path_group_membership_assignments,
            attack_path_compromised_sp_credentials=compromised_sp_creds,
            attack_path_subscription_reader_assignments=attack_path_subscription_reader_assignments
        )
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

        # Read Terraform outputs for SP credentials
        if compromised_sp_creds:
            outputs = self.terraform_mgr.get_outputs()
            sp_credentials = outputs.get('compromised_sp_credentials', {})
            for ap_name, sp_cred in sp_credentials.items():
                if ap_name in user_creds:
                    user_creds[ap_name]['client_id'] = sp_cred.get('client_id')
                    user_creds[ap_name]['client_secret'] = sp_cred.get('client_secret')

        logging.info("Azure AD tenant setup completed with assigned permissions and configurations!")
        self.output_formatter.write_users_file(users, domain)
        self.output_formatter.format_random_mode_attack_paths(
            config, attack_path_application_owner_assignments,
            attack_path_kv_abuse_assignments, attack_path_storage_abuse_assignments,
            attack_path_managed_identity_theft_assignments,
            attack_path_cosmos_abuse_assignments,
            attack_path_application_role_assignments, attack_path_app_api_permission_assignments,
            attack_path_user_role_assignments,
            user_creds, domain
        )

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

        # Collect compromised SP credentials for Terraform
        user_creds = attack_path_assignments.get('user_creds', {})
        compromised_sp_creds = {}
        for ap_name, creds in user_creds.items():
            if creds.get('initial_access') == 'service_principal':
                sp_name = creds.get('service_principal_name')
                if sp_name:
                    compromised_sp_creds[ap_name] = {'app_name': sp_name}

        # Add recon permissions to initial access identities
        recon_api_perms, attack_path_subscription_reader_assignments = \
            self.attack_path_mgr.build_recon_permissions(user_creds)
        attack_path_assignments['app_api_permissions'].update(recon_api_perms)

        # Build and write Terraform variables
        tf_vars = self.terraform_mgr.build_terraform_vars(
            tenant_id, domain, subscription_id, public_ip, azure_config_dir,
            users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, logic_apps,
            automation_accounts, function_apps, cosmos_dbs,
            {}, {}, {}, {}, {},  # Empty random assignments
            attack_path_assignments.get('app_owners', {}),
            attack_path_assignments.get('user_roles', {}),
            attack_path_assignments.get('app_roles', {}),
            attack_path_assignments.get('app_api_permissions', {}),
            attack_path_assignments.get('kv_abuse', {}),
            attack_path_assignments.get('storage_abuse', {}),
            attack_path_assignments.get('managed_identity_theft', {}),
            attack_path_assignments.get('vm_contributor', {}),
            attack_path_assignments.get('cosmos_abuse', {}),
            attack_path_assignments.get('group_membership_assignments', {}),
            attack_path_compromised_sp_credentials=compromised_sp_creds,
            attack_path_subscription_reader_assignments=attack_path_subscription_reader_assignments
        )
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

        # Read Terraform outputs for SP credentials
        if compromised_sp_creds:
            outputs = self.terraform_mgr.get_outputs()
            sp_credentials = outputs.get('compromised_sp_credentials', {})
            for ap_name, sp_cred in sp_credentials.items():
                if ap_name in user_creds:
                    user_creds[ap_name]['client_id'] = sp_cred.get('client_id')
                    user_creds[ap_name]['client_secret'] = sp_cred.get('client_secret')

        logging.info("Azure AD tenant setup completed!")
        self.output_formatter.write_users_file(users, domain)
        self.output_formatter.format_targeted_mode_attack_paths(config, attack_path_assignments, users, domain)

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
            'app_owners': {},
            'user_roles': {},
            'app_roles': {},
            'app_api_permissions': {},
            'kv_abuse': {},
            'storage_abuse': {},
            'cosmos_abuse': {},
            'managed_identity_theft': {},
            'vm_contributor': {},
            'group_assignments': {},
            'group_membership_assignments': {}
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
                result = self.attack_path_mgr.create_application_ownership_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['app_owners'].update(result['app_owner_assignments'])
                assignments['user_roles'].update(result['user_role_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
                user_creds[path_name] = result['credentials']
            
            elif priv_esc == 'ApplicationOwnershipAbuse':
                result = self.attack_path_mgr.create_application_ownership_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['app_owners'].update(result['app_owner_assignments'])
                assignments['user_roles'].update(result['user_role_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
                user_creds[path_name] = result['credentials']
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                result = self.attack_path_mgr.create_application_administrator_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['user_roles'].update(result['user_role_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
                user_creds[path_name] = result['credentials']

            elif priv_esc == 'CloudAppAdministratorAbuse':
                result = self.attack_path_mgr.create_cloud_app_administrator_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['user_roles'].update(result['user_role_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
                user_creds[path_name] = result['credentials']

            elif priv_esc == 'KeyVaultSecretTheft':
                result = self.attack_path_mgr.create_keyvault_secret_theft(
                    path_config, applications, key_vaults, users, applications,
                    virtual_machines, domain, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['kv_abuse'].update(result['kv_abuse_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['vm_contributor'].update(result['vm_contributor_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
                user_creds[path_name] = result['credentials']
            
            elif priv_esc == 'StorageCertificateTheft':
                result = self.attack_path_mgr.create_storage_certificate_theft(
                    path_config, applications, storage_accounts, users, applications,
                    virtual_machines, domain, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['storage_abuse'].update(result['storage_abuse_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['vm_contributor'].update(result['vm_contributor_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
                user_creds[path_name] = result['credentials']
            
            elif priv_esc == 'CosmosDBSecretTheft':
                result = self.attack_path_mgr.create_cosmosdb_secret_theft(
                    path_config, applications, cosmos_dbs, users, applications,
                    domain, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['cosmos_abuse'].update(result['cosmos_abuse_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
                user_creds[path_name] = result['credentials']

            elif priv_esc == 'ManagedIdentityTheft':
                result = self.attack_path_mgr.create_managed_identity_theft(
                    path_config, applications, key_vaults, storage_accounts, users,
                    domain, virtual_machines, logic_apps, automation_accounts, function_apps, mode='targeted', entities=entities, path_name=path_name,
                    cosmos_dbs=cosmos_dbs
                )
                assignments['managed_identity_theft'].update(result['mi_theft_assignments'])
                assignments['app_roles'].update(result['app_role_assignments'])
                assignments['app_api_permissions'].update(result['app_api_permission_assignments'])
                assignments['vm_contributor'].update(result['vm_contributor_assignments'])
                assignments['group_assignments'].update(result.get('group_assignments', {}))
                assignments['group_membership_assignments'].update(result.get('group_membership_assignments', {}))
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