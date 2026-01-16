"""
CLI command handlers for BadZure.
Implements build, show, and destroy commands.
"""
import os
import logging
from typing import Dict
from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.assignment_manager import AssignmentManager
from src.attack_path_manager import AttackPathManager
from src.terraform_manager import TerraformManager
from src.output_formatter import OutputFormatter
import src.utils as utils


class BuildCommand:
    """Handles the build command to create vulnerable tenants."""
    
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
        azure_config_dir = os.path.expanduser('~/.azure')
        os.environ['AZURE_CONFIG_DIR'] = azure_config_dir
        
        tenant_id = config['tenant']['tenant_id']
        subscription_id = config['tenant']['subscription_id']
        domain = config['tenant']['domain']
        
        max_users = config['tenant']['users']
        max_groups = config['tenant']['groups']
        max_apps = config['tenant']['applications']
        max_aunits = config['tenant']['administrative_units']
        max_rgroups = config['tenant']['resource_groups']
        max_kvs = config['tenant']['key_vaults']
        max_sas = config['tenant']['storage_accounts']
        max_vms = config['tenant']['virtual_machines']
        
        public_ip = utils.get_public_ip()
        
        # Generate entities
        logging.info(f"Generating {max_users} random users")
        users = self.generator.generate_users(max_users)
        
        logging.info(f"Generating {max_groups} random groups")
        groups = self.generator.generate_groups(max_groups)
        
        logging.info(f"Generating {max_apps} random application registrations/service principals")
        applications = self.generator.generate_applications(max_apps)
        
        logging.info(f"Generating {max_aunits} random administrative units")
        administrative_units = self.generator.generate_administrative_units(max_aunits)
        
        logging.info(f"Generating {max_rgroups} resource groups")
        resource_groups = self.generator.generate_resource_groups(max_rgroups)
        
        logging.info(f"Generating {max_kvs} key vaults")
        key_vaults = self.generator.generate_key_vaults(max_kvs, resource_groups)
        
        logging.info(f"Generating {max_sas} storage accounts")
        storage_accounts = self.generator.generate_storage_accounts(max_sas, resource_groups)
        
        logging.info(f"Generating {max_vms} virtual machines")
        virtual_machines = self.generator.generate_virtual_machines(max_vms, resource_groups)
        
        # Create random assignments
        (user_group_assignments, user_au_assignments, user_role_assignments,
         app_role_assignments, app_api_permission_assignments) = \
            self.assignment_mgr.create_random_assignments(users, groups, administrative_units, applications)
        
        # Create attack paths
        attack_path_application_owner_assignments = {}
        attack_path_user_role_assignments = {}
        attack_path_application_role_assignments = {}
        attack_path_app_api_permission_assignments = {}
        attack_path_kv_abuse_assignments = {}
        attack_path_storage_abuse_assignments = {}
        attack_path_vm_contributor_assignments = {}
        user_creds = {}
        
        for attack_path_name, attack_path_data in config['attack_paths'].items():
            if not attack_path_data['enabled']:
                continue
            
            # Support both old and new names with deprecation warning
            priv_esc = attack_path_data['privilege_escalation']
            
            if priv_esc == 'ServicePrincipalAbuse':
                logging.warning(f"{attack_path_name}: 'ServicePrincipalAbuse' is deprecated. Please use 'ApplicationOwnershipAbuse' instead.")
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                (initial_access, ap_app_owner, ap_user_role, ap_app_role,
                 ap_app_api_permission) = self.attack_path_mgr.create_application_ownership_abuse(
                    attack_path_data, users, applications, domain, mode='random'
                )
                attack_path_application_owner_assignments.update(ap_app_owner)
                attack_path_user_role_assignments.update(ap_user_role)
                attack_path_application_role_assignments.update(ap_app_role)
                attack_path_app_api_permission_assignments.update(ap_app_api_permission)
                user_creds[attack_path_name] = initial_access
            
            elif priv_esc == 'ApplicationOwnershipAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                (initial_access, ap_app_owner, ap_user_role, ap_app_role,
                 ap_app_api_permission) = self.attack_path_mgr.create_application_ownership_abuse(
                    attack_path_data, users, applications, domain, mode='random'
                )
                attack_path_application_owner_assignments.update(ap_app_owner)
                attack_path_user_role_assignments.update(ap_user_role)
                attack_path_application_role_assignments.update(ap_app_role)
                attack_path_app_api_permission_assignments.update(ap_app_api_permission)
                user_creds[attack_path_name] = initial_access
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                logging.info(f"Creating assignments for attack path '{attack_path_name}'")
                (initial_access, ap_user_role, ap_app_role,
                 ap_app_api_permission) = self.attack_path_mgr.create_application_administrator_abuse(
                    attack_path_data, users, applications, domain, mode='random'
                )
                attack_path_user_role_assignments.update(ap_user_role)
                attack_path_application_role_assignments.update(ap_app_role)
                attack_path_app_api_permission_assignments.update(ap_app_api_permission)
                user_creds[attack_path_name] = initial_access
            
            elif attack_path_data['privilege_escalation'] == 'KeyVaultAbuse':
                (kv_abuse, kv_app_role, kv_app_api_permission,
                 kv_vm_contributor) = self.attack_path_mgr.create_keyvault_abuse(
                    attack_path_data, applications, key_vaults, users, applications,
                    virtual_machines, mode='random'
                )
                attack_path_kv_abuse_assignments.update(kv_abuse)
                attack_path_application_role_assignments.update(kv_app_role)
                attack_path_app_api_permission_assignments.update(kv_app_api_permission)
                attack_path_vm_contributor_assignments.update(kv_vm_contributor)
            
            elif attack_path_data['privilege_escalation'] == 'StorageAccountAbuse':
                (sa_abuse, sa_app_role, sa_app_api_permission,
                 sa_vm_contributor) = self.attack_path_mgr.create_storage_account_abuse(
                    attack_path_data, applications, storage_accounts, users, applications,
                    virtual_machines, mode='random'
                )
                attack_path_storage_abuse_assignments.update(sa_abuse)
                attack_path_application_role_assignments.update(sa_app_role)
                attack_path_app_api_permission_assignments.update(sa_app_api_permission)
                attack_path_vm_contributor_assignments.update(sa_vm_contributor)
        
        # Build and write Terraform variables
        tf_vars = self.terraform_mgr.build_terraform_vars(
            tenant_id, domain, subscription_id, public_ip, azure_config_dir,
            users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines,
            user_group_assignments, user_au_assignments, user_role_assignments,
            app_role_assignments, app_api_permission_assignments,
            attack_path_application_owner_assignments, attack_path_user_role_assignments,
            attack_path_application_role_assignments, attack_path_app_api_permission_assignments,
            attack_path_kv_abuse_assignments, attack_path_storage_abuse_assignments,
            attack_path_vm_contributor_assignments
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
        
        logging.info("Azure AD tenant setup completed with assigned permissions and configurations!")
        self.output_formatter.write_users_file(users, domain)
        self.output_formatter.format_random_mode_attack_paths(
            config, attack_path_application_owner_assignments,
            attack_path_kv_abuse_assignments, attack_path_storage_abuse_assignments,
            user_creds, domain
        )
        logging.info("Good bye.")
    
    def _build_targeted_mode(self, config: Dict, verbose: bool) -> None:
        """Build in targeted mode."""
        # Validate targeted configuration
        is_valid, errors = self.config_mgr.validate_targeted_config(config)
        if not is_valid:
            logging.error("Configuration validation failed:")
            for error in errors:
                logging.error(f"  - {error}")
            return
        
        azure_config_dir = os.path.expanduser('~/.azure')
        os.environ['AZURE_CONFIG_DIR'] = azure_config_dir
        
        tenant_id = config['tenant']['tenant_id']
        subscription_id = config['tenant']['subscription_id']
        domain = config['tenant']['domain']
        public_ip = utils.get_public_ip()
        
        # Collect entities from attack paths
        logging.info("Collecting entities from attack paths")
        all_entities = self._collect_entities_from_attack_paths(config)
        
        # Generate entities
        logging.info("Generating entity details")
        users = self.generator.generate_users_targeted(all_entities.get('users', []))
        groups = self.generator.generate_groups_targeted(all_entities.get('groups', []))
        applications = self.generator.generate_applications_targeted(all_entities.get('applications', []))
        administrative_units = self.generator.generate_administrative_units_targeted(
            all_entities.get('administrative_units', [])
        )
        resource_groups = self.generator.generate_resource_groups_targeted(
            all_entities.get('resource_groups', [])
        )
        key_vaults = self.generator.generate_key_vaults_targeted(
            all_entities.get('key_vaults', []), resource_groups
        )
        storage_accounts = self.generator.generate_storage_accounts_targeted(
            all_entities.get('storage_accounts', []), resource_groups
        )
        virtual_machines = self.generator.generate_virtual_machines_targeted(
            all_entities.get('virtual_machines', []), resource_groups
        )
        
        # Create targeted attack path assignments
        logging.info("Creating attack path assignments")
        attack_path_assignments = self._create_targeted_assignments(
            config, users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines, domain
        )
        
        # Build and write Terraform variables
        tf_vars = self.terraform_mgr.build_terraform_vars(
            tenant_id, domain, subscription_id, public_ip, azure_config_dir,
            users, groups, applications, administrative_units,
            resource_groups, key_vaults, storage_accounts, virtual_machines,
            {}, {}, {}, {}, {},  # Empty random assignments
            attack_path_assignments.get('app_owners', {}),
            attack_path_assignments.get('user_roles', {}),
            attack_path_assignments.get('app_roles', {}),
            attack_path_assignments.get('app_api_permissions', {}),
            attack_path_assignments.get('kv_abuse', {}),
            attack_path_assignments.get('storage_abuse', {}),
            attack_path_assignments.get('vm_contributor', {})
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
        
        logging.info("Azure AD tenant setup completed!")
        self.output_formatter.write_users_file(users, domain)
        self.output_formatter.format_targeted_mode_attack_paths(config, attack_path_assignments, users, domain)
    
    def _create_targeted_assignments(
        self, config: Dict, users: Dict, groups: Dict, applications: Dict,
        administrative_units: Dict, resource_groups: Dict, key_vaults: Dict,
        storage_accounts: Dict, virtual_machines: Dict, domain: str
    ) -> Dict:
        """Create targeted attack path assignments using consolidated AttackPathManager."""
        assignments = {
            'app_owners': {},
            'user_roles': {},
            'app_roles': {},
            'app_api_permissions': {},
            'kv_abuse': {},
            'storage_abuse': {},
            'vm_contributor': {}
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
                (initial_access, ap_app_owner, ap_user_role, ap_app_role,
                 ap_app_api_permission) = self.attack_path_mgr.create_application_ownership_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['app_owners'].update(ap_app_owner)
                assignments['user_roles'].update(ap_user_role)
                assignments['app_roles'].update(ap_app_role)
                assignments['app_api_permissions'].update(ap_app_api_permission)
                user_creds[path_name] = initial_access
            
            elif priv_esc == 'ApplicationOwnershipAbuse':
                (initial_access, ap_app_owner, ap_user_role, ap_app_role,
                 ap_app_api_permission) = self.attack_path_mgr.create_application_ownership_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['app_owners'].update(ap_app_owner)
                assignments['user_roles'].update(ap_user_role)
                assignments['app_roles'].update(ap_app_role)
                assignments['app_api_permissions'].update(ap_app_api_permission)
                user_creds[path_name] = initial_access
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                (initial_access, ap_user_role, ap_app_role,
                 ap_app_api_permission) = self.attack_path_mgr.create_application_administrator_abuse(
                    path_config, users, applications, domain,
                    mode='targeted', entities=entities, path_name=path_name
                )
                assignments['user_roles'].update(ap_user_role)
                assignments['app_roles'].update(ap_app_role)
                assignments['app_api_permissions'].update(ap_app_api_permission)
                user_creds[path_name] = initial_access
            
            elif priv_esc == 'KeyVaultAbuse':
                (kv_abuse, kv_app_role, kv_app_api_permission,
                 kv_vm_contributor) = self.attack_path_mgr.create_keyvault_abuse(
                    path_config, applications, key_vaults, users, applications,
                    virtual_machines, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['kv_abuse'].update(kv_abuse)
                assignments['app_roles'].update(kv_app_role)
                assignments['app_api_permissions'].update(kv_app_api_permission)
                assignments['vm_contributor'].update(kv_vm_contributor)
            
            elif priv_esc == 'StorageAccountAbuse':
                (sa_abuse, sa_app_role, sa_app_api_permission,
                 sa_vm_contributor) = self.attack_path_mgr.create_storage_account_abuse(
                    path_config, applications, storage_accounts, users, applications,
                    virtual_machines, mode='targeted', entities=entities, path_name=path_name
                )
                assignments['storage_abuse'].update(sa_abuse)
                assignments['app_roles'].update(sa_app_role)
                assignments['app_api_permissions'].update(sa_app_api_permission)
                assignments['vm_contributor'].update(sa_vm_contributor)
        
        # Store user credentials for output
        assignments['user_creds'] = user_creds
        
        return assignments
        logging.info("Good bye.")
    
    def _collect_entities_from_attack_paths(self, config: Dict) -> Dict:
        """Collect all entities from enabled attack paths."""
        all_entities = {
            'users': [], 'groups': [], 'applications': [], 'administrative_units': [],
            'resource_groups': [], 'key_vaults': [], 'storage_accounts': [], 'virtual_machines': []
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
        
        return all_entities


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