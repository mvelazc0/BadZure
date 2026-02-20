"""
Terraform management for BadZure.
Handles all Terraform operations and variable building.
"""
import os
import json
import logging
from typing import Dict, Tuple
from python_terraform import Terraform


class TerraformManager:
    """Manages Terraform operations."""
    
    def __init__(self, terraform_dir: str = "terraform"):
        self.terraform_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), terraform_dir)
        self.tf = Terraform(working_dir=self.terraform_dir)
    
    def init(self) -> Tuple[int, str, str]:
        """Initialize Terraform."""
        return self.tf.init()
    
    def apply(self, verbose: bool = False) -> Tuple[int, str, str]:
        """Apply Terraform configuration."""
        return self.tf.apply(skip_plan=True, capture_output=not verbose)
    
    def destroy(self, verbose: bool = False) -> Tuple[int, str, str]:
        """Destroy Terraform resources."""
        return self.tf.apply(skip_plan=True, destroy=True, auto_approve=True, capture_output=not verbose)
    
    def show(self, verbose: bool = False) -> Tuple[int, str, str]:
        """Show Terraform state."""
        return self.tf.show(json=True, capture_output=not verbose)

    def get_outputs(self) -> Dict:
        """Get Terraform outputs as a dictionary."""
        return_code, stdout, stderr = self.tf.cmd('output', '-json')
        if return_code != 0:
            logging.warning(f"Failed to get Terraform outputs: {stderr}")
            return {}
        try:
            raw = json.loads(stdout)
            # Terraform output -json wraps each output in {value: ..., type: ..., sensitive: ...}
            return {k: v.get('value') for k, v in raw.items()}
        except (json.JSONDecodeError, AttributeError):
            logging.warning("Failed to parse Terraform output JSON")
            return {}
    
    def build_terraform_vars(
        self,
        tenant_id: str,
        domain: str,
        subscription_id: str,
        public_ip: str,
        azure_config_dir: str,
        users: Dict,
        groups: Dict,
        applications: Dict,
        administrative_units: Dict,
        resource_groups: Dict,
        key_vaults: Dict,
        storage_accounts: Dict,
        virtual_machines: Dict,
        logic_apps: Dict,
        automation_accounts: Dict,
        function_apps: Dict,
        cosmos_dbs: Dict,
        user_group_assignments: Dict,
        user_au_assignments: Dict,
        user_role_assignments: Dict,
        app_role_assignments: Dict,
        app_api_permission_assignments: Dict,
        attack_path_application_owner_assignments: Dict,
        attack_path_user_role_assignments: Dict,
        attack_path_application_role_assignments: Dict,
        attack_path_application_api_permission_assignments: Dict,
        attack_path_kv_abuse_assignments: Dict,
        attack_path_storage_abuse_assignments: Dict,
        attack_path_managed_identity_theft_assignments: Dict,
        attack_path_vm_contributor_assignments: Dict,
        attack_path_cosmos_abuse_assignments: Dict = None,
        attack_path_group_memberships: Dict = None,
        attack_path_compromised_sp_credentials: Dict = None
    ) -> Dict:
        """
        Build Terraform variables dictionary.
        
        Args:
            attack_path_group_memberships: Group membership assignments for attack paths.
                                          Maps attack path keys to group membership info.
        
        Returns:
            Dictionary of Terraform variables
        """
        # Initialize optional parameters
        attack_path_cosmos_abuse_assignments = attack_path_cosmos_abuse_assignments or {}
        attack_path_group_memberships = attack_path_group_memberships or {}
        attack_path_compromised_sp_credentials = attack_path_compromised_sp_credentials or {}
        
        # Convert entity dictionaries to Terraform format
        user_vars = {user['user_principal_name']: user for user in users.values()}
        group_vars = {group['display_name']: group for group in groups.values()}
        application_vars = {app['display_name']: app for app in applications.values()}
        administrative_unit_vars = {au['display_name']: au for au in administrative_units.values()}
        
        tf_vars = {
            # Environment
            'tenant_id': tenant_id,
            'domain': domain,
            'public_ip': public_ip,
            'subscription_id': subscription_id,
            
            # Entities
            'users': user_vars,
            'azure_config_dir': azure_config_dir,
            'groups': group_vars,
            'applications': application_vars,
            'administrative_units': administrative_unit_vars,
            
            # ARM Resources
            'resource_groups': resource_groups,
            'key_vaults': key_vaults,
            'storage_accounts': storage_accounts,
            'virtual_machines': virtual_machines,
            'logic_apps': logic_apps,
            'automation_accounts': automation_accounts,
            'function_apps': function_apps,
            'cosmos_dbs': cosmos_dbs,
            
            # Assignments
            'user_group_assignments': user_group_assignments,
            'user_au_assignments': user_au_assignments,
            'user_role_assignments': user_role_assignments,
            'app_role_assignments': app_role_assignments,
            'app_api_permission_assignments': app_api_permission_assignments,
            
            # Attack Paths
            'attack_path_application_owner_assignments': attack_path_application_owner_assignments,
            'attack_path_user_role_assignments': attack_path_user_role_assignments,
            'attack_path_application_role_assignments': attack_path_application_role_assignments,
            'attack_path_application_api_permission_assignments': attack_path_application_api_permission_assignments,
            'attack_path_kv_abuse_assignments': attack_path_kv_abuse_assignments,
            'attack_path_storage_abuse_assignments': attack_path_storage_abuse_assignments,
            'attack_path_managed_identity_theft_assignments': attack_path_managed_identity_theft_assignments,
            'attack_path_cosmos_abuse_assignments': attack_path_cosmos_abuse_assignments,
            'attack_path_vm_contributor_assignments': attack_path_vm_contributor_assignments,
            'attack_path_group_memberships': attack_path_group_memberships,
            'attack_path_compromised_sp_credentials': attack_path_compromised_sp_credentials
        }
        
        return tf_vars
    
    def write_terraform_vars(self, tf_vars: Dict) -> None:
        """Write Terraform variables to file."""
        tfvars_path = os.path.join(self.terraform_dir, 'terraform.tfvars.json')
        logging.info("Creating terraform.tfvars.json")
        with open(tfvars_path, 'w') as f:
            json.dump(tf_vars, f, indent=4)
    
    def cleanup_state_files(self) -> None:
        """Remove Terraform state files and generated certificates."""
        logging.info("Deleting terraform state files")
        for file in ["terraform.tfstate", "terraform.tfstate.backup", "terraform.tfvars.json"]:
            try:
                os.remove(os.path.join(self.terraform_dir, file))
            except FileNotFoundError:
                pass
        
        # Clean up generated certificate and key files
        logging.info("Deleting generated certificates and keys")
        try:
            for file in os.listdir(self.terraform_dir):
                if file.endswith('.pem') or file.endswith('.key'):
                    file_path = os.path.join(self.terraform_dir, file)
                    try:
                        os.remove(file_path)
                        logging.debug(f"Deleted {file}")
                    except Exception as e:
                        logging.warning(f"Failed to delete {file}: {e}")
        except Exception as e:
            logging.warning(f"Error cleaning up certificates: {e}")
    
    def parse_terraform_output(self, output: str) -> list:
        """
        Parse Terraform state output and extract essential information.
        
        Args:
            output: JSON output from terraform show
            
        Returns:
            List of resource descriptions
        """
        resources = []
        
        try:
            state = json.loads(output)
            for module in state.get('values', {}).get('root_module', {}).get('resources', []):
                resource_type = module.get('type')
                resource_name = module.get('name')
                
                # Skip certain resource types
                if resource_type in ['azuread_domains', 'azuread_administrative_unit_member',
                                    'azuread_group_member', 'azuread_directory_role_assignment']:
                    continue
                
                # Extract key attribute based on resource type
                if resource_type == 'azuread_user':
                    key_attr = module.get('values', {}).get('user_principal_name')
                elif resource_type == 'azuread_group':
                    key_attr = module.get('values', {}).get('display_name')
                elif resource_type == 'azuread_application_registration':
                    key_attr = module.get('values', {}).get('display_name')
                elif resource_type == 'azuread_administrative_unit':
                    key_attr = module.get('values', {}).get('display_name')
                elif resource_type == 'azuread_service_principal':
                    key_attr = module.get('values', {}).get('id')
                else:
                    key_attr = "N/A"
                
                resources.append(f"Resource Type: {resource_type}, Identifier: {key_attr}")
        
        except json.JSONDecodeError:
            logging.error("Failed to parse Terraform state output")
        
        return resources