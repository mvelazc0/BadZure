"""
Output formatting for BadZure.
Handles formatting and writing of attack path details and user files.
"""
import logging
from typing import Dict


class OutputFormatter:
    """Formats and writes output for BadZure."""
    
    def write_users_file(self, users: Dict, domain: str, file_path: str = 'users.txt') -> None:
        """
        Write users to a file.
        
        Args:
            users: Dictionary of users
            domain: Domain name
            file_path: Path to output file
        """
        with open(file_path, 'w') as file:
            for user in users.values():
                file.write(f"{user['user_principal_name']}@{domain}\n")
        logging.info(f"Created {file_path} file")
    
    def format_random_mode_attack_paths(
        self,
        config: Dict,
        attack_path_application_owner_assignments: Dict,
        attack_path_kv_abuse_assignments: Dict,
        attack_path_storage_abuse_assignments: Dict,
        user_creds: Dict,
        domain: str
    ) -> None:
        """Format and display attack paths for random mode."""
        logging.info("Attack Path Details")
        
        for attack_path_name, attack_path_data in config['attack_paths'].items():
            if not attack_path_data['enabled']:
                continue
            
            logging.info(f"*** {attack_path_name} ***")
            
            # Display based on privilege escalation type
            priv_esc = attack_path_data['privilege_escalation']
            
            # Support both old and new names
            if priv_esc in ['ServicePrincipalAbuse', 'ApplicationOwnershipAbuse', 'ApplicationAdministratorAbuse']:
                if attack_path_application_owner_assignments:
                    attack_path_id = list(attack_path_application_owner_assignments.keys())[0].split('-')[-1]
                    logging.info(f"Attack Path ID: attack-path-{attack_path_id}")
                    if attack_path_name in user_creds:
                        logging.info(f"Initial Access Identity: User - {user_creds[attack_path_name]['user_principal_name']}")
            
            elif attack_path_data['privilege_escalation'] == 'KeyVaultAbuse':
                # Filter assignments to only show the one for this attack path
                for key, assignment in attack_path_kv_abuse_assignments.items():
                    # Check if this assignment belongs to the current attack path
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        principal_type = assignment['principal_type']
                        principal_name = assignment['principal_name']
                        key_vault = assignment['key_vault']
                        
                        if principal_type == "user":
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        elif principal_type == "service_principal":
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        elif principal_type == "managed_identity":
                            vm_name = assignment['virtual_machine']
                            initial_user = assignment.get('initial_access_user')
                            logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                            logging.info(f"Target Managed Identity: {vm_name}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        
                        # Only show one assignment per attack path
                        break
            
            elif attack_path_data['privilege_escalation'] == 'StorageAccountAbuse':
                # Filter assignments to only show the one for this attack path
                for key, assignment in attack_path_storage_abuse_assignments.items():
                    # Check if this assignment belongs to the current attack path
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        principal_type = assignment['principal_type']
                        principal_name = assignment['principal_name']
                        storage_account = assignment['storage_account']
                        
                        if principal_type == "user":
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        elif principal_type == "service_principal":
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        elif principal_type == "managed_identity":
                            vm_name = assignment['virtual_machine']
                            initial_user = assignment.get('initial_access_user')
                            logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                            logging.info(f"Target Managed Identity: {vm_name}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        
                        # Only show one assignment per attack path
                        break
    
    def format_targeted_mode_attack_paths(
        self,
        config: Dict,
        assignments: Dict,
        users: Dict,
        domain: str
    ) -> None:
        """Format and display attack paths for targeted mode."""
        logging.info("=" * 60)
        logging.info("TARGETED ATTACK PATH DETAILS")
        logging.info("=" * 60)
        
        user_creds = assignments.get('user_creds', {})
        
        for path_name, path_config in config['attack_paths'].items():
            if not path_config.get('enabled', False):
                continue
            
            logging.info(f"\n*** {path_name} ***")
            description = path_config.get('description', 'N/A')
            if description != 'N/A':
                logging.info(f"Description: {description}")
            
            priv_esc = path_config.get('privilege_escalation')
            
            # Support both old and new names
            if priv_esc in ['ServicePrincipalAbuse', 'ApplicationOwnershipAbuse']:
                for key, assignment in assignments.get('app_owners', {}).items():
                    # Match the key to the path_name
                    if path_name in key and path_name in user_creds:
                        logging.info(f"Attack Path ID: {key}")
                        logging.info(f"Privilege Escalation: {priv_esc}")
                        logging.info(f"Initial Access Identity: User - {user_creds[path_name]['user_principal_name']}")
                        logging.info(f"Password: {user_creds[path_name]['password']}")
                        logging.info(f"Owned Application: {assignment['app_name']}")
                        
                        if key in assignments.get('app_roles', {}):
                            logging.info(f"Application Privileges: Entra Role(s)")
                        elif key in assignments.get('app_api_permissions', {}):
                            logging.info(f"Application Privileges: API Permission(s)")
                        break
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                # ApplicationAdministratorAbuse doesn't use app_owners, only user_roles
                if path_name in user_creds:
                    # Find the matching key in user_roles
                    for key in assignments.get('user_roles', {}).keys():
                        if path_name in key:
                            logging.info(f"Attack Path ID: {key}")
                            logging.info(f"Privilege Escalation: ApplicationAdministratorAbuse")
                            logging.info(f"Initial Access Identity: User - {user_creds[path_name]['user_principal_name']}")
                            logging.info(f"Password: {user_creds[path_name]['password']}")
                            logging.info(f"User Role: Application Administrator")
                            
                            # Find target application from app_roles or app_api_permissions
                            if key in assignments.get('app_roles', {}):
                                target_app = assignments['app_roles'][key]['app_name']
                                logging.info(f"Target Application: {target_app}")
                                logging.info(f"Application Privileges: Entra Role(s)")
                            elif key in assignments.get('app_api_permissions', {}):
                                target_app = assignments['app_api_permissions'][key]['app_name']
                                logging.info(f"Target Application: {target_app}")
                                logging.info(f"Application Privileges: API Permission(s)")
                            break
            
            elif priv_esc == 'KeyVaultAbuse':
                for key, assignment in assignments.get('kv_abuse', {}).items():
                    # Match the key to the path_name
                    if path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        principal_type = assignment['principal_type']
                        principal_name = assignment['principal_name']
                        key_vault = assignment['key_vault']
                        
                        if principal_type == 'user':
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if principal_name in users:
                                logging.info(f"Password: {users[principal_name]['password']}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        elif principal_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        elif principal_type == 'managed_identity':
                            vm_name = assignment['virtual_machine']
                            initial_user = assignment.get('initial_access_user')
                            logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                            if initial_user in users:
                                logging.info(f"Password: {users[initial_user]['password']}")
                            logging.info(f"Target Managed Identity: {vm_name}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        
                        logging.info(f"Target Application: {assignment['app_name']}")
                        break
            
            elif priv_esc == 'StorageAccountAbuse':
                for key, assignment in assignments.get('storage_abuse', {}).items():
                    # Match the key to the path_name
                    if path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        principal_type = assignment['principal_type']
                        principal_name = assignment['principal_name']
                        storage_account = assignment['storage_account']
                        
                        if principal_type == 'user':
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if principal_name in users:
                                logging.info(f"Password: {users[principal_name]['password']}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        elif principal_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        elif principal_type == 'managed_identity':
                            vm_name = assignment['virtual_machine']
                            initial_user = assignment.get('initial_access_user')
                            logging.info(f"Initial Access Identity: User - {initial_user}@{domain} (with VM Contributor on {vm_name})")
                            if initial_user in users:
                                logging.info(f"Password: {users[initial_user]['password']}")
                            logging.info(f"Target Managed Identity: {vm_name}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        
                        logging.info(f"Target Application: {assignment['app_name']}")
                        logging.info(f"Certificate stored in: {storage_account}/cert-container/")
                        break
        
        logging.info("\n" + "=" * 60)