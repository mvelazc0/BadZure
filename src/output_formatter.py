"""
Output formatting for BadZure.
Handles formatting and writing of attack path details and user files.
"""
import logging
from typing import Dict
from src.constants import API_REGISTRY


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
        attack_path_managed_identity_theft_assignments: Dict,
        attack_path_application_role_assignments: Dict,
        attack_path_app_api_permission_assignments: Dict,
        attack_path_user_role_assignments: Dict,
        user_creds: Dict,
        domain: str
    ) -> None:
        """Format and display attack paths for random mode."""
        logging.info("=" * 70)
        logging.info("ATTACK PATH DETAILS")
        logging.info("=" * 70)
        
        for attack_path_name, attack_path_data in config['attack_paths'].items():
            if not attack_path_data['enabled']:
                continue
            
            logging.info(f"*** {attack_path_name} ***")
            
            # Display based on privilege escalation type
            priv_esc = attack_path_data['privilege_escalation']
            
            # Support both old and new names
            if priv_esc in ['ServicePrincipalAbuse', 'ApplicationOwnershipAbuse']:
                # Find the matching assignment for this attack path
                for key, assignment in attack_path_application_owner_assignments.items():
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        if attack_path_name in user_creds:
                            logging.info(f"Initial Access Identity: User - {user_creds[attack_path_name]['user_principal_name']}")
                        logging.info(f"Owned Application: {assignment['app_name']}")
                        
                        # Show what privileges the application has
                        if key in attack_path_application_role_assignments:
                            role_info = attack_path_application_role_assignments[key]
                            role_ids_str = ', '.join(role_info['role_ids'])
                            logging.info(f"Application Privileges: Entra Role(s) - {role_ids_str}")
                        elif key in attack_path_app_api_permission_assignments:
                            perm_info = attack_path_app_api_permission_assignments[key]
                            api_type = perm_info.get('api_type', 'graph')
                            api_display = API_REGISTRY.get(api_type, {}).get('display_name', api_type)
                            perm_ids_str = ', '.join(perm_info['api_permission_ids'])
                            logging.info(f"Application Privileges: {api_display} - {perm_ids_str}")
                        logging.info("")  # Blank line after attack path
                        break
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                # Find the matching user role assignment for this attack path
                for key, assignment in attack_path_user_role_assignments.items():
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        if attack_path_name in user_creds:
                            logging.info(f"Initial Access Identity: User - {user_creds[attack_path_name]['user_principal_name']}")
                        logging.info(f"User Role: Application Administrator")
                        
                        # Find target application from app_roles or app_api_permissions
                        if key in attack_path_application_role_assignments:
                            role_info = attack_path_application_role_assignments[key]
                            target_app = role_info['app_name']
                            role_ids_str = ', '.join(role_info['role_ids'])
                            logging.info(f"Target Application: {target_app}")
                            logging.info(f"Application Privileges: Entra Role(s) - {role_ids_str}")
                        elif key in attack_path_app_api_permission_assignments:
                            perm_info = attack_path_app_api_permission_assignments[key]
                            target_app = perm_info['app_name']
                            api_type = perm_info.get('api_type', 'graph')
                            api_display = API_REGISTRY.get(api_type, {}).get('display_name', api_type)
                            perm_ids_str = ', '.join(perm_info['api_permission_ids'])
                            logging.info(f"Target Application: {target_app}")
                            logging.info(f"Application Privileges: {api_display} - {perm_ids_str}")
                        logging.info("")  # Blank line after attack path
                        break
            
            elif attack_path_data['privilege_escalation'] == 'KeyVaultSecretTheft':
                # Filter assignments to only show the one for this attack path
                for key, assignment in attack_path_kv_abuse_assignments.items():
                    # Check if this assignment belongs to the current attack path
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        identity_type = assignment['identity_type']
                        principal_name = assignment['principal_name']
                        key_vault = assignment['key_vault']
                        
                        if identity_type == "user":
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        elif identity_type == "service_principal":
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        
                        logging.info("")  # Blank line after attack path
                        # Only show one assignment per attack path
                        break
            
            elif attack_path_data['privilege_escalation'] == 'StorageCertificateTheft':
                # Filter assignments to only show the one for this attack path
                for key, assignment in attack_path_storage_abuse_assignments.items():
                    # Check if this assignment belongs to the current attack path
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        identity_type = assignment['identity_type']
                        principal_name = assignment['principal_name']
                        storage_account = assignment['storage_account']
                        
                        if identity_type == "user":
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        elif identity_type == "service_principal":
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        
                        logging.info("")  # Blank line after attack path
                        # Only show one assignment per attack path
                        break
            
            elif attack_path_data['privilege_escalation'] == 'ManagedIdentityTheft':
                # Filter assignments to only show the one for this attack path
                for key, assignment in attack_path_managed_identity_theft_assignments.items():
                    # Check if this assignment belongs to the current attack path
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        source_type = assignment['source_type']
                        source_name = assignment['source_name']
                        target_resource_type = assignment['target_resource_type']
                        target_name = assignment['target_name']
                        identity_type = assignment.get('identity_type', 'user')
                        initial_access_principal = assignment.get('initial_access_principal')
                        app_name = assignment.get('app_name')
                        managed_identity_name = assignment.get('managed_identity_name')
                        
                        # Get the appropriate role name based on source type
                        role_name = {
                            'vm': 'VM Contributor',
                            'logic_app': 'Logic App Contributor',
                            'automation_account': 'Automation Contributor',
                            'function_app': 'Website Contributor'
                        }.get(source_type, 'Contributor')
                        
                        # Display initial access identity based on identity_type
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {initial_access_principal}@{domain}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {initial_access_principal}")
                        
                        # Display source information
                        if source_type == 'vm':
                            logging.info(f"Source Resource: Virtual Machine - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'logic_app':
                            logging.info(f"Source Resource: Logic App - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'automation_account':
                            logging.info(f"Source Resource: Automation Account - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'function_app':
                            # Get OS type from assignment if available
                            os_type = assignment.get('os_type', 'linux')
                            os_display = f" ({os_type.capitalize()})" if os_type else ""
                            logging.info(f"Source Resource: Function App{os_display} - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        
                        # Display target information
                        if target_resource_type == 'key_vault':
                            logging.info(f"Target Resource: Key Vault - {target_name} (Key Vault Contributor)")
                        elif target_resource_type == 'storage_account':
                            logging.info(f"Target Resource: Storage Account - {target_name} (Storage Blob Data Reader)")
                        
                        # Display application with privileges
                        logging.info(f"Target Application: {app_name}")
                        
                        # Show what privileges the application has
                        if key in attack_path_application_role_assignments:
                            role_info = attack_path_application_role_assignments[key]
                            role_ids_str = ', '.join(role_info['role_ids'])
                            logging.info(f"Application Privileges: Entra Role(s) - {role_ids_str}")
                        elif key in attack_path_app_api_permission_assignments:
                            perm_info = attack_path_app_api_permission_assignments[key]
                            api_type = perm_info.get('api_type', 'graph')
                            api_display = API_REGISTRY.get(api_type, {}).get('display_name', api_type)
                            perm_ids_str = ', '.join(perm_info['api_permission_ids'])
                            logging.info(f"Application Privileges: {api_display} - {perm_ids_str}")
                        
                        logging.info("")  # Blank line after attack path
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
            
            elif priv_esc == 'KeyVaultSecretTheft':
                for key, assignment in assignments.get('kv_abuse', {}).items():
                    # Match the key to the path_name
                    if path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        identity_type = assignment['identity_type']
                        principal_name = assignment['principal_name']
                        key_vault = assignment['key_vault']
                        
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if principal_name in users:
                                logging.info(f"Password: {users[principal_name]['password']}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")
                        
                        logging.info(f"Target Application: {assignment['app_name']}")
                        break
            
            elif priv_esc == 'StorageCertificateTheft':
                for key, assignment in assignments.get('storage_abuse', {}).items():
                    # Match the key to the path_name
                    if path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        identity_type = assignment['identity_type']
                        principal_name = assignment['principal_name']
                        storage_account = assignment['storage_account']
                        
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if principal_name in users:
                                logging.info(f"Password: {users[principal_name]['password']}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")
                        
                        logging.info(f"Target Application: {assignment['app_name']}")
                        logging.info(f"Certificate stored in: {storage_account}/cert-container/")
                        break
            
            elif priv_esc == 'ManagedIdentityTheft':
                for key, assignment in assignments.get('managed_identity_theft', {}).items():
                    # Match the key to the path_name
                    if path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        logging.info(f"Privilege Escalation: ManagedIdentityTheft")
                        
                        source_type = assignment['source_type']
                        source_name = assignment['source_name']
                        target_resource_type = assignment['target_resource_type']
                        target_name = assignment['target_name']
                        identity_type = assignment.get('identity_type', 'user')
                        initial_access_principal = assignment.get('initial_access_principal')
                        app_name = assignment.get('app_name')
                        managed_identity_name = assignment.get('managed_identity_name')
                        
                        # Get the appropriate role name based on source type
                        role_name = {
                            'vm': 'VM Contributor',
                            'logic_app': 'Logic App Contributor',
                            'automation_account': 'Automation Contributor',
                            'function_app': 'Website Contributor'
                        }.get(source_type, 'Contributor')
                        
                        # Display initial access identity based on identity_type
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {initial_access_principal}@{domain}")
                            if initial_access_principal in users:
                                logging.info(f"Password: {users[initial_access_principal]['password']}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {initial_access_principal}")
                        
                        # Display source information
                        if source_type == 'vm':
                            logging.info(f"Source Resource: Virtual Machine - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'logic_app':
                            logging.info(f"Source Resource: Logic App - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'automation_account':
                            logging.info(f"Source Resource: Automation Account - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'function_app':
                            # Get OS type from assignment if available
                            os_type = assignment.get('os_type', 'linux')
                            os_display = f" ({os_type.capitalize()})" if os_type else ""
                            logging.info(f"Source Resource: Function App{os_display} - {source_name} (with {role_name})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        
                        # Display target information
                        if target_resource_type == 'key_vault':
                            logging.info(f"Target Resource: Key Vault - {target_name} (Key Vault Contributor)")
                        elif target_resource_type == 'storage_account':
                            logging.info(f"Target Resource: Storage Account - {target_name} (Storage Blob Data Reader)")
                        
                        # Display application with privileges
                        logging.info(f"Target Application: {app_name}")
                        
                        # Show certificate location for storage accounts
                        if target_resource_type == 'storage_account':
                            logging.info(f"Certificate stored in: {target_name}/cert-container/")
                        break
        
        logging.info("\n" + "=" * 60)