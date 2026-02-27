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
        attack_path_cosmos_abuse_assignments: Dict,
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
                        
                        # Display initial access based on initial_access
                        if attack_path_name in user_creds:
                            creds = user_creds[attack_path_name]
                            identity_type = creds.get('initial_access', 'user')
                            if identity_type == 'user':
                                logging.info(f"Initial Access Identity: User - {creds.get('user_principal_name', 'N/A')}")
                                if 'password' in creds:
                                    logging.info(f"Password: {creds['password']}")
                            elif identity_type == 'service_principal':
                                logging.info(f"Initial Access Identity: Service Principal - {creds.get('service_principal_name', 'N/A')}")
                                if 'client_id' in creds:
                                    logging.info(f"Client ID: {creds['client_id']}")
                                if 'client_secret' in creds:
                                    logging.info(f"Client Secret: {creds['client_secret']}")

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
            
            elif priv_esc in ['ApplicationAdministratorAbuse', 'CloudAppAdministratorAbuse']:
                role_display_name = "Cloud Application Administrator" if priv_esc == 'CloudAppAdministratorAbuse' else "Application Administrator"
                # Find the matching user role assignment for this attack path
                for key, assignment in attack_path_user_role_assignments.items():
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")

                        # Display initial access based on initial_access
                        if attack_path_name in user_creds:
                            creds = user_creds[attack_path_name]
                            identity_type = creds.get('initial_access', 'user')
                            if identity_type == 'user':
                                logging.info(f"Initial Access Identity: User - {creds.get('user_principal_name', 'N/A')}")
                                if 'password' in creds:
                                    logging.info(f"Password: {creds['password']}")
                            elif identity_type == 'service_principal':
                                logging.info(f"Initial Access Identity: Service Principal - {creds.get('service_principal_name', 'N/A')}")
                                if 'client_id' in creds:
                                    logging.info(f"Client ID: {creds['client_id']}")
                                if 'client_secret' in creds:
                                    logging.info(f"Client Secret: {creds['client_secret']}")

                        # Show group assignment details if applicable
                        assignment_type = assignment.get('assignment_type', 'direct')
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', assignment.get('principal_name', 'N/A'))
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                            logging.info(f"Principal Role: {role_display_name} (via Group)")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', assignment.get('principal_name', 'N/A'))
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 {role_display_name}")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")
                            logging.info(f"Principal Role: {role_display_name} (via Group)")
                        else:
                            logging.info(f"Principal Role: {role_display_name}")

                        # Display role scope
                        scope_app = assignment.get('scope_app_name')
                        if scope_app:
                            logging.info(f"Role Scope: Application ({scope_app})")
                        else:
                            logging.info(f"Role Scope: Directory (tenant-wide)")

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
                        
                        identity_type = assignment['initial_access']
                        principal_name = assignment['principal_name']
                        key_vault = assignment['key_vault']
                        assignment_type = assignment.get('assignment_type', 'direct')
                        
                        if identity_type == "user":
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if attack_path_name in user_creds and 'password' in user_creds[attack_path_name]:
                                logging.info(f"Password: {user_creds[attack_path_name]['password']}")
                        elif identity_type == "service_principal":
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            if attack_path_name in user_creds:
                                sp_creds = user_creds[attack_path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor via Group)")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 KeyVaultSecretTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor via Group)")
                        else:
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")

                        # Show target application and privileges
                        app_name = assignment.get('app_name')
                        if app_name:
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

            elif attack_path_data['privilege_escalation'] == 'StorageCertificateTheft':
                # Filter assignments to only show the one for this attack path
                for key, assignment in attack_path_storage_abuse_assignments.items():
                    # Check if this assignment belongs to the current attack path
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        identity_type = assignment['initial_access']
                        principal_name = assignment['principal_name']
                        storage_account = assignment['storage_account']
                        assignment_type = assignment.get('assignment_type', 'direct')
                        
                        if identity_type == "user":
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if attack_path_name in user_creds and 'password' in user_creds[attack_path_name]:
                                logging.info(f"Password: {user_creds[attack_path_name]['password']}")
                        elif identity_type == "service_principal":
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            if attack_path_name in user_creds:
                                sp_creds = user_creds[attack_path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader via Group)")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 StorageCertificateTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader via Group)")
                        else:
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")

                        # Show target application and privileges
                        app_name = assignment.get('app_name')
                        if app_name:
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

            elif attack_path_data['privilege_escalation'] == 'CosmosDBSecretTheft':
                # Filter assignments to only show the one for this attack path
                for key, assignment in attack_path_cosmos_abuse_assignments.items():
                    if attack_path_name in key:
                        logging.info(f"Attack Path ID: {key}")

                        identity_type = assignment['initial_access']
                        principal_name = assignment['principal_name']
                        cosmos_db = assignment['cosmos_db']
                        assignment_type = assignment.get('assignment_type', 'direct')

                        if identity_type == "user":
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if attack_path_name in user_creds and 'password' in user_creds[attack_path_name]:
                                logging.info(f"Password: {user_creds[attack_path_name]['password']}")
                        elif identity_type == "service_principal":
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            if attack_path_name in user_creds:
                                sp_creds = user_creds[attack_path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                            logging.info(f"Cosmos DB Access: {cosmos_db} (Data Contributor via Group)")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 CosmosDBSecretTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")
                            logging.info(f"Cosmos DB Access: {cosmos_db} (Data Contributor via Group)")
                        else:
                            logging.info(f"Cosmos DB Access: {cosmos_db} (Data Contributor)")

                        # Show target application and privileges
                        app_name = assignment.get('app_name')
                        if app_name:
                            logging.info(f"Target Application: {app_name}")

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
                        identity_type = assignment.get('initial_access', 'user')
                        initial_access_principal = assignment.get('initial_access_principal')
                        app_name = assignment.get('app_name')
                        managed_identity_name = assignment.get('managed_identity_name')
                        assignment_type = assignment.get('assignment_type', 'direct')
                        
                        # Get the appropriate role name based on source type
                        role_name = {
                            'vm': 'VM Contributor',
                            'logic_app': 'Logic App Contributor',
                            'automation_account': 'Automation Contributor',
                            'function_app': 'Website Contributor'
                        }.get(source_type, 'Contributor')
                        
                        # Display initial access identity based on initial_access
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {initial_access_principal}@{domain}")
                            if attack_path_name in user_creds and 'password' in user_creds[attack_path_name]:
                                logging.info(f"Password: {user_creds[attack_path_name]['password']}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {initial_access_principal}")
                            if attack_path_name in user_creds:
                                sp_creds = user_creds[attack_path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', initial_access_principal)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', initial_access_principal)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 ManagedIdentityTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")

                        # Display source information with role (via Group if applicable)
                        role_suffix = " via Group" if assignment_type in ('group_member', 'group_owner') else ""
                        if source_type == 'vm':
                            logging.info(f"Source Resource: Virtual Machine - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'logic_app':
                            logging.info(f"Source Resource: Logic App - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'automation_account':
                            logging.info(f"Source Resource: Automation Account - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'function_app':
                            # Get OS type from assignment if available
                            os_type = assignment.get('os_type', 'linux')
                            os_display = f" ({os_type.capitalize()})" if os_type else ""
                            logging.info(f"Source Resource: Function App{os_display} - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")

                        # Display target information
                        if target_resource_type == 'key_vault':
                            logging.info(f"Target Resource: Key Vault - {target_name} (Key Vault Contributor)")
                            # Show credential storage location based on credential_type
                            credential_type = assignment.get('credential_type', 'secret')
                            if credential_type == 'certificate':
                                logging.info(f"Certificate stored in: {target_name}/certificates/mi-certificate-{app_name}")
                                logging.info(f"Client ID stored in: {target_name}/secrets/mi-client-id-{app_name}")
                            else:
                                logging.info(f"Client secret stored in: {target_name}/mi-client-secret-{app_name}")
                                logging.info(f"Client ID stored in: {target_name}/mi-client-id-{app_name}")
                        elif target_resource_type == 'storage_account':
                            logging.info(f"Target Resource: Storage Account - {target_name} (Storage Blob Data Reader)")
                            # Show credential storage location based on credential_type
                            credential_type = assignment.get('credential_type', 'secret')
                            if credential_type == 'certificate':
                                logging.info(f"Certificate stored in: {target_name}/mi-credentials/{app_name}-certificate.pem")
                                logging.info(f"Private key stored in: {target_name}/mi-credentials/{app_name}-private-key.key")
                                logging.info(f"App ID stored in: {target_name}/mi-credentials/{app_name}-app-id.txt")
                            else:
                                logging.info(f"App ID stored in: {target_name}/mi-credentials/{app_name}-app-id.txt")
                                logging.info(f"Secret stored in: {target_name}/mi-credentials/{app_name}-secret.txt")
                        elif target_resource_type == 'cosmos_db':
                            logging.info(f"Target Resource: Cosmos DB - {target_name} (Data Contributor)")

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
                        
                        # Display initial access based on initial_access
                        creds = user_creds[path_name]
                        identity_type = creds.get('initial_access', 'user')
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {creds.get('user_principal_name', 'N/A')}")
                            if 'password' in creds:
                                logging.info(f"Password: {creds['password']}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {creds.get('service_principal_name', 'N/A')}")
                            if 'client_id' in creds:
                                logging.info(f"Client ID: {creds['client_id']}")
                            if 'client_secret' in creds:
                                logging.info(f"Client Secret: {creds['client_secret']}")

                        logging.info(f"Owned Application: {assignment['app_name']}")
                        
                        if key in assignments.get('app_roles', {}):
                            logging.info(f"Application Privileges: Entra Role(s)")
                        elif key in assignments.get('app_api_permissions', {}):
                            logging.info(f"Application Privileges: API Permission(s)")
                        break
            
            elif priv_esc in ['ApplicationAdministratorAbuse', 'CloudAppAdministratorAbuse']:
                role_display_name = "Cloud Application Administrator" if priv_esc == 'CloudAppAdministratorAbuse' else "Application Administrator"
                # These techniques don't use app_owners, only user_roles
                if path_name in user_creds:
                    # Find the matching key in user_roles
                    for key, assignment in assignments.get('user_roles', {}).items():
                        if path_name in key:
                            logging.info(f"Attack Path ID: {key}")
                            logging.info(f"Privilege Escalation: {priv_esc}")

                            # Display initial access based on initial_access
                            creds = user_creds[path_name]
                            identity_type = creds.get('initial_access', 'user')
                            if identity_type == 'user':
                                logging.info(f"Initial Access Identity: User - {creds.get('user_principal_name', 'N/A')}")
                                if 'password' in creds:
                                    logging.info(f"Password: {creds['password']}")
                            elif identity_type == 'service_principal':
                                logging.info(f"Initial Access Identity: Service Principal - {creds.get('service_principal_name', 'N/A')}")
                                if 'client_id' in creds:
                                    logging.info(f"Client ID: {creds['client_id']}")
                                if 'client_secret' in creds:
                                    logging.info(f"Client Secret: {creds['client_secret']}")

                            # Show group assignment details if applicable
                            assignment_type = assignment.get('assignment_type', 'direct')
                            if assignment_type == 'group_member':
                                group_name = assignment.get('group_name', 'N/A')
                                original_principal = assignment.get('original_principal', assignment.get('principal_name', 'N/A'))
                                original_identity_type = assignment.get('original_initial_access', 'user')
                                logging.info(f"Assignment Type: Group Member (indirect)")
                                logging.info(f"Group: {group_name}")
                                if original_identity_type == 'user':
                                    logging.info(f"Group Member: User - {original_principal}@{domain}")
                                else:
                                    logging.info(f"Group Member: Service Principal - {original_principal}")
                                logging.info(f"Principal Role: {role_display_name} (via Group)")
                            elif assignment_type == 'group_owner':
                                group_name = assignment.get('group_name', 'N/A')
                                original_principal = assignment.get('original_principal', assignment.get('principal_name', 'N/A'))
                                original_identity_type = assignment.get('original_initial_access', 'user')
                                logging.info(f"Assignment Type: Group Owner (indirect)")
                                logging.info(f"Attack Chain: Group Ownership \u2192 {role_display_name}")
                                logging.info(f"Group: {group_name}")
                                if original_identity_type == 'user':
                                    logging.info(f"Group Owner: User - {original_principal}@{domain}")
                                else:
                                    logging.info(f"Group Owner: Service Principal - {original_principal}")
                                logging.info(f"Principal Role: {role_display_name} (via Group)")
                            else:
                                logging.info(f"Principal Role: {role_display_name}")

                            # Display role scope
                            scope_app = assignment.get('scope_app_name')
                            if scope_app:
                                logging.info(f"Role Scope: Application ({scope_app})")
                            else:
                                logging.info(f"Role Scope: Directory (tenant-wide)")

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
                        
                        identity_type = assignment['initial_access']
                        principal_name = assignment['principal_name']
                        key_vault = assignment['key_vault']
                        assignment_type = assignment.get('assignment_type', 'direct')
                        
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if principal_name in users:
                                logging.info(f"Password: {users[principal_name]['password']}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            if path_name in user_creds:
                                sp_creds = user_creds[path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor via Group)")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 KeyVaultSecretTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor via Group)")
                        else:
                            logging.info(f"Key Vault Access: {key_vault} (Key Vault Contributor)")

                        logging.info(f"Target Application: {assignment['app_name']}")
                        break

            elif priv_esc == 'StorageCertificateTheft':
                for key, assignment in assignments.get('storage_abuse', {}).items():
                    # Match the key to the path_name
                    if path_name in key:
                        logging.info(f"Attack Path ID: {key}")
                        
                        identity_type = assignment['initial_access']
                        principal_name = assignment['principal_name']
                        storage_account = assignment['storage_account']
                        assignment_type = assignment.get('assignment_type', 'direct')
                        
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if principal_name in users:
                                logging.info(f"Password: {users[principal_name]['password']}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            if path_name in user_creds:
                                sp_creds = user_creds[path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader via Group)")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 StorageCertificateTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader via Group)")
                        else:
                            logging.info(f"Storage Account Access: {storage_account} (Storage Blob Data Reader)")

                        logging.info(f"Target Application: {assignment['app_name']}")
                        logging.info(f"Certificate stored in: {storage_account}/cert-container/")
                        break

            elif priv_esc == 'CosmosDBSecretTheft':
                for key, assignment in assignments.get('cosmos_abuse', {}).items():
                    if path_name in key:
                        logging.info(f"Attack Path ID: {key}")

                        identity_type = assignment['initial_access']
                        principal_name = assignment['principal_name']
                        cosmos_db = assignment['cosmos_db']
                        assignment_type = assignment.get('assignment_type', 'direct')

                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {principal_name}@{domain}")
                            if principal_name in users:
                                logging.info(f"Password: {users[principal_name]['password']}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {principal_name}")
                            if path_name in user_creds:
                                sp_creds = user_creds[path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                            logging.info(f"Cosmos DB Access: {cosmos_db} (Data Contributor via Group)")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', principal_name)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 CosmosDBSecretTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")
                            logging.info(f"Cosmos DB Access: {cosmos_db} (Data Contributor via Group)")
                        else:
                            logging.info(f"Cosmos DB Access: {cosmos_db} (Data Contributor)")

                        logging.info(f"Target Application: {assignment['app_name']}")
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
                        identity_type = assignment.get('initial_access', 'user')
                        initial_access_principal = assignment.get('initial_access_principal')
                        app_name = assignment.get('app_name')
                        managed_identity_name = assignment.get('managed_identity_name')
                        assignment_type = assignment.get('assignment_type', 'direct')
                        
                        # Get the appropriate role name based on source type
                        role_name = {
                            'vm': 'VM Contributor',
                            'logic_app': 'Logic App Contributor',
                            'automation_account': 'Automation Contributor',
                            'function_app': 'Website Contributor'
                        }.get(source_type, 'Contributor')
                        
                        # Display initial access identity based on initial_access
                        if identity_type == 'user':
                            logging.info(f"Initial Access Identity: User - {initial_access_principal}@{domain}")
                            if initial_access_principal in users:
                                logging.info(f"Password: {users[initial_access_principal]['password']}")
                        elif identity_type == 'service_principal':
                            logging.info(f"Initial Access Identity: Service Principal - {initial_access_principal}")
                            if path_name in user_creds:
                                sp_creds = user_creds[path_name]
                                if 'client_id' in sp_creds:
                                    logging.info(f"Client ID: {sp_creds['client_id']}")
                                if 'client_secret' in sp_creds:
                                    logging.info(f"Client Secret: {sp_creds['client_secret']}")

                        # Show group assignment details if applicable
                        if assignment_type == 'group_member':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', initial_access_principal)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Member (indirect)")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Member: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Member: Service Principal - {original_principal}")
                        elif assignment_type == 'group_owner':
                            group_name = assignment.get('group_name', 'N/A')
                            original_principal = assignment.get('original_principal', initial_access_principal)
                            original_identity_type = assignment.get('original_initial_access', 'user')
                            logging.info(f"Assignment Type: Group Owner (indirect)")
                            logging.info(f"Attack Chain: Group Ownership \u2192 ManagedIdentityTheft")
                            logging.info(f"Group: {group_name}")
                            if original_identity_type == 'user':
                                logging.info(f"Group Owner: User - {original_principal}@{domain}")
                            else:
                                logging.info(f"Group Owner: Service Principal - {original_principal}")

                        # Display source information with role (via Group if applicable)
                        role_suffix = " via Group" if assignment_type in ('group_member', 'group_owner') else ""
                        if source_type == 'vm':
                            logging.info(f"Source Resource: Virtual Machine - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'logic_app':
                            logging.info(f"Source Resource: Logic App - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'automation_account':
                            logging.info(f"Source Resource: Automation Account - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")
                        elif source_type == 'function_app':
                            # Get OS type from assignment if available
                            os_type = assignment.get('os_type', 'linux')
                            os_display = f" ({os_type.capitalize()})" if os_type else ""
                            logging.info(f"Source Resource: Function App{os_display} - {source_name} (with {role_name}{role_suffix})")
                            logging.info(f"Managed Identity: {managed_identity_name}")

                        # Display target information
                        if target_resource_type == 'key_vault':
                            logging.info(f"Target Resource: Key Vault - {target_name} (Key Vault Contributor)")
                            # Show credential storage location based on credential_type
                            credential_type = assignment.get('credential_type', 'secret')
                            if credential_type == 'certificate':
                                logging.info(f"Certificate stored in: {target_name}/certificates/mi-certificate-{app_name}")
                                logging.info(f"Client ID stored in: {target_name}/secrets/mi-client-id-{app_name}")
                            else:
                                logging.info(f"Client secret stored in: {target_name}/mi-client-secret-{app_name}")
                                logging.info(f"Client ID stored in: {target_name}/mi-client-id-{app_name}")
                        elif target_resource_type == 'storage_account':
                            logging.info(f"Target Resource: Storage Account - {target_name} (Storage Blob Data Reader)")
                            # Show credential storage location based on credential_type
                            credential_type = assignment.get('credential_type', 'secret')
                            if credential_type == 'certificate':
                                logging.info(f"Certificate stored in: {target_name}/mi-credentials/{app_name}-certificate.pem")
                                logging.info(f"Private key stored in: {target_name}/mi-credentials/{app_name}-private-key.key")
                                logging.info(f"App ID stored in: {target_name}/mi-credentials/{app_name}-app-id.txt")
                            else:
                                logging.info(f"App ID stored in: {target_name}/mi-credentials/{app_name}-app-id.txt")
                                logging.info(f"Secret stored in: {target_name}/mi-credentials/{app_name}-secret.txt")
                        elif target_resource_type == 'cosmos_db':
                            logging.info(f"Target Resource: Cosmos DB - {target_name} (Data Contributor)")

                        # Display application with privileges
                        logging.info(f"Target Application: {app_name}")
                        break

        logging.info("\n" + "=" * 60)