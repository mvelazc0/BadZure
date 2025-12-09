"""
Targeted attack path manager for BadZure.
Handles creation of attack path assignments for targeted mode.
"""
import random
import string
import logging
from typing import Dict
from src.constants import HIGH_PRIVILEGED_ENTRA_ROLES, HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS
from src.crypto import generate_certificate_and_key


class TargetedAttackPathManager:
    """Manages targeted attack path creation for specific scenarios."""
    
    def create_assignments(
        self,
        config: Dict,
        users: Dict,
        groups: Dict,
        applications: Dict,
        administrative_units: Dict,
        resource_groups: Dict,
        key_vaults: Dict,
        storage_accounts: Dict,
        virtual_machines: Dict,
        domain: str
    ) -> Dict:
        """
        Creates attack path assignments using the specified entities from the config.
        
        Args:
            config: Configuration dictionary
            users: Dictionary of users
            groups: Dictionary of groups
            applications: Dictionary of applications
            administrative_units: Dictionary of administrative units
            resource_groups: Dictionary of resource groups
            key_vaults: Dictionary of key vaults
            storage_accounts: Dictionary of storage accounts
            virtual_machines: Dictionary of virtual machines
            domain: Domain name
            
        Returns:
            Dictionary containing all assignment types and user credentials
        """
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
            
            # Generate unique attack path ID using path name to ensure uniqueness
            attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            key = f"attack-path-{path_name}-{attack_path_id}"
            
            if priv_esc == 'ServicePrincipalAbuse':
                self._create_sp_abuse_assignment(
                    path_name, path_config, entities, users, applications,
                    domain, key, assignments, user_creds
                )
            
            elif priv_esc == 'KeyVaultAbuse':
                self._create_kv_abuse_assignment(
                    path_name, path_config, entities, users, applications,
                    key_vaults, virtual_machines, domain, key, assignments, user_creds
                )
            
            elif priv_esc == 'StorageAccountAbuse':
                self._create_storage_abuse_assignment(
                    path_name, path_config, entities, users, applications,
                    storage_accounts, virtual_machines, domain, key, assignments, user_creds
                )
        
        # Store user credentials for output
        assignments['user_creds'] = user_creds
        
        return assignments
    
    def _create_sp_abuse_assignment(
        self, path_name, path_config, entities, users, applications,
        domain, key, assignments, user_creds
    ):
        """Create Service Principal Abuse assignment."""
        # Get first user and first application from entities
        user_list = list(entities.get('users', []))
        if not user_list:
            return
            
        user_spec = user_list[0]
        user_name = user_spec.get('name', 'random')
        if user_name == 'random':
            user_name = list(users.keys())[0]
        
        app_list = list(entities.get('applications', []))
        if not app_list:
            return
            
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = list(applications.keys())[0]
        
        scenario = path_config.get('scenario', 'direct')
        method = path_config.get('method')
        
        # Create app owner assignment
        user_principal_name = f"{user_name}@{domain}"
        assignments['app_owners'][key] = {
            'app_name': app_name,
            'user_principal_name': user_principal_name
        }
        
        # Handle helpdesk scenario
        if scenario == 'helpdesk':
            if len(user_list) > 1:
                second_user_spec = user_list[1]
                second_user_name = second_user_spec.get('name', 'random')
                if second_user_name == 'random':
                    user_keys = list(users.keys())
                    second_user_name = user_keys[1] if len(user_keys) > 1 else user_keys[0]
            else:
                logging.warning(f"{path_name}: Helpdesk scenario requires 2 users, only 1 defined. Reusing first user.")
                second_user_name = user_name
            
            helpdesk_admin_role_id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
            assignments['user_roles'][key] = {
                'user_name': second_user_name,
                'role_definition_id': helpdesk_admin_role_id
            }
            
            user_creds[path_name] = {
                'user_principal_name': f"{second_user_name}@{domain}",
                'password': users[second_user_name]['password']
            }
        else:
            user_creds[path_name] = {
                'user_principal_name': user_principal_name,
                'password': users[user_name]['password']
            }
        
        # Assign privileges to application
        self._assign_app_privileges(path_config, app_name, key, assignments, method)
    
    def _create_kv_abuse_assignment(
        self, path_name, path_config, entities, users, applications,
        key_vaults, virtual_machines, domain, key, assignments, user_creds
    ):
        """Create Key Vault Abuse assignment."""
        # Get entities
        app_list = list(entities.get('applications', []))
        if not app_list:
            return
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = list(applications.keys())[0]
        
        kv_list = list(entities.get('key_vaults', []))
        if not kv_list:
            return
        kv_spec = kv_list[0]
        kv_name = kv_spec.get('name', 'random')
        if kv_name == 'random':
            kv_name = list(key_vaults.keys())[0]
        
        principal_type = path_config.get('principal_type', 'user')
        
        if principal_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                return
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = list(users.keys())[0]
                
            user_creds[path_name] = {
                'user_principal_name': f"{principal_name}@{domain}",
                'password': users[principal_name]['password']
            }
            
        elif principal_type == 'service_principal':
            principal_name = app_name
            
        elif principal_type == 'managed_identity':
            vm_list = list(entities.get('virtual_machines', []))
            if not vm_list:
                return
            vm_spec = vm_list[0]
            principal_name = vm_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = list(virtual_machines.keys())[0]
            
            # Assign VM Contributor to a user
            user_list = list(entities.get('users', []))
            if not user_list:
                return
            user_spec = user_list[0]
            user_name = user_spec.get('name', 'random')
            if user_name == 'random':
                user_name = list(users.keys())[0]
            
            assignments['vm_contributor'][key] = {
                'user_name': user_name,
                'virtual_machine': principal_name
            }
            
            user_creds[path_name] = {
                'user_principal_name': f"{user_name}@{domain}",
                'password': users[user_name]['password']
            }
        
        assignments['kv_abuse'][key] = {
            'key_vault': kv_name,
            'principal_type': principal_type,
            'principal_name': principal_name,
            'virtual_machine': principal_name if principal_type == 'managed_identity' else None,
            'app_name': app_name,
            'initial_access_user': user_name if principal_type == 'managed_identity' else None
        }
        
        # Assign privileges to application
        method = path_config.get('method')
        self._assign_app_privileges(path_config, app_name, key, assignments, method)
    
    def _create_storage_abuse_assignment(
        self, path_name, path_config, entities, users, applications,
        storage_accounts, virtual_machines, domain, key, assignments, user_creds
    ):
        """Create Storage Account Abuse assignment."""
        # Get entities
        app_list = list(entities.get('applications', []))
        if not app_list:
            return
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = list(applications.keys())[0]
        
        sa_list = list(entities.get('storage_accounts', []))
        if not sa_list:
            return
        sa_spec = sa_list[0]
        sa_name = sa_spec.get('name', 'random')
        if sa_name == 'random':
            sa_name = list(storage_accounts.keys())[0]
        
        principal_type = path_config.get('principal_type', 'user')
        
        # Generate certificate for storage account authentication
        cert_path, key_path = generate_certificate_and_key(app_name)
        
        if principal_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                return
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = list(users.keys())[0]
                
            user_creds[path_name] = {
                'user_principal_name': f"{principal_name}@{domain}",
                'password': users[principal_name]['password']
            }
            
        elif principal_type == 'service_principal':
            principal_name = app_name
            
        elif principal_type == 'managed_identity':
            vm_list = list(entities.get('virtual_machines', []))
            if not vm_list:
                return
            vm_spec = vm_list[0]
            principal_name = vm_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = list(virtual_machines.keys())[0]
            
            # Assign VM Contributor to a user
            user_list = list(entities.get('users', []))
            if not user_list:
                return
            user_spec = user_list[0]
            user_name = user_spec.get('name', 'random')
            if user_name == 'random':
                user_name = list(users.keys())[0]
            
            assignments['vm_contributor'][key] = {
                'user_name': user_name,
                'virtual_machine': principal_name
            }
            
            user_creds[path_name] = {
                'user_principal_name': f"{user_name}@{domain}",
                'password': users[user_name]['password']
            }
        
        assignments['storage_abuse'][key] = {
            'app_name': app_name,
            'storage_account': sa_name,
            'principal_type': principal_type,
            'principal_name': principal_name,
            'virtual_machine': principal_name if principal_type == 'managed_identity' else None,
            'certificate_path': cert_path,
            'private_key_path': key_path,
            'initial_access_user': user_name if principal_type == 'managed_identity' else None
        }
        
        # Assign privileges to application
        method = path_config.get('method')
        self._assign_app_privileges(path_config, app_name, key, assignments, method)
    
    def _assign_app_privileges(self, path_config, app_name, key, assignments, method):
        """Assign privileges to application based on method."""
        if method == 'AzureADRole':
            entra_role = path_config.get('entra_role')
            if entra_role == 'random':
                role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
            elif isinstance(entra_role, list):
                role_ids = entra_role
            else:
                role_ids = [entra_role]
            
            assignments['app_roles'][key] = {
                'app_name': app_name,
                'role_ids': role_ids
            }
        
        elif method == 'GraphAPIPermission':
            app_role = path_config.get('app_role')
            if app_role == 'random':
                api_permission_ids = [random.choice([perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()])]
            elif isinstance(app_role, list):
                api_permission_ids = app_role
            else:
                api_permission_ids = [app_role]
            
            assignments['app_api_permissions'][key] = {
                'app_name': app_name,
                'api_permission_ids': api_permission_ids
            }