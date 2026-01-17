"""
Attack path management for BadZure.
Handles creation of all attack path types for both random and targeted modes.
"""
import random
import string
import logging
from typing import Dict, Tuple, Optional
from src.constants import (
    HIGH_PRIVILEGED_ENTRA_ROLES,
    HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS,
    ALL_HIGH_PRIVILEGED_PERMISSIONS,
    API_REGISTRY
)
from src.crypto import generate_certificate_and_key


class AttackPathManager:
    """Manages creation of attack paths for both random and targeted modes."""
    
    def create_application_ownership_abuse(
        self,
        attack_config: Dict,
        users: Dict,
        applications: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None
    ) -> Tuple[Dict, Dict, Dict, Dict, Dict]:
        """
        Create Application Ownership Abuse attack path.
        
        Args:
            attack_config: Attack path configuration
            users: Dictionary of users
            applications: Dictionary of applications
            domain: Domain name
            mode: 'random' or 'targeted'
            entities: Entity specifications (required for targeted mode)
            path_name: Attack path name (used for targeted mode)
        
        Returns:
            Tuple of (initial_access_user, app_owner_assignments, 
                     user_role_assignments, app_role_assignments, 
                     app_api_permission_assignments)
        """
        app_owner_assignments = {}
        user_role_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        
        # Generate attack path key
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Select entities based on mode
        if mode == 'random':
            app_name, user_name, second_user_name = self._select_random_entities_app_ownership(
                users, applications, attack_config.get('scenario', 'direct')
            )
        else:  # targeted mode
            app_name, user_name, second_user_name = self._select_targeted_entities_app_ownership(
                users, applications, entities, attack_config.get('scenario', 'direct'), path_name
            )
        
        # Create assignments
        scenario = attack_config.get('scenario', 'direct')
        user_principal_name = f"{user_name}@{domain}"
        password = users[user_name]['password']
        
        if scenario == "direct":
            initial_access_user = {
                "user_principal_name": user_principal_name,
                "password": password
            }
        elif scenario == "helpdesk":
            helpdesk_admin_role_id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
            second_user_principal_name = f"{second_user_name}@{domain}"
            second_user_password = users[second_user_name]['password']
            
            initial_access_user = {
                "user_principal_name": second_user_principal_name,
                "password": second_user_password
            }
            
            user_role_assignments[key] = {
                'user_name': second_user_name,
                'role_definition_id': helpdesk_admin_role_id
            }
        
        app_owner_assignments[key] = {
            'app_name': app_name,
            'user_principal_name': user_principal_name,
        }
        
        # Assign privileges
        self._assign_app_privileges(
            attack_config, app_name, key, 
            app_role_assignments, app_api_permission_assignments
        )
        
        return (
            initial_access_user,
            app_owner_assignments,
            user_role_assignments,
            app_role_assignments,
            app_api_permission_assignments
        )
    
    def create_application_administrator_abuse(
        self,
        attack_config: Dict,
        users: Dict,
        applications: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Application Administrator Abuse attack path.
        
        This technique exploits the Application Administrator Entra ID role to manage
        any application in the tenant and add credentials to privileged applications.
        
        Args:
            attack_config: Attack path configuration
            users: Dictionary of users
            applications: Dictionary of applications
            domain: Domain name
            mode: 'random' or 'targeted'
            entities: Entity specifications (required for targeted mode)
            path_name: Attack path name (used for targeted mode)
        
        Returns:
            Tuple of (initial_access_user, user_role_assignments,
                     app_role_assignments, app_api_permission_assignments)
        """
        user_role_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        
        # Generate attack path key
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Select entities based on mode
        if mode == 'random':
            app_name, user_name = self._select_random_entities_app_administrator(
                users, applications
            )
        else:  # targeted mode
            app_name, user_name = self._select_targeted_entities_app_administrator(
                users, applications, entities, path_name
            )
        
        # Create assignments
        user_principal_name = f"{user_name}@{domain}"
        password = users[user_name]['password']
        
        initial_access_user = {
            "user_principal_name": user_principal_name,
            "password": password
        }
        
        # Assign Application Administrator role to user
        # Application Administrator role ID: 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3
        app_admin_role_id = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
        user_role_assignments[key] = {
            'user_name': user_name,
            'role_definition_id': app_admin_role_id
        }
        
        # Assign privileges to the target application
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return (
            initial_access_user,
            user_role_assignments,
            app_role_assignments,
            app_api_permission_assignments
        )
    
    def create_keyvault_abuse(
        self,
        attack_config: Dict,
        applications: Dict,
        keyvaults: Dict,
        users: Dict,
        service_principals: Dict,
        virtual_machines: Dict,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Key Vault Abuse attack path.
        
        Args:
            attack_config: Attack path configuration
            applications: Dictionary of applications
            keyvaults: Dictionary of key vaults
            users: Dictionary of users
            service_principals: Dictionary of service principals
            virtual_machines: Dictionary of virtual machines
            mode: 'random' or 'targeted'
            entities: Entity specifications (required for targeted mode)
            path_name: Attack path name (used for targeted mode)
        
        Returns:
            Tuple of (kv_abuse_assignments, app_role_assignments, 
                     app_api_permission_assignments, vm_contributor_assignments)
        """
        attack_path_kv_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}
        
        # Generate attack path key
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            # Include path_name in random mode to enable filtering in output
            # Use path_name directly with random ID (no "attack-path" prefix to avoid duplication)
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Select entities based on mode
        if mode == 'random':
            app_name, kv_name, principal_name, user_name = self._select_random_entities_kv_abuse(
                applications, keyvaults, users, service_principals, 
                virtual_machines, attack_config['principal_type']
            )
        else:  # targeted mode
            app_name, kv_name, principal_name, user_name = self._select_targeted_entities_kv_abuse(
                applications, keyvaults, users, virtual_machines,
                entities, attack_config['principal_type'], path_name
            )
        
        principal_type = attack_config['principal_type']
        
        # Handle managed identity VM Contributor assignment
        if principal_type == "managed_identity":
            vm_contributor_assignments[key] = {
                'user_name': user_name,
                'virtual_machine': principal_name
            }
        
        attack_path_kv_abuse_assignments[key] = {
            "key_vault": kv_name,
            "principal_type": principal_type,
            "principal_name": principal_name,
            "virtual_machine": principal_name if principal_type == "managed_identity" else None,
            "app_name": app_name,
            'initial_access_user': user_name if principal_type == "managed_identity" else None
        }
        
        # Assign privileges
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return (
            attack_path_kv_abuse_assignments,
            app_role_assignments,
            app_api_permission_assignments,
            vm_contributor_assignments
        )
    
    def create_storage_account_abuse(
        self,
        attack_config: Dict,
        applications: Dict,
        storage_accounts: Dict,
        users: Dict,
        service_principals: Dict,
        virtual_machines: Dict,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Storage Account Abuse attack path.
        
        Args:
            attack_config: Attack path configuration
            applications: Dictionary of applications
            storage_accounts: Dictionary of storage accounts
            users: Dictionary of users
            service_principals: Dictionary of service principals
            virtual_machines: Dictionary of virtual machines
            mode: 'random' or 'targeted'
            entities: Entity specifications (required for targeted mode)
            path_name: Attack path name (used for targeted mode)
        
        Returns:
            Tuple of (storage_abuse_assignments, app_role_assignments, 
                     app_api_permission_assignments, vm_contributor_assignments)
        """
        attack_path_storage_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}
        
        # Generate attack path key
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            # Include path_name in random mode to enable filtering in output
            # Use path_name directly with random ID (no "attack-path" prefix to avoid duplication)
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Select entities based on mode
        if mode == 'random':
            app_name, sa_name, principal_name, user_name = self._select_random_entities_storage_abuse(
                applications, storage_accounts, users, service_principals,
                virtual_machines, attack_config['principal_type']
            )
        else:  # targeted mode
            app_name, sa_name, principal_name, user_name = self._select_targeted_entities_storage_abuse(
                applications, storage_accounts, users, virtual_machines,
                entities, attack_config['principal_type'], path_name
            )
        
        principal_type = attack_config['principal_type']
        
        # Generate certificate
        cert_path, key_path = generate_certificate_and_key(app_name)
        
        # Handle managed identity VM Contributor assignment
        if principal_type == "managed_identity":
            vm_contributor_assignments[key] = {
                'user_name': user_name,
                'virtual_machine': principal_name
            }
        
        attack_path_storage_abuse_assignments[key] = {
            "app_name": app_name,
            "storage_account": sa_name,
            "principal_type": principal_type,
            "principal_name": principal_name,
            "virtual_machine": principal_name if principal_type == "managed_identity" else None,
            'certificate_path': cert_path,
            'private_key_path': key_path,
            'initial_access_user': user_name if principal_type == "managed_identity" else None
        }
        
        # Assign privileges
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return (
            attack_path_storage_abuse_assignments,
            app_role_assignments,
            app_api_permission_assignments,
            vm_contributor_assignments
        )
    
    # ========================================================================
    # Random Mode Entity Selection
    # ========================================================================
    
    def _select_random_entities_app_ownership(
        self, users: Dict, applications: Dict, scenario: str
    ) -> Tuple[str, str, str]:
        """Select random entities for Application Ownership Abuse."""
        app_keys = list(applications.keys())
        app_name = random.choice(app_keys)
        
        user_keys = list(users.keys())
        user_name = random.choice(user_keys)
        second_user_name = random.choice(user_keys) if scenario == "helpdesk" else user_name
        
        return app_name, user_name, second_user_name
    
    def _select_random_entities_app_administrator(
        self, users: Dict, applications: Dict
    ) -> Tuple[str, str]:
        """Select random entities for Application Administrator Abuse."""
        app_keys = list(applications.keys())
        app_name = random.choice(app_keys)
        
        user_keys = list(users.keys())
        user_name = random.choice(user_keys)
        
        return app_name, user_name
    
    def _select_random_entities_kv_abuse(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        service_principals: Dict, virtual_machines: Dict, principal_type: str
    ) -> Tuple[str, str, str, Optional[str]]:
        """Select random entities for Key Vault Abuse."""
        app_name = random.choice(list(applications.keys()))
        kv_name = random.choice(list(keyvaults.keys()))
        
        if principal_type == "user":
            principal_name = random.choice(list(users.keys()))
            user_name = None
        elif principal_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
            user_name = None
        elif principal_type == "managed_identity":
            principal_name = random.choice(list(virtual_machines.keys()))
            user_name = random.choice(list(users.keys()))
        
        return app_name, kv_name, principal_name, user_name
    
    def _select_random_entities_storage_abuse(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        service_principals: Dict, virtual_machines: Dict, principal_type: str
    ) -> Tuple[str, str, str, Optional[str]]:
        """Select random entities for Storage Account Abuse."""
        app_name = random.choice(list(applications.keys()))
        sa_name = random.choice(list(storage_accounts.keys()))
        
        if principal_type == "user":
            principal_name = random.choice(list(users.keys()))
            user_name = None
        elif principal_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
            user_name = None
        elif principal_type == "managed_identity":
            principal_name = random.choice(list(virtual_machines.keys()))
            user_name = random.choice(list(users.keys()))
        
        return app_name, sa_name, principal_name, user_name
    
    # ========================================================================
    # Targeted Mode Entity Selection
    # ========================================================================
    
    def _select_targeted_entities_app_ownership(
        self, users: Dict, applications: Dict, entities: Dict,
        scenario: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Application Ownership Abuse."""
        # Get user
        user_list = list(entities.get('users', []))
        if not user_list:
            raise ValueError(f"{path_name}: No users specified")
        
        user_spec = user_list[0]
        user_name = user_spec.get('name', 'random')
        if user_name == 'random':
            user_name = random.choice(list(users.keys()))
        
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        # Get second user for helpdesk scenario
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
        else:
            second_user_name = user_name
        
        return app_name, user_name, second_user_name
    
    def _select_targeted_entities_app_administrator(
        self, users: Dict, applications: Dict, entities: Dict, path_name: str
    ) -> Tuple[str, str]:
        """Select targeted entities for Application Administrator Abuse."""
        # Get user
        user_list = list(entities.get('users', []))
        if not user_list:
            raise ValueError(f"{path_name}: No users specified")
        
        user_spec = user_list[0]
        user_name = user_spec.get('name', 'random')
        if user_name == 'random':
            user_name = random.choice(list(users.keys()))
        
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        return app_name, user_name
    
    def _select_targeted_entities_kv_abuse(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        virtual_machines: Dict, entities: Dict, principal_type: str, path_name: str
    ) -> Tuple[str, str, str, Optional[str]]:
        """Select targeted entities for Key Vault Abuse."""
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        # Get key vault
        kv_list = list(entities.get('key_vaults', []))
        if not kv_list:
            raise ValueError(f"{path_name}: No key_vaults specified")
        kv_spec = kv_list[0]
        kv_name = kv_spec.get('name', 'random')
        if kv_name == 'random':
            kv_name = random.choice(list(keyvaults.keys()))
        
        # Get principal based on type
        user_name = None
        if principal_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: principal_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif principal_type == 'service_principal':
            principal_name = app_name
        elif principal_type == 'managed_identity':
            vm_list = list(entities.get('virtual_machines', []))
            if not vm_list:
                raise ValueError(f"{path_name}: principal_type 'managed_identity' requires virtual_machines")
            vm_spec = vm_list[0]
            principal_name = vm_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(virtual_machines.keys()))
            
            # Get user for VM Contributor
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: managed_identity requires users for VM Contributor")
            user_spec = user_list[0]
            user_name = user_spec.get('name', 'random')
            if user_name == 'random':
                user_name = random.choice(list(users.keys()))
        
        return app_name, kv_name, principal_name, user_name
    
    def _select_targeted_entities_storage_abuse(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        virtual_machines: Dict, entities: Dict, principal_type: str, path_name: str
    ) -> Tuple[str, str, str, Optional[str]]:
        """Select targeted entities for Storage Account Abuse."""
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        # Get storage account
        sa_list = list(entities.get('storage_accounts', []))
        if not sa_list:
            raise ValueError(f"{path_name}: No storage_accounts specified")
        sa_spec = sa_list[0]
        sa_name = sa_spec.get('name', 'random')
        if sa_name == 'random':
            sa_name = random.choice(list(storage_accounts.keys()))
        
        # Get principal based on type
        user_name = None
        if principal_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: principal_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif principal_type == 'service_principal':
            principal_name = app_name
        elif principal_type == 'managed_identity':
            vm_list = list(entities.get('virtual_machines', []))
            if not vm_list:
                raise ValueError(f"{path_name}: principal_type 'managed_identity' requires virtual_machines")
            vm_spec = vm_list[0]
            principal_name = vm_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(virtual_machines.keys()))
            
            # Get user for VM Contributor
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: managed_identity requires users for VM Contributor")
            user_spec = user_list[0]
            user_name = user_spec.get('name', 'random')
            if user_name == 'random':
                user_name = random.choice(list(users.keys()))
        
        return app_name, sa_name, principal_name, user_name
    
    # ========================================================================
    # Privilege Assignment (Shared Logic)
    # ========================================================================
    
    def _assign_app_privileges(
        self, attack_config: Dict, app_name: str, key: str,
        app_role_assignments: Dict, app_api_permission_assignments: Dict
    ) -> None:
        """Assign privileges to application based on method (shared logic for both modes)."""
        method = attack_config.get('method')
        
        if method == "AzureADRole":
            if isinstance(attack_config['entra_role'], list):
                role_ids = attack_config['entra_role']
            elif attack_config['entra_role'] == 'random':
                role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
            else:
                role_ids = [attack_config['entra_role']]
            
            app_role_assignments[key] = {
                'app_name': app_name,
                'role_ids': role_ids
            }
        
        elif method == "GraphAPIPermission":
            # Backward compatibility: GraphAPIPermission always uses Microsoft Graph
            if isinstance(attack_config['app_role'], list):
                api_permission_ids = attack_config['app_role']
            elif attack_config['app_role'] != 'random':
                api_permission_ids = [attack_config['app_role']]
            else:
                api_permission_ids = [random.choice(
                    [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
                )]
            
            app_api_permission_assignments[key] = {
                'app_name': app_name,
                'api_permission_ids': api_permission_ids,
                'api_type': 'graph'  # Always graph for backward compatibility
            }
        
        elif method == "APIPermission":
            # New method supporting multiple API types (graph, exchange, etc.)
            api_type = attack_config.get('api_type', 'graph')
            
            # Validate api_type
            if api_type not in API_REGISTRY:
                logging.warning(f"Invalid api_type '{api_type}', defaulting to 'graph'")
                api_type = 'graph'
            
            if isinstance(attack_config['app_role'], list):
                api_permission_ids = attack_config['app_role']
            elif attack_config['app_role'] != 'random':
                api_permission_ids = [attack_config['app_role']]
            else:
                # Get random permission from the specified API type
                api_permission_ids = [random.choice(
                    [perm["id"] for perm in ALL_HIGH_PRIVILEGED_PERMISSIONS[api_type].values()]
                )]
            
            app_api_permission_assignments[key] = {
                'app_name': app_name,
                'api_permission_ids': api_permission_ids,
                'api_type': api_type
            }