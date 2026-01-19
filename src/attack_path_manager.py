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
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None,
        used_users: Optional[set] = None
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
        elif mode == 'random' and path_name:
            # Include path_name in random mode to enable filtering in output
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Select entities based on mode
        if mode == 'random':
            app_name, user_name, second_user_name = self._select_random_entities_app_ownership(
                users, applications, attack_config.get('scenario', 'direct'),
                used_apps, used_users
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
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None,
        used_users: Optional[set] = None
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
        elif mode == 'random' and path_name:
            # Include path_name in random mode to enable filtering in output
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Select entities based on mode
        if mode == 'random':
            app_name, user_name = self._select_random_entities_app_administrator(
                users, applications, used_apps, used_users
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
    
    def create_managed_identity_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        key_vaults: Dict,
        storage_accounts: Dict,
        users: Dict,
        virtual_machines: Dict,
        logic_apps: Dict,
        automation_accounts: Dict,
        function_apps: Dict,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None,
        used_users: Optional[set] = None
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Managed Identity Theft attack path.
        
        This technique simulates stealing a managed identity token from a resource
        (VM, Logic App, etc.) to access other Azure resources.
        
        Args:
            attack_config: Attack path configuration
            applications: Dictionary of applications
            key_vaults: Dictionary of key vaults (if target is key_vault)
            storage_accounts: Dictionary of storage accounts (if target is storage_account)
            users: Dictionary of users
            virtual_machines: Dictionary of virtual machines
            mode: 'random' or 'targeted'
            entities: Entity specifications (required for targeted mode)
            path_name: Attack path name
            used_apps: Set of already-used application names
        
        Returns:
            Tuple of (mi_theft_assignments, app_role_assignments,
                     app_api_permission_assignments, vm_contributor_assignments)
        """
        mi_theft_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}  # Empty - Terraform handles this directly
        
        # Generate attack path key
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Get source_type and target_resource_type from config
        source_type = attack_config.get('source_type', 'vm')
        target_resource_type = attack_config.get('target_resource_type')
        
        # Select entities based on mode
        if mode == 'random':
            app_name, target_name, source_name, user_name = self._select_random_entities_mi_theft(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, source_type, target_resource_type, used_apps, used_users
            )
        else:  # targeted mode
            app_name, target_name, source_name, user_name = self._select_targeted_entities_mi_theft(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, entities, source_type, target_resource_type, path_name
            )
        
        # Create MI theft assignment
        # Note: VM Contributor assignment is handled directly by Terraform
        # from the initial_access_user field in this assignment
        mi_theft_assignment = {
            'source_type': source_type,
            'source_name': source_name,
            'target_resource_type': target_resource_type,
            'target_name': target_name,
            'app_name': app_name,
            'initial_access_user': user_name,
            'managed_identity_name': source_name  # For VMs, MI name = VM name
        }
        
        # Generate certificate for storage account targets
        if target_resource_type == 'storage_account':
            cert_path, key_path = generate_certificate_and_key(app_name)
            mi_theft_assignment['certificate_path'] = cert_path
            mi_theft_assignment['private_key_path'] = key_path
        else:
            # For key_vault targets, these are optional (not used)
            mi_theft_assignment['certificate_path'] = ''
            mi_theft_assignment['private_key_path'] = ''
        
        mi_theft_assignments[key] = mi_theft_assignment
        
        # Assign privileges to the target application
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return (
            mi_theft_assignments,
            app_role_assignments,
            app_api_permission_assignments,
            vm_contributor_assignments  # Always empty for ManagedIdentityTheft
        )
    
    def create_keyvault_secret_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        keyvaults: Dict,
        users: Dict,
        service_principals: Dict,
        virtual_machines: Dict,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Key Vault Secret Theft attack path.
        
        This technique only supports principal_type 'user' or 'service_principal'.
        For managed identity scenarios, use ManagedIdentityTheft instead.
        
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
        # Validate principal_type
        principal_type = attack_config.get('principal_type', 'user')
        if principal_type == 'managed_identity':
            raise ValueError(
                "KeyVaultSecretTheft does not support principal_type 'managed_identity'. "
                "Use 'ManagedIdentityTheft' with target_resource_type 'key_vault' instead."
            )
        
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
            app_name, kv_name, principal_name = self._select_random_entities_kv_secret_theft(
                applications, keyvaults, users, service_principals,
                principal_type, used_apps
            )
        else:  # targeted mode
            app_name, kv_name, principal_name = self._select_targeted_entities_kv_secret_theft(
                applications, keyvaults, users,
                entities, principal_type, path_name
            )
        
        attack_path_kv_abuse_assignments[key] = {
            "key_vault": kv_name,
            "principal_type": principal_type,
            "principal_name": principal_name,
            "app_name": app_name
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
    
    def create_storage_certificate_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        storage_accounts: Dict,
        users: Dict,
        service_principals: Dict,
        virtual_machines: Dict,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Storage Certificate Theft attack path.
        
        This technique only supports principal_type 'user' or 'service_principal'.
        For managed identity scenarios, use ManagedIdentityTheft instead.
        
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
        # Validate principal_type
        principal_type = attack_config.get('principal_type', 'user')
        if principal_type == 'managed_identity':
            raise ValueError(
                "StorageCertificateTheft does not support principal_type 'managed_identity'. "
                "Use 'ManagedIdentityTheft' with target_resource_type 'storage_account' instead."
            )
        
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
            app_name, sa_name, principal_name = self._select_random_entities_storage_cert_theft(
                applications, storage_accounts, users, service_principals,
                principal_type, used_apps
            )
        else:  # targeted mode
            app_name, sa_name, principal_name = self._select_targeted_entities_storage_cert_theft(
                applications, storage_accounts, users,
                entities, principal_type, path_name
            )
        
        # Generate certificate
        cert_path, key_path = generate_certificate_and_key(app_name)
        
        attack_path_storage_abuse_assignments[key] = {
            "app_name": app_name,
            "storage_account": sa_name,
            "principal_type": principal_type,
            "principal_name": principal_name,
            'certificate_path': cert_path,
            'private_key_path': key_path
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
        self, users: Dict, applications: Dict, scenario: str,
        used_apps: set = None, used_users: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Application Ownership Abuse."""
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        user_keys = list(users.keys())
        
        # Exclude used users
        if used_users:
            available_users = [user for user in user_keys if user not in used_users]
            if available_users:
                user_keys = available_users
        
        user_name = random.choice(user_keys)
        second_user_name = random.choice(user_keys) if scenario == "helpdesk" else user_name
        
        return app_name, user_name, second_user_name
    
    def _select_random_entities_app_administrator(
        self, users: Dict, applications: Dict,
        used_apps: set = None, used_users: set = None
    ) -> Tuple[str, str]:
        """Select random entities for Application Administrator Abuse."""
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        user_keys = list(users.keys())
        
        # Exclude used users
        if used_users:
            available_users = [user for user in user_keys if user not in used_users]
            if available_users:
                user_keys = available_users
        
        user_name = random.choice(user_keys)
        
        return app_name, user_name
    
    def _select_random_entities_kv_secret_theft(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        service_principals: Dict, principal_type: str,
        used_apps: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Key Vault Secret Theft."""
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        kv_name = random.choice(list(keyvaults.keys()))
        
        if principal_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif principal_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
        
        return app_name, kv_name, principal_name
    
    def _select_random_entities_storage_cert_theft(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        service_principals: Dict, principal_type: str,
        used_apps: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Storage Certificate Theft."""
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        sa_name = random.choice(list(storage_accounts.keys()))
        
        if principal_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif principal_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
        
        return app_name, sa_name, principal_name
    
    def _select_random_entities_mi_theft(
        self, applications: Dict, key_vaults: Dict, storage_accounts: Dict,
        virtual_machines: Dict, logic_apps: Dict, automation_accounts: Dict, function_apps: Dict, users: Dict,
        source_type: str, target_resource_type: str, used_apps: set = None, used_users: set = None
    ) -> Tuple[str, str, str, str]:
        """Select random entities for Managed Identity Theft."""
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        # Select source based on type
        if source_type == 'vm':
            source_name = random.choice(list(virtual_machines.keys()))
        elif source_type == 'logic_app':
            source_name = random.choice(list(logic_apps.keys()))
        elif source_type == 'automation_account':
            source_name = random.choice(list(automation_accounts.keys()))
        elif source_type == 'function_app':
            source_name = random.choice(list(function_apps.keys()))
        else:
            # Default to VM for unknown types
            source_name = random.choice(list(virtual_machines.keys()))
        
        # Select target resource
        if target_resource_type == 'key_vault':
            target_name = random.choice(list(key_vaults.keys()))
        elif target_resource_type == 'storage_account':
            target_name = random.choice(list(storage_accounts.keys()))
        else:
            # For future expansion: subscription, resource_group
            target_name = random.choice(list(key_vaults.keys()))
        
        # Select user for Contributor access
        user_keys = list(users.keys())
        
        # Exclude used users
        if used_users:
            available_users = [user for user in user_keys if user not in used_users]
            if available_users:
                user_keys = available_users
        
        user_name = random.choice(user_keys)
        
        return app_name, target_name, source_name, user_name
    
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
    
    def _select_targeted_entities_kv_secret_theft(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        entities: Dict, principal_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Key Vault Secret Theft."""
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
        
        return app_name, kv_name, principal_name
    
    def _select_targeted_entities_storage_cert_theft(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        entities: Dict, principal_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Storage Certificate Theft."""
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
        
        return app_name, sa_name, principal_name
    
    def _select_targeted_entities_mi_theft(
        self, applications: Dict, key_vaults: Dict, storage_accounts: Dict,
        virtual_machines: Dict, logic_apps: Dict, automation_accounts: Dict, function_apps: Dict, users: Dict,
        entities: Dict, source_type: str, target_resource_type: str, path_name: str
    ) -> Tuple[str, str, str, str]:
        """Select targeted entities for Managed Identity Theft."""
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        # Get source resource
        if source_type == 'vm':
            vm_list = list(entities.get('virtual_machines', []))
            if not vm_list:
                raise ValueError(f"{path_name}: source_type 'vm' requires virtual_machines")
            vm_spec = vm_list[0]
            source_name = vm_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(virtual_machines.keys()))
        elif source_type == 'logic_app':
            la_list = list(entities.get('logic_apps', []))
            if not la_list:
                raise ValueError(f"{path_name}: source_type 'logic_app' requires logic_apps")
            la_spec = la_list[0]
            source_name = la_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(logic_apps.keys()))
        elif source_type == 'automation_account':
            aa_list = list(entities.get('automation_accounts', []))
            if not aa_list:
                raise ValueError(f"{path_name}: source_type 'automation_account' requires automation_accounts")
            aa_spec = aa_list[0]
            source_name = aa_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(automation_accounts.keys()))
        elif source_type == 'function_app':
            fa_list = list(entities.get('function_apps', []))
            if not fa_list:
                raise ValueError(f"{path_name}: source_type 'function_app' requires function_apps")
            fa_spec = fa_list[0]
            source_name = fa_spec.get('name', 'random')
            if source_name == 'random':
                source_name = random.choice(list(function_apps.keys()))
        else:
            # Default to VM for unknown types
            source_name = random.choice(list(virtual_machines.keys()))
        
        # Get target resource
        if target_resource_type == 'key_vault':
            kv_list = list(entities.get('key_vaults', []))
            if not kv_list:
                raise ValueError(f"{path_name}: target_resource_type 'key_vault' requires key_vaults")
            kv_spec = kv_list[0]
            target_name = kv_spec.get('name', 'random')
            if target_name == 'random':
                target_name = random.choice(list(key_vaults.keys()))
        elif target_resource_type == 'storage_account':
            sa_list = list(entities.get('storage_accounts', []))
            if not sa_list:
                raise ValueError(f"{path_name}: target_resource_type 'storage_account' requires storage_accounts")
            sa_spec = sa_list[0]
            target_name = sa_spec.get('name', 'random')
            if target_name == 'random':
                target_name = random.choice(list(storage_accounts.keys()))
        else:
            # For future expansion
            target_name = random.choice(list(key_vaults.keys()))
        
        # Get user for VM Contributor
        user_list = list(entities.get('users', []))
        if not user_list:
            raise ValueError(f"{path_name}: ManagedIdentityTheft requires users for VM Contributor")
        user_spec = user_list[0]
        user_name = user_spec.get('name', 'random')
        if user_name == 'random':
            user_name = random.choice(list(users.keys()))
        
        return app_name, target_name, source_name, user_name
    
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