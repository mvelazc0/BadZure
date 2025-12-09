"""
Attack path management for BadZure.
Handles creation of all attack path types.
"""
import random
import string
from typing import Dict, Tuple
from src.constants import HIGH_PRIVILEGED_ENTRA_ROLES, HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS
from src.crypto import generate_certificate_and_key


class AttackPathManager:
    """Manages creation of attack paths."""
    
    def create_service_principal_abuse(
        self,
        attack_config: Dict,
        users: Dict,
        applications: Dict,
        domain: str
    ) -> Tuple[Dict, Dict, Dict, Dict, Dict]:
        """
        Create Service Principal Abuse attack path.
        
        Returns:
            Tuple of (initial_access_user, app_owner_assignments, 
                     user_role_assignments, app_role_assignments, 
                     app_api_permission_assignments)
        """
        app_owner_assignments = {}
        user_role_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        
        # Pick random application and user
        app_keys = list(applications.keys())
        random_app = random.choice(app_keys)
        
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        key = f"attack-path-{attack_path_id}"
        
        user_keys = list(users.keys())
        random_user = random.choice(user_keys)
        user_principal_name = f"{users[random_user]['user_principal_name']}@{domain}"
        password = users[random_user]['password']
        
        scenario = attack_config.get('scenario', 'direct')
        
        if scenario == "direct":
            initial_access_user = {
                "user_principal_name": user_principal_name,
                "password": password
            }
        elif scenario == "helpdesk":
            helpdesk_admin_role_id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
            second_random_user = random.choice(user_keys)
            second_user_principal_name = f"{users[second_random_user]['user_principal_name']}@{domain}"
            second_user_password = users[second_random_user]['password']
            
            initial_access_user = {
                "user_principal_name": second_user_principal_name,
                "password": second_user_password
            }
            
            user_role_assignments[key] = {
                'user_name': second_random_user,
                'role_definition_id': helpdesk_admin_role_id
            }
        
        app_owner_assignments[key] = {
            'app_name': random_app,
            'user_principal_name': user_principal_name,
        }
        
        # Assign privileges based on method
        if attack_config['method'] == "AzureADRole":
            if isinstance(attack_config['entra_role'], list):
                role_ids = attack_config['entra_role']
            elif attack_config['entra_role'] == 'random':
                role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
            else:
                role_ids = [attack_config['entra_role']]
            
            app_role_assignments[key] = {
                'app_name': random_app,
                'role_ids': role_ids
            }
        
        elif attack_config['method'] == "GraphAPIPermission":
            if isinstance(attack_config['app_role'], list):
                api_permission_ids = attack_config['app_role']
            elif attack_config['app_role'] != 'random':
                api_permission_ids = [attack_config['app_role']]
            else:
                api_permission_ids = [random.choice(
                    [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
                )]
            
            app_api_permission_assignments[key] = {
                'app_name': random_app,
                'api_permission_ids': api_permission_ids,
            }
        
        return (
            initial_access_user,
            app_owner_assignments,
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
        virtual_machines: Dict
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Key Vault Abuse attack path.
        
        Returns:
            Tuple of (kv_abuse_assignments, app_role_assignments, 
                     app_api_permission_assignments, vm_contributor_assignments)
        """
        attack_path_kv_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}
        
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        key = f"attack-path-{attack_path_id}"
        
        # Pick random application and key vault
        app_keys = list(applications.keys())
        random_app = random.choice(app_keys)
        
        kv_keys = list(keyvaults.keys())
        random_kv = random.choice(kv_keys)
        
        principal_type = attack_config['principal_type']
        
        if principal_type == "user":
            principal_keys = list(users.keys())
            random_principal = random.choice(principal_keys)
        elif principal_type == "service_principal":
            principal_keys = list(service_principals.keys())
            random_principal = random.choice(principal_keys)
        elif principal_type == "managed_identity":
            principal_keys = list(virtual_machines.keys())
            random_principal = random.choice(principal_keys)
            
            # Assign VM Contributor to a user
            user_keys = list(users.keys())
            random_user = random.choice(user_keys)
            vm_contributor_assignments[key] = {
                'user_name': random_user,
                'virtual_machine': random_principal
            }
        
        attack_path_kv_abuse_assignments[key] = {
            "key_vault": random_kv,
            "principal_type": principal_type,
            "principal_name": random_principal,
            "virtual_machine": random_principal if principal_type == "managed_identity" else None,
            "app_name": random_app,
            'initial_access_user': random_user if principal_type == "managed_identity" else None
        }
        
        # Assign privileges based on method
        if attack_config['method'] == "AzureADRole":
            if isinstance(attack_config['entra_role'], list):
                role_ids = attack_config['entra_role']
            elif attack_config['entra_role'] == 'random':
                role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
            else:
                role_ids = [attack_config['entra_role']]
            
            app_role_assignments[key] = {
                'app_name': random_app,
                'role_ids': role_ids
            }
        
        elif attack_config['method'] == "GraphAPIPermission":
            if isinstance(attack_config['app_role'], list):
                api_permission_ids = attack_config['app_role']
            elif attack_config['app_role'] != 'random':
                api_permission_ids = [attack_config['app_role']]
            else:
                api_permission_ids = [random.choice(
                    [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
                )]
            
            app_api_permission_assignments[key] = {
                'app_name': random_app,
                'api_permission_ids': api_permission_ids,
            }
        
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
        virtual_machines: Dict
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """
        Create Storage Account Abuse attack path.
        
        Returns:
            Tuple of (storage_abuse_assignments, app_role_assignments, 
                     app_api_permission_assignments, vm_contributor_assignments)
        """
        attack_path_storage_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}
        
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        key = f"attack-path-{attack_path_id}"
        
        # Pick random application and storage account
        app_keys = list(applications.keys())
        random_app = random.choice(app_keys)
        
        sa_keys = list(storage_accounts.keys())
        random_sa = random.choice(sa_keys)
        
        principal_type = attack_config['principal_type']
        
        # Generate certificate
        cert_path, key_path = generate_certificate_and_key(random_app)
        
        if principal_type == "user":
            principal_keys = list(users.keys())
            random_principal = random.choice(principal_keys)
        elif principal_type == "service_principal":
            principal_keys = list(service_principals.keys())
            random_principal = random.choice(principal_keys)
        elif principal_type == "managed_identity":
            principal_keys = list(virtual_machines.keys())
            random_principal = random.choice(principal_keys)
            
            # Assign VM Contributor to a user
            user_keys = list(users.keys())
            random_user = random.choice(user_keys)
            vm_contributor_assignments[key] = {
                'user_name': random_user,
                'virtual_machine': random_principal
            }
        
        attack_path_storage_abuse_assignments[key] = {
            "app_name": random_app,
            "storage_account": random_sa,
            "principal_type": principal_type,
            "principal_name": random_principal,
            "virtual_machine": random_principal if principal_type == "managed_identity" else None,
            'certificate_path': cert_path,
            'private_key_path': key_path,
            'initial_access_user': random_user if principal_type == "managed_identity" else None
        }
        
        # Assign privileges based on method
        if attack_config['method'] == "AzureADRole":
            if isinstance(attack_config['entra_role'], list):
                role_ids = attack_config['entra_role']
            elif attack_config['entra_role'] == 'random':
                role_ids = [random.choice(list(HIGH_PRIVILEGED_ENTRA_ROLES.values()))]
            else:
                role_ids = [attack_config['entra_role']]
            
            app_role_assignments[key] = {
                'app_name': random_app,
                'role_ids': role_ids
            }
        
        elif attack_config['method'] == "GraphAPIPermission":
            if isinstance(attack_config['app_role'], list):
                api_permission_ids = attack_config['app_role']
            elif attack_config['app_role'] != 'random':
                api_permission_ids = [attack_config['app_role']]
            else:
                api_permission_ids = [random.choice(
                    [perm["id"] for perm in HIGH_PRIVILEGED_GRAPH_API_PERMISSIONS.values()]
                )]
            
            app_api_permission_assignments[key] = {
                'app_name': random_app,
                'api_permission_ids': api_permission_ids,
            }
        
        return (
            attack_path_storage_abuse_assignments,
            app_role_assignments,
            app_api_permission_assignments,
            vm_contributor_assignments
        )