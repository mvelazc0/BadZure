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
    API_REGISTRY,
    APP_ADMIN_ROLE_ID,
    CLOUD_APP_ADMIN_ROLE_ID,
    RECON_DIRECTORY_READ_ALL_ID
)
from src.crypto import generate_certificate_and_key
from src.entity_generator import EntityGenerator


class AttackPathManager:
    """Manages creation of attack paths for both random and targeted modes."""
    
    def __init__(self, entity_generator: EntityGenerator = None):
        """
        Initialize AttackPathManager.
        
        Args:
            entity_generator: EntityGenerator instance for creating attack path groups.
                            If not provided, a new instance will be created.
        """
        self.entity_generator = entity_generator or EntityGenerator()

    def build_recon_permissions(self, user_creds: Dict) -> Tuple[Dict, Dict]:
        """
        Build recon permissions for all initial access identities.

        - Service principals get Directory.Read.All (Graph API) for Entra ID enumeration
        - All identities (users and SPs) get subscription-level Reader role for Azure resource enumeration
        - Users already have directory read access by default in Entra ID
        """
        recon_api_permissions = {}
        subscription_reader_assignments = {}

        for path_name, credentials in user_creds.items():
            identity_type = credentials.get('initial_access')

            if identity_type == 'service_principal':
                sp_name = credentials.get('service_principal_name')
                if sp_name:
                    # Directory.Read.All for Entra ID enumeration
                    api_key = f"recon_{sp_name}"
                    if api_key not in recon_api_permissions:
                        recon_api_permissions[api_key] = {
                            'app_name': sp_name,
                            'api_permission_ids': [RECON_DIRECTORY_READ_ALL_ID],
                            'api_type': 'graph'
                        }
                    # Subscription Reader for Azure resource enumeration
                    reader_key = f"recon_{sp_name}"
                    if reader_key not in subscription_reader_assignments:
                        subscription_reader_assignments[reader_key] = {
                            'initial_access': 'service_principal',
                            'principal_name': sp_name
                        }

            elif identity_type == 'user':
                # Extract bare username from UPN (remove @domain)
                upn = credentials.get('user_principal_name', '')
                principal_name = upn.split('@')[0] if '@' in upn else upn
                if principal_name:
                    # Subscription Reader only (users already have directory read)
                    reader_key = f"recon_{principal_name}"
                    if reader_key not in subscription_reader_assignments:
                        subscription_reader_assignments[reader_key] = {
                            'initial_access': 'user',
                            'principal_name': principal_name
                        }

        return recon_api_permissions, subscription_reader_assignments

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
    ) -> Dict:
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
            Dictionary with keys:
                - credentials: Initial access credentials
                - app_owner_assignments: Application owner assignments
                - user_role_assignments: User role assignments
                - app_role_assignments: Application role assignments
                - app_api_permission_assignments: API permission assignments
                - group_assignments: Groups to create for indirect assignment
                - group_membership_assignments: Group membership assignments
        """
        app_owner_assignments = {}
        user_role_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        group_assignments = {}
        group_membership_assignments = {}
        
        # Get initial_access, entry_point, and assignment_type from config
        identity_type = attack_config.get('initial_access', 'user')
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        scenario = attack_config.get('scenario', 'direct')
        assignment_type = attack_config.get('assignment_type', 'direct')
        
        # Validate: assignment_type 'group_member'/'group_owner' is NOT supported for ApplicationOwnershipAbuse
        # Azure AD does not allow groups to be application owners
        if assignment_type in ('group_member', 'group_owner'):
            logging.warning(f"{path_name}: assignment_type '{assignment_type}' is not supported for ApplicationOwnershipAbuse. "
                          "Azure AD does not allow groups to be application owners. Falling back to 'direct'.")
            assignment_type = 'direct'
        
        # Validate: helpdesk scenario only works with user identity_type
        if scenario == 'helpdesk' and identity_type == 'service_principal':
            logging.warning(f"{path_name}: Helpdesk scenario is not supported with service_principal initial_access. Falling back to user.")
            identity_type = 'user'
        
        # Generate attack path key
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            # Include path_name in random mode to enable filtering in output
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Select entities based on mode and identity_type
        if mode == 'random':
            app_name, principal_name, second_user_name = self._select_random_entities_app_ownership(
                users, applications, scenario, identity_type,
                used_apps, used_users
            )
        else:  # targeted mode
            app_name, principal_name, second_user_name = self._select_targeted_entities_app_ownership(
                users, applications, entities, scenario, identity_type, path_name
            )
        
        # Create initial access credentials based on identity_type
        if identity_type == 'user':
            user_principal_name = f"{principal_name}@{domain}"
            password = users[principal_name]['password']
            
            if scenario == "direct":
                credentials = {
                    "initial_access": "user",
                    "user_principal_name": user_principal_name,
                    "password": password,
                    "entry_point": entry_point
                }
            elif scenario == "helpdesk":
                helpdesk_admin_role_id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
                second_user_principal_name = f"{second_user_name}@{domain}"
                second_user_password = users[second_user_name]['password']
                
                credentials = {
                    "initial_access": "user",
                    "user_principal_name": second_user_principal_name,
                    "password": second_user_password,
                    "entry_point": entry_point
                }
                
                user_role_assignments[key] = {
                    'initial_access': 'user',
                    'principal_name': second_user_name,
                    'role_definition_id': helpdesk_admin_role_id,
                    'entry_point': entry_point
                }
            
            # App owner assignment for user - handle group-based assignment
            if assignment_type == 'group_member':
                # Generate a dedicated group for this attack path
                group_spec = self.entity_generator.generate_attack_path_group()
                group_name = group_spec['display_name']

                # Add group to be created
                group_assignments[group_name] = group_spec

                # Add user to group
                group_membership_assignments[key] = {
                    'group_name': group_name,
                    'initial_access': 'user',
                    'principal_name': principal_name
                }

                # App owner assignment - group owns the application
                app_owner_assignments[key] = {
                    'app_name': app_name,
                    'initial_access': 'group',
                    'principal_name': group_name,
                    'entry_point': entry_point,
                    'assignment_type': 'group_member',
                    'group_name': group_name,
                    'original_principal': principal_name,
                    'original_initial_access': 'user'
                }
            else:
                # Direct assignment
                app_owner_assignments[key] = {
                    'app_name': app_name,
                    'initial_access': 'user',
                    'principal_name': principal_name,
                    'entry_point': entry_point,
                    'assignment_type': 'direct'
                }
        else:  # service_principal
            # For service principal, we need to generate credentials
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point
            }
            
            # App owner assignment for service principal - handle group-based assignment
            if assignment_type == 'group_member':
                # Generate a dedicated group for this attack path
                group_spec = self.entity_generator.generate_attack_path_group()
                group_name = group_spec['display_name']

                # Add group to be created
                group_assignments[group_name] = group_spec

                # Add service principal to group
                group_membership_assignments[key] = {
                    'group_name': group_name,
                    'initial_access': 'service_principal',
                    'principal_name': principal_name
                }

                # App owner assignment - group owns the application
                app_owner_assignments[key] = {
                    'app_name': app_name,
                    'initial_access': 'group',
                    'principal_name': group_name,
                    'entry_point': entry_point,
                    'assignment_type': 'group_member',
                    'group_name': group_name,
                    'original_principal': principal_name,
                    'original_initial_access': 'service_principal'
                }
            else:
                # Direct assignment
                app_owner_assignments[key] = {
                    'app_name': app_name,
                    'initial_access': 'service_principal',
                    'principal_name': principal_name,
                    'entry_point': entry_point,
                    'assignment_type': 'direct'
                }
        
        # Assign privileges
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return {
            'credentials': credentials,
            'app_owner_assignments': app_owner_assignments,
            'user_role_assignments': user_role_assignments,
            'app_role_assignments': app_role_assignments,
            'app_api_permission_assignments': app_api_permission_assignments,
            'group_assignments': group_assignments,
            'group_membership_assignments': group_membership_assignments
        }
    
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
    ) -> Dict:
        """
        Create Application Administrator Abuse attack path.

        This technique exploits the Application Administrator Entra ID role to manage
        any application in the tenant and add credentials to privileged applications.
        """
        return self._create_admin_role_abuse(
            attack_config, users, applications, domain,
            admin_role_id=APP_ADMIN_ROLE_ID,
            mode=mode, entities=entities, path_name=path_name,
            used_apps=used_apps, used_users=used_users
        )

    def create_cloud_app_administrator_abuse(
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
    ) -> Dict:
        """
        Create Cloud Application Administrator Abuse attack path.

        This technique exploits the Cloud Application Administrator Entra ID role to manage
        applications in the tenant (excluding those with certain sensitive permissions)
        and add credentials to privileged applications.
        """
        return self._create_admin_role_abuse(
            attack_config, users, applications, domain,
            admin_role_id=CLOUD_APP_ADMIN_ROLE_ID,
            mode=mode, entities=entities, path_name=path_name,
            used_apps=used_apps, used_users=used_users
        )

    def _create_admin_role_abuse(
        self,
        attack_config: Dict,
        users: Dict,
        applications: Dict,
        domain: str,
        admin_role_id: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None,
        used_users: Optional[set] = None
    ) -> Dict:
        """
        Shared implementation for Application Administrator and Cloud Application
        Administrator abuse attack paths.

        Args:
            attack_config: Attack path configuration
            users: Dictionary of users
            applications: Dictionary of applications
            domain: Domain name
            admin_role_id: The Entra ID role ID to assign
            mode: 'random' or 'targeted'
            entities: Entity specifications (required for targeted mode)
            path_name: Attack path name (used for targeted mode)
            used_apps: Set of already-used application names
            used_users: Set of already-used user names

        Returns:
            Dictionary with keys:
                - credentials: Initial access credentials
                - user_role_assignments: User role assignments
                - app_role_assignments: Application role assignments
                - app_api_permission_assignments: API permission assignments
                - group_assignments: Groups to create for indirect assignment
                - group_membership_assignments: Group membership assignments
        """
        user_role_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        group_assignments = {}
        group_membership_assignments = {}

        # Get initial_access, entry_point, assignment_type, and scope from config
        identity_type = attack_config.get('initial_access', 'user')
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        assignment_type = attack_config.get('assignment_type', 'direct')
        scope = attack_config.get('scope', 'directory')

        # Generate attack path key
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            # Include path_name in random mode to enable filtering in output
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"

        # Select entities based on mode and identity_type
        if mode == 'random':
            app_name, principal_name = self._select_random_entities_app_administrator(
                users, applications, identity_type, used_apps, used_users
            )
        else:  # targeted mode
            app_name, principal_name = self._select_targeted_entities_app_administrator(
                users, applications, entities, identity_type, path_name
            )

        # Determine scope_app_name: scope to target application or directory-wide
        scope_app_name = app_name if scope == 'application' else None

        # Create initial access credentials based on identity_type
        if identity_type == 'user':
            user_principal_name = f"{principal_name}@{domain}"
            password = users[principal_name]['password']

            credentials = {
                "initial_access": "user",
                "user_principal_name": user_principal_name,
                "password": password,
                "entry_point": entry_point
            }

            # Assign admin role - handle group-based assignment
            if assignment_type in ('group_member', 'group_owner'):
                # Generate a dedicated group for this attack path
                if assignment_type == 'group_owner':
                    group_spec = self.entity_generator.generate_attack_path_group(
                        owner_name=principal_name, owner_type='user'
                    )
                else:
                    group_spec = self.entity_generator.generate_attack_path_group()
                group_name = group_spec['display_name']

                # Add group to be created
                group_assignments[group_name] = group_spec

                # Only add membership for 'group_member' — NOT for 'group_owner'
                if assignment_type == 'group_member':
                    group_membership_assignments[key] = {
                        'group_name': group_name,
                        'initial_access': 'user',
                        'principal_name': principal_name
                    }

                # Assign admin role to group
                user_role_assignments[key] = {
                    'initial_access': 'group',
                    'principal_name': group_name,
                    'role_definition_id': admin_role_id,
                    'entry_point': entry_point,
                    'assignment_type': assignment_type,
                    'group_name': group_name,
                    'original_principal': principal_name,
                    'original_initial_access': 'user',
                    'scope_app_name': scope_app_name
                }
            else:
                # Direct assignment
                user_role_assignments[key] = {
                    'initial_access': 'user',
                    'principal_name': principal_name,
                    'role_definition_id': admin_role_id,
                    'entry_point': entry_point,
                    'assignment_type': 'direct',
                    'scope_app_name': scope_app_name
                }
        else:  # service_principal
            # For service principal, we need to generate credentials
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point
            }

            # Assign admin role - handle group-based assignment
            if assignment_type in ('group_member', 'group_owner'):
                # Generate a dedicated group for this attack path
                if assignment_type == 'group_owner':
                    group_spec = self.entity_generator.generate_attack_path_group(
                        owner_name=principal_name, owner_type='service_principal'
                    )
                else:
                    group_spec = self.entity_generator.generate_attack_path_group()
                group_name = group_spec['display_name']

                # Add group to be created
                group_assignments[group_name] = group_spec

                # Only add membership for 'group_member' — NOT for 'group_owner'
                if assignment_type == 'group_member':
                    group_membership_assignments[key] = {
                        'group_name': group_name,
                        'initial_access': 'service_principal',
                        'principal_name': principal_name
                    }

                # Assign admin role to group
                user_role_assignments[key] = {
                    'initial_access': 'group',
                    'principal_name': group_name,
                    'role_definition_id': admin_role_id,
                    'entry_point': entry_point,
                    'assignment_type': assignment_type,
                    'group_name': group_name,
                    'original_principal': principal_name,
                    'original_initial_access': 'service_principal',
                    'scope_app_name': scope_app_name
                }
            else:
                # Direct assignment
                user_role_assignments[key] = {
                    'initial_access': 'service_principal',
                    'principal_name': principal_name,
                    'role_definition_id': admin_role_id,
                    'entry_point': entry_point,
                    'assignment_type': 'direct',
                    'scope_app_name': scope_app_name
                }

        # Assign privileges to the target application
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )

        return {
            'credentials': credentials,
            'user_role_assignments': user_role_assignments,
            'app_role_assignments': app_role_assignments,
            'app_api_permission_assignments': app_api_permission_assignments,
            'group_assignments': group_assignments,
            'group_membership_assignments': group_membership_assignments
        }
    
    def create_managed_identity_abuse(
        self,
        attack_config: Dict,
        applications: Dict,
        key_vaults: Dict,
        storage_accounts: Dict,
        users: Dict,
        domain: str,
        virtual_machines: Dict,
        logic_apps: Dict,
        automation_accounts: Dict,
        function_apps: Dict,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None,
        used_users: Optional[set] = None,
        cosmos_dbs: Optional[Dict] = None
    ) -> Dict:
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
            Dictionary with keys:
                - mi_abuse_assignments: Managed identity theft assignments
                - app_role_assignments: Application role assignments
                - app_api_permission_assignments: API permission assignments
                - vm_contributor_assignments: VM contributor assignments (empty)
                - group_assignments: Groups to create for indirect assignment
                - group_membership_assignments: Group membership assignments
        """
        mi_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}  # Empty - Terraform handles this directly
        group_assignments = {}
        group_membership_assignments = {}
        
        # Generate attack path key
        attack_path_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"
        
        # Get source_type, target_resource_type, entry_point, initial_access, credential_type, and assignment_type from config
        source_type = attack_config.get('source_type', 'vm')
        target_resource_type = attack_config.get('target_resource_type')
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        identity_type = attack_config.get('initial_access', 'user')
        credential_type = attack_config.get('credential_type', 'secret')
        assignment_type = attack_config.get('assignment_type', 'direct')
        
        # Select entities based on mode
        if mode == 'random':
            app_name, target_name, source_name, principal_name = self._select_random_entities_mi_abuse(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, source_type, target_resource_type,
                identity_type, used_apps, used_users,
                cosmos_dbs=cosmos_dbs or {}
            )
        else:  # targeted mode
            app_name, target_name, source_name, principal_name = self._select_targeted_entities_mi_abuse(
                applications, key_vaults, storage_accounts, virtual_machines, logic_apps,
                automation_accounts, function_apps, users, entities, source_type, target_resource_type,
                identity_type, path_name,
                cosmos_dbs=cosmos_dbs or {}
            )
        
        # Create initial access credentials based on identity_type
        if identity_type == 'user':
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point
            }
        else:  # service_principal
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point
            }

        # Create MI theft assignment
        # Note: Source Contributor assignment is handled directly by Terraform
        # from the initial_access_principal field in this assignment
        mi_abuse_assignment = {
            'source_type': source_type,
            'source_name': source_name,
            'target_resource_type': target_resource_type,
            'target_name': target_name,
            'app_name': app_name,
            'entry_point': entry_point,
            'initial_access': identity_type,
            'initial_access_principal': principal_name,
            'managed_identity_name': source_name  # For VMs, MI name = VM name
        }
        
        # Handle group-based assignment for the Contributor role
        if assignment_type in ('group_member', 'group_owner'):
            # Generate a dedicated group for this attack path
            if assignment_type == 'group_owner':
                group_spec = self.entity_generator.generate_attack_path_group(
                    owner_name=principal_name, owner_type=identity_type
                )
            else:
                group_spec = self.entity_generator.generate_attack_path_group()
            group_name = group_spec['display_name']

            # Add group to be created
            group_assignments[group_name] = group_spec

            # Only add membership for 'group_member' — NOT for 'group_owner'
            if assignment_type == 'group_member':
                group_membership_assignments[key] = {
                    'group_name': group_name,
                    'initial_access': identity_type,
                    'principal_name': principal_name
                }

            # Update MI theft assignment with group info
            mi_abuse_assignment['assignment_type'] = assignment_type
            mi_abuse_assignment['group_name'] = group_name
            mi_abuse_assignment['original_principal'] = principal_name
            mi_abuse_assignment['original_initial_access'] = identity_type
        else:
            mi_abuse_assignment['assignment_type'] = 'direct'
        
        # Generate certificate based on credential_type for both key_vault and storage_account
        if credential_type == 'certificate':
            # Generate certificates when requested (for both key_vault and storage_account)
            cert_path, key_path, pfx_path = generate_certificate_and_key(app_name)
            mi_abuse_assignment['certificate_path'] = cert_path
            mi_abuse_assignment['private_key_path'] = key_path
            mi_abuse_assignment['pfx_path'] = pfx_path
            mi_abuse_assignment['credential_type'] = 'certificate'
        else:
            # Use secrets (app ID and secret) - no certificate generation needed
            mi_abuse_assignment['certificate_path'] = ''
            mi_abuse_assignment['private_key_path'] = ''
            mi_abuse_assignment['pfx_path'] = ''
            mi_abuse_assignment['credential_type'] = 'secret'
        
        mi_abuse_assignments[key] = mi_abuse_assignment
        
        # Assign privileges to the target application
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return {
            'credentials': credentials,
            'mi_abuse_assignments': mi_abuse_assignments,
            'app_role_assignments': app_role_assignments,
            'app_api_permission_assignments': app_api_permission_assignments,
            'vm_contributor_assignments': vm_contributor_assignments,
            'group_assignments': group_assignments,
            'group_membership_assignments': group_membership_assignments
        }
    
    def create_keyvault_secret_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        keyvaults: Dict,
        users: Dict,
        service_principals: Dict,
        virtual_machines: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Dict:
        """
        Create Key Vault Secret Theft attack path.
        
        This technique only supports identity_type 'user' or 'service_principal'.
        For managed identity scenarios, use ManagedIdentityAbuse instead.
        
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
            Dictionary with keys:
                - kv_abuse_assignments: Key vault abuse assignments
                - app_role_assignments: Application role assignments
                - app_api_permission_assignments: API permission assignments
                - vm_contributor_assignments: VM contributor assignments (empty)
                - group_assignments: Groups to create for indirect assignment
                - group_membership_assignments: Group membership assignments
        """
        # Validate identity_type
        identity_type = attack_config.get('initial_access', 'user')
        if identity_type == 'managed_identity':
            raise ValueError(
                "KeyVaultSecretTheft does not support initial_access 'managed_identity'. "
                "Use 'ManagedIdentityAbuse' with target_resource_type 'key_vault' instead."
            )
        
        attack_path_kv_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}
        group_assignments = {}
        group_membership_assignments = {}
        
        # Get assignment_type from config
        assignment_type = attack_config.get('assignment_type', 'direct')
        
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
                identity_type, used_apps
            )
        else:  # targeted mode
            app_name, kv_name, principal_name = self._select_targeted_entities_kv_secret_theft(
                applications, keyvaults, users,
                entities, identity_type, path_name
            )
        
        # Build initial access credentials
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        if identity_type == 'user':
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point
            }
        else:  # service_principal
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point
            }

        # Create KV abuse assignment
        kv_abuse_assignment = {
            "key_vault": kv_name,
            "initial_access": identity_type,
            "principal_name": principal_name,
            "app_name": app_name
        }
        
        # Handle group-based assignment for Key Vault access
        if assignment_type in ('group_member', 'group_owner'):
            # Generate a dedicated group for this attack path
            if assignment_type == 'group_owner':
                group_spec = self.entity_generator.generate_attack_path_group(
                    owner_name=principal_name, owner_type=identity_type
                )
            else:
                group_spec = self.entity_generator.generate_attack_path_group()
            group_name = group_spec['display_name']

            # Add group to be created
            group_assignments[group_name] = group_spec

            # Only add membership for 'group_member' — NOT for 'group_owner'
            if assignment_type == 'group_member':
                group_membership_assignments[key] = {
                    'group_name': group_name,
                    'initial_access': identity_type,
                    'principal_name': principal_name
                }

            # Update KV abuse assignment with group info
            kv_abuse_assignment['assignment_type'] = assignment_type
            kv_abuse_assignment['group_name'] = group_name
            kv_abuse_assignment['original_principal'] = principal_name
            kv_abuse_assignment['original_initial_access'] = identity_type
        else:
            kv_abuse_assignment['assignment_type'] = 'direct'
        
        attack_path_kv_abuse_assignments[key] = kv_abuse_assignment
        
        # Assign privileges
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return {
            'credentials': credentials,
            'kv_abuse_assignments': attack_path_kv_abuse_assignments,
            'app_role_assignments': app_role_assignments,
            'app_api_permission_assignments': app_api_permission_assignments,
            'vm_contributor_assignments': vm_contributor_assignments,
            'group_assignments': group_assignments,
            'group_membership_assignments': group_membership_assignments
        }
    
    def create_storage_certificate_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        storage_accounts: Dict,
        users: Dict,
        service_principals: Dict,
        virtual_machines: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Dict:
        """
        Create Storage Certificate Theft attack path.
        
        This technique only supports identity_type 'user' or 'service_principal'.
        For managed identity scenarios, use ManagedIdentityAbuse instead.
        
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
            Dictionary with keys:
                - storage_abuse_assignments: Storage abuse assignments
                - app_role_assignments: Application role assignments
                - app_api_permission_assignments: API permission assignments
                - vm_contributor_assignments: VM contributor assignments (empty)
                - group_assignments: Groups to create for indirect assignment
                - group_membership_assignments: Group membership assignments
        """
        # Validate identity_type
        identity_type = attack_config.get('initial_access', 'user')
        if identity_type == 'managed_identity':
            raise ValueError(
                "StorageCertificateTheft does not support initial_access 'managed_identity'. "
                "Use 'ManagedIdentityAbuse' with target_resource_type 'storage_account' instead."
            )
        
        attack_path_storage_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        vm_contributor_assignments = {}
        group_assignments = {}
        group_membership_assignments = {}
        
        # Get assignment_type from config
        assignment_type = attack_config.get('assignment_type', 'direct')
        
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
                identity_type, used_apps
            )
        else:  # targeted mode
            app_name, sa_name, principal_name = self._select_targeted_entities_storage_cert_theft(
                applications, storage_accounts, users,
                entities, identity_type, path_name
            )
        
        # Build initial access credentials
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        if identity_type == 'user':
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point
            }
        else:  # service_principal
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point
            }

        # Generate certificate
        cert_path, key_path, pfx_path = generate_certificate_and_key(app_name)

        # Create storage abuse assignment
        storage_abuse_assignment = {
            "app_name": app_name,
            "storage_account": sa_name,
            "initial_access": identity_type,
            "principal_name": principal_name,
            'certificate_path': cert_path,
            'private_key_path': key_path,
            'pfx_path': pfx_path
        }
        
        # Handle group-based assignment for Storage Account access
        if assignment_type in ('group_member', 'group_owner'):
            # Generate a dedicated group for this attack path
            if assignment_type == 'group_owner':
                group_spec = self.entity_generator.generate_attack_path_group(
                    owner_name=principal_name, owner_type=identity_type
                )
            else:
                group_spec = self.entity_generator.generate_attack_path_group()
            group_name = group_spec['display_name']

            # Add group to be created
            group_assignments[group_name] = group_spec

            # Only add membership for 'group_member' — NOT for 'group_owner'
            if assignment_type == 'group_member':
                group_membership_assignments[key] = {
                    'group_name': group_name,
                    'initial_access': identity_type,
                    'principal_name': principal_name
                }

            # Update storage abuse assignment with group info
            storage_abuse_assignment['assignment_type'] = assignment_type
            storage_abuse_assignment['group_name'] = group_name
            storage_abuse_assignment['original_principal'] = principal_name
            storage_abuse_assignment['original_initial_access'] = identity_type
        else:
            storage_abuse_assignment['assignment_type'] = 'direct'
        
        attack_path_storage_abuse_assignments[key] = storage_abuse_assignment
        
        # Assign privileges
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )
        
        return {
            'credentials': credentials,
            'storage_abuse_assignments': attack_path_storage_abuse_assignments,
            'app_role_assignments': app_role_assignments,
            'app_api_permission_assignments': app_api_permission_assignments,
            'vm_contributor_assignments': vm_contributor_assignments,
            'group_assignments': group_assignments,
            'group_membership_assignments': group_membership_assignments
        }
    
    def create_cosmosdb_secret_theft(
        self,
        attack_config: Dict,
        applications: Dict,
        cosmos_dbs: Dict,
        users: Dict,
        service_principals: Dict,
        domain: str,
        mode: str = 'random',
        entities: Optional[Dict] = None,
        path_name: Optional[str] = None,
        used_apps: Optional[set] = None
    ) -> Dict:
        """
        Create Cosmos DB Secret Theft attack path.

        This technique only supports identity_type 'user' or 'service_principal'.
        For managed identity scenarios, use ManagedIdentityAbuse with target_resource_type 'cosmos_db'.

        Args:
            attack_config: Attack path configuration
            applications: Dictionary of applications
            cosmos_dbs: Dictionary of Cosmos DB accounts
            users: Dictionary of users
            service_principals: Dictionary of service principals
            domain: Domain name
            mode: 'random' or 'targeted'
            entities: Entity specifications (required for targeted mode)
            path_name: Attack path name (used for targeted mode)
            used_apps: Set of already-used application names

        Returns:
            Dictionary with keys:
                - cosmos_abuse_assignments: Cosmos DB abuse assignments
                - app_role_assignments: Application role assignments
                - app_api_permission_assignments: API permission assignments
                - group_assignments: Groups to create for indirect assignment
                - group_membership_assignments: Group membership assignments
        """
        # Validate identity_type
        identity_type = attack_config.get('initial_access', 'user')
        if identity_type == 'managed_identity':
            raise ValueError(
                "CosmosDBSecretTheft does not support initial_access 'managed_identity'. "
                "Use 'ManagedIdentityAbuse' with target_resource_type 'cosmos_db' instead."
            )

        attack_path_cosmos_abuse_assignments = {}
        app_role_assignments = {}
        app_api_permission_assignments = {}
        group_assignments = {}
        group_membership_assignments = {}

        # Get assignment_type from config
        assignment_type = attack_config.get('assignment_type', 'direct')

        # Generate attack path key
        attack_path_id = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        if mode == 'targeted' and path_name:
            key = f"attack-path-{path_name}-{attack_path_id}"
        elif mode == 'random' and path_name:
            key = f"{path_name}-{attack_path_id}"
        else:
            key = f"attack-path-{attack_path_id}"

        # Select entities based on mode
        if mode == 'random':
            app_name, cosmos_db_name, principal_name = self._select_random_entities_cosmos_secret_theft(
                applications, cosmos_dbs, users, service_principals,
                identity_type, used_apps
            )
        else:  # targeted mode
            app_name, cosmos_db_name, principal_name = self._select_targeted_entities_cosmos_secret_theft(
                applications, cosmos_dbs, users,
                entities, identity_type, path_name
            )

        # Build initial access credentials
        entry_point = attack_config.get('entry_point', 'compromised_identity')
        if identity_type == 'user':
            credentials = {
                "initial_access": "user",
                "user_principal_name": f"{principal_name}@{domain}",
                "password": users[principal_name]['password'],
                "entry_point": entry_point
            }
        else:  # service_principal
            credentials = {
                "initial_access": "service_principal",
                "service_principal_name": principal_name,
                "entry_point": entry_point
            }

        # Create Cosmos DB abuse assignment
        cosmos_abuse_assignment = {
            "cosmos_db": cosmos_db_name,
            "initial_access": identity_type,
            "principal_name": principal_name,
            "app_name": app_name
        }

        # Handle group-based assignment for Cosmos DB access
        if assignment_type in ('group_member', 'group_owner'):
            if assignment_type == 'group_owner':
                group_spec = self.entity_generator.generate_attack_path_group(
                    owner_name=principal_name, owner_type=identity_type
                )
            else:
                group_spec = self.entity_generator.generate_attack_path_group()
            group_name = group_spec['display_name']

            group_assignments[group_name] = group_spec

            if assignment_type == 'group_member':
                group_membership_assignments[key] = {
                    'group_name': group_name,
                    'initial_access': identity_type,
                    'principal_name': principal_name
                }

            cosmos_abuse_assignment['assignment_type'] = assignment_type
            cosmos_abuse_assignment['group_name'] = group_name
            cosmos_abuse_assignment['original_principal'] = principal_name
            cosmos_abuse_assignment['original_initial_access'] = identity_type
        else:
            cosmos_abuse_assignment['assignment_type'] = 'direct'

        attack_path_cosmos_abuse_assignments[key] = cosmos_abuse_assignment

        # Assign privileges
        self._assign_app_privileges(
            attack_config, app_name, key,
            app_role_assignments, app_api_permission_assignments
        )

        return {
            'credentials': credentials,
            'cosmos_abuse_assignments': attack_path_cosmos_abuse_assignments,
            'app_role_assignments': app_role_assignments,
            'app_api_permission_assignments': app_api_permission_assignments,
            'group_assignments': group_assignments,
            'group_membership_assignments': group_membership_assignments
        }

    # ========================================================================
    # Random Mode Entity Selection
    # ========================================================================

    def _select_random_entities_app_ownership(
        self, users: Dict, applications: Dict, scenario: str, identity_type: str,
        used_apps: set = None, used_users: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Application Ownership Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            scenario: 'direct' or 'helpdesk'
            identity_type: 'user' or 'service_principal'
            used_apps: Set of already-used application names
            used_users: Set of already-used user/principal names
        
        Returns:
            Tuple of (app_name, principal_name, second_user_name)
        """
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        if identity_type == 'user':
            user_keys = list(users.keys())
            
            # Exclude used users
            if used_users:
                available_users = [user for user in user_keys if user not in used_users]
                if available_users:
                    user_keys = available_users
            
            principal_name = random.choice(user_keys)
            second_user_name = random.choice(user_keys) if scenario == "helpdesk" else principal_name
        else:  # service_principal
            # For service principal, select a different application as the owner
            sp_keys = [k for k in applications.keys() if k != app_name]
            if sp_keys:
                principal_name = random.choice(sp_keys)
            else:
                # Fallback to the same app if no other apps available
                principal_name = app_name
            second_user_name = principal_name  # Not used for service_principal
        
        return app_name, principal_name, second_user_name
    
    def _select_random_entities_app_administrator(
        self, users: Dict, applications: Dict, identity_type: str,
        used_apps: set = None, used_users: set = None
    ) -> Tuple[str, str]:
        """Select random entities for Application Administrator Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            identity_type: 'user' or 'service_principal'
            used_apps: Set of already-used application names
            used_users: Set of already-used user/principal names
        
        Returns:
            Tuple of (app_name, principal_name)
        """
        app_keys = list(applications.keys())
        
        # Exclude used applications
        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps
        
        app_name = random.choice(app_keys)
        
        if identity_type == 'user':
            user_keys = list(users.keys())
            
            # Exclude used users
            if used_users:
                available_users = [user for user in user_keys if user not in used_users]
                if available_users:
                    user_keys = available_users
            
            principal_name = random.choice(user_keys)
        else:  # service_principal
            # For service principal, select a different application
            sp_keys = [k for k in applications.keys() if k != app_name]
            if sp_keys:
                principal_name = random.choice(sp_keys)
            else:
                # Fallback to the same app if no other apps available
                principal_name = app_name
        
        return app_name, principal_name
    
    def _select_random_entities_kv_secret_theft(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        service_principals: Dict, identity_type: str,
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
        
        if identity_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif identity_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
        
        return app_name, kv_name, principal_name
    
    def _select_random_entities_storage_cert_theft(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        service_principals: Dict, identity_type: str,
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
        
        if identity_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif identity_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))
        
        return app_name, sa_name, principal_name

    def _select_random_entities_cosmos_secret_theft(
        self, applications: Dict, cosmos_dbs: Dict, users: Dict,
        service_principals: Dict, identity_type: str,
        used_apps: set = None
    ) -> Tuple[str, str, str]:
        """Select random entities for Cosmos DB Secret Theft."""
        app_keys = list(applications.keys())

        if used_apps:
            available_apps = [app for app in app_keys if app not in used_apps]
            if available_apps:
                app_keys = available_apps

        app_name = random.choice(app_keys)
        cosmos_db_name = random.choice(list(cosmos_dbs.keys()))

        if identity_type == "user":
            principal_name = random.choice(list(users.keys()))
        elif identity_type == "service_principal":
            principal_name = random.choice(list(service_principals.keys()))

        return app_name, cosmos_db_name, principal_name

    def _select_random_entities_mi_abuse(
        self, applications: Dict, key_vaults: Dict, storage_accounts: Dict,
        virtual_machines: Dict, logic_apps: Dict, automation_accounts: Dict, function_apps: Dict, users: Dict,
        source_type: str, target_resource_type: str, identity_type: str,
        used_apps: set = None, used_users: set = None,
        cosmos_dbs: Dict = None
    ) -> Tuple[str, str, str, str]:
        """Select random entities for Managed Identity Theft.

        Args:
            applications: Dictionary of applications
            key_vaults: Dictionary of key vaults
            storage_accounts: Dictionary of storage accounts
            virtual_machines: Dictionary of virtual machines
            logic_apps: Dictionary of logic apps
            automation_accounts: Dictionary of automation accounts
            function_apps: Dictionary of function apps
            users: Dictionary of users (used when identity_type is 'user')
            source_type: Type of source resource ('vm', 'logic_app', etc.)
            target_resource_type: Type of target resource ('key_vault', 'storage_account', 'cosmos_db')
            identity_type: Type of initial access identity ('user' or 'service_principal')
            used_apps: Set of already-used application names
            used_users: Set of already-used user names
            cosmos_dbs: Dictionary of Cosmos DB accounts

        Returns:
            Tuple of (app_name, target_name, source_name, principal_name)
        """
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
        elif target_resource_type == 'cosmos_db' and cosmos_dbs:
            target_name = random.choice(list(cosmos_dbs.keys()))
        else:
            # For future expansion: subscription, resource_group
            target_name = random.choice(list(key_vaults.keys()))
        
        # Select principal for Contributor access based on identity_type
        if identity_type == 'user':
            user_keys = list(users.keys())
            # Exclude used users
            if used_users:
                available_users = [user for user in user_keys if user not in used_users]
                if available_users:
                    user_keys = available_users
            principal_name = random.choice(user_keys)
        elif identity_type == 'service_principal':
            # For service_principal, use a random application (different from target app)
            sp_keys = [k for k in applications.keys() if k != app_name]
            if sp_keys:
                principal_name = random.choice(sp_keys)
            else:
                # Fallback to the same app if no other apps available
                principal_name = app_name
        else:
            # Default to user
            principal_name = random.choice(list(users.keys()))
        
        return app_name, target_name, source_name, principal_name
    
    # ========================================================================
    # Targeted Mode Entity Selection
    # ========================================================================
    
    def _select_targeted_entities_app_ownership(
        self, users: Dict, applications: Dict, entities: Dict,
        scenario: str, identity_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Application Ownership Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            entities: Entity specifications from config
            scenario: 'direct' or 'helpdesk'
            identity_type: 'user' or 'service_principal'
            path_name: Attack path name for error messages
        
        Returns:
            Tuple of (app_name, principal_name, second_user_name)
        """
        # Get application (target app that will be owned)
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        if identity_type == 'user':
            # Get user as owner
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
            
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
                    second_user_name = principal_name
            else:
                second_user_name = principal_name
        else:  # service_principal
            # Get service principal as owner
            sp_list = list(entities.get('service_principals', []))
            if sp_list:
                sp_spec = sp_list[0]
                principal_name = sp_spec.get('name', 'random')
                if principal_name == 'random':
                    # Use a random application as service principal (different from target)
                    sp_keys = [k for k in applications.keys() if k != app_name]
                    principal_name = random.choice(sp_keys) if sp_keys else app_name
            else:
                # Default to using a different application as service principal
                sp_keys = [k for k in applications.keys() if k != app_name]
                principal_name = random.choice(sp_keys) if sp_keys else app_name
            second_user_name = principal_name  # Not used for service_principal
        
        return app_name, principal_name, second_user_name
    
    def _select_targeted_entities_app_administrator(
        self, users: Dict, applications: Dict, entities: Dict, identity_type: str, path_name: str
    ) -> Tuple[str, str]:
        """Select targeted entities for Application Administrator Abuse.
        
        Args:
            users: Dictionary of users
            applications: Dictionary of applications
            entities: Entity specifications from config
            identity_type: 'user' or 'service_principal'
            path_name: Attack path name for error messages
        
        Returns:
            Tuple of (app_name, principal_name)
        """
        # Get application (target app with privileges)
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))
        
        if identity_type == 'user':
            # Get user with Application Administrator role
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        else:  # service_principal
            # Get service principal with Application Administrator role
            sp_list = list(entities.get('service_principals', []))
            if sp_list:
                sp_spec = sp_list[0]
                principal_name = sp_spec.get('name', 'random')
                if principal_name == 'random':
                    # Use a random application as service principal (different from target)
                    sp_keys = [k for k in applications.keys() if k != app_name]
                    principal_name = random.choice(sp_keys) if sp_keys else app_name
            else:
                # Default to using a different application as service principal
                sp_keys = [k for k in applications.keys() if k != app_name]
                principal_name = random.choice(sp_keys) if sp_keys else app_name
        
        return app_name, principal_name
    
    def _select_targeted_entities_kv_secret_theft(
        self, applications: Dict, keyvaults: Dict, users: Dict,
        entities: Dict, identity_type: str, path_name: str
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
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            principal_name = app_name
        
        return app_name, kv_name, principal_name
    
    def _select_targeted_entities_storage_cert_theft(
        self, applications: Dict, storage_accounts: Dict, users: Dict,
        entities: Dict, identity_type: str, path_name: str
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
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            principal_name = app_name
        
        return app_name, sa_name, principal_name
    
    def _select_targeted_entities_cosmos_secret_theft(
        self, applications: Dict, cosmos_dbs: Dict, users: Dict,
        entities: Dict, identity_type: str, path_name: str
    ) -> Tuple[str, str, str]:
        """Select targeted entities for Cosmos DB Secret Theft."""
        # Get application
        app_list = list(entities.get('applications', []))
        if not app_list:
            raise ValueError(f"{path_name}: No applications specified")
        app_spec = app_list[0]
        app_name = app_spec.get('name', 'random')
        if app_name == 'random':
            app_name = random.choice(list(applications.keys()))

        # Get Cosmos DB account
        cosmos_list = list(entities.get('cosmos_dbs', []))
        if not cosmos_list:
            raise ValueError(f"{path_name}: No cosmos_dbs specified")
        cosmos_spec = cosmos_list[0]
        cosmos_db_name = cosmos_spec.get('name', 'random')
        if cosmos_db_name == 'random':
            cosmos_db_name = random.choice(list(cosmos_dbs.keys()))

        # Get principal based on type
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            principal_name = app_name

        return app_name, cosmos_db_name, principal_name

    def _select_targeted_entities_mi_abuse(
        self, applications: Dict, key_vaults: Dict, storage_accounts: Dict,
        virtual_machines: Dict, logic_apps: Dict, automation_accounts: Dict, function_apps: Dict, users: Dict,
        entities: Dict, source_type: str, target_resource_type: str, identity_type: str, path_name: str,
        cosmos_dbs: Dict = None
    ) -> Tuple[str, str, str, str]:
        """Select targeted entities for Managed Identity Theft.

        Args:
            applications: Dictionary of applications
            key_vaults: Dictionary of key vaults
            storage_accounts: Dictionary of storage accounts
            virtual_machines: Dictionary of virtual machines
            logic_apps: Dictionary of logic apps
            automation_accounts: Dictionary of automation accounts
            function_apps: Dictionary of function apps
            users: Dictionary of users
            entities: Entity specifications from config
            source_type: Type of source resource ('vm', 'logic_app', etc.)
            target_resource_type: Type of target resource ('key_vault', 'storage_account', 'cosmos_db')
            identity_type: Type of initial access identity ('user' or 'service_principal')
            path_name: Attack path name for error messages
            cosmos_dbs: Dictionary of Cosmos DB accounts

        Returns:
            Tuple of (app_name, target_name, source_name, principal_name)
        """
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
        elif target_resource_type == 'cosmos_db' and cosmos_dbs:
            cosmos_list = list(entities.get('cosmos_dbs', []))
            if not cosmos_list:
                raise ValueError(f"{path_name}: target_resource_type 'cosmos_db' requires cosmos_dbs")
            cosmos_spec = cosmos_list[0]
            target_name = cosmos_spec.get('name', 'random')
            if target_name == 'random':
                target_name = random.choice(list(cosmos_dbs.keys()))
        else:
            # For future expansion
            target_name = random.choice(list(key_vaults.keys()))
        
        # Get principal for Contributor access based on identity_type
        if identity_type == 'user':
            user_list = list(entities.get('users', []))
            if not user_list:
                raise ValueError(f"{path_name}: identity_type 'user' requires users")
            user_spec = user_list[0]
            principal_name = user_spec.get('name', 'random')
            if principal_name == 'random':
                principal_name = random.choice(list(users.keys()))
        elif identity_type == 'service_principal':
            # For service_principal, use a specified service principal or the target app
            sp_list = list(entities.get('service_principals', []))
            if sp_list:
                sp_spec = sp_list[0]
                principal_name = sp_spec.get('name', 'random')
                if principal_name == 'random':
                    # Use a random application as service principal
                    sp_keys = [k for k in applications.keys() if k != app_name]
                    principal_name = random.choice(sp_keys) if sp_keys else app_name
            else:
                # Default to using a different application as service principal
                sp_keys = [k for k in applications.keys() if k != app_name]
                principal_name = random.choice(sp_keys) if sp_keys else app_name
        else:
            # Default to user
            user_list = list(entities.get('users', []))
            if user_list:
                user_spec = user_list[0]
                principal_name = user_spec.get('name', 'random')
                if principal_name == 'random':
                    principal_name = random.choice(list(users.keys()))
            else:
                principal_name = random.choice(list(users.keys()))
        
        return app_name, target_name, source_name, principal_name
    
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