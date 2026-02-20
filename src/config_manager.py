"""
Configuration management for BadZure.
Handles loading and validation of YAML configuration files.
"""
import os
import yaml
import logging
from typing import Dict, List, Tuple, Optional
from src.constants import (
    API_REGISTRY,
    ALL_API_PERMISSIONS,
    ENTRA_ROLES,
    HIGH_PRIVILEGED_ENTRA_ROLES,
    VALID_TECHNIQUES,
    MANAGED_IDENTITY_SOURCE_TYPES,
    MI_TARGET_RESOURCE_TYPES,
    FUNCTION_APP_OS_TYPES,
    VALID_ASSIGNMENT_TYPES,
    VALID_SCOPE_TYPES
)

# Environment variable names for tenant configuration
ENV_TENANT_ID = 'BADZURE_TENANT_ID'
ENV_DOMAIN = 'BADZURE_DOMAIN'
ENV_SUBSCRIPTION_ID = 'BADZURE_SUBSCRIPTION_ID'


class ConfigManager:
    """Manages configuration loading and validation for BadZure."""
    
    def load_config(self, file_path: str) -> Dict:
        """
        Load and return the configuration from a YAML file.
        
        Args:
            file_path: Path to the YAML configuration file
            
        Returns:
            Dictionary containing the configuration
            
        Raises:
            FileNotFoundError: If configuration file doesn't exist
            yaml.YAMLError: If YAML parsing fails
        """
        try:
            with open(file_path, 'r') as file:
                config = yaml.safe_load(file)
                return config
        except FileNotFoundError:
            logging.error(f"Configuration file not found at: {file_path}")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error parsing the YAML file: {e}")
            raise
    
    def validate_targeted_config(self, config: Dict) -> Tuple[bool, List[str]]:
        """
        Validates targeted mode configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        for path_name, path_config in config['attack_paths'].items():
            if not path_config.get('enabled', False):
                continue
                
            # Check entities section exists
            if 'entities' not in path_config:
                errors.append(f"{path_name}: Missing 'entities' section in targeted mode")
                continue
            
            entities = path_config['entities']
            
            # Validate based on privilege_escalation type
            priv_esc = path_config.get('privilege_escalation')
            
            # Support both old and new names with deprecation warning
            if priv_esc == 'ServicePrincipalAbuse':
                logging.warning(f"{path_name}: 'ServicePrincipalAbuse' is deprecated. Please use 'ApplicationOwnershipAbuse' instead.")
                self._validate_app_ownership_abuse(path_name, path_config, entities, errors)
            
            elif priv_esc == 'ApplicationOwnershipAbuse':
                self._validate_app_ownership_abuse(path_name, path_config, entities, errors)
            
            elif priv_esc == 'ApplicationAdministratorAbuse':
                self._validate_app_administrator_abuse(path_name, path_config, entities, errors)

            elif priv_esc == 'CloudAppAdministratorAbuse':
                self._validate_app_administrator_abuse(path_name, path_config, entities, errors)

            elif priv_esc == 'KeyVaultSecretTheft':
                self._validate_kv_secret_theft(path_name, path_config, entities, errors)

            elif priv_esc == 'StorageCertificateTheft':
                self._validate_storage_certificate_theft(path_name, path_config, entities, errors)

            elif priv_esc == 'CosmosDBSecretTheft':
                self._validate_cosmosdb_secret_theft(path_name, path_config, entities, errors)

            elif priv_esc == 'ManagedIdentityTheft':
                self._validate_managed_identity_theft(path_name, path_config, entities, errors)
        
        return len(errors) == 0, errors
    
    def _validate_app_ownership_abuse(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Application Ownership Abuse configuration."""
        identity_type = path_config.get('identity_type', 'user')
        if identity_type == 'service_principal':
            if 'service_principals' not in entities or not entities['service_principals']:
                errors.append(f"{path_name}: ApplicationOwnershipAbuse with identity_type 'service_principal' requires at least one service_principal")
        else:
            if 'users' not in entities or not entities['users']:
                errors.append(f"{path_name}: ApplicationOwnershipAbuse requires at least one user")
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: ApplicationOwnershipAbuse requires at least one application")
        
        # Validate assignment_type parameter
        self._validate_assignment_type(path_name, path_config, errors)
        
        # Validate method and related parameters
        method = path_config.get('method')
        if not method:
            errors.append(f"{path_name}: Missing 'method' parameter")
            return
        
        if method == 'AzureADRole':
            self._validate_entra_role(path_name, path_config, errors)
        elif method == 'GraphAPIPermission':
            self._validate_graph_api_permission(path_name, path_config, errors)
        elif method == 'APIPermission':
            self._validate_api_permission(path_name, path_config, errors)
        else:
            errors.append(f"{path_name}: Invalid method '{method}'. Must be 'AzureADRole', 'GraphAPIPermission', or 'APIPermission'")
    
    def _validate_app_administrator_abuse(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Application Administrator Abuse configuration."""
        identity_type = path_config.get('identity_type', 'user')
        if identity_type == 'service_principal':
            if 'service_principals' not in entities or not entities['service_principals']:
                errors.append(f"{path_name}: ApplicationAdministratorAbuse with identity_type 'service_principal' requires at least one service_principal")
        else:
            if 'users' not in entities or not entities['users']:
                errors.append(f"{path_name}: ApplicationAdministratorAbuse requires at least one user")
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: ApplicationAdministratorAbuse requires at least one application")

        # Validate assignment_type parameter
        self._validate_assignment_type(path_name, path_config, errors)

        # Validate scope parameter
        scope = path_config.get('scope', 'directory')
        if scope not in VALID_SCOPE_TYPES:
            errors.append(f"{path_name}: Invalid scope '{scope}'. Must be one of: {', '.join(VALID_SCOPE_TYPES)}")

        # Validate method and related parameters
        method = path_config.get('method')
        if not method:
            errors.append(f"{path_name}: Missing 'method' parameter")
            return
        
        if method == 'AzureADRole':
            self._validate_entra_role(path_name, path_config, errors)
        elif method == 'GraphAPIPermission':
            self._validate_graph_api_permission(path_name, path_config, errors)
        elif method == 'APIPermission':
            self._validate_api_permission(path_name, path_config, errors)
        else:
            errors.append(f"{path_name}: Invalid method '{method}'. Must be 'AzureADRole', 'GraphAPIPermission', or 'APIPermission'")
    
    def _validate_entra_role(self, path_name: str, path_config: Dict, errors: List[str]) -> None:
        """Validate Entra ID role configuration."""
        entra_role = path_config.get('entra_role')
        if not entra_role:
            errors.append(f"{path_name}: method 'AzureADRole' requires 'entra_role' parameter")
            return
        
        if entra_role == 'random':
            return  # Valid
        
        # Validate role ID(s) format only - don't restrict to predefined list
        # Users may want to use custom roles or roles not in our constants
        role_ids = [entra_role] if isinstance(entra_role, str) else entra_role
        
        import re
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        
        for role_id in role_ids:
            if not uuid_pattern.match(role_id):
                errors.append(f"{path_name}: Invalid Entra role ID format '{role_id}'. Must be a valid UUID.")
    
    def _validate_graph_api_permission(self, path_name: str, path_config: Dict, errors: List[str]) -> None:
        """Validate Graph API permission configuration (backward compatibility)."""
        app_role = path_config.get('app_role')
        if not app_role:
            errors.append(f"{path_name}: method 'GraphAPIPermission' requires 'app_role' parameter")
            return
        
        if app_role == 'random':
            return  # Valid
        
        # Validate permission ID(s) format only - don't restrict to predefined list
        # Microsoft may add new permissions, and users may want to use them
        permission_ids = [app_role] if isinstance(app_role, str) else app_role
        
        import re
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        
        for perm_id in permission_ids:
            if not uuid_pattern.match(perm_id):
                errors.append(f"{path_name}: Invalid Graph API permission ID format '{perm_id}'. Must be a valid UUID.")
    
    def _validate_api_permission(self, path_name: str, path_config: Dict, errors: List[str]) -> None:
        """Validate API permission configuration with api_type support."""
        api_type = path_config.get('api_type', 'graph')
        
        # Validate api_type
        if api_type not in API_REGISTRY:
            errors.append(f"{path_name}: Invalid api_type '{api_type}'. Must be one of: {', '.join(API_REGISTRY.keys())}")
            return
        
        app_role = path_config.get('app_role')
        if not app_role:
            errors.append(f"{path_name}: method 'APIPermission' requires 'app_role' parameter")
            return
        
        if app_role == 'random':
            return  # Valid
        
        # Validate permission ID(s) format only - don't restrict to predefined list
        # Microsoft may add new permissions, and users may want to use them
        permission_ids = [app_role] if isinstance(app_role, str) else app_role
        
        import re
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        
        for perm_id in permission_ids:
            if not uuid_pattern.match(perm_id):
                api_name = API_REGISTRY[api_type]['display_name']
                errors.append(f"{path_name}: Invalid {api_name} permission ID format '{perm_id}'. Must be a valid UUID.")
    
    def _validate_assignment_type(self, path_name: str, path_config: Dict, errors: List[str]) -> None:
        """
        Validate assignment_type parameter for attack paths.
        
        Args:
            path_name: Name of the attack path for error messages
            path_config: Attack path configuration dictionary
            errors: List to append error messages to
        """
        assignment_type = path_config.get('assignment_type', 'direct')
        if assignment_type not in VALID_ASSIGNMENT_TYPES:
            errors.append(
                f"{path_name}: Invalid assignment_type '{assignment_type}'. "
                f"Must be one of: {', '.join(VALID_ASSIGNMENT_TYPES)}"
            )
    
    def _validate_kv_secret_theft(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Key Vault Secret Theft configuration."""
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: KeyVaultSecretTheft requires at least one application")
        if 'key_vaults' not in entities or not entities['key_vaults']:
            errors.append(f"{path_name}: KeyVaultSecretTheft requires at least one key_vault")
        if 'resource_groups' not in entities or not entities['resource_groups']:
            errors.append(f"{path_name}: KeyVaultSecretTheft requires at least one resource_group")
        
        # Validate assignment_type parameter
        self._validate_assignment_type(path_name, path_config, errors)
        
        # Validate identity_type requirements (only user and service_principal supported)
        identity_type = path_config.get('identity_type', 'user')
        if identity_type not in ['user', 'service_principal']:
            errors.append(f"{path_name}: KeyVaultSecretTheft only supports identity_type 'user' or 'service_principal'. Use 'ManagedIdentityTheft' for managed identity scenarios.")
        elif identity_type == 'user' and ('users' not in entities or not entities['users']):
            errors.append(f"{path_name}: identity_type 'user' requires at least one user")
    
    def _validate_storage_certificate_theft(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Storage Certificate Theft configuration."""
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: StorageCertificateTheft requires at least one application")
        if 'storage_accounts' not in entities or not entities['storage_accounts']:
            errors.append(f"{path_name}: StorageCertificateTheft requires at least one storage_account")
        if 'resource_groups' not in entities or not entities['resource_groups']:
            errors.append(f"{path_name}: StorageCertificateTheft requires at least one resource_group")
        
        # Validate assignment_type parameter
        self._validate_assignment_type(path_name, path_config, errors)
            
        # Validate identity_type requirements (only user and service_principal supported)
        identity_type = path_config.get('identity_type', 'user')
        if identity_type not in ['user', 'service_principal']:
            errors.append(f"{path_name}: StorageCertificateTheft only supports identity_type 'user' or 'service_principal'. Use 'ManagedIdentityTheft' for managed identity scenarios.")
        elif identity_type == 'user' and ('users' not in entities or not entities['users']):
            errors.append(f"{path_name}: identity_type 'user' requires at least one user")
    
    def _validate_cosmosdb_secret_theft(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Cosmos DB Secret Theft configuration."""
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: CosmosDBSecretTheft requires at least one application")
        if 'cosmos_dbs' not in entities or not entities['cosmos_dbs']:
            errors.append(f"{path_name}: CosmosDBSecretTheft requires at least one cosmos_db")
        if 'resource_groups' not in entities or not entities['resource_groups']:
            errors.append(f"{path_name}: CosmosDBSecretTheft requires at least one resource_group")

        # Validate assignment_type parameter
        self._validate_assignment_type(path_name, path_config, errors)

        # Validate identity_type requirements (only user and service_principal supported)
        identity_type = path_config.get('identity_type', 'user')
        if identity_type not in ['user', 'service_principal']:
            errors.append(f"{path_name}: CosmosDBSecretTheft only supports identity_type 'user' or 'service_principal'. Use 'ManagedIdentityTheft' for managed identity scenarios.")
        elif identity_type == 'user' and ('users' not in entities or not entities['users']):
            errors.append(f"{path_name}: identity_type 'user' requires at least one user")

    def _validate_managed_identity_theft(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Managed Identity Theft configuration."""
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: ManagedIdentityTheft requires at least one application")
        
        # Only require user if identity_type is 'user' (or not specified, defaulting to user)
        identity_type = path_config.get('identity_type', 'user')
        if identity_type == 'user' and ('users' not in entities or not entities['users']):
            errors.append(f"{path_name}: ManagedIdentityTheft with identity_type 'user' requires at least one user for Contributor access")
        
        if 'resource_groups' not in entities or not entities['resource_groups']:
            errors.append(f"{path_name}: ManagedIdentityTheft requires at least one resource_group")
        
        # Validate assignment_type parameter
        self._validate_assignment_type(path_name, path_config, errors)
        
        # Validate source_type parameter
        source_type = path_config.get('source_type')
        if not source_type:
            errors.append(f"{path_name}: ManagedIdentityTheft requires 'source_type' parameter")
        elif source_type not in MANAGED_IDENTITY_SOURCE_TYPES:
            errors.append(f"{path_name}: Invalid source_type '{source_type}'. Must be one of: {', '.join(MANAGED_IDENTITY_SOURCE_TYPES)}")
        
        # Validate target_resource_type parameter
        target_resource_type = path_config.get('target_resource_type')
        if not target_resource_type:
            errors.append(f"{path_name}: ManagedIdentityTheft requires 'target_resource_type' parameter")
        elif target_resource_type not in MI_TARGET_RESOURCE_TYPES:
            errors.append(f"{path_name}: Invalid target_resource_type '{target_resource_type}'. Must be one of: {', '.join(MI_TARGET_RESOURCE_TYPES)}")
        
        # Validate credential_type parameter (applies to both key_vault and storage_account targets)
        credential_type = path_config.get('credential_type', 'secret')
        if credential_type not in ['secret', 'certificate']:
            errors.append(f"{path_name}: credential_type must be 'secret' or 'certificate', got '{credential_type}'")
        
        # Validate required entities based on source_type
        if source_type == 'vm':
            if 'virtual_machines' not in entities or not entities['virtual_machines']:
                errors.append(f"{path_name}: source_type 'vm' requires at least one virtual_machine")
        elif source_type == 'logic_app':
            if 'logic_apps' not in entities or not entities['logic_apps']:
                errors.append(f"{path_name}: source_type 'logic_app' requires at least one logic_app")
        elif source_type == 'automation_account':
            if 'automation_accounts' not in entities or not entities['automation_accounts']:
                errors.append(f"{path_name}: source_type 'automation_account' requires at least one automation_account")
        elif source_type == 'function_app':
            if 'function_apps' not in entities or not entities['function_apps']:
                errors.append(f"{path_name}: source_type 'function_app' requires at least one function_app")
        
        # Validate required entities based on target_resource_type
        if target_resource_type == 'key_vault':
            if 'key_vaults' not in entities or not entities['key_vaults']:
                errors.append(f"{path_name}: target_resource_type 'key_vault' requires at least one key_vault")
        elif target_resource_type == 'storage_account':
            if 'storage_accounts' not in entities or not entities['storage_accounts']:
                errors.append(f"{path_name}: target_resource_type 'storage_account' requires at least one storage_account")
        elif target_resource_type == 'cosmos_db':
            if 'cosmos_dbs' not in entities or not entities['cosmos_dbs']:
                errors.append(f"{path_name}: target_resource_type 'cosmos_db' requires at least one cosmos_db")
    
    def validate_random_mode_resources(self, config: Dict) -> Tuple[bool, List[str]]:
        """
        Validate that there are enough resources for random mode attack paths.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Count enabled attack paths
        enabled_paths = [
            (name, path) for name, path in config.get('attack_paths', {}).items()
            if path.get('enabled', False)
        ]
        
        if not enabled_paths:
            return True, []  # No enabled paths, nothing to validate
        
        # Get resource counts
        num_applications = config.get('tenant', {}).get('applications', 0)
        num_users = config.get('tenant', {}).get('users', 0)
        
        # Count attack paths that need applications
        app_paths = sum(
            1 for name, path in enabled_paths
            if path.get('privilege_escalation') in [
                'ServicePrincipalAbuse', 'ApplicationOwnershipAbuse',
                'ApplicationAdministratorAbuse', 'CloudAppAdministratorAbuse',
                'KeyVaultSecretTheft', 'StorageCertificateTheft', 'CosmosDBSecretTheft',
                'ManagedIdentityTheft'
            ]
        )
        
        # Count attack paths that need user roles
        user_role_paths = sum(
            1 for name, path in enabled_paths
            if path.get('privilege_escalation') in ['ApplicationAdministratorAbuse', 'CloudAppAdministratorAbuse'] or
            (path.get('privilege_escalation') in ['ServicePrincipalAbuse', 'ApplicationOwnershipAbuse'] and
             path.get('scenario') == 'helpdesk')
        )
        
        # Validate application count
        if num_applications < app_paths:
            errors.append(
                f"Insufficient applications: {app_paths} attack paths enabled but only "
                f"{num_applications} applications configured. To avoid role assignment conflicts, "
                f"set 'applications' to at least {app_paths}.\n"
                f"Example fix:\n"
                f"  tenant:\n"
                f"    applications: {app_paths}  # Increase from {num_applications}"
            )
        
        # Validate user count
        if user_role_paths > 0 and num_users < user_role_paths:
            errors.append(
                f"Insufficient users: {user_role_paths} attack paths need user roles but only "
                f"{num_users} users configured. To avoid role assignment conflicts, "
                f"set 'users' to at least {user_role_paths}.\n"
                f"Example fix:\n"
                f"  tenant:\n"
                f"    users: {user_role_paths}  # Increase from {num_users}"
            )
        
        return len(errors) == 0, errors
    
    def resolve_tenant_config(self, config: Dict) -> Tuple[str, str, str]:
        """
        Resolve tenant configuration values with environment variable fallback.
        
        Priority order:
        1. Environment variables (BADZURE_TENANT_ID, BADZURE_DOMAIN, BADZURE_SUBSCRIPTION_ID)
        2. YAML configuration values
        
        Args:
            config: Configuration dictionary loaded from YAML
            
        Returns:
            Tuple of (tenant_id, domain, subscription_id)
            
        Raises:
            ValueError: If any required value is missing from both env vars and YAML
        """
        tenant_config = config.get('tenant', {})
        
        # Resolve tenant_id
        tenant_id = os.environ.get(ENV_TENANT_ID) or tenant_config.get('tenant_id')
        if not tenant_id:
            raise ValueError(
                f"tenant_id is required. Set {ENV_TENANT_ID} environment variable "
                "or specify 'tenant_id' in the YAML configuration."
            )
        
        # Resolve domain
        domain = os.environ.get(ENV_DOMAIN) or tenant_config.get('domain')
        if not domain:
            raise ValueError(
                f"domain is required. Set {ENV_DOMAIN} environment variable "
                "or specify 'domain' in the YAML configuration."
            )
        
        # Resolve subscription_id
        subscription_id = os.environ.get(ENV_SUBSCRIPTION_ID) or tenant_config.get('subscription_id')
        if not subscription_id:
            raise ValueError(
                f"subscription_id is required. Set {ENV_SUBSCRIPTION_ID} environment variable "
                "or specify 'subscription_id' in the YAML configuration."
            )
        
        # Log which source was used for each value
        if os.environ.get(ENV_TENANT_ID):
            logging.info(f"Using tenant_id from {ENV_TENANT_ID} environment variable")
        if os.environ.get(ENV_DOMAIN):
            logging.info(f"Using domain from {ENV_DOMAIN} environment variable")
        if os.environ.get(ENV_SUBSCRIPTION_ID):
            logging.info(f"Using subscription_id from {ENV_SUBSCRIPTION_ID} environment variable")
        
        return tenant_id, domain, subscription_id