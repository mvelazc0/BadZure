"""
Configuration management for BadZure.
Handles loading and validation of YAML configuration files.
"""
import yaml
import logging
from typing import Dict, List, Tuple
from src.constants import (
    API_REGISTRY,
    ALL_API_PERMISSIONS,
    ENTRA_ROLES,
    HIGH_PRIVILEGED_ENTRA_ROLES
)


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
            
            if priv_esc == 'ServicePrincipalAbuse':
                self._validate_sp_abuse(path_name, path_config, entities, errors)
                    
            elif priv_esc == 'KeyVaultAbuse':
                self._validate_kv_abuse(path_name, path_config, entities, errors)
                    
            elif priv_esc == 'StorageAccountAbuse':
                self._validate_storage_abuse(path_name, path_config, entities, errors)
        
        return len(errors) == 0, errors
    
    def _validate_sp_abuse(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Service Principal Abuse configuration."""
        if 'users' not in entities or not entities['users']:
            errors.append(f"{path_name}: ServicePrincipalAbuse requires at least one user")
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: ServicePrincipalAbuse requires at least one application")
        
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
    
    def _validate_kv_abuse(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Key Vault Abuse configuration."""
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: KeyVaultAbuse requires at least one application")
        if 'key_vaults' not in entities or not entities['key_vaults']:
            errors.append(f"{path_name}: KeyVaultAbuse requires at least one key_vault")
        if 'resource_groups' not in entities or not entities['resource_groups']:
            errors.append(f"{path_name}: KeyVaultAbuse requires at least one resource_group")
        
        # Validate principal_type requirements
        principal_type = path_config.get('principal_type', 'user')
        if principal_type == 'user' and ('users' not in entities or not entities['users']):
            errors.append(f"{path_name}: principal_type 'user' requires at least one user")
        elif principal_type == 'managed_identity':
            if 'virtual_machines' not in entities or not entities['virtual_machines']:
                errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one virtual_machine")
            if 'users' not in entities or not entities['users']:
                errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one user for VM Contributor access")
    
    def _validate_storage_abuse(self, path_name: str, path_config: Dict, entities: Dict, errors: List[str]) -> None:
        """Validate Storage Account Abuse configuration."""
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: StorageAccountAbuse requires at least one application")
        if 'storage_accounts' not in entities or not entities['storage_accounts']:
            errors.append(f"{path_name}: StorageAccountAbuse requires at least one storage_account")
        if 'resource_groups' not in entities or not entities['resource_groups']:
            errors.append(f"{path_name}: StorageAccountAbuse requires at least one resource_group")
            
        # Validate principal_type requirements
        principal_type = path_config.get('principal_type', 'user')
        if principal_type == 'user' and ('users' not in entities or not entities['users']):
            errors.append(f"{path_name}: principal_type 'user' requires at least one user")
        elif principal_type == 'managed_identity':
            if 'virtual_machines' not in entities or not entities['virtual_machines']:
                errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one virtual_machine")
            if 'users' not in entities or not entities['users']:
                errors.append(f"{path_name}: principal_type 'managed_identity' requires at least one user for VM Contributor access")