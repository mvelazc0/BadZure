"""
Configuration management for BadZure.
Handles loading and validation of YAML configuration files.
"""
import yaml
import logging
from typing import Dict, List, Tuple


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
                self._validate_sp_abuse(path_name, entities, errors)
                    
            elif priv_esc == 'KeyVaultAbuse':
                self._validate_kv_abuse(path_name, path_config, entities, errors)
                    
            elif priv_esc == 'StorageAccountAbuse':
                self._validate_storage_abuse(path_name, path_config, entities, errors)
        
        return len(errors) == 0, errors
    
    def _validate_sp_abuse(self, path_name: str, entities: Dict, errors: List[str]) -> None:
        """Validate Service Principal Abuse configuration."""
        if 'users' not in entities or not entities['users']:
            errors.append(f"{path_name}: ServicePrincipalAbuse requires at least one user")
        if 'applications' not in entities or not entities['applications']:
            errors.append(f"{path_name}: ServicePrincipalAbuse requires at least one application")
    
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