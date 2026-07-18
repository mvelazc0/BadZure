"""
Configuration management for BadZure.
Handles loading and validation of YAML configuration files.
"""
import os
import yaml
import logging
from typing import Dict, Tuple, Optional

# Environment variable names for tenant configuration
ENV_TENANT_ID = 'BADZURE_TENANT_ID'
ENV_DOMAIN = 'BADZURE_DOMAIN'
ENV_SUBSCRIPTION_ID = 'BADZURE_SUBSCRIPTION_ID'

# Environment variable names for LLM configuration (`badzure generate`)
ENV_LLM_MODEL = 'BADZURE_LLM_MODEL'
ENV_LLM_API_KEY = 'BADZURE_LLM_API_KEY'
ENV_LLM_BASE_URL = 'BADZURE_LLM_BASE_URL'

REPORT_METADATA_KEYS = frozenset({
    'title', 'lab_description', 'organization_description',
})


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

    def validate_report_config(self, config: Dict) -> Dict[str, str]:
        """Return validated optional report presentation metadata.

        Report metadata never affects compilation or deployment. Keeping its
        validation here gives every reporting entry point the same small schema.
        """
        metadata = config.get('report')
        if metadata is None:
            return {}
        if not isinstance(metadata, dict):
            raise ValueError("`report` must be a mapping.")

        unknown = sorted(set(metadata) - REPORT_METADATA_KEYS)
        if unknown:
            raise ValueError(
                "`report` has unknown field(s): " + ", ".join(unknown)
                + ". Supported fields: " + ", ".join(sorted(REPORT_METADATA_KEYS)) + "."
            )
        invalid = sorted(key for key, value in metadata.items()
                         if not isinstance(value, str))
        if invalid:
            raise ValueError(
                "`report` field(s) must be strings: " + ", ".join(invalid) + "."
            )
        return dict(metadata)

    def resolve_llm_config(self, config: Optional[Dict] = None,
                           model_override: Optional[str] = None) -> Dict:
        """Resolve LLM settings for `badzure generate`, mirroring the tenant
        resolution precedence: CLI override > env var > YAML `llm:` block.

        Returns {model, api_key, base_url}. `model` is required (raises if absent);
        `api_key`/`base_url` may be None — LiteLLM falls back to native provider
        env vars (ANTHROPIC_API_KEY, ...) when no explicit key is given.
        """
        llm_config = (config or {}).get('llm', {}) or {}

        model = (model_override or os.environ.get(ENV_LLM_MODEL)
                 or llm_config.get('model'))
        if not model:
            raise ValueError(
                f"No LLM model configured. Pass --model, set {ENV_LLM_MODEL}, or add "
                f"`llm.model` to the config (e.g. anthropic/claude-opus-4-1, "
                f"openai/gpt-4o, ollama/llama3)."
            )

        api_key = os.environ.get(ENV_LLM_API_KEY) or llm_config.get('api_key')
        base_url = os.environ.get(ENV_LLM_BASE_URL) or llm_config.get('base_url')
        return {"model": model, "api_key": api_key, "base_url": base_url}
