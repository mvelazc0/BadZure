"""Merges selected scenarios into a BadZure YAML config file."""
import tempfile
from pathlib import Path
from typing import Optional
import yaml
from ..models.common import TenantConfig
from ..models.scenarios import ScenarioDetail


# Minimum resource counts needed per technique
RESOURCE_REQUIREMENTS: dict[str, dict[str, int]] = {
    "KeyVaultSecretTheft": {"key_vaults": 1, "resource_groups": 1},
    "StorageCertificateTheft": {"storage_accounts": 1, "resource_groups": 1},
    "ManagedIdentityTheft": {"resource_groups": 1},
}

# Source type to resource count key mapping for ManagedIdentityTheft
MI_SOURCE_RESOURCE_MAP: dict[str, str] = {
    "vm": "virtual_machines",
    "logic_app": "logic_apps",
    "automation_account": "automation_accounts",
    "function_app": "function_apps",
}

MI_TARGET_RESOURCE_MAP: dict[str, str] = {
    "key_vault": "key_vaults",
    "storage_account": "storage_accounts",
}


def generate_config(
    scenarios: list[ScenarioDetail],
    tenant_config: Optional[TenantConfig] = None,
) -> Path:
    """Generate a BadZure YAML config from selected scenarios.

    Returns the path to a temporary YAML file.
    """
    # Calculate minimum resource counts
    resource_counts: dict[str, int] = {
        "users": 5,
        "applications": 5,
        "groups": 3,
        "administrative_units": 2,
        "resource_groups": 0,
        "key_vaults": 0,
        "storage_accounts": 0,
        "virtual_machines": 0,
        "logic_apps": 0,
        "automation_accounts": 0,
        "function_apps": 0,
        "cosmos_dbs": 0,
    }

    # Ensure enough identities for attack paths
    resource_counts["users"] = max(resource_counts["users"], len(scenarios) + 2)
    resource_counts["applications"] = max(resource_counts["applications"], len(scenarios) + 2)

    for scenario in scenarios:
        technique = scenario.technique
        reqs = RESOURCE_REQUIREMENTS.get(technique, {})
        for key, min_count in reqs.items():
            resource_counts[key] = max(resource_counts[key], min_count)

        # Parse yaml_content to check for MI source/target types
        if technique == "ManagedIdentityTheft":
            parsed = yaml.safe_load(scenario.yaml_content)
            ap = list(parsed.get("attack_paths", {}).values())[0]
            source_type = ap.get("source_type", "vm")
            target_type = ap.get("target_resource_type", "key_vault")
            src_key = MI_SOURCE_RESOURCE_MAP.get(source_type)
            tgt_key = MI_TARGET_RESOURCE_MAP.get(target_type)
            if src_key:
                resource_counts[src_key] = max(resource_counts[src_key], 1)
            if tgt_key:
                resource_counts[tgt_key] = max(resource_counts[tgt_key], 1)

    # Need at least 1 resource group if any Azure resources
    azure_resource_sum = sum(
        resource_counts[k]
        for k in [
            "key_vaults", "storage_accounts", "virtual_machines",
            "logic_apps", "automation_accounts", "function_apps", "cosmos_dbs",
        ]
    )
    if azure_resource_sum > 0:
        resource_counts["resource_groups"] = max(resource_counts["resource_groups"], 1)

    # Build tenant section
    tenant = {
        "tenant_id": tenant_config.tenant_id if tenant_config else "YOUR-TENANT-GUID-HERE",
        "domain": tenant_config.domain if tenant_config else "yourdomain.onmicrosoft.com",
        "subscription_id": tenant_config.subscription_id if tenant_config else "YOUR-SUBSCRIPTION-GUID-HERE",
        **resource_counts,
    }

    # Build attack_paths section by merging all scenario YAML contents
    attack_paths: dict = {}
    for scenario in scenarios:
        parsed = yaml.safe_load(scenario.yaml_content)
        paths = parsed.get("attack_paths", {})
        for key, value in paths.items():
            value["enabled"] = True
            attack_paths[key] = value

    config = {
        "tenant": tenant,
        "attack_paths": attack_paths,
    }

    # Write to temp file
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", prefix="badzure_web_", delete=False
    )
    yaml.dump(config, tmp, default_flow_style=False, sort_keys=False)
    tmp.close()
    return Path(tmp.name)
