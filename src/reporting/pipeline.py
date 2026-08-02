"""Config -> interactive HTML report, as one reusable function.

Both the `report` CLI command and the docs build hook render reports; keeping the
config -> scenario -> projections -> model -> HTML pipeline here means they share a
single code path and can never drift. The CLI owns file IO, browser launch, and exit
codes; this module owns the transform.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.scenario_loader import ScenarioLoader
from src.reporting import (
    assemble_report_model,
    build_attack_projections,
    build_environment_graphs,
    build_posture_panels,
    render_report,
)

# Counts under `tenant:` mark a retired legacy `mode:` config; the declarative shape
# keeps counts under `baseline:`. Mirrors BuildCommand._LEGACY_TENANT_COUNT_KEYS.
_LEGACY_TENANT_COUNT_KEYS = (
    'users', 'applications', 'groups', 'administrative_units', 'resource_groups',
    'key_vaults', 'storage_accounts', 'virtual_machines', 'logic_apps',
    'automation_accounts', 'function_apps', 'app_services', 'cosmos_dbs',
)


def is_legacy_config(config: Dict) -> bool:
    """True for a retired legacy `mode:` config (rejected by the report path)."""
    if not isinstance(config, dict):
        return False
    if config.get('mode') in ('random', 'targeted'):
        return True
    tenant = config.get('tenant')
    if isinstance(tenant, dict) and any(k in tenant for k in _LEGACY_TENANT_COUNT_KEYS):
        return True
    return False


def build_report_html(
    config: Dict,
    source_config: str,
    *,
    generator: Optional[EntityGenerator] = None,
    config_mgr: Optional[ConfigManager] = None,
    domain: str = "example.com",
) -> str:
    """Render a loaded declarative ``config`` into one self-contained HTML report.

    Raises ``ValueError`` for a non-declarative/legacy config (the CLI maps this to
    its config-error exit code) and ``ReportRenderError`` for projection/render
    failures.
    """
    if not isinstance(config, dict) or is_legacy_config(config):
        raise ValueError("Not a declarative config (legacy 'mode:' shape or invalid).")

    config_mgr = config_mgr or ConfigManager()
    generator = generator or EntityGenerator()

    metadata = config_mgr.validate_report_config(config)
    scenario = ScenarioLoader(generator).load(
        config, domain=domain, enforce_reachability=False,
    )

    environment = build_environment_graphs(scenario.model)
    posture_panels = build_posture_panels(scenario.model, scenario.attack_paths or [])
    attack_projections = build_attack_projections(
        scenario.model, scenario.attack_paths or [],
    )

    path_count = len(scenario.attack_paths or [])
    title = metadata.get('title', f"BadZure lab: {os.path.basename(source_config)}")
    lab_description = metadata.get(
        'lab_description', _lab_description(environment, path_count),
    )
    organization_description = metadata.get(
        'organization_description', _organization_description(environment),
    )

    report = assemble_report_model(
        title=title,
        source_config=source_config,
        environment=environment,
        posture_panels=posture_panels,
        attack_projections=attack_projections,
        lab_description=lab_description,
        organization_description=organization_description,
    )
    return render_report(report)


def build_report_html_from_file(
    config_file: str, *, generator: Optional[EntityGenerator] = None,
) -> str:
    """Load ``config_file`` and render its report. Convenience for callers (the docs
    hook) that start from a path rather than an in-memory config."""
    config_mgr = ConfigManager()
    config = config_mgr.load_config(config_file)
    return build_report_html(
        config, source_config=config_file, generator=generator, config_mgr=config_mgr,
    )


def _lab_description(environment, path_count: int) -> str:
    inventory = environment.inventory
    resources = sum(
        len(rows) for key, rows in inventory.items()
        if key not in {'users', 'groups', 'applications', 'administrative_units'}
    )
    return (
        f"This lab contains {resources} Azure resource(s), "
        f"{len(environment.assignment_details)} assignment(s), and "
        f"{path_count} enabled attack path(s)."
    )


def _organization_description(environment) -> str:
    inventory = environment.inventory
    return (
        f"The organization contains {len(inventory.get('users', []))} user(s), "
        f"{len(inventory.get('groups', []))} group(s), "
        f"{len(inventory.get('applications', []))} service principal(s), and "
        f"{len(inventory.get('administrative_units', []))} administrative unit(s)."
    )
