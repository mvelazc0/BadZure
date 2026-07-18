"""Compose and render a self-contained interactive BadZure HTML report."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from src.reporting.attack import AttackProjection
from src.reporting.environment import EnvironmentProjection
from src.reporting.model import GraphPanel, ReportModel
from src.reporting.ontology import load_bundled_ontology, validate_panel
from src.reporting.safety import dom_id
from src.reporting.style import (
    BACKGROUND_COLOR,
    DEFAULT_NODE_COLOR,
    EDGE_STYLES,
    SENSITIVE_BORDER_COLOR,
    color_for,
)


_REPORTING_DIR = Path(__file__).resolve().parent
_TEMPLATE_DIR = _REPORTING_DIR / "templates"
_ASSET_DIR = _REPORTING_DIR / "assets"

_IDENTITY_OVERVIEW_KEYS = {
    "Users", "Groups", "Service principals", "Administrative units", "Assignments",
}
_IDENTITY_INVENTORY_KEYS = (
    "users", "groups", "applications", "administrative_units",
)
_RESOURCE_INVENTORY_KEYS = (
    "key_vaults", "storage_accounts", "virtual_machines", "logic_apps",
    "automation_accounts", "function_apps", "app_services", "cosmos_dbs",
)


class ReportRenderError(ValueError):
    """Report composition or rendering failed before an artifact was written."""


def assemble_report_model(
    title: str,
    source_config: str,
    environment: EnvironmentProjection,
    posture_panels: Sequence[GraphPanel],
    attack_projections: Sequence[AttackProjection],
    lab_description: str = "",
    organization_description: str = "",
) -> ReportModel:
    """Combine independently projected data into the final ordered report model."""

    posture_by_key = {panel.key: panel for panel in posture_panels}
    if len(posture_by_key) != len(posture_panels):
        raise ReportRenderError("Posture panels contain duplicate keys")

    panels = list(environment.panels)
    paths = []
    for projection in attack_projections:
        narrative = projection.narrative
        posture = posture_by_key.get(narrative.posture_panel_key)
        if posture is None:
            raise ReportRenderError(
                f"Attack path '{narrative.name}' has no matching posture panel "
                f"'{narrative.posture_panel_key}'"
            )
        panels.extend((posture, projection.panel))
        path = asdict(narrative)
        paths.append(path)

    inventory = environment.inventory
    regions = {
        row.get("location")
        for key in ("resource_groups", *_RESOURCE_INVENTORY_KEYS)
        for row in inventory.get(key, [])
        if row.get("location")
    }
    overview = {
        "Users": len(inventory.get("users", [])),
        "Groups": len(inventory.get("groups", [])),
        "Service principals": len(inventory.get("applications", [])),
        "Administrative units": len(inventory.get("administrative_units", [])),
        "Resource groups": len(inventory.get("resource_groups", [])),
        "Azure resources": sum(len(inventory.get(key, [])) for key in _RESOURCE_INVENTORY_KEYS),
        "Regions": len(regions),
        "Assignments": len(environment.assignment_details),
        "Attack paths": len(paths),
    }
    return ReportModel(
        title=title,
        source_config=source_config,
        lab_description=lab_description,
        organization_description=organization_description,
        overview=overview,
        inventory=inventory,
        assignments=environment.assignment_details,
        paths=paths,
        panels=panels,
    )


def render_report(report: ReportModel) -> str:
    """Return one complete offline HTML document for ``report``."""

    panel_views = _panel_views(report.panels)
    overview_sections = _overview_sections(report.overview, report.inventory)
    panels_json = _safe_json({view["key"]: view["payload"] for view in panel_views})
    cytoscape_js = _read_required_asset("cytoscape.min.js")

    environment = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(enabled_extensions=("html",), default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["display_value"] = _display_value
    try:
        template = environment.get_template("report.html.j2")
        return template.render(
            report=report,
            overview_sections=overview_sections,
            panel_views=panel_views,
            panels_json=panels_json,
            cytoscape_js=cytoscape_js,
            background_color=BACKGROUND_COLOR,
            default_node_color=DEFAULT_NODE_COLOR,
            sensitive_border_color=SENSITIVE_BORDER_COLOR,
        )
    except ReportRenderError:
        raise
    except Exception as exc:
        raise ReportRenderError(f"Could not render report: {exc}") from exc


def _overview_sections(
    overview: Dict[str, Any], inventory: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Pair each control plane's overview tiles with its safe inventory details."""

    identity = []
    cloud = []
    for label, value in overview.items():
        target = identity if label in _IDENTITY_OVERVIEW_KEYS else cloud
        target.append((label, value))
    identity_keys = set(_IDENTITY_INVENTORY_KEYS)
    return [
        {
            "title": "Identity Plane",
            "metrics": identity,
            "categories": [
                (key, inventory.get(key, [])) for key in _IDENTITY_INVENTORY_KEYS
            ],
        },
        {
            "title": "Cloud Plane",
            "metrics": cloud,
            "categories": [
                (key, rows) for key, rows in inventory.items() if key not in identity_keys
            ],
        },
    ]


def _panel_views(panels: Sequence[GraphPanel]) -> List[Dict[str, Any]]:
    keys = [panel.key for panel in panels]
    duplicate_keys = sorted({key for key in keys if keys.count(key) > 1})
    if duplicate_keys:
        raise ReportRenderError(
            "Report panels contain duplicate keys: " + ", ".join(duplicate_keys)
        )

    used_dom_ids = set()
    views = []
    for panel in panels:
        validate_panel(panel, load_bundled_ontology(panel.ontology))
        missing_positions = [node.id for node in panel.nodes if node.position is None]
        if missing_positions:
            raise ReportRenderError(
                f"Panel '{panel.key}' has node(s) without preset positions: "
                + ", ".join(missing_positions)
            )
        base_dom_id = dom_id(panel.key, prefix="panel")
        dom_key = base_dom_id
        suffix = 2
        while dom_key in used_dom_ids:
            dom_key = f"{base_dom_id}-{suffix}"
            suffix += 1
        used_dom_ids.add(dom_key)

        payload = _panel_payload(panel, dom_key)
        node_types = sorted({node.type for node in panel.nodes})
        edge_types = sorted({edge.type for edge in panel.edges})
        views.append({
            "key": panel.key,
            "dom_key": dom_key,
            "title": panel.title,
            "caption": panel.caption,
            "ontology": panel.ontology,
            "node_legend": [
                {"type": node_type, "color": color_for(node_type)}
                for node_type in node_types
            ],
            "edge_legend": edge_types,
            "payload": payload,
        })
    return views


def _panel_payload(panel: GraphPanel, dom_key: str) -> Dict[str, Any]:
    elements = []
    for node in panel.nodes:
        elements.append({
            "group": "nodes",
            "data": {
                "id": node.id,
                "label": node.label,
                "type": node.type,
                "properties": node.properties,
                "node_color": color_for(node.type),
                "border_color": SENSITIVE_BORDER_COLOR if node.sensitive else BACKGROUND_COLOR,
                "border_width": 5 if node.sensitive else 2,
                "aggregate": node.aggregate,
                "sensitive": node.sensitive,
            },
            "position": {"x": node.position[0], "y": node.position[1]},
        })
    for edge in panel.edges:
        style = EDGE_STYLES[edge.emphasis]
        elements.append({
            "group": "edges",
            "data": {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "label": edge.type.replace("_", " "),
                "type": edge.type,
                "properties": edge.properties,
                "emphasis": edge.emphasis,
                "edge_color": style["color"],
                "edge_width": style["width"],
                "line_style": style["line_style"],
            },
        })
    return {
        "key": panel.key,
        "dom_key": dom_key,
        "title": panel.title,
        "ontology": panel.ontology,
        "elements": elements,
    }


def _safe_json(value: Any) -> str:
    """Serialize JSON for an inline script without permitting tag breakout."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) \
        .replace("&", "\\u0026") \
        .replace("<", "\\u003c") \
        .replace(">", "\\u003e") \
        .replace("\u2028", "\\u2028") \
        .replace("\u2029", "\\u2029")


def _read_required_asset(filename: str) -> str:
    path = _ASSET_DIR / filename
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportRenderError(f"Required report asset is missing: {path}") from exc


def _display_value(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return ", ".join(f"{key}: {item}" for key, item in value.items())
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)
