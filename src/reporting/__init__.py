"""Ontology-driven graph/report foundations for BadZure.

Phase 1 intentionally exposes only the renderer-independent contracts and
validation API.  Later phases add DeploymentModel projectors and HTML output on
top of these types.
"""

from src.reporting.model import GraphEdge, GraphNode, GraphPanel, ReportModel
from src.reporting.environment import (
    EnvironmentProjection,
    build_assignment_panel,
    build_environment_graphs,
    build_identity_panel,
    build_resource_panel,
    build_safe_inventory,
)
from src.reporting.ontology import (
    GraphValidationError,
    Ontology,
    OntologyDefinitionError,
    bundled_ontology_path,
    load_bundled_ontology,
    validate_panel,
)

__all__ = [
    "GraphEdge",
    "GraphNode",
    "GraphPanel",
    "GraphValidationError",
    "EnvironmentProjection",
    "Ontology",
    "OntologyDefinitionError",
    "ReportModel",
    "build_assignment_panel",
    "build_environment_graphs",
    "build_identity_panel",
    "build_resource_panel",
    "build_safe_inventory",
    "bundled_ontology_path",
    "load_bundled_ontology",
    "validate_panel",
]
