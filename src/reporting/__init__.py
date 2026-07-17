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
from src.reporting.posture import (
    POSTURE_FORBIDDEN_VERBS,
    build_posture_panel,
    build_posture_panels,
    select_posture_primitive_keys,
)
from src.reporting.attack import (
    AttackPathNarrative,
    AttackProjection,
    build_attack_panel,
    build_attack_panels,
    build_attack_projections,
    build_path_narrative,
)

__all__ = [
    "GraphEdge",
    "GraphNode",
    "GraphPanel",
    "GraphValidationError",
    "EnvironmentProjection",
    "AttackPathNarrative",
    "AttackProjection",
    "Ontology",
    "OntologyDefinitionError",
    "POSTURE_FORBIDDEN_VERBS",
    "ReportModel",
    "build_assignment_panel",
    "build_attack_panel",
    "build_attack_panels",
    "build_attack_projections",
    "build_environment_graphs",
    "build_identity_panel",
    "build_resource_panel",
    "build_safe_inventory",
    "build_posture_panel",
    "build_posture_panels",
    "build_path_narrative",
    "bundled_ontology_path",
    "load_bundled_ontology",
    "select_posture_primitive_keys",
    "validate_panel",
]
