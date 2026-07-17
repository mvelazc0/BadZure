"""Phase 1 tests for report graph contracts, safety, and ontology validation."""

from pathlib import Path

import pytest

from src.reporting import (
    GraphEdge,
    GraphNode,
    GraphPanel,
    GraphValidationError,
    Ontology,
    OntologyDefinitionError,
    load_bundled_ontology,
    validate_panel,
)
from src.reporting.ontology import BUNDLED_ONTOLOGIES
from src.reporting.safety import (
    UnsafeReportPropertyError,
    dom_id,
    edge_id,
    safe_properties,
    typed_id,
)
from src.reporting.style import EDGE_STYLES, color_for


def _identity_panel():
    organization = GraphNode(
        id=typed_id("Organization", "lab"),
        type="Organization",
        label="Organization",
        properties={"users": 10, "groups": 2},
    )
    group = GraphNode(
        id=typed_id("Group", "engineering"),
        type="Group",
        label="Engineering",
        properties={"member_count": 7, "origin": "random"},
    )
    return GraphPanel(
        key="identity",
        title="Identity",
        ontology="identity",
        nodes=[organization, group],
        edges=[GraphEdge(
            id=edge_id("identity", "CONTAINS", "engineering"),
            type="CONTAINS",
            source=organization.id,
            target=group.id,
        )],
    )


def test_all_bundled_ontologies_load():
    for name in BUNDLED_ONTOLOGIES:
        ontology = load_bundled_ontology(name)
        assert ontology.name == name
        assert ontology.node_types
        assert isinstance(ontology.edge_types, dict)


def test_valid_panel_passes():
    validate_panel(_identity_panel(), load_bundled_ontology("identity"))


def test_validation_aggregates_duplicate_dangling_and_bad_properties():
    panel = _identity_panel()
    panel.nodes.append(GraphNode(
        id=panel.nodes[0].id,
        type="Mystery",
        label="Duplicate",
        properties={"password": "must-not-pass"},
    ))
    panel.edges.append(GraphEdge(
        id="bad-edge",
        type="CONTAINS",
        source="Organization:missing",
        target=panel.nodes[1].id,
        properties={"not_declared": True},
        emphasis="loud",
    ))

    with pytest.raises(GraphValidationError) as caught:
        validate_panel(panel, load_bundled_ontology("identity"))

    message = str(caught.value)
    assert "duplicate node id" in message
    assert "unknown type 'Mystery'" in message
    assert "dangling source" in message
    assert "undeclared properties" in message
    assert "invalid emphasis" in message
    assert len(caught.value.errors) >= 5


def test_validation_rejects_illegal_endpoint_types():
    panel = _identity_panel()
    panel.edges[0].source = panel.nodes[1].id  # Group cannot CONTAIN in identity ontology.

    with pytest.raises(GraphValidationError, match="cannot start at 'Group'"):
        validate_panel(panel, load_bundled_ontology("identity"))


def test_validation_rejects_missing_required_property():
    panel = GraphPanel(
        key="resources",
        title="Resources",
        ontology="resources",
        nodes=[GraphNode(
            id=typed_id("KeyVaultSummary", "rg-data"),
            type="KeyVaultSummary",
            label="Key Vaults",
        )],
    )
    with pytest.raises(GraphValidationError, match="missing required properties: count"):
        validate_panel(panel, load_bundled_ontology("resources"))


def test_panel_must_select_the_validated_ontology():
    panel = _identity_panel()
    panel.ontology = "resources"
    with pytest.raises(GraphValidationError, match="panel selects ontology 'resources'"):
        validate_panel(panel, load_bundled_ontology("identity"))


def test_ontology_definition_rejects_unknown_endpoint_type(tmp_path):
    ontology_file = tmp_path / "broken.yml"
    ontology_file.write_text(
        """name: broken
node_types:
  Known: {}
edge_types:
  BAD:
    from: [Known]
    to: [Missing]
""",
        encoding="utf-8",
    )
    with pytest.raises(OntologyDefinitionError, match="unknown node type.*Missing"):
        Ontology.from_yaml(ontology_file)


def test_ontology_definition_rejects_required_property_not_declared(tmp_path):
    ontology_file = tmp_path / "broken.yml"
    ontology_file.write_text(
        """name: broken
node_types:
  Known:
    properties: []
    required_properties: [count]
edge_types: {}
""",
        encoding="utf-8",
    )
    with pytest.raises(OntologyDefinitionError, match="requires undeclared property.*count"):
        Ontology.from_yaml(ontology_file)


def test_unknown_bundled_ontology_is_clear():
    with pytest.raises(OntologyDefinitionError, match="Unknown bundled ontology 'other'"):
        load_bundled_ontology("other")


def test_typed_ids_do_not_collide_across_types():
    assert typed_id("Group", "shared") != typed_id("ServicePrincipal", "shared")
    assert typed_id("Group", "shared") == "Group:shared"
    assert edge_id("posture-path", "OWNS", "a1") == "posture-path:OWNS:a1"


def test_dom_id_is_deterministic_and_safe():
    assert dom_id("Path: Finance / GA") == "panel-path-finance-ga"
    assert dom_id("***", prefix="tab") == "tab-item"


def test_safe_properties_uses_allowlist_and_json_safe_values():
    source = {
        "name": "alice",
        "tags": ["identity", "entry"],
        "details": {"active": True},
        "password": "do-not-copy",
    }
    assert safe_properties(source, {"name", "tags", "details"}) == {
        "name": "alice",
        "tags": ["identity", "entry"],
        "details": {"active": True},
    }


def test_safe_properties_rejects_forbidden_allowlist_fields():
    with pytest.raises(UnsafeReportPropertyError, match="forbidden field.*password"):
        safe_properties({"password": "secret"}, {"password"})


def test_safe_properties_rejects_non_json_values():
    with pytest.raises(UnsafeReportPropertyError, match="unsupported value type set"):
        safe_properties({"tags": {"one", "two"}}, {"tags"})


def test_shared_style_has_all_edge_states_and_fallback_color():
    assert set(EDGE_STYLES) == {"normal", "spine", "offspine"}
    assert color_for("User") != color_for("UnknownFutureType")


def test_cytoscape_asset_and_license_are_vendored():
    assets = Path(__file__).resolve().parents[1] / "src" / "reporting" / "assets"
    script = assets / "cytoscape.min.js"
    license_file = assets / "CYTOSCAPE_LICENSE.txt"
    assert script.stat().st_size > 300_000
    assert "Cytoscape Consortium" in script.read_text(encoding="utf-8")[:500]
    assert "MIT License" in license_file.read_text(encoding="utf-8")
