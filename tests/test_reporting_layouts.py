"""Focused tests for deterministic report graph layouts."""

from src.reporting.layouts import apply_spine_layout
from src.reporting.model import GraphEdge, GraphNode, GraphPanel


def test_spine_layout_promotes_minimal_connector_between_path_components():
    nodes = [GraphNode(id=key, type="Test", label=key) for key in "ABCDE"]
    edges = [
        GraphEdge(id="ab", type="PATH", source="A", target="B", emphasis="spine"),
        GraphEdge(id="bc", type="PATH", source="B", target="C", emphasis="offspine"),
        GraphEdge(id="cd", type="PATH", source="C", target="D", emphasis="offspine"),
        GraphEdge(id="de", type="PATH", source="D", target="E", emphasis="spine"),
    ]
    panel = GraphPanel(key="path", title="Path", ontology="test", nodes=nodes, edges=edges)

    apply_spine_layout(panel)

    assert [edge.emphasis for edge in edges] == ["spine"] * 4
    ordered = sorted(nodes, key=lambda node: node.position[0])
    assert [node.position[1] for node in ordered] == [-90.0, 90.0, -90.0, 90.0, -90.0]
