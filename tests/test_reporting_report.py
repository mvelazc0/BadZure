"""Phase 5 tests for assembling and rendering the interactive HTML report."""

import pytest

from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.reporting.attack import build_attack_projections
from src.reporting.environment import build_environment_graphs
from src.reporting.model import GraphNode, GraphPanel, ReportModel
from src.reporting.posture import build_posture_panels
from src.reporting.report import (
    ReportRenderError,
    assemble_report_model,
    render_report,
)
from src.scenario_loader import ScenarioLoader


def _scenario(fixture="chained_fullstack.yml"):
    config = ConfigManager().load_config(f"examples/chained/{fixture}")
    return ScenarioLoader(EntityGenerator(data_dir="entity_data")).load(
        config, domain="example.com", enforce_reachability=False,
    )


def _report(fixture="chained_fullstack.yml"):
    scenario = _scenario(fixture)
    environment = build_environment_graphs(scenario.model)
    posture = build_posture_panels(scenario.model, scenario.attack_paths)
    attack = build_attack_projections(scenario.model, scenario.attack_paths)
    return assemble_report_model(
        title="BadZure lab report",
        source_config=f"examples/chained/{fixture}",
        environment=environment,
        posture_panels=posture,
        attack_projections=attack,
        lab_description="A deliberately vulnerable Azure lab.",
        organization_description="A fictional organization used for training.",
    )


def test_assembly_orders_environment_then_paired_path_panels():
    report = _report()

    assert [panel.key for panel in report.panels[:3]] == [
        "identity", "resources", "assignments",
    ]
    assert len(report.panels) == 3 + (2 * len(report.paths))
    for index, path in enumerate(report.paths):
        offset = 3 + (index * 2)
        assert report.panels[offset].key == path["posture_panel_key"]
        assert report.panels[offset + 1].key == path["attack_panel_key"]
    assert report.overview["Attack paths"] == len(report.paths)
    assert report.overview["Regions"] >= 1
    assert not ({"Reached", "Blocked", "Invalid", "Unverified"} & report.overview.keys())
    assert report.assignments


def test_report_is_one_self_contained_interactive_document():
    report = _report("chained_kv_theft.yml")
    html = render_report(report)

    assert html.startswith("<!DOCTYPE html>")
    assert "cytoscape" in html
    assert '<script src=' not in html
    assert '<link rel="stylesheet"' not in html
    assert "https://cdn" not in html
    assert "layout: { name: \"preset\"" in html
    assert 'cy.on("tap", "node, edge"' in html
    assert 'cy.on("mouseover", "node, edge"' in html
    assert 'data-action="fit"' in html
    assert 'data-action="reset"' in html
    assert 'data-action="family-overview"' in html
    assert "showAssignmentOverview" in html
    assert "expandAssignmentFamily" in html
    assert 'get("embed")' in html
    assert "activateTab(requestedEmbeddedPanel)" in html
    assert "html.embed-mode .report-header" in html
    assert "A deliberately vulnerable Azure lab." in html
    assert "Identity Plane" in html
    assert "Cloud Plane" in html
    identity_section = html.index("Identity Plane")
    cloud_section = html.index("Cloud Plane")
    assert identity_section < html.index("Service principals", identity_section) < cloud_section
    assert cloud_section < html.index("Azure resources", cloud_section)
    assert "Safe inventory details" not in html
    assert "Assignmen" in html
    identity_at = html.index("Identity Plane")
    cloud_at = html.index("Cloud Plane")
    assignments_at = html.index("Assignments(", identity_at)
    paths_at = html.index('id="paths-heading"')
    assert identity_at < assignments_at < cloud_at < paths_at
    assert identity_at < html.index("Users (", identity_at) < cloud_at
    assert cloud_at < html.index("Resource Groups (", cloud_at) < paths_at
    assert "--primary: #1565c0" in html
    assert "--accent: #ff6d00" in html
    assert "--panel: #212738" in html
    for panel in report.panels:
        assert f'data-page="{panel.key}"' in html


def test_render_is_deterministic_and_marks_graph_semantics():
    report = _report("chained_kv_theft.yml")

    first = render_report(report)
    assert first == render_report(report)
    assert '"emphasis":"spine"' in first
    assert '"type":"Objective"' in first
    assert 'selector: "node[aggregate = true]"' in first
    assert "selector: \"node[type = 'Objective']\"" in first
    assert '"shape": "ellipse"' in first
    assert '"shape": "round-rectangle"' not in first
    assert '"shape": "diamond"' not in first


def test_inline_json_and_template_values_cannot_break_out_of_markup():
    payload = '</script><img src=x onerror="alert(1)">'
    panel = GraphPanel(
        key="identity", title=payload, ontology="identity",
        nodes=[GraphNode(
            id="Organization:lab", type="Organization", label=payload,
            properties={"users": payload}, position=(0, 0),
        )],
    )
    report = ReportModel(
        title=payload, source_config=payload, lab_description=payload,
        panels=[panel],
    )
    html = render_report(report)

    assert payload not in html
    assert "&lt;/script&gt;&lt;img" in html
    assert "\\u003c/script\\u003e\\u003cimg" in html


def test_dom_ids_remain_unique_when_sanitized_panel_keys_collide():
    panels = [
        GraphPanel(key="a b", title="One", ontology="identity"),
        GraphPanel(key="a-b", title="Two", ontology="identity"),
    ]
    html = render_report(ReportModel(title="Report", source_config="lab.yml", panels=panels))

    assert 'id="graph-panel-a-b"' in html
    assert 'id="graph-panel-a-b-2"' in html


def test_duplicate_panel_keys_are_rejected():
    panel = GraphPanel(key="identity", title="Identity", ontology="identity")
    report = ReportModel(title="Report", source_config="lab.yml", panels=[panel, panel])

    with pytest.raises(ReportRenderError, match="duplicate keys"):
        render_report(report)


def test_nodes_without_preset_positions_are_rejected():
    panel = GraphPanel(
        key="identity", title="Identity", ontology="identity",
        nodes=[GraphNode(id="Organization:lab", type="Organization", label="Lab")],
    )

    with pytest.raises(ReportRenderError, match="without preset positions"):
        render_report(ReportModel(title="Report", source_config="lab.yml", panels=[panel]))


def test_missing_posture_pair_is_rejected():
    scenario = _scenario("chained_kv_theft.yml")
    environment = build_environment_graphs(scenario.model)
    attacks = build_attack_projections(scenario.model, scenario.attack_paths)

    with pytest.raises(ReportRenderError, match="no matching posture panel"):
        assemble_report_model("Report", "lab.yml", environment, [], attacks)


def test_baseline_only_lab_renders_without_attack_path_tabs():
    scenario = _scenario("chained_org_baseline.yml")
    environment = build_environment_graphs(scenario.model)
    report = assemble_report_model("Baseline", "lab.yml", environment, [], [])
    html = render_report(report)

    assert report.paths == []
    assert [panel.key for panel in report.panels] == [
        "identity", "resources", "assignments",
    ]
    assert "No enabled attack paths are defined" in html
    assert 'data-page="posture-' not in html
    assert 'data-page="attack-' not in html


def test_safe_projected_report_does_not_leak_operator_credentials():
    report = _report("chained_apex.yml")
    html = render_report(report)

    # "password" can legitimately describe a credential's non-secret material
    # type. Secret-bearing field names and values must still stay out.
    assert "admin_password" not in html.lower()
    assert "literal_value" not in html.lower()
    assert "client_secret" not in html.lower()
    assert "pfx_password" not in html.lower()
