"""Phase 4 tests for attacker-action graphs and path narratives."""

from pathlib import Path
from types import SimpleNamespace

from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.primitives import DeploymentModel
from src.reporting.attack import (
    build_attack_panel,
    build_attack_projections,
    build_path_narrative,
)
from src.scenario_loader import ScenarioLoader


def _scenario(path):
    config = ConfigManager().load_config(path)
    return ScenarioLoader(EntityGenerator(data_dir="entity_data")).load(
        config, domain="example.com", enforce_reachability=False,
    )


def _chained(fixture):
    return _scenario(f"examples/chained/{fixture}")


def _edge_types(panel):
    return [edge.type for edge in panel.edges]


def test_credential_loot_expands_into_read_steal_and_authenticate_actions():
    scenario = _chained("chained_kv_theft.yml")
    panel = build_attack_panel(scenario.model, scenario.attack_paths[0])

    assert _edge_types(panel) == [
        "COMPROMISES", "READS", "STEALS_CREDENTIAL", "AUTHENTICATES_AS", "ACHIEVES",
    ]
    assert any(node.id == "DataResource:kv-replace-me" for node in panel.nodes)
    credential = next(node for node in panel.nodes if node.type == "Credential")
    assert set(credential.properties) == {"source_ref"}
    assert all(edge.emphasis == "spine" for edge in panel.edges)


def test_application_ownership_adds_credential_then_authenticates_as_target():
    scenario = _scenario("examples/atomic/atomic_app_ownership_user_role.yml")
    panel = build_attack_panel(scenario.model, scenario.attack_paths[0])
    added = next(edge for edge in panel.edges if edge.type == "ADDS_APP_CREDENTIAL")
    authenticated = next(edge for edge in panel.edges if edge.type == "AUTHENTICATES_AS")
    credential = next(
        node for node in panel.nodes
        if node.type == "Credential" and node.properties.get("created_by_attacker") is True
    )

    assert added.target == credential.id
    assert authenticated.source == credential.id
    assert added.properties["authorization_source"] == "application_ownership"
    assert credential.properties["created_by_attacker"] is True
    assert credential.label == f"Credential for {credential.properties['target_ref']}"
    assert "TAKES_OVER" not in _edge_types(panel)


def test_application_administrator_names_role_used_to_add_credential():
    scenario = _scenario("examples/atomic/atomic_app_admin_user_role.yml")
    panel = build_attack_panel(scenario.model, scenario.attack_paths[0])
    added = next(edge for edge in panel.edges if edge.type == "ADDS_APP_CREDENTIAL")

    assert added.properties["authorization_source"] == "entra_role"
    assert added.properties["authorization_role"] == "Application Administrator"
    assert _edge_types(panel)[1:3] == ["ADDS_APP_CREDENTIAL", "AUTHENTICATES_AS"]


def test_group_ownership_explicitly_adds_controlled_principal_to_group():
    scenario = _scenario("examples/atomic/atomic_app_admin_group_owner.yml")
    panel = build_attack_panel(scenario.model, scenario.attack_paths[0])
    membership = next(
        edge for edge in panel.edges if edge.type == "ADDS_SELF_TO_GROUP"
    )

    assert membership.properties["action"] == "group_membership_modification"
    assert membership.target.startswith("Identity:")


def test_resource_control_expands_compute_and_managed_identity_actions():
    scenario = _chained("chained_apex.yml")
    panel = build_attack_panel(scenario.model, scenario.attack_paths[0])
    edge_types = _edge_types(panel)

    assert "EXECUTES_ON" in edge_types
    assert "USES_MANAGED_IDENTITY" in edge_types
    assert edge_types.count("USES_MANAGED_IDENTITY") == 4
    assert any(node.properties.get("identity_type") == "managed_identity"
               for node in panel.nodes if node.type == "Identity")
    assert all(node.position is not None for node in panel.nodes)


def test_direct_read_objective_expands_managed_identity_and_target_resource():
    scenario = _chained("chained_vulnerable_webapp.yml")
    panel = build_attack_panel(scenario.model, scenario.attack_paths[0])

    assert _edge_types(panel) == [
        "EXPLOITS", "USES_MANAGED_IDENTITY", "READS", "ACHIEVES",
    ]
    assert panel.edges[1].source == "ComputeResource:app01-portal"
    assert panel.edges[1].target == "Identity:mi:app01-portal"
    assert panel.edges[2].target == "DataResource:kv-1999ba-xz"
    assert panel.edges[2].properties["step"] == 2


def test_blocked_path_does_not_claim_to_achieve_objective():
    scenario = _chained("chained_unreachable.yml")
    overlay = scenario.attack_paths[0]
    panel = build_attack_panel(scenario.model, overlay)
    objective = next(node for node in panel.nodes if node.type == "Objective")

    assert objective.properties["status"] == "blocked"
    assert _edge_types(panel) == ["BLOCKED_AT"]
    assert panel.edges[0].properties["reason"] == overlay.reachability["reason"]
    assert "ACHIEVES" not in _edge_types(panel)


def test_unverified_empty_path_targets_objective_without_inventing_actions():
    overlay = SimpleNamespace(
        name="unknown",
        objective={"name": "Future objective"},
        initial_access={}, metadata={}, steps=[], credentials={},
        reachability={"status": "unverified", "reason": "not modeled"},
    )
    panel = build_attack_panel(DeploymentModel(), overlay)

    assert _edge_types(panel) == ["TARGETS"]
    assert panel.edges[0].source == "Attacker:unknown"
    assert panel.edges[0].properties["status"] == "unverified"


def test_invalid_partial_path_preserves_known_actions_then_stops():
    model = DeploymentModel(users={"alice": {}})
    overlay = SimpleNamespace(
        name="invalid",
        objective={"name": "Malformed objective", "capability": "entra_role"},
        initial_access={"principal_ref": "alice"}, metadata={}, credentials={},
        steps=[{
            "name": "Compromise Alice", "source_ref": "alice",
            "action": "compromised_identity",
        }],
        reachability={"status": "invalid", "reason": "objective role is missing"},
    )
    panel = build_attack_panel(model, overlay)

    assert _edge_types(panel) == ["COMPROMISES", "BLOCKED_AT"]
    assert panel.edges[-1].properties == {
        "action": "entra_role", "step": 1,
        "status": "invalid", "reason": "objective role is missing",
    }


def test_unknown_authored_action_uses_generic_edge_and_preserves_original_text():
    model = DeploymentModel(users={"alice": {}}, applications={"app": {}})
    overlay = SimpleNamespace(
        name="future",
        objective={"name": "Future objective", "capability": "future_capability"},
        initial_access={"principal_ref": "alice", "method": "compromised_identity"},
        metadata={}, credentials={},
        steps=[
            {"name": "Compromise Alice", "source_ref": "alice",
             "action": "compromised_identity"},
            {"name": "Consent phishing", "source_ref": "alice", "target_ref": "app",
             "action": "consent_phishing", "mitre": "T1528"},
        ],
        reachability={"status": "unverified", "reason": "future capability"},
    )
    panel = build_attack_panel(model, overlay)
    generic = next(edge for edge in panel.edges if edge.type == "PERFORMS_ACTION")

    assert generic.properties["original_action"] == "consent_phishing"
    assert generic.properties["mitre"] == "T1528"
    assert _edge_types(panel)[-1] == "TARGETS"


def test_narrative_uses_allowlisted_metadata_and_never_operator_credentials():
    overlay = SimpleNamespace(
        name="path",
        objective={
            "name": "Global Administrator", "description": "Escalate privileges.",
            "capability": "entra_role", "role": "Global Administrator",
            "impact": "critical", "internal_note": "drop me",
        },
        initial_access={
            "principal_ref": "alice", "method": "compromised_identity",
            "password": "NeverIncludeMe",
        },
        metadata={
            "complexity": "low", "tags": ["identity"], "mitre": ["T1078"],
            "private": "drop me",
        },
        reachability={"status": "reached", "reason": "role reached", "debug": "drop"},
        steps=[{
            "name": "Compromise", "source_ref": "alice",
            "action": "compromised_identity", "private": "drop",
        }],
        credentials={"password": "NeverIncludeMe", "client_secret": "NeverIncludeMe"},
    )
    narrative = build_path_narrative(overlay)
    text = repr(narrative)

    assert narrative.summary == "Escalate privileges."
    assert narrative.posture_panel_key == "posture-path"
    assert narrative.attack_panel_key == "attack-path"
    assert narrative.metadata == {
        "complexity": "low", "tags": ["identity"], "mitre": ["T1078"],
    }
    assert "NeverIncludeMe" not in text
    assert "internal_note" not in text
    assert "private" not in text


def test_narrative_has_deterministic_fallback_summary():
    overlay = SimpleNamespace(
        name="path", objective={"name": "Target"},
        initial_access={"principal_ref": "alice"}, metadata={}, steps=[],
        reachability={}, credentials={},
    )
    assert build_path_narrative(overlay).summary == "Attack path from alice to Target."


def test_projection_pairs_panel_and_narrative_for_each_path():
    scenario = _chained("chained_fullstack.yml")
    projections = build_attack_projections(scenario.model, scenario.attack_paths)

    assert len(projections) == len(scenario.attack_paths)
    for projection, overlay in zip(projections, scenario.attack_paths):
        assert projection.panel.key == f"attack-{overlay.name}"
        assert projection.narrative.name == overlay.name
        assert projection.narrative.attack_panel_key == projection.panel.key


def test_attack_layout_is_deterministic():
    scenario = _chained("chained_apex.yml")
    first = build_attack_panel(scenario.model, scenario.attack_paths[0])
    second = build_attack_panel(scenario.model, scenario.attack_paths[0])

    assert {node.id: node.position for node in first.nodes} == {
        node.id: node.position for node in second.nodes
    }


def test_every_example_path_builds_and_known_actions_need_no_generic_fallback():
    file_count = 0
    path_count = 0
    for path in sorted(Path("examples").rglob("*.yml")):
        scenario = _scenario(str(path))
        for overlay in scenario.attack_paths:
            panel = build_attack_panel(scenario.model, overlay)
            assert not any(edge.type == "PERFORMS_ACTION" for edge in panel.edges), path
            assert not any(edge.type == "TAKES_OVER" for edge in panel.edges), path
            path_count += 1
        file_count += 1

    assert file_count >= 53
    assert path_count >= 78


def test_attack_graph_properties_contain_no_secret_material():
    scenario = _chained("chained_apex.yml")
    panel = build_attack_panel(scenario.model, scenario.attack_paths[0])
    properties = [node.properties for node in panel.nodes] + [
        edge.properties for edge in panel.edges
    ]
    keys = {key for item in properties for key in item}
    text = repr(properties)

    assert not ({"password", "literal_value", "file_path", "pfx_password",
                 "private_key", "client_secret"} & keys)
    assert ".pem" not in text
    assert ".pfx" not in text
