"""Phase 3 tests for per-path, configuration-only posture graphs."""

from types import SimpleNamespace

from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.name_resolver import NameResolver
from src.primitives import (
    ATTACK_PATH,
    RANDOM,
    DeploymentModel,
    EntraRoleAssignment,
    GroupMembership,
    InitialAccessVector,
)
from src.reporting.posture import (
    POSTURE_FORBIDDEN_VERBS,
    build_posture_panel,
    build_posture_panels,
    select_posture_primitive_keys,
)
from src.scenario_loader import ScenarioLoader


def _scenario(path):
    config = ConfigManager().load_config(path)
    return ScenarioLoader(EntityGenerator(data_dir="entity_data")).load(
        config, domain="example.com", enforce_reachability=False,
    )


def _chained(fixture):
    return _scenario(f"examples/chained/{fixture}")


def _edges_by_key(panel):
    return {
        edge.properties.get("key"): edge
        for edge in panel.edges if edge.properties.get("key")
    }


def test_posture_adds_derived_management_bridge_to_disconnected_objective_holder():
    resolver = NameResolver(load_overrides=False)
    role_id = resolver.entra_roles["Global Administrator"]
    model = DeploymentModel(
        applications={"controller": {}, "objective-holder": {}},
        primitives=[EntraRoleAssignment(
            "path__role", ATTACK_PATH, "objective-holder", "service_principal", role_id,
        )],
    )
    overlay = SimpleNamespace(
        name="path",
        initial_access={"principal_ref": "controller"},
        objective={
            "name": "Reach Global Administrator", "capability": "entra_role",
            "role": "Global Administrator",
        },
        reachability={"status": "reached"},
        steps=[
            {
                "name": "Implicitly manage objective application",
                "source_ref": "controller", "target_ref": "objective-holder",
                "action": "application_control", "derived": True,
            },
            {
                "name": "Achieve objective", "source_ref": "objective-holder",
                "action": "entra_role", "derived": True,
            },
        ],
    )

    panel = build_posture_panel(model, overlay, resolver)
    bridge = next(edge for edge in panel.edges if edge.type == "CAN_MANAGE")

    assert bridge.source == "ServicePrincipal:controller"
    assert bridge.target == "ServicePrincipal:objective-holder"
    assert bridge.emphasis == "inferred"
    assert bridge.properties == {
        "derived": True,
        "reason": "Implicitly manage objective application",
        "capability": "entra_role",
    }


def test_key_vault_path_expands_complete_configuration_chain():
    scenario = _chained("chained_kv_theft.yml")
    overlay = scenario.attack_paths[0]
    panel = build_posture_panel(scenario.model, overlay)
    by_key = _edges_by_key(panel)
    node_types = {node.type for node in panel.nodes}

    assert by_key["kv_theft__a1"].type == "HAS_AZURE_ROLE"
    assert by_key["kv_theft__a1"].emphasis == "spine"
    assert by_key["kv_theft__d1"].type == "STORES"
    assert by_key["kv_theft__d1"].emphasis == "spine"
    assert by_key["kv_theft__app_secret"].type == "HAS_CREDENTIAL"
    assert by_key["kv_theft__a2"].type == "HAS_ENTRA_ROLE"
    assert {"User", "KeyVault", "Credential", "ServicePrincipal", "EntraRole", "Objective"} <= node_types
    assert any(edge.type == "CREDENTIAL_FOR" and edge.emphasis == "spine"
               for edge in panel.edges)
    assert any(edge.type == "SATISFIES_OBJECTIVE" for edge in panel.edges)
    assert all(node.position is not None for node in panel.nodes)


def test_apex_graph_marks_traversed_read_edges_and_offspine_relationships():
    scenario = _chained("chained_apex.yml")
    panel = build_posture_panel(scenario.model, scenario.attack_paths[0])
    by_key = _edges_by_key(panel)

    # Reachability steps name the DataInject for a credential loot. The projector
    # must also recover the RBAC read edge that makes the loot possible.
    assert by_key["apex_to_global_admin__rbac_f_read"].emphasis == "spine"
    assert by_key["apex_to_global_admin__rbac_v_read"].emphasis == "spine"
    assert by_key["apex_to_global_admin__rbac_a_read"].emphasis == "spine"
    assert by_key["apex_to_global_admin__rbac_l_read"].emphasis == "spine"

    assert by_key["apex_to_global_admin__api_recon"].emphasis == "offspine"
    assert by_key["apex_to_global_admin__rbac_v_cosmos"].emphasis == "offspine"
    assert by_key["apex_to_global_admin__au_user"].type == "MEMBER_OF_AU"
    assert by_key["apex_to_global_admin__au_user"].emphasis == "offspine"
    assert any(edge.type == "RUNS_AS" and edge.emphasis == "spine"
               for edge in panel.edges)
    assert any(node.type == "ManagedIdentity" for node in panel.nodes)


def test_posture_edges_never_use_attack_ontology_verbs():
    scenario = _chained("chained_apex.yml")
    panel = build_posture_panel(scenario.model, scenario.attack_paths[0])
    edge_types = {edge.type for edge in panel.edges}

    assert not (edge_types & POSTURE_FORBIDDEN_VERBS)
    assert not any(
        token in edge.type
        for edge in panel.edges
        for token in ("EXPLOIT", "STEAL", "COMPROMISE", "PIVOT", "TAKE_OVER")
    )


def test_unreachable_path_targets_but_does_not_satisfy_objective():
    scenario = _chained("chained_unreachable.yml")
    panel = build_posture_panel(scenario.model, scenario.attack_paths[0])
    objective = next(node for node in panel.nodes if node.type == "Objective")

    assert objective.properties["status"] == "blocked"
    assert any(edge.type == "TARGETS_OBJECTIVE" for edge in panel.edges)
    assert not any(edge.type == "SATISFIES_OBJECTIVE" for edge in panel.edges)


def test_resource_foothold_draws_only_real_internet_exposure():
    model = DeploymentModel(
        virtual_machines={"vm": {"resource_group_name": "rg"}},
        resource_groups={"rg": {"location": "eastus"}},
        primitives=[InitialAccessVector(
            "path__foothold", ATTACK_PATH, "exposed_rdp", "vm", "virtual_machine",
            "code_execution", expose_to_internet=True, credential="weak",
        )],
    )
    overlay = SimpleNamespace(
        name="path",
        objective={"name": "Code execution", "capability": "code_execution", "target_ref": "vm"},
        initial_access={"principal_ref": "vm", "method": "exposed_rdp"},
        steps=[{"name": "RDP", "source_ref": "vm", "action": "exposed_rdp"}],
        reachability={"status": "reached", "reason": "vm is controlled"},
    )

    panel = build_posture_panel(model, overlay)
    can_reach = next(edge for edge in panel.edges if edge.type == "CAN_REACH")
    assert can_reach.emphasis == "spine"
    assert can_reach.source == "Internet:internet"
    assert can_reach.target == "VirtualMachine:vm"


def test_precompromised_identity_is_entry_marker_not_attack_edge():
    model = DeploymentModel(users={"alice": {}})
    overlay = SimpleNamespace(
        name="path",
        objective={"name": "Control Alice", "capability": "control_principal", "target_ref": "alice"},
        initial_access={"principal_ref": "alice", "method": "compromised_identity"},
        steps=[{"name": "Compromise alice", "source_ref": "alice",
                "action": "compromised_identity"}],
        reachability={"status": "reached", "reason": "alice is controlled"},
    )
    panel = build_posture_panel(model, overlay)
    alice = next(node for node in panel.nodes if node.id == "User:alice")

    assert alice.properties["entry"] is True
    assert not any(edge.type == "COMPROMISES" for edge in panel.edges)
    assert any(edge.type == "SATISFIES_OBJECTIVE" for edge in panel.edges)


def test_step_can_pull_a_traversed_baseline_primitive_into_the_path():
    baseline_edge = GroupMembership(
        "baseline__membership", RANDOM, "alice", "user", "operators",
    )
    model = DeploymentModel(
        users={"alice": {}}, groups={"operators": {}}, primitives=[baseline_edge],
    )
    overlay = SimpleNamespace(
        name="path",
        objective={"name": "Control operators", "capability": "control_principal",
                   "target_ref": "operators"},
        initial_access={"principal_ref": "alice"},
        steps=[
            {"name": "Compromise", "source_ref": "alice"},
            {"name": "Inherit", "source_ref": "alice", "target_ref": "operators",
             "uses": ["membership"]},
        ],
        reachability={"status": "reached", "reason": "operators controlled"},
    )

    selected, spine = select_posture_primitive_keys(model, overlay)
    panel = build_posture_panel(model, overlay)

    assert selected == spine == {"baseline__membership"}
    membership = next(edge for edge in panel.edges if edge.type == "MEMBER_OF")
    assert membership.properties["origin"] == RANDOM
    assert membership.emphasis == "spine"


def test_each_panel_excludes_other_paths_primitives():
    scenario = _chained("chained_fullstack.yml")
    panels = build_posture_panels(scenario.model, scenario.attack_paths)
    assert len(panels) == len(scenario.attack_paths)

    for panel, overlay in zip(panels, scenario.attack_paths):
        keys = {
            edge.properties["key"] for edge in panel.edges
            if edge.properties.get("key")
        }
        other_prefixes = {
            f"{other.name}__" for other in scenario.attack_paths if other.name != overlay.name
        }
        assert all(not any(key.startswith(prefix) for prefix in other_prefixes) for key in keys)


def test_atomic_macro_path_also_builds_a_valid_posture_panel():
    scenario = _scenario("examples/atomic/atomic_kv_theft_user.yml")
    panels = build_posture_panels(scenario.model, scenario.attack_paths)

    assert panels
    assert panels[0].nodes
    assert any(edge.type == "STORES" for edge in panels[0].edges)


def test_posture_properties_never_contain_secret_values_or_paths():
    scenario = _chained("chained_apex.yml")
    panel = build_posture_panel(scenario.model, scenario.attack_paths[0])
    properties = [node.properties for node in panel.nodes] + [
        edge.properties for edge in panel.edges
    ]
    keys = {key for item in properties for key in item}
    rendered_data = repr(properties)

    assert not ({"password", "literal_value", "file_path", "pfx_password",
                 "private_key"} & keys)
    assert ".pem" not in rendered_data
    assert ".pfx" not in rendered_data
