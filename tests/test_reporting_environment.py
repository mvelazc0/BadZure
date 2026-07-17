"""Phase 2 tests for identity, resource, and assignment projections."""

from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator
from src.name_resolver import NameResolver
from src.primitives import (
    ATTACK_PATH,
    RANDOM,
    ApiPermission,
    AppCredential,
    AppOwnership,
    AuMembership,
    AzureRbacAssignment,
    DataInject,
    DeploymentModel,
    EntraRoleAssignment,
    GroupMembership,
    GroupOwnership,
)
from src.reporting.environment import (
    APP_NODE_CAP,
    GROUP_NODE_CAP,
    build_assignment_panel,
    build_environment_graphs,
    build_identity_panel,
    build_resource_panel,
    build_safe_inventory,
)
from src.scenario_loader import ScenarioLoader


def _compiled(fixture):
    config = ConfigManager().load_config(f"examples/chained/{fixture}")
    return ScenarioLoader(EntityGenerator(data_dir="entity_data")).load(
        config, domain="example.com", enforce_reachability=False,
    ).model


def _edge_types(panel):
    return {edge.type for edge in panel.edges}


def test_chained_fixture_builds_three_valid_positioned_panels():
    model = _compiled("chained_apex.yml")
    result = build_environment_graphs(model)

    assert [panel.key for panel in result.panels] == [
        "identity", "resources", "assignments",
    ]
    assert all(node.position is not None for panel in result.panels for node in panel.nodes)
    assignment_primitives = sum(isinstance(p, (
        EntraRoleAssignment, AzureRbacAssignment, ApiPermission, GroupMembership,
        GroupOwnership, AppOwnership, AuMembership,
    )) for p in model.primitives)
    assert len(result.assignments.edges) == assignment_primitives
    assert len(result.assignment_details) == assignment_primitives


def test_identity_projection_preserves_structure_and_aggregation():
    model = DeploymentModel(
        users={"alice": {}, "bob": {}},
        groups={"child": {}, "parent": {}, "owned": {}},
        applications={"sp-owner": {}, "sp-target": {}, "sp-hidden": {}},
        administrative_units={"tier0": {}},
        primitives=[
            GroupMembership("member-user", RANDOM, "alice", "user", "child"),
            GroupMembership("member-nested", ATTACK_PATH, "child", "group", "parent"),
            GroupOwnership("group-user-owner", RANDOM, "bob", "user", "owned"),
            GroupOwnership("group-sp-owner", ATTACK_PATH, "sp-owner", "service_principal", "owned"),
            AppOwnership("app-user-owner", RANDOM, "alice", "user", "sp-target"),
            AppOwnership("app-sp-owner", ATTACK_PATH, "sp-owner", "service_principal", "sp-target"),
            AuMembership("au-user", RANDOM, "alice", "user", "tier0"),
            AuMembership("au-group", RANDOM, "owned", "group", "tier0"),
        ],
    )

    panel = build_identity_panel(model)
    by_id = {node.id: node for node in panel.nodes}

    assert "User:alice" not in by_id
    assert by_id["Organization:lab"].properties["users"] == 2
    assert by_id["Group:child"].properties["member_count"] == 1
    assert by_id["Group:owned"].properties["owner_count"] == 1
    assert by_id["AdministrativeUnit:tier0"].properties == {
        "user_count": 1, "group_count": 1,
    }
    assert "ServicePrincipal:sp-owner" in by_id
    assert "ServicePrincipal:sp-target" in by_id
    assert by_id["ServicePrincipalSummary:other"].properties == {
        "count": 1, "members": ["sp-hidden"],
    }
    assert {"CONTAINS", "MEMBER_OF", "OWNS"} <= _edge_types(panel)


def test_identity_projection_collapses_groups_and_pathologically_connected_apps():
    groups = {f"g{i}": {} for i in range(GROUP_NODE_CAP + 1)}
    apps = {f"app{i}": {} for i in range(APP_NODE_CAP + 1)}
    primitives = [
        AppOwnership(f"own{i}", ATTACK_PATH, f"app{i}", "service_principal",
                     f"app{(i + 1) % len(apps)}")
        for i in range(len(apps))
    ]
    panel = build_identity_panel(DeploymentModel(
        groups=groups, applications=apps, primitives=primitives,
    ))
    by_id = {node.id: node for node in panel.nodes}

    assert by_id["GroupSummary:all"].properties["count"] == GROUP_NODE_CAP + 1
    assert by_id["ServicePrincipalSummary:other"].properties["count"] == APP_NODE_CAP + 1
    assert not any(node.type == "Group" for node in panel.nodes)
    assert not any(node.type == "ServicePrincipal" for node in panel.nodes)


def test_resource_projection_covers_every_supported_resource_family():
    resource_groups = {
        "rg-one": {"name": "rg-one", "location": "eastus"},
        "rg-empty": {"name": "rg-empty", "location": "westus"},
    }
    common = {"name": "resource", "location": "eastus", "resource_group_name": "rg-one"}
    model = DeploymentModel(
        subscription_id="sub-123",
        resource_groups=resource_groups,
        key_vaults={"kv": dict(common)},
        storage_accounts={"storage": dict(common)},
        virtual_machines={"vm": dict(common)},
        logic_apps={"logic": dict(common)},
        automation_accounts={"auto": dict(common)},
        function_apps={"function": dict(common)},
        app_services={"web": dict(common)},
        cosmos_dbs={"cosmos": dict(common)},
    )

    panel = build_resource_panel(model)
    node_types = {node.type for node in panel.nodes}
    assert {
        "Subscription", "ResourceGroup", "KeyVaultSummary", "StorageAccountSummary",
        "VirtualMachineSummary", "LogicAppSummary", "AutomationAccountSummary",
        "FunctionAppSummary", "AppServiceSummary", "CosmosDBSummary",
    } <= node_types
    assert "ResourceGroup:rg-empty" in {node.id for node in panel.nodes}
    summaries = [node for node in panel.nodes if node.type.endswith("Summary")]
    assert len(summaries) == 8
    assert all(node.properties["count"] == 1 for node in summaries)


def test_safe_inventory_keeps_useful_fields_and_removes_secret_material():
    model = DeploymentModel(
        users={"alice": {
            "display_name": "Alice", "user_principal_name": "alice@example.com",
            "password": "NeverIncludeMe",
        }},
        virtual_machines={"vm": {
            "name": "vm", "resource_group_name": "rg", "location": "eastus",
            "admin_username": "operator", "admin_password": "NeverIncludeMeEither",
        }},
    )
    inventory = build_safe_inventory(model)
    text = repr(inventory)

    assert inventory["users"][0]["user_principal_name"] == "alice@example.com"
    assert inventory["virtual_machines"][0]["admin_username"] == "operator"
    assert "NeverIncludeMe" not in text
    assert "password" not in text


def test_assignment_projection_maps_all_seven_primitive_families():
    resolver = NameResolver(load_overrides=False)
    role_id = resolver.entra_roles["Global Administrator"]
    permission_id = resolver.api_permissions["graph"]["Directory.Read.All"]
    model = DeploymentModel(
        subscription_id="sub-123",
        users={"alice": {}},
        groups={"engineers": {}},
        applications={"app": {}, "owned-app": {}},
        administrative_units={"corp": {}},
        resource_groups={"rg": {"location": "eastus"}},
        key_vaults={"kv": {"resource_group_name": "rg", "location": "eastus"}},
        primitives=[
            EntraRoleAssignment("entra", RANDOM, "alice", "user", role_id),
            AzureRbacAssignment(
                "rbac", ATTACK_PATH, "app", "service_principal", "Reader",
                "resource", scope_ref="kv", scope_resource_type="key_vault",
            ),
            ApiPermission("api", ATTACK_PATH, "app", permission_id, "graph"),
            GroupMembership("member", RANDOM, "alice", "user", "engineers"),
            GroupOwnership("group-owner", ATTACK_PATH, "app", "service_principal", "engineers"),
            AppOwnership("app-owner", ATTACK_PATH, "app", "service_principal", "owned-app"),
            AuMembership("au", RANDOM, "engineers", "group", "corp"),
            AppCredential("ignored-credential", ATTACK_PATH, "app", "password"),
            DataInject(
                "ignored-inject", ATTACK_PATH, "literal", "key_vault_secret", "kv",
                "do-not-render", literal_value="secret",
            ),
        ],
    )

    panel, details = build_assignment_panel(model, resolver)
    assert _edge_types(panel) == {
        "ASSIGNED_ENTRA_ROLE", "ASSIGNED_AZURE_ROLE", "GRANTED_API_PERMISSION",
        "MEMBER_OF", "OWNS_GROUP", "OWNS_APPLICATION", "MEMBER_OF_AU",
    }
    assert len(panel.edges) == len(details) == 7
    assert "Global Administrator" in {node.label for node in panel.nodes}
    api_edge = next(edge for edge in panel.edges if edge.type == "GRANTED_API_PERMISSION")
    assert api_edge.properties["permission"] == "Directory.Read.All"
    rbac_edge = next(edge for edge in panel.edges if edge.type == "ASSIGNED_AZURE_ROLE")
    assert rbac_edge.target == "AzureResource:kv"
    assert rbac_edge.emphasis == "spine"
    assert next(edge for edge in panel.edges if edge.id.endswith(":entra")).emphasis == "normal"
    assert "secret" not in repr(details).lower()


def test_assignment_projection_supports_managed_identity_and_all_scope_levels():
    model = DeploymentModel(
        subscription_id="sub",
        resource_groups={"rg": {"location": "eastus"}},
        virtual_machines={"vm": {"resource_group_name": "rg"}},
        primitives=[
            AzureRbacAssignment(
                "sub-role", RANDOM, "vm", "managed_identity", "Reader",
                "subscription", mi_source_type="vm",
            ),
            AzureRbacAssignment(
                "rg-role", RANDOM, "vm", "managed_identity", "Reader",
                "resource_group", mi_source_type="vm", scope_ref="rg",
            ),
            AzureRbacAssignment(
                "resource-role", RANDOM, "vm", "managed_identity", "Contributor",
                "resource", mi_source_type="vm", scope_ref="vm",
                scope_resource_type="virtual_machine",
            ),
        ],
    )
    panel, _details = build_assignment_panel(model)
    by_id = {node.id: node for node in panel.nodes}

    assert by_id["ManagedIdentity:vm"].properties["source_type"] == "vm"
    assert {edge.target for edge in panel.edges} == {
        "Subscription:sub", "ResourceGroup:rg", "AzureResource:vm",
    }


def test_layout_is_deterministic_for_the_same_model():
    model = _compiled("chained_org_baseline.yml")
    first = build_environment_graphs(model)
    second = build_environment_graphs(model)

    for first_panel, second_panel in zip(first.panels, second.panels):
        assert {node.id: node.position for node in first_panel.nodes} == {
            node.id: node.position for node in second_panel.nodes
        }


def test_environment_details_contain_no_credential_or_inject_records():
    model = _compiled("chained_apex.yml")
    result = build_environment_graphs(model)
    detail_types = {detail["type"] for detail in result.assignment_details}
    assert "AppCredential" not in detail_types
    assert "DataInject" not in detail_types
    assert not any("password" in repr(row).lower() for rows in result.inventory.values() for row in rows)
