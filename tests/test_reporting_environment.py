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
    assert len(result.assignment_details) == assignment_primitives
    assert {node.type for node in result.assignments.nodes} >= {
        "AssignmentCatalog", "AssignmentFamily", "PrincipalSummary",
    }


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
    assert by_id["Organization:lab"].properties["managed_identities"] == 0
    assert by_id["IdentitySummary:users"].properties == {
        "identity_type": "user", "count": 2,
        "group_memberships": 1, "group_ownerships": 1,
        "application_ownerships": 1, "administrative_unit_memberships": 1,
    }
    assert by_id["IdentitySummary:service-principals"].properties == {
        "identity_type": "service_principal", "count": 3,
        "credentialed_principals": 0, "group_memberships": 0,
        "group_ownerships": 1, "application_ownerships": 1,
        "credential_count": 0,
    }
    assert by_id["IdentitySummary:managed-identities"].properties == {
        "identity_type": "managed_identity", "count": 0, "source_types": {},
    }
    assert by_id["Group:child"].properties["user_members"] == 1
    assert by_id["Group:parent"].properties["group_members"] == 1
    assert by_id["Group:owned"].properties["user_owners"] == 1
    assert by_id["Group:owned"].properties["service_principal_owners"] == 1
    assert by_id["AdministrativeUnit:tier0"].properties == {
        "user_count": 1, "group_count": 1,
    }
    assert {by_id[f"IdentityCategory:{key}"].properties["count"] for key in (
        "users", "service-principals", "groups",
    )} == {2, 3}
    assert by_id["AdministrativeUnitCatalog:all"].properties == {"count": 1}
    assert not any(node.type == "ServicePrincipal" for node in panel.nodes)
    assert _edge_types(panel) == {
        "HAS_PRINCIPAL_CATALOG", "HAS_ADMINISTRATIVE_UNITS",
        "HAS_IDENTITY_CATEGORY", "SUMMARIZES", "CONTAINS_IDENTITY", "NESTED_IN",
    }


def test_identity_projection_collapses_large_group_inventory():
    groups = {f"g{i}": {} for i in range(GROUP_NODE_CAP + 1)}
    panel = build_identity_panel(DeploymentModel(
        groups=groups, applications={f"app{i}": {} for i in range(75)},
    ))
    by_id = {node.id: node for node in panel.nodes}

    assert by_id["IdentitySummary:groups"].properties["count"] == GROUP_NODE_CAP + 1
    assert by_id["IdentitySummary:service-principals"].properties["count"] == 75
    assert not any(node.type == "Group" for node in panel.nodes)
    assert not any(node.type == "ServicePrincipal" for node in panel.nodes)


def test_identity_layout_wraps_group_children_without_entering_principal_columns():
    panel = build_identity_panel(DeploymentModel(
        users={"alice": {}},
        applications={"app": {}},
        groups={f"group-{index}": {} for index in range(12)},
        administrative_units={"engineering": {}},
    ))
    by_id = {node.id: node for node in panel.nodes}
    groups = [node for node in panel.nodes if node.type == "Group"]

    assert len({node.position[1] for node in groups}) == 4
    assert len({node.position[0] for node in groups}) == 3
    assert min(node.position[0] for node in groups) > (
        by_id["IdentitySummary:managed-identities"].position[0]
    )
    assert max(node.position[0] for node in groups) < (
        by_id["AdministrativeUnitCatalog:all"].position[0]
    )


def test_identity_catalog_orders_principals_and_separates_directory_structure():
    panel = build_identity_panel(DeploymentModel(
        users={"alice": {}}, groups={"engineering": {}},
        applications={"automation": {}}, administrative_units={"finance": {}},
    ))
    root = next(node for node in panel.nodes if node.type == "Organization")
    categories = [node for node in panel.nodes if node.type == "IdentityCategory"]

    assert len(categories) == 3
    assert len({node.position[0] for node in categories}) == 3
    assert len({node.position[1] for node in categories}) == 1
    assert all(root.position[1] < node.position[1] for node in categories)
    by_id = {node.id: node for node in panel.nodes}
    assert (
        by_id["IdentityCategory:users"].position[0]
        < by_id["IdentityCategory:service-principals"].position[0]
        < by_id["IdentityCategory:groups"].position[0]
    )
    assert "IdentityCategory:administrative-units" not in by_id
    assert by_id["AdministrativeUnitCatalog:all"].properties == {"count": 1}
    assert (
        by_id["SecurityPrincipalCatalog:all"].position[0]
        < by_id["AdministrativeUnitCatalog:all"].position[0]
    )
    assert all(
        node.position[0] > by_id["IdentityCategory:groups"].position[0]
        for node in panel.nodes if node.type == "AdministrativeUnit"
    )


def test_identity_projection_counts_managed_identities_as_service_principal_subtypes():
    panel = build_identity_panel(DeploymentModel(
        applications={"automation-app": {}},
        virtual_machines={"vm-one": {}, "vm-two": {}},
        logic_apps={"workflow": {}},
        automation_accounts={"runbooks": {}},
        function_apps={"function": {}},
        app_services={"web": {}},
    ))
    by_id = {node.id: node for node in panel.nodes}

    assert by_id["Organization:lab"].properties["service_principals"] == 7
    assert by_id["Organization:lab"].properties["managed_identities"] == 6
    assert by_id["IdentityCategory:service-principals"].properties["count"] == 7
    assert by_id["IdentitySummary:service-principals"].properties["count"] == 1
    assert by_id["IdentitySummary:managed-identities"].properties == {
        "identity_type": "managed_identity",
        "count": 6,
        "source_types": {
            "Virtual Machines": 2,
            "Logic Apps": 1,
            "Automation Accounts": 1,
            "Function Apps": 1,
            "App Services": 1,
        },
    }
    managed_edge = next(
        edge for edge in panel.edges
        if edge.target == "IdentitySummary:managed-identities"
    )
    assert managed_edge.source == "IdentityCategory:service-principals"
    assert managed_edge.properties == {"count": 6}


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
    assert {node.label for node in summaries} == {
        "Key Vault · 1", "Storage Account · 1", "Virtual Machine · 1",
        "Logic App · 1", "Automation Account · 1", "Function App · 1",
        "App Service · 1", "Cosmos DB Account · 1",
    }
    by_id = {node.id: node for node in panel.nodes}
    assert by_id["Subscription:sub-123"].properties == {
        "subscription_id": "sub-123", "resource_group_count": 2,
        "resource_count": 8, "resource_type_count": 8,
        "region_count": 2, "regions": ["eastus", "westus"],
    }
    assert by_id["ResourceGroup:rg-one"].properties["resource_count"] == 8
    assert by_id["ResourceGroup:rg-one"].properties["resource_type_count"] == 8
    assert by_id["ResourceGroup:rg-empty"].properties == {
        "location": "westus", "resource_count": 0, "resource_type_count": 0,
        "resource_types": [], "empty": True,
    }


def test_resource_projection_pluralizes_counts_and_calls_out_unplaced_resources():
    model = DeploymentModel(
        key_vaults={
            "kv-one": {"location": "eastus"},
            "kv-two": {"location": "eastus"},
        },
        storage_accounts={"storage": {"location": "eastus"}},
    )

    panel = build_resource_panel(model)
    by_type = {node.type: node for node in panel.nodes}

    assert by_type["UnplacedResources"].label == "Unplaced Resources · 3"
    assert by_type["UnplacedResources"].properties == {
        "resource_count": 3, "resource_type_count": 2,
        "resource_types": ["Key Vaults", "Storage Accounts"],
        "warning": "No resource group placement is available",
    }
    assert by_type["KeyVaultSummary"].label == "Key Vaults · 2"
    assert by_type["StorageAccountSummary"].label == "Storage Account · 1"
    assert not any(node.type == "ResourceGroup" for node in panel.nodes)
    assert {edge.source for edge in panel.edges if edge.target.startswith(
        ("KeyVaultSummary:", "StorageAccountSummary:")
    )} == {"UnplacedResources:all"}


def test_resource_layout_keeps_each_resource_group_children_in_separate_clusters():
    common = {"location": "eastus"}
    panel = build_resource_panel(DeploymentModel(
        resource_groups={
            "rg-a": dict(common), "rg-b": dict(common), "rg-c": dict(common),
        },
        key_vaults={
            "kv-a": {**common, "resource_group_name": "rg-a"},
            "kv-b": {**common, "resource_group_name": "rg-b"},
        },
        storage_accounts={
            "sa-b": {**common, "resource_group_name": "rg-b"},
            "sa-c": {**common, "resource_group_name": "rg-c"},
        },
        app_services={
            "web-a": {**common, "resource_group_name": "rg-a"},
            "web-c": {**common, "resource_group_name": "rg-c"},
        },
    ))
    by_id = {node.id: node for node in panel.nodes}
    child_x = {}
    for edge in panel.edges:
        if edge.source.startswith("ResourceGroup:") and not edge.target.startswith(
            "ResourceGroup:"
        ):
            child_x.setdefault(edge.source, []).append(by_id[edge.target].position[0])

    ordered = sorted(child_x, key=lambda node_id: by_id[node_id].position[0])
    assert all(
        max(child_x[left]) < min(child_x[right])
        for left, right in zip(ordered, ordered[1:])
    )
    assert all(
        min(xs) <= by_id[parent].position[0] <= max(xs)
        for parent, xs in child_x.items()
    )


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
    exchange_permission_id = resolver.api_permissions["exchange"]["full_access_as_app"]
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
            ApiPermission(
                "exchange-api", RANDOM, "app", exchange_permission_id, "exchange",
            ),
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
    assert _edge_types(panel) == {"CONTAINS_FAMILY", "CONTAINS_KIND", "ASSIGNED_TO"}
    assert len(details) == 8
    family_labels = {node.label for node in panel.nodes if node.type == "AssignmentFamily"}
    assert family_labels == {
        "Entra ID Roles", "Azure RBAC", "Microsoft Graph", "Exchange Online", "Group Membership",
        "Group Ownership", "Application Ownership", "Administrative Units",
    }
    kind_labels = {node.label for node in panel.nodes
                   if node.type in {"Role", "Permission", "Relationship"}}
    assert {
        "Global Administrator", "Reader", "Directory.Read.All", "full_access_as_app",
    } <= kind_labels
    summaries = [node for node in panel.nodes if node.type == "PrincipalSummary"]
    assert {node.properties["principal_type"] for node in summaries} == {
        "user", "group", "service_principal",
    }
    assert any(edge.emphasis == "spine" for edge in panel.edges
               if edge.type == "ASSIGNED_TO")
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
    roles = {node.label: node for node in panel.nodes if node.type == "Role"}
    summaries = [node for node in panel.nodes if node.type == "PrincipalSummary"]

    assert set(roles) == {"Reader", "Contributor"}
    assert roles["Reader"].properties["count"] == 2
    assert len(summaries) == 2
    reader_summary = next(node for node in summaries if node.id.startswith(
        "PrincipalSummary:azure-rbac:Reader"
    ))
    assert reader_summary.properties == {
        "principal_type": "managed_identity", "count": 2,
        "unique_principals": 1, "principals": ["vm"],
        "baseline_count": 2, "attack_path_count": 0,
        "assignment_keys": ["rg-role", "sub-role"],
    }


def test_assignment_taxonomy_aggregates_repeated_roles_by_principal_type():
    model = DeploymentModel(
        users={"alice": {}, "bob": {}},
        groups={"readers": {}},
        applications={"automation": {}},
        primitives=[
            AzureRbacAssignment(
                "reader-alice", RANDOM, "alice", "user", "Reader", "subscription",
            ),
            AzureRbacAssignment(
                "reader-bob", RANDOM, "bob", "user", "Reader", "subscription",
            ),
            AzureRbacAssignment(
                "reader-group", RANDOM, "readers", "group", "Reader", "subscription",
            ),
            AzureRbacAssignment(
                "reader-app", ATTACK_PATH, "automation", "service_principal",
                "Reader", "subscription",
            ),
        ],
    )

    panel, details = build_assignment_panel(model)
    roles = [node for node in panel.nodes if node.type == "Role"]
    summaries = [node for node in panel.nodes if node.type == "PrincipalSummary"]

    assert len(details) == 4
    assert len(roles) == 1
    assert roles[0].label == "Reader"
    assert roles[0].properties["count"] == 4
    assert len(summaries) == 3
    users = next(node for node in summaries
                 if node.properties["principal_type"] == "user")
    assert users.label == "Users · 2"
    assert users.properties["principals"] == ["alice", "bob"]
    assert users.properties["baseline_count"] == 2
    app = next(node for node in summaries
               if node.properties["principal_type"] == "service_principal")
    assert app.properties["attack_path_count"] == 1
    app_edge = next(edge for edge in panel.edges if edge.target == app.id)
    assert app_edge.emphasis == "spine"


def test_assignment_taxonomy_layout_grows_down_from_root():
    model = DeploymentModel(
        users={"alice": {}},
        applications={"app": {}},
        primitives=[
            AzureRbacAssignment(
                "reader", RANDOM, "alice", "user", "Reader", "subscription",
            ),
            AppOwnership(
                "owner", RANDOM, "app", "service_principal", "app",
            ),
        ],
    )

    panel, _details = build_assignment_panel(model)
    root = next(node for node in panel.nodes if node.type == "AssignmentCatalog")
    families = [node for node in panel.nodes if node.type == "AssignmentFamily"]
    kinds = [node for node in panel.nodes
             if node.type in {"Role", "Permission", "Relationship"}]
    summaries = [node for node in panel.nodes if node.type == "PrincipalSummary"]

    assert all(root.position[1] < node.position[1] for node in families)
    assert max(node.position[1] for node in families) < min(
        node.position[1] for node in kinds
    )
    assert max(node.position[1] for node in kinds) < min(
        node.position[1] for node in summaries
    )
    assert len({node.position[0] for node in families}) > 1


def test_assignment_family_layout_uses_requested_left_to_right_order():
    model = DeploymentModel(
        users={"alice": {}}, groups={"team": {}}, applications={"app": {}},
        primitives=[
            EntraRoleAssignment("entra", RANDOM, "alice", "user", "Role A"),
            AzureRbacAssignment(
                "rbac", RANDOM, "alice", "user", "Reader", "subscription",
            ),
            GroupMembership("member", RANDOM, "alice", "user", "team"),
            GroupOwnership("group-owner", RANDOM, "alice", "user", "team"),
            AppOwnership("app-owner", RANDOM, "alice", "user", "app"),
            ApiPermission("graph", RANDOM, "app", "Permission A", "graph"),
        ],
    )
    panel, _details = build_assignment_panel(model)
    families = sorted(
        (node for node in panel.nodes if node.type == "AssignmentFamily"),
        key=lambda node: node.position[0],
    )

    assert [node.label for node in families] == [
        "Entra ID Roles", "Azure RBAC", "Group Membership", "Group Ownership",
        "Application Ownership", "Microsoft Graph",
    ]


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
