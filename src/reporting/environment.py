"""Pure DeploymentModel projections for environment-level report graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.name_resolver import NameResolver
from src.primitives import (
    ApiPermission,
    AppOwnership,
    AuMembership,
    AzureRbacAssignment,
    DeploymentModel,
    EntraRoleAssignment,
    GroupMembership,
    GroupOwnership,
)
from src.reporting.layouts import apply_layered_layout
from src.reporting.model import GraphEdge, GraphNode, GraphPanel
from src.reporting.ontology import load_bundled_ontology, validate_panel
from src.reporting.safety import edge_id, safe_properties, typed_id


GROUP_NODE_CAP = 60
APP_NODE_CAP = 40

_RESOURCE_TYPES = {
    "key_vaults": ("KeyVaultSummary", "Key Vault"),
    "storage_accounts": ("StorageAccountSummary", "Storage Account"),
    "virtual_machines": ("VirtualMachineSummary", "Virtual Machine"),
    "logic_apps": ("LogicAppSummary", "Logic App"),
    "automation_accounts": ("AutomationAccountSummary", "Automation Account"),
    "function_apps": ("FunctionAppSummary", "Function App"),
    "app_services": ("AppServiceSummary", "App Service"),
    "cosmos_dbs": ("CosmosDBSummary", "Cosmos DB"),
}

_RESOURCE_TYPE_TO_ATTR = {
    "key_vault": "key_vaults",
    "storage_account": "storage_accounts",
    "virtual_machine": "virtual_machines",
    "logic_app": "logic_apps",
    "automation_account": "automation_accounts",
    "function_app": "function_apps",
    "app_service": "app_services",
    "cosmos_db": "cosmos_dbs",
}

_INVENTORY_SAFE_FIELDS = {
    "users": ("display_name", "user_principal_name", "mail_nickname"),
    "groups": ("display_name",),
    "applications": ("display_name",),
    "administrative_units": ("display_name",),
    "resource_groups": ("name", "location"),
    "key_vaults": ("name", "location", "resource_group_name", "sku_name"),
    "storage_accounts": (
        "name", "location", "resource_group_name", "account_tier",
        "account_replication_type",
    ),
    "virtual_machines": (
        "name", "location", "resource_group_name", "os_type", "vm_size",
        "admin_username",
    ),
    "logic_apps": ("name", "location", "resource_group_name"),
    "automation_accounts": ("name", "location", "resource_group_name"),
    "function_apps": ("name", "location", "resource_group_name", "os_type"),
    "app_services": ("name", "location", "resource_group_name", "os_type"),
    "cosmos_dbs": (
        "name", "location", "resource_group_name", "kind", "offer_type",
        "database_name", "container_name", "partition_key_path",
    ),
}

_ASSIGNMENT_TYPES = (
    EntraRoleAssignment,
    AzureRbacAssignment,
    ApiPermission,
    GroupMembership,
    GroupOwnership,
    AppOwnership,
    AuMembership,
)


@dataclass
class EnvironmentProjection:
    """The three environment panels plus safe details hidden by aggregation."""

    identity: GraphPanel
    resources: GraphPanel
    assignments: GraphPanel
    inventory: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    assignment_details: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def panels(self) -> List[GraphPanel]:
        return [self.identity, self.resources, self.assignments]


def build_environment_graphs(
    model: DeploymentModel, resolver: Optional[NameResolver] = None,
) -> EnvironmentProjection:
    """Build and validate all environment-level report projections."""

    resolver = resolver or NameResolver()
    identity = build_identity_panel(model)
    resources = build_resource_panel(model)
    assignments, assignment_details = build_assignment_panel(model, resolver)
    return EnvironmentProjection(
        identity=identity,
        resources=resources,
        assignments=assignments,
        inventory=build_safe_inventory(model),
        assignment_details=assignment_details,
    )


def build_identity_panel(model: DeploymentModel) -> GraphPanel:
    groups = set(model.groups)
    apps = set(model.applications)
    member_count: Dict[str, int] = {}
    nesting: List[Tuple[str, str, Any]] = []
    au_user_count: Dict[str, int] = {}
    au_groups: Dict[str, List[Tuple[str, Any]]] = {}
    group_user_owner_count: Dict[str, int] = {}
    group_sp_owners: List[Tuple[str, str, Any]] = []
    app_user_owner_count: Dict[str, int] = {}
    app_sp_owners: List[Tuple[str, str, Any]] = []

    for primitive in model.primitives:
        if isinstance(primitive, GroupMembership):
            member_count[primitive.group_ref] = member_count.get(primitive.group_ref, 0) + 1
            if primitive.principal_type == "group":
                nesting.append((primitive.principal_ref, primitive.group_ref, primitive))
        elif isinstance(primitive, AuMembership):
            if primitive.principal_type == "group" or primitive.principal_ref in groups:
                au_groups.setdefault(primitive.au_ref, []).append(
                    (primitive.principal_ref, primitive)
                )
            else:
                au_user_count[primitive.au_ref] = au_user_count.get(primitive.au_ref, 0) + 1
        elif isinstance(primitive, GroupOwnership):
            if primitive.principal_type == "service_principal" or primitive.principal_ref in apps:
                group_sp_owners.append((primitive.principal_ref, primitive.group_ref, primitive))
            else:
                group_user_owner_count[primitive.group_ref] = (
                    group_user_owner_count.get(primitive.group_ref, 0) + 1
                )
        elif isinstance(primitive, AppOwnership):
            if primitive.principal_type == "service_principal" or primitive.principal_ref in apps:
                app_sp_owners.append((primitive.principal_ref, primitive.app_ref, primitive))
            else:
                app_user_owner_count[primitive.app_ref] = (
                    app_user_owner_count.get(primitive.app_ref, 0) + 1
                )

    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    organization = GraphNode(
        id=typed_id("Organization", "lab"), type="Organization", label="Organization",
        properties={
            "users": len(model.users),
            "groups": len(model.groups),
            "service_principals": len(model.applications),
            "administrative_units": len(model.administrative_units),
        },
    )
    nodes.append(organization)

    for au_ref in model.administrative_units:
        node = GraphNode(
            id=typed_id("AdministrativeUnit", au_ref),
            type="AdministrativeUnit",
            label=au_ref,
            properties={
                "user_count": au_user_count.get(au_ref, 0),
                "group_count": len(au_groups.get(au_ref, [])),
            },
        )
        nodes.append(node)
        edges.append(GraphEdge(
            id=edge_id("identity", "CONTAINS", f"org-au-{au_ref}"),
            type="CONTAINS", source=organization.id, target=node.id,
        ))

    show_groups = len(model.groups) <= GROUP_NODE_CAP
    if show_groups:
        nested_children = {child for child, _parent, _primitive in nesting}
        for group_ref in model.groups:
            nodes.append(GraphNode(
                id=typed_id("Group", group_ref), type="Group", label=group_ref,
                properties={
                    "member_count": member_count.get(group_ref, 0),
                    "owner_count": group_user_owner_count.get(group_ref, 0),
                },
            ))
            if group_ref not in nested_children:
                edges.append(GraphEdge(
                    id=edge_id("identity", "CONTAINS", f"org-group-{group_ref}"),
                    type="CONTAINS", source=organization.id,
                    target=typed_id("Group", group_ref),
                ))
        for child, parent, primitive in nesting:
            if child in groups and parent in groups:
                edges.append(_identity_edge(
                    primitive, "MEMBER_OF", typed_id("Group", child),
                    typed_id("Group", parent),
                ))
        for au_ref, memberships in au_groups.items():
            if au_ref not in model.administrative_units:
                continue
            for group_ref, primitive in memberships:
                if group_ref in groups:
                    edges.append(GraphEdge(
                        id=edge_id("identity", "CONTAINS", primitive.key),
                        type="CONTAINS",
                        source=typed_id("AdministrativeUnit", au_ref),
                        target=typed_id("Group", group_ref),
                        properties={"count": 1},
                    ))
    elif model.groups:
        summary = GraphNode(
            id=typed_id("GroupSummary", "all"), type="GroupSummary", label="Groups",
            properties={"count": len(model.groups), "members": sorted(model.groups)},
            aggregate=True,
        )
        nodes.append(summary)
        edges.append(GraphEdge(
            id=edge_id("identity", "CONTAINS", "org-groups"), type="CONTAINS",
            source=organization.id, target=summary.id, properties={"count": len(model.groups)},
        ))

    connected_apps = set()
    for owner, target, _primitive in app_sp_owners:
        connected_apps.update((owner, target))
    for owner, _target, _primitive in group_sp_owners:
        connected_apps.add(owner)
    drawn_apps = [ref for ref in model.applications if ref in connected_apps]
    if len(drawn_apps) > APP_NODE_CAP:
        drawn_apps = []
    drawn = set(drawn_apps)
    for app_ref in drawn_apps:
        nodes.append(GraphNode(
            id=typed_id("ServicePrincipal", app_ref),
            type="ServicePrincipal", label=app_ref,
            properties={"owner_count": app_user_owner_count.get(app_ref, 0)},
        ))
    for owner, target, primitive in app_sp_owners:
        if owner in drawn and target in drawn:
            edges.append(_identity_edge(
                primitive, "OWNS", typed_id("ServicePrincipal", owner),
                typed_id("ServicePrincipal", target),
            ))
    if show_groups:
        for owner, target, primitive in group_sp_owners:
            if owner in drawn and target in groups:
                edges.append(_identity_edge(
                    primitive, "OWNS", typed_id("ServicePrincipal", owner),
                    typed_id("Group", target),
                ))

    hidden_apps = [ref for ref in model.applications if ref not in drawn]
    if hidden_apps:
        summary = GraphNode(
            id=typed_id("ServicePrincipalSummary", "other"),
            type="ServicePrincipalSummary",
            label="Other Service Principals" if drawn else "Service Principals",
            properties={"count": len(hidden_apps), "members": hidden_apps},
            aggregate=True,
        )
        nodes.append(summary)
        edges.append(GraphEdge(
            id=edge_id("identity", "CONTAINS", "org-service-principals"),
            type="CONTAINS", source=organization.id, target=summary.id,
            properties={"count": len(hidden_apps)},
        ))

    panel = GraphPanel(
        key="identity", title="Identity / Organization", ontology="identity",
        nodes=nodes, edges=edges,
        caption="Entra organization structure with high-volume identities summarized.",
    )
    apply_layered_layout(panel, direction="TB")
    validate_panel(panel, load_bundled_ontology("identity"))
    return panel


def build_resource_panel(model: DeploymentModel) -> GraphPanel:
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    subscription_ref = model.subscription_id or "current"
    subscription = GraphNode(
        id=typed_id("Subscription", subscription_ref), type="Subscription",
        label="Subscription",
        properties={"subscription_id": model.subscription_id} if model.subscription_id else {},
    )
    nodes.append(subscription)

    buckets: Dict[str, Dict[str, List[str]]] = {}
    for attr in _RESOURCE_TYPES:
        for ref, info in getattr(model, attr).items():
            rg_ref = (info or {}).get("resource_group_name") or "(unplaced)"
            buckets.setdefault(rg_ref, {}).setdefault(attr, []).append(ref)

    resource_groups = list(model.resource_groups)
    resource_groups.extend(rg for rg in buckets if rg not in model.resource_groups)
    for rg_ref in resource_groups:
        rg_info = model.resource_groups.get(rg_ref) or {}
        rg_node = GraphNode(
            id=typed_id("ResourceGroup", rg_ref), type="ResourceGroup", label=rg_ref,
            properties=safe_properties(rg_info, ("location",)),
        )
        nodes.append(rg_node)
        edges.append(GraphEdge(
            id=edge_id("resources", "CONTAINS", f"subscription-{rg_ref}"),
            type="CONTAINS", source=subscription.id, target=rg_node.id,
        ))
        for attr, refs in sorted(buckets.get(rg_ref, {}).items()):
            node_type, label = _RESOURCE_TYPES[attr]
            refs = sorted(refs)
            summary = GraphNode(
                id=typed_id(node_type, rg_ref), type=node_type, label=label,
                properties={"count": len(refs), "resources": refs}, aggregate=True,
            )
            nodes.append(summary)
            edges.append(GraphEdge(
                id=edge_id("resources", "CONTAINS", f"{rg_ref}-{attr}"),
                type="CONTAINS", source=rg_node.id, target=summary.id,
                properties={"count": len(refs)},
            ))

    panel = GraphPanel(
        key="resources", title="Azure Resources", ontology="resources",
        nodes=nodes, edges=edges,
        caption="Subscription and resource-group placement with resources grouped by type.",
    )
    apply_layered_layout(panel, direction="TB")
    validate_panel(panel, load_bundled_ontology("resources"))
    return panel


def build_assignment_panel(
    model: DeploymentModel, resolver: Optional[NameResolver] = None,
) -> Tuple[GraphPanel, List[Dict[str, Any]]]:
    resolver = resolver or NameResolver()
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    details: List[Dict[str, Any]] = []

    for primitive in model.primitives:
        if not isinstance(primitive, _ASSIGNMENT_TYPES):
            continue
        edge, new_nodes, detail = _project_assignment(model, primitive, resolver)
        for node in new_nodes:
            nodes.setdefault(node.id, node)
        edges.append(edge)
        details.append(detail)

    panel = GraphPanel(
        key="assignments", title="Assignments", ontology="assignments",
        nodes=list(nodes.values()), edges=edges,
        caption="Entra, Azure, API, membership, and ownership assignments.",
    )
    apply_layered_layout(panel, direction="LR", rank_spacing=330.0, node_spacing=190.0)
    validate_panel(panel, load_bundled_ontology("assignments"))
    return panel, details


def build_safe_inventory(model: DeploymentModel) -> Dict[str, List[Dict[str, Any]]]:
    inventory = {}
    for attr in model.ENTITY_MAPS:
        rows = []
        for ref, info in getattr(model, attr).items():
            row = {"ref": ref}
            row.update(safe_properties(info or {}, _INVENTORY_SAFE_FIELDS[attr]))
            rows.append(row)
        inventory[attr] = rows
    return inventory


def _identity_edge(primitive, edge_type, source, target):
    return GraphEdge(
        id=edge_id("identity", edge_type, primitive.key),
        type=edge_type, source=source, target=target,
        properties={"origin": primitive.origin},
    )


def _project_assignment(model, primitive, resolver):
    if isinstance(primitive, EntraRoleAssignment):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type)
        role_name = resolver.entra_role_name(primitive.role)
        if primitive.scope_app_ref:
            target = GraphNode(
                id=typed_id("Application", primitive.scope_app_ref), type="Application",
                label=primitive.scope_app_ref,
            )
        else:
            target = GraphNode(
                id=typed_id("EntraRole", primitive.role), type="EntraRole", label=role_name,
                properties={"role_id": primitive.role, "display_name": role_name},
            )
        props = _without_none({
            "origin": primitive.origin, "key": primitive.key, "role": role_name,
            "scope_app_ref": primitive.scope_app_ref,
        })
        return _assignment_result(primitive, "ASSIGNED_ENTRA_ROLE", source, target, props)

    if isinstance(primitive, AzureRbacAssignment):
        source = _principal_node(
            model, primitive.principal_ref, primitive.principal_type,
            source_type=primitive.mi_source_type,
        )
        target = _azure_scope_node(model, primitive)
        props = _without_none({
            "origin": primitive.origin, "key": primitive.key, "role": primitive.role,
            "scope_type": primitive.scope_type, "scope_ref": primitive.scope_ref,
            "data_plane": primitive.data_plane,
        })
        return _assignment_result(primitive, "ASSIGNED_AZURE_ROLE", source, target, props)

    if isinstance(primitive, ApiPermission):
        source = _principal_node(model, primitive.principal_ref, "service_principal")
        api_type = primitive.api_type or "graph"
        api_node_type = "ExchangeOnline" if api_type == "exchange" else "MicrosoftGraph"
        target = GraphNode(
            id=typed_id(api_node_type, api_type), type=api_node_type,
            label="Exchange Online" if api_type == "exchange" else "Microsoft Graph",
        )
        permission = resolver.api_permission_name(primitive.permission_id, api_type)
        props = {
            "origin": primitive.origin, "key": primitive.key,
            "permission": permission, "permission_id": primitive.permission_id,
            "api_type": api_type,
        }
        return _assignment_result(primitive, "GRANTED_API_PERMISSION", source, target, props)

    if isinstance(primitive, GroupMembership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type)
        target = _principal_node(model, primitive.group_ref, "group")
        props = {"origin": primitive.origin, "key": primitive.key}
        return _assignment_result(primitive, "MEMBER_OF", source, target, props)

    if isinstance(primitive, GroupOwnership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type)
        target = _principal_node(model, primitive.group_ref, "group")
        props = {"origin": primitive.origin, "key": primitive.key}
        return _assignment_result(primitive, "OWNS_GROUP", source, target, props)

    if isinstance(primitive, AppOwnership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type)
        target = GraphNode(
            id=typed_id("Application", primitive.app_ref), type="Application",
            label=primitive.app_ref,
        )
        props = {"origin": primitive.origin, "key": primitive.key}
        return _assignment_result(primitive, "OWNS_APPLICATION", source, target, props)

    if isinstance(primitive, AuMembership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type)
        target = GraphNode(
            id=typed_id("AdministrativeUnit", primitive.au_ref),
            type="AdministrativeUnit", label=primitive.au_ref,
        )
        props = {"origin": primitive.origin, "key": primitive.key}
        return _assignment_result(primitive, "MEMBER_OF_AU", source, target, props)

    raise TypeError(f"Unsupported assignment primitive: {type(primitive).__name__}")


def _assignment_result(primitive, edge_type, source, target, properties):
    edge = GraphEdge(
        id=edge_id("assignments", edge_type, primitive.key), type=edge_type,
        source=source.id, target=target.id, properties=properties,
        emphasis="spine" if primitive.origin == "attack_path" else "normal",
    )
    detail = {
        "key": primitive.key,
        "type": edge_type,
        "source": source.label,
        "target": target.label,
        **properties,
    }
    return edge, [source, target], detail


def _principal_node(model, ref, principal_type, source_type=None):
    node_type = {
        "user": "User",
        "group": "Group",
        "service_principal": "ServicePrincipal",
        "managed_identity": "ManagedIdentity",
    }.get(principal_type)
    if node_type is None:
        raise ValueError(f"Unsupported assignment principal_type '{principal_type}' for '{ref}'")
    properties = {"principal_type": principal_type}
    if node_type == "ManagedIdentity" and source_type:
        properties["source_type"] = source_type
    return GraphNode(id=typed_id(node_type, ref), type=node_type, label=ref,
                     properties=properties)


def _azure_scope_node(model, primitive):
    if primitive.scope_type == "subscription":
        ref = model.subscription_id or "current"
        properties = {"subscription_id": model.subscription_id} if model.subscription_id else {}
        return GraphNode(id=typed_id("Subscription", ref), type="Subscription",
                         label="Subscription", properties=properties)
    if primitive.scope_type == "resource_group":
        ref = primitive.scope_ref or "(unknown resource group)"
        info = model.resource_groups.get(ref) or {}
        return GraphNode(
            id=typed_id("ResourceGroup", ref), type="ResourceGroup", label=ref,
            properties=safe_properties(info, ("location",)),
        )

    resource_type = primitive.scope_resource_type or _resource_type_for_ref(
        model, primitive.scope_ref
    ) or "unknown"
    attr = _RESOURCE_TYPE_TO_ATTR.get(resource_type)
    info = getattr(model, attr, {}).get(primitive.scope_ref, {}) if attr else {}
    properties = _without_none({
        "resource_type": resource_type,
        "resource_group": info.get("resource_group_name"),
    })
    return GraphNode(
        id=typed_id("AzureResource", primitive.scope_ref or "(unknown resource)"),
        type="AzureResource", label=primitive.scope_ref or "Unknown resource",
        properties=properties,
    )


def _resource_type_for_ref(model, ref):
    for resource_type, attr in _RESOURCE_TYPE_TO_ATTR.items():
        if ref in getattr(model, attr):
            return resource_type
    return None


def _without_none(values):
    return {key: value for key, value in values.items() if value is not None}
