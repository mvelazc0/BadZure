"""Pure DeploymentModel projections for environment-level report graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.name_resolver import NameResolver
from src.primitives import (
    ApiPermission,
    AppCredential,
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

_MANAGED_IDENTITY_SOURCES = {
    "virtual_machines": "Virtual Machines",
    "logic_apps": "Logic Apps",
    "automation_accounts": "Automation Accounts",
    "function_apps": "Function Apps",
    "app_services": "App Services",
}

_RESOURCE_TYPES = {
    "key_vaults": ("KeyVaultSummary", "Key Vault", "Key Vaults"),
    "storage_accounts": ("StorageAccountSummary", "Storage Account", "Storage Accounts"),
    "virtual_machines": ("VirtualMachineSummary", "Virtual Machine", "Virtual Machines"),
    "logic_apps": ("LogicAppSummary", "Logic App", "Logic Apps"),
    "automation_accounts": (
        "AutomationAccountSummary", "Automation Account", "Automation Accounts",
    ),
    "function_apps": ("FunctionAppSummary", "Function App", "Function Apps"),
    "app_services": ("AppServiceSummary", "App Service", "App Services"),
    "cosmos_dbs": ("CosmosDBSummary", "Cosmos DB Account", "Cosmos DB Accounts"),
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

_ASSIGNMENT_FAMILY_ORDER = {
    "entra": 0,
    "azure-rbac": 1,
    "group-membership": 2,
    "group-ownership": 3,
    "application-ownership": 4,
    "graph": 5,
    "administrative-units": 6,
    "exchange": 7,
}


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
    """Describe the lab's identity inventory without drawing individual principals."""

    managed_identity_counts = {
        label: len(getattr(model, attr))
        for attr, label in _MANAGED_IDENTITY_SOURCES.items()
        if getattr(model, attr)
    }
    managed_identity_count = sum(managed_identity_counts.values())
    service_principal_count = len(model.applications) + managed_identity_count

    group_counts: Dict[str, Dict[str, int]] = {
        ref: {
            "user_members": 0, "group_members": 0, "service_principal_members": 0,
            "user_owners": 0, "service_principal_owners": 0,
        }
        for ref in model.groups
    }
    nesting: List[Tuple[str, str, Any]] = []
    au_counts: Dict[str, Dict[str, int]] = {
        ref: {"user_count": 0, "group_count": 0}
        for ref in model.administrative_units
    }
    user_activity = {
        "group_memberships": 0, "group_ownerships": 0,
        "application_ownerships": 0, "administrative_unit_memberships": 0,
    }
    sp_activity = {
        "group_memberships": 0, "group_ownerships": 0,
        "application_ownerships": 0, "credential_count": 0,
    }
    credentialed_apps = set()

    for primitive in model.primitives:
        if isinstance(primitive, GroupMembership):
            counts = group_counts.get(primitive.group_ref)
            if counts is None:
                continue
            if primitive.principal_type == "group":
                counts["group_members"] += 1
                nesting.append((primitive.principal_ref, primitive.group_ref, primitive))
            elif primitive.principal_type == "service_principal":
                counts["service_principal_members"] += 1
                sp_activity["group_memberships"] += 1
            else:
                counts["user_members"] += 1
                user_activity["group_memberships"] += 1
        elif isinstance(primitive, AuMembership):
            counts = au_counts.get(primitive.au_ref)
            if counts is None:
                continue
            if primitive.principal_type == "group":
                counts["group_count"] += 1
            else:
                counts["user_count"] += 1
                user_activity["administrative_unit_memberships"] += 1
        elif isinstance(primitive, GroupOwnership):
            counts = group_counts.get(primitive.group_ref)
            if counts is None:
                continue
            if primitive.principal_type == "service_principal":
                counts["service_principal_owners"] += 1
                sp_activity["group_ownerships"] += 1
            else:
                counts["user_owners"] += 1
                user_activity["group_ownerships"] += 1
        elif isinstance(primitive, AppOwnership):
            if primitive.principal_type == "service_principal":
                sp_activity["application_ownerships"] += 1
            else:
                user_activity["application_ownerships"] += 1
        elif isinstance(primitive, AppCredential):
            sp_activity["credential_count"] += 1
            credentialed_apps.add(primitive.app_ref)

    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    organization = GraphNode(
        id=typed_id("Organization", "lab"), type="Organization", label="Organization",
        properties={
            "users": len(model.users),
            "groups": len(model.groups),
            "service_principals": service_principal_count,
            "managed_identities": managed_identity_count,
            "administrative_units": len(model.administrative_units),
        },
    )
    nodes.append(organization)

    principal_catalog = GraphNode(
        id=typed_id("SecurityPrincipalCatalog", "all"),
        type="SecurityPrincipalCatalog", label="Security Principals",
        properties={"count": len(model.users) + service_principal_count + len(model.groups)},
        aggregate=True,
    )
    administrative_unit_catalog = GraphNode(
        id=typed_id("AdministrativeUnitCatalog", "all"),
        type="AdministrativeUnitCatalog", label="Administrative Units",
        properties={"count": len(model.administrative_units)},
        aggregate=True,
    )
    nodes.extend((principal_catalog, administrative_unit_catalog))
    edges.extend((
        GraphEdge(
            id=edge_id("identity", "HAS_PRINCIPAL_CATALOG", "all"),
            type="HAS_PRINCIPAL_CATALOG", source=organization.id,
            target=principal_catalog.id,
        ),
        GraphEdge(
            id=edge_id("identity", "HAS_ADMINISTRATIVE_UNITS", "all"),
            type="HAS_ADMINISTRATIVE_UNITS", source=organization.id,
            target=administrative_unit_catalog.id,
        ),
    ))

    category_specs = (
        ("users", "Users", len(model.users)),
        ("service-principals", "Service Principals", service_principal_count),
        ("groups", "Groups", len(model.groups)),
    )
    categories = {}
    for key, label, count in category_specs:
        category = GraphNode(
            id=typed_id("IdentityCategory", key), type="IdentityCategory", label=label,
            properties={"category": key, "count": count}, aggregate=True,
        )
        categories[key] = category
        nodes.append(category)
        edges.append(GraphEdge(
            id=edge_id("identity", "HAS_IDENTITY_CATEGORY", key),
            type="HAS_IDENTITY_CATEGORY", source=principal_catalog.id, target=category.id,
            properties={"count": count},
        ))

    user_summary = GraphNode(
        id=typed_id("IdentitySummary", "users"), type="IdentitySummary",
        label=f"{len(model.users)} users created",
        properties={"identity_type": "user", "count": len(model.users), **user_activity},
        aggregate=True,
    )
    nodes.append(user_summary)
    edges.append(GraphEdge(
        id=edge_id("identity", "SUMMARIZES", "users"), type="SUMMARIZES",
        source=categories["users"].id, target=user_summary.id,
        properties={"count": len(model.users)},
    ))

    sp_summary = GraphNode(
        id=typed_id("IdentitySummary", "service-principals"), type="IdentitySummary",
        label=f"{len(model.applications)} application service principals",
        properties={
            "identity_type": "service_principal", "count": len(model.applications),
            "credentialed_principals": len(credentialed_apps), **sp_activity,
        },
        aggregate=True,
    )
    nodes.append(sp_summary)
    edges.append(GraphEdge(
        id=edge_id("identity", "SUMMARIZES", "service-principals"), type="SUMMARIZES",
        source=categories["service-principals"].id, target=sp_summary.id,
        properties={"count": len(model.applications)},
    ))

    managed_identity_summary = GraphNode(
        id=typed_id("IdentitySummary", "managed-identities"), type="IdentitySummary",
        label=f"{managed_identity_count} managed identities",
        properties={
            "identity_type": "managed_identity",
            "count": managed_identity_count,
            "source_types": managed_identity_counts,
        },
        aggregate=True,
    )
    nodes.append(managed_identity_summary)
    edges.append(GraphEdge(
        id=edge_id("identity", "SUMMARIZES", "managed-identities"), type="SUMMARIZES",
        source=categories["service-principals"].id,
        target=managed_identity_summary.id,
        properties={"count": managed_identity_count},
    ))

    for au_ref in model.administrative_units:
        node = GraphNode(
            id=typed_id("AdministrativeUnit", au_ref),
            type="AdministrativeUnit",
            label=au_ref,
            properties=au_counts[au_ref],
        )
        nodes.append(node)
        edges.append(GraphEdge(
            id=edge_id("identity", "CONTAINS_IDENTITY", f"au-{au_ref}"),
            type="CONTAINS_IDENTITY",
            source=administrative_unit_catalog.id, target=node.id,
        ))

    show_groups = len(model.groups) <= GROUP_NODE_CAP
    if show_groups:
        for group_ref in model.groups:
            counts = group_counts[group_ref]
            nodes.append(GraphNode(
                id=typed_id("Group", group_ref), type="Group", label=group_ref,
                properties={
                    **counts,
                    "member_count": (
                        counts["user_members"] + counts["group_members"]
                        + counts["service_principal_members"]
                    ),
                    "owner_count": counts["user_owners"] + counts["service_principal_owners"],
                },
            ))
            edges.append(GraphEdge(
                id=edge_id("identity", "CONTAINS_IDENTITY", f"group-{group_ref}"),
                type="CONTAINS_IDENTITY", source=categories["groups"].id,
                target=typed_id("Group", group_ref),
            ))
        for child, parent, primitive in nesting:
            if child in model.groups and parent in model.groups:
                edges.append(_identity_edge(
                    primitive, "NESTED_IN", typed_id("Group", child),
                    typed_id("Group", parent),
                ))
    elif model.groups:
        summary = GraphNode(
            id=typed_id("IdentitySummary", "groups"), type="IdentitySummary",
            label=f"{len(model.groups)} groups created",
            properties={"count": len(model.groups), "members": sorted(model.groups)},
            aggregate=True,
        )
        nodes.append(summary)
        edges.append(GraphEdge(
            id=edge_id("identity", "SUMMARIZES", "groups"), type="SUMMARIZES",
            source=categories["groups"].id, target=summary.id,
            properties={"count": len(model.groups)},
        ))

    panel = GraphPanel(
        key="identity", title="Identity / Organization", ontology="identity",
        nodes=nodes, edges=edges,
        caption=(
            "High-level Entra identity inventory with user, application service-principal, "
            "and managed-identity summaries, group structure, and administrative-unit "
            "membership counts."
        ),
    )
    _apply_identity_layout(panel)
    validate_panel(panel, load_bundled_ontology("identity"))
    return panel


def _apply_identity_layout(panel: GraphPanel) -> None:
    """Keep principal and directory branches in separate coordinate regions."""

    by_id = {node.id: node for node in panel.nodes}
    positions = {
        typed_id("Organization", "lab"): (0.0, 0.0),
        typed_id("SecurityPrincipalCatalog", "all"): (-550.0, 260.0),
        typed_id("AdministrativeUnitCatalog", "all"): (750.0, 260.0),
        # Intentional left-to-right principal ordering.
        typed_id("IdentityCategory", "users"): (-1000.0, 540.0),
        typed_id("IdentityCategory", "service-principals"): (-600.0, 540.0),
        typed_id("IdentityCategory", "groups"): (-100.0, 540.0),
    }

    def place_children(node_type: str, center_x: float, y: float,
                       spacing: float = 220.0) -> None:
        children = sorted(node.id for node in panel.nodes if node.type == node_type)
        offset = (len(children) - 1) * spacing / 2.0
        for index, node_id in enumerate(children):
            positions[node_id] = (center_x + index * spacing - offset, y)

    place_children("AdministrativeUnit", 750.0, 540.0)

    group_ids = sorted(node.id for node in panel.nodes if node.type == "Group")
    group_columns = min(3, len(group_ids)) or 1
    group_spacing_x = 280.0
    group_spacing_y = 240.0
    group_center_x = 100.0
    for index, node_id in enumerate(group_ids):
        column = index % group_columns
        row = index // group_columns
        offset = (group_columns - 1) * group_spacing_x / 2.0
        positions[node_id] = (
            group_center_x + column * group_spacing_x - offset,
            840.0 + row * group_spacing_y,
        )

    summary_positions = {
        typed_id("IdentitySummary", "users"): (-1000.0, 840.0),
        typed_id("IdentitySummary", "service-principals"): (-700.0, 840.0),
        typed_id("IdentitySummary", "managed-identities"): (-500.0, 840.0),
        typed_id("IdentitySummary", "groups"): (-100.0, 840.0),
    }
    positions.update(
        (node_id, position) for node_id, position in summary_positions.items()
        if node_id in by_id
    )

    # Defensive fallback for future identity ontology nodes. They remain below the
    # principal branch instead of silently overlapping at the origin.
    unplaced = sorted(node_id for node_id in by_id if node_id not in positions)
    for index, node_id in enumerate(unplaced):
        positions[node_id] = (-550.0 + index * 220.0, 1120.0)

    for node_id, node in by_id.items():
        node.position = positions[node_id]
    panel.layout = "preset"


def build_resource_panel(model: DeploymentModel) -> GraphPanel:
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    subscription_ref = model.subscription_id or "current"
    buckets: Dict[str, Dict[str, List[str]]] = {}
    for attr in _RESOURCE_TYPES:
        for ref, info in getattr(model, attr).items():
            rg_ref = (info or {}).get("resource_group_name") or "(unplaced)"
            buckets.setdefault(rg_ref, {}).setdefault(attr, []).append(ref)

    resource_count = sum(
        len(getattr(model, attr)) for attr in _RESOURCE_TYPES
    )
    populated_types = [attr for attr in _RESOURCE_TYPES if getattr(model, attr)]
    regions = sorted({
        info.get("location")
        for info in model.resource_groups.values()
        if info and info.get("location")
    })
    subscription_properties = _without_none({
        "subscription_id": model.subscription_id,
        "resource_group_count": len(model.resource_groups),
        "resource_count": resource_count,
        "resource_type_count": len(populated_types),
        "region_count": len(regions),
        "regions": regions,
    })
    subscription = GraphNode(
        id=typed_id("Subscription", subscription_ref), type="Subscription",
        label="Subscription", properties=subscription_properties,
    )
    nodes.append(subscription)

    resource_groups = list(model.resource_groups)
    resource_groups.extend(
        rg for rg in buckets if rg not in model.resource_groups and rg != "(unplaced)"
    )
    for rg_ref in resource_groups:
        rg_info = model.resource_groups.get(rg_ref) or {}
        rg_buckets = buckets.get(rg_ref, {})
        rg_resource_count = sum(len(refs) for refs in rg_buckets.values())
        rg_node = GraphNode(
            id=typed_id("ResourceGroup", rg_ref), type="ResourceGroup", label=rg_ref,
            properties={
                **safe_properties(rg_info, ("location",)),
                "resource_count": rg_resource_count,
                "resource_type_count": len(rg_buckets),
                "resource_types": [
                    _RESOURCE_TYPES[attr][2] for attr in sorted(rg_buckets)
                ],
                "empty": rg_resource_count == 0,
            },
        )
        nodes.append(rg_node)
        edges.append(GraphEdge(
            id=edge_id("resources", "CONTAINS", f"subscription-{rg_ref}"),
            type="CONTAINS", source=subscription.id, target=rg_node.id,
        ))
        for attr, refs in sorted(rg_buckets.items()):
            node_type, singular, plural = _RESOURCE_TYPES[attr]
            refs = sorted(refs)
            label = singular if len(refs) == 1 else plural
            summary = GraphNode(
                id=typed_id(node_type, rg_ref), type=node_type,
                label=f"{label} · {len(refs)}",
                properties={"count": len(refs), "resources": refs}, aggregate=True,
            )
            nodes.append(summary)
            edges.append(GraphEdge(
                id=edge_id("resources", "CONTAINS", f"{rg_ref}-{attr}"),
                type="CONTAINS", source=rg_node.id, target=summary.id,
                properties={"count": len(refs)},
            ))

    unplaced_buckets = buckets.get("(unplaced)", {})
    if unplaced_buckets:
        unplaced_count = sum(len(refs) for refs in unplaced_buckets.values())
        unplaced = GraphNode(
            id=typed_id("UnplacedResources", "all"), type="UnplacedResources",
            label=f"Unplaced Resources · {unplaced_count}",
            properties={
                "resource_count": unplaced_count,
                "resource_type_count": len(unplaced_buckets),
                "resource_types": [
                    _RESOURCE_TYPES[attr][2] for attr in sorted(unplaced_buckets)
                ],
                "warning": "No resource group placement is available",
            },
            aggregate=True,
        )
        nodes.append(unplaced)
        edges.append(GraphEdge(
            id=edge_id("resources", "CONTAINS", "subscription-unplaced"),
            type="CONTAINS", source=subscription.id, target=unplaced.id,
            properties={"count": unplaced_count},
        ))
        for attr, refs in sorted(unplaced_buckets.items()):
            node_type, singular, plural = _RESOURCE_TYPES[attr]
            refs = sorted(refs)
            label = singular if len(refs) == 1 else plural
            summary = GraphNode(
                id=typed_id(node_type, "unplaced"), type=node_type,
                label=f"{label} · {len(refs)}",
                properties={"count": len(refs), "resources": refs}, aggregate=True,
            )
            nodes.append(summary)
            edges.append(GraphEdge(
                id=edge_id("resources", "CONTAINS", f"unplaced-{attr}"),
                type="CONTAINS", source=unplaced.id, target=summary.id,
                properties={"count": len(refs)},
            ))

    panel = GraphPanel(
        key="resources", title="Azure Resources", ontology="resources",
        nodes=nodes, edges=edges,
        caption=(
            "Subscription and resource-group placement with visible inventory totals, "
            "resources grouped by type, and missing placement called out explicitly."
        ),
    )
    _apply_resource_layout(panel)
    validate_panel(panel, load_bundled_ontology("resources"))
    return panel


def _apply_resource_layout(panel: GraphPanel) -> None:
    """Lay out each resource group's summaries as one non-overlapping cluster."""

    by_id = {node.id: node for node in panel.nodes}
    subscription = next(node for node in panel.nodes if node.type == "Subscription")
    containers = sorted(
        (node for node in panel.nodes
         if node.type in {"ResourceGroup", "UnplacedResources"}),
        key=lambda node: node.id,
    )
    children_by_container = {container.id: [] for container in containers}
    for edge in panel.edges:
        if edge.source in children_by_container and edge.target in by_id:
            children_by_container[edge.source].append(edge.target)
    for child_ids in children_by_container.values():
        child_ids.sort()

    child_spacing = 260.0
    cluster_gap = 220.0
    cluster_widths = {
        container.id: max(child_spacing, len(children_by_container[container.id]) * child_spacing)
        for container in containers
    }
    total_width = sum(cluster_widths.values()) + max(0, len(containers) - 1) * cluster_gap
    cursor = -total_width / 2.0
    positions = {}
    for container in containers:
        width = cluster_widths[container.id]
        center_x = cursor + width / 2.0
        positions[container.id] = (center_x, 280.0)
        children = children_by_container[container.id]
        child_offset = (len(children) - 1) * child_spacing / 2.0
        for index, child_id in enumerate(children):
            positions[child_id] = (
                center_x + index * child_spacing - child_offset,
                600.0,
            )
        cursor += width + cluster_gap

    if containers:
        first_x = positions[containers[0].id][0]
        last_x = positions[containers[-1].id][0]
        positions[subscription.id] = ((first_x + last_x) / 2.0, 0.0)
    else:
        positions[subscription.id] = (0.0, 0.0)

    # Future resource nodes remain visible and deterministic until assigned to a
    # specific resource-group cluster above.
    unplaced = sorted(node_id for node_id in by_id if node_id not in positions)
    for index, node_id in enumerate(unplaced):
        positions[node_id] = (index * child_spacing, 900.0)

    for node_id, node in by_id.items():
        node.position = positions[node_id]
    panel.layout = "preset"


def build_assignment_panel(
    model: DeploymentModel, resolver: Optional[NameResolver] = None,
) -> Tuple[GraphPanel, List[Dict[str, Any]]]:
    """Build a compact taxonomy of generated assignment variety.

    The canvas deliberately scales with families, roles/permissions, and principal
    types rather than raw assignments. ``details`` remains the lossless safe list
    used by the report table and can explain every aggregate.
    """
    resolver = resolver or NameResolver()
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    details: List[Dict[str, Any]] = []
    aggregates: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    for primitive in model.primitives:
        if not isinstance(primitive, _ASSIGNMENT_TYPES):
            continue
        _edge, _new_nodes, detail = _project_assignment(model, primitive, resolver)
        details.append(detail)
        family_key, family_label, kind_type, kind_label, principal_type = (
            _assignment_taxonomy(primitive, resolver)
        )
        key = (family_key, family_label, kind_type, kind_label, principal_type)
        aggregate = aggregates.setdefault(key, {
            "count": 0, "baseline_count": 0, "attack_path_count": 0,
            "principals": set(), "assignment_keys": [],
        })
        aggregate["count"] += 1
        origin_bucket = "attack_path_count" if primitive.origin == "attack_path" else "baseline_count"
        aggregate[origin_bucket] += 1
        aggregate["principals"].add(primitive.principal_ref)
        aggregate["assignment_keys"].append(primitive.key)

    if aggregates:
        catalog = GraphNode(
            id=typed_id("AssignmentCatalog", "all"), type="AssignmentCatalog",
            label="Generated Assignments", properties={"count": len(details)},
            aggregate=True,
        )
        nodes[catalog.id] = catalog

    family_totals: Dict[str, int] = {}
    kind_totals: Dict[Tuple[str, str, str], int] = {}
    for (family_key, _family_label, kind_type, kind_label, _principal_type), data in aggregates.items():
        family_totals[family_key] = family_totals.get(family_key, 0) + data["count"]
        kind_key = (family_key, kind_type, kind_label)
        kind_totals[kind_key] = kind_totals.get(kind_key, 0) + data["count"]

    for (family_key, family_label, kind_type, kind_label, principal_type), data in aggregates.items():
        family_id = typed_id("AssignmentFamily", family_key)
        if family_id not in nodes:
            nodes[family_id] = GraphNode(
                id=family_id, type="AssignmentFamily", label=family_label,
                properties={"count": family_totals[family_key]}, aggregate=True,
            )
            edges.append(GraphEdge(
                id=edge_id("assignments", "CONTAINS_FAMILY", family_key),
                type="CONTAINS_FAMILY", source=catalog.id, target=family_id,
                properties={"count": family_totals[family_key]},
            ))

        kind_key = (family_key, kind_type, kind_label)
        kind_id = typed_id(kind_type, f"{family_key}:{kind_label}")
        if kind_id not in nodes:
            nodes[kind_id] = GraphNode(
                id=kind_id, type=kind_type, label=kind_label,
                properties={
                    "assignment_family": family_label,
                    "count": kind_totals[kind_key],
                },
                aggregate=True,
            )
            edges.append(GraphEdge(
                id=edge_id("assignments", "CONTAINS_KIND", f"{family_key}:{kind_label}"),
                type="CONTAINS_KIND", source=family_id, target=kind_id,
                properties={"count": kind_totals[kind_key]},
            ))

        summary_id = typed_id(
            "PrincipalSummary", f"{family_key}:{kind_label}:{principal_type}",
        )
        principal_label = {
            "user": "Users", "group": "Groups",
            "service_principal": "Service Principals",
            "managed_identity": "Managed Identities",
        }[principal_type]
        nodes[summary_id] = GraphNode(
            id=summary_id, type="PrincipalSummary",
            label=f"{principal_label} · {data['count']}",
            properties={
                "principal_type": principal_type,
                "count": data["count"],
                "unique_principals": len(data["principals"]),
                "principals": sorted(data["principals"]),
                "baseline_count": data["baseline_count"],
                "attack_path_count": data["attack_path_count"],
                "assignment_keys": sorted(data["assignment_keys"]),
            },
            aggregate=True,
        )
        edges.append(GraphEdge(
            id=edge_id("assignments", "ASSIGNED_TO", summary_id),
            type="ASSIGNED_TO", source=kind_id, target=summary_id,
            properties={
                "count": data["count"],
                "baseline_count": data["baseline_count"],
                "attack_path_count": data["attack_path_count"],
            },
            emphasis="spine" if data["attack_path_count"] else "normal",
        ))

    panel = GraphPanel(
        key="assignments", title="Assignments", ontology="assignments",
        nodes=list(nodes.values()), edges=edges,
        caption=(
            "Generated assignment families, roles and permissions, summarized by "
            "principal type. Select an aggregate for counts and underlying references."
        ),
    )
    _apply_assignment_layout(panel)
    validate_panel(panel, load_bundled_ontology("assignments"))
    return panel, details


def _apply_assignment_layout(panel: GraphPanel) -> None:
    """Keep every assignment family and its descendants in one ordered column."""

    if not panel.nodes:
        panel.layout = "preset"
        return
    by_id = {node.id: node for node in panel.nodes}
    catalog = next(node for node in panel.nodes if node.type == "AssignmentCatalog")
    families = sorted(
        (node for node in panel.nodes if node.type == "AssignmentFamily"),
        key=lambda node: (
            _ASSIGNMENT_FAMILY_ORDER.get(node.id.split(":", 1)[1], 99), node.id,
        ),
    )
    kinds_by_family = {family.id: [] for family in families}
    summaries_by_kind: Dict[str, List[str]] = {}
    for edge in panel.edges:
        if edge.type == "CONTAINS_KIND" and edge.source in kinds_by_family:
            kinds_by_family[edge.source].append(edge.target)
        elif edge.type == "ASSIGNED_TO":
            summaries_by_kind.setdefault(edge.source, []).append(edge.target)
    for kind_ids in kinds_by_family.values():
        kind_ids.sort()
    for summary_ids in summaries_by_kind.values():
        summary_ids.sort()

    summary_spacing = 230.0
    kind_gap = 100.0
    family_gap = 220.0
    family_widths = {}
    kind_widths = {}
    for family in families:
        widths = []
        for kind_id in kinds_by_family[family.id]:
            width = max(summary_spacing, len(summaries_by_kind.get(kind_id, [])) * summary_spacing)
            kind_widths[kind_id] = width
            widths.append(width)
        family_widths[family.id] = max(
            summary_spacing,
            sum(widths) + max(0, len(widths) - 1) * kind_gap,
        )

    total_width = sum(family_widths.values()) + max(0, len(families) - 1) * family_gap
    cursor = -total_width / 2.0
    positions = {}
    for family in families:
        family_width = family_widths[family.id]
        family_center = cursor + family_width / 2.0
        positions[family.id] = (family_center, 280.0)
        kind_cursor = cursor
        for kind_id in kinds_by_family[family.id]:
            kind_width = kind_widths[kind_id]
            kind_center = kind_cursor + kind_width / 2.0
            positions[kind_id] = (kind_center, 590.0)
            summaries = summaries_by_kind.get(kind_id, [])
            offset = (len(summaries) - 1) * summary_spacing / 2.0
            for index, summary_id in enumerate(summaries):
                positions[summary_id] = (
                    kind_center + index * summary_spacing - offset,
                    900.0,
                )
            kind_cursor += kind_width + kind_gap
        cursor += family_width + family_gap

    if families:
        positions[catalog.id] = (
            (positions[families[0].id][0] + positions[families[-1].id][0]) / 2.0,
            0.0,
        )
    else:
        positions[catalog.id] = (0.0, 0.0)

    unplaced = sorted(node_id for node_id in by_id if node_id not in positions)
    for index, node_id in enumerate(unplaced):
        positions[node_id] = (index * summary_spacing, 1200.0)
    for node_id, node in by_id.items():
        node.position = positions[node_id]
    panel.layout = "preset"


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


def _assignment_taxonomy(primitive, resolver):
    """Return family, kind, and principal type for one assignment primitive."""

    if isinstance(primitive, EntraRoleAssignment):
        return (
            "entra", "Entra ID Roles", "Role", resolver.entra_role_name(primitive.role),
            primitive.principal_type,
        )
    if isinstance(primitive, AzureRbacAssignment):
        return (
            "azure-rbac", "Azure RBAC", "Role", primitive.role,
            primitive.principal_type,
        )
    if isinstance(primitive, ApiPermission):
        api_type = primitive.api_type or "graph"
        family = "Exchange Online" if api_type == "exchange" else "Microsoft Graph"
        return (
            api_type, family, "Permission",
            resolver.api_permission_name(primitive.permission_id, api_type),
            "service_principal",
        )
    if isinstance(primitive, GroupMembership):
        return (
            "group-membership", "Group Membership", "Relationship",
            "Member of group", primitive.principal_type,
        )
    if isinstance(primitive, GroupOwnership):
        return (
            "group-ownership", "Group Ownership", "Relationship",
            "Owns group", primitive.principal_type,
        )
    if isinstance(primitive, AppOwnership):
        return (
            "application-ownership", "Application Ownership", "Relationship",
            "Owns application", primitive.principal_type,
        )
    if isinstance(primitive, AuMembership):
        return (
            "administrative-units", "Administrative Units", "Relationship",
            "Member of administrative unit", primitive.principal_type,
        )
    raise TypeError(f"Unsupported assignment primitive: {type(primitive).__name__}")


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
