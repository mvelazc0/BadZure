"""Defender-oriented, configuration-only posture projections per attack path."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Set, Tuple

from src import capabilities
from src.name_resolver import NameResolver
from src.primitives import (
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
    InitialAccessVector,
)
from src.reporting.layouts import apply_spine_layout
from src.reporting.model import GraphEdge, GraphNode, GraphPanel
from src.reporting.ontology import load_bundled_ontology, validate_panel
from src.reporting.safety import edge_id, typed_id


POSTURE_FORBIDDEN_VERBS = frozenset({
    "COMPROMISES", "EXPLOITS", "TAKES_OVER", "STEALS_CREDENTIAL",
    "AUTHENTICATES_AS", "ACHIEVES", "PERFORMS_ACTION",
})

_RESOURCE_NODE_TYPES = {
    "key_vaults": "KeyVault",
    "storage_accounts": "StorageAccount",
    "virtual_machines": "VirtualMachine",
    "logic_apps": "LogicApp",
    "automation_accounts": "AutomationAccount",
    "function_apps": "FunctionApp",
    "app_services": "AppService",
    "cosmos_dbs": "CosmosDB",
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
_ATTR_TO_RESOURCE_TYPE = {value: key for key, value in _RESOURCE_TYPE_TO_ATTR.items()}
_MI_SOURCE_TO_ATTR = {
    "vm": "virtual_machines",
    "logic_app": "logic_apps",
    "automation_account": "automation_accounts",
    "function_app": "function_apps",
    "app_service": "app_services",
}
_READ_CAPABILITY_TO_RESOURCE = dict(capabilities.READ_CAPABILITY_RESOURCE)


def build_posture_panels(
    model: DeploymentModel, overlays: Sequence,
    resolver: Optional[NameResolver] = None,
) -> List[GraphPanel]:
    resolver = resolver or NameResolver()
    return [build_posture_panel(model, overlay, resolver) for overlay in overlays]


def build_posture_panel(
    model: DeploymentModel, overlay, resolver: Optional[NameResolver] = None,
) -> GraphPanel:
    """Project one attack path into legitimate configuration relationships."""

    resolver = resolver or NameResolver()
    primitive_by_key = {primitive.key: primitive for primitive in model.primitives}
    selected_keys, spine_keys = select_posture_primitive_keys(
        model, overlay, resolver, primitive_by_key,
    )
    selected = [
        primitive for primitive in model.primitives if primitive.key in selected_keys
    ]
    credentials = {
        primitive.key: primitive for primitive in selected
        if isinstance(primitive, AppCredential)
    }
    # A spine data inject depends on its registered app credential even though
    # reachability records only the inject key in the derived step.
    for primitive in selected:
        if isinstance(primitive, DataInject) and primitive.key in spine_keys:
            if primitive.credential_ref in primitive_by_key:
                spine_keys.add(primitive.credential_ref)
                selected_keys.add(primitive.credential_ref)
                credential = primitive_by_key[primitive.credential_ref]
                if isinstance(credential, AppCredential):
                    credentials[credential.key] = credential

    nodes: Dict[str, GraphNode] = {}
    edges: Dict[str, GraphEdge] = {}

    entry_ref = (overlay.initial_access or {}).get("principal_ref")
    for primitive in model.primitives:
        if primitive.key not in selected_keys:
            continue
        emphasis = "spine" if primitive.key in spine_keys else "offspine"
        _project_primitive(
            model, primitive, resolver, credentials, nodes, edges, emphasis,
            entry_ref=entry_ref,
        )

    # A compromised-identity entry has no deployable primitive. Mark the node
    # without inventing an attack edge in the configuration graph.
    if entry_ref:
        entry_node = _entity_node(model, entry_ref, entry=True)
        if entry_node:
            _add_node(nodes, entry_node)

    _add_objective(model, overlay, resolver, nodes, edges, selected)

    panel = GraphPanel(
        key=f"posture-{overlay.name}",
        title=f"Posture: {overlay.name}", ontology="posture",
        nodes=list(nodes.values()), edges=list(edges.values()),
        caption="Legitimate configuration relationships that make this path possible.",
    )
    apply_spine_layout(panel)
    validate_panel(panel, load_bundled_ontology("posture"))
    forbidden = POSTURE_FORBIDDEN_VERBS & {edge.type for edge in panel.edges}
    if forbidden:
        raise ValueError(
            f"Posture panel '{panel.key}' contains attacker verbs: {sorted(forbidden)}"
        )
    return panel


def select_posture_primitive_keys(
    model: DeploymentModel, overlay, resolver: Optional[NameResolver] = None,
    primitive_by_key: Optional[Dict[str, object]] = None,
) -> Tuple[Set[str], Set[str]]:
    """Return (selected keys, emphasized spine keys) for one path."""

    resolver = resolver or NameResolver()
    primitive_by_key = primitive_by_key or {
        primitive.key: primitive for primitive in model.primitives
    }
    prefix = f"{overlay.name}__"
    selected = {key for key in primitive_by_key if key.startswith(prefix)}
    spine: Set[str] = set()

    for step in overlay.steps or []:
        for raw_key in step.get("uses") or []:
            key = _resolve_step_key(raw_key, overlay.name, primitive_by_key)
            if key:
                selected.add(key)
                spine.add(key)
        for resource_ref in step.get("reads") or []:
            for primitive in model.primitives:
                if isinstance(primitive, AzureRbacAssignment) \
                        and primitive.principal_ref == step.get("source_ref") \
                        and _rbac_reads_ref(model, primitive, resource_ref):
                    selected.add(primitive.key)
                    spine.add(primitive.key)

    # Resource footholds are always the path entry even though the derived first
    # step does not carry a `uses` key.
    for key in selected:
        if isinstance(primitive_by_key.get(key), InitialAccessVector):
            spine.add(key)

    objective_keys = _objective_primitive_keys(model, overlay, resolver)
    selected.update(objective_keys)
    spine.update(objective_keys)
    return selected, spine


def _project_primitive(
    model, primitive, resolver, credentials, nodes, edges, emphasis, entry_ref=None,
):
    if isinstance(primitive, GroupMembership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type,
                                 entry=primitive.principal_ref == entry_ref)
        target = _principal_node(model, primitive.group_ref, "group")
        _relationship(nodes, edges, primitive, "MEMBER_OF", source, target, emphasis)
        return
    if isinstance(primitive, GroupOwnership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type,
                                 entry=primitive.principal_ref == entry_ref)
        target = _principal_node(model, primitive.group_ref, "group")
        _relationship(nodes, edges, primitive, "OWNS", source, target, emphasis)
        return
    if isinstance(primitive, AppOwnership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type,
                                 entry=primitive.principal_ref == entry_ref)
        target = _principal_node(model, primitive.app_ref, "service_principal")
        _relationship(nodes, edges, primitive, "OWNS", source, target, emphasis)
        return
    if isinstance(primitive, AuMembership):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type,
                                 entry=primitive.principal_ref == entry_ref)
        target = GraphNode(
            id=typed_id("AdministrativeUnit", primitive.au_ref),
            type="AdministrativeUnit", label=primitive.au_ref,
        )
        _relationship(nodes, edges, primitive, "MEMBER_OF_AU", source, target, emphasis)
        return
    if isinstance(primitive, EntraRoleAssignment):
        source = _principal_node(model, primitive.principal_ref, primitive.principal_type,
                                 entry=primitive.principal_ref == entry_ref)
        role_name = resolver.entra_role_name(primitive.role)
        if primitive.scope_app_ref:
            target = _principal_node(model, primitive.scope_app_ref, "service_principal")
        else:
            target = GraphNode(
                id=typed_id("EntraRole", primitive.role), type="EntraRole", label=role_name,
                properties={"role_id": primitive.role, "display_name": role_name},
            )
        _relationship(
            nodes, edges, primitive, "HAS_ENTRA_ROLE", source, target, emphasis,
            _without_none({"role": role_name, "scope_app_ref": primitive.scope_app_ref}),
        )
        return
    if isinstance(primitive, AzureRbacAssignment):
        if primitive.principal_type == "managed_identity":
            source, compute = _managed_identity_nodes(model, primitive)
            _add_node(nodes, compute)
            _add_node(nodes, source)
            _add_edge(edges, GraphEdge(
                id=edge_id("posture", "RUNS_AS", f"{compute.id}-{source.id}"),
                type="RUNS_AS", source=compute.id, target=source.id,
                properties={"source_type": primitive.mi_source_type or "unknown"},
                emphasis=emphasis,
            ))
        else:
            source = _principal_node(
                model, primitive.principal_ref, primitive.principal_type,
                entry=primitive.principal_ref == entry_ref,
            )
        target = _scope_node(model, primitive)
        _relationship(
            nodes, edges, primitive, "HAS_AZURE_ROLE", source, target, emphasis,
            _without_none({
                "role": primitive.role, "scope_type": primitive.scope_type,
                "scope_ref": primitive.scope_ref, "data_plane": primitive.data_plane,
            }),
        )
        return
    if isinstance(primitive, ApiPermission):
        source = _principal_node(model, primitive.principal_ref, "service_principal",
                                 entry=primitive.principal_ref == entry_ref)
        api_type = primitive.api_type or "graph"
        api_node_type = "ExchangeOnline" if api_type == "exchange" else "MicrosoftGraph"
        target = GraphNode(
            id=typed_id(api_node_type, api_type), type=api_node_type,
            label="Exchange Online" if api_type == "exchange" else "Microsoft Graph",
        )
        _relationship(
            nodes, edges, primitive, "HAS_API_PERMISSION", source, target, emphasis,
            {
                "permission": resolver.api_permission_name(primitive.permission_id, api_type),
                "permission_id": primitive.permission_id, "api_type": api_type,
            },
        )
        return
    if isinstance(primitive, AppCredential):
        app = _principal_node(model, primitive.app_ref, "service_principal")
        credential = _credential_node(primitive.key, primitive.type, None, primitive.origin)
        _relationship(
            nodes, edges, primitive, "HAS_CREDENTIAL", app, credential, emphasis,
            {"credential_type": primitive.type},
        )
        return
    if isinstance(primitive, DataInject):
        resource = _resource_node(model, primitive.location_ref)
        credential_key = primitive.credential_ref \
            if primitive.credential_ref in credentials else f"data:{primitive.key}"
        credential_type = credentials[primitive.credential_ref].type \
            if primitive.credential_ref in credentials else None
        credential = _credential_node(
            credential_key, credential_type, primitive.material, primitive.origin,
        )
        _relationship(
            nodes, edges, primitive, "STORES", resource, credential, emphasis,
            _without_none({
                "location_type": primitive.location_type, "item_name": primitive.name,
                "material": primitive.material,
            }),
        )
        app_ref = primitive.source_ref
        if not app_ref and primitive.credential_ref in credentials:
            app_ref = credentials[primitive.credential_ref].app_ref
        if app_ref:
            app = _principal_node(model, app_ref, "service_principal")
            _add_node(nodes, credential)
            _add_node(nodes, app)
            _add_edge(edges, GraphEdge(
                id=edge_id("posture", "CREDENTIAL_FOR", primitive.key),
                type="CREDENTIAL_FOR", source=credential.id, target=app.id,
                properties={"origin": primitive.origin}, emphasis=emphasis,
            ))
        return
    if isinstance(primitive, InitialAccessVector):
        if primitive.expose_to_internet:
            internet = GraphNode(id=typed_id("Internet", "internet"), type="Internet",
                                 label="Internet")
            target = _resource_node(model, primitive.target_ref)
            _add_node(nodes, internet)
            _add_node(nodes, target)
            _add_edge(edges, GraphEdge(
                id=edge_id("posture", "CAN_REACH", primitive.key), type="CAN_REACH",
                source=internet.id, target=target.id,
                properties={"method": primitive.method, "exposure": "internet"},
                emphasis=emphasis,
            ))


def _add_objective(model, overlay, resolver, nodes, edges, selected):
    objective = overlay.objective or {}
    reachability = overlay.reachability or {}
    status = reachability.get("status", "unverified")
    objective_node = GraphNode(
        id=typed_id("Objective", overlay.name), type="Objective",
        label=objective.get("name") or objective.get("role") or overlay.name,
        properties=_without_none({
            "capability": objective.get("capability"), "status": status,
            "impact": objective.get("impact"), "reason": reachability.get("reason"),
            "target_ref": objective.get("target_ref"),
        }),
        sensitive=True,
    )
    _add_node(nodes, objective_node)
    source = _objective_source_node(model, overlay, resolver, selected)
    if source:
        _add_node(nodes, source)
        relationship = "SATISFIES_OBJECTIVE" if status == "reached" else "TARGETS_OBJECTIVE"
        relationship_properties = {"capability": objective.get("capability") or "unverified"}
        if relationship == "TARGETS_OBJECTIVE":
            relationship_properties["status"] = status
        _add_edge(edges, GraphEdge(
            id=edge_id("posture", relationship, overlay.name),
            type=relationship, source=source.id, target=objective_node.id,
            properties=relationship_properties,
            emphasis="spine",
        ))


def _objective_source_node(model, overlay, resolver, selected):
    objective = overlay.objective or {}
    capability = objective.get("capability")
    if capability == "entra_role":
        role = objective.get("role") or objective.get("name")
        try:
            role_ids = set(resolver.resolve_entra_role(role))
        except Exception:
            role_ids = set()
        match = next((p for p in selected if isinstance(p, EntraRoleAssignment)
                      and p.role in role_ids), None)
        if match:
            name = resolver.entra_role_name(match.role)
            return GraphNode(
                id=typed_id("EntraRole", match.role), type="EntraRole", label=name,
                properties={"role_id": match.role, "display_name": name},
            )
    if capability in _READ_CAPABILITY_TO_RESOURCE or capability == "code_execution":
        target_ref = objective.get("target_ref")
        return _resource_node(model, target_ref) if target_ref else None
    if capability == "read_mail":
        match = next((p for p in selected if isinstance(p, ApiPermission)), None)
        if match:
            api_type = match.api_type or "graph"
            node_type = "ExchangeOnline" if api_type == "exchange" else "MicrosoftGraph"
            return GraphNode(
                id=typed_id(node_type, api_type), type=node_type,
                label="Exchange Online" if api_type == "exchange" else "Microsoft Graph",
            )
    target_ref = objective.get("target_ref")
    if target_ref:
        return _entity_node(model, target_ref) or _resource_node(model, target_ref)
    final_ref = next((step.get("source_ref") for step in reversed(overlay.steps or [])
                      if step.get("source_ref")), None)
    return _entity_node(model, final_ref) if final_ref else None


def _objective_primitive_keys(model, overlay, resolver):
    objective = overlay.objective or {}
    capability = objective.get("capability")
    final_ref = next((step.get("source_ref") for step in reversed(overlay.steps or [])
                      if step.get("source_ref")), None)
    keys = set()
    if capability == "entra_role":
        role = objective.get("role") or objective.get("name")
        try:
            role_ids = set(resolver.resolve_entra_role(role))
        except Exception:
            role_ids = set()
        keys.update(p.key for p in model.primitives
                    if isinstance(p, EntraRoleAssignment) and p.role in role_ids
                    and (not final_ref or p.principal_ref == final_ref))
    elif capability == "read_mail":
        mail_ids = capabilities.mail_permission_guids()
        keys.update(p.key for p in model.primitives
                    if isinstance(p, ApiPermission) and p.permission_id in mail_ids
                    and (not final_ref or p.principal_ref == final_ref))
    elif capability in _READ_CAPABILITY_TO_RESOURCE:
        target_ref = objective.get("target_ref")
        keys.update(p.key for p in model.primitives
                    if isinstance(p, AzureRbacAssignment)
                    and (not final_ref or p.principal_ref == final_ref)
                    and _rbac_reads_ref(model, p, target_ref))
    elif capability == "code_execution":
        target_ref = objective.get("target_ref")
        resource_type = _resource_type_for_ref(model, target_ref)
        if resource_type:
            keys.update(p.key for p in model.primitives
                        if isinstance(p, AzureRbacAssignment)
                        and capabilities.rbac_controls_resource(p.role, resource_type)
                        and _scope_covers(model, p, target_ref, resource_type))
    return keys


def _resolve_step_key(raw_key, path_name, primitive_by_key):
    candidates = (raw_key, f"{path_name}__{raw_key}", f"baseline__{raw_key}")
    return next((candidate for candidate in candidates if candidate in primitive_by_key), None)


def _rbac_reads_ref(model, primitive, resource_ref):
    resource_type = _resource_type_for_ref(model, resource_ref)
    return bool(resource_type) and capabilities.rbac_reads_resource(
        primitive.role, resource_type,
    ) and _scope_covers(model, primitive, resource_ref, resource_type)


def _scope_covers(model, primitive, resource_ref, resource_type):
    if primitive.scope_type == "subscription":
        return True
    if primitive.scope_type == "resource":
        return primitive.scope_ref == resource_ref and (
            not primitive.scope_resource_type or primitive.scope_resource_type == resource_type
        )
    if primitive.scope_type == "resource_group":
        attr = _RESOURCE_TYPE_TO_ATTR.get(resource_type)
        info = getattr(model, attr, {}).get(resource_ref, {}) if attr else {}
        return info.get("resource_group_name") == primitive.scope_ref
    return False


def _relationship(nodes, edges, primitive, rel_type, source, target, emphasis, extra=None):
    _add_node(nodes, source)
    _add_node(nodes, target)
    properties = {"origin": primitive.origin, "key": primitive.key}
    properties.update(extra or {})
    _add_edge(edges, GraphEdge(
        id=edge_id("posture", rel_type, primitive.key), type=rel_type,
        source=source.id, target=target.id, properties=properties, emphasis=emphasis,
    ))


def _add_node(nodes, node):
    existing = nodes.get(node.id)
    if existing:
        existing.properties.update({k: v for k, v in node.properties.items() if v is not None})
        existing.sensitive = existing.sensitive or node.sensitive
    else:
        nodes[node.id] = node


def _add_edge(edges, edge):
    existing = edges.get(edge.id)
    if existing and edge.emphasis == "spine":
        existing.emphasis = "spine"
    elif not existing:
        edges[edge.id] = edge


def _principal_node(model, ref, principal_type, entry=False):
    node_type = {
        "user": "User", "group": "Group",
        "service_principal": "ServicePrincipal",
    }.get(principal_type)
    if not node_type:
        raise ValueError(f"Unsupported posture principal type '{principal_type}' for '{ref}'")
    properties = {"entry": True} if entry else {}
    return GraphNode(id=typed_id(node_type, ref), type=node_type, label=ref,
                     properties=properties)


def _entity_node(model, ref, entry=False):
    if ref in model.users:
        return _principal_node(model, ref, "user", entry)
    if ref in model.groups:
        return _principal_node(model, ref, "group", entry)
    if ref in model.applications:
        return _principal_node(model, ref, "service_principal", entry)
    return None


def _resource_node(model, ref):
    for attr, node_type in _RESOURCE_NODE_TYPES.items():
        if ref in getattr(model, attr):
            info = getattr(model, attr)[ref] or {}
            return GraphNode(
                id=typed_id(node_type, ref), type=node_type, label=ref,
                properties=_without_none({"resource_group": info.get("resource_group_name")}),
            )
    if ref in model.resource_groups:
        info = model.resource_groups[ref] or {}
        return GraphNode(
            id=typed_id("ResourceGroup", ref), type="ResourceGroup", label=ref,
            properties=_without_none({"location": info.get("location")}),
        )
    raise ValueError(f"Posture graph references unknown resource '{ref}'")


def _managed_identity_nodes(model, primitive):
    source_type = primitive.mi_source_type or _source_type_for_ref(model, primitive.principal_ref)
    attr = _MI_SOURCE_TO_ATTR.get(source_type)
    node_type = _RESOURCE_NODE_TYPES.get(attr)
    if not node_type:
        raise ValueError(
            f"Cannot model managed identity '{primitive.principal_ref}': "
            f"unknown source type '{source_type}'"
        )
    compute = _resource_node(model, primitive.principal_ref)
    identity = GraphNode(
        id=typed_id("ManagedIdentity", f"mi:{primitive.principal_ref}"),
        type="ManagedIdentity", label=f"MI: {primitive.principal_ref}",
        properties={"source_type": source_type},
    )
    return identity, compute


def _source_type_for_ref(model, ref):
    for source_type, attr in _MI_SOURCE_TO_ATTR.items():
        if ref in getattr(model, attr):
            return source_type
    return None


def _scope_node(model, primitive):
    if primitive.scope_type == "subscription":
        ref = model.subscription_id or "current"
        return GraphNode(
            id=typed_id("Subscription", ref), type="Subscription", label="Subscription",
            properties={"subscription_id": model.subscription_id} if model.subscription_id else {},
        )
    if primitive.scope_type == "resource_group":
        return _resource_node(model, primitive.scope_ref)
    return _resource_node(model, primitive.scope_ref)


def _credential_node(key, credential_type, material, origin):
    return GraphNode(
        id=typed_id("Credential", key), type="Credential", label="Credential",
        properties=_without_none({
            "credential_type": credential_type, "material": material, "origin": origin,
        }),
    )


def _resource_type_for_ref(model, ref):
    for attr in _RESOURCE_NODE_TYPES:
        if ref in getattr(model, attr):
            return _ATTR_TO_RESOURCE_TYPE[attr]
    return None


def _without_none(values):
    return {key: value for key, value in values.items() if value is not None}
