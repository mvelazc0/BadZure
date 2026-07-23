"""Attacker-action graph and narrative projections for BadZure paths."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from src import capabilities
from src.name_resolver import NameResolver
from src.primitives import (
    ApiPermission, AppOwnership, AzureRbacAssignment, EntraRoleAssignment,
)
from src.reporting.layouts import apply_spine_layout
from src.reporting.model import GraphEdge, GraphNode, GraphPanel
from src.reporting.ontology import load_bundled_ontology, validate_panel
from src.reporting.safety import edge_id, safe_properties, typed_id


_COMPUTE_TYPES = {
    "virtual_machines": "virtual_machine",
    "logic_apps": "logic_app",
    "automation_accounts": "automation_account",
    "function_apps": "function_app",
    "app_services": "app_service",
}
_DATA_TYPES = {
    "key_vaults": "key_vault",
    "storage_accounts": "storage_account",
    "cosmos_dbs": "cosmos_db",
}
_IDENTITY_TYPES = {
    "users": "user",
    "groups": "group",
    "applications": "service_principal",
}
_OBJECTIVE_ACTIONS = {
    "control_principal", "entra_role", "read_secrets", "read_blob",
    "read_cosmos", "read_mail", "code_execution",
}
_NARRATIVE_OBJECTIVE_FIELDS = (
    "name", "description", "capability", "target_ref", "role", "impact",
)
_NARRATIVE_INITIAL_ACCESS_FIELDS = (
    "method", "vector", "principal_ref", "target_ref", "target_type", "variant",
    "expose_to_internet", "credential", "mitre",
)
_NARRATIVE_METADATA_FIELDS = ("complexity", "tags", "mitre")
_NARRATIVE_STEP_FIELDS = (
    "name", "source_ref", "target_ref", "action", "mitre", "uses", "reads",
    "gains", "derived",
)


@dataclass
class AttackPathNarrative:
    name: str
    objective: Dict[str, Any]
    initial_access: Dict[str, Any]
    metadata: Dict[str, Any]
    reachability: Dict[str, Any]
    steps: List[Dict[str, Any]]
    summary: str
    posture_panel_key: str
    attack_panel_key: str


@dataclass
class AttackProjection:
    panel: GraphPanel
    narrative: AttackPathNarrative


def build_attack_projections(model, overlays: Sequence) -> List[AttackProjection]:
    return [AttackProjection(
        panel=build_attack_panel(model, overlay),
        narrative=build_path_narrative(overlay),
    ) for overlay in overlays]


def build_attack_panels(model, overlays: Sequence) -> List[GraphPanel]:
    return [build_attack_panel(model, overlay) for overlay in overlays]


def build_attack_panel(model, overlay) -> GraphPanel:
    """Project ordered path steps into attacker actions without inventing success."""

    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    aliases: Dict[str, GraphNode] = {}
    attacker = GraphNode(
        id=typed_id("Attacker", overlay.name), type="Attacker", label="Attacker",
    )
    nodes[attacker.id] = attacker
    current = attacker
    steps = overlay.steps or []

    for index, step in enumerate(steps):
        action = step.get("action") or "unspecified"
        if _is_terminal_objective_step(step, index, steps, overlay.objective or {}):
            continue

        source_ref = step.get("source_ref")
        source = aliases.get(source_ref) or (
            _node_for_ref(model, source_ref) if source_ref else current
        )
        if index == 0 and action in ("compromised_identity", "compromised_credential"):
            target = _identity_node(model, source_ref)
            _add_node(nodes, target)
            edges.append(_edge(overlay.name, index, "COMPROMISES", attacker, target, step))
            aliases[source_ref] = target
            current = target
            continue
        if index == 0 and action in (
            "exposed_rdp", "exposed_ssh", "vulnerable_web_app",
        ):
            target = _compute_node(model, source_ref)
            _add_node(nodes, target)
            edges.append(_edge(overlay.name, index, "EXPLOITS", attacker, target, step))
            aliases[source_ref] = target
            current = target
            continue

        _add_node(nodes, source)
        target_ref = step.get("target_ref")
        if action in (
            "app_credential_addition", "app_admin_credential_addition",
            "app_takeover", "traverse",
        ):
            current = _expand_application_credential_addition(
                model, overlay.name, index, step, source, nodes, edges,
            )
            if target_ref:
                aliases[target_ref] = current
        elif action in ("group_membership_modification", "group_takeover"):
            target = _identity_node(model, target_ref)
            _add_node(nodes, target)
            edges.append(_edge(
                overlay.name, index, "ADDS_SELF_TO_GROUP", source, target, step,
            ))
            aliases[target_ref] = target
            current = target
        elif action == "group_membership_inheritance":
            target = _identity_node(model, target_ref)
            _add_node(nodes, target)
            edges.append(_edge(
                overlay.name, index, "INHERITS_ACCESS", source, target, step,
            ))
            aliases[target_ref] = target
            current = target
        elif action == "resource_control":
            compute = _compute_node(model, target_ref)
            identity = _managed_identity_node(target_ref)
            _add_node(nodes, compute)
            _add_node(nodes, identity)
            edges.append(_edge(
                overlay.name, index, "EXECUTES_ON", source, compute, step, suffix="execute",
            ))
            edges.append(_edge(
                overlay.name, index, "USES_MANAGED_IDENTITY", compute, identity, step,
                suffix="managed-identity",
            ))
            aliases[target_ref] = identity
            current = identity
        elif action == "credential_loot":
            current = _expand_credential_loot(
                model, overlay.name, index, step, source, nodes, edges,
            )
            if target_ref:
                aliases[target_ref] = current
        elif action == "uses_managed_identity":
            target = _identity_node(model, target_ref, identity_type="managed_identity")
            _add_node(nodes, target)
            edges.append(_edge(
                overlay.name, index, "USES_MANAGED_IDENTITY", source, target, step,
            ))
            aliases[target_ref] = target
            current = target
        else:
            target = _node_for_ref(model, target_ref) if target_ref else GraphNode(
                id=typed_id("Session", f"{overlay.name}:{index}"), type="Session",
                label=step.get("name") or action,
                properties={"principal_ref": source_ref} if source_ref else {},
            )
            _add_node(nodes, target)
            edges.append(_edge(
                overlay.name, index, "PERFORMS_ACTION", source, target, step,
                extra={"original_action": action},
            ))
            if target_ref:
                aliases[target_ref] = target
            current = target

    objective = overlay.objective or {}
    reachability = overlay.reachability or {}
    status = reachability.get("status") or "unverified"
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
    terminal_source = _terminal_source(model, steps, aliases, current)
    terminal_source = _expand_objective_evidence(
        model, overlay, terminal_source, nodes, edges,
    )
    relationship = {
        "reached": "ACHIEVES",
        "blocked": "BLOCKED_AT",
        "invalid": "BLOCKED_AT",
        "unverified": "TARGETS",
    }.get(status, "TARGETS")
    terminal_properties = {}
    if relationship != "ACHIEVES":
        terminal_properties = _without_none({
            "status": status, "reason": reachability.get("reason"),
        })
    terminal_index = max(len(steps) - 1, 0)
    edges.append(_edge(
        overlay.name, terminal_index, relationship, terminal_source, objective_node,
        {"action": objective.get("capability") or relationship.lower()},
        extra=terminal_properties, suffix="objective",
    ))

    panel = GraphPanel(
        key=f"attack-{overlay.name}", title=f"Attack: {overlay.name}",
        ontology="attack", nodes=list(nodes.values()), edges=edges,
        caption="Ordered attacker actions from initial access to the path objective.",
    )
    apply_spine_layout(panel, rank_spacing=330.0, branch_spacing=190.0)
    validate_panel(panel, load_bundled_ontology("attack"))
    return panel


def _expand_application_credential_addition(
    model, path_name, index, step, source, nodes, edges,
):
    """Show the concrete add-credential and authenticate application takeover."""

    target_ref = step.get("target_ref")
    target = _identity_node(model, target_ref)
    authorization = _application_authorization(model, step)
    credential = GraphNode(
        id=typed_id("Credential", f"{path_name}:{index}:added"),
        type="Credential", label=f"Credential for {target_ref}",
        properties=_without_none({
            "credential_type": "password_or_certificate",
            "created_by_attacker": True,
            "target_ref": target_ref,
            **authorization,
        }),
    )
    _add_node(nodes, credential)
    _add_node(nodes, target)
    edges.append(_edge(
        path_name, index, "ADDS_APP_CREDENTIAL", source, credential, step,
        extra={"target_ref": target_ref, **authorization}, suffix="add-credential",
    ))
    edges.append(_edge(
        path_name, index, "AUTHENTICATES_AS", credential, target, step,
        extra={"target_ref": target_ref, **authorization}, suffix="authenticate",
    ))
    return target


def _application_authorization(model, step):
    primitive_by_key = {primitive.key: primitive for primitive in model.primitives}
    primitives = [primitive_by_key[key] for key in (step.get("uses") or [])
                  if key in primitive_by_key]
    ownership = next((p for p in primitives if isinstance(p, AppOwnership)), None)
    if ownership:
        return {"authorization_source": "application_ownership"}
    assignment = next(
        (p for p in primitives if isinstance(p, EntraRoleAssignment)), None,
    )
    if assignment:
        return {
            "authorization_source": "entra_role",
            "authorization_role": NameResolver().entra_role_name(assignment.role),
        }
    return {"authorization_source": "application_management"}


def build_path_narrative(overlay) -> AttackPathNarrative:
    objective = safe_properties(overlay.objective or {}, _NARRATIVE_OBJECTIVE_FIELDS)
    initial_access = safe_properties(
        overlay.initial_access or {}, _NARRATIVE_INITIAL_ACCESS_FIELDS,
    )
    metadata = safe_properties(overlay.metadata or {}, _NARRATIVE_METADATA_FIELDS)
    reachability = safe_properties(
        overlay.reachability or {}, ("status", "reason"),
    )
    steps = [safe_properties(step, _NARRATIVE_STEP_FIELDS) for step in overlay.steps or []]
    objective_name = objective.get("name") or objective.get("role") or overlay.name
    entry = initial_access.get("principal_ref") or initial_access.get("target_ref") \
        or "the initial-access point"
    summary = objective.get("description") or (
        f"Attack path from {entry} to {objective_name}."
    )
    return AttackPathNarrative(
        name=overlay.name,
        objective=objective,
        initial_access=initial_access,
        metadata=metadata,
        reachability=reachability,
        steps=steps,
        summary=summary,
        posture_panel_key=f"posture-{overlay.name}",
        attack_panel_key=f"attack-{overlay.name}",
    )


def _expand_credential_loot(model, path_name, index, step, source, nodes, edges):
    credential = GraphNode(
        id=typed_id("Credential", f"{path_name}:{index}"), type="Credential",
        label="Looted credential",
        properties=_without_none({
            "source_ref": (step.get("reads") or [None])[0],
        }),
    )
    _add_node(nodes, credential)
    reads = step.get("reads") or []
    if reads:
        for read_index, resource_ref in enumerate(reads):
            resource = _data_node(model, resource_ref)
            _add_node(nodes, resource)
            edges.append(_edge(
                path_name, index, "READS", source, resource, step,
                suffix=f"read-{read_index}",
            ))
            edges.append(_edge(
                path_name, index, "STEALS_CREDENTIAL", resource, credential, step,
                suffix=f"steal-{read_index}",
            ))
    else:
        edges.append(_edge(
            path_name, index, "STEALS_CREDENTIAL", source, credential, step,
            suffix="steal",
        ))

    target_ref = step.get("target_ref")
    if target_ref:
        target = _identity_node(model, target_ref)
        _add_node(nodes, target)
        edges.append(_edge(
            path_name, index, "AUTHENTICATES_AS", credential, target, step,
            suffix="authenticate",
        ))
        return target
    session = GraphNode(
        id=typed_id("Session", f"{path_name}:{index}"), type="Session",
        label="Authenticated session",
    )
    _add_node(nodes, session)
    edges.append(_edge(
        path_name, index, "AUTHENTICATES_AS", credential, session, step,
        suffix="authenticate",
    ))
    return session


def _expand_objective_evidence(model, overlay, source, nodes, edges):
    """Expand final read/MI actions compressed by reachability objective checks."""

    objective = overlay.objective or {}
    capability = objective.get("capability")
    target_ref = objective.get("target_ref")
    step_index = max(len(overlay.steps or []) - 1, 0)
    synthetic_step = {
        "action": capability,
        "source_ref": (overlay.steps or [{}])[-1].get("source_ref"),
        "target_ref": target_ref,
    }

    if capability in capabilities.READ_CAPABILITY_RESOURCE and target_ref:
        resource_type = capabilities.READ_CAPABILITY_RESOURCE[capability]
        reader_ref = synthetic_step.get("source_ref")
        matching_rbac = next((
            primitive for primitive in model.primitives
            if isinstance(primitive, AzureRbacAssignment)
            and primitive.principal_ref == reader_ref
            and capabilities.rbac_reads_resource(primitive.role, resource_type)
            and _scope_covers(model, primitive, target_ref, resource_type)
        ), None)
        if matching_rbac and matching_rbac.principal_type == "managed_identity" \
                and source.type == "ComputeResource":
            identity = _managed_identity_node(reader_ref)
            _add_node(nodes, identity)
            edges.append(_edge(
                overlay.name, step_index, "USES_MANAGED_IDENTITY", source, identity,
                synthetic_step, suffix="objective-managed-identity",
            ))
            source = identity
        target = _data_node(model, target_ref)
        _add_node(nodes, target)
        edges.append(_edge(
            overlay.name, step_index, "READS", source, target, synthetic_step,
            suffix="objective-read",
        ))
        return target

    if capability == "read_mail":
        reader_ref = synthetic_step.get("source_ref")
        has_mail_permission = any(
            isinstance(primitive, ApiPermission)
            and primitive.principal_ref == reader_ref
            and primitive.permission_id in capabilities.mail_permission_guids()
            for primitive in model.primitives
        )
        if has_mail_permission:
            target = GraphNode(
                id=typed_id("DataResource", target_ref or "mailboxes"),
                type="DataResource", label=target_ref or "Mailboxes",
                properties={
                    "ref": target_ref or "mailboxes", "resource_type": "mailbox",
                },
            )
            _add_node(nodes, target)
            edges.append(_edge(
                overlay.name, step_index, "READS", source, target, synthetic_step,
                suffix="objective-read-mail",
            ))
            return target
    return source


def _is_terminal_objective_step(step, index, steps, objective):
    if index != len(steps) - 1:
        return False
    action = step.get("action")
    return bool(step.get("gains")) or action == objective.get("capability") \
        or action in _OBJECTIVE_ACTIONS


def _terminal_source(model, steps, aliases, current):
    if steps:
        final_ref = steps[-1].get("source_ref")
        if final_ref in aliases:
            return aliases[final_ref]
        if final_ref:
            return _node_for_ref(model, final_ref)
    return current


def _scope_covers(model, primitive, target_ref, resource_type):
    if primitive.scope_type == "subscription":
        return True
    if primitive.scope_type == "resource":
        return primitive.scope_ref == target_ref and (
            not primitive.scope_resource_type
            or primitive.scope_resource_type == resource_type
        )
    if primitive.scope_type == "resource_group":
        attr = next((name for name, kind in _DATA_TYPES.items() if kind == resource_type), None)
        info = getattr(model, attr, {}).get(target_ref, {}) if attr else {}
        return info.get("resource_group_name") == primitive.scope_ref
    return False


def _edge(path_name, index, relationship, source, target, step, extra=None, suffix=None):
    properties = _without_none({
        "action": step.get("action"), "step": index + 1,
        "mitre": step.get("mitre"), "uses": step.get("uses"),
    })
    properties.update(extra or {})
    discriminator = f"{index}-{suffix or relationship.lower()}"
    return GraphEdge(
        id=edge_id(f"attack-{path_name}", relationship, discriminator),
        type=relationship, source=source.id, target=target.id,
        properties=properties, emphasis="spine",
    )


def _node_for_ref(model, ref):
    if ref is None:
        raise ValueError("Attack step needs a source or target reference")
    for attr, identity_type in _IDENTITY_TYPES.items():
        if ref in getattr(model, attr):
            return _identity_node(model, ref, identity_type)
    for attr in _COMPUTE_TYPES:
        if ref in getattr(model, attr):
            return _compute_node(model, ref)
    for attr in _DATA_TYPES:
        if ref in getattr(model, attr):
            return _data_node(model, ref)
    # Authored future steps may name ephemeral attacker/session identities that
    # are not deployable entities. Preserve them as an explicitly unknown identity.
    return _identity_node(model, ref, "unknown")


def _identity_node(model, ref, identity_type=None):
    if identity_type is None:
        identity_type = next((kind for attr, kind in _IDENTITY_TYPES.items()
                              if ref in getattr(model, attr)), "unknown")
    return GraphNode(
        id=typed_id("Identity", ref), type="Identity", label=ref,
        properties={"ref": ref, "identity_type": identity_type},
    )


def _managed_identity_node(resource_ref):
    ref = f"mi:{resource_ref}"
    return GraphNode(
        id=typed_id("Identity", ref), type="Identity", label=f"MI: {resource_ref}",
        properties={"ref": ref, "identity_type": "managed_identity", "controlled": True},
    )


def _compute_node(model, ref):
    resource_type = next((kind for attr, kind in _COMPUTE_TYPES.items()
                          if ref in getattr(model, attr)), "compute")
    return GraphNode(
        id=typed_id("ComputeResource", ref), type="ComputeResource", label=ref,
        properties={"ref": ref, "resource_type": resource_type},
    )


def _data_node(model, ref):
    resource_type = next((kind for attr, kind in _DATA_TYPES.items()
                          if ref in getattr(model, attr)), "data_resource")
    return GraphNode(
        id=typed_id("DataResource", ref), type="DataResource", label=ref,
        properties={"ref": ref, "resource_type": resource_type},
    )


def _add_node(nodes, node):
    existing = nodes.get(node.id)
    if existing:
        existing.properties.update(node.properties)
    else:
        nodes[node.id] = node


def _without_none(values):
    return {key: value for key, value in values.items() if value is not None}
