"""Deterministic Python layouts for renderer-independent graph panels."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, Iterable, Mapping, Tuple

from src.reporting.model import GraphEdge, GraphNode, GraphPanel


def layered_positions(
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
    direction: str = "TB",
    rank_spacing: float = 260.0,
    node_spacing: float = 230.0,
) -> Dict[str, Tuple[float, float]]:
    """Place nodes by directed depth, with stable ordering inside each rank.

    Cycles and disconnected components are placed deterministically after the
    acyclic ranks.  This is intentionally simple: Cytoscape receives these as a
    preset layout and never introduces random physics.
    """

    node_ids = sorted(node.id for node in nodes)
    known = set(node_ids)
    outgoing = defaultdict(list)
    indegree = {node_id: 0 for node_id in node_ids}
    for edge in edges:
        if edge.source not in known or edge.target not in known:
            continue
        outgoing[edge.source].append(edge.target)
        indegree[edge.target] += 1
    for source in outgoing:
        outgoing[source].sort()

    rank = {node_id: 0 for node_id, degree in indegree.items() if degree == 0}
    queue = deque(sorted(rank))
    remaining_indegree = dict(indegree)
    while queue:
        source = queue.popleft()
        for target in outgoing[source]:
            rank[target] = max(rank.get(target, 0), rank[source] + 1)
            remaining_indegree[target] -= 1
            if remaining_indegree[target] == 0:
                queue.append(target)

    # Nodes left by cycles (or a component reachable only within a cycle) go in
    # stable successive ranks so they never overlap the traversed DAG.
    next_rank = max(rank.values(), default=-1) + 1
    for node_id in node_ids:
        if node_id not in rank:
            rank[node_id] = next_rank
            next_rank += 1

    by_rank = defaultdict(list)
    for node_id, depth in rank.items():
        by_rank[depth].append(node_id)

    positions = {}
    for depth in sorted(by_rank):
        members = sorted(by_rank[depth])
        offset = (len(members) - 1) * node_spacing / 2.0
        for index, node_id in enumerate(members):
            across = index * node_spacing - offset
            along = depth * rank_spacing
            positions[node_id] = (
                (across, along) if direction == "TB" else (along, across)
            )
    return positions


def apply_layered_layout(
    panel: GraphPanel,
    direction: str = "TB",
    rank_spacing: float = 260.0,
    node_spacing: float = 230.0,
) -> GraphPanel:
    """Assign preset positions to every node and return ``panel``."""

    positions = layered_positions(
        panel.nodes, panel.edges, direction=direction,
        rank_spacing=rank_spacing, node_spacing=node_spacing,
    )
    for node in panel.nodes:
        node.position = positions[node.id]
    panel.layout = "preset"
    return panel


def apply_spine_layout(
    panel: GraphPanel,
    rank_spacing: float = 360.0,
    branch_spacing: float = 220.0,
) -> GraphPanel:
    """Lay out an emphasized path left-to-right with side branches above/below.

    The spine itself uses the deterministic layered algorithm. Non-spine nodes
    anchor to the closest connected spine node; disconnected detail nodes trail
    after the spine. No browser-side physics is required.
    """

    spine_edges = [edge for edge in panel.edges if edge.emphasis == "spine"]
    spine_ids = {endpoint for edge in spine_edges for endpoint in (edge.source, edge.target)}
    by_id = {node.id: node for node in panel.nodes}

    if spine_ids:
        spine_positions = layered_positions(
            [by_id[node_id] for node_id in sorted(spine_ids)],
            spine_edges, direction="LR", rank_spacing=rank_spacing,
            node_spacing=branch_spacing,
        )
    else:
        spine_positions = {}

    positions = dict(spine_positions)
    side_ids = sorted(set(by_id) - set(positions))
    connections = defaultdict(list)
    for edge in panel.edges:
        connections[edge.source].append(edge.target)
        connections[edge.target].append(edge.source)

    branch_counts = defaultdict(int)
    trailing_x = max((position[0] for position in positions.values()), default=-rank_spacing)
    for side_id in side_ids:
        anchors = sorted(
            (neighbor for neighbor in connections[side_id] if neighbor in positions),
            key=lambda node_id: (positions[node_id][0], node_id),
        )
        if anchors:
            anchor = anchors[0]
            branch_counts[anchor] += 1
            index = branch_counts[anchor]
            sign = -1 if index % 2 else 1
            distance = ((index + 1) // 2) * branch_spacing
            positions[side_id] = (positions[anchor][0], sign * distance)
        else:
            trailing_x += rank_spacing
            positions[side_id] = (trailing_x, branch_spacing)

    for node in panel.nodes:
        node.position = positions[node.id]
    panel.layout = "preset"
    return panel
