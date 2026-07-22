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
    zigzag_height: float = 180.0,
) -> GraphPanel:
    """Lay out an emphasized path left-to-right in a deterministic zigzag.

    Alternating spine heights use the available canvas height without changing
    narrative direction. Non-spine nodes extend outward from their closest spine
    node, away from the main path. No browser-side physics is required.
    """

    spine_edges = _connect_spine_components(panel)
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

    ordered_spine = sorted(
        spine_positions,
        key=lambda node_id: (spine_positions[node_id][0], node_id),
    )
    for index, node_id in enumerate(ordered_spine):
        x, _y = spine_positions[node_id]
        spine_positions[node_id] = (
            x,
            -zigzag_height / 2.0 if index % 2 == 0 else zigzag_height / 2.0,
        )

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
            anchor_x, anchor_y = positions[anchor]
            outward = -1 if anchor_y <= 0 else 1
            positions[side_id] = (
                anchor_x,
                anchor_y + outward * index * branch_spacing,
            )
        else:
            trailing_x += rank_spacing
            placed_count = sum(node_id in positions for node_id in side_ids)
            positions[side_id] = (
                trailing_x,
                -zigzag_height / 2.0 if placed_count % 2 == 0 else zigzag_height / 2.0,
            )

    for node in panel.nodes:
        node.position = positions[node.id]
    panel.layout = "preset"
    return panel


def _connect_spine_components(panel: GraphPanel):
    """Promote the shortest selected relationships joining spine components."""

    spine_edges = [edge for edge in panel.edges if edge.emphasis == "spine"]
    if len(spine_edges) < 2:
        return spine_edges
    by_id = {edge.id: edge for edge in panel.edges}
    adjacency = defaultdict(list)
    for edge in sorted(panel.edges, key=lambda item: item.id):
        adjacency[edge.source].append((edge.target, edge.id))
        adjacency[edge.target].append((edge.source, edge.id))

    def components():
        graph = defaultdict(set)
        members = set()
        for edge in spine_edges:
            graph[edge.source].add(edge.target)
            graph[edge.target].add(edge.source)
            members.update((edge.source, edge.target))
        result = []
        unseen = set(members)
        while unseen:
            start = min(unseen)
            component = {start}
            queue = deque([start])
            unseen.remove(start)
            while queue:
                node_id = queue.popleft()
                for neighbor in sorted(graph[node_id]):
                    if neighbor in unseen:
                        unseen.remove(neighbor)
                        component.add(neighbor)
                        queue.append(neighbor)
            result.append(component)
        return result

    while True:
        parts = components()
        if len(parts) <= 1:
            break
        best_path = None
        for index, source_part in enumerate(parts):
            for target_part in parts[index + 1:]:
                queue = deque(sorted(source_part))
                previous = {node_id: None for node_id in source_part}
                previous_edge = {}
                destination = None
                while queue and destination is None:
                    node_id = queue.popleft()
                    for neighbor, edge_id in adjacency[node_id]:
                        if neighbor in previous:
                            continue
                        previous[neighbor] = node_id
                        previous_edge[neighbor] = edge_id
                        if neighbor in target_part:
                            destination = neighbor
                            break
                        queue.append(neighbor)
                if destination is None:
                    continue
                path = []
                cursor = destination
                while previous[cursor] is not None:
                    path.append(previous_edge[cursor])
                    cursor = previous[cursor]
                path.reverse()
                candidate = (len(path), tuple(path), path)
                if best_path is None or candidate[:2] < best_path[:2]:
                    best_path = candidate
        if best_path is None:
            break
        for edge_id in best_path[2]:
            edge = by_id[edge_id]
            if edge.emphasis != "inferred":
                edge.emphasis = "spine"
            if edge not in spine_edges:
                spine_edges.append(edge)
    return spine_edges
