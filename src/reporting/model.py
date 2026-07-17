"""Small, renderer-independent contracts shared by every report graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class GraphNode:
    """One typed graph node.

    ``id`` is an internal identity, while ``label`` is presentation text.  They
    are deliberately separate so captions can change without breaking edges.
    """

    id: str
    type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    sensitive: bool = False
    aggregate: bool = False
    position: Optional[Tuple[float, float]] = None


@dataclass
class GraphEdge:
    """One typed, directed relationship between two node IDs."""

    id: str
    type: str
    source: str
    target: str
    properties: Dict[str, Any] = field(default_factory=dict)
    emphasis: str = "normal"  # normal | spine | offspine


@dataclass
class GraphPanel:
    """A complete graph panel before HTML rendering."""

    key: str
    title: str
    ontology: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    layout: str = "preset"
    caption: str = ""
    legend: Dict[str, str] = field(default_factory=dict)


@dataclass
class ReportModel:
    """All safe content needed to render a report.

    ``overview``, ``inventory``, and ``paths`` remain plain structures because
    their final presentation shape is introduced with the HTML phase.
    """

    title: str
    source_config: str
    lab_description: str = ""
    organization_description: str = ""
    overview: Dict[str, Any] = field(default_factory=dict)
    inventory: Dict[str, Any] = field(default_factory=dict)
    paths: List[Dict[str, Any]] = field(default_factory=list)
    panels: List[GraphPanel] = field(default_factory=list)
