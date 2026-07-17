"""YAML ontology loading and pure graph-panel validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Mapping

import yaml

from src.reporting.model import GraphPanel


_ONTOLOGY_DIR = Path(__file__).resolve().parent / "ontologies"
BUNDLED_ONTOLOGIES = frozenset({"identity", "resources", "assignments", "posture", "attack"})
_EMPHASIS_VALUES = frozenset({"normal", "spine", "offspine"})


class OntologyDefinitionError(ValueError):
    """A bundled or supplied ontology YAML is structurally invalid."""


class GraphValidationError(ValueError):
    """A projected graph violates its selected ontology."""

    def __init__(self, panel_key: str, errors: Iterable[str]):
        self.panel_key = panel_key
        self.errors = list(errors)
        super().__init__(
            f"Panel '{panel_key}' violates its ontology ({len(self.errors)} problem(s)):\n"
            + "\n".join(f"  - {error}" for error in self.errors)
        )


@dataclass(frozen=True)
class NodeTypeDefinition:
    properties: FrozenSet[str]
    required_properties: FrozenSet[str]


@dataclass(frozen=True)
class EdgeTypeDefinition:
    source_types: FrozenSet[str]
    target_types: FrozenSet[str]
    properties: FrozenSet[str]
    required_properties: FrozenSet[str]


@dataclass(frozen=True)
class Ontology:
    name: str
    node_types: Mapping[str, NodeTypeDefinition]
    edge_types: Mapping[str, EdgeTypeDefinition]

    @classmethod
    def from_yaml(cls, path: Path) -> "Ontology":
        try:
            with Path(path).open("r", encoding="utf-8") as stream:
                raw = yaml.safe_load(stream)
        except (OSError, yaml.YAMLError) as exc:
            raise OntologyDefinitionError(f"Could not load ontology '{path}': {exc}") from exc

        if not isinstance(raw, dict):
            raise OntologyDefinitionError(f"Ontology '{path}' must be a YAML mapping")
        allowed_top = {"name", "node_types", "edge_types"}
        unknown_top = set(raw) - allowed_top
        if unknown_top:
            raise OntologyDefinitionError(
                f"Ontology '{path}' has unknown top-level key(s): {', '.join(sorted(unknown_top))}"
            )

        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise OntologyDefinitionError(f"Ontology '{path}' needs a non-empty string `name`")

        node_raw = raw.get("node_types")
        edge_raw = raw.get("edge_types")
        if not isinstance(node_raw, dict) or not node_raw:
            raise OntologyDefinitionError(f"Ontology '{name}' needs a non-empty `node_types` mapping")
        if not isinstance(edge_raw, dict):
            raise OntologyDefinitionError(f"Ontology '{name}' needs an `edge_types` mapping")

        nodes: Dict[str, NodeTypeDefinition] = {}
        for type_name, definition in node_raw.items():
            definition = _definition_mapping(name, "node", type_name, definition)
            _reject_unknown_definition_keys(
                name, "node", type_name, definition, {"properties", "required_properties"}
            )
            properties = _string_set(name, f"node '{type_name}'.properties",
                                     definition.get("properties", []))
            required = _string_set(name, f"node '{type_name}'.required_properties",
                                   definition.get("required_properties", []))
            _require_subset(name, f"node '{type_name}'", required, properties)
            nodes[str(type_name)] = NodeTypeDefinition(properties, required)

        edges: Dict[str, EdgeTypeDefinition] = {}
        for type_name, definition in edge_raw.items():
            definition = _definition_mapping(name, "edge", type_name, definition)
            _reject_unknown_definition_keys(
                name, "edge", type_name, definition,
                {"from", "to", "properties", "required_properties"},
            )
            source_types = _string_set(name, f"edge '{type_name}'.from", definition.get("from"))
            target_types = _string_set(name, f"edge '{type_name}'.to", definition.get("to"))
            if not source_types or not target_types:
                raise OntologyDefinitionError(
                    f"Ontology '{name}' edge '{type_name}' needs non-empty `from` and `to` lists"
                )
            unknown_nodes = (source_types | target_types) - set(nodes)
            if unknown_nodes:
                raise OntologyDefinitionError(
                    f"Ontology '{name}' edge '{type_name}' references unknown node type(s): "
                    + ", ".join(sorted(unknown_nodes))
                )
            properties = _string_set(name, f"edge '{type_name}'.properties",
                                     definition.get("properties", []))
            required = _string_set(name, f"edge '{type_name}'.required_properties",
                                   definition.get("required_properties", []))
            _require_subset(name, f"edge '{type_name}'", required, properties)
            edges[str(type_name)] = EdgeTypeDefinition(
                source_types, target_types, properties, required
            )

        return cls(name=name, node_types=nodes, edge_types=edges)


def bundled_ontology_path(name: str) -> Path:
    if name not in BUNDLED_ONTOLOGIES:
        raise OntologyDefinitionError(
            f"Unknown bundled ontology '{name}'. Valid: {', '.join(sorted(BUNDLED_ONTOLOGIES))}"
        )
    return _ONTOLOGY_DIR / f"{name}.yml"


def load_bundled_ontology(name: str) -> Ontology:
    ontology = Ontology.from_yaml(bundled_ontology_path(name))
    if ontology.name != name:
        raise OntologyDefinitionError(
            f"Bundled ontology file '{name}.yml' declares name '{ontology.name}'"
        )
    return ontology


def validate_panel(panel: GraphPanel, ontology: Ontology) -> None:
    """Validate ``panel`` completely, aggregating all discovered problems."""

    errors: List[str] = []
    if panel.ontology != ontology.name:
        errors.append(
            f"panel selects ontology '{panel.ontology}', validator received '{ontology.name}'"
        )

    node_by_id = {}
    for node in panel.nodes:
        if node.id in node_by_id:
            errors.append(f"duplicate node id '{node.id}'")
        else:
            node_by_id[node.id] = node
        definition = ontology.node_types.get(node.type)
        if definition is None:
            errors.append(f"node '{node.id}' has unknown type '{node.type}'")
            continue
        _validate_properties(
            errors, f"node '{node.id}'", node.properties,
            definition.properties, definition.required_properties,
        )

    edge_ids = set()
    for edge in panel.edges:
        if edge.id in edge_ids:
            errors.append(f"duplicate edge id '{edge.id}'")
        edge_ids.add(edge.id)
        definition = ontology.edge_types.get(edge.type)
        if definition is None:
            errors.append(f"edge '{edge.id}' has unknown type '{edge.type}'")
            continue
        source = node_by_id.get(edge.source)
        target = node_by_id.get(edge.target)
        if source is None:
            errors.append(f"edge '{edge.id}' has dangling source '{edge.source}'")
        elif source.type not in definition.source_types:
            errors.append(
                f"edge '{edge.id}' type '{edge.type}' cannot start at '{source.type}'"
            )
        if target is None:
            errors.append(f"edge '{edge.id}' has dangling target '{edge.target}'")
        elif target.type not in definition.target_types:
            errors.append(
                f"edge '{edge.id}' type '{edge.type}' cannot end at '{target.type}'"
            )
        if edge.emphasis not in _EMPHASIS_VALUES:
            errors.append(
                f"edge '{edge.id}' has invalid emphasis '{edge.emphasis}' "
                f"(valid: {', '.join(sorted(_EMPHASIS_VALUES))})"
            )
        _validate_properties(
            errors, f"edge '{edge.id}'", edge.properties,
            definition.properties, definition.required_properties,
        )

    if errors:
        raise GraphValidationError(panel.key, errors)


def _definition_mapping(ontology, kind, type_name, definition):
    if definition is None:
        return {}
    if not isinstance(definition, dict):
        raise OntologyDefinitionError(
            f"Ontology '{ontology}' {kind} '{type_name}' definition must be a mapping"
        )
    return definition


def _reject_unknown_definition_keys(ontology, kind, type_name, definition, allowed):
    unknown = set(definition) - allowed
    if unknown:
        raise OntologyDefinitionError(
            f"Ontology '{ontology}' {kind} '{type_name}' has unknown key(s): "
            + ", ".join(sorted(unknown))
        )


def _string_set(ontology: str, field: str, value) -> FrozenSet[str]:
    if value is None:
        value = []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise OntologyDefinitionError(
            f"Ontology '{ontology}' {field} must be a list of non-empty strings"
        )
    if len(value) != len(set(value)):
        raise OntologyDefinitionError(f"Ontology '{ontology}' {field} contains duplicates")
    return frozenset(value)


def _require_subset(ontology: str, subject: str, required, properties):
    missing = required - properties
    if missing:
        raise OntologyDefinitionError(
            f"Ontology '{ontology}' {subject} requires undeclared property/properties: "
            + ", ".join(sorted(missing))
        )


def _validate_properties(errors, subject, actual, allowed, required):
    actual_keys = set(actual)
    unknown = actual_keys - allowed
    missing = required - actual_keys
    if unknown:
        errors.append(f"{subject} has undeclared properties: {', '.join(sorted(unknown))}")
    if missing:
        errors.append(f"{subject} is missing required properties: {', '.join(sorted(missing))}")
