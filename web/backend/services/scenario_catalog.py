"""Loads and serves the scenario catalog."""
import json
from pathlib import Path
from ..config import settings
from ..models.scenarios import ScenarioCatalogEntry, ScenarioDetail


class ScenarioCatalog:
    def __init__(self):
        self._scenarios: list[ScenarioDetail] = []
        self._by_id: dict[str, ScenarioDetail] = {}
        self._load()

    def _load(self):
        catalog_path = settings.catalog_file
        with open(catalog_path, "r") as f:
            raw = json.load(f)
        for item in raw:
            detail = ScenarioDetail(**item)
            self._scenarios.append(detail)
            self._by_id[detail.id] = detail

    def list_all(self) -> list[ScenarioCatalogEntry]:
        return [
            ScenarioCatalogEntry(**s.model_dump(exclude={"long_description", "attack_path_key", "yaml_content"}))
            for s in self._scenarios
        ]

    def get_by_id(self, scenario_id: str) -> ScenarioDetail | None:
        return self._by_id.get(scenario_id)

    def get_many(self, scenario_ids: list[str]) -> list[ScenarioDetail]:
        return [self._by_id[sid] for sid in scenario_ids if sid in self._by_id]


catalog = ScenarioCatalog()
