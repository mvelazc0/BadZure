"""Scenario catalog models."""
from pydantic import BaseModel
from typing import Optional


class ScenarioCatalogEntry(BaseModel):
    id: str
    name: str
    technique: str
    description: str
    tags: list[str]
    mode: str
    difficulty: str
    identity_type: str
    method: str
    requires_azure_resources: list[str]


class ScenarioDetail(ScenarioCatalogEntry):
    long_description: str
    attack_path_key: str
    yaml_content: str
