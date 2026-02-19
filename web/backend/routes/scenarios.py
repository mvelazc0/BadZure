"""Scenario catalog routes."""
from fastapi import APIRouter, HTTPException
from ..services.scenario_catalog import catalog
from ..models.scenarios import ScenarioCatalogEntry, ScenarioDetail

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


@router.get("", response_model=list[ScenarioCatalogEntry])
async def list_scenarios():
    return catalog.list_all()


@router.get("/{scenario_id}", response_model=ScenarioDetail)
async def get_scenario(scenario_id: str):
    scenario = catalog.get_by_id(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario
