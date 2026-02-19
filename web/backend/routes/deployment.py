"""Deployment routes."""
import asyncio
from fastapi import APIRouter, HTTPException
from ..models.deployment import DeployRequest, DeploymentStatus
from ..services.deployment_manager import deployment_manager

router = APIRouter(prefix="/api", tags=["deployment"])


@router.post("/deploy")
async def start_deploy(request: DeployRequest):
    try:
        # Fire and forget - deployment runs in background
        asyncio.create_task(
            deployment_manager.deploy(request.scenario_ids, request.tenant_config)
        )
        return {"message": "Deployment started", "scenario_ids": request.scenario_ids}
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.get("/status", response_model=DeploymentStatus)
async def get_status():
    return deployment_manager.get_status()


@router.post("/destroy")
async def start_destroy():
    try:
        asyncio.create_task(deployment_manager.destroy())
        return {"message": "Destroy started"}
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
