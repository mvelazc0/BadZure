"""Deployment state models."""
from enum import Enum
from pydantic import BaseModel
from typing import Optional
from .common import TenantConfig


class DeploymentState(str, Enum):
    IDLE = "idle"
    DEPLOYING = "deploying"
    DEPLOYED = "deployed"
    DESTROYING = "destroying"
    ERROR = "error"


class DeployRequest(BaseModel):
    scenario_ids: list[str]
    tenant_config: Optional[TenantConfig] = None


class DeploymentResource(BaseModel):
    type: str
    name: str
    provider: str


class DeploymentStatus(BaseModel):
    state: DeploymentState
    scenario_ids: list[str] = []
    resources: list[DeploymentResource] = []
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
