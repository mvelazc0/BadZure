"""Shared models."""
from pydantic import BaseModel
from typing import Optional


class TenantConfig(BaseModel):
    tenant_id: str
    domain: str
    subscription_id: str


class LogMessage(BaseModel):
    timestamp: str
    level: str  # "info", "error", "warning", "stdout", "stderr"
    message: str
    source: Optional[str] = None  # "terraform", "badzure", "system"
