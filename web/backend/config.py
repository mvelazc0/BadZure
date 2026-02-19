"""Application configuration with environment variable support."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Paths
    project_root: Path = Path(__file__).resolve().parent.parent.parent
    terraform_dir: Path = project_root / "terraform"
    badzure_script: Path = project_root / "BadZure.py"
    catalog_file: Path = Path(__file__).resolve().parent / "catalog" / "scenarios.json"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Deployment
    log_buffer_size: int = 1000
    status_poll_interval: int = 3

    # Auth - when running behind Azure Container Apps built-in auth,
    # user identity is passed via X-MS-CLIENT-PRINCIPAL headers
    auth_enabled: bool = os.getenv("AUTH_ENABLED", "false").lower() == "true"

    class Config:
        env_prefix = "BADZURE_WEB_"


settings = Settings()
