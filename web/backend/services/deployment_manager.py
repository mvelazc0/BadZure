"""Deployment state machine and subprocess orchestration."""
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import settings
from ..models.deployment import DeploymentState, DeploymentStatus, DeploymentResource
from ..services.log_broadcaster import broadcaster
from ..services.config_generator import generate_config
from ..services.scenario_catalog import catalog


class DeploymentManager:
    def __init__(self):
        self._state = DeploymentState.IDLE
        self._scenario_ids: list[str] = []
        self._started_at: Optional[str] = None
        self._completed_at: Optional[str] = None
        self._error_message: Optional[str] = None
        self._lock = asyncio.Lock()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._config_path: Optional[Path] = None
        # Check for existing deployment on startup
        self._detect_existing_deployment()

    def _detect_existing_deployment(self):
        tfstate = settings.terraform_dir / "terraform.tfstate"
        if tfstate.exists():
            try:
                with open(tfstate) as f:
                    state = json.load(f)
                resources = state.get("resources", [])
                if resources:
                    self._state = DeploymentState.DEPLOYED
            except (json.JSONDecodeError, OSError):
                pass

    def get_status(self) -> DeploymentStatus:
        resources = self._read_terraform_resources() if self._state == DeploymentState.DEPLOYED else []
        return DeploymentStatus(
            state=self._state,
            scenario_ids=self._scenario_ids,
            resources=resources,
            started_at=self._started_at,
            completed_at=self._completed_at,
            error_message=self._error_message,
        )

    def _read_terraform_resources(self) -> list[DeploymentResource]:
        tfstate = settings.terraform_dir / "terraform.tfstate"
        if not tfstate.exists():
            return []
        try:
            with open(tfstate) as f:
                state = json.load(f)
            resources = []
            for r in state.get("resources", []):
                rtype = r.get("type", "unknown")
                # Skip data sources and internal resources
                if r.get("mode") == "data":
                    continue
                for inst in r.get("instances", []):
                    name = inst.get("attributes", {}).get("display_name") or \
                           inst.get("attributes", {}).get("name") or \
                           r.get("name", "unknown")
                    resources.append(DeploymentResource(
                        type=rtype,
                        name=name,
                        provider=r.get("provider", "unknown"),
                    ))
            return resources
        except (json.JSONDecodeError, OSError):
            return []

    async def deploy(self, scenario_ids: list[str], tenant_config=None):
        async with self._lock:
            if self._state not in (DeploymentState.IDLE, DeploymentState.ERROR):
                raise RuntimeError(f"Cannot deploy in state {self._state}")

            self._state = DeploymentState.DEPLOYING
            self._scenario_ids = scenario_ids
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._completed_at = None
            self._error_message = None
            broadcaster.clear_buffer()

        # Generate config
        scenarios = catalog.get_many(scenario_ids)
        if not scenarios:
            await self._fail("No valid scenarios selected")
            return

        await broadcaster.broadcast("info", f"Generating config for {len(scenarios)} scenario(s)...", "system")
        self._config_path = generate_config(scenarios, tenant_config)
        await broadcaster.broadcast("info", f"Config written to {self._config_path}", "system")

        # Run BadZure as subprocess
        python = sys.executable
        badzure_script = str(settings.badzure_script)
        config_path = str(self._config_path)

        await broadcaster.broadcast("info", f"Starting BadZure build...", "badzure")

        try:
            self._process = await asyncio.create_subprocess_exec(
                python, badzure_script, "build", "--config", config_path, "--verbose",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(settings.project_root),
                env={**os.environ},
            )
            # Stream output
            await asyncio.gather(
                self._stream_output(self._process.stdout, "stdout"),
                self._stream_output(self._process.stderr, "stderr"),
            )
            returncode = await self._process.wait()

            if returncode == 0:
                self._state = DeploymentState.DEPLOYED
                self._completed_at = datetime.now(timezone.utc).isoformat()
                await broadcaster.broadcast("info", "Deployment completed successfully!", "system")
            else:
                await self._fail(f"BadZure exited with code {returncode}")
        except Exception as e:
            await self._fail(str(e))
        finally:
            self._process = None
            self._cleanup_config()

    async def destroy(self):
        async with self._lock:
            if self._state not in (DeploymentState.DEPLOYED, DeploymentState.ERROR):
                raise RuntimeError(f"Cannot destroy in state {self._state}")

            self._state = DeploymentState.DESTROYING
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._completed_at = None
            self._error_message = None
            broadcaster.clear_buffer()

        python = sys.executable
        badzure_script = str(settings.badzure_script)

        await broadcaster.broadcast("info", "Starting BadZure destroy...", "badzure")

        try:
            self._process = await asyncio.create_subprocess_exec(
                python, badzure_script, "destroy", "--verbose",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(settings.project_root),
                env={**os.environ},
            )
            await asyncio.gather(
                self._stream_output(self._process.stdout, "stdout"),
                self._stream_output(self._process.stderr, "stderr"),
            )
            returncode = await self._process.wait()

            if returncode == 0:
                self._state = DeploymentState.IDLE
                self._scenario_ids = []
                self._completed_at = datetime.now(timezone.utc).isoformat()
                await broadcaster.broadcast("info", "Destroy completed successfully!", "system")
            else:
                await self._fail(f"Destroy exited with code {returncode}")
        except Exception as e:
            await self._fail(str(e))
        finally:
            self._process = None

    async def _stream_output(self, stream, level: str):
        async for line in stream:
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                await broadcaster.broadcast(level, text, "terraform")

    async def _fail(self, message: str):
        self._state = DeploymentState.ERROR
        self._error_message = message
        self._completed_at = datetime.now(timezone.utc).isoformat()
        await broadcaster.broadcast("error", message, "system")

    def _cleanup_config(self):
        if self._config_path and self._config_path.exists():
            try:
                self._config_path.unlink()
            except OSError:
                pass
            self._config_path = None


deployment_manager = DeploymentManager()
