"""FastAPI application entry point."""
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import settings
from .services.auth import AuthMiddleware
from .routes import scenarios, deployment, websocket

app = FastAPI(
    title="BadZure Web UI",
    description="Web interface for BadZure attack path simulation tool",
    version="1.0.0",
)

# CORS - allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth middleware (only enforced when AUTH_ENABLED=true)
app.add_middleware(AuthMiddleware)

# Routes
app.include_router(scenarios.router)
app.include_router(deployment.router)
app.include_router(websocket.router)


@app.get("/health")
async def health():
    return {"status": "ok"}


# Serve frontend static files in production
# The built React app is expected at web/frontend/dist/
frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
