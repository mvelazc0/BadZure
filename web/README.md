# BadZure Web UI

Web interface for BadZure attack path simulation tool. Browse a catalog of 22 hardcoded attack path scenarios, select which ones to deploy, watch real-time Terraform logs, and manage deployments.

## Architecture

- **Backend**: FastAPI (Python) with WebSocket log streaming
- **Frontend**: React + Vite + TypeScript + Tailwind CSS
- **Auth**: Azure Container Apps built-in Entra ID authentication
- **Deployment target**: Azure Container Apps (Docker container)

## Local Development

### Prerequisites

- Python 3.11+
- Node.js 20+
- Terraform CLI
- Azure CLI (authenticated)

### Backend

```bash
cd web/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd web/frontend
npm install
npm run dev
```

The frontend dev server runs on `http://localhost:5173` and proxies `/api` and `/ws` requests to the backend.

## Docker Build

```bash
# From repo root
docker build -f web/Dockerfile -t badzure-web .
docker run -p 8000:8000 -e AUTH_ENABLED=false badzure-web
```

## Azure Container Apps Deployment

1. Build and push the Docker image to Azure Container Registry
2. Create a Container App with the image
3. Enable built-in Entra ID authentication on the Container App
4. Set `AUTH_ENABLED=true` environment variable

When Entra ID auth is enabled, user identity is passed via `X-MS-CLIENT-PRINCIPAL` headers by the platform.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/scenarios` | List all attack path scenarios |
| GET | `/api/scenarios/{id}` | Scenario detail with YAML content |
| POST | `/api/deploy` | Start deployment |
| GET | `/api/status` | Current deployment state + resources |
| POST | `/api/destroy` | Start destroy |
| WS | `/ws/logs` | Real-time log stream |
| GET | `/health` | Health check |
