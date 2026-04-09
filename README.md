# Docker Scout CVE API

Small Flask service that runs `docker scout cves` against container images and returns structured CVE data (and optional full SARIF) as JSON. When you pass `image=all`, it discovers images from Docker Hub using the same Hub API flow as the main `appsec_dockerscout` extension, then scans each reference.

## Prerequisites

- **Python 3.10+**
- **Docker Engine** (e.g. Docker Desktop on Windows) running and on your `PATH` (`docker version` works in a terminal).
- **Docker Scout** available in the Docker CLI (`docker scout version` or `docker scout --help`). Install or enable Scout per [Docker’s documentation](https://docs.docker.com/scout/) if needed.
- A **Docker Hub** account with a **personal access token (PAT)** (or password where still allowed) for API login and `docker login`.

## Install

From the **repository root** (`python-appsec_dockerscout`):

```bash
cd docker_scout_api
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux / macOS:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Alternatively, without a venv:

```bash
pip install -r docker_scout_api/requirements.txt
```

## Configure

Set these **environment variables** before starting the app.

| Variable | Required | Description |
|----------|----------|-------------|
| `DOCKER_USERNAME` | Yes | Docker Hub username. |
| `DOCKER_PASSWORD` | Yes* | Docker Hub password or PAT. |
| `DOCKER_PAT` | Yes* | Alternative to `DOCKER_PASSWORD`; either can be set. |
| `DOCKERHUB_ORG_FILTER` | No | Comma-separated Docker Hub **organization** names. When set, `image=all` only discovers repos under those orgs. |
| `PORT` | No | HTTP port (default `5000`). |
| `LOG_LEVEL` | No | Python log level, e.g. `DEBUG` or `INFO` (default `INFO`). |

\* At least one of `DOCKER_PASSWORD` or `DOCKER_PAT` must be set.

**Windows (PowerShell) example:**

```powershell
$env:DOCKER_USERNAME = "your_hub_username"
$env:DOCKER_PASSWORD = "your_personal_access_token"
$env:DOCKERHUB_ORG_FILTER = "mycompany,otherorg"   # optional
$env:PORT = "5000"                                 # optional
```

**Linux / macOS example:**

```bash
export DOCKER_USERNAME="your_hub_username"
export DOCKER_PASSWORD="your_personal_access_token"
export DOCKERHUB_ORG_FILTER="mycompany,otherorg"   # optional
export PORT=5000                                    # optional
```

## Run

From the **repository root** (so the `docker_scout_api` package imports correctly):

```bash
python -m docker_scout_api.app
```

The server listens on `0.0.0.0` and the port from `PORT` (default `5000`).

**Health check:**

```bash
curl http://127.0.0.1:5000/health
```

## API

### `GET /health`

Returns `{"status":"ok"}` if the process is up.

### `GET /scan`

Query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image` | `all` | `all` = discover all `org/repo:tag` from Docker Hub (for orgs you have access to, subject to `DOCKERHUB_ORG_FILTER`), then scan each. Any other value = a single image reference. |
| `include_sarif` | `1` | Set to `0`, `false`, or `no` to omit the full `sarif` object per image and only return the parsed `cves` list (smaller payloads). |

**Single image** examples:

- `myorg/myapp:1.2.3` — namespace `myorg`, repo `myapp`, tag `1.2.3`.
- `nginx:latest` — treated as `library/nginx:latest` (Docker Hub official images).

**Examples:**

```bash
# Default: discover all Hub images (can be slow; consider DOCKERHUB_ORG_FILTER)
curl "http://127.0.0.1:5000/scan"

# Explicit all
curl "http://127.0.0.1:5000/scan?image=all"

# One image
curl "http://127.0.0.1:5000/scan?image=nginx:latest"

# Parsed CVEs only (no embedded full SARIF document)
curl "http://127.0.0.1:5000/scan?image=nginx:latest&include_sarif=0"
```

**Successful response shape (summary):**

```json
{
  "count": 1,
  "images": [
    {
      "image": "library/nginx:latest",
      "success": true,
      "returncode": 0,
      "stderr": null,
      "tool_driver_full_name": "Docker Scout",
      "cves": [ { "rule_id": "...", "severity": "...", ... } ],
      "sarif": { "$schema": "...", "runs": [ ... ] }
    }
  ]
}
```

On errors you may get HTTP `400` (bad `image` value), `502` (Docker Hub API failure), or `503` (missing credentials, `docker login` failure, etc.) with an `error` field in the JSON body.

## Behavior notes

- **`image=all`** calls the Docker Hub API to list organizations, Scout-active repositories (`status == 1`), and tags, then runs `docker scout cves` for each `org/repo:tag`. Large accounts can produce many scans and take a long time.
- **`docker login`** runs once per `/scan` request (same credentials as Hub), so the engine can pull images for Scout when needed.
- Scans use the same CLI pattern as `appsec_dockerscout`: `docker scout cves --format sarif registry://org/repo:tag`.
- This API does **not** send data to Dynatrace; it only returns JSON to the client.

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| `docker login failed` | `DOCKER_USERNAME` / `DOCKER_PASSWORD` (or `DOCKER_PAT`), network, and Hub token scopes. |
| `docker not found` | Docker installed and `docker` on `PATH`; restart terminal after installing Docker Desktop. |
| `docker scout not found` | Scout CLI installed/enabled for your Docker version. |
| Empty discovery for `image=all` | Orgs/repos may have no Scout-active repos; optional `DOCKERHUB_ORG_FILTER` might be too narrow; Hub token must see those namespaces. |
| Timeout on scans | Very large images can exceed the default 600s Scout timeout (see `scout_cli.py` if you need to adjust). |
