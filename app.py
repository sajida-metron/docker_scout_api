"""
Flask API: scan container images with Docker Scout and return CVEs as JSON.

Environment:
  DOCKER_USERNAME / DOCKER_PASSWORD — Docker Hub (API discovery + docker login).
  DOCKERHUB_ORG_FILTER — optional comma-separated org names when image=all.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

from docker_scout_api.hub import DockerHubClient, DockerHubClientError
from docker_scout_api.image_spec import parse_image_spec
from docker_scout_api.models import ImageRef
from docker_scout_api.sarif import parse_sarif
from docker_scout_api.scout_cli import docker_login, docker_scout_cves

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = Flask(__name__)


def _hub_creds() -> tuple[str, str]:
    user = os.environ.get("DOCKER_USERNAME", "").strip()
    password = os.environ.get("DOCKER_PASSWORD", os.environ.get("DOCKER_PAT", "")).strip()
    if not user or not password:
        raise RuntimeError(
            "Set DOCKER_USERNAME and DOCKER_PASSWORD (or DOCKER_PAT) for registry access."
        )
    return user, password


def _org_filter_from_env() -> Optional[List[str]]:
    raw = os.environ.get("DOCKERHUB_ORG_FILTER", "").strip()
    if not raw:
        return None
    return [part.strip() for part in raw.split(",") if part.strip()]


def _discover_all_images() -> List[ImageRef]:
    user, password = _hub_creds()
    hub = DockerHubClient(username=user, password=password)
    hub.login()
    return hub.discover_images(org_filter=_org_filter_from_env())


def _ensure_docker_logged_in() -> None:
    user, password = _hub_creds()
    result = docker_login(user, password)
    if not result.success:
        raise RuntimeError(f"docker login failed: {result.stderr}")


def _scan_one(ref: ImageRef) -> Dict[str, Any]:
    scout = docker_scout_cves(ref)
    row: Dict[str, Any] = {
        "image": ref.full_name,
        "success": scout.success,
        "returncode": scout.returncode,
        "stderr": scout.stderr if not scout.success else None,
        "tool_driver_full_name": None,
        "cves": [],
        "sarif": None,
    }
    if not scout.success:
        return row
    if not scout.stdout:
        return row
    try:
        row["sarif"] = json.loads(scout.stdout)
    except json.JSONDecodeError:
        row["success"] = False
        row["stderr"] = "SARIF stdout was not valid JSON"
        return row
    findings, driver_name = parse_sarif(scout.stdout)
    row["tool_driver_full_name"] = driver_name
    row["cves"] = [f.to_json_dict() for f in findings]
    return row


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok"})


@app.get("/scan")
def scan() -> Any:
    """
    Query params:
      image — full reference (``myorg/app:tag`` or ``nginx:latest``), or ``all`` (default).
      include_sarif — if ``0`` or ``false``, omit embedded ``sarif`` object per image to save size.
    """
    image_param = request.args.get("image", "all").strip()
    include_sarif = request.args.get("include_sarif", "1").lower() not in (
        "0",
        "false",
        "no",
    )

    try:
        if image_param.lower() == "all":
            refs = _discover_all_images()
            if not refs:
                return jsonify({"images": [], "message": "No images discovered from Docker Hub."})
        else:
            refs = [parse_image_spec(image_param)]
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except DockerHubClientError as e:
        return jsonify({"error": f"Docker Hub error: {e}"}), 502

    try:
        _ensure_docker_logged_in()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503

    results: List[Dict[str, Any]] = []
    for ref in refs:
        try:
            row = _scan_one(ref)
            if not include_sarif:
                row.pop("sarif", None)
            results.append(row)
        except Exception as e:
            logger.exception("scan failed for %s", ref.full_name)
            results.append(
                {
                    "image": ref.full_name,
                    "success": False,
                    "returncode": -1,
                    "stderr": str(e),
                    "cves": [],
                }
            )

    return jsonify({"images": results, "count": len(results)})


def create_app() -> Flask:
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
