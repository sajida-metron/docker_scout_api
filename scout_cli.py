"""Run `docker login` and `docker scout cves` via subprocess."""

import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from docker_scout_api.models import ImageRef

logger = logging.getLogger(__name__)

DEFAULT_CVES_TIMEOUT = 600
DEFAULT_LOGIN_TIMEOUT = 30


@dataclass
class ScoutResult:
    stdout: str
    stderr: str
    returncode: int
    success: bool


def _completed_process_to_scout_result(proc: subprocess.CompletedProcess) -> ScoutResult:
    out, err = proc.stdout, proc.stderr
    if isinstance(out, bytes):
        stdout = out.decode("utf-8", errors="replace") if out else ""
    else:
        stdout = out or ""
    if isinstance(err, bytes):
        stderr = err.decode("utf-8", errors="replace") if err else ""
    else:
        stderr = err or ""
    return ScoutResult(
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode or 0,
        success=proc.returncode == 0,
    )


def _run_docker_subprocess(
    cmd: list[str],
    *,
    timeout: int,
    text: bool,
    input_bytes: Optional[bytes] = None,
    timeout_msg: str,
    not_found_msg: str,
    on_exception: Callable[[Exception], None],
) -> ScoutResult:
    try:
        run_kw: dict = {
            "capture_output": True,
            "timeout": timeout,
            "text": text,
            "env": os.environ.copy(),
        }
        if input_bytes is not None:
            run_kw["input"] = input_bytes
        proc = subprocess.run(cmd, **run_kw)
        return _completed_process_to_scout_result(proc)
    except subprocess.TimeoutExpired:
        logger.warning("%s", timeout_msg)
        return ScoutResult(stdout="", stderr="timeout", returncode=-1, success=False)
    except FileNotFoundError:
        logger.warning("docker executable not found")
        return ScoutResult(
            stdout="", stderr=not_found_msg, returncode=-1, success=False
        )
    except Exception as e:
        on_exception(e)
        return ScoutResult(stdout="", stderr=str(e), returncode=-1, success=False)


def docker_login(
    username: str, password: str, timeout: int = DEFAULT_LOGIN_TIMEOUT
) -> ScoutResult:
    return _run_docker_subprocess(
        ["docker", "login", "-u", username, "--password-stdin"],
        timeout=timeout,
        text=False,
        input_bytes=password.encode("utf-8"),
        timeout_msg="docker login timed out",
        not_found_msg="docker not found",
        on_exception=lambda e: logger.warning("docker login failed: %s", e),
    )


def docker_scout_cves(
    image_ref: ImageRef,
    timeout: int = DEFAULT_CVES_TIMEOUT,
) -> ScoutResult:
    uri = image_ref.registry_uri()
    logger.info("docker scout cves: %s", uri)
    return _run_docker_subprocess(
        ["docker", "scout", "cves", "--format", "sarif", uri],
        timeout=timeout,
        text=True,
        timeout_msg=f"docker scout cves timed out for {uri}",
        not_found_msg="docker or docker scout not found",
        on_exception=lambda e: logger.warning("docker scout cves failed for %s: %s", uri, e),
    )
