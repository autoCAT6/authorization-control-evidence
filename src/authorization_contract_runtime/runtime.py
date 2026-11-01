"""Run the pinned local evaluation without forwarding worker credentials."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time


ASSETS = Path(__file__).parent / "assets"
RUNTIME_ENV = "AUTHORIZATION_CONTRACT_RUNTIME"
MAX_REPORT_BYTES = 1_048_576
FORBIDDEN = re.compile(
    r'-----BEGIN[^\n]*PRIVATE KEY|"(?:authorization|proofValue|'
    r'privateKeyMultibase|privateKeyBase58|capability-invocation)"\s*:'
    r'|urn:zcap:|synthetic-private-record', re.IGNORECASE
)


class EvaluationError(RuntimeError):
    """A failed/incomplete evaluation, with no raw child diagnostics."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _runtime_dir() -> Path:
    value = os.environ.get(RUNTIME_ENV)
    if not value:
        raise EvaluationError("Prepared evaluation runtime is not configured")
    directory = Path(value).resolve()
    manifest = json.loads((ASSETS / "asset-hashes.json").read_text())
    for name, expected in manifest.items():
        path = directory / name
        if not path.is_file() or _digest(path.read_bytes()) != expected:
            raise EvaluationError("Prepared evaluation assets do not match this package")
    dependencies = json.loads((directory / "package.json").read_text())["dependencies"]
    for name, version in dependencies.items():
        installed = directory / "node_modules" / name / "package.json"
        if not installed.is_file() or json.loads(installed.read_text())["version"] != version:
            raise EvaluationError("Prepared evaluation dependencies are missing or incompatible")
    return directory


def _executables() -> tuple[str, str]:
    node = shutil.which("node")
    openssl = shutil.which("openssl")
    if not node or not openssl:
        raise EvaluationError("Node.js and OpenSSL are required in the worker runtime")
    return node, openssl


def _child_environment(temp_dir: Path, executables: tuple[str, ...]) -> dict[str, str]:
    paths = list(dict.fromkeys(str(Path(x).parent) for x in executables))
    paths.extend(["/usr/bin", "/bin"])
    return {
        "PATH": os.pathsep.join(paths), "TMPDIR": str(temp_dir),
        "TMP": str(temp_dir), "TEMP": str(temp_dir), "LANG": "C", "TZ": "UTC"
    }


def _run_checked(
    argv: list[str], *, directory: Path, temp_dir: Path,
    timeout: float, executables: tuple[str, ...], phase: str
) -> None:
    if timeout <= 0:
        raise EvaluationError("Evaluation deadline exceeded")
    # No child output enters Dioptra logs/artifacts. Error messages carry only
    # the trusted phase label and exit status, never request options or tokens.
    process = subprocess.Popen(
        argv, cwd=directory, env=_child_environment(temp_dir, executables),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=(os.name == "posix")
    )
    try:
        result = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.wait()
        raise EvaluationError(f"{phase} exceeded the evaluation deadline") from None
    if result:
        raise EvaluationError(f"{phase} exited with status {result}")


def validate_artifact_json(contents: str) -> dict:
    if not isinstance(contents, str) or len(contents.encode()) > MAX_REPORT_BYTES:
        raise EvaluationError("Evaluation artifact is invalid or too large")
    if FORBIDDEN.search(contents):
        raise EvaluationError("Evaluation artifact contains prohibited raw material")
    try:
        value = json.loads(contents)
    except (ValueError, TypeError):
        raise EvaluationError("Evaluation artifact is not valid JSON") from None
    if not isinstance(value, dict):
        raise EvaluationError("Evaluation artifact must be a JSON object")
    return value


def evaluate(*, timeout: float = 30) -> tuple[str, str, str]:
    """Return observation, audit and summary JSON only after a successful audit.

    Dependencies are prepared before a job; this function never installs them.
    It accepts no private records, credentials, external targets or commands.
    """
    directory = _runtime_dir()
    node, openssl = _executables()
    deadline = time.monotonic() + timeout
    # Node's temporary TLS files also live here, so timeout cleanup removes
    # them even when a killed child cannot run its own finally handler.
    with tempfile.TemporaryDirectory(prefix="authorization-contract-") as temporary:
        temp = Path(temporary)
        observation = temp / "observations.json"
        audit = temp / "audit.json"
        for phase, argv in [
            ("Protocol evaluation", [node, str(directory / "probe.mjs"), str(observation)]),
            ("Evidence audit", [node, str(directory / "audit-evidence.mjs"), str(observation), str(audit)])
        ]:
            _run_checked(
                argv, directory=directory, temp_dir=temp,
                timeout=deadline-time.monotonic(), executables=(node, openssl), phase=phase
            )
        if any(not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES for path in [observation, audit]):
            raise EvaluationError("Evaluation did not produce bounded evidence files")
        observation_text = observation.read_text()
        audit_text = audit.read_text()
        observed = validate_artifact_json(observation_text)
        audited = validate_artifact_json(audit_text)
        if audited.get("result") != "pass" or audited.get("cases") != len(observed.get("results", [])):
            raise EvaluationError("Evaluation has no matching successful evidence audit")
        if observed.get("cleanup") != {"listenerClosed": True, "tlsFilesRemoved": True}:
            raise EvaluationError("Evaluation did not confirm local cleanup")
        summary = {
            "schema": "authorization-contract-summary/v1",
            "status": "pass",
            "cases": audited["cases"],
            "actualHttpsRequests": audited["actualHttpsRequests"],
            "endpointEffects": audited["endpointEffects"],
            "explicitRefusalResponses": audited["explicitRefusalResponses"],
            "observationsSha256": _digest(observation_text.encode()),
            "auditSha256": _digest(audit_text.encode()),
            "sourceSha256": observed["sourceSha256"],
            "dependencyLockSha256": observed["dependencyLockSha256"],
            "profile": observed["profile"],
            "limits": observed["limits"]
        }
        return observation_text, audit_text, json.dumps(summary, indent=2) + "\n"
