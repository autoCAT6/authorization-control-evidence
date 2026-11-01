"""Real import routes, SQLite registrations, bundles and offline TaskEngine.

The upstream fixture substitutes an unused MLflow backend. RQ, containers,
external artifact storage and deployment authentication are outside this test.
"""
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import tarfile

import pytest
import structlog

from dioptra.client import DioptraFile
from dioptra.sdk.utilities.run_dioptra_job import (
    Context, _build_artifact_tasks, _create_engine_schema, _validate_yaml,
)
from dioptra.task_engine.task_engine import run_experiment
from authorization_contract_runtime import EvaluationError


ROOT = Path(__file__).resolve().parents[1]
FILES = [
    "dioptra.toml", "entrypoints/authorization-contract.yaml",
    "plugins/authorization_contract/tasks.py",
    "plugins/authorization_contract/artifacts.py",
]


def resource_files(*, manifest=None):
    return [DioptraFile(name, BytesIO(
        manifest.encode() if name == "dioptra.toml" and manifest is not None
        else (ROOT / name).read_bytes()
    ), None) for name in FILES]


def unpack_local_bundle(source, destination):
    # Only the actual bundle returned by our local synthetic API is accepted.
    with tarfile.open(source) as archive:
        archive.extractall(destination, filter="data")


def test_unauthenticated_import_denied(dioptra_client):
    result = dioptra_client.workflows.import_resources(
        1, source=resource_files(), config_path="dioptra.toml"
    )
    assert result.status_code == 401


@pytest.mark.parametrize("manifest", [
    "[[plugins]",  # malformed TOML
    (ROOT / "dioptra.toml").read_text().replace('type = "string"', 'type = "missing_type"'),
], ids=["malformed-toml", "unregistered-type"])
def test_invalid_registration_has_no_resources(dioptra_client, auth_account, manifest):
    result = dioptra_client.workflows.import_resources(
        auth_account["default_group_id"], source=resource_files(manifest=manifest),
        config_path="dioptra.toml",
    )
    assert result.status_code == 400, result.text
    assert dioptra_client.plugins.get().json()["data"] == []
    assert dioptra_client.entrypoints.get().json()["data"] == []


@pytest.mark.parametrize("configured", [True, False], ids=["complete", "unconfigured-runtime"])
def test_imported_entrypoint_executes_and_serializes(client, dioptra_client, auth_account, tmp_path, monkeypatch, configured):
    result = dioptra_client.workflows.import_resources(
        auth_account["default_group_id"], source=resource_files(), config_path="dioptra.toml"
    )
    assert result.status_code == 200, result.text
    resource_ids = result.json()["resources"]
    entrypoint_id = resource_ids["entrypoints"]["Authorization contract evaluation"]
    response = dioptra_client.entrypoints.get_by_id(entrypoint_id)
    assert response.status_code == 200, response.text
    snapshot_id = response.json()["snapshot"]
    config = dioptra_client.entrypoints.snapshots.get_config(entrypoint_id, snapshot_id)
    assert config.status_code == 200, config.text
    configuration = config.json()
    metadata = dioptra_client.entrypoints.snapshots.get_artifact_plugins(entrypoint_id, snapshot_id)
    assert metadata.status_code == 200, metadata.text
    artifact_plugins = metadata.json()

    monkeypatch.chdir(tmp_path)
    context = Context()
    context.mkdirs()
    for resource, destination, stem in [
        ("plugins", context.plugins_dir, "plugins"),
        ("artifactPlugins", context.serialize_dir, "serializers"),
    ]:
        # The upstream Flask-test download helper passes requests' `params`
        # to Flask. Use its actual HTTP route with Flask's query_string,
        # leaving both the upstream source and production SDK untouched.
        base = dioptra_client.entrypoints.snapshots.build_sub_collection_url(entrypoint_id)
        download = client.get(f"{base}/{snapshot_id}/{resource}/bundle", query_string={"fileType": "tar_gz"})
        assert download.status_code == 200, download.get_data(as_text=True)
        bundle = context.dioptra_dir / (stem + ".tar.gz")
        bundle.write_bytes(download.data)
        unpack_local_bundle(bundle, destination)
    for name in ("tasks.py", "artifacts.py"):
        expected = (ROOT / "plugins/authorization_contract" / name).read_bytes()
        assert (context.plugins_dir / "authorization_contract" / name).read_bytes() == expected
    log = structlog.get_logger()
    _create_engine_schema(context, artifact_plugins, log)
    _validate_yaml(configuration, log)
    tasks = _build_artifact_tasks(context, artifact_plugins, log)
    if not configured:
        monkeypatch.delenv("AUTHORIZATION_CONTRACT_RUNTIME", raising=False)
        with pytest.raises(EvaluationError, match="not configured"):
            run_experiment(configuration, {}, {}, tasks, context.artifacts_dir,
                           context.plugins_dir, context.serialize_dir, context.deserialize_dir)
        assert not context.artifacts_results_file.exists()
        assert not (tmp_path / "summary.json").exists()
        return
    run_experiment(configuration, {}, {}, tasks, context.artifacts_dir,
                   context.plugins_dir, context.serialize_dir, context.deserialize_dir)

    index = json.loads(context.artifacts_results_file.read_text())
    values = {}
    for artifact in index["artifacts"]:
        path = Path(artifact["path"])
        assert path.resolve().is_relative_to(tmp_path.resolve())
        values[artifact["name"]] = path.read_text()
        task = tasks["VerifiedJsonArtifactTask"]
        assert artifact["task_plugin_snapshot_id"] == task["plugin_snapshot_id"]
        assert artifact["task_id"] == task["task_id"]
    assert set(values) == {"observations", "audit", "summary"}
    summary = json.loads(values["summary"])
    assert summary["status"] == "pass"
    assert summary["cases"] == 14
    assert summary["actualHttpsRequests"] == 24
    assert summary["endpointEffects"] == 9
    assert summary["explicitRefusalResponses"] == 12
    assert summary["observationsSha256"] == hashlib.sha256(values["observations"].encode()).hexdigest()
    assert summary["auditSha256"] == hashlib.sha256(values["audit"].encode()).hexdigest()

    # Optional external result directory is task-owned and contains no keys.
    if output := os.environ.get("CONTRACT_INTEGRATION_RESULTS"):
        target = Path(output)
        target.mkdir(parents=True, exist_ok=True)
        for name, value in values.items():
            (target / (name + ".json")).write_text(value)
        (target / "registration.json").write_text(json.dumps({
            "import": result.json(), "entrypointId": entrypoint_id,
            "snapshotId": snapshot_id, "configuration": configuration,
            "artifactPlugins": artifact_plugins, "artifactIndex": index,
            "dioptraSource": "71bf4fa7ad62f96640e0884b0d11e7c3fdc1b4c0",
            "execution": "real offline TaskEngine, local Flask transport and SQLite",
            "notTested": ["RQ worker", "MLflow tracking", "containers", "distributed storage"],
        }, indent=2) + "\n")
