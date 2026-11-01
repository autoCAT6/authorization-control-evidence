"""Exercise the existing evaluation through the actual requests-based SDK.

The local WSGI development server is not a production deployment. Upstream
fixtures initialize SQLite and substitute the unused MLflow backend. No Flask
test client is used by this flow, including account creation and bundle download.
"""
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import tarfile
from threading import Thread

import structlog
from werkzeug.serving import make_server, WSGIRequestHandler

from dioptra.client import DioptraFile, connect_response_dioptra_client
from dioptra.sdk.utilities.run_dioptra_job import (
    Context, _build_artifact_tasks, _create_engine_schema, _validate_yaml,
)
from dioptra.task_engine.task_engine import run_experiment

ROOT=Path(__file__).resolve().parents[1]
FILES=["dioptra.toml","entrypoints/authorization-contract.yaml",
       "plugins/authorization_contract/tasks.py",
       "plugins/authorization_contract/artifacts.py"]


def files():
    return [DioptraFile(name,BytesIO((ROOT/name).read_bytes()),None) for name in FILES]


class QuietHandler(WSGIRequestHandler):
    def log_request(self,*args,**kwargs):
        pass


class RequestEvidence:
    def __init__(self,app):
        self.app=app
        self.events=[]

    def __call__(self,environ,start_response):
        def record(status,headers,exc_info=None):
            # Do not persist bodies, query strings, credentials, headers or cookies.
            self.events.append({"method":environ["REQUEST_METHOD"],
                                "path":environ["PATH_INFO"],
                                "status":int(status.split()[0])})
            return start_response(status,headers,exc_info)
        return self.app(environ,record)


def test_http_sdk_registration_download_and_execution(flask_app,tmp_path,monkeypatch):
    assert flask_app.config["LOGIN_DISABLED"] is False
    app=RequestEvidence(flask_app)
    server=make_server("127.0.0.1",0,app,request_handler=QuietHandler)
    port=server.server_port
    thread=Thread(target=server.serve_forever,kwargs={"poll_interval":0.05},daemon=True)
    thread.start()
    client=connect_response_dioptra_client(f"http://127.0.0.1:{port}")
    # Configure the actual requests session to ignore proxy/netrc settings.
    # This keeps the synthetic test from consulting unrelated private sources.
    client._session.connect()
    client._session._session.trust_env=False
    secret=secrets.token_urlsafe(24)
    evidence={"transport":"actual loopback HTTP with production requests SDK",
              "dioptraSource":"71bf4fa7ad62f96640e0884b0d11e7c3fdc1b4c0",
              "sourceChanged":False,"httpEvents":app.events,
              "newAuthorizationCases":0}
    try:
        denied=client.workflows.import_resources(1,source=files(),config_path="dioptra.toml")
        assert denied.status_code==401
        created=client.users.create("synthetic-http-evaluator",secret)
        assert created.status_code in (200,201),created.text
        group=created.json()["groups"][0]["id"]
        wrong=client.auth.login("synthetic-http-evaluator",secret+"wrong")
        assert wrong.status_code==401
        logged=client.auth.login("synthetic-http-evaluator",secret)
        assert logged.status_code==200,logged.text
        imported=client.workflows.import_resources(group,source=files(),config_path="dioptra.toml")
        assert imported.status_code==200,imported.text
        entrypoint=imported.json()["resources"]["entrypoints"]["Authorization contract evaluation"]
        response=client.entrypoints.get_by_id(entrypoint)
        assert response.status_code==200,response.text
        snapshot=response.json()["snapshot"]
        configured=client.entrypoints.snapshots.get_config(entrypoint,snapshot)
        assert configured.status_code==200,configured.text
        configuration=configured.json()
        response=client.entrypoints.snapshots.get_artifact_plugins(entrypoint,snapshot)
        assert response.status_code==200,response.text
        metadata=response.json()
        monkeypatch.chdir(tmp_path)
        context=Context();context.mkdirs()
        bundles=[]
        for kind,download,destination in [
            ("plugins",client.entrypoints.snapshots.get_plugins_bundle,context.plugins_dir),
            ("artifactPlugins",client.entrypoints.snapshots.get_artifact_plugins_bundle,context.serialize_dir),
        ]:
            bundle=download(entrypoint,snapshot,output_dir=context.dioptra_dir)
            with tarfile.open(bundle) as archive:
                archive.extractall(destination,filter="data")
            bundles.append({"kind":kind,"bytes":bundle.stat().st_size,
                            "sha256":hashlib.sha256(bundle.read_bytes()).hexdigest()})
        for name in ("tasks.py","artifacts.py"):
            assert (context.plugins_dir/"authorization_contract"/name).read_bytes()==(ROOT/"plugins/authorization_contract"/name).read_bytes()
        log=structlog.get_logger()
        _create_engine_schema(context,metadata,log)
        _validate_yaml(configuration,log)
        tasks=_build_artifact_tasks(context,metadata,log)
        run_experiment(configuration,{},{},tasks,context.artifacts_dir,
                       context.plugins_dir,context.serialize_dir,context.deserialize_dir)
        index=json.loads(context.artifacts_results_file.read_text())
        reports={}
        for artifact in index["artifacts"]:
            path=Path(artifact["path"])
            assert path.resolve().is_relative_to(tmp_path.resolve())
            reports[artifact["name"]]=path.read_bytes()
            assert artifact["task_id"]==tasks["VerifiedJsonArtifactTask"]["task_id"]
            assert artifact["task_plugin_snapshot_id"]==tasks["VerifiedJsonArtifactTask"]["plugin_snapshot_id"]
        assert set(reports)=={"observations","audit","summary"}
        summary=json.loads(reports["summary"])
        assert summary["status"]=="pass"
        assert (summary["cases"],summary["actualHttpsRequests"],summary["endpointEffects"],summary["explicitRefusalResponses"])==(14,24,9,12)
        assert summary["observationsSha256"]==hashlib.sha256(reports["observations"]).hexdigest()
        assert summary["auditSha256"]==hashlib.sha256(reports["audit"]).hexdigest()
        logout=client.auth.logout()
        assert logout.status_code==200,logout.text
        denied=client.entrypoints.get_by_id(entrypoint)
        assert denied.status_code==401
        evidence.update({"status":"pass","entrypointId":entrypoint,
                         "snapshotId":snapshot,"bundles":bundles,
                         "registration":imported.json(),"summary":summary,
                         "artifactNames":sorted(reports)})
        if output:=os.environ.get("CONTRACT_INTEGRATION_RESULTS"):
            target=Path(output);target.mkdir(parents=True,exist_ok=True)
            for name,value in reports.items():(target/(name+".json")).write_bytes(value)
    finally:
        client.close()
        server.shutdown();server.server_close();thread.join(timeout=2)
        assert not thread.is_alive()
        with socket.socket() as check:
            check.settimeout(1)
            assert check.connect_ex(("127.0.0.1",port))!=0
        evidence["serverThreadStopped"]=True
        evidence["listenerClosed"]=True
        if output:=os.environ.get("CONTRACT_INTEGRATION_RESULTS"):
            target=Path(output);target.mkdir(parents=True,exist_ok=True)
            serialized=json.dumps(evidence,indent=2)+"\n"
            assert secret not in serialized
            assert '"Cookie"' not in serialized and '"Set-Cookie"' not in serialized
            (target/"http-sdk-evidence.json").write_text(serialized)
