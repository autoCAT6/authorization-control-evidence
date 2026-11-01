"""Adapter failure boundaries; these do not add protocol scenarios."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time

import pytest

from authorization_contract_runtime import EvaluationError
from authorization_contract_runtime import runtime


ROOT = Path(__file__).resolve().parents[1]


def artifact_class():
    spec = importlib.util.spec_from_file_location(
        "contract_artifact_under_test", ROOT / "plugins/authorization_contract/artifacts.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VerifiedJsonArtifactTask


def test_unconfigured_runtime_refuses(monkeypatch):
    monkeypatch.delenv(runtime.RUNTIME_ENV, raising=False)
    with pytest.raises(EvaluationError, match="not configured"):
        runtime.evaluate()


def test_modified_assets_refuse_before_execution(tmp_path, monkeypatch):
    for name in json.loads((runtime.ASSETS / "asset-hashes.json").read_text()):
        shutil.copyfile(runtime.ASSETS / name, tmp_path / name)
    (tmp_path / "probe.mjs").write_text("process.exit(0)")
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(tmp_path))
    with pytest.raises(EvaluationError, match="assets do not match"):
        runtime.evaluate()


def test_missing_dependencies_refuse_before_execution(tmp_path, monkeypatch):
    for name in json.loads((runtime.ASSETS / "asset-hashes.json").read_text()):
        shutil.copyfile(runtime.ASSETS / name, tmp_path / name)
    monkeypatch.setenv(runtime.RUNTIME_ENV, str(tmp_path))
    with pytest.raises(EvaluationError, match="dependencies are missing"):
        runtime.evaluate()


def test_child_credentials_and_diagnostics_do_not_propagate(tmp_path, monkeypatch, capfd):
    marker = "synthetic-adapter-secret-do-not-forward"
    for key in ("AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "HTTPS_PROXY", "NODE_OPTIONS"):
        monkeypatch.setenv(key, marker)
    output = tmp_path / "environment.json"
    code = (
        "import os,json,pathlib,sys; "
        f"pathlib.Path({str(output)!r}).write_text(json.dumps(dict(os.environ))); "
        f"print({marker!r});print({marker!r},file=sys.stderr);sys.exit(9)"
    )
    with pytest.raises(EvaluationError, match="Controlled phase exited with status 9") as error:
        runtime._run_checked([sys.executable, "-c", code], directory=tmp_path,
                             temp_dir=tmp_path, timeout=3,
                             executables=(sys.executable,), phase="Controlled phase")
    environment = json.loads(output.read_text())
    assert marker not in json.dumps(environment)
    assert "HOME" not in environment
    # Python itself may add LC_CTYPE on macOS; the adapter passes only six keys.
    assert set(runtime._child_environment(tmp_path, (sys.executable,))) == {
        "PATH", "TMPDIR", "TMP", "TEMP", "LANG", "TZ"
    }
    captured = capfd.readouterr()
    assert marker not in str(error.value) + captured.out + captured.err


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup is POSIX only")
def test_timeout_stops_delayed_descendant_effect(tmp_path):
    ready = tmp_path / "ready"
    late = tmp_path / "late-effect"
    child_code = f"import time,pathlib;time.sleep(0.7);pathlib.Path({str(late)!r}).write_text('bad')"
    parent_code = (
        "import subprocess,sys,time,pathlib;"
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
        f"pathlib.Path({str(ready)!r}).write_text('ready');time.sleep(5)"
    )
    with pytest.raises(EvaluationError, match="exceeded the evaluation deadline"):
        runtime._run_checked([sys.executable, "-c", parent_code], directory=tmp_path,
                             temp_dir=tmp_path, timeout=0.25,
                             executables=(sys.executable,), phase="Controlled timeout")
    assert ready.exists(), "Controlled parent must start before its timeout"
    time.sleep(0.8)
    assert not late.exists()


def test_incomplete_evaluation_has_no_success_report(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "_run_checked", lambda *a, **k: None)
    with pytest.raises(EvaluationError, match="did not produce bounded evidence"):
        runtime.evaluate()


@pytest.mark.parametrize("audit_result,cleanup", [
    ("fail", {"listenerClosed": True, "tlsFilesRemoved": True}),
    ("pass", {"listenerClosed": False, "tlsFilesRemoved": True}),
], ids=["failed-audit", "incomplete-cleanup"])
def test_audit_or_cleanup_failure_has_no_success_report(monkeypatch, audit_result, cleanup):
    def fake_phase(argv, **kwargs):
        if kwargs["phase"] == "Protocol evaluation":
            Path(argv[-1]).write_text(json.dumps({"results": [1], "cleanup": cleanup}))
        else:
            Path(argv[-1]).write_text(json.dumps({"result": audit_result, "cases": 1}))
    monkeypatch.setattr(runtime, "_run_checked", fake_phase)
    with pytest.raises(EvaluationError, match="successful evidence audit|confirm local cleanup"):
        runtime.evaluate()


@pytest.mark.parametrize("name,contents", [
    ("../outside", "{}"),
    ("nested/file", "{}"),
    ("nested\\file", "{}"),
    ("private", '{"proofValue":"raw-credential"}'),
    ("private-key", '{"key":"-----BEGIN PRIVATE KEY-----"}'),
    ("too-big", json.dumps({"x": "x" * runtime.MAX_REPORT_BYTES})),
    ("array", "[]"),
], ids=["parent-path", "nested-path", "windows-path", "raw-proof", "private-key", "oversize", "non-object"])
def test_serializer_rejects_unsafe_outputs_without_files(tmp_path, name, contents):
    before = set(tmp_path.iterdir())
    with pytest.raises(EvaluationError):
        artifact_class().serialize(tmp_path, name, contents)
    assert set(tmp_path.iterdir()) == before


def test_serializer_roundtrip_and_deserializer_boundaries(tmp_path):
    cls = artifact_class()
    contents = '{"status":"pass"}\n'
    result = cls.serialize(tmp_path, "summary", contents)
    assert cls.deserialize(tmp_path, result.name) == contents
    with pytest.raises(EvaluationError, match="outside"):
        cls.deserialize(tmp_path, "../outside.json")
    target = tmp_path / "large.json"
    with target.open("wb") as stream:
        stream.truncate(runtime.MAX_REPORT_BYTES + 1)
    with pytest.raises(EvaluationError, match="too large"):
        cls.deserialize(tmp_path, target.name)
