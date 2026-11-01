"""The CLI must not replace prior evidence or publish a failed evaluation."""
import hashlib
import json

import pytest

from authorization_contract_runtime import EvaluationError
from authorization_contract_runtime import __main__ as cli


def reports():
    observation = '{"results": []}\n'
    audit = '{"result": "pass"}\n'
    summary = json.dumps({
        "status": "pass", "cases": 14, "actualHttpsRequests": 24,
        "endpointEffects": 9, "explicitRefusalResponses": 12,
        "observationsSha256": hashlib.sha256(observation.encode()).hexdigest(),
        "auditSha256": hashlib.sha256(audit.encode()).hexdigest(),
    })
    return observation, audit, summary


def invoke(tmp_path, output):
    return cli.main(["--runtime", str(tmp_path), "--results", str(output)])


def test_existing_output_is_untouched(tmp_path, monkeypatch):
    output = tmp_path / "prior"
    output.mkdir()
    (output / "summary.json").write_text("prior evidence")
    monkeypatch.setattr(cli, "evaluate", lambda: pytest.fail("must not evaluate"))
    with pytest.raises(SystemExit) as error:
        invoke(tmp_path, output)
    assert error.value.code == 2
    assert (output / "summary.json").read_text() == "prior evidence"


def test_missing_parent_does_not_start_evaluation(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "evaluate", lambda: pytest.fail("must not evaluate"))
    with pytest.raises(SystemExit):
        invoke(tmp_path, tmp_path / "missing" / "output")
    assert not (tmp_path / "missing").exists()


def test_refused_evaluation_has_no_reports(tmp_path, monkeypatch, capsys):
    def fail():
        raise EvaluationError("Protocol evaluation exited with status 1")
    monkeypatch.setattr(cli, "evaluate", fail)
    output = tmp_path / "output"
    assert invoke(tmp_path, output) == 1
    assert not output.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "status 1" in captured.err


def test_completed_evaluation_writes_three_hash_linked_reports(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "evaluate", reports)
    output = tmp_path / "output"
    assert invoke(tmp_path, output) == 0
    assert sorted(file.name for file in output.iterdir()) == [
        "audit.json", "observations.json", "summary.json"]
    summary = json.loads((output / "summary.json").read_text())
    for name in ["observations", "audit"]:
        assert summary[name + "Sha256"] == hashlib.sha256(
            (output / (name + ".json")).read_bytes()).hexdigest()
    assert json.loads(capsys.readouterr().out)["cases"] == 14


def test_destination_created_during_evaluation_is_untouched(tmp_path, monkeypatch):
    output = tmp_path / "output"
    def race():
        output.mkdir()
        (output / "prior.txt").write_text("prior evidence")
        return reports()
    monkeypatch.setattr(cli, "evaluate", race)
    assert invoke(tmp_path, output) == 1
    assert (output / "prior.txt").read_text() == "prior evidence"
    assert len(list(output.iterdir())) == 1
