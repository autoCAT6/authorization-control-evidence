"""Serialize only bounded JSON evidence, without executable object formats."""

import os
from pathlib import Path
import tempfile

from dioptra.sdk.api.artifact import ArtifactTaskInterface
from authorization_contract_runtime import EvaluationError, validate_artifact_json
from authorization_contract_runtime.runtime import MAX_REPORT_BYTES


class VerifiedJsonArtifactTask(ArtifactTaskInterface):
    @staticmethod
    def serialize(working_dir: Path, name: str, contents: str, **kwargs) -> Path:
        if not name or name in {".", ".."} or Path(name).name != name or "\\" in name:
            raise EvaluationError("Artifact name must be a simple filename")
        validate_artifact_json(contents)
        destination = working_dir / (name + ".json")
        descriptor, temporary = tempfile.mkstemp(prefix=".contract-", dir=working_dir)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
                stream.write(contents)
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return destination

    @staticmethod
    def deserialize(working_dir: Path, path: str, **kwargs) -> str:
        base = working_dir.resolve()
        file = (base / path).resolve()
        if not file.is_relative_to(base):
            raise EvaluationError("Artifact input is outside the working directory")
        if not file.is_file() or file.stat().st_size > MAX_REPORT_BYTES:
            raise EvaluationError("Artifact input is invalid or too large")
        contents = file.read_text()
        validate_artifact_json(contents)
        return contents

    @staticmethod
    def validation():
        return None
