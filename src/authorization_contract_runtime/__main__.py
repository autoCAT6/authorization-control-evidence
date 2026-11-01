"""Run the synthetic signed-capability evaluation without Dioptra."""
import argparse
import json
import os
from pathlib import Path
import sys

from .runtime import EvaluationError, RUNTIME_ENV, evaluate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args(argv)
    output = args.results.absolute()
    if output.exists() or output.is_symlink():
        parser.error("results must be a new directory")
    if not output.parent.is_dir():
        parser.error("the results parent directory must already exist")
    os.environ[RUNTIME_ENV] = str(args.runtime.resolve())
    try:
        observations, audit, summary = evaluate()
    except EvaluationError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError):
        print("Evaluation preparation or report parsing failed", file=sys.stderr)
        return 1
    created = []
    owned_directory = False
    try:
        # Exclusive creation also catches a destination created during evaluation.
        output.mkdir(exist_ok=False)
        owned_directory = True
        for name, content in [("observations", observations), ("audit", audit),
                              ("summary", summary)]:
            path = output / (name + ".json")
            with path.open("x") as stream:
                created.append(path)
                stream.write(content)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        if owned_directory:
            output.rmdir()
        print("Results could not be written to a new directory", file=sys.stderr)
        return 1
    verified = json.loads(summary)
    print(json.dumps({key: verified[key] for key in [
        "status", "cases", "actualHttpsRequests", "endpointEffects",
        "explicitRefusalResponses"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
