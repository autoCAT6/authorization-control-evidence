"""Verify pinned Dioptra files, then run real integration and boundary checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dioptra-source", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    source = args.dioptra_source.resolve()
    hashes = json.loads((root / "dioptra-source-hashes.json").read_text())
    for name, expected in hashes.items():
        path = source / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Pinned Dioptra source mismatch: {name}")
    import authorization_contract_runtime
    package_root = Path(authorization_contract_runtime.__file__).parent.parent
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.update({
        "PYTHONPATH": os.pathsep.join([str(source / "src"), str(source), str(package_root)]),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "AUTHORIZATION_CONTRACT_RUNTIME": str(args.runtime.resolve()),
        "CONTRACT_INTEGRATION_RESULTS": str(results / "integration"),
    })
    command = [sys.executable, "-m", "pytest", "-q", "-p", "faker.contrib.pytest.plugin",
               "--import-mode=importlib", str(root / "checks"), "--tb=short",
               f"--junitxml={results / 'checks.xml'}"]
    with (results / "checks.log").open("w") as log:
        result = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    print(json.dumps({"exit": result.returncode, "results": str(results),
                      "verifiedDioptraSourceFiles": len(hashes)}))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
