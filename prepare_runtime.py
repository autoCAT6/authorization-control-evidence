"""Prepare pinned dependencies before an evaluation job, never inside it."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from authorization_contract_runtime.runtime import ASSETS, _executables


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--offline-cache", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ASSETS / "asset-hashes.json").read_text())
    for name, expected in manifest.items():
        raw = (ASSETS / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        (directory / name).write_bytes(raw)
    npm = shutil.which("npm")
    if not npm:
        raise SystemExit("npm is required during runtime preparation")
    node, openssl = _executables()
    # Avoid user/global npm configuration during this preparation.
    empty = directory / ".empty-user-npmrc"
    empty_global = directory / ".empty-global-npmrc"
    empty.write_text("")
    empty_global.write_text("")
    command = [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
        "--userconfig", str(empty), "--globalconfig", str(empty_global)]
    if args.offline_cache:
        command += ["--offline", "--cache", str(args.offline_cache.resolve())]
    subprocess.run(command, cwd=directory, check=True)
    versions = {
        "node": subprocess.check_output([node, "--version"], text=True).strip(),
        "openssl": subprocess.check_output([openssl, "version"], text=True).strip(),
        "npm": subprocess.check_output([npm, "--version"], text=True).strip()
    }
    (directory / "prepared-runtime.json").write_text(json.dumps({
        "assets": manifest, "versions": versions,
        "job_execution_installs_dependencies": False
    }, indent=2) + "\n")
    print(json.dumps({"prepared": str(directory), "versions": versions}))


if __name__ == "__main__":
    main()
