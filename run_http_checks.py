"""Verify the existing source pin and execute one bounded HTTP SDK flow."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--dioptra-source',type=Path,required=True)
    p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--results',type=Path,required=True)
    args=p.parse_args()
    root=Path(__file__).resolve().parent;source=args.dioptra_source.resolve()
    hashes=json.loads((root/'dioptra-source-hashes.json').read_text())
    for name,expected in hashes.items():
        path=source/name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
            raise SystemExit('Pinned Dioptra source mismatch: '+name)
    import authorization_contract_runtime
    package=Path(authorization_contract_runtime.__file__).parent.parent
    out=args.results.resolve();out.mkdir(parents=True,exist_ok=False)
    environment=dict(os.environ)
    environment.update({'PYTHONPATH':os.pathsep.join([str(source/'src'),str(source),str(package)]),
                        'PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1',
                        'AUTHORIZATION_CONTRACT_RUNTIME':str(args.runtime.resolve()),
                        'CONTRACT_INTEGRATION_RESULTS':str(out/'integration')})
    cmd=[sys.executable,'-m','pytest','-q','-p','faker.contrib.pytest.plugin',
         '--import-mode=importlib',str(root/'checks/test_http_sdk_integration.py'),
         '--tb=short',f'--junitxml={out / "checks.xml"}']
    with (out/'checks.log').open('w') as log:
        child=subprocess.Popen(cmd,env=environment,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try:code=child.wait(timeout=45)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGKILL);child.wait()
            raise SystemExit('HTTP integration deadline exceeded; owned process group reaped')
    print(json.dumps({'exit':code,'sourceFilesVerified':len(hashes),'results':str(out)}))
    raise SystemExit(code)


if __name__=='__main__':main()
