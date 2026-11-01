# Authorization control evidence

Run a synthetic copy service with signed capabilities and inspect what its
resource endpoints actually read or wrote. Alice supplies separate input-read
and output-write permissions. The service invokes them directly or delegates
them to a separately keyed worker. A separate audit checks request observations,
resource effects, final state and cleanup before producing a passing summary.

The example follows the software pattern discussed in
[W3C CCG zcap-spec #130](https://github.com/w3c-ccg/zcap-spec/issues/130).
An optional adapter registers and executes the same evaluation in NIST Dioptra.
This is independently maintained software; it has no W3C or NIST acceptance.

## Run without Dioptra

The standalone path needs Python 3.11 or later, Node, npm, OpenSSL with the
`req -addext` option, and permission to bind a loopback listener. It needs no
model, cloud account, API credential, private records or Dioptra installation.
The recorded local environment is macOS ARM64, Python 3.12.14, Node 25.8.2,
npm 11.11.1 and OpenSSL 3.6.4. Other operating systems have not been verified.

From an extracted source directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python prepare_runtime.py ./prepared-runtime
.venv/bin/python -m authorization_contract_runtime \
  --runtime ./prepared-runtime --results ./results
```

Dependency preparation runs `npm ci --ignore-scripts`. The evaluation installs
nothing and passes a six-variable environment to its owned subprocesses. If an
npm cache is already populated, preparation accepts `--offline-cache PATH`.
Results must be a new directory with an existing parent. Existing results are
never overwritten. A failed evaluation returns nonzero without writing reports.

The result directory contains `observations.json`, `audit.json` and
`summary.json`. The summary binds the first two files by SHA-256. A passing
reference run has 14 cases, 24 actual loopback HTTPS requests, nine endpoint
effects and 12 explicit refusals. These are different counts. Timestamps, fresh
keys and the allocated port make output hashes vary between runs.

## What to examine

* Direct and two-hop copying retain separate input-read/output-write permissions.
* Invalid action, resource, actor, expired or attenuated authority is refused.
* A signed-body substitution fails before its requested resource effect.
* Revoking an ancestor blocks subsequent uses through a local application hook.
* A read that already executed before revocation is recorded as an effect; it
  cannot be retroactively undone. Later unauthorized output is still refused.

`example-results` contains synthetic reference outputs. They are local results,
not independent assessments. Reports retain hashed resource and actor references
and status/effect observations. Raw synthetic payloads, signed capabilities,
private keys and request authorization headers are excluded from those reports.
The output gate checks known representations; it is not a general secret scanner.

## Optional Dioptra integration

See [the integration guide](docs/DIOPTRA-INTEGRATION.md). It uses pinned upstream
source, SQLite fixtures, actual HTTP requests and Dioptra's production SDK for
import and bundle downloads, followed by its real offline TaskEngine.
`run_checks.py` runs 22 adapter/integration checks; `run_http_checks.py` selects
the HTTP flow. Its 13 Dioptra HTTP requests are separate from the 24 signed
HTTPS requests. The guide records dependency and fixture boundaries.

## Trust and scope

The operator-prepared executable paths, dependencies and local machine are
trusted. The runtime verifies four reference assets and eight direct dependency
versions; it does not attest every installed dependency file. Node and OpenSSL
are owned subprocesses with bounded execution and temporary-directory cleanup.
This process isolation is not an operating-system sandbox for hostile code.

The revocation hook is synchronous local application policy, not a distributed
revocation protocol. One reference stack and synthetic data do not establish
ZCAP conformance, complete personal-agent security, production deployment,
model safety, independent validation or a general privacy guarantee. The
Dioptra adapter does not run RQ, real MLflow tracking, object storage or containers.

## Revision and attribution

Version 0.1.2 adds this standalone command, packaging metadata and review
instructions. The signed probe, evidence audit, Python runtime and plugin code
are unchanged from the locally validated 0.1.1 observer revision. That revision
waits up to one second for a matching server completion observation and fails if
it never arrives. It does not invent an observation or weaken refusal checks.

Original example code is by Yanzhi Xin, under Apache-2.0; see LICENSE and NOTICE.
Dependencies retain their own terms; see [THIRD-PARTY.md](THIRD-PARTY.md).
