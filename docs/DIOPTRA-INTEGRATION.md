# Authorization evidence in Dioptra

This self-managed software example imports a signed-capability evaluation into Dioptra and executes its registered entrypoint with Dioptra's offline task engine. It produces three JSON artifacts: request/effect observations, an evidence audit, and a summary containing their SHA-256 hashes. It is not a NIST project, accepted Dioptra contribution, agency assessment or endorsement.

The integration uses unmodified Dioptra source at `71bf4fa7ad62f96640e0884b0d11e7c3fdc1b4c0`. The source hash inventory covers 543 files used by the integration harness. The server's actual TOML import, SQLite resource registration, compiled entrypoint configuration and plugin/artifact bundle routes are exercised. The engine receives the downloaded Python files and real registered artifact-task identifiers, rather than an independently reconstructed task graph.

## Evaluation

The authorization cases and evidence audit retain the existing local reference semantics. Runtime 0.1.1 adds the bounded observation-order correction described below. Four separately keyed actors exercise signed invocations, separate input-read/output-write permissions, direct and two-hop delegated copying, attenuation, expiry and an explicitly defined local ancestor-revocation hook. The full underlying matrix has 14 cases, 24 actual loopback HTTPS requests, nine endpoint effects and 12 explicit refusals. Re-executing that matrix through Dioptra does not create additional protocol cases or independent verification.

A successful summary is returned only after the separate evidence audit succeeds and confirms cleanup. The adapter bounds report sizes, drops raw child output, passes a six-variable child environment rather than inherited credentials, and applies a deadline. The POSIX timeout control kills the process group and removes the parent-owned temporary directory. JSON serialization rejects parent/nested artifact names and known raw credential/key representations. This output gate is specific to the known synthetic reports; it is not a general secret detector.

The operator-prepared dependencies and executable paths are trusted. The adapter checks the four reference asset hashes and eight direct installed dependency versions. The npm lock records integrity for dependency preparation; execution does not attest every installed dependency file. This is not an OS sandbox for untrusted code or a distributed revocation service.

## Reproduce

Tested locally on macOS ARM64 with Python 3.12.14, Node 25.8.2, npm 11.11.1 and OpenSSL 3.6.4. The integration harness requires the pinned Dioptra REST API and its test dependencies. The recorded environment lists package versions, but is not a portable, platform-complete dependency lock.

1. Obtain the public Dioptra source at the commit above. Retain its existing attribution and license. Install its relevant REST API/test dependencies in an isolated Python environment, including pytest, Faker and freezegun. No private service credentials are needed.
2. Install the runtime from the release wheel or extracted source directory into that environment with `python -m pip install --no-deps PATH_TO_WHEEL`, or `python -m pip install .` for the source.
3. Prepare a task-owned dependency directory before running a job:

   ```sh
   python prepare_runtime.py /absolute/path/to/prepared-runtime
   ```

   Preparation runs `npm ci --ignore-scripts` using the included lockfile. For an already populated task-owned npm cache, add `--offline-cache /absolute/path/to/cache`. No npm installation occurs during evaluation.
4. Run the actual integration and failure controls:

   ```sh
   python run_checks.py \
     --dioptra-source /absolute/path/to/pinned-dioptra \
     --runtime /absolute/path/to/prepared-runtime \
     --results /absolute/path/to/new-results
   ```

The runner verifies the pinned Dioptra source inventory before importing it. A local loopback listener is required. The current runner includes 22 adapter/integration checks; the earlier run passed its original 21 checks without skips or errors. The three JSON reports and registration/index capture are written under the result directory; JUnit and the test log accompany them. The example reports in this package are synthetic reference outputs, not independent assessments.

## Execution boundary

Dioptra's resource importer copies Python plugin files, so the thin task plugin calls the separately installed runtime wheel. Its output serializer is registered through the same manifest. The legacy adapter checks use Dioptra's real Flask routes and SQLite with upstream fixtures; the additional mode below uses the actual requests-based SDK over loopback HTTP. Those fixtures substitute an unused MLflow backend; RQ workers, MLflow tracking, object-store uploads and containers are not run. Authentication is enabled for the import tests, including an unauthenticated 401 control; this is not a full deployment-authentication audit.

In the legacy Flask checks, the pinned upstream test-session download helper passes `params` to Flask, which expects `query_string`. Those checks access the same actual bundle routes directly with Flask's argument. The additional HTTP mode uses the unmodified production SDK download methods without that bypass. The legacy checks change no Dioptra source and make no claim about production HTTP SDK downloads; the additional mode below exercises those methods on a local server. Three private SDK helpers prepare the offline schema and artifact registry; this adapter is pinned to this commit, not a promise of version-independent API compatibility.

The 21 checks include actual successful registration/execution, a real-engine unconfigured-runtime failure with no success artifact, malformed/unknown-type registration rollback, missing/modified runtime refusal, controlled child failure and credential-environment minimization, POSIX delayed-descendant-effect prevention on timeout, incomplete audit/cleanup refusal and artifact boundaries. Some failure controls inject deliberately incomplete outputs into the adapter; they are not extra cryptographic tests. A synthetic initial smoke execution exited with status 1 before a report was retained. Later direct evaluation and the integrated final run passed; its earlier cause was not established. No upstream defect or corrective causal claim is assigned to that isolated result. Earlier harness failures and their corrections are retained in the local validation record.

No Docker or Podman runtime was available. No complete personal agent, model-training pipeline, distributed deployment, full ZCAP conformance, general privacy theorem, independent use or maintainer acceptance is established. The revocation control remains a synchronous local application hook, and an already executed pre-revocation read is not retroactively canceled.

## Attribution and status

This is independently maintained software prepared by Yanzhi Xin using a pre-existing local reference method and public Dioptra APIs. It is separate from pending Dioptra PR #1435. General maintainer guidance supporting separately maintained plugins appears in Dioptra issue #1283 and was addressed to another author; it is not an invitation or acceptance of this example. Existing upstream source, third-party libraries and contributions remain attributed to their authors. This example is maintained separately; third-party source and dependencies retain their own terms.


## Actual HTTP and SDK reproduction

The additional HTTP mode starts a temporary development WSGI server bound only to loopback, then uses Dioptra's unchanged production requests-based SDK for account creation, login, multipart resource import, configuration queries and both streamed bundle downloads. It bypasses no bundle routes and uses no Flask test client for those operations. The requests session is configured with trust_env=False so it does not consult unrelated proxy or netrc settings.

With the same prerequisites and installed wheel described above, run:

```sh
python run_http_checks.py --dioptra-source /absolute/path/to/pinned-dioptra --runtime /absolute/path/to/prepared-runtime --results /absolute/path/to/new-http-results
```

The runner verifies the same 543 source-file hashes, executes only the additional HTTP flow, and bounds its owned process group to 45 seconds. The normal SDK handles the account-creation redirect. The request evidence retains only method, path and status, with no body, cookie, password or headers. The test verifies an unauthenticated import, wrong password, successful session, download integrity, the registered artifact identifiers, three hash-linked JSON results, logout and subsequent refusal. It closes the client, joins the server thread and checks that the listener is closed.

The recorded run contains 13 Dioptra HTTP requests, including one 308 redirect, nine 200 responses and three 401 responses. The embedded authorization matrix remains 14 cases, 24 HTTPS requests, nine endpoint effects and 12 explicit refusals. Those two request paths and counts are separate. A fresh archive run repeats this transport path; it creates no additional protocol cases or independent review.

This mode resolves the earlier test-client-only download limitation for the checked path. SQLite initialization and the unused MLflow substitution still come from upstream fixtures. The API server uses local HTTP, not a TLS or production reverse-proxy deployment. The same three private SDK preparation helpers and offline TaskEngine remain in use. RQ, real MLflow tracking, object storage, containers, model serving, external evaluators and NIST acceptance remain outside the result. The original 21 adapter checks remain available through run_checks.py. They are regression checks for the observer revision, not new protocol results.

The first constrained attempt could not bind its loopback socket and exited before account or evaluation work. The allowed loopback execution passed. That environment restriction is not an upstream defect or a paired regression fixed by this work. Example result files are synthetic local outputs.


### Observation ordering correction

Clean-archive verification exposed a race in the self-authored reference probe. A client could receive the expected body-substitution refusal before the server finish observation had reached the evidence ledger. Runtime 0.1.1 waits up to one second for the matching case and status observation before assessing a refusal. It never fabricates the observation, treats a timeout as a failure, and preserves the same HTTP status, no-effect and resource-state requirements. The authorization dependencies, NIST source, Python runtime and evidence audit are unchanged. Earlier successful reports remain evidence of their recorded runs; they do not establish that the prior harness was free of this intermittent race. This is a local evaluation-tool correction, not a vulnerability or a change to the authorization protocol.

The observer revision passed all 22 current adapter/integration checks, including the existing 21 controls and the additional HTTP flow. A clean archive execution of the HTTP flow also passed. A bounded 12-run diagnostic repeatability check passed; this is evidence about the reproduced harness race, not independent validation or additional privacy cases. Earlier C30 failures without captured diagnostics cannot be retrospectively assigned this cause.
