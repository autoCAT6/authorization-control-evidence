import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const positive = ['valid-direct', 'valid-worker', 'same-resource-distinct-authorities'];
const refused = ['action-expansion', 'target-expansion', 'wrong-signer',
  'tampered-ancestor', 'expiry-expansion', 'expired-leaf',
  'argument-delegated-to-wrong-service', 'signed-body-substitution'];
const dynamic = ['revoked-ancestor-live-leaf', 'inflight-and-post-commit',
  'independent-authority-revocation-control'];
const expectedCases = [...positive, ...refused, ...dynamic];

export function audit(e) {
  assert.equal(e.stage, 'local-full-matrix-executed-awaiting-evidence-audit');
  assert.equal(e.sourceSha256, hash(readFileSync(new URL('probe.mjs', import.meta.url))));
  assert.equal(e.dependencyLockSha256, hash(readFileSync(new URL('package-lock.json', import.meta.url))));
  assert.deepEqual(e.cleanup, {listenerClosed: true, tlsFilesRemoved: true});
  assert.equal(e.results.length, 14);
  assert.deepEqual([...e.results.map(x => x.caseId)].sort(), [...expectedCases].sort());
  assert.ok(e.results.every(x => x.outcome === 'pass'));
  assert.ok(!/-----BEGIN[^\n]*PRIVATE KEY|"(?:authorization|proofValue|privateKeyMultibase|privateKeyBase58|capability-invocation)"\s*:|urn:zcap:|synthetic-private-record/i.test(JSON.stringify(e)));

  const requests = new Map();
  let previousPolicy = 1;
  for(const [index, row] of e.ledger.entries()) {
    assert.equal(row.sequence, index + 1);
    assert.ok(Number.isFinite(Date.parse(row.atUtc)));
    assert.ok(row.policyVersion >= previousPolicy);
    previousPolicy = row.policyVersion;
    assert.ok(expectedCases.includes(row.caseId));
    if(row.requestRef) {
      assert.match(row.requestRef, /^[a-f0-9]{16}$/);
      const records = requests.get(row.requestRef) || [];
      records.push(row);
      requests.set(row.requestRef, records);
    }
  }
  assert.equal(requests.size, 24);
  for(const rows of requests.values()) {
    const incoming = rows.filter(x => x.stage === 'received');
    const completed = rows.filter(x => x.stage === 'http-completed');
    assert.equal(incoming.length, 1);
    assert.equal(completed.length, 1);
    assert.ok(incoming[0].sequence < completed[0].sequence);
    assert.ok(rows.every(x => x.caseId === incoming[0].caseId));
    const verified = rows.filter(x => x.stage === 'verified');
    const effects = rows.filter(x => x.stage === 'effect');
    if(effects.length) {
      assert.equal(verified.length, 1);
      assert.equal(verified[0].endpoint, 'resource');
      for(const effect of effects) {
        assert.ok(verified[0].sequence < effect.sequence);
        assert.ok(effect.sequence < completed[0].sequence);
        assert.equal(effect.operation, verified[0].action);
        assert.match(effect.valueDigest, /^[a-f0-9]{64}$/);
      }
    }
    if(completed[0].status >= 400) assert.equal(effects.length, 0);
  }

  for(const caseId of expectedCases) {
    const rows = e.ledger.filter(x => x.caseId === caseId);
    const result = e.results.find(x => x.caseId === caseId);
    const effects = rows.filter(x => x.stage === 'effect');
    const completions = rows.filter(x => x.stage === 'http-completed');
    assert.equal(effects.length, result.observedEffects);
    assert.ok(completions.some(x => x.status === result.responseStatus));
    if(positive.includes(caseId)) {
      assert.equal(result.responseStatus, 200);
      assert.deepEqual(effects.map(x => x.operation), ['read', 'write']);
      assert.equal(effects[0].valueDigest, effects[1].valueDigest);
      const resourceProofs = rows.filter(x => x.stage === 'verified' && x.endpoint === 'resource');
      assert.deepEqual(resourceProofs.map(x => x.chainDepth),
        caseId === 'valid-direct' ? [2, 2] : [3, 3]);
      assert.notEqual(resourceProofs[0].capabilityRef, resourceProofs[1].capabilityRef);
      if(caseId === 'same-resource-distinct-authorities') {
        assert.equal(effects[0].resourceRef, effects[1].resourceRef);
      }
    } else if(refused.includes(caseId)) {
      assert.equal(effects.length, 0);
      assert.equal(result.responseStatus, caseId === 'signed-body-substitution' ? 400 : 403);
      assert.deepEqual(result.stateBefore, result.stateAfter);
      assert.ok(result.explicitHttpRefusal && result.unchangedResourceState);
      if(caseId === 'argument-delegated-to-wrong-service') {
        assert.ok(rows.some(x => x.stage === 'verified' && x.endpoint === 'copy'));
        assert.ok(!rows.some(x => x.stage === 'verified' && x.endpoint === 'resource'));
      }
    } else {
      const commits = rows.filter(x => x.stage === 'revocation-committed');
      assert.equal(commits.length, 1);
      const commit = commits[0];
      assert.equal(result.commitSequence, commit.sequence);
      assert.ok(completions.some(x => x.status === 403 && x.sequence > commit.sequence));
      assert.equal(effects.length, 1);
      if(caseId === 'independent-authority-revocation-control') {
        assert.ok(effects[0].sequence > commit.sequence);
        assert.ok(rows.some(x => x.stage === 'http-completed' && x.endpoint === 'copy' && x.status === 403));
        assert.ok(rows.some(x => x.stage === 'http-completed' && x.endpoint === 'resource' && x.status === 200));
      } else {
        assert.ok(effects[0].sequence < commit.sequence);
        assert.equal(result.postCommitEffects, 0);
        const postCommitRequests = rows.filter(x => x.stage === 'received' && x.sequence > commit.sequence);
        assert.equal(postCommitRequests.length, 1);
        const postCommitCompletion = completions.find(x => x.requestRef === postCommitRequests[0].requestRef);
        assert.equal(postCommitCompletion.status, 403);
        // Refusal must precede natural expiry by more than the declared skew.
        assert.ok(Date.parse(result.leafExpiresAt) > Date.parse(postCommitCompletion.atUtc) + 1000);
        if(caseId === 'inflight-and-post-commit') {
          const completion = completions.find(x => x.requestRef === effects[0].requestRef);
          assert.equal(completion.status, 200);
          assert.ok(completion.sequence > commit.sequence);
        }
      }
    }
  }
  return {
    result: 'pass', cases: 14, actualHttpsRequests: requests.size,
    endpointEffects: e.ledger.filter(x => x.stage === 'effect').length,
    explicitRefusalResponses: e.ledger.filter(x => x.stage === 'http-completed' && x.status >= 400).length,
    claim: 'Single local reference-stack execution with synthetic data; no independent acceptance or use.'
  };
}

const observations = JSON.parse(readFileSync(process.argv[2]));
const baseResult = audit(observations);
function movePreCommitEffectAfterCommit(x) {
  const caseId = 'revoked-ancestor-live-leaf';
  const effect = x.ledger.find(r => r.caseId === caseId && r.stage === 'effect');
  const completion = x.ledger.find(r => r.stage === 'http-completed' && r.requestRef === effect.requestRef);
  const commit = x.ledger.find(r => r.caseId === caseId && r.stage === 'revocation-committed');
  x.ledger = x.ledger.filter(r => r !== effect && r !== completion);
  effect.policyVersion = completion.policyVersion = commit.policyVersion;
  x.ledger.splice(x.ledger.indexOf(commit) + 1, 0, effect, completion);
  for(const [index, row] of x.ledger.entries()) row.sequence = index + 1;
  for(const result of x.results) {
    if(result.commitSequence) result.commitSequence = x.ledger.find(
      r => r.caseId === result.caseId && r.stage === 'revocation-committed').sequence;
  }
}
const controls = [
  ['missing-endpoint-effects', x => {x.ledger.filter(r => r.caseId === 'valid-worker' && r.stage === 'effect').forEach(r => {r.stage = 'note';});}],
  ['missing-explicit-refusal', x => {x.ledger.find(r => r.caseId === 'action-expansion' && r.stage === 'http-completed').stage = 'completion-missing';}],
  ['wrong-worker-chain-depth', x => {x.ledger.find(r => r.caseId === 'valid-worker' && r.stage === 'verified' && r.endpoint === 'resource').chainDepth = 2;}],
  ['changed-output-state-on-denial', x => {x.results.find(r => r.caseId === 'target-expansion').stateAfter[0][1] = 'changed';}],
  ['expiry-confounds-revocation', x => {x.results.find(r => r.caseId === 'revoked-ancestor-live-leaf').leafExpiresAt = '2000-01-01T00:00:00Z';}],
  ['post-commit-effect', movePreCommitEffectAfterCommit],
  ['missing-inflight-correlation', x => {x.ledger.find(r => r.caseId === 'inflight-and-post-commit' && r.stage === 'effect').requestRef = '0000000000000000';}],
  ['unrelated-authority-erased', x => {x.ledger.find(r => r.caseId === 'independent-authority-revocation-control' && r.stage === 'effect').stage = 'note';}],
  ['leaked-capability-material', x => {x.rawCredential = {proofValue: 'prohibited'};}],
  ['source-changed-after-run', x => {x.sourceSha256 = '0'.repeat(64);}]
];
const rejected = [];
for(const [name, mutate] of controls) {
  const candidate = structuredClone(observations);
  mutate(candidate);
  assert.throws(() => audit(candidate), undefined, `Evidence audit failed to reject ${name}`);
  rejected.push(name);
}
const report = {...baseResult, rejectedEvidenceNegativeControls: rejected};
if(process.argv[3]) writeFileSync(process.argv[3], JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report));
