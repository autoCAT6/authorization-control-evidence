import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import https from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import express from 'express';
import jsigs from 'jsonld-signatures';
import {ZcapClient} from '@digitalbazaar/ezcap';
import {authorizeZcapInvocation} from '@digitalbazaar/ezcap-express';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from '@digitalbazaar/ed25519-verification-key-2020';
import {CapabilityDelegation, extendDocumentLoader} from '@digitalbazaar/zcap';
import {signCapabilityInvocation} from '@digitalbazaar/http-signature-zcap-invoke';

// Self-authored local evaluation for the public W3C CCG zcap130 example.
// Dependencies are unmodified. All data, controllers and keys are synthetic.
const documents = new Map();
const ledger = [];
const revoked = new Set();
const resources = new Map();
const gates = new Map();
const results = [];
const diagnostics = [];
const httpCompletions = new EventEmitter();
let sequence = 0;
let policyVersion = 1;
let origin;
let evidence;
let requestCount = 0;
const ref = value => createHash('sha256').update(value).digest('hex').slice(0, 16);
const digest = value => createHash('sha256').update(String(value)).digest('hex');
const event = (caseId, stage, extra = {}) => ledger.push({
  sequence: ++sequence, atUtc: new Date().toISOString(), caseId, stage, policyVersion, ...extra
});
const reqEvent = (req, stage, extra = {}) => event(req.caseId, stage, {
  requestRef: req.requestRef, ...extra
});
const rootId = target => `urn:zcap:root:${encodeURIComponent(target)}`;

const documentLoader = extendDocumentLoader(jsigs.extendContextLoader(async url => {
  let document;
  if(documents.has(url)) {
    document = documents.get(url);
  } else if(url === Ed25519Signature2020.CONTEXT_URL) {
    document = Ed25519Signature2020.CONTEXT;
  } else {
    throw new Error('Document is outside the synthetic local registry');
  }
  return {contextUrl: null, documentUrl: url, document};
}));

async function makeActor(name) {
  const controller = `https://controllers.example/${name}`;
  const key = await Ed25519VerificationKey2020.generate({
    id: `${controller}#key-1`, controller
  });
  const publicKey = key.export({publicKey: true, includeContext: true});
  documents.set(key.id, publicKey);
  documents.set(controller, {
    '@context': 'https://w3id.org/security/v2',
    id: controller,
    capabilityDelegation: [publicKey],
    capabilityInvocation: [publicKey]
  });
  const signer = key.signer();
  signer.controller = controller;
  return {
    controller, key, signer,
    client: new ZcapClient({
      SuiteClass: Ed25519Signature2020, documentLoader,
      invocationSigner: signer, delegationSigner: signer,
      agent: undefined
    })
  };
}

const alice = await makeActor('alice');
const service = await makeActor('copy-service');
const worker = await makeActor('worker');
const stranger = await makeActor('stranger');
const actors = [alice, service, worker, stranger];

const tlsDir = mkdtempSync(join(tmpdir(), 'zcap130-tls-'));
let server;
let agent;
try {
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1',
    '-keyout', join(tlsDir, 'key.pem'), '-out', join(tlsDir, 'cert.pem')
  ], {stdio: 'pipe'});
  const cert = readFileSync(join(tlsDir, 'cert.pem'));
  const key = readFileSync(join(tlsDir, 'key.pem'));
  agent = new https.Agent({ca: cert});
  for(const actor of actors) actor.client.agent = agent;
  // The files are no longer needed; no TLS or actor private key is persisted.
  rmSync(tlsDir, {recursive: true, force: true});

  const app = express();
  app.use(express.raw({type: 'application/json', limit: '128kb'}));
  app.use((req, res, next) => {
    req.caseId = req.path.split('/')[2] || 'unclassified';
    req.requestRef = ref(`${req.caseId}:${++requestCount}`);
    reqEvent(req, 'received', {endpoint: req.path.endsWith('/copy') ? 'copy' : 'resource'});
    res.on('finish', () => {
      reqEvent(req, 'http-completed', {
        endpoint: req.path.endsWith('/copy') ? 'copy' : 'resource', status: res.statusCode
      });
      httpCompletions.emit('completed');
    });
    next();
  });

  const authorize = authorizeZcapInvocation({
    documentLoader,
    getExpectedValues({req}) {
      return {
        action: req.method === 'GET' ? 'read' : 'write',
        host: new URL(origin).host,
        target: `${origin}${req.path}`,
        rootInvocationTarget: req.path.endsWith('/copy') ?
          `${origin}${req.path}` : `${origin}${req.path.split('/').slice(0, 4).join('/')}`
      };
    },
    async getRootController({rootInvocationTarget}) {
      return rootInvocationTarget.endsWith('/copy') ? service.controller : alice.controller;
    },
    async getVerifier({keyId}) {
      const verificationMethod = documents.get(keyId);
      if(!verificationMethod) throw new Error('Unknown synthetic verification key');
      const key = await Ed25519VerificationKey2020.from(verificationMethod);
      return {verifier: key.verifier(), verificationMethod};
    },
    suiteFactory: () => new Ed25519Signature2020(),
    // Invocation timestamps have second precision; delegation dates may not.
    maxClockSkew: 1,
    maxChainLength: 16,
    onError({error}) {
      function collect(e, depth = 0) {
        if(!e || depth > 5) return;
        diagnostics.push({name: e.name, message: String(e.message).slice(0, 250)});
        collect(e.cause, depth + 1);
        for(const nested of e.errors || []) collect(nested, depth + 1);
      }
      collect(error);
      error.httpStatusCode ||= 403;
      throw error;
    },
    async inspectCapabilityChain({capabilityChain}) {
      const valid = !capabilityChain.some(capability => revoked.has(capability.id));
      return {valid, error: valid ? undefined : new Error('Revoked synthetic capability')};
    }
  });
  app.use(authorize);
  app.use((req, res, next) => {
    reqEvent(req, 'verified', {
      endpoint: req.path.endsWith('/copy') ? 'copy' : 'resource',
      action: req.zcap.capabilityAction,
      capabilityRef: ref(req.zcap.capability.id || req.zcap.capability),
      chainDepth: req.zcap.dereferencedChain.length,
      actorRef: ref(req.zcap.controller)
    });
    next();
  });
  app.post('/cases/:caseId/copy', async (req, res, next) => {
    try {
      const body = JSON.parse(req.body.toString('utf8'));
      let input = body.input.capability;
      let output = body.output.capability;
      let actor = service;
      if(body.mode === 'worker') {
        actor = worker;
        input = await service.client.delegate({
          capability: input, controller: worker.controller,
          allowedActions: ['read'], expires: new Date(Date.now() + 60_000)
        });
        output = await service.client.delegate({
          capability: output, controller: worker.controller,
          allowedActions: ['write'], expires: new Date(Date.now() + 60_000)
        });
      }
      const response = await actor.client.read({url: body.input.target, capability: input});
      const data = response.data;
      await actor.client.write({
        url: body.output.target, capability: output, json: data
      });
      res.json({copied: true});
    } catch(error) {
      if(error.status >= 400 && error.status < 500) {
        reqEvent(req, 'copy-refused', {status: error.status});
        res.status(error.status).json({refused: true});
      } else {
        next(error);
      }
    }
  });
  app.get('/cases/:caseId/objects/:name', async (req, res) => {
    const entry = resources.get(req.path);
    if(entry === undefined) return res.status(404).json({missing: true});
    reqEvent(req, 'effect', {operation: 'read', resourceRef: ref(req.path), valueDigest: digest(entry)});
    const gate = gates.get(req.caseId);
    if(gate) {
      gate.ready();
      await gate.released;
    }
    res.json({value: entry});
  });
  app.post('/cases/:caseId/objects/:name', (req, res) => {
    const body = JSON.parse(req.body.toString('utf8'));
    resources.set(req.path, body.value);
    reqEvent(req, 'effect', {operation: 'write', resourceRef: ref(req.path), valueDigest: digest(body.value)});
    res.json({written: true});
  });
  app.use((error, req, res, _next) => {
    const status = error.httpStatusCode || 500;
    reqEvent(req, 'refused', {status, errorType: error.name});
    res.status(status).json({refused: true, code: 'request-rejected'});
  });
  // Verification failures returned directly by the library have HTTP403 and
  // no handler effects. Record completed responses as independent observations.
  app.use((_req, res) => res.status(404).end());

  server = https.createServer({key, cert}, app);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  origin = `https://127.0.0.1:${server.address().port}`;

  async function fixture(caseId, {sameResource = false, inputController} = {}) {
    const base = `${origin}/cases/${caseId}`;
    const inputTarget = `${base}/objects/${sameResource ? 'shared' : 'input'}`;
    const outputTarget = sameResource ? inputTarget : `${base}/objects/output`;
    resources.set(new URL(inputTarget).pathname, 'synthetic-private-record');
    if(!sameResource) resources.set(new URL(outputTarget).pathname, 'empty');
    resources.set(`${new URL(base).pathname}/objects/other`, 'other-synthetic-record');
    const expiry = new Date(Date.now() + 180_000);
    const resourceRoot = rootId(`${base}/objects`);
    const input = await alice.client.delegate({
      capability: resourceRoot,
      invocationTarget: inputTarget, controller: inputController || service.controller,
      allowedActions: ['read'], expires: expiry
    });
    const output = await alice.client.delegate({
      capability: resourceRoot,
      invocationTarget: outputTarget, controller: service.controller,
      allowedActions: ['write'], expires: expiry
    });
    const copy = await service.client.delegate({
      invocationTarget: `${base}/copy`, controller: alice.controller,
      allowedActions: ['write'], expires: expiry
    });
    return {caseId, base, input, output, copy, inputTarget, outputTarget};
  }
  const copyBody = (f, mode) => ({
    mode, input: {target: f.inputTarget, capability: f.input},
    output: {target: f.outputTarget, capability: f.output}
  });
  async function observedRequest(operation) {
    try {
      return {status: (await operation()).status};
    } catch(error) {
      // A network exception is not evidence of an authorization refusal.
      if(error.status >= 400 && error.status < 500) return {status: error.status};
      throw error;
    }
  }
  function snapshotCase(caseId) {
    return [...resources].filter(([path]) => path.startsWith(`/cases/${caseId}/`))
      .map(([path, value]) => [ref(path), ref(String(value))]);
  }
  async function waitForHttpCompletion({caseId, start, status}) {
    const ready = () => ledger.slice(start).some(x => x.caseId === caseId &&
      x.stage === 'http-completed' && x.status === status);
    if(ready()) return;
    await new Promise((resolve, reject) => {
      const finish = () => {
        if(!ready()) return;
        clearTimeout(deadline);
        httpCompletions.off('completed', finish);
        resolve();
      };
      const deadline = setTimeout(() => {
        httpCompletions.off('completed', finish);
        reject(new Error(`Missing completed HTTP observation for ${caseId}`));
      }, 1000);
      httpCompletions.on('completed', finish);
      finish();
    });
  }
  async function recordRefusal({caseId, start, response, before, reasonPattern}) {
    // Client receipt can precede the server's finish callback. Wait for the
    // matching observation without fabricating an event or relaxing refusal.
    await waitForHttpCompletion({caseId, start, status: response.status});
    const events = ledger.slice(start);
    assert.ok(response.status >= 400 && response.status < 500);
    assert.ok(events.some(x => x.stage === 'http-completed' && x.status === response.status));
    assert.equal(events.filter(x => x.stage === 'effect').length, 0);
    assert.deepEqual(snapshotCase(caseId), before);
    if(reasonPattern) assert.ok(diagnostics.some(x => reasonPattern.test(x.message)), `Missing expected rejection category for ${caseId}`);
    results.push({
      caseId, responseStatus: response.status, observedEffects: 0,
      unchangedResourceState: true, stateBefore: before, stateAfter: snapshotCase(caseId),
      explicitHttpRefusal: true, outcome: 'pass'
    });
  }
  async function workerCapability(f, options = {}) {
    return service.client.delegate({
      capability: f.input, controller: worker.controller,
      allowedActions: ['read'], expires: new Date(Date.now() + 60_000), ...options
    });
  }
  async function adversarialChild(f, changes) {
    const document = await workerCapability(f);
    delete document.proof;
    Object.assign(document, changes);
    // This signing-only fixture option models a malicious delegator. The
    // resource verifier above receives no skip option and remains unchanged.
    return jsigs.sign(document, {
      documentLoader,
      suite: new Ed25519Signature2020({signer: service.signer}),
      purpose: new CapabilityDelegation({
        parentCapability: f.input, _skipLocalValidationForTesting: true
      })
    });
  }
  function revoke(caseId, ids) {
    ids.forEach(id => revoked.add(id));
    ++policyVersion;
    event(caseId, 'revocation-committed', {capabilityRefs: ids.map(ref)});
    return sequence;
  }

  for(const [caseId, mode, sameResource] of [
    ['valid-direct', 'direct', false],
    ['valid-worker', 'worker', false],
    ['same-resource-distinct-authorities', 'worker', true]
  ]) {
    const f = await fixture(caseId, {sameResource});
    const start = ledger.length;
    const response = await alice.client.write({
      url: `${f.base}/copy`, capability: f.copy, json: copyBody(f, mode)
    });
    assert.equal(response.status, 200);
    assert.equal(resources.get(new URL(f.outputTarget).pathname), 'synthetic-private-record');
    const events = ledger.slice(start);
    const effects = events.filter(x => x.stage === 'effect');
    assert.deepEqual(effects.map(x => x.operation), ['read', 'write']);
    assert.equal(effects[0].valueDigest, effects[1].valueDigest);
    const depths = events.filter(x => x.stage === 'verified' && x.endpoint === 'resource').map(x => x.chainDepth);
    assert.deepEqual(depths, mode === 'worker' ? [3, 3] : [2, 2]);
    results.push({caseId, responseStatus: response.status, observedEffects: effects.length, resourceChainDepths: depths, outcome: 'pass'});
  }

  for(const kind of ['action-expansion', 'target-expansion', 'wrong-signer', 'tampered-ancestor', 'expiry-expansion', 'expired-leaf']) {
    const f = await fixture(kind);
    const before = snapshotCase(kind);
    let options = {};
    let method = 'read';
    let target = f.inputTarget;
    let actor = worker;
    let reasonPattern;
    let adversarialChanges;
    if(kind === 'action-expansion') {
      adversarialChanges = {allowedAction: ['write']};
      method = 'write';
      reasonPattern = /allowedAction.*delegated capability/;
    } else if(kind === 'target-expansion') {
      target = `${f.base}/objects/other`;
      adversarialChanges = {invocationTarget: target};
      reasonPattern = /invocationTarget.*delegated capability/;
    } else if(kind === 'wrong-signer') {
      actor = stranger;
    } else if(kind === 'tampered-ancestor') {
      f.input = structuredClone(f.input);
      f.input.allowedAction = ['read', 'write'];
    } else if(kind === 'expiry-expansion') {
      adversarialChanges = {expires: new Date(Date.now() + 300_000).toISOString()};
      reasonPattern = /expir.*parent/i;
    } else if(kind === 'expired-leaf') {
      f.input = await alice.client.delegate({
        capability: f.input.parentCapability, invocationTarget: f.inputTarget,
        controller: service.controller, allowedActions: ['read'],
        now: Date.now() - 30_000, expires: new Date(Date.now() + 180_000)
      });
      options.now = Date.now() - 20_000;
      options.expires = new Date(Date.now() - 10_000);
      reasonPattern = /expired/i;
    }
    const capability = adversarialChanges ?
      await adversarialChild(f, adversarialChanges) : await workerCapability(f, options);
    const start = ledger.length;
    diagnostics.length = 0;
    const response = await observedRequest(() => actor.client[method]({
      url: target, capability, ...(method === 'write' ? {json: {value: 'prohibited-change'}} : {})
    }));
    await recordRefusal({caseId: kind, start, response, before, reasonPattern});
  }

  {
    const caseId = 'argument-delegated-to-wrong-service';
    const f = await fixture(caseId, {inputController: stranger.controller});
    const before = snapshotCase(caseId);
    const start = ledger.length;
    const response = await observedRequest(() => alice.client.write({
      url: `${f.base}/copy`, capability: f.copy, json: copyBody(f, 'worker')
    }));
    await recordRefusal({caseId, start, response, before});
    assert.ok(ledger.slice(start).some(x => x.stage === 'verified' && x.endpoint === 'copy'));
  }

  {
    const caseId = 'signed-body-substitution';
    const f = await fixture(caseId);
    const before = snapshotCase(caseId);
    const original = copyBody(f, 'direct');
    const headers = await signCapabilityInvocation({
      url: `${f.base}/copy`, method: 'post', json: original,
      headers: {date: new Date().toUTCString(), 'content-type': 'application/json'},
      invocationSigner: alice.signer, capability: f.copy, capabilityAction: 'write'
    });
    const altered = {...original, mode: 'worker'};
    const start = ledger.length;
    diagnostics.length = 0;
    const response = await new Promise((resolve, reject) => {
      const request = https.request(`${f.base}/copy`, {method: 'POST', headers, agent}, res => {
        res.resume();
        res.on('end', () => resolve({status: res.statusCode}));
      });
      request.setTimeout(5000, () => request.destroy(new Error('Local request timeout')));
      request.on('error', reject);
      request.end(JSON.stringify(altered));
    });
    await recordRefusal({caseId, start, response, before, reasonPattern: /digest.*body/i});
  }

  {
    const caseId = 'revoked-ancestor-live-leaf';
    const f = await fixture(caseId);
    const capability = await workerCapability(f);
    const start = ledger.length;
    assert.equal((await worker.client.read({url: f.inputTarget, capability})).status, 200);
    const commitSequence = revoke(caseId, [f.input.id]);
    const afterCommit = ledger.length;
    const before = snapshotCase(caseId);
    const response = await observedRequest(() => worker.client.read({url: f.inputTarget, capability}));
    assert.equal(response.status, 403);
    assert.equal(ledger.slice(afterCommit).filter(x => x.stage === 'effect').length, 0);
    assert.deepEqual(snapshotCase(caseId), before);
    const all = ledger.slice(start);
    assert.equal(all.filter(x => x.stage === 'effect').length, 1);
    assert.ok(all.find(x => x.stage === 'effect').sequence < commitSequence);
    assert.ok(Date.parse(capability.expires) > Date.now() + 30_000);
    results.push({caseId, responseStatus: response.status, observedEffects: 1,
      preCommitEffects: 1, postCommitEffects: 0, leafUnexpired: true, commitSequence,
      leafExpiresAt: capability.expires, explicitHttpRefusal: true, outcome: 'pass'});
  }

  {
    const caseId = 'inflight-and-post-commit';
    const f = await fixture(caseId);
    const capability = await workerCapability(f);
    let ready;
    let release;
    const started = new Promise(resolve => {ready = resolve;});
    const released = new Promise(resolve => {release = resolve;});
    gates.set(caseId, {ready, released, release});
    const start = ledger.length;
    const inflight = worker.client.read({url: f.inputTarget, capability});
    await started;
    const commitSequence = revoke(caseId, [f.input.id]);
    const afterCommit = ledger.length;
    const refused = await observedRequest(() => worker.client.read({url: f.inputTarget, capability}));
    release();
    assert.equal((await inflight).status, 200);
    gates.delete(caseId);
    assert.equal(refused.status, 403);
    assert.equal(ledger.slice(afterCommit).filter(x => x.stage === 'effect').length, 0);
    const all = ledger.slice(start);
    const effect = all.find(x => x.stage === 'effect');
    assert.ok(effect.sequence < commitSequence);
    const completed = all.find(x => x.stage === 'http-completed' && x.requestRef === effect.requestRef);
    assert.ok(completed.sequence > commitSequence && completed.status === 200);
    results.push({caseId, responseStatus: refused.status, observedEffects: 1,
      preCommitEffects: 1, postCommitEffects: 0, inflightCompletionStatus: 200,
      effectRequestRef: effect.requestRef, leafExpiresAt: capability.expires,
      commitSequence, outcome: 'pass'});
  }

  {
    const caseId = 'independent-authority-revocation-control';
    const f = await fixture(caseId);
    const capability = await workerCapability(f);
    const start = ledger.length;
    const commitSequence = revoke(caseId, [f.copy.id]);
    const refused = await observedRequest(() => alice.client.write({
      url: `${f.base}/copy`, capability: f.copy, json: copyBody(f, 'worker')
    }));
    assert.equal(refused.status, 403);
    assert.equal((await worker.client.read({url: f.inputTarget, capability})).status, 200);
    const effects = ledger.slice(start).filter(x => x.stage === 'effect');
    assert.equal(effects.length, 1);
    assert.ok(effects[0].sequence > commitSequence);
    results.push({caseId, responseStatus: refused.status, observedEffects: 1,
      independentlyGrantedReadStillAllowed: true, commitSequence, outcome: 'pass'});
  }

  evidence = {
    stage: 'local-full-matrix-executed-awaiting-evidence-audit',
    actors: actors.length,
    libraryVersions: JSON.parse(readFileSync(new URL('package.json', import.meta.url))).dependencies,
    actualRequestTransport: 'TLS-verified loopback HTTPS; task-specific trusted certificate, no global TLS bypass',
    dependencyLockSha256: digest(readFileSync(new URL('package-lock.json', import.meta.url), 'utf8')),
    results, ledger,
    profile: {maxClockSkewSeconds: 1, maxChainLength: 16,
      revocation: 'Explicit synchronous local control-plane commit; resource native chain-inspection hook checks revoked ancestor IDs. Not a default or universal revocation API.'},
    limits: 'One local reference stack with synthetic records and separate actor keys; not a second implementation, independent review, full ZCAP specification conformance, model safety, or production adoption.'
  };
  console.log(JSON.stringify({cases: results.length, results, stage: evidence.stage}));
} catch(error) {
  console.error(JSON.stringify({
    name: error.name, status: error.status,
    message: String(error.message).slice(0, 200), diagnostics
  }));
  evidence = {stage: 'incomplete-run-not-a-completed-matrix', results, ledger,
    failureType: error.name, failureStatus: error.status};
  process.exitCode = 1;
} finally {
  // Release fixture gates even on failure so cleanup cannot hang behind an
  // intentionally delayed response.
  for(const gate of gates.values()) gate.release();
  if(server?.listening) await new Promise(resolve => server.close(resolve));
  agent?.destroy();
  rmSync(tlsDir, {recursive: true, force: true});
  if(evidence) {
    evidence.cleanup = {listenerClosed: !server?.listening, tlsFilesRemoved: !existsSync(tlsDir)};
    evidence.sourceSha256 = createHash('sha256').update(readFileSync(new URL('probe.mjs', import.meta.url))).digest('hex');
    if(process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(evidence, null, 2) + '\n');
  }
}
