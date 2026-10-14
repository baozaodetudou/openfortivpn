import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../app/package.json', import.meta.url));
const ts = require('typescript');
const source = readFileSync(new URL('../app/src/lib/services/manager-state.ts', import.meta.url), 'utf8');
const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const context = vm.createContext({ exports: {}, Error, Map, Promise });
vm.runInContext(output, context);
const { mergeInstance, mergeProfile, mergeLogEvents, errorText, EventSubscriptions, SnapshotAuthority } = context.exports;
const controllerSource = readFileSync(new URL('../app/src/lib/services/profile-controller.ts', import.meta.url), 'utf8');
const controllerContext = vm.createContext({ exports: {}, Error, Set, Promise });
vm.runInContext(ts.transpileModule(controllerSource, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, controllerContext);
const { CertificatePrompts, LatestRequest, ProfileController } = controllerContext.exports;
const instance = (attemptSequence, revision = 0) => ({ id: `attempt-${attemptSequence}`, profileId: 'one', profileGeneration: 7, attemptSequence, revision, startedAt: 100 });

test('a reconnect under the same intent replaces its old attempt even within one clock second', () => {
  let state = [instance(1, 10)];
  state = mergeInstance(state, instance(2));
  assert.equal(state[0].id, 'attempt-2');
  assert.equal(mergeInstance(state, instance(1, 99)), state);
  assert.equal(mergeInstance(state, { ...instance(3), profileGeneration: 6 }), state);
  assert.equal(mergeInstance(state, { ...instance(2, 99), id: 'foreign-attempt' }), state);
  state = mergeInstance(state, instance(2, 1));
  assert.equal(state[0].revision, 1);
  assert.equal(mergeInstance(state, instance(2)), state);
});
test('older profile replies never overwrite a newer revision and log retention is deterministic', () => {
  const profile = revision => ({ profile: { id: 'one', name: 'one', revision } });
  const state = [profile(3)];
  assert.equal(mergeProfile(state, profile(2)), state);
  assert.equal(mergeProfile(state, profile(4))[0].profile.revision, 4);
  const logs = Array.from({ length: 600 }, (_, id) => ({ id, instanceId: 'one', timestamp: 100 }));
  const retained = mergeLogEvents(logs, [logs[599]], 400);
  assert.equal(retained.length, 400);
  assert.equal(retained[0].id, 200);
  assert.equal(retained[399].id, 599);
});
test('an event subscription resolving after unmount is removed and cannot update the disposed page', async () => {
  let resolve, handler, removed = 0, received = 0;
  const subscriptions = new EventSubscriptions((_name, callback) => {
    handler = callback;
    return new Promise(done => { resolve = done; });
  }, () => assert.fail('unexpected error'));
  subscriptions.add('event', () => received++);
  subscriptions.dispose();
  handler({ payload: {} });
  resolve(() => removed++);
  await Promise.resolve();
  assert.equal(received, 0);
  assert.equal(removed, 1);
  subscriptions.dispose();
  assert.equal(removed, 1);
});
test('structured IPC failures show their message without exposing arbitrary response fields', () => {
  assert.equal(errorText({ code: 'RECOVERY_REQUIRED', message: '请恢复配置仓库', password: 'synthetic' }), '请恢复配置仓库');
  assert.equal(errorText({ error: { message: '配置忙' } }), '配置忙');
  assert.ok(!errorText({ password: 'synthetic' }).includes('synthetic'));
});
test('newer events and refreshes prevent stale snapshots from replacing current state', () => {
  const authority = new SnapshotAuthority();
  const first = authority.begin();
  assert.equal(authority.accepts(first, 'profiles'), true);
  authority.changed('profiles');
  authority.changed('privilege');
  assert.equal(authority.accepts(first, 'profiles'), false);
  assert.equal(authority.accepts(first, 'privilege'), false);
  assert.equal(authority.accepts(first, 'remote'), true);
  const second = authority.begin();
  assert.equal(authority.current(first), false);
  assert.equal(authority.accepts(second, 'profiles'), true);
  authority.changed('remote');
  assert.equal(authority.accepts(second, 'remote'), false);
  assert.equal(authority.accepts(second, 'recovery'), true);
  authority.dispose();
  assert.equal(authority.current(second), false);
  assert.equal(authority.current(authority.begin()), false);
});

const certificateView = (revision = 7) => ({ profile: { id: 'one', name: 'Synthetic', host: 'vpn.example.test', port: 443, revision }, passwordStored: true });
const certificateEvent = (id = 'attempt-1') => ({ instanceId: id, profileId: 'one', profileRevision: 7, host: 'vpn.example.test', port: 443, payload: { event: 'cert_error', digest: 'ab'.repeat(32) } });
const certificateInstance = (id = 'attempt-1') => ({ id, profileId: 'one', status: 'failed' });
test('certificate prompts reject an old attempt, changed target or revision and bound event memory', () => {
  const queue = new CertificatePrompts(() => true, 2, 4);
  const view = certificateView(), instance = certificateInstance();
  for (const event of [certificateEvent('attempt-old'), { ...certificateEvent(), host: 'changed.example.test' }, { ...certificateEvent(), profileRevision: 6 }, { ...certificateEvent(), port: 8443 }]) {
    assert.equal(queue.receive(event, instance, view), null);
  }
  const first = queue.receive(certificateEvent(), instance, view);
  assert.equal(first.profileRevision, 7);
  queue.receive(certificateEvent(), instance, view);
  assert.equal(queue.close(), null);
  assert.equal(queue.receive(certificateEvent(), instance, view), null);
  for (let i = 0; i < 100; i++) {
    const id = `attempt-${i + 2}`;
    assert.equal(queue.receive(certificateEvent(id), certificateInstance(id), view).instanceId, id);
    queue.close();
  }
  assert.equal(queue.seen.size, 4);
  queue.dispose();
  assert.equal(queue.current(), null);
});
test('late authentication and recovery replies cannot update a disposed page or supersede a newer reply', () => {
  let alive = true;
  const requests = new LatestRequest(() => alive);
  const older = requests.begin(), newer = requests.begin();
  assert.equal(requests.current(older), false);
  assert.equal(requests.current(newer), true);
  alive = false;
  assert.equal(requests.current(newer), false);
});
test('certificate trust awaits backend process cleanup proof and uses the prompted revision', async () => {
  const calls = [];
  let proveStopped;
  const controller = new ProfileController((command, args) => {
    calls.push({ command, args });
    if (command === 'await_profile_stopped') return new Promise(resolve => { proveStopped = resolve; });
    return Promise.resolve(certificateView(8));
  }, () => true);
  const queue = new CertificatePrompts(() => true);
  const prompt = queue.receive(certificateEvent(), certificateInstance(), certificateView());
  const pending = controller.trust(prompt, () => certificateView(), () => {});
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'await_profile_stopped');
  proveStopped(certificateInstance());
  await pending;
  assert.equal(calls[1].command, 'save_profile');
  assert.equal(calls[1].args.input.expectedRevision, 7);
  assert.equal(calls[1].args.input.password, null);
  assert.equal(calls[1].args.input.profile.trustedCert, 'ab'.repeat(32));
});
test('changed certificate targets and disposal during backend wait never submit a trust write', async () => {
  for (const scenario of ['revision', 'host', 'attempt', 'disposal']) {
    let alive = true, resolve;
    const calls = [];
    const controller = new ProfileController((command) => {
      calls.push(command);
      return new Promise(done => { resolve = done; });
    }, () => alive);
    const queue = new CertificatePrompts(() => true);
    const prompt = queue.receive(certificateEvent(), certificateInstance(), certificateView());
    const pending = controller.trust(prompt, () => scenario === 'revision' ? certificateView(8) : scenario === 'host' ? { ...certificateView(), profile: { ...certificateView().profile, host: 'changed.example.test' } } : certificateView(), () => {});
    if (scenario === 'disposal') alive = false;
    resolve(certificateInstance(scenario === 'attempt' ? 'attempt-other' : 'attempt-1'));
    await assert.rejects(pending);
    assert.equal(calls.length, 1);
  }
});
test('desktop deletes carry the observed revision and explicitly stop the active attempt first', async () => {
  let payload;
  const controller = new ProfileController(async (command, args) => { payload = { command, args }; }, () => true);
  await controller.delete(certificateView());
  assert.equal(payload.command, 'delete_profile');
  assert.equal(payload.args.expectedRevision, 7);
  assert.equal(payload.args.stopFirst, true);
});
