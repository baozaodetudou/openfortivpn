// End-to-end private pipe tests; no gateway, helper, adapter or network mutation.
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
const executable = process.argv[2];
const engine = process.argv[3];
if (!executable) throw new Error('A test driver is required');
const attempt = '00000000-0000-4000-8000-000000000001';
for (const scenario of ['otp', 'lease-grant', 'lease-deny', 'wrong-attempt', 'eof']) {
  const child = spawn(executable, [scenario === 'otp' ? 'otp' : 'lease'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const timer = setTimeout(() => child.kill(), 5000);
  let stderr = '', stdout = '', responded = false;
  child.stdout.on('data', chunk => stdout += chunk);
  child.stderr.on('data', chunk => {
    stderr += chunk;
    for (const line of stderr.split('\n').filter(Boolean)) {
      let event; try { event = JSON.parse(line); } catch { continue; }
      if (responded || !event.requestId) continue;
      responded = true;
      assert.equal(event.attemptId, attempt);
      assert.match(event.requestId, /^[a-f0-9]{32}$/);
      if (scenario === 'eof') { child.stdin.end(); continue; }
      const id = scenario === 'wrong-attempt' ? '00000000-0000-4000-8000-000000000002' : attempt;
      const action = scenario === 'otp' ? 'auth_response' : 'lease_decision';
      const response = scenario === 'otp' ? 'synthetic-otp' : scenario === 'lease-deny' ? 'deny' : 'grant';
      child.stdin.end(`OFV2 ${id} ${event.requestId} ${action} ${Buffer.from(response).toString('base64')}\n`);
    }
  });
  const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
  clearTimeout(timer);
  assert.equal(code, ['otp', 'lease-grant'].includes(scenario) ? 0 : 2, scenario);
  assert(!`${stderr}${stdout}`.includes('synthetic-otp'), 'response escaped into an output stream');
  assert(responded, 'driver emitted no challenge');
}
process.stdout.write('Private pipe challenge/lease, denial, stale attempt, EOF and no-secret-output checks passed\n');
if (process.platform !== 'win32') {
  for (const scenario of ['native', 'native-cancel', 'native-deny', 'native-unsafe', 'native-proxy-route']) {
    const unsafe = ['native-unsafe', 'native-proxy-route'].includes(scenario);
    const child = spawn(executable, [unsafe || scenario === 'native-cancel' ? scenario : 'native'], { stdio: ['pipe', 'pipe', 'pipe'] });
    const timer = setTimeout(() => child.kill(), 5000);
    let buffered = '', events = [];
    child.stderr.on('data', chunk => {
      buffered += chunk;
      while (buffered.includes('\n')) {
        const end = buffered.indexOf('\n'), line = buffered.slice(0, end);
        buffered = buffered.slice(end + 1);
        const event = JSON.parse(line);
        assert.equal(event.attemptId, attempt);
        assert(line.length < 2048, 'resource frame exceeds C event buffer');
        events.push(event);
        if (event.event === 'network_commit' || event.event === 'network_release') {
          const result = scenario === 'native-deny' ? 'deny' : event.event === 'network_commit' ? 'applied' : 'released';
          const reply = () => child.stdin.write(`OFV2 ${attempt} ${event.requestId} network_result ${Buffer.from(result).toString('base64')}\n`);
          if (scenario === 'native-cancel' && event.event === 'network_commit') setTimeout(reply, 200);
          else reply();
        }
      }
    });
    const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
    clearTimeout(timer);
    const successful = ['native', 'native-cancel'].includes(scenario);
    assert.equal(code, successful ? 0 : 2);
    if (unsafe) assert.equal(events.length, 0, 'unsafe plan must emit no partial plan');
    else {
      assert.deepEqual(events.slice(0, 3).map(e => e.event), ['network_begin', 'network_resource', 'network_commit']);
      assert.equal(events[0].resourceCount, 1);
      assert.equal(events[0].binding.transportAddress, '127.0.0.1', 'bind actual TLS socket peer, including a proxy');
      assert.equal(events[1].ordinal, 0);
      assert.equal(events[1].resource.spec.destination, '10.0.0.0/8');
      assert.equal(events[3].success, successful);
      if (successful) assert.equal(events[4].event, 'network_release');
    }
  }
  process.stdout.write('Bounded native resource plan, applied/released responses and unsafe plan rejection passed\n');
  for (const scenario of ['grant', 'deny', 'eof']) {
    const child = spawn(executable, ['launch'], { stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
    let exited = false;
    const exit = new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('exit', () => { exited = true; });
      child.on('close', resolve);
    });
    const timer = setTimeout(() => child.kill(), 5000);
    // Verify that exec completed but the driver cannot proceed before grant.
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(exited, false, 'engine bypassed the launch barrier');
    child.stdio[3].end(scenario === 'eof' ? undefined : Buffer.from([scenario === 'grant' ? 1 : 2]));
    assert.equal(await exit, scenario === 'grant' ? 0 : 2, scenario);
    clearTimeout(timer);
  }
  process.stdout.write('Launch barrier waits for durable-owner grant and rejects denial/parent EOF\n');
  if (engine) {
    for (const scenario of ['grant', 'deny', 'eof']) {
      // Missing configuration and host guarantee that this cannot open a VPN.
      const child = spawn(engine, ['--json-events', '--manager-launch-fd=3', '-c', '/nonexistent/ofv-launch-test.conf'],
        { stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
      let output = '', exited = false;
      child.stdout.on('data', chunk => output += chunk);
      child.stderr.on('data', chunk => output += chunk);
      const exit = new Promise((resolve, reject) => {
        child.on('error', reject);
        child.on('exit', () => { exited = true; });
        child.on('close', resolve);
      });
      const timer = setTimeout(() => child.kill(), 5000);
      await new Promise(resolve => setTimeout(resolve, 50));
      assert.equal(exited, false, 'actual engine bypassed startup barrier');
      assert.equal(output, '', 'actual engine read configuration before durable registration');
      child.stdio[3].end(scenario === 'eof' ? undefined : Buffer.from([scenario === 'grant' ? 1 : 2]));
      assert.notEqual(await exit, 0);
      clearTimeout(timer);
      assert.equal(output.includes('Could not load configuration file'), scenario === 'grant');
    }
    process.stdout.write('Actual C CLI startup barrier precedes configuration and rejects parent EOF\n');
  }
}
