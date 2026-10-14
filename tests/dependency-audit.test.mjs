import test from 'node:test';
import assert from 'node:assert/strict';
import { packageVersions, validateAdvisories } from '../scripts/audit-npm.mjs';

test('all installed versions are scanned, including nested and development packages', () => {
  const graph = packageVersions([{ dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } } }, devDependencies: { b: { version: '3.0.0' } } }]);
  assert.deepEqual(graph, { a: ['1.0.0'], b: ['2.0.0', '3.0.0'] });
  assert.throws(() => packageVersions([]), /empty/);
  assert.throws(() => packageVersions([{ dependencies: { a: { version: {} } } }]), /Unresolved/);
});
test('high advisories block and invalid registry responses cannot count as clean scans', () => {
  const advisory = { id: 123, title: 'Synthetic advisory', severity: 'high' };
  assert.equal(validateAdvisories({ package: [advisory] }).blocking.length, 1);
  assert.equal(validateAdvisories({ package: [{ ...advisory, severity: 'low' }] }).blocking.length, 0);
  assert.throws(() => validateAdvisories({ error: 'registry unavailable' }), /Invalid/);
  assert.throws(() => validateAdvisories({ package: [{ ...advisory, severity: 'future' }] }), /Invalid/);
});
