import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { assemble, installersForPlatform, platforms } from '../scripts/release-manifest.mjs';

const commit = 'a'.repeat(40);
const hash = value => createHash('sha256').update(value).digest('hex');
test('desktop evidence excludes Debian internals while headless retains its distributable archive', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ofv-installers-'));
  t.after(() => fs.rmSync(root, { recursive: true }));
  const desktop = path.join(root, 'desktop'), headless = path.join(root, 'headless');
  fs.mkdirSync(path.join(desktop, 'deb', 'staging'), { recursive: true });
  fs.mkdirSync(headless);
  const deb = path.join(desktop, 'deb', 'manager.deb');
  for (const file of [deb, path.join(desktop, 'deb', 'staging', 'control.tar.gz'), path.join(desktop, 'deb', 'staging', 'data.tar.gz')]) fs.writeFileSync(file, 'synthetic-package');
  for (const name of ['manager.msi', 'manager.exe', 'manager.dmg']) fs.writeFileSync(path.join(desktop, name), 'synthetic-package');
  assert.deepEqual(installersForPlatform(desktop, 'Linux-x64'), [deb]);
  assert.deepEqual(installersForPlatform(desktop, 'Windows-x64').map(file => path.basename(file)).sort(), ['manager.exe', 'manager.msi']);
  for (const platform of ['macOS-arm64', 'macOS-x86_64']) assert.deepEqual(installersForPlatform(desktop, platform), [path.join(desktop, 'manager.dmg')]);
  for (const name of ['manager.deb', 'manager.tar.gz']) fs.writeFileSync(path.join(headless, name), 'synthetic-package');
  assert.deepEqual(installersForPlatform(headless, 'Linux-headless-x86_64').map(file => path.basename(file)).sort(), ['manager.deb', 'manager.tar.gz']);
  assert.throws(() => installersForPlatform(root, 'unknown'), /Unknown release platform/);
});
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ofv-release-'));
  t.after(() => fs.rmSync(root, { recursive: true }));
  const evidence = platforms.map(platform => {
    const installer = `${platform}.deb`, sbom = `sbom-${platform}.cdx.json`;
    fs.writeFileSync(path.join(root, installer), platform);
    fs.writeFileSync(path.join(root, sbom), '{}');
    return { schemaVersion: 1, commit, platform,
      components: { manager: { version: '1' }, engine: { version: '2', eventProtocol: 2 } },
      assets: [{ name: installer, sha256: hash(platform) }],
      sbom: { name: sbom, sha256: hash('{}') },
      signing: platform.startsWith('macOS') ? 'developer-id' : 'authenticode', notarization: 'verified' };
  });
  return { root, evidence };
}
test('a candidate contains every platform and hashes the verified artifacts', t => {
  const { root, evidence } = fixture(t);
  assert.equal(assemble(root, commit, evidence, null).releaseMode, 'candidate');
  fs.appendFileSync(path.join(root, evidence[0].assets[0].name), 'changed');
  assert.throws(() => assemble(root, commit, evidence, null), /changed after verification/);
});
test('official publication requires real functional evidence in addition to signing', t => {
  const { root, evidence } = fixture(t);
  assert.throws(() => assemble(root, commit, evidence, null, true), /functional acceptance/);
  const acceptance = { schemaVersion: 1, commit, platforms: Object.fromEntries(platforms.map(platform => [platform, { evidenceId: 'controlled-run', checks: { 'network-recovery': 'passed', 'password-gateway': 'passed', upgrade: 'passed', rollback: 'passed' } }])) };
  assert.equal(assemble(root, commit, evidence, acceptance, true).releaseMode, 'official');
  evidence[1].notarization = 'not-run';
  assert.throws(() => assemble(root, commit, evidence, acceptance, true), /notarization/);
});
test('duplicate names, missing platforms and source mismatch fail closed', t => {
  const { root, evidence } = fixture(t);
  assert.throws(() => assemble(root, commit, evidence.slice(1), null), /complete platform/);
  evidence[0].commit = 'b'.repeat(40);
  assert.throws(() => assemble(root, commit, evidence, null), /mismatched/);
  fs.mkdirSync(path.join(root, 'duplicate'));
  fs.copyFileSync(path.join(root, evidence[0].assets[0].name), path.join(root, 'duplicate', evidence[0].assets[0].name));
  assert.throws(() => assemble(root, commit, evidence, null), /Duplicate/);
});
