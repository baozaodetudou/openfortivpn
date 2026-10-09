import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

export const platforms = ['Linux-x64', 'macOS-arm64', 'macOS-x86_64', 'Windows-x64', 'Linux-headless-x86_64'];
const requiredChecks = ['network-recovery', 'password-gateway', 'upgrade', 'rollback'];
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const assets = /\.(deb|dmg|msi|exe|tar\.gz)$/;

export function walk(root) {
  return fs.readdirSync(root, { withFileTypes: true }).flatMap(entry => {
    const file = path.join(root, entry.name);
    if (entry.isDirectory() && entry.name.endsWith('.app')) return [];
    if (entry.isSymbolicLink()) throw new Error(`Symlink is not a release artifact: ${file}`);
    return entry.isDirectory() ? walk(file) : [file];
  });
}

export function assemble(root, commit, evidence, acceptance, official = false) {
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('A full source commit is required');
  const names = new Set();
  const allAssets = walk(root).filter(file => assets.test(file) && !file.includes('.app' + path.sep));
  const digests = new Map();
  for (const file of allAssets) {
    const name = path.basename(file).replaceAll(' ', '.');
    if (names.has(name)) throw new Error(`Duplicate release asset name: ${name}`);
    names.add(name);
    digests.set(name, hash(file));
  }
  const seen = new Set();
  for (const item of evidence) {
    if (item.schemaVersion !== 1 || item.commit !== commit || !platforms.includes(item.platform) || seen.has(item.platform)) {
      throw new Error('Invalid, duplicate or mismatched platform evidence');
    }
    seen.add(item.platform);
    if (!item.assets?.length || !item.components?.manager || !item.components?.engine || !item.sbom) {
      throw new Error(`Incomplete bundle evidence: ${item.platform}`);
    }
    if (item.components.engine.eventProtocol !== 2 || !item.components.engine.version) throw new Error('Unsupported bundled engine protocol');
    for (const asset of item.assets) {
      if (digests.get(asset.name) !== asset.sha256) throw new Error(`Asset changed after verification: ${asset.name}`);
      digests.delete(asset.name);
    }
    const sbomFile = walk(root).find(file => path.basename(file) === item.sbom.name);
    if (!sbomFile || hash(sbomFile) !== item.sbom.sha256) throw new Error(`Missing or changed SBOM: ${item.platform}`);
    if (official) {
      if (item.platform.startsWith('macOS') && (item.signing !== 'developer-id' || item.notarization !== 'verified')) throw new Error('Official macOS artifacts require verified signing and notarization');
      if (item.platform === 'Windows-x64' && item.signing !== 'authenticode') throw new Error('Official Windows artifacts require verified Authenticode');
      const functional = acceptance?.platforms?.[item.platform];
      if (acceptance?.schemaVersion !== 1 || acceptance.commit !== commit || !functional?.evidenceId || requiredChecks.some(check => functional.checks?.[check] !== 'passed')) {
        throw new Error(`Missing functional acceptance evidence: ${item.platform}`);
      }
    }
  }
  if (platforms.some(platform => !seen.has(platform))) throw new Error('The complete platform bundle is required');
  if (digests.size) throw new Error('An installer has no platform verification evidence');
  const versions = new Set(evidence.map(item => item.components.manager.version));
  if (versions.size !== 1 || ![...versions][0]) throw new Error('Manager versions differ across platforms');
  return {
    schemaVersion: 1, commit, managerVersion: [...versions][0],
    releaseMode: official ? 'official' : 'candidate',
    platforms: evidence,
    functionalAcceptance: acceptance?.commit === commit ? acceptance : null,
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const { values } = parseArgs({ options: {
    root: { type: 'string' }, commit: { type: 'string' }, output: { type: 'string' },
    acceptance: { type: 'string' }, official: { type: 'boolean', default: false },
  } });
  if (!values.root || !values.commit || !values.output) throw new Error('--root, --commit and --output are required');
  const files = walk(values.root);
  const evidence = files.filter(file => /^release-evidence-.*\.json$/.test(path.basename(file))).map(file => JSON.parse(fs.readFileSync(file, 'utf8')));
  const acceptance = values.acceptance ? JSON.parse(fs.readFileSync(values.acceptance, 'utf8')) : null;
  const manifest = assemble(values.root, values.commit, evidence, acceptance, values.official);
  fs.writeFileSync(values.output, JSON.stringify(manifest, null, 2) + '\n');
}
