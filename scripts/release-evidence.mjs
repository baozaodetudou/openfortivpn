// Run only after the platform's bundle validation and installation smoke test.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { walk } from './release-manifest.mjs';

const { values } = parseArgs({ options: {
  platform: { type: 'string' }, root: { type: 'string' }, engine: { type: 'string' },
  manager: { type: 'string' }, helper: { type: 'string' }, manifest: { type: 'string' },
  'app-bundle': { type: 'string' },
  'helper-manifest': { type: 'string' },
} });
for (const field of ['platform', 'root', 'engine', 'manager', 'manifest']) if (!values[field]) throw new Error(`--${field} is required`);
if (!/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA ?? '')) throw new Error('GITHUB_SHA is required');
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const run = (file, args, options = {}) => execFileSync(file, args, { encoding: 'utf8', timeout: 30_000, maxBuffer: 64 * 1024 * 1024, ...options });
const engine = JSON.parse(run(values.engine, ['--capabilities-json'], { timeout: 5_000, maxBuffer: 64 * 1024 }));
if (engine.protocolVersion !== 2) throw new Error('Bundled engine protocol is unsupported');
const metadata = JSON.parse(run('cargo', ['metadata', '--locked', '--format-version', '1', '--manifest-path', values.manifest], { timeout: 120_000 }));
const managerPackage = metadata.packages.find(pkg => metadata.workspace_members.includes(pkg.id) && pkg.name.startsWith('openfortivpn-manager'));
if (!managerPackage) throw new Error('Manager metadata is missing');
const component = (name, file, version, protocol) => ({ name, version, sha256: hash(file), ...(protocol ? { eventProtocol: protocol } : {}) });
const components = {
  manager: component(managerPackage.name, values.manager, managerPackage.version),
  engine: component('openfortivpn', values.engine, engine.version, engine.protocolVersion),
};
if (values.helper) {
  const helper = JSON.parse(run(values.helper, ['--capabilities-json']));
  components.helper = { ...component('openfortivpn-manager-helper', values.helper, helper.version), protocol: helper.protocolVersion };
}
const helperMetadata = values['helper-manifest'] ? JSON.parse(run('cargo', ['metadata', '--locked', '--format-version', '1', '--manifest-path', values['helper-manifest']], { timeout: 120_000 })) : null;
const cargoPackages = [...new Map([...metadata.packages, ...(helperMetadata?.packages ?? [])].map(pkg => [pkg.id, pkg])).values()];
const packages = cargoPackages.map(pkg => ({
  type: 'library', name: pkg.name, version: pkg.version,
  'bom-ref': pkg.id, purl: `pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`,
  ...(pkg.license ? { licenses: [{ expression: pkg.license }] } : {}),
}));
if (!values.platform.includes('headless')) {
  // Windows Corepack is a .cmd shim; execFile cannot launch it directly.
  // Keep the shell command constant and pass the workspace only through cwd.
  const trees = JSON.parse(process.platform === 'win32'
    ? run('cmd.exe', ['/d', '/s', '/c', 'corepack pnpm list --depth Infinity --json'], { cwd: path.resolve(path.dirname(values.manifest), '..') })
    : run('corepack', ['pnpm', 'list', '--depth', 'Infinity', '--json'], { cwd: path.resolve(path.dirname(values.manifest), '..') }));
  const npm = new Map();
  const visit = tree => {
    for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [name, item] of Object.entries(tree[group] ?? {})) {
        const reference = `pkg:npm/${name.replace(/^@/, '%40')}@${item.version}`;
        if (npm.has(reference)) continue;
        npm.set(reference, { type: 'library', name, version: item.version, purl: reference, 'bom-ref': reference });
        visit(item);
      }
    }
  };
  trees.forEach(visit);
  packages.push(...npm.values());
}
const runtime = walk(path.dirname(values.engine)).filter(file => /\.(dll|so|dylib)(\.[0-9.]+)?$/.test(file)).map(file => ({
  type: 'library', name: path.basename(file), 'bom-ref': `runtime:${path.basename(file)}`,
  hashes: [{ alg: 'SHA-256', content: hash(file) }],
}));
const sbom = {
  bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
  metadata: { component: { type: 'application', name: managerPackage.name, version: managerPackage.version } },
  components: [...packages, ...runtime, { type: 'library', name: 'OpenSSL', version: engine.cryptoVersion }, { type: 'application', name: 'openfortivpn', version: engine.version, hashes: [{ alg: 'SHA-256', content: hash(values.engine) }] }],
  dependencies: [...new Map([...metadata.resolve.nodes, ...(helperMetadata?.resolve.nodes ?? [])].map(node => [node.id, { ref: node.id, dependsOn: node.dependencies }])).values()],
};
let signing = 'unverified', notarization = 'not-run';
const installers = walk(values.root).filter(file => /\.(deb|dmg|msi|exe|tar\.gz)$/.test(file) && !file.includes('.app' + path.sep));
if (values.platform.startsWith('macOS')) {
  if (!values['app-bundle']) throw new Error('--app-bundle is required for macOS');
  run('codesign', ['--verify', '--deep', '--strict', values['app-bundle']]);
  const identity = spawnSync('codesign', ['-d', '--verbose=2', values['app-bundle']], { encoding: 'utf8', timeout: 10_000 });
  signing = identity.status === 0 && /Authority=Developer ID Application/.test(identity.stderr) ? 'developer-id' : 'ad-hoc';
  const staple = spawnSync('xcrun', ['stapler', 'validate', values['app-bundle']], { timeout: 30_000 });
  const assessment = staple.status === 0 ? spawnSync('spctl', ['--assess', '--type', 'execute', values['app-bundle']], { timeout: 30_000 }) : null;
  if (assessment?.status === 0) notarization = 'verified';
} else if (values.platform === 'Windows-x64') {
  const payloads = [values.manager, values.engine, ...runtime.map(item => path.join(path.dirname(values.engine), item.name)), ...installers];
  const signatures = payloads.map(file => {
    const script = `$ErrorActionPreference = 'Stop'; (Get-AuthenticodeSignature -LiteralPath '${path.resolve(file).replaceAll("'", "''")}').Status.ToString()`;
    return run('pwsh.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')]).trim();
  });
  signing = signatures.every(status => status === 'Valid') ? 'authenticode' : 'unsigned';
} else signing = 'checksums-only';
const sbomName = `sbom-${values.platform}.cdx.json`;
const sbomFile = path.join(values.root, sbomName);
fs.writeFileSync(sbomFile, JSON.stringify(sbom, null, 2) + '\n');
const evidence = {
  schemaVersion: 1, commit: process.env.GITHUB_SHA, platform: values.platform,
  evidenceId: `${process.env.GITHUB_RUN_ID ?? 'local'}/${process.env.GITHUB_RUN_ATTEMPT ?? '1'}/${values.platform}`,
  components, signing, notarization,
  sbom: { name: sbomName, sha256: hash(sbomFile) },
  assets: installers.map(file => ({ name: path.basename(file).replaceAll(' ', '.'), sha256: hash(file) })),
  checks: { build: 'passed', installationSmoke: 'passed', networkRecovery: 'not-run', gateway: 'not-run', upgrade: 'not-run', rollback: 'not-run' },
};
fs.writeFileSync(path.join(values.root, `release-evidence-${values.platform}.json`), JSON.stringify(evidence, null, 2) + '\n');
