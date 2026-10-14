// Audit the installed, frozen pnpm graph against npm's bulk advisory API.
// Some pnpm versions fail decoding this API; do not interpret that as a clean scan.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export function packageVersions(trees) {
  const versions = new Map();
  const visited = new Set();
  const visit = tree => {
    for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [name, item] of Object.entries(tree[group] ?? {})) {
        if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name) || typeof item.version !== 'string' || !/^\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?$/i.test(item.version)) {
          throw new Error(`Unresolved package identity: ${name}`);
        }
        const key = `${name}@${item.version}`;
        if (visited.has(key)) continue;
        visited.add(key);
        if (!versions.has(name)) versions.set(name, new Set());
        versions.get(name).add(item.version);
        visit(item);
      }
    }
  };
  trees.forEach(visit);
  if (!versions.size) throw new Error('The installed dependency graph is empty');
  return Object.fromEntries([...versions].map(([name, list]) => [name, [...list]]));
}

export function validateAdvisories(response) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) throw new Error('Invalid advisory response');
  const advisories = Object.entries(response).flatMap(([name, items]) => {
    if (!Array.isArray(items)) throw new Error('Invalid advisory list');
    for (const item of items) {
      if (!item.id || !item.title || !['info', 'low', 'moderate', 'high', 'critical'].includes(item.severity)) throw new Error('Invalid advisory record');
    }
    return items.map(item => ({ package: name, ...item }));
  });
  return { advisories, blocking: advisories.filter(item => ['high', 'critical'].includes(item.severity)) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const trees = JSON.parse(execFileSync('corepack', ['pnpm', 'list', '--depth', 'Infinity', '--json'], { cwd: path.resolve(fileURLToPath(new URL('../app', import.meta.url))), encoding: 'utf8', timeout: 30_000, maxBuffer: 64 * 1024 * 1024 }));
  const graph = packageVersions(trees);
  const response = await fetch('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(graph), signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`Advisory registry failed: HTTP ${response.status}`);
  const result = validateAdvisories(await response.json());
  process.stdout.write(JSON.stringify({ scannedPackages: Object.keys(graph).length, ...result }, null, 2) + '\n');
  if (result.blocking.length) process.exitCode = 1;
}
