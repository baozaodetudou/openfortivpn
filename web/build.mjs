// Use the existing locked TypeScript toolchain; no remote runtime dependencies.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(new URL('../app/package.json', import.meta.url));
const ts = require('typescript');
const config = ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile);
if (config.error) throw new Error(ts.flattenDiagnosticMessageText(config.error.messageText, '\n'));
const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
const program = ts.createProgram(parsed.fileNames, parsed.options);
const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(program)];
if (diagnostics.length) {
  process.stderr.write(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => root,
    getCanonicalFileName: name => name,
    getNewLine: () => '\n',
  }));
  process.exit(1);
}
let generated;
program.emit(program.getSourceFile(path.join(root, 'remote-client.ts')), (filename, text) => {
  if (filename.endsWith('remote-client.js')) generated = '// Generated from remote-client.ts by node web/build.mjs.\n' + text;
});
if (!generated) throw new Error('remote client emission failed');
const destination = path.join(root, 'remote-client.js');
if (process.argv.includes('--check')) {
  if (fs.readFileSync(destination, 'utf8') !== generated) {
    process.stderr.write('Remote bundle is stale. Run node web/build.mjs.\n');
    process.exit(1);
  }
} else {
  fs.writeFileSync(destination, generated);
}
