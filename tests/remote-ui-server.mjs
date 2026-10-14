// Isolated UI fixture. Never launches a VPN or reads manager configuration.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
const page = readFileSync(new URL('../app/src-tauri/src/remote.html', import.meta.url));
const client = readFileSync(new URL('../web/remote-client.js', import.meta.url));
const server = createServer((request, response) => {
  response.setHeader('cache-control', 'no-store');
  response.setHeader('content-security-policy', "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'");
  if (request.url === '/') { response.setHeader('content-type', 'text/html; charset=utf-8'); return response.end(page); }
  if (request.url === '/remote-client.js') { response.setHeader('content-type', 'text/javascript'); return response.end(client); }
  response.setHeader('content-type', 'application/json');
  if (request.headers.authorization !== 'Bearer synthetic-ui-token') { response.statusCode = 401; return response.end(JSON.stringify({error:'invalid synthetic token'})); }
  if (request.url === '/api/v1/capabilities') return response.end(JSON.stringify({apiVersions:[1],authentication:['password'],concurrentNetworkConnections:1,sessionPasswords:true,privilegeSetup:false}));
  if (request.url === '/api/v1/snapshot') return response.end(JSON.stringify({profiles:[],instances:[],logs:[],engine:{available:true,version:'fixture',platform:'Linux'},privilege:{required:false,ready:true}}));
  response.statusCode = 404;
  response.end(JSON.stringify({error:'fixture endpoint not implemented'}));
});
server.listen(Number(process.env.VPN_UI_FIXTURE_PORT ?? 18763), '127.0.0.1', () => {
  process.stdout.write(`UI fixture: http://127.0.0.1:${server.address().port}\n`);
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close());
