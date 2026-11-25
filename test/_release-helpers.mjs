import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  MCP_TOOLS_CATALOG,
} from '../src/stage5/mcp-stdio-server.mjs';
import {
  buildZipArchive, parseZipArchive,
} from '../src/stage5/office-clinical-bridge.mjs';

export function resolveReleaseDir() {
  const d = process.env.SIP_RELEASE_DIR ||
    '/root/release-v3.1.0';
  let ok = false;
  try {
    fs.accessSync(d, fs.constants.R_OK);
    ok = fs.statSync(d).isDirectory();
  } catch {
    ok = false;
  }
  const req = process.env.SIP_REQUIRE_RELEASE_ASSETS;
  if (!ok && req === '1') {
    assert.fail('Missing required release dir: ' + d);
  }
  return ok ? d : null;
}

export function verifyOfflineMcpbFallback() {
  const pj = JSON.parse(
    fs.readFileSync('package.json', 'utf8')
  );
  const srv = JSON.parse(
    fs.readFileSync('server.json', 'utf8')
  );
  assert.equal(srv.name, pj.mcpName);
  assert.ok(srv.description.length <= 100);
  const pkgs = srv.packages.filter(
    (p) => p.registryType === 'mcpb'
  );
  assert.equal(pkgs.length, 4);
  for (const p of pkgs) {
    assert.match(String(p.fileSha256), /^[0-9a-f]{64}$/);
  }
  const mf = {
    manifest_version: '0.3',
    name: 'sip1-offline-check',
    version: pj.version,
    privacy_policies: ['https://shuliak.dev/privacy'],
    user_config: {
      allowed_directories: { type: 'directory' },
      sip1_license_key: { type: 'string', sensitive: true },
    },
    tools: MCP_TOOLS_CATALOG.map((t) => ({
      name: t.name, description: t.description,
    })),
  };
  const raw = Buffer.from(JSON.stringify(mf), 'utf8');
  const zip = buildZipArchive([
    { name: 'manifest.json', data: raw, content: raw },
  ]);
  const ents = parseZipArchive(zip);
  const m = ents.find((e) => e.name === 'manifest.json');
  assert.ok(m, 'manifest.json missing in zip');
  const pm = JSON.parse(
    Buffer.from(m.data || m.content).toString('utf8')
  );
  assert.equal(pm.manifest_version, '0.3');
  assert.equal(pm.user_config.sip1_license_key.sensitive,
               true);
  assert.equal(pm.user_config.allowed_directories.type,
               'directory');
  assert.equal(pm.tools.length, 8);
}
