import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const cliMod = await import('../src/cli.mjs');
const brgMod = await import(
  '../src/stage2/blast-radius-guard.mjs'
);
const licMod = await import(
  '../src/stage4/license-authority.mjs'
);
const wpMod = await import('../src/stage5/mcp-wrap-proxy.mjs');
const mcpMod = await import(
  '../src/stage5/mcp-stdio-server.mjs'
);
const spMod = await import('../src/stage4/sector-packs.mjs');
const fbMod = await import(
  '../src/stage5/protected-file-bridge.mjs'
);

test('GATE-01: Property Fuzzing 200 bijections', () => {
  const k = crypto.randomBytes(32);
  const tw = Buffer.from('fuzz-2026', 'utf8');
  for (let i = 0; i < 100; i++) {
    const area = 1 + (i % 660);
    const grp = 1 + (i % 98);
    const ser = 1000 + i;
    const ssn = String(area).padStart(3, '0') + '-' +
      String(grp).padStart(2, '0') + '-' +
      String(ser).padStart(4, '0');
    const syn = spMod.transformUsSsn(k, tw, ssn, false);
    assert.notEqual(syn, ssn);
    assert.equal(spMod.transformUsSsn(k, tw, syn, true), ssn);
  }
  for (const ib of [
    'FR7630006000011234567890189',
    'ES9121000418450200051332',
    'IT60X0542811101000000123456',
    'BE68539007547034',
    'NO9386011117947',
  ]) {
    for (let r = 0; r < 20; r++) {
      const rk = crypto.randomBytes(32);
      const syn = spMod.transformSepaIban(rk, tw, ib, false);
      assert.equal(
        spMod.transformSepaIban(rk, tw, syn, true), ib
      );
    }
  }
});

test('GATE-02: Stage 2 IMDS, SQL RCE & Self-Mutate', () => {
  const ws = os.tmpdir();
  const fn = brgMod.classifyToolAction ||
    Object.values(brgMod).find((v) => typeof v === 'function');

  const rImds = fn({
    server: 'fetch-mcp',
    tool: 'fetch',
    args: { url: 'http://169.254.169.254/latest/meta-data/' },
    workspaceDir: ws,
  });
  assert.equal(rImds.ruleId, 'SIP-G06');

  const rSql = fn({
    server: 'postgres-mcp',
    tool: 'query',
    args: { sql: "SELECT pg_read_file('/etc/passwd');" },
    workspaceDir: ws,
  });
  assert.equal(rSql.ruleId, 'SIP-G07');

  const rMerge = fn({
    server: 'supabase-mcp',
    tool: 'execute_sql',
    args: {
      query: 'MERGE INTO users u USING tmp t ON u.id=t.id ' +
             'WHEN MATCHED THEN DELETE',
    },
    workspaceDir: ws,
  });
  assert.equal(rMerge.ruleId, 'SIP-G07');

  const rMut = fn({
    server: 'desktop-commander',
    tool: 'set_config_value',
    args: { key: 'allowedDirectories', value: ['/'] },
    workspaceDir: ws,
  });
  assert.equal(rMut.ruleId, 'SIP-G05');

  const rHook = fn({
    server: 'fs-mcp',
    tool: 'write_file',
    args: { path: '.cursor/hooks.json', content: '{}' },
    workspaceDir: ws,
  });
  assert.equal(rHook.ruleId, 'SIP-G01');
});

test('GATE-03: 300KB Minified JSON & Blob Bypass Fix', () => {
  const fn = wpMod.shouldBypassBinaryPayload;
  const bigJson = JSON.stringify(
    Array.from({ length: 9000 }, (_, i) => ({
      id: i, pan: '4532015112830366',
    }))
  );
  assert.equal(bigJson.length > 262144, true);
  assert.equal(fn(bigJson, ''), false);
  assert.equal(fn('leak 4532015112830366', 'blob'), false);
  assert.equal(fn('A'.repeat(512), 'blob'), true);
});

test('GATE-04: Clock Skew, 8-Tool Catalog & E2E Bridge', () => {
  assert.equal(cliMod.CLI_VERSION, '3.1.0');
  assert.equal(licMod.CLOCK_SKEW_LEEWAY_MS, 300_000);

  const cat = mcpMod.MCP_TOOLS_CATALOG ||
    mcpMod.MCP_TOOL_DEFINITIONS ||
    Object.values(mcpMod).find((v) => Array.isArray(v) && v[0] && typeof v[0] === "object" && v[0].name);
  assert.equal(cat.length, 8);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpb-'));
  try {
    const doc = path.join(tmp, 'agreement.txt');
    fs.writeFileSync(
      doc,
      'IBAN FR76 3000 6000 0112 3456 7890 189 ' +
      'SSN 123-45-6789\n'
    );
    const k32 = crypto.randomBytes(32);
    const vlt = fbMod.createBridgeSessionVault('2026-11-20');
    const r1 = fbMod.readProtectedDocument({
      filePath: doc, key32: k32, sessionVault: vlt,
    });
    assert.equal(r1.safeText.includes('123-45-6789'), false);
    const r2 = fbMod.saveRestoredDocument({
      aiDraftText: r1.safeText,
      sessionVault: vlt,
      sourcePath: doc,
    });
    const saved = fs.readFileSync(r2.savedPath, 'utf8');
    assert.equal(saved.includes('123-45-6789'), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
