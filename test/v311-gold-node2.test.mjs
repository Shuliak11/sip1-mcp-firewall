import {
  resolveReleaseDir, verifyOfflineMcpbFallback,
} from './_release-helpers.mjs';
/**
 * @license Apache-2.0
 * SHULIAK SIP v3.1 Gold Master - Node 2 Battle Suite
 * Covers: Office/Clinical bridge, prompts, shield offset
 * patcher, 2026 discovery, orphan reaper, token tax,
 * schema diet, SIP-F03 spill, RFC 9162 Merkle proofs,
 * 3-tier license/seat-roster/MDM, and 4x .mcpb bundles.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

import {
  buildZipArchive,
  parseZipArchive,
} from '../src/stage5/office-clinical-bridge.mjs';
import {
  createBridgeSessionVault,
  readProtectedDocument,
  saveRestoredDocument,
} from '../src/stage5/protected-file-bridge.mjs';
import {
  MCP_PROMPTS_CATALOG,
  MCP_TOOLS_CATALOG,
  createMcpServerSession,
} from '../src/stage5/mcp-stdio-server.mjs';
import {
  SUPPORTED_MCP_CLIENTS,
  discoverMcpConfigs,
  extractServersFromParsedConfig,
} from '../src/stage1/config-discovery.mjs';
import { parseJsoncSafe }
  from '../src/core/workspace-io.mjs';
import {
  inspectWorkspaceEntitlement,
} from '../src/stage4/license-authority.mjs';
import {
  generateAuditorAttestationBundle,
} from '../src/stage4/auditor-attestation.mjs';
import {
  createSignedCiReceipt,
} from '../src/stage4/mdm-fleet.mjs';
import {
  formatAuditTerminalReport,
  runStaticMcpAudit,
} from '../src/stage1/audit-scanner.mjs';
import {
  acquireNpxColdStartLock,
  applyShieldToWorkspace,
  formatMultiDialectHookDecision,
  rollbackShieldInWorkspace,
} from '../src/stage1/auto-shield.mjs';
import {
  createInlineProxySession,
  createOrphanProcessReaper,
} from '../src/stage5/mcp-wrap-proxy.mjs';
import {
  computeMerkleTreeHead,
  generateConsistencyProof,
  generateInclusionPath,
  verifyConsistencyProof,
  verifyInclusionProof,
  verifySignedIsepMerkleProof,
} from '../src/stage3/rfc9162-merkle.mjs';
import {
  closeKeyring,
  initKeyring,
  recordAgentEvent,
} from '../src/stage3/isep-engine.mjs';
import {
  COMMERCIAL_TIERS,
  activateWorkspaceLicense,
  evaluateSeatRoster,
  generateAuthorityKeypair,
  issueCommercialLicenseToken,
} from '../src/stage4/license-authority.mjs';
import {
  verifySignedCiReceipt,
} from '../src/stage4/mdm-fleet.mjs';
import { runCli } from '../src/cli.mjs';

function mkTmp(pfx) {
  const b = process.env.TMPDIR || os.tmpdir() || '/tmp';
  return fs.mkdtempSync(path.join(b, pfx));
}

test('GM2-01: ZIP/CRC32 & zip-bomb/traversal guards', () => {
  const z = buildZipArchive([
    { name: 'a.txt', data: 'hello world' },
    { name: 'sub/b.xml', data: '<root/>' },
  ]);
  const ents = parseZipArchive(z);
  assert.equal(ents.length, 2);
  assert.equal(ents[0].data.toString('utf8'), 'hello world');

  const bomb = buildZipArchive([
    { name: 'big.xml', data: Buffer.alloc(26 * 1024 * 1024,
      0x41) },
  ]);
  assert.throws(
    () => parseZipArchive(bomb),
    /ERR_ZIP_BOMB_LIMIT_EXCEEDED/
  );

  const many = Array.from({ length: 260 }, (_, i) => ({
    name: `f${i}.txt`, data: 'x',
  }));
  assert.throws(
    () => parseZipArchive(buildZipArchive(many)),
    /ERR_ZIP_BOMB_TOO_MANY_FILES/
  );

  const slip = buildZipArchive([
    { name: '../evil.txt', data: 'x' },
  ]);
  assert.throws(
    () => parseZipArchive(slip),
    /ERR_ZIP_PATH_TRAVERSAL/
  );
});

test('GM2-02: DOCX/XLSX/ODT/PDF round-trips & DDE', () => {
  const tmp = mkTmp('sip-gm2-off-');
  const key = crypto.randomBytes(32);
  try {
    // DOCX split-run PAN + RU header co-ref + table
    const docXml =
      '<w:document><w:body>' +
      '<w:p><w:r><w:t>\u041f\u0430\u0446\u0438\u0435' +
      '\u043d\u0442: \u0421\u043c\u0438\u0440\u043d' +
      '\u043e\u0432 \u041f\u0435\u0442\u0440</w:t></w:r>' +
      '</w:p><w:tbl><w:tr><w:tc><w:p>' +
      '<w:r><w:t>PAN 4532 0151 </w:t></w:r>' +
      '<w:r><w:t>1283 0366</w:t></w:r></w:p></w:tc>' +
      '</w:tr></w:tbl><w:p><w:r><w:t>Rx for ' +
      '\u0421\u043c\u0438\u0440\u043d\u043e\u0432 ' +
      '\u041f\u0435\u0442\u0440</w:t></w:r></w:p>' +
      '</w:body></w:document>';
    const dxP = path.join(tmp, 'note.docx');
    fs.writeFileSync(dxP, buildZipArchive([
      { name: 'word/document.xml', data: docXml },
    ]));
    const v1 = createBridgeSessionVault('2026-11-25');
    const r1 = readProtectedDocument({
      filePath: dxP, key32: key, sessionVault: v1,
    });
    assert.equal(r1.format, 'docx');
    assert.equal(r1.safeText.includes('4532 0151'), false);
    assert.equal(
      r1.safeText.includes('\u0421\u043c\u0438\u0440'),
      false
    );
    assert.match(r1.safeText, /PATIENT_01/);
    const dxOut = path.join(tmp, 'note.out.docx');
    saveRestoredDocument({
      aiDraftText: r1.safeText, sessionVault: v1,
      sourcePath: dxP, outputPath: dxOut,
    });
    const rXml = parseZipArchive(fs.readFileSync(dxOut))
      .find((e) => e.name === 'word/document.xml')
      .data.toString('utf8');
    assert.ok(rXml.includes('<w:tbl>'));
    assert.ok(rXml.includes('4532 0151 1283 0366'));

    // XLSX sharedStrings + inlineStr + DDE guard
    const xP = path.join(tmp, 'sheet.xlsx');
    fs.writeFileSync(xP, buildZipArchive([
      { name: 'xl/sharedStrings.xml',
        data: '<sst><si><t>DE89370400440532013000</t></si>' +
          '<si><t>=cmd|\' /C calc\'!A0</t></si></sst>' },
      { name: 'xl/worksheets/sheet1.xml',
        data: '<worksheet><sheetData><row><c t="inlineStr">' +
          '<is><t>cfo@bank.eu</t></is></c>' +
          '<c><f>IMPORTXML("http://x","//a")</f></c>' +
          '</row></sheetData></worksheet>' },
    ]));
    const v2 = createBridgeSessionVault('2026-11-25');
    const r2 = readProtectedDocument({
      filePath: xP, key32: key, sessionVault: v2,
    });
    assert.equal(
      r2.safeText.includes('DE89370400440532013000'), false
    );
    const xOut = path.join(tmp, 'sheet.out.xlsx');
    const sv2 = saveRestoredDocument({
      aiDraftText: r2.safeText, sessionVault: v2,
      sourcePath: xP, outputPath: xOut,
    });
    assert.ok(sv2.neutralizedCsvFormulas >= 2);

    // ODT content.xml + Party A/B co-ref
    const odP = path.join(tmp, 'deal.odt');
    fs.writeFileSync(odP, buildZipArchive([
      { name: 'mimetype',
        data: 'application/vnd.oasis.opendocument.text',
        compress: false },
      { name: 'content.xml',
        data: '<office:body><text:p>Party A: Alpha LLC' +
          '</text:p><text:p>Party B: Omega SA</text:p>' +
          '<text:p>Alpha LLC pays Omega SA</text:p>' +
          '</office:body>' },
    ]));
    const v3 = createBridgeSessionVault('2026-11-25');
    const r3 = readProtectedDocument({
      filePath: odP, key32: key, sessionVault: v3,
    });
    assert.equal(r3.safeText.includes('Alpha LLC'), false);
    assert.equal(r3.safeText.includes('Omega SA'), false);
    assert.match(r3.safeText, /PARTY_A pays PARTY_B/);
    const odOut = path.join(tmp, 'deal.out.odt');
    saveRestoredDocument({
      aiDraftText: r3.safeText, sessionVault: v3,
      sourcePath: odP, outputPath: odOut,
    });
    const oXml = parseZipArchive(fs.readFileSync(odOut))
      .find((e) => e.name === 'content.xml')
      .data.toString('utf8');
    assert.ok(oXml.includes('Alpha LLC pays Omega SA'));

    // PDF FlateDecode Tj/TJ
    const strm = zlib.deflateSync(Buffer.from(
      'BT (Client: Delta Inc) Tj ' +
      '[(Card ) (4532015112830366)] TJ ET', 'latin1'
    ));
    const pBuf = Buffer.concat([
      Buffer.from('%PDF-1.7\n1 0 obj\n<< /Filter ' +
        `/FlateDecode /Length ${strm.length} >>\nstream\n`,
        'latin1'),
      strm,
      Buffer.from('\nendstream\nendobj\n%%EOF\n', 'latin1'),
    ]);
    const pdfP = path.join(tmp, 'rep.pdf');
    fs.writeFileSync(pdfP, pBuf);
    const v4 = createBridgeSessionVault('2026-11-25');
    const r4 = readProtectedDocument({
      filePath: pdfP, key32: key, sessionVault: v4,
    });
    assert.equal(r4.format, 'pdf');
    assert.equal(r4.safeText.includes('Delta Inc'), false);
    assert.equal(
      r4.safeText.includes('4532015112830366'), false
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('GM2-03: Clinical HL7 v2 & FHIR R4 protection', () => {
  const tmp = mkTmp('sip-gm2-clin-');
  const key = crypto.randomBytes(32);
  try {
    const hl7P = path.join(tmp, 'adt.hl7');
    fs.writeFileSync(hl7P,
      'MSH|^~\\&|EHR|CLN||20261125||ADT^A01|1|P|2.5\n' +
      'PID|1||MRN77441||Roe^John||19820711|M|||' +
      '42 Pine Rd||||||||123-45-6789\n' +
      'NTE|1||Discharged John Roe\n'
    );
    const v1 = createBridgeSessionVault('2026-11-25');
    const rh = readProtectedDocument({
      filePath: hl7P, key32: key, sessionVault: v1,
    });
    assert.equal(rh.format, 'hl7_v2');
    for (const s of ['MRN77441', 'Roe^John', 'John Roe',
                     '19820711', '42 Pine Rd',
                     '123-45-6789']) {
      assert.equal(rh.safeText.includes(s), false, s);
    }

    const fhP = path.join(tmp, 'bundle.json');
    fs.writeFileSync(fhP, JSON.stringify({
      resourceType: 'Bundle',
      entry: [{
        resource: {
          resourceType: 'Patient',
          identifier: [{ value: 'PAT-9001' }],
          name: [{ family: 'Miller', given: ['Clara'] }],
          telecom: [{ value: 'clara@hosp.org' }],
          birthDate: '1975-09-21',
          address: [{ line: ['7 Elm St'],
                      postalCode: '03601' }],
        },
      }],
    }));
    const v2 = createBridgeSessionVault('2026-11-25');
    const rf = readProtectedDocument({
      filePath: fhP, key32: key, sessionVault: v2,
    });
    assert.equal(rf.format, 'fhir_r4');
    for (const s of ['PAT-9001', 'Miller', 'Clara',
                     'clara@hosp.org', '1975-09-21',
                     '7 Elm St']) {
      assert.equal(rf.safeText.includes(s), false, s);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('GM2-04: MCP prompts/list, prompts/get & banner', async () => {
  const tmp = mkTmp('sip-gm2-mcp-');
  try {
    const doc = path.join(tmp, 'sample.txt');
    fs.writeFileSync(doc, 'Client: Orion Group\n', 'utf8');
    const srv = createMcpServerSession({ workspaceDir: tmp });
    const init = await srv.handleMessage({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2026-07-28' },
    });
    assert.ok(init.result.capabilities.prompts);
    const pl = await srv.handleMessage({
      jsonrpc: '2.0', id: 2, method: 'prompts/list',
    });
    assert.equal(pl.result.prompts.length, 4);
    assert.deepEqual(
      pl.result.prompts.map((p) => p.name),
      MCP_PROMPTS_CATALOG.map((p) => p.name)
    );
    for (const p of MCP_PROMPTS_CATALOG) {
      const pg = await srv.handleMessage({
        jsonrpc: '2.0', id: 10, method: 'prompts/get',
        params: { name: p.name,
                  arguments: { filePath: doc } },
      });
      assert.equal(pg.result.messages.length, 1);
    }
    const callR = await srv.handleMessage({
      jsonrpc: '2.0', id: 20, method: 'tools/call',
      params: { name: 'sip_read_protected_file',
                arguments: { filePath: doc } },
    });
    assert.match(
      callR.result.content[1].text,
      /\[SHULIAK SIP-1 ACTIVE \| 0 Sockets \| Protected/
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('GM2-05: 2026 discovery & shield comment-safe rollback',
async () => {
  const ws = mkTmp('sip-gm2-sh-');
  const fakeHome = mkTmp('sip-gm2-hm-');
  try {
    assert.equal(SUPPORTED_MCP_CLIENTS.length, 9);
    fs.mkdirSync(path.join(ws, '.roo'), { recursive: true });
    fs.mkdirSync(path.join(ws, '.gemini'),
      { recursive: true });
    fs.mkdirSync(path.join(ws, '.zed'), { recursive: true });
    fs.mkdirSync(path.join(ws, '.codex'),
      { recursive: true });
    fs.mkdirSync(path.join(fakeHome, '.copilot'),
      { recursive: true });
    fs.mkdirSync(
      path.join(fakeHome, '.cline', 'data', 'settings'),
      { recursive: true }
    );

    const mcpOrig =
      '// keep line comment\n{\n  /* keep block */\n' +
      '  "mcpServers": {\n' +
      '    "db": { "command": "npx", ' +
      '"args": ["-y", "db@1.0.0"] }\n  }\n}\n';
    const mcpP = path.join(ws, '.mcp.json');
    fs.writeFileSync(mcpP, mcpOrig, 'utf8');

    const tomlOrig =
      '# keep header\n[mcp_servers.api]\n' +
      'command = "npx" # keep cmd\n' +
      'args = ["-y", "api@1.0.0"]\n';
    const tomlP = path.join(ws, '.codex', 'config.toml');
    fs.writeFileSync(tomlP, tomlOrig, 'utf8');

    fs.writeFileSync(
      path.join(ws, '.roo', 'mcp.json'),
      '{"mcpServers":{"r":{"command":"node","args":["r"]}}}'
    );
    fs.writeFileSync(
      path.join(ws, '.gemini', 'settings.json'),
      '{"mcpServers":{"g":{"command":"node","args":["g"]}}}'
    );
    fs.writeFileSync(
      path.join(ws, '.zed', 'settings.json'),
      '{"context_servers":{"z":{"command":{"path":"node"}}}}'
    );
    fs.writeFileSync(
      path.join(fakeHome, '.copilot', 'mcp-config.json'),
      '{"mcpServers":{"c":{"command":"node","args":["c"]}}}'
    );
    fs.writeFileSync(
      path.join(
        fakeHome, '.cline', 'data', 'settings',
        'cline_mcp_settings.json'
      ),
      '{"mcpServers":{"cl":{"command":"node","args":["1"]}}}'
    );

    const cfgs = discoverMcpConfigs({
      workspaceDir: ws, homeDir: fakeHome,
      includeGlobal: true,
    });
    const clSet = new Set(cfgs.map((c) => c.client));
    for (const c of ['roo', 'gemini', 'zed',
                     'copilot', 'cline']) {
      assert.ok(clSet.has(c), c);
    }
    const zedCfg = cfgs.find((c) => c.client === 'zed');
    assert.equal(zedCfg.servers.length, 1);

    const sha = (p) => crypto.createHash('sha256')
      .update(fs.readFileSync(p)).digest('hex');
    const s1 = sha(mcpP);
    const s2 = sha(tomlP);

    const a1 = applyShieldToWorkspace({
      workspaceDir: ws, includeGlobal: false,
    });
    assert.ok(a1.modifiedCount >= 2);
    const mAfter = fs.readFileSync(mcpP, 'utf8');
    const tAfter = fs.readFileSync(tomlP, 'utf8');
    assert.ok(mAfter.includes('// keep line comment'));
    assert.ok(mAfter.includes('/* keep block */'));
    assert.ok(mAfter.includes(fs.realpathSync(process.execPath)));
    assert.ok(tAfter.includes('# keep header'));
    assert.ok(tAfter.includes('# keep cmd'));

    const a2 = applyShieldToWorkspace({
      workspaceDir: ws, includeGlobal: false,
    });
    assert.equal(a2.modifiedCount, 0);

    const rb = rollbackShieldInWorkspace({
      workspaceDir: ws,
    });
    assert.equal(rb.status, 'ROLLED_BACK_EXACT');
    assert.equal(sha(mcpP), s1);
    assert.equal(sha(tomlP), s2);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
    fs.rmSync(fakeHome, { recursive: true, force: true });
  }
});

test('GM2-06: Multi-dialect hooks, reaper & npx mutex', () => {
  const ws = mkTmp('sip-gm2-hk-');
  try {
    const c1 = formatMultiDialectHookDecision('claude', {
      blocked: true, reason: 'x',
    });
    assert.equal(c1.exitCode, 2);
    assert.equal(c1.stdout, '');
    assert.equal(
      JSON.parse(formatMultiDialectHookDecision('cursor', {
        blocked: true, reason: 'x',
      }).stdout).permission, 'deny'
    );
    assert.equal(
      JSON.parse(formatMultiDialectHookDecision('codex', {
        blocked: true, reason: 'x',
      }).stdout).permissionDecision, 'deny'
    );
    assert.equal(
      JSON.parse(formatMultiDialectHookDecision('cline', {
        blocked: true, reason: 'x',
      }).stdout).cancel, true
    );
    assert.equal(
      JSON.parse(formatMultiDialectHookDecision('devin', {
        blocked: true, reason: 'x',
      }).stdout).decision, 'block'
    );

    let pp = 5000;
    let dead = false;
    const r = createOrphanProcessReaper({
      getPpid: () => pp,
      onOrphan: () => { dead = true; },
      intervalMs: 60_000,
    });
    r.check();
    assert.equal(dead, false);
    pp = 1;
    r.check();
    assert.equal(dead, true);
    r.stop();

    const lk = acquireNpxColdStartLock({
      lockDir: path.join(ws, 'locks'),
    });
    assert.ok(fs.existsSync(lk.lockPath));
    lk.release();
    assert.equal(fs.existsSync(lk.lockPath), false);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('GM2-07: Token tax, schema diet & SIP-F03 spill',
async () => {
  const ws = mkTmp('sip-gm2-f03-');
  try {
    fs.writeFileSync(
      path.join(ws, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          big: { command: 'node', args: ['srv.js'] },
        },
      })
    );
    const cfgs = discoverMcpConfigs({
      workspaceDir: ws, includeGlobal: false,
    });
    const tools101 = Array.from({ length: 101 }, (_, i) => ({
      name: `op_${i}`, description: 'Execute step',
    }));
    const aud = runStaticMcpAudit({
      configs: cfgs, workspaceDir: ws,
      toolsByServer: { big: tools101 },
    });
    assert.equal(aud.tokenTax.tokenizer, 'cl100k_base');
    assert.equal(aud.tokenTax.windsurfLimitExceeded, true);
    assert.match(
      formatAuditTerminalReport(aud), /Windsurf 100-tool/
    );

    const sess = createInlineProxySession({
      serverName: 'big', workspaceDir: ws,
      persistVault: false, enableIsep: false,
      enableIfc: false,
      allowTools: ['read_*'], excludeTools: ['read_secret'],
      spillThresholdBytes: 1024,
    });
    await sess.inspectHostRequest({
      jsonrpc: '2.0', id: 1, method: 'tools/list',
    });
    const tl = await sess.inspectDownstreamResponse({
      jsonrpc: '2.0', id: 1,
      result: {
        tools: [
          { name: 'read_ok', inputSchema: {} },
          { name: 'read_secret', inputSchema: {} },
          { name: 'write_any', inputSchema: {} },
        ],
      },
    });
    assert.deepEqual(
      tl.message.result.tools.map((t) => t.name),
      ['read_ok']
    );
    await sess.inspectHostRequest({
      jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'read_ok', arguments: {} },
    });
    const sp = await sess.inspectDownstreamResponse({
      jsonrpc: '2.0', id: 2,
      result: {
        content: [{ type: 'text', text: 'Z'.repeat(3000) }],
      },
    });
    assert.equal(
      sp.message.result._sipSpill.ruleId,
      'SIP-F03_OVERSIZED_PAYLOAD_SPILL'
    );
    assert.ok(
      fs.existsSync(sp.message.result._sipSpill.spillPath)
    );
    sess.closeSession();
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('GM2-08: RFC 9162 7-leaf tree & CLI prove', async () => {
  const leaves = Array.from({ length: 7 }, (_, i) =>
    Buffer.from(`rec-${i}`, 'utf8')
  );
  const root7 = computeMerkleTreeHead(leaves);
  for (let m = 0; m < 7; m++) {
    const p = generateInclusionPath(m, leaves);
    assert.equal(verifyInclusionProof({
      leafBytes: leaves[m], leafIndex: m, treeSize: 7,
      auditPath: p, expectedRoot: root7,
    }), true);
  }
  for (const sz of [1, 2, 3, 4, 5, 6, 7]) {
    const rOld = computeMerkleTreeHead(leaves.slice(0, sz));
    const pf = generateConsistencyProof(sz, leaves);
    assert.equal(verifyConsistencyProof({
      firstSize: sz, secondSize: 7,
      firstRoot: rOld, secondRoot: root7, proof: pf,
    }), true);
  }

  const ws = mkTmp('sip-gm2-mrk-');
  try {
    const kr = initKeyring({
      workspaceDir: ws, bucketCount: 16,
    });
    for (let i = 1; i <= 7; i++) {
      recordAgentEvent(kr, {
        server: 's', tool: 't', args: { i },
      });
    }
    closeKeyring(kr);
    const out = await runCli([
      'prove', '--dir', ws, '--seq', '5',
      '--compare-size', '3', '--json',
    ]);
    assert.equal(out.exitCode, 0);
    const prf = JSON.parse(out.stdout);
    assert.equal(
      verifySignedIsepMerkleProof(prf).valid, true
    );
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('GM2-09: 3-tier keys, seat-roster & MDM fleet',
async () => {
  const ws = mkTmp('sip-gm2-lic-');
  const rootAuth = generateAuthorityKeypair();
  try {
    const kr = initKeyring({
      workspaceDir: ws, bucketCount: 16,
    });
    recordAgentEvent(kr, {
      server: 'db', tool: 'q', args: { ok: 1 },
    });
    closeKeyring(kr);
    fs.writeFileSync(
      path.join(ws, '.mcp.json'),
      JSON.stringify({
        mcpServers: { a: { command: 'node', args: ['a'] } },
      })
    );
    fs.writeFileSync(
      path.join(ws, '.sip', 'team-policy.json'),
      JSON.stringify({ minGrade: 'B' })
    );

    // PRO_SECOPS ($79, 5 seats)
    const pro = issueCommercialLicenseToken({
      authorityPrivateKey: rootAuth.privateKey,
      tier: COMMERCIAL_TIERS.PRO_SECOPS,
      licenseId: 'lic_pro_t',
      orgName: 'Pro Corp', orgDomain: 'pro.test',
    });
    assert.equal(pro.payload.maxSeats, 5);
    await activateWorkspaceLicense({
      workspaceDir: ws, tokenStr: pro.token,
      authorityPubB64u: rootAuth.publicKeyB64u,
    });
    const ciR = await runCli([
      'audit', '--dir', ws, '--no-global', '--signed-receipt',
      '--authority-pub', rootAuth.publicKeyB64u, '--json',
    ]);
    assert.equal(ciR.exitCode, 0);
    const aJson = JSON.parse(ciR.stdout);
    assert.equal(aJson.teamPolicy.applied, true);
    assert.equal(verifySignedCiReceipt({
      receipt: aJson.signedCiReceipt,
      authorityPubB64u: rootAuth.publicKeyB64u,
    }).valid, true);

    // Seat cap enforcement (5 seats -> 6th blocked)
    const rp = path.join(ws, '.sip', 'r5.json');
    for (let i = 1; i <= 5; i++) {
      assert.equal(evaluateSeatRoster({
        workspaceDir: ws, licenseId: 'lic_pro_t',
        tier: 'PRO_SECOPS', maxSeats: 5,
        custodianPubB64u: `k${i}`, rosterPath: rp,
        register: true,
      }).allowed, true);
    }
    assert.equal(evaluateSeatRoster({
      workspaceDir: ws, licenseId: 'lic_pro_t',
      tier: 'PRO_SECOPS', maxSeats: 5,
      custodianPubB64u: 'k6', rosterPath: rp,
      register: true,
    }).status, 'SEAT_CAP_EXCEEDED');

    // COMPLIANCE ($299, 25 seats) -> --template pci
    const comp = issueCommercialLicenseToken({
      authorityPrivateKey: rootAuth.privateKey,
      tier: COMMERCIAL_TIERS.COMPLIANCE,
      licenseId: 'lic_comp_t',
      orgName: 'Pay Vault GmbH', orgDomain: 'pay.de',
    });
    assert.equal(comp.payload.maxSeats, 25);
    await activateWorkspaceLicense({
      workspaceDir: ws, tokenStr: comp.token,
      authorityPubB64u: rootAuth.publicKeyB64u,
    });
    const att = await runCli([
      'attest', '--dir', ws, '--no-global',
      '--template', 'pci',
      '--authority-pub', rootAuth.publicKeyB64u, '--json',
    ]);
    assert.equal(att.exitCode, 0);
    const attSum = JSON.parse(att.stdout);
    const pdfStr = fs.readFileSync(attSum.pdfPath)
      .toString('latin1');
    assert.ok(pdfStr.includes('[PCI]'));
    assert.ok(pdfStr.includes('Pay Vault GmbH'));

    // ENTERPRISE ($990, 250 seats) -> mdm-export & fleet
    const ent = issueCommercialLicenseToken({
      authorityPrivateKey: rootAuth.privateKey,
      tier: COMMERCIAL_TIERS.ENTERPRISE,
      licenseId: 'lic_ent_t',
      orgName: 'MegaBank AG', orgDomain: 'megabank.ch',
    });
    assert.equal(ent.payload.maxSeats, 250);
    await activateWorkspaceLicense({
      workspaceDir: ws, tokenStr: ent.token,
      authorityPubB64u: rootAuth.publicKeyB64u,
    });
    const mdm = await runCli([
      'mdm-export', '--dir', ws,
      '--authority-pub', rootAuth.publicKeyB64u, '--json',
    ]);
    assert.equal(mdm.exitCode, 0);
    assert.equal(JSON.parse(mdm.stdout).files.length, 2);

    const fDir = path.join(ws, 'fleet');
    fs.mkdirSync(fDir, { recursive: true });
    fs.copyFileSync(
      attSum.certJsonPath, path.join(fDir, 'n1.json')
    );
    const fv = await runCli([
      'fleet-verify', '--dir', ws, '--fleet-dir', fDir,
      '--authority-pub', rootAuth.publicKeyB64u, '--json',
    ]);
    assert.equal(fv.exitCode, 0);
    assert.equal(JSON.parse(fv.stdout).status,
      'FLEET_VERIFIED');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('GM2-10: 4 .mcpb bundles, server.json & SHA256SUMS',
() => {
  const relDir = resolveReleaseDir();
  const srv = JSON.parse(
    fs.readFileSync('server.json', 'utf8')
  );
  const mcpbPkgs = srv.packages.filter(
    (p) => p.registryType === 'mcpb'
  );
  assert.equal(mcpbPkgs.length, 4);
  if (!relDir) { verifyOfflineMcpbFallback(); return; }

  const sumsTxt = fs.readFileSync(
    path.join(relDir, 'SHA256SUMS.txt'), 'utf8'
  );
  const sumsMap = new Map();
  for (const ln of sumsTxt.trim().split('\n')) {
    const [dig, fn] = ln.trim().split(/\s+/);
    sumsMap.set(fn, dig);
  }

  const catNames = MCP_TOOLS_CATALOG.map((t) => t.name);
  for (const pkg of mcpbPkgs) {
    const fn = pkg.identifier.split('/').pop();
    const fp = path.join(relDir, fn);
    assert.ok(fs.existsSync(fp), fn);
    const buf = fs.readFileSync(fp);
    const dig = crypto.createHash('sha256')
      .update(buf).digest('hex');
    assert.equal(pkg.fileSha256, dig, fn);
    assert.equal(sumsMap.get(fn), dig, fn);

    const ents = parseZipArchive(buf);
    const names = ents.map((e) => e.name);
    assert.equal(
      names.some((n) => /\.(?:pem|key)$/.test(n)), false
    );
    assert.equal(names.includes('mcp-publisher'), false);
    const mf = JSON.parse(
      ents.find((e) => e.name === 'manifest.json')
        .data.toString('utf8')
    );
    assert.equal(mf.manifest_version, '0.3');
    assert.equal(
      mf.user_config.allowed_directories.type, 'directory'
    );
    assert.equal(
      mf.user_config.sip1_license_key.sensitive, true
    );
    assert.equal(
      mf.server.mcp_config.env.SIP_LICENSE_KEY,
      '${user_config.sip1_license_key}'
    );
    assert.equal(mf.documentation, 'https://shuliak.dev/docs');
    assert.equal(mf.support, 'https://shuliak.dev/support');
    assert.deepEqual(
      mf.privacy_policies, ['https://shuliak.dev/privacy']
    );
    assert.deepEqual(
      mf.tools.map((t) => t.name), catNames
    );
  }
});

test('GM2-11: P0-1 Zed context_servers & null safe', () => {
  const rNull = extractServersFromParsedConfig(null, {
    client: 'zed', scope: 'workspace',
    filePath: '.zed/settings.json',
  });
  assert.deepEqual(rNull.servers, []);
  const rZed = extractServersFromParsedConfig(
    { context_servers: { z1: { command: { path: 'node',
      args: ['s.js'] } } } },
    { client: 'zed', scope: 'workspace',
      filePath: '.zed/settings.json' }
  );
  assert.equal(rZed.servers.length, 1);
  assert.equal(rZed.servers[0].command, 'node');
});

test('GM2-12: P0-2 realpath/default pack & P0-3 glue',
async () => {
  const ws = mkTmp('sip-gm2-p02-');
  const outDir = mkTmp('sip-gm2-out-');
  const prevDirs = process.env.SIP_ALLOWED_DIRS;
  const prevPack = process.env.SIP_DEFAULT_PACK;
  try {
    const extF = path.join(outDir, 'secret.txt');
    fs.writeFileSync(extF, 'TOP SECRET', 'utf8');
    const sym = path.join(ws, 'escape.txt');
    fs.symlinkSync(extF, sym);
    process.env.SIP_ALLOWED_DIRS = ws;
    assert.throws(
      () => readProtectedDocument({
        filePath: sym, key32: crypto.randomBytes(32),
        sessionVault: createBridgeSessionVault('2026-11-25'),
      }),
      /ERR_OUTSIDE_ALLOWED_DIRS/
    );

    const clFile = path.join(ws, 'chart.txt');
    fs.writeFileSync(
      clFile, 'Visit 2024-05-10 PAN 4532015112830366\n'
    );
    process.env.SIP_DEFAULT_PACK = 'hipaa_clinical';
    const srv = createMcpServerSession({ workspaceDir: ws });
    const resp = await srv.handleMessage({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'sip_read_protected_file',
                arguments: { filePath: clFile } },
    });
    const out = JSON.parse(resp.result.content[0].text);
    assert.equal(out.safeText.includes('2024-05-10'), false);
    assert.equal(out.safeText.includes('4532015112830366'),
      true);

    // P0-3: glued hyphen/dot twin restoration
    const f2 = path.join(ws, 'fin.txt');
    fs.writeFileSync(
      f2, '4532015112830366 DE89370400440532013000\n'
    );
    const v = createBridgeSessionVault('2026-11-25');
    const r = readProtectedDocument({
      filePath: f2, key32: crypto.randomBytes(32),
      sessionVault: v,
    });
    const [tPan, tIban] = r.safeText.trim().split(/\s+/);
    const glued = `Card-${tPan} ref.${tIban}\n`;
    const dst = path.join(ws, 'fin.restored.txt');
    const sv = saveRestoredDocument({
      aiDraftText: glued, sessionVault: v,
      sourcePath: f2, outputPath: dst,
    });
    assert.equal(sv.restoredCount, 2);
    const body = fs.readFileSync(dst, 'utf8');
    assert.equal(
      body, 'Card-4532015112830366 ref.DE89370400440532013000\n'
    );
  } finally {
    if (prevDirs === undefined) {
      delete process.env.SIP_ALLOWED_DIRS;
    } else process.env.SIP_ALLOWED_DIRS = prevDirs;
    if (prevPack === undefined) {
      delete process.env.SIP_DEFAULT_PACK;
    } else process.env.SIP_DEFAULT_PACK = prevPack;
    fs.rmSync(ws, { recursive: true, force: true });
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test('GM2-13: P0-4 self-wrap skip & JSONC trailing cmt',
() => {
  const ws = mkTmp('sip-gm2-p04-');
  try {
    const raw =
      '{\n' +
      '  "mcpServers": {\n' +
      '    "self1": {\n' +
      '      "command": "npx",\n' +
      '      "args": ["-y", "@shuliak-corp/sip1-mcp"]\n' +
      '    },\n' +
      '    "self2": {\n' +
      '      "command": "node",\n' +
      '      "args": ["/app/src/cli.mjs", "serve"]\n' +
      '    },\n' +
      '    "ext": {\n' +
      '      "command": "npx",\n' +
      '      "args": ["-y", "pg@1.0.0"],\n' +
      '      "env": {\n' +
      '        "FOO": "bar" // keep end comment\n' +
      '      }\n' +
      '    }\n' +
      '  }\n' +
      '}\n';
    const mp = path.join(ws, '.mcp.json');
    fs.writeFileSync(mp, raw, 'utf8');
    const res = applyShieldToWorkspace({
      workspaceDir: ws, includeGlobal: false,
    });
    assert.equal(res.modifiedCount, 1);
    assert.deepEqual(res.files[0].wrappedServers, ['ext']);
    const after = fs.readFileSync(mp, 'utf8');
    assert.ok(after.includes('// keep end comment'));
    const parsed = parseJsoncSafe(after);
    assert.ok(parsed.mcpServers.ext.env.PATH);
    assert.equal(parsed.mcpServers.self1.command, 'npx');
    assert.equal(parsed.mcpServers.self2.command, 'node');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('GM2-14: P1-5 seat reg, reason & 78-col help',
async () => {
  const ws = mkTmp('sip-gm2-p15-');
  const rootAuth = generateAuthorityKeypair();
  const prevLic = process.env.SIP_LICENSE_KEY;
  try {
    const kr = initKeyring({
      workspaceDir: ws, bucketCount: 16,
    });
    recordAgentEvent(kr, {
      server: 'db', tool: 'q', args: { x: 1 },
    });
    closeKeyring(kr);

    const tok = issueCommercialLicenseToken({
      authorityPrivateKey: rootAuth.privateKey,
      tier: COMMERCIAL_TIERS.COMPLIANCE,
      licenseId: 'lic_seat1',
      orgName: 'Seat One Corp', orgDomain: 'seat1.io',
      maxSeats: 1,
    });
    process.env.SIP_LICENSE_KEY = tok.token;

    // Register seat via generateAuditorAttestationBundle
    const rp = path.join(ws, '.sip', 'seat-roster.json');
    generateAuditorAttestationBundle({
      workspaceDir: ws, previewMode: false,
      authorityPubB64u: rootAuth.publicKeyB64u,
      rosterPath: rp,
    });
    assert.ok(fs.existsSync(rp));
    const rObj = JSON.parse(fs.readFileSync(rp, 'utf8'));
    assert.equal(
      Object.keys(rObj.licenses.lic_seat1.seats).length, 1
    );

    // Replace registered seat with another key -> exceed cap
    rObj.licenses.lic_seat1.seats = {
      other_device_pub: { firstSeenAt: '2026-01-01' },
    };
    fs.writeFileSync(rp, JSON.stringify(rObj));
    const ent = inspectWorkspaceEntitlement({
      workspaceDir: ws,
      authorityPubB64u: rootAuth.publicKeyB64u,
      rosterPath: rp,
    });
    assert.equal(ent.status, 'SEAT_CAP_EXCEEDED');
    assert.match(ent.reason, /Seat cap exceeded/);
    assert.throws(
      () => createSignedCiReceipt({
        workspaceDir: ws,
        auditResult: { score: 100, grade: 'A+', findings: [] },
        authorityPubB64u: rootAuth.publicKeyB64u,
        rosterPath: rp,
      }),
      /SEAT_CAP_EXCEEDED/
    );

    const h = await runCli(['--help', '--no-color']);
    assert.equal(h.exitCode, 0);
    for (const kw of ['shield', 'prove', 'mdm-export',
                      'fleet-verify', 'Enterprise Sovereign']) {
      assert.ok(h.stdout.includes(kw), kw);
    }
    for (const ln of h.stdout.split('\n')) {
      assert.ok(ln.length <= 78, `line > 78: ${ln}`);
    }
  } finally {
    if (prevLic === undefined) {
      delete process.env.SIP_LICENSE_KEY;
    } else process.env.SIP_LICENSE_KEY = prevLic;
    fs.rmSync(ws, { recursive: true, force: true });
  }
});
