import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.resolve(__dirname, '../src/cli.mjs');

const brgMod = await import(
  '../src/stage2/blast-radius-guard.mjs'
);
const spMod = await import('../src/stage4/sector-packs.mjs');
const fbMod = await import(
  '../src/stage5/protected-file-bridge.mjs'
);

test('CHAOS-01: Live serve + split UTF-8 + CRLF', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch01-'));
  const child = spawn(process.execPath, [CLI_PATH, 'serve'], {
    cwd: tmp,
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const responses = new Map();
  let stdoutBuf = '';
  let errBuf = '';
  child.stderr.on('data', (d) => { errBuf += d; });
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdoutBuf += chunk;
    let nl;
    while ((nl = stdoutBuf.indexOf('\n')) !== -1) {
      const line = stdoutBuf.slice(0, nl).trim();
      stdoutBuf = stdoutBuf.slice(nl + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      if (msg.id !== undefined) responses.set(msg.id, msg);
    }
  });

  const waitId = (id, ms = 5000) => new Promise((res, rej) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      if (responses.has(id)) {
        clearInterval(iv);
        res(responses.get(id));
      } else if (Date.now() - t0 > ms) {
        clearInterval(iv);
        rej(new Error('Timeout id=' + id + ' err=' + errBuf));
      }
    }, 15);
  });

  try {
    const geoWord = '\u10d1\u10d0\u10d7\u10e3\u10db\u10d8';
    const cyrName = '\u0434\u043e\u0433_77.txt';
    const doc = path.join(tmp, cyrName);
    fs.writeFileSync(
      doc,
      'City ' + geoWord +
      ' SSN 123-45-6789 IBAN BE68539007547034\n',
      'utf8'
    );

    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'chaos', version: '1.0' },
      },
    }) + '\r\n');
    const rInit = await waitId(1);
    assert.equal(rInit.result.serverInfo.version, '3.1.0');

    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', method: 'notifications/initialized',
    }) + '\n');

    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'sip_list_sector_packs', arguments: {} },
    }) + '\n');
    const rPacks = await waitId(2);
    const _u = (r) => r.result?.content?.[0]?.text
      ? JSON.parse(r.result.content[0].text) : r.result;
    assert.equal(Boolean(rPacks.error), false,
      JSON.stringify(rPacks.error));
    const pList = _u(rPacks);
    assert.equal(pList.packs.length, spMod.SECTOR_PACK_IDS.length);

    // Split multi-byte UTF-8 Cyrillic byte 0xD0 across 2 writes
    const rawReq = JSON.stringify({
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: {
        name: 'sip_read_protected_file',
        arguments: { filePath: doc },
      },
    });
    const callBuf = Buffer.from(
      rawReq.replace(/\\u0434/g, '\u0434') + '\r\n', 'utf8'
    );
    const cut = callBuf.indexOf(0xd0) + 1;
    assert.equal(cut > 0, true);
    child.stdin.write(callBuf.subarray(0, cut));
    await new Promise((r) => setTimeout(r, 25));
    child.stdin.write(callBuf.subarray(cut));

    const rRead = await waitId(3);
    assert.equal(Boolean(rRead.error), false,
      JSON.stringify(rRead.error));
    const parsed = _u(rRead);
    assert.ok(parsed?.safeText, JSON.stringify(rRead));
    assert.equal(
      parsed.safeText.includes('123-45-6789'), false
    );
    assert.equal(parsed.safeText.includes(geoWord), true);

    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', id: 4, method: 'tools/call',
      params: {
        name: 'sip_save_restored_document',
        arguments: {
          aiDraftText: parsed.safeText,
          sourcePath: doc,
        },
      },
    }) + '\n');
    const rSave = await waitId(4);
    assert.equal(Boolean(rSave.error), false,
      JSON.stringify(rSave.error));
    const meta = _u(rSave);
    const disk = fs.readFileSync(meta.savedPath, 'utf8');
    assert.equal(disk.includes('123-45-6789'), true);
    assert.equal(disk.includes('BE68539007547034'), true);
  } finally {
    child.stdin.end();
    child.kill('SIGTERM');
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CHAOS-02: Poisoned Config CLI Subprocess Audit', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch02-'));
  try {
    const curDir = path.join(tmp, '.cursor');
    fs.mkdirSync(curDir);
    const badMcp = {
      mcpServers: {
        leakyDb: {
          command: 'npx',
          args: [
            '-y', '@bytebase/dbhub@latest',
            '--dsn', 'postgres://adm:PlainPass99@db.io:5432/p',
          ],
          env: {
            STRIPE_KEY: 'sk_l' + 'ive_51ABCDEFG0123456789abcd',
          },
        },
      },
    };
    fs.writeFileSync(
      path.join(curDir, 'mcp.json'),
      JSON.stringify(badMcp, null, 2)
    );

    const run = spawnSync(
      process.execPath,
      [CLI_PATH, 'audit', '--json'],
      { cwd: tmp, env: process.env, encoding: 'utf8' }
    );
    assert.equal(run.status === 0 || run.status === 1, true);
    const rep = JSON.parse(run.stdout);
    assert.equal(rep.engineVersion, '3.1.0');
    const repStr = JSON.stringify(rep);
    assert.equal(repStr.includes('PlainPass99'), false);
    assert.equal(
      repStr.includes('sk_l' + 'ive_51ABCDEFG0123456789abcd'), false
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CHAOS-03: UTF-16LE/BE Plane-14, BiDi & Odd-Byte', () => {
  const p14 = String.fromCodePoint(0xE0001, 0xE0058, 0xE007F);
  const bidi = '\u202E';
  const raw = 'Invoice ' + p14 + bidi + 'OK';

  const leBuf = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from(raw, 'utf16le'),
  ]);
  assert.equal(
    fbMod.decodeSmartTextBuffer(leBuf), 'Invoice OK'
  );

  const bePayload = Buffer.from(raw, 'utf16le');
  bePayload.swap16();
  const oddBeBuf = Buffer.concat([
    Buffer.from([0xfe, 0xff]),
    bePayload,
    Buffer.from([0xaa]),
  ]);
  assert.equal(
    fbMod.decodeSmartTextBuffer(oddBeBuf), 'Invoice OK'
  );
});

test('CHAOS-04: Multilingual Unicode + Leap-Year Shift', () => {
  const k = crypto.randomBytes(32);
  const tw = Buffer.from('chaos-04', 'utf8');
  const uniHdr = '\u0414\u043e\u0433 | ' +
    '\u10d1\u10d0\u10d7\u10e3\u10db\u10d8 | ' +
    'M\u00fcnchen \u00df | \u5951\u7d04 ' +
    String.fromCodePoint(0x1F9EC);
  const doc = uniHdr + '\n' +
    'Amex: 3782 822463 10005 | UK NINO: AB123456C\n' +
    'LEI: 5493006MHB84DD0ZWV18 | ES NIF: X1234567L\n';
  const res = spMod.pseudonymizeSectorText(doc, k, tw, ['all']);
  assert.equal(res.text.includes('3782 822463 10005'), false);
  assert.equal(res.text.includes('AB123456C'), false);
  const lei = '5493006MHB84DD0ZWV18';
  assert.equal(res.text.includes(lei), false);
  assert.equal(res.text.includes('X1234567L'), false);
  assert.equal(res.text.includes(uniHdr), true);

  for (let i = 0; i < 200; i++) {
    const sc = 'patient-scope-' + i;
    const sh = spMod.shiftIsoDateString(
      '2024-02-29', k, sc, false
    );
    assert.notEqual(sh, '2024-02-29');
    assert.equal(
      spMod.shiftIsoDateString(sh, k, sc, true), '2024-02-29'
    );
  }
});

test('CHAOS-05: 25,500 Ring Eviction & Non-Overwrite', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch05-'));
  try {
    const v = fbMod.createBridgeSessionVault('2026-11-20');
    const k = crypto.randomBytes(32);
    for (let i = 0; i < 25_500; i++) {
      fbMod.sanitizeStructuredJson(
        { client_name: 'Client_Num_' + i }, k, v
      );
    }
    assert.equal(v.twinToReal.size, 25_000);
    assert.equal(v.realToTwin.size, 25_000);
    assert.equal(v.realToTwin.has('Client_Num_0'), false);
    assert.equal(v.realToTwin.has('Client_Num_25499'), true);

    const src = path.join(tmp, 'report.csv');
    fs.writeFileSync(src, 'a,b\n1,2\n', 'utf8');
    const s1 = fbMod.saveRestoredDocument({
      aiDraftText: 'a,b\n1,2\n',
      sessionVault: v,
      sourcePath: src,
    });
    const s2 = fbMod.saveRestoredDocument({
      aiDraftText: 'a,b\n1,2\n',
      sessionVault: v,
      sourcePath: src,
    });
    assert.match(s1.savedPath, /report\.restored\.csv$/);
    assert.match(s2.savedPath, /report\.restored\.1\.csv$/);

    assert.throws(
      () => fbMod.saveRestoredDocument({
        aiDraftText: 'x', sessionVault: v, outputPath: src,
      }),
      /ERR_REFUSE_OVERWRITE_EXISTING/
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CHAOS-06: 0% False-Positives & Cloud SSRF Matrix', () => {
  const k = crypto.randomBytes(32);
  const tw = Buffer.from('fp-check', 'utf8');
  const sha = 'e3b0c44298fc1c149afbf4c8996fb924' +
              '27ae41e4649b934ca495991b7852b855';
  const benign =
    'commit a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 ' +
    'sha ' + sha + ' ' +
    'uuid 550e8400-e29b-41d4-a716-446655440000 ' +
    'ts 1763668200123 amt -98450.25 tel +995-593-124-700';
  const out = spMod.pseudonymizeSectorText(
    benign, k, tw, ['all']
  );
  assert.equal(out.text, benign);
  assert.equal(Object.keys(out.counts).length, 0);

  for (const badUrl of [
    'http://[fd00:ec2::254]/latest/meta-data/',
    'http://100.100.100.200/latest/meta-data/',
    'https://metadata.google.internal/computeMetadata/v1/',
    'file:///etc/shadow',
  ]) {
    const r = brgMod.classifyToolAction({
      server: 'fetch', tool: 'get',
      args: { url: badUrl }, workspaceDir: '/tmp',
    });
    assert.equal(r.ruleId, 'SIP-G06', badUrl);
  }
});
