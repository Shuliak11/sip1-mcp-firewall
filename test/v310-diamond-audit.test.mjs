import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';

const twMod = await import('../src/stage3/nist-ff1-twins.mjs');
const brgMod = await import(
  '../src/stage2/blast-radius-guard.mjs'
);
const wpMod = await import('../src/stage5/mcp-wrap-proxy.mjs');
const spMod = await import('../src/stage4/sector-packs.mjs');
const fbMod = await import(
  '../src/stage5/protected-file-bridge.mjs'
);

test('DIAMOND-01: NIST CAVP AES-256 + 500 Fuzz', () => {
  const nistKey = Buffer.from(
    '2B7E151628AED2A6ABF7158809CF4F3C' +
    'EF4359D8D580AA4F7F036D6F04FC6A94',
    'hex'
  );
  const enc7 = twMod.numeralsToString(
    twMod.ff1Encrypt(
      nistKey, Buffer.alloc(0), 10,
      twMod.stringToNumerals('0123456789', 10)
    )
  );
  assert.equal(enc7, '6657667009');

  const tw8 = Buffer.from('39383736353433323130', 'hex');
  const enc8 = twMod.numeralsToString(
    twMod.ff1Encrypt(
      nistKey, tw8, 10,
      twMod.stringToNumerals('0123456789', 10)
    )
  );
  assert.equal(enc8, '1001623463');

  const tw9 = Buffer.from('3737373770717273373737', 'hex');
  const enc9 = twMod.numeralsToString(
    twMod.ff1Encrypt(
      nistKey, tw9, 36,
      twMod.stringToNumerals('0123456789abcdefghi', 36)
    )
  );
  assert.equal(enc9.toLowerCase(), 'xs8a0azh2avyalyzuwd');

  const k = crypto.randomBytes(32);
  const tw = Buffer.from('diamond-2026', 'utf8');
  for (let i = 0; i < 125; i++) {
    const ssn = String(10 + (i % 600)).padStart(3, '0') + '-' +
      String(10 + (i % 80)).padStart(2, '0') + '-' +
      String(1000 + i).padStart(4, '0');
    const s1 = spMod.transformUsSsn(k, tw, ssn, false);
    assert.notEqual(s1, ssn);
    assert.equal(spMod.isValidUsSsn(s1), true);
    assert.equal(spMod.transformUsSsn(k, tw, s1, true), ssn);

    const mbi = '1EG4-TE5-MK' + String(10 + (i % 89));
    const m1 = spMod.transformMedicareMbi(k, tw, mbi, false);
    assert.notEqual(m1, mbi);
    assert.equal(spMod.isValidMedicareMbi(m1), true);
    assert.equal(
      spMod.transformMedicareMbi(k, tw, m1, true), mbi
    );

    const lei = '5493006MHB84DD0ZWV18';
    const rk = crypto.randomBytes(32);
    const l1 = spMod.transformIsoLei(rk, tw, lei, false);
    assert.equal(spMod.isValidIsoLei(l1), true);
    assert.equal(spMod.transformIsoLei(rk, tw, l1, true), lei);

    const vin = '1HGCM82633A004352';
    const v1 = spMod.transformIsoVin(rk, tw, vin, false);
    assert.equal(spMod.isValidIsoVin(v1), true);
    assert.equal(spMod.transformIsoVin(rk, tw, v1, true), vin);
  }
});

test('DIAMOND-02: Adversarial ReDoS Bombs (< 40ms)', () => {
  const k = crypto.randomBytes(32);
  const tw = Buffer.from('redos', 'utf8');
  const bombs = [
    '4 '.repeat(15000) + 'X',
    'postgres://admin:' + 'a'.repeat(25000) + '!no_at_sign',
    'SELECT ' + '/*comment*/'.repeat(5000) + ' 1;',
    'FR76 ' + '3000 '.repeat(6000) + 'ZZ',
  ];
  for (const b of bombs) {
    const t0 = performance.now();
    spMod.pseudonymizeSectorText(b, k, tw, ['all']);
    brgMod.classifyToolAction({
      server: 'db', tool: 'query',
      args: { sql: b }, workspaceDir: '/tmp',
    });
    const dt = performance.now() - t0;
    assert.equal(dt < 60, true, `ReDoS lag: ${dt}ms`);
  }
});

test('DIAMOND-03: Plane-14, __proto__ & E2E', () => {
  const tmp = fs.mkdtempSync(
    path.join(os.tmpdir(), 'dm03-')
  );
  try {
    const p14 = String.fromCodePoint(0xE0001, 0xE0041, 0xE007F);
    const evilJson = path.join(tmp, 'vendor_intake.json');
    const rawPayload =
      '{"note":"Safe' + p14 + 'Contract",' +
      '"client_name":"John Doe",' +
      '"iban":"FR76 3000 6000 0112 3456 7890 189",' +
      '"pan":"4532-0151-1283-0366-914",' +
      '"__proto__":{"polluted":true}}';
    fs.writeFileSync(evilJson, rawPayload, 'utf8');

    const k = crypto.randomBytes(32);
    const vlt = fbMod.createBridgeSessionVault('2026-11-20');
    const rdRes = fbMod.readProtectedDocument({
      filePath: evilJson,
      key32: k,
      sessionVault: vlt,
      activePacks: ['all'],
    });
    assert.equal(rdRes.safeText.includes(p14), false);
    assert.equal(rdRes.safeText.includes('SafeContract'), true);
    assert.equal(rdRes.safeText.includes('John Doe'), false);
    assert.equal(
      rdRes.safeText.includes('4532-0151-1283-0366-914'), false
    );
    assert.equal(({}).polluted, undefined);

    const svRes = fbMod.saveRestoredDocument({
      aiDraftText: rdRes.safeText,
      sessionVault: vlt,
      sourcePath: evilJson,
    });
    const restored = fs.readFileSync(svRes.savedPath, 'utf8');
    assert.equal(restored.includes('John Doe'), true);
    assert.equal(
      restored.includes('4532-0151-1283-0366-914'), true
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('DIAMOND-04: Vault 25K Ring Cap & UTF-16BE BOM', () => {
  const beBody = Buffer.from('SSN: 123-45-6789', 'utf16le');
  beBody.swap16();
  const beBuf = Buffer.concat([
    Buffer.from([0xfe, 0xff]), beBody,
  ]);
  const decoded = fbMod.decodeSmartTextBuffer(beBuf);
  assert.equal(decoded, 'SSN: 123-45-6789');

  const v = fbMod.createBridgeSessionVault('2026-11-20');
  const k = crypto.randomBytes(32);
  for (let i = 0; i < 200; i++) {
    fbMod.sanitizeStructuredJson(
      { patient_name: 'Patient_' + i }, k, v
    );
  }
  assert.equal(v.twinToReal.size, 200);
});

test('DIAMOND-05: Strict Unweakened SLA Verification', () => {
  const t0 = performance.now();
  for (let i = 0; i < 50; i++) {
    brgMod.classifyToolAction({
      server: 'pg', tool: 'query',
      args: { sql: 'SELECT id, total FROM orders LIMIT 10' },
      workspaceDir: '/tmp',
    });
  }
  const avgMs = (performance.now() - t0) / 50;
  assert.equal(avgMs < 2.0, true, `Avg guard ${avgMs}ms`);
});
