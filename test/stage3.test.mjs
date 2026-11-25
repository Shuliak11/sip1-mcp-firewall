/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 3 Cryptographic, Persistence & Anti-Spoliation Test Suite (34 Vectors)
 * Zero external dependencies (`node:test`, `node:assert/strict`).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Buffer } from 'node:buffer';

import {
  computeLuhnCheckDigit,
  extractAndPseudonymizePayload,
  ff1Decrypt,
  ff1Encrypt,
  ibanMod97,
  isValidLuhnPan,
  numeralsToString,
  stringToNumerals,
  synthesizeIbanTwin,
  synthesizePanTwin,
  synthesizeScopedToken,
} from '../src/stage3/nist-ff1-twins.mjs';
import {
  createHeadlessEnclaveAdapter,
  createVolatileRamEnclaveAdapter,
} from '../src/stage3/enclave-adapter.mjs';
import {
  SLOT_STATE,
  closeKeyring,
  decryptAgentSidecar,
  executeGdprShredding,
  initKeyring,
  inspectActiveSlotPlacements,
  openKeyring,
  recordAgentEvent,
  setSubjectLitigationHold,
  verifyIsepChainQuick,
} from '../src/stage3/isep-engine.mjs';
import { DOMAIN_PREFIX, b64u, domainSha256, signDomainPayload } from '../src/core/crypto-primitives.mjs';
import { jcsCanonicalize } from '../src/core/jcs.mjs';
import { runCli } from '../src/cli.mjs';

function makeTempDir(prefix = 'sip-stage3-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ============================================================================
// 1–9: Official NIST SP 800-38G CAVP FF1 Test Vectors (9/9 Bit-Exact)
// ============================================================================

const NIST_CAVP_FF1_VECTORS = [
  {
    id: 'S3-01',
    name: 'NIST CAVP FF1-AES128 #1 (radix=10, empty tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3C',
    tweakHex: '',
    radix: 10,
    pt: '0123456789',
    ct: '2433477484',
  },
  {
    id: 'S3-02',
    name: 'NIST CAVP FF1-AES128 #2 (radix=10, 10B tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3C',
    tweakHex: '39383736353433323130',
    radix: 10,
    pt: '0123456789',
    ct: '6124200773',
  },
  {
    id: 'S3-03',
    name: 'NIST CAVP FF1-AES128 #3 (radix=36, 11B tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3C',
    tweakHex: '3737373770717273373737',
    radix: 36,
    pt: '0123456789abcdefghi',
    ct: 'a9tv40mll9kdu509eum',
  },
  {
    id: 'S3-04',
    name: 'NIST CAVP FF1-AES192 #4 (radix=10, empty tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F',
    tweakHex: '',
    radix: 10,
    pt: '0123456789',
    ct: '2830668132',
  },
  {
    id: 'S3-05',
    name: 'NIST CAVP FF1-AES192 #5 (radix=10, 10B tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F',
    tweakHex: '39383736353433323130',
    radix: 10,
    pt: '0123456789',
    ct: '2496655549',
  },
  {
    id: 'S3-06',
    name: 'NIST CAVP FF1-AES192 #6 (radix=36, 11B tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F',
    tweakHex: '3737373770717273373737',
    radix: 36,
    pt: '0123456789abcdefghi',
    ct: 'xbj3kv35jrawxv32ysr',
  },
  {
    id: 'S3-07',
    name: 'NIST CAVP FF1-AES256 #7 (radix=10, empty tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
    tweakHex: '',
    radix: 10,
    pt: '0123456789',
    ct: '6657667009',
  },
  {
    id: 'S3-08',
    name: 'NIST CAVP FF1-AES256 #8 (radix=10, 10B tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
    tweakHex: '39383736353433323130',
    radix: 10,
    pt: '0123456789',
    ct: '1001623463',
  },
  {
    id: 'S3-09',
    name: 'NIST CAVP FF1-AES256 #9 (radix=36, 11B tweak)',
    keyHex: '2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94',
    tweakHex: '3737373770717273373737',
    radix: 36,
    pt: '0123456789abcdefghi',
    ct: 'xs8a0azh2avyalyzuwd',
  },
];

for (const vec of NIST_CAVP_FF1_VECTORS) {
  test(`${vec.id}: ${vec.name} encrypt + decrypt round-trip`, () => {
    const keyBuf = Buffer.from(vec.keyHex, 'hex');
    const tweakBuf = vec.tweakHex ? Buffer.from(vec.tweakHex, 'hex') : Buffer.alloc(0);
    const ptNumerals = stringToNumerals(vec.pt, vec.radix);

    const encNumerals = ff1Encrypt(keyBuf, tweakBuf, vec.radix, ptNumerals);
    const actualCt = numeralsToString(encNumerals, false);
    assert.equal(actualCt, vec.ct);

    const decNumerals = ff1Decrypt(keyBuf, tweakBuf, vec.radix, encNumerals);
    const recoveredPt = numeralsToString(decNumerals, false);
    assert.equal(recoveredPt, vec.pt);
  });
}

test('S3-10: NIST SP 800-38G Rev. 1 minimum domain size guard rejects radix^n < 1,000,000', () => {
  const key32 = crypto.randomBytes(32);
  const tweak = Buffer.alloc(0);
  // 10^5 = 100,000 < 1,000,000 -> must throw RangeError
  assert.throws(() => ff1Encrypt(key32, tweak, 10, [1, 2, 3, 4, 5]), RangeError);
  // 10^6 = 1,000,000 -> permitted
  const out = ff1Encrypt(key32, tweak, 10, [1, 2, 3, 4, 5, 6]);
  assert.equal(out.length, 6);
});

test('S3-11: Luhn PAN twin generator produces 100/100 valid Luhn twins preserving MII != plaintext', () => {
  const key32 = crypto.randomBytes(32);
  const tweak16 = crypto.randomBytes(16);

  for (let i = 0; i < 100; i++) {
    const mii = String((i % 4) + 3); // 3, 4, 5, 6
    let body = mii;
    for (let d = 0; d < 14; d++) {
      body += String(crypto.randomInt(0, 10));
    }
    const rawPan = body + computeLuhnCheckDigit(body);
    assert.equal(isValidLuhnPan(rawPan), true);

    const twin = synthesizePanTwin(key32, tweak16, rawPan);
    assert.equal(twin.length, 16);
    assert.equal(twin[0], mii);
    assert.notEqual(twin, rawPan);
    assert.equal(isValidLuhnPan(twin), true);
  }
});

test('S3-12: ISO-7064 MOD-97 IBAN twin generator preserves country code and produces valid MOD-97 twins', () => {
  const key32 = crypto.randomBytes(32);
  const tweak16 = crypto.randomBytes(16);

  const geIban = 'GE29NB0000000101904917';
  assert.equal(ibanMod97(geIban), 1);
  const geTwin = synthesizeIbanTwin(key32, tweak16, geIban);
  assert.equal(geTwin.slice(0, 2), 'GE');
  assert.equal(geTwin.length, geIban.length);
  assert.notEqual(geTwin, geIban);
  assert.equal(ibanMod97(geTwin), 1);

  const deIban = 'DE89370400440532013000';
  assert.equal(ibanMod97(deIban), 1);
  const deTwin = synthesizeIbanTwin(key32, tweak16, deIban);
  assert.equal(deTwin.slice(0, 2), 'DE');
  assert.equal(deTwin.length, deIban.length);
  assert.notEqual(deTwin, deIban);
  assert.equal(ibanMod97(deTwin), 1);
});

test('S3-13: Short-input graceful HMAC fallback ("1234", PINs, emails) never throws RangeError', () => {
  const key32 = crypto.randomBytes(32);
  const tweak16 = crypto.randomBytes(16);

  const shortPanFallback = synthesizePanTwin(key32, tweak16, '1234');
  assert.match(shortPanFallback, /^tok-[0-9a-f]{16}$/);

  const emailTwin = synthesizeScopedToken(key32, tweak16, 'email:alice@corp.eu');
  assert.equal(emailTwin.length, 34);
  assert.match(emailTwin, /^u-[0-9a-f]{16}@example\.invalid$/);

  const extracted = extractAndPseudonymizePayload(
    { pin: '1234', email: 'alice@corp.eu', amount: 450.75, timestamp: '2026-11-15T13:58:44.912Z' },
    () => ({ rSlot32: key32, tweak16 })
  );
  assert.match(extracted.skeletonPayload.pin, /^tok-[0-9a-f]{16}$/);
  assert.equal(extracted.skeletonPayload.amount_band, '[100, 1000)');
  assert.equal(extracted.skeletonPayload.ts_bucket, '2026-11-15T13:58:00Z');
});

// ============================================================================
// 14–15: Zero Prior Plaintext Invariant & Sidecar AEAD Decryption
// ============================================================================

test('S3-14: Zero Prior Plaintext Invariant — raw PAN, IBAN, email, secret & prompt never touch disk in plaintext', () => {
  const dir = makeTempDir();
  try {
    const ctx = initKeyring({ workspaceDir: dir, bucketCount: 64 });
    const rawPan = '4532015112830366';
    const rawIban = 'GE29NB0000000101904917';
    const rawEmail = 'cfo.secret@zurich-vault.ch';
    const rawApiSecret = 'sk-p' + 'roj-SuperSensitiveLiveKey998877665544';
    const rawPrompt = 'Wire €8,420.55 urgently to cfo.secret@zurich-vault.ch using card 4532015112830366';

    const res = recordAgentEvent(ctx, {
      server: 'sepa-treasury',
      tool: 'execute_wire',
      args: {
        beneficiaryEmail: rawEmail,
        iban: rawIban,
        fallbackCard: rawPan,
        authHeader: rawApiSecret,
        amount: 8420.55,
        timestamp: '2026-11-15T14:22:39.481Z',
      },
      prompt: rawPrompt,
    });

    assert.equal(res.seq, 1);
    assert.equal(res.eventRecord.pseudonymized_args.amount_band, '[1000, 10000)');
    assert.equal(res.eventRecord.pseudonymized_args.ts_bucket, '2026-11-15T14:22:00Z');
    assert.equal(isValidLuhnPan(res.eventRecord.pseudonymized_args.fallbackCard), true);
    assert.equal(ibanMod97(res.eventRecord.pseudonymized_args.iban), 1);

    const jsonlBytes = fs.readFileSync(ctx.logPath);
    const blobsBytes = fs.readFileSync(ctx.blobsPath);
    const keyringBytes = fs.readFileSync(ctx.keyringPath);

    for (const sensitive of [rawPan, rawIban, rawEmail, rawApiSecret, '8420.55', '14:22:39', 'zurich-vault']) {
      assert.equal(jsonlBytes.includes(Buffer.from(sensitive)), false, `Leaked ${sensitive} in .jsonl`);
      assert.equal(blobsBytes.includes(Buffer.from(sensitive)), false, `Leaked ${sensitive} in .blobs`);
      assert.equal(keyringBytes.includes(Buffer.from(sensitive)), false, `Leaked ${sensitive} in .keyring`);
    }

    closeKeyring(ctx);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-15: Authorized m-of-m XOR sidecar decryption works before shred and fails after shred', () => {
  const dir = makeTempDir();
  try {
    const ctx = initKeyring({ workspaceDir: dir, bucketCount: 64 });
    recordAgentEvent(ctx, {
      server: 'crm-mcp',
      tool: 'create_ticket',
      args: { customer: 'diana@corp.eu', notes: 'Confidential M&A acquisition memo' },
    });

    const decrypted = decryptAgentSidecar(ctx, 1);
    assert.equal(decrypted.sidecar.raw.args.customer, 'diana@corp.eu');
    assert.equal(decrypted.sidecar.raw.args.notes, 'Confidential M&A acquisition memo');

    executeGdprShredding(ctx, {
      canonicalTargetBuf: 'diana@corp.eu',
      dsarTicketId: 'DSAR-2026-1001',
    });

    assert.throws(() => decryptAgentSidecar(ctx, 1), /SIDECAR_PURGED_GDPR_ART17/);
    closeKeyring(ctx);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 16–18: Multi-Subject (`Alice + Bob`) Double-Shred Regression Suite
// ============================================================================

test('S3-16: Multi-Subject (Alice + Bob) event allocates 16-byte tag region and verifies VALID_UNMODIFIED', () => {
  const dir = makeTempDir();
  try {
    const ctx = initKeyring({ workspaceDir: dir, bucketCount: 64 });
    const ev1 = recordAgentEvent(ctx, {
      server: 'payments-mcp',
      tool: 'joint_escrow_transfer',
      args: { sender: 'alice@corp.eu', recipient: 'bob@corp.eu', amount: 2500 },
    });
    assert.equal(ev1.subjectCount, 2);
    assert.equal(ev1.sidecarByteLen, 80 + 16 + 512);

    const v0 = verifyIsepChainQuick({
      logPath: ctx.logPath,
      blobsPath: ctx.blobsPath,
      custodianPublicKey: ctx.custodianPublicKey,
    });
    assert.equal(v0.valid, true);
    assert.equal(v0.status, 'VALID_UNMODIFIED');
    closeKeyring(ctx);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-17: First subject shred (Alice) transitions joint event to VALID_WITH_LAWFUL_ERASURES while preserving Carol', () => {
  const dir = makeTempDir();
  try {
    const ctx = initKeyring({ workspaceDir: dir, bucketCount: 64 });
    recordAgentEvent(ctx, {
      server: 'payments-mcp',
      tool: 'joint_escrow_transfer',
      args: { sender: 'alice@corp.eu', recipient: 'bob@corp.eu', amount: 2500 },
    });
    recordAgentEvent(ctx, {
      server: 'payments-mcp',
      tool: 'audit_balance',
      args: { accountOwner: 'carol@corp.eu', amount: 900 },
    });

    const shredAlice = executeGdprShredding(ctx, {
      canonicalTargetBuf: 'alice@corp.eu',
      dsarTicketId: 'DSAR-ALICE-01',
    });
    assert.deepEqual(shredAlice.erasedSeqs, [1]);

    const v1 = verifyIsepChainQuick({
      logPath: ctx.logPath,
      blobsPath: ctx.blobsPath,
      custodianPublicKey: ctx.custodianPublicKey,
    });
    assert.equal(v1.valid, true);
    assert.equal(v1.status, 'VALID_WITH_LAWFUL_ERASURES');

    const carolDecrypted = decryptAgentSidecar(ctx, 2);
    assert.equal(carolDecrypted.sidecar.raw.args.accountOwner, 'carol@corp.eu');
    closeKeyring(ctx);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-18: Second subject Double-Shred (Bob) preserves ISBL alloc_tag_bytes=16 without CORRUPT_BLOB_MAGIC offset shift', () => {
  const dir = makeTempDir();
  try {
    const ctx = initKeyring({ workspaceDir: dir, bucketCount: 64 });
    recordAgentEvent(ctx, {
      server: 'payments-mcp',
      tool: 'joint_escrow_transfer',
      args: { sender: 'alice@corp.eu', recipient: 'bob@corp.eu', amount: 2500 },
    });
    const ev2 = recordAgentEvent(ctx, {
      server: 'payments-mcp',
      tool: 'audit_balance',
      args: { accountOwner: 'carol@corp.eu', amount: 900 },
    });
    assert.equal(ev2.sidecarOffset, 608);

    executeGdprShredding(ctx, {
      canonicalTargetBuf: 'alice@corp.eu',
      dsarTicketId: 'DSAR-ALICE-01',
    });

    // Second shred: Bob requests GDPR Art. 17 erasure on ALREADY-PURGED seq=1!
    const shredBob = executeGdprShredding(ctx, {
      canonicalTargetBuf: 'bob@corp.eu',
      dsarTicketId: 'DSAR-BOB-02',
    });
    assert.deepEqual(shredBob.erasedSeqs, [1]);

    // Verify immutable [6..19] bytes in `.isep.blobs` were NEVER overwritten with zero!
    const rawBlobs = fs.readFileSync(ctx.blobsPath);
    assert.equal(rawBlobs.readUInt16BE(6), 16, 'alloc_tag_bytes must remain 16 after double-shred');
    assert.equal(rawBlobs.readUInt32BE(8), 512, 'cipher_len must remain 512 after double-shred');
    assert.equal(Number(rawBlobs.readBigUInt64BE(12)), 1, 'seq must remain 1 after double-shred');

    const v2 = verifyIsepChainQuick({
      logPath: ctx.logPath,
      blobsPath: ctx.blobsPath,
      custodianPublicKey: ctx.custodianPublicKey,
    });
    assert.equal(v2.valid, true);
    assert.equal(v2.status, 'VALID_WITH_LAWFUL_ERASURES');
    assert.equal(v2.tombstones, 2);

    const carolDecrypted = decryptAgentSidecar(ctx, 2);
    assert.equal(carolDecrypted.sidecar.raw.args.accountOwner, 'carol@corp.eu');

    closeKeyring(ctx);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 19–21: Cold-Start Persistence (`openKeyring`) & Crash Tail Truncation
// ============================================================================

test('S3-19: Cold-Start Reload (openKeyring) reloads buckets, appends events & shreds pre-restart subject', () => {
  const dir = makeTempDir();
  try {
    const ctx1 = initKeyring({ workspaceDir: dir, bucketCount: 64 });
    recordAgentEvent(ctx1, {
      server: 'erp-mcp',
      tool: 'sync_payroll',
      args: { employee: 'frank@corp.eu', amount: 6400 },
    });
    recordAgentEvent(ctx1, {
      server: 'erp-mcp',
      tool: 'sync_payroll',
      args: { employee: 'grace@corp.eu', amount: 7100 },
    });
    const pubKey = ctx1.custodianPublicKey;
    closeKeyring(ctx1);

    // Cold-start reopen from disk
    const ctx2 = openKeyring({ workspaceDir: dir });
    assert.equal(ctx2.seqCounter, 2);

    // Append seq=3 after restart
    const ev3 = recordAgentEvent(ctx2, {
      server: 'erp-mcp',
      tool: 'sync_payroll',
      args: { employee: 'heidi@corp.eu', amount: 5200 },
    });
    assert.equal(ev3.seq, 3);

    // Shred `frank@corp.eu` who was recorded BEFORE the cold-start reload!
    const shredFrank = executeGdprShredding(ctx2, {
      canonicalTargetBuf: 'frank@corp.eu',
      dsarTicketId: 'DSAR-FRANK-99',
    });
    assert.deepEqual(shredFrank.erasedSeqs, [1]);

    const ver = verifyIsepChainQuick({
      logPath: ctx2.logPath,
      blobsPath: ctx2.blobsPath,
      custodianPublicKey: pubKey,
    });
    assert.equal(ver.valid, true);
    assert.equal(ver.status, 'VALID_WITH_LAWFUL_ERASURES');
    assert.equal(ver.totalEvents, 3);
    assert.deepEqual(ver.lawfullyErasedSeqs, [1]);

    closeKeyring(ctx2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-20: Crash recovery truncates incomplete trailing .jsonl and uncommitted .isep.blobs bytes cleanly', () => {
  const dir = makeTempDir();
  try {
    const ctx1 = initKeyring({ workspaceDir: dir, bucketCount: 32 });
    recordAgentEvent(ctx1, {
      server: 'db',
      tool: 'q',
      args: { email: 'ivan@corp.eu' },
    });
    const logPath = ctx1.logPath;
    const blobsPath = ctx1.blobsPath;
    const pubKey = ctx1.custodianPublicKey;
    closeKeyring(ctx1);

    // Simulate torn power-loss write at EOF of both `.jsonl` and `.isep.blobs`
    fs.appendFileSync(logPath, '{"v":"isep-event/3.0","record_type":"AGENT_EV');
    fs.appendFileSync(blobsPath, Buffer.from('ISBL_PARTIAL_CRASH_TAIL_BYTES'));

    const ctxRecovered = openKeyring({ workspaceDir: dir });
    assert.equal(ctxRecovered.seqCounter, 1);

    // Append seq=2 cleanly after recovery
    const ev2 = recordAgentEvent(ctxRecovered, {
      server: 'db',
      tool: 'q',
      args: { email: 'judy@corp.eu' },
    });
    assert.equal(ev2.seq, 2);

    const ver = verifyIsepChainQuick({
      logPath,
      blobsPath,
      custodianPublicKey: pubKey,
    });
    assert.equal(ver.valid, true);
    assert.equal(ver.totalEvents, 2);
    closeKeyring(ctxRecovered);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-21: Headless Enclave Adapter stores 0o600 sealed KEK envelope and rejects tampered bytes', () => {
  const dir = makeTempDir();
  try {
    const adapter = createHeadlessEnclaveAdapter(dir);
    const kek = crypto.randomBytes(32);
    adapter.sealRootKey('prod', kek);

    const kekFile = path.join(dir, 'prod.kek');
    const mode = fs.statSync(kekFile).mode & 0o777;
    assert.equal(mode, 0o600);

    const unsealed = adapter.unsealRootKey('prod');
    assert.equal(unsealed.equals(kek), true);

    // Tamper 1 byte in prod.kek -> AES-GCM authentication fails
    const raw = fs.readFileSync(kekFile);
    raw[raw.length - 1] ^= 0xff;
    fs.writeFileSync(kekFile, raw);
    assert.throws(() => adapter.unsealRootKey('prod'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 22–25: History-Independence & Zero Metadata Leakage Proofs
// ============================================================================

test('S3-22: History-Independence Proof — (Insert A, Insert B, Shred A) === fresh (Insert B)', () => {
  const dir1 = makeTempDir();
  const dir2 = makeTempDir();
  try {
    const sharedLocatorKey = crypto.randomBytes(32);
    const detSecret = (canonBuf) =>
      crypto.createHmac('sha256', sharedLocatorKey).update('DET-RSLOT\0').update(canonBuf).digest();

    const kr1 = initKeyring({
      workspaceDir: dir1,
      bucketCount: 16,
      enclaveAdapter: createVolatileRamEnclaveAdapter(),
      customLocatorKey: sharedLocatorKey,
      deterministicSlotSecretFn: detSecret,
    });
    recordAgentEvent(kr1, { server: 's', tool: 't', args: { u: 'alice@corp.eu' } });
    recordAgentEvent(kr1, { server: 's', tool: 't', args: { u: 'bob@corp.eu' } });
    executeGdprShredding(kr1, { canonicalTargetBuf: 'alice@corp.eu', dsarTicketId: 'DSAR-HI-1' });

    const kr2 = initKeyring({
      workspaceDir: dir2,
      bucketCount: 16,
      enclaveAdapter: createVolatileRamEnclaveAdapter(),
      customLocatorKey: sharedLocatorKey,
      deterministicSlotSecretFn: detSecret,
    });
    recordAgentEvent(kr2, { server: 's', tool: 't', args: { u: 'bob@corp.eu' } });

    assert.deepEqual(inspectActiveSlotPlacements(kr1), inspectActiveSlotPlacements(kr2));
    closeKeyring(kr1);
    closeKeyring(kr2);
  } finally {
    fs.rmSync(dir1, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

test('S3-23: Insertion-Order Independence — (A, B, C) === (C, A, B)', () => {
  const dir1 = makeTempDir();
  const dir2 = makeTempDir();
  try {
    const sharedLocatorKey = crypto.randomBytes(32);
    const kr1 = initKeyring({
      workspaceDir: dir1,
      bucketCount: 8,
      enclaveAdapter: createVolatileRamEnclaveAdapter(),
      customLocatorKey: sharedLocatorKey,
    });
    for (const u of ['a@corp.eu', 'b@corp.eu', 'c@corp.eu']) {
      recordAgentEvent(kr1, { server: 's', tool: 't', args: { u } });
    }

    const kr2 = initKeyring({
      workspaceDir: dir2,
      bucketCount: 8,
      enclaveAdapter: createVolatileRamEnclaveAdapter(),
      customLocatorKey: sharedLocatorKey,
    });
    for (const u of ['c@corp.eu', 'a@corp.eu', 'b@corp.eu']) {
      recordAgentEvent(kr2, { server: 's', tool: 't', args: { u } });
    }

    assert.deepEqual(inspectActiveSlotPlacements(kr1), inspectActiveSlotPlacements(kr2));
    closeKeyring(kr1);
    closeKeyring(kr2);
  } finally {
    fs.rmSync(dir1, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

test('S3-24: High-Collision Cuckoo Eviction History-Independence (4 buckets, 12 subjects -> shred 6)', () => {
  const dir1 = makeTempDir();
  const dir2 = makeTempDir();
  try {
    const sharedLocatorKey = crypto.randomBytes(32);
    const all12 = Array.from({ length: 12 }, (_, i) => `user${i}@collision-test.org`);
    const survivors = all12.filter((_, idx) => idx % 2 === 1);
    const toShred = all12.filter((_, idx) => idx % 2 === 0);

    const kr1 = initKeyring({
      workspaceDir: dir1,
      bucketCount: 4, // 4 * 4 = 16 slots total -> guaranteed Cuckoo evictions on 12 subjects!
      enclaveAdapter: createVolatileRamEnclaveAdapter(),
      customLocatorKey: sharedLocatorKey,
    });
    for (const u of all12) {
      recordAgentEvent(kr1, { server: 's', tool: 't', args: { u } });
    }
    for (let i = 0; i < toShred.length; i++) {
      executeGdprShredding(kr1, { canonicalTargetBuf: toShred[i], dsarTicketId: `DSAR-C-${i}` });
    }

    const kr2 = initKeyring({
      workspaceDir: dir2,
      bucketCount: 4,
      enclaveAdapter: createVolatileRamEnclaveAdapter(),
      customLocatorKey: sharedLocatorKey,
    });
    for (const u of [...survivors].reverse()) {
      recordAgentEvent(kr2, { server: 's', tool: 't', args: { u } });
    }

    assert.deepEqual(inspectActiveSlotPlacements(kr1), inspectActiveSlotPlacements(kr2));
    closeKeyring(kr1);
    closeKeyring(kr2);
  } finally {
    fs.rmSync(dir1, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

test('S3-25: Zero Keyring Metadata Leak — fp128, key_tag64, and slot_id never appear in .jsonl', () => {
  const dir = makeTempDir();
  try {
    const kr = initKeyring({ workspaceDir: dir, bucketCount: 16 });
    recordAgentEvent(kr, { server: 's', tool: 't', args: { u: 'privacy@corp.eu' } });
    const placements = inspectActiveSlotPlacements(kr);
    assert.equal(placements.length, 1);

    const jsonlText = fs.readFileSync(kr.logPath, 'utf8');
    assert.equal(jsonlText.includes(placements[0].fpHex), false);
    assert.equal(jsonlText.includes(placements[0].tagHex), false);
    assert.equal(jsonlText.includes('slot_id'), false);
    assert.equal(jsonlText.includes('fp128'), false);
    closeKeyring(kr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 26–30: Root KEK Rotation, Litigation Hold, Spoliation & Compliance Fraud
// ============================================================================

test('S3-26: Root KEK generation rotation invalidates backed-up pre-shred .isep.keyring snapshot', () => {
  const dir = makeTempDir();
  try {
    const kr = initKeyring({ workspaceDir: dir, bucketCount: 32 });
    recordAgentEvent(kr, { server: 's', tool: 't', args: { u: 'target@corp.eu' } });

    // Attacker/admin copies pre-shred `.isep.keyring` snapshot before DSAR erasure
    const preShredSnapshot = fs.readFileSync(kr.keyringPath);

    executeGdprShredding(kr, {
      canonicalTargetBuf: 'target@corp.eu',
      dsarTicketId: 'DSAR-ROTATE-01',
    });
    const krPath = kr.keyringPath;
    closeKeyring(kr);

    // Attempt to restore old `.isep.keyring` over rotated enclave K_root_kek -> MUST FAIL!
    fs.writeFileSync(krPath, preShredSnapshot);
    assert.throws(() => openKeyring({ workspaceDir: dir }), /OLD_KEYRING_SNAPSHOT_INVALIDATED/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-27: GDPR Art. 17(3)(e) Litigation Hold (0x02) blocks shredding across restarts until released', () => {
  const dir = makeTempDir();
  try {
    const kr1 = initKeyring({ workspaceDir: dir, bucketCount: 32 });
    recordAgentEvent(kr1, { server: 'legal-mcp', tool: 'archive', args: { custodian: 'exec@corp.eu' } });
    const holdRes = setSubjectLitigationHold(kr1, {
      canonicalTargetBuf: 'exec@corp.eu',
      holdActive: true,
    });
    assert.equal(holdRes.slotState, SLOT_STATE.LITIGATION_HOLD);
    closeKeyring(kr1);

    // Reopen from disk -> hold state 0x02 persisted in encrypted Cuckoo bucket!
    const kr2 = openKeyring({ workspaceDir: dir });
    assert.throws(
      () =>
        executeGdprShredding(kr2, {
          canonicalTargetBuf: 'exec@corp.eu',
          dsarTicketId: 'DSAR-BLOCKED-HOLD',
        }),
      /LITIGATION_HOLD_ACTIVE/
    );

    // Release hold -> shred now succeeds
    setSubjectLitigationHold(kr2, { canonicalTargetBuf: 'exec@corp.eu', holdActive: false });
    const shredOk = executeGdprShredding(kr2, {
      canonicalTargetBuf: 'exec@corp.eu',
      dsarTicketId: 'DSAR-RELEASED-HOLD',
    });
    assert.deepEqual(shredOk.erasedSeqs, [1]);
    closeKeyring(kr2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-28: Tampering 1 byte in .isep.events.jsonl triggers UNAUTHORIZED_ERASURE_SPOLIATION', () => {
  const dir = makeTempDir();
  try {
    const kr = initKeyring({ workspaceDir: dir, bucketCount: 32 });
    recordAgentEvent(kr, { server: 'mcp-a', tool: 'read_doc', args: { user: 'u1@corp.eu' } });
    const pubKey = kr.custodianPublicKey;
    const logPath = kr.logPath;
    const blobsPath = kr.blobsPath;
    closeKeyring(kr);

    const tampered = fs.readFileSync(logPath, 'utf8').replace('read_doc', 'read_d0c');
    fs.writeFileSync(logPath, tampered, 'utf8');

    const ver = verifyIsepChainQuick({ logPath, blobsPath, custodianPublicKey: pubKey });
    assert.equal(ver.valid, false);
    assert.equal(ver.status, 'UNAUTHORIZED_ERASURE_SPOLIATION');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-29: Zeroing or truncating .isep.blobs without a signed Tombstone triggers UNAUTHORIZED_ERASURE_SPOLIATION', () => {
  const dir = makeTempDir();
  try {
    const kr = initKeyring({ workspaceDir: dir, bucketCount: 32 });
    recordAgentEvent(kr, { server: 'mcp-a', tool: 'write_doc', args: { user: 'u2@corp.eu' } });
    const pubKey = kr.custodianPublicKey;
    const logPath = kr.logPath;
    const blobsPath = kr.blobsPath;
    closeKeyring(kr);

    // Flip 1 byte in ciphertext without a Tombstone
    const raw = fs.readFileSync(blobsPath);
    raw[raw.length - 10] ^= 0x01;
    fs.writeFileSync(blobsPath, raw);

    const verFlip = verifyIsepChainQuick({ logPath, blobsPath, custodianPublicKey: pubKey });
    assert.equal(verFlip.valid, false);
    assert.equal(verFlip.status, 'UNAUTHORIZED_ERASURE_SPOLIATION');

    // Truncate blob file without a Tombstone
    fs.writeFileSync(blobsPath, Buffer.alloc(0));
    const verTrunc = verifyIsepChainQuick({ logPath, blobsPath, custodianPublicKey: pubKey });
    assert.equal(verTrunc.valid, false);
    assert.equal(verTrunc.status, 'UNAUTHORIZED_ERASURE_SPOLIATION');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-30: Appending a validly-signed Tombstone WITHOUT zeroing .isep.blobs triggers COMPLIANCE_FRAUD_UNPURGED_BYTES', () => {
  const dir = makeTempDir();
  try {
    const kr = initKeyring({ workspaceDir: dir, bucketCount: 32 });
    recordAgentEvent(kr, { server: 'mcp-a', tool: 'log_pii', args: { user: 'fraud@corp.eu' } });

    // Dishonest custodian signs a valid Tombstone claiming seq=1 was erased, WITHOUT zeroing `.isep.blobs`!
    const tsBucket = '2026-11-15T14:00:00Z';
    const witness = b64u(
      domainSha256(
        DOMAIN_PREFIX.TOMBSTONE_WITNESS,
        jcsCanonicalize({ erased_seqs: [1], gen_counter: 2, ts_bucket: tsBucket })
      )
    );
    const fakeSkeleton = {
      dsar_receipt_commit: b64u(crypto.randomBytes(32)),
      dsar_salt: b64u(crypto.randomBytes(16)),
      erased_seqs: [1],
      gen_counter: 2,
      key_destroy_commit: b64u(crypto.randomBytes(32)),
      record_type: 'GDPR_SHRED_TOMBSTONE',
      tombstone_witness: witness,
      ts_bucket: tsBucket,
      v: 'isep-tombstone/3.0',
    };
    const skelHash = b64u(domainSha256(DOMAIN_PREFIX.EVENT_SKELETON, jcsCanonicalize(fakeSkeleton)));
    const chainBytes = domainSha256(DOMAIN_PREFIX.CHAIN_LINK, kr.prevChainHash, skelHash, witness);
    const chainHash = b64u(chainBytes);
    const sig = signDomainPayload('ISEP-v3-CHAIN', chainBytes, kr.custodianPrivateKey);

    fs.appendFileSync(
      kr.logPath,
      JSON.stringify({
        ...fakeSkeleton,
        skeleton_hash: skelHash,
        prev_chain_hash: kr.prevChainHash,
        chain_hash: chainHash,
        key_id: kr.keyId,
        signature: sig,
      }) + '\n'
    );

    const ver = verifyIsepChainQuick({
      logPath: kr.logPath,
      blobsPath: kr.blobsPath,
      custodianPublicKey: kr.custodianPublicKey,
    });
    assert.equal(ver.valid, false);
    assert.equal(ver.status, 'COMPLIANCE_FRAUD_UNPURGED_BYTES');
    closeKeyring(kr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 31–34: Stage 3 CLI (`isep init | record | hold | shred | verify`) & <=78-Col Box
// ============================================================================

test('S3-31: CLI `--version` reports 3.1.0-stage3 and `isep init` + `isep record` + `isep verify` pass', async () => {
  const dir = makeTempDir();
  try {
    const verOut = await runCli(['--version']);
    assert.match(verOut.stdout.trim(), /^3\.1\.\d+(?:-stage\d+)?$/);

    const initOut = await runCli(['isep', 'init', '--dir', dir, '--buckets', '64']);
    assert.equal(initOut.exitCode, 0);

    const recOut = await runCli([
      'isep',
      'record',
      '--dir',
      dir,
      '--server',
      'stripe-mcp',
      '--tool',
      'charge_card',
      '--args',
      JSON.stringify({ customer: 'cli-user@corp.eu', amount: 320 }),
      '--prompt',
      'Charge cli-user@corp.eu $320',
    ]);
    assert.equal(recOut.exitCode, 0);

    const verify1 = await runCli(['isep', 'verify', '--dir', dir]);
    assert.equal(verify1.exitCode, 0);
    assert.match(verify1.stdout, /VALID_UNMODIFIED/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-32: CLI `isep hold` blocks `isep shred` with exit code 2 until `--release` is executed', async () => {
  const dir = makeTempDir();
  try {
    await runCli(['isep', 'init', '--dir', dir, '--buckets', '64']);
    await runCli([
      'isep',
      'record',
      '--dir',
      dir,
      '--server',
      'stripe-mcp',
      '--tool',
      'charge_card',
      '--args',
      JSON.stringify({ customer: 'cli-user@corp.eu', amount: 320 }),
    ]);

    const holdOn = await runCli(['isep', 'hold', '--dir', dir, '--subject', 'cli-user@corp.eu']);
    assert.equal(holdOn.exitCode, 0);

    const blockedShred = await runCli([
      'isep',
      'shred',
      '--dir',
      dir,
      '--subject',
      'cli-user@corp.eu',
      '--ticket',
      'DSAR-CLI-77',
    ]);
    assert.equal(blockedShred.exitCode, 2);
    assert.match(blockedShred.stderr, /LITIGATION_HOLD_ACTIVE/);

    const holdOff = await runCli([
      'isep',
      'hold',
      '--dir',
      dir,
      '--subject',
      'cli-user@corp.eu',
      '--release',
    ]);
    assert.equal(holdOff.exitCode, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-33: CLI `isep shred` + `isep verify --json` transitions chain to VALID_WITH_LAWFUL_ERASURES', async () => {
  const dir = makeTempDir();
  try {
    await runCli(['isep', 'init', '--dir', dir, '--buckets', '64']);
    await runCli([
      'isep',
      'record',
      '--dir',
      dir,
      '--server',
      'stripe-mcp',
      '--tool',
      'charge_card',
      '--args',
      JSON.stringify({ customer: 'cli-user@corp.eu', amount: 320 }),
    ]);

    const shredOk = await runCli([
      'isep',
      'shred',
      '--dir',
      dir,
      '--subject',
      'cli-user@corp.eu',
      '--ticket',
      'DSAR-CLI-77',
    ]);
    assert.equal(shredOk.exitCode, 0);

    const verifyJson = await runCli(['isep', 'verify', '--dir', dir, '--json']);
    assert.equal(verifyJson.exitCode, 0);
    const parsed = JSON.parse(verifyJson.stdout);
    assert.equal(parsed.valid, true);
    assert.equal(parsed.status, 'VALID_WITH_LAWFUL_ERASURES');
    assert.deepEqual(parsed.lawfullyErasedSeqs, [1]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('S3-34: Every line of Stage 3 CLI ASCII terminal reports fits strictly within <= 78 columns with ZERO emojis', async () => {
  const dir = makeTempDir();
  try {
    const initOut = await runCli(['isep', 'init', '--dir', dir, '--buckets', '64']);
    const recOut = await runCli([
      'isep',
      'record',
      '--dir',
      dir,
      '--server',
      'very-long-enterprise-treasury-gateway-mcp-server',
      '--tool',
      'execute_international_sepa_instant_settlement_wire_transfer',
      '--args',
      JSON.stringify({ customer: 'cli-user@corp.eu', amount: 320 }),
    ]);
    const verify1 = await runCli(['isep', 'verify', '--dir', dir]);
    const holdOn = await runCli(['isep', 'hold', '--dir', dir, '--subject', 'cli-user@corp.eu']);
    await runCli(['isep', 'hold', '--dir', dir, '--subject', 'cli-user@corp.eu', '--release']);
    const shredOk = await runCli([
      'isep',
      'shred',
      '--dir',
      dir,
      '--subject',
      'cli-user@corp.eu',
      '--ticket',
      'DSAR-CLI-VERY-LONG-ENTERPRISE-TICKET-IDENTIFIER-2026-0099',
    ]);
    const verify2 = await runCli(['isep', 'verify', '--dir', dir]);

    const emojiRe = /\p{Extended_Pictographic}/u;
    for (const chunk of [initOut.stdout, recOut.stdout, verify1.stdout, holdOn.stdout, shredOk.stdout, verify2.stdout]) {
      assert.equal(emojiRe.test(chunk), false);
      for (const line of chunk.trim().split('\n')) {
        assert.ok(line.length <= 78, `Stage 3 CLI line exceeded 78 columns (${line.length}): ${line}`);
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
