/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 3 Hardened ISEP v3.0 Evidentiary Audit Blackbox & GDPR Art. 17 Shredder
 * Zero external dependencies. Implements:
 * - Signed 256B `ISEPKR03` header + `B` encrypted 288B Cuckoo buckets (4 x 64B slots)
 * - Keyed deterministic Cuckoo eviction & lexicographical `fp128` History-Independent rebuild
 * - 80B `ISBL` sidecar records with immutable `alloc_tag_bytes` (Double-Shred proof)
 * - m-of-m XOR subject key gate + 512B ISO/IEC 7816-4 padded AES-256-GCM
 * - Cold-start reload & crash tail truncation + Two-pass Anti-Spoliation & Compliance-Fraud verifier
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  allocSecure,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  exportEd25519RawPublic,
  resolveEd25519PublicKey,
  signDomainPayload,
  unb64u,
  verifyDomainPayload,
  zeroizeBuffer,
} from '../core/crypto-primitives.mjs';
import { writeFileAtomic600 } from '../core/workspace-io.mjs';
import { createHeadlessEnclaveAdapter } from './enclave-adapter.mjs';
import {
  canonicalizeSubjectIdentifier,
  extractAndPseudonymizePayload,
  quantizeTimestamp60s,
} from './nist-ff1-twins.mjs';

export const MAGIC_KR = Buffer.from('ISEPKR03', 'ascii');
export const MAGIC_BLOB = Buffer.from('ISBL', 'ascii');

export const SLOT_STATE = Object.freeze({
  FREE_CHAFF: 0x00,
  ACTIVE: 0x01,
  LITIGATION_HOLD: 0x02,
});

export const BLOB_STATE = Object.freeze({
  PURGED: 0x00,
  ACTIVE: 0x01,
});

const KR_HEADER_BYTES = 256;
const KR_SIGNED_PREFIX_BYTES = 192;
const SLOTS_PER_BUCKET = 4;
const SLOT_BYTES = 64;
const BUCKET_PLAIN_BYTES = SLOTS_PER_BUCKET * SLOT_BYTES; // 256B
const BUCKET_DISK_BYTES = 288; // 12B iv + 16B tag + 4B bucketIdx + 256B cipher
const BLOB_HEADER_BYTES = 80;
const BLOB_BLOCK_ALIGN = 512;

const KR_HDR_SIGN_LABEL = 'ISEP-v3-KR-HDR';
const CHAIN_SIGN_LABEL = 'ISEP-v3-CHAIN';

/**
 * Check power-of-two integer >= 4.
 * @param {number} n
 * @returns {boolean}
 */
function isPowerOfTwoAtLeast4(n) {
  return Number.isInteger(n) && n >= 4 && (n & (n - 1)) === 0;
}

/**
 * Encode 64-bit unsigned BigInt as 8-byte big-endian Buffer.
 * @param {bigint | number} n
 * @returns {Buffer}
 */
function u64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n), 0);
  return b;
}

/**
 * Encode 32-bit unsigned number as 4-byte big-endian Buffer.
 * @param {number} n
 * @returns {Buffer}
 */
function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

/**
 * Encode 16-bit unsigned number as 2-byte big-endian Buffer.
 * @param {number} n
 * @returns {Buffer}
 */
function u16be(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
}

/**
 * ISO/IEC 7816-4 padding (`0x80` followed by `0x00` bytes) to a strict multiple of `512` bytes.
 * @param {Buffer} plainBuf
 * @returns {Buffer}
 */
export function padIso7816_4(plainBuf) {
  const totalLen = Math.max(
    BLOB_BLOCK_ALIGN,
    Math.ceil((plainBuf.length + 1) / BLOB_BLOCK_ALIGN) * BLOB_BLOCK_ALIGN
  );
  const out = allocSecure(totalLen);
  plainBuf.copy(out, 0);
  out[plainBuf.length] = 0x80;
  return out;
}

/**
 * Remove ISO/IEC 7816-4 padding.
 * @param {Buffer} paddedBuf
 * @returns {Buffer}
 */
export function unpadIso7816_4(paddedBuf) {
  let i = paddedBuf.length - 1;
  while (i >= 0 && paddedBuf[i] === 0x00) {
    i--;
  }
  if (i < 0 || paddedBuf[i] !== 0x80) {
    throw new Error('Invalid ISO/IEC 7816-4 padding marker in sidecar plaintext');
  }
  return Buffer.from(paddedBuf.subarray(0, i));
}

/**
 * Compute 16-byte `fp128` and 8-byte `keyTag64` from `kLocator` (32B) and `canonicalTargetBuf`.
 * @param {Buffer} kLocator
 * @param {Buffer} canonicalTargetBuf
 * @returns {{ fp128: Buffer, fpHex: string, keyTag64: Buffer, tagHex: string }}
 */
function computeSubjectLocators(kLocator, canonicalTargetBuf) {
  const fp128 = crypto
    .createHmac('sha256', kLocator)
    .update(Buffer.from('ISEP-v3-FP128\0', 'ascii'))
    .update(canonicalTargetBuf)
    .digest()
    .subarray(0, 16);
  const keyTag64 = crypto
    .createHmac('sha256', kLocator)
    .update(Buffer.from('ISEP-v3-TAG64\0', 'ascii'))
    .update(canonicalTargetBuf)
    .digest()
    .subarray(0, 8);
  return {
    fp128: Buffer.from(fp128),
    fpHex: fp128.toString('hex'),
    keyTag64: Buffer.from(keyTag64),
    tagHex: keyTag64.toString('hex'),
  };
}

/**
 * Compute deterministic Cuckoo candidate bucket pair `(b1, b2)` (`b1 !== b2`) from `fp128`.
 * @param {Buffer} fp128
 * @param {number} bucketCount
 * @returns {[number, number]}
 */
function computeCuckooBucketPair(fp128, bucketCount) {
  const mask = bucketCount - 1;
  const h = crypto
    .createHash('sha256')
    .update(Buffer.from('ISEP-v3-CUCKOO-BKT\0', 'ascii'))
    .update(fp128)
    .digest();
  const b1 = h.readUInt32BE(0) & mask;
  const oddDelta = (h.readUInt32BE(4) | 1) & mask;
  const b2 = (b1 ^ (oddDelta || 1)) & mask;
  return [b1, b2];
}

/**
 * Generate a 64-byte `FREE_CHAFF` slot (`slot[0] = 0x00`, `slot[1..63]` = CSPRNG).
 * @returns {Buffer}
 */
function generateFreeChaffSlot64() {
  const buf = Buffer.alloc(SLOT_BYTES);
  crypto.randomFillSync(buf, 1, SLOT_BYTES - 1);
  buf[0] = SLOT_STATE.FREE_CHAFF;
  return buf;
}

/**
 * Serialize an active/hold subject slot entry into an exact 64-byte Buffer.
 * Bytes `[26..31]` are strictly `0x00` so slot representation is 100% history- and timestamp-independent.
 * @param {{ state: number, keyTag64: Buffer, fp128: Buffer, rSlot: Buffer }} entry
 * @returns {Buffer}
 */
function encodeActiveSlot64(entry) {
  const buf = allocSecure(SLOT_BYTES);
  buf[0] = entry.state & 0xff;
  buf[1] = 0x00;
  entry.keyTag64.copy(buf, 2, 0, 8);
  entry.fp128.copy(buf, 10, 0, 16);
  // [26..31] reserved 0x00
  entry.rSlot.copy(buf, 32, 0, 32);
  return buf;
}

/**
 * Parse a 64-byte decrypted slot buffer. Returns `null` if `FREE_CHAFF` (`0x00`).
 * @param {Buffer} slotBuf64
 */
function decodeSlot64(slotBuf64) {
  const state = slotBuf64[0];
  if (state === SLOT_STATE.FREE_CHAFF) {
    return null;
  }
  if (state !== SLOT_STATE.ACTIVE && state !== SLOT_STATE.LITIGATION_HOLD) {
    throw new Error(`Corrupted keyring slot state byte: 0x${state.toString(16)}`);
  }
  const keyTag64 = Buffer.from(slotBuf64.subarray(2, 10));
  const fp128 = Buffer.from(slotBuf64.subarray(10, 26));
  const rSlot = allocSecure(32);
  slotBuf64.copy(rSlot, 0, 32, 64);
  return {
    state,
    keyTag64,
    tagHex: keyTag64.toString('hex'),
    fp128,
    fpHex: fp128.toString('hex'),
    rSlot,
  };
}

/**
 * Rebuild Cuckoo hash table in canonical lexicographical `fp128` order with keyed deterministic
 * Cuckoo eviction (`victimIdx = sha256(carryFp128 || u16be(kick))[0] & 3`), guaranteeing 100% History Independence!
 *
 * @param {Iterable<{ state: number, keyTag64: Buffer, tagHex: string, fp128: Buffer, fpHex: string, rSlot: Buffer }>} subjectsIter
 * @param {number} bucketCount
 */
function buildCanonicalCuckooLayout(subjectsIter, bucketCount) {
  const sorted = [...subjectsIter].sort((a, b) => Buffer.compare(a.fp128, b.fp128));
  /** @type {Array<Array<typeof sorted[0] | null>>} */
  const grid = Array.from({ length: bucketCount }, () => [null, null, null, null]);

  for (const item of sorted) {
    const [b1, b2] = computeCuckooBucketPair(item.fp128, bucketCount);
    const free1 = grid[b1].indexOf(null);
    if (free1 !== -1) {
      grid[b1][free1] = item;
      continue;
    }
    const free2 = grid[b2].indexOf(null);
    if (free2 !== -1) {
      grid[b2][free2] = item;
      continue;
    }

    let carry = item;
    let curBucket = b1;
    let placed = false;

    for (let kick = 0; kick < 512; kick++) {
      const victimIdx =
        crypto.createHash('sha256').update(carry.fp128).update(u16be(kick)).digest()[0] & 3;
      const evicted = /** @type {typeof sorted[0]} */ (grid[curBucket][victimIdx]);
      grid[curBucket][victimIdx] = carry;
      carry = evicted;

      const [cb1, cb2] = computeCuckooBucketPair(carry.fp128, bucketCount);
      curBucket = curBucket === cb1 ? cb2 : cb1;

      const openIdx = grid[curBucket].indexOf(null);
      if (openIdx !== -1) {
        grid[curBucket][openIdx] = carry;
        placed = true;
        break;
      }
    }

    if (!placed) {
      throw new Error('ISEP Cuckoo table load factor exceeded (512 kicks); increase bucketCount');
    }
  }

  // Canonical intra-bucket ordering by fp128 so slot index within bucket is also 100% history-independent
  for (let b = 0; b < bucketCount; b++) {
    const occupied = grid[b].filter((x) => x !== null).sort((x, y) => Buffer.compare(x.fp128, y.fp128));
    for (let s = 0; s < SLOTS_PER_BUCKET; s++) {
      grid[b][s] = s < occupied.length ? occupied[s] : null;
    }
  }

  return grid;
}

/**
 * Encrypt a single 256-byte bucket (`4 x 64B` slots) into a 288-byte disk bucket record.
 * `AAD = MAGIC_KR || u64be(genCounter) || u32be(bucketIdx)`.
 *
 * @param {Buffer} kTableDek
 * @param {bigint} genCounter
 * @param {number} bucketIdx
 * @param {Array<{ state: number, keyTag64: Buffer, fp128: Buffer, rSlot: Buffer } | null>} bucketSlots
 * @returns {Buffer}
 */
function encryptBucket288(kTableDek, genCounter, bucketIdx, bucketSlots) {
  const plain256 = allocSecure(BUCKET_PLAIN_BYTES);
  try {
    for (let s = 0; s < SLOTS_PER_BUCKET; s++) {
      const entry = bucketSlots[s];
      const slotBuf = entry ? encodeActiveSlot64(entry) : generateFreeChaffSlot64();
      slotBuf.copy(plain256, s * SLOT_BYTES);
      if (entry) zeroizeBuffer(slotBuf);
    }

    const iv12 = crypto.randomBytes(12);
    const aad = Buffer.concat([MAGIC_KR, u64be(genCounter), u32be(bucketIdx)]);
    const cipher = crypto.createCipheriv('aes-256-gcm', kTableDek, iv12);
    cipher.setAAD(aad);
    const enc256 = Buffer.concat([cipher.update(plain256), cipher.final()]);
    const tag16 = cipher.getAuthTag();

    const out = Buffer.alloc(BUCKET_DISK_BYTES);
    iv12.copy(out, 0);
    tag16.copy(out, 12);
    out.writeUInt32BE(bucketIdx >>> 0, 28);
    enc256.copy(out, 32);
    return out;
  } finally {
    zeroizeBuffer(plain256);
  }
}

/**
 * Decrypt a 288-byte disk bucket record into an array of 4 decoded slot objects (or `null` for chaff).
 * @param {Buffer} kTableDek
 * @param {bigint} genCounter
 * @param {number} bucketIdx
 * @param {Buffer} diskBucket288
 */
function decryptBucket288(kTableDek, genCounter, bucketIdx, diskBucket288) {
  if (diskBucket288.length !== BUCKET_DISK_BYTES) {
    throw new Error(`Invalid bucket byte length at index ${bucketIdx}: ${diskBucket288.length}`);
  }
  const iv12 = diskBucket288.subarray(0, 12);
  const tag16 = diskBucket288.subarray(12, 28);
  const recordedIdx = diskBucket288.readUInt32BE(28);
  if (recordedIdx !== bucketIdx) {
    throw new Error(`Bucket index mismatch: expected ${bucketIdx}, found ${recordedIdx}`);
  }
  const enc256 = diskBucket288.subarray(32, 288);

  const aad = Buffer.concat([MAGIC_KR, u64be(genCounter), u32be(bucketIdx)]);
  const decipher = crypto.createDecipheriv('aes-256-gcm', kTableDek, iv12);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag16);
  const plain256 = Buffer.concat([decipher.update(enc256), decipher.final()]);

  try {
    const decoded = new Array(SLOTS_PER_BUCKET);
    for (let s = 0; s < SLOTS_PER_BUCKET; s++) {
      decoded[s] = decodeSlot64(plain256.subarray(s * SLOT_BYTES, (s + 1) * SLOT_BYTES));
    }
    return decoded;
  } finally {
    plain256.fill(0);
  }
}

/**
 * Pack and Ed25519-sign the 256-byte `ISEPKR03` keyring header (`"ISEP-v3-KR-HDR\0" || Header[0..191]`).
 */
function buildSignedKeyringHeader256({
  genCounter,
  bucketCount,
  custodianPubRaw,
  custodianPrivateKey,
  kRootKek,
  kTableDek,
  kLocator,
  keyringId,
}) {
  const hdr = Buffer.alloc(KR_HEADER_BYTES, 0);
  MAGIC_KR.copy(hdr, 0); // [0..7]
  hdr.writeBigUInt64BE(BigInt(genCounter), 8); // [8..15]
  hdr.writeUInt32BE(bucketCount >>> 0, 16); // [16..19]
  hdr.writeUInt32BE(SLOTS_PER_BUCKET, 20); // [20..23]
  custodianPubRaw.copy(hdr, 24, 0, 32); // [24..55]

  const wrapIv = crypto.randomBytes(12);
  const keyBundle64 = allocSecure(64);
  try {
    kTableDek.copy(keyBundle64, 0, 0, 32);
    kLocator.copy(keyBundle64, 32, 0, 32);
    const cipher = crypto.createCipheriv('aes-256-gcm', kRootKek, wrapIv);
    cipher.setAAD(hdr.subarray(0, 56));
    const wrapped64 = Buffer.concat([cipher.update(keyBundle64), cipher.final()]);
    const wrapTag = cipher.getAuthTag();

    wrapIv.copy(hdr, 56); // [56..67]
    wrapTag.copy(hdr, 68); // [68..83]
    wrapped64.copy(hdr, 84); // [84..147]
  } finally {
    zeroizeBuffer(keyBundle64);
  }

  const idHash = crypto.createHash('sha256').update(String(keyringId), 'utf8').digest();
  idHash.copy(hdr, 148); // [148..179]

  const sigMsg = Buffer.concat([
    Buffer.from(`${KR_HDR_SIGN_LABEL}\0`, 'ascii'),
    hdr.subarray(0, KR_SIGNED_PREFIX_BYTES),
  ]);
  const privObj =
    custodianPrivateKey instanceof crypto.KeyObject
      ? custodianPrivateKey
      : crypto.createPrivateKey(custodianPrivateKey);
  const sig64 = crypto.sign(null, sigMsg, privObj);
  sig64.copy(hdr, KR_SIGNED_PREFIX_BYTES); // [192..255]

  return hdr;
}

/**
 * Verify 256-byte `ISEPKR03` keyring header Ed25519 signature and unwrap `(kTableDek, kLocator)` via `kRootKek`.
 */
function parseAndUnwrapKeyringHeader256(hdr256, kRootKek, expectedCustodianPub = null) {
  if (!Buffer.isBuffer(hdr256) || hdr256.length < KR_HEADER_BYTES) {
    throw new Error('Truncated ISEPKR03 keyring header');
  }
  if (!hdr256.subarray(0, 8).equals(MAGIC_KR)) {
    throw new Error('Invalid keyring magic (expected ISEPKR03)');
  }

  const genCounter = hdr256.readBigUInt64BE(8);
  const bucketCount = hdr256.readUInt32BE(16);
  const slotsPerBucket = hdr256.readUInt32BE(20);
  if (!isPowerOfTwoAtLeast4(bucketCount) || slotsPerBucket !== SLOTS_PER_BUCKET) {
    throw new Error(`Invalid keyring geometry: buckets=${bucketCount}, slots=${slotsPerBucket}`);
  }

  const custodianPubRaw = Buffer.from(hdr256.subarray(24, 56));
  if (expectedCustodianPub) {
    const expObj = resolveEd25519PublicKey(expectedCustodianPub);
    const expRaw = exportEd25519RawPublic(expObj);
    if (!expRaw.equals(custodianPubRaw)) {
      throw new Error('Keyring header custodian public key mismatch');
    }
  }

  const pubObj = resolveEd25519PublicKey(custodianPubRaw);
  const sig64 = hdr256.subarray(KR_SIGNED_PREFIX_BYTES, KR_HEADER_BYTES);
  const sigMsg = Buffer.concat([
    Buffer.from(`${KR_HDR_SIGN_LABEL}\0`, 'ascii'),
    hdr256.subarray(0, KR_SIGNED_PREFIX_BYTES),
  ]);
  if (!crypto.verify(null, sigMsg, pubObj, sig64)) {
    throw new Error('ISEPKR03 keyring header Ed25519 signature verification failed');
  }

  const wrapIv = hdr256.subarray(56, 68);
  const wrapTag = hdr256.subarray(68, 84);
  const wrapped64 = hdr256.subarray(84, 148);

  let unwrapped;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', kRootKek, wrapIv);
    decipher.setAAD(hdr256.subarray(0, 56));
    decipher.setAuthTag(wrapTag);
    unwrapped = Buffer.concat([decipher.update(wrapped64), decipher.final()]);
  } catch {
    throw new Error(
      'OLD_KEYRING_SNAPSHOT_INVALIDATED: Failed to unwrap ISEPKR03 keys under current Enclave Root KEK'
    );
  }

  const kTableDek = allocSecure(32);
  const kLocator = allocSecure(32);
  unwrapped.copy(kTableDek, 0, 0, 32);
  unwrapped.copy(kLocator, 0, 32, 64);
  unwrapped.fill(0);

  return {
    genCounter,
    bucketCount,
    custodianPubRaw,
    kTableDek,
    kLocator,
  };
}

/**
 * Compute bucket fingerprint string for dirty-bucket diffing.
 * @param {Array<{ state: number, fpHex: string, rSlot: Buffer } | null>} bucketSlots
 * @returns {string}
 */
function bucketStateSignature(bucketSlots) {
  return bucketSlots
    .map((s) => (s ? `${s.state}:${s.fpHex}:${s.rSlot.toString('hex')}` : '_'))
    .join('|');
}

/**
 * Resolve standard ISEP file paths inside `workspaceDir` (or explicit overrides).
 * @param {Record<string, any>} opts
 */
export function resolveIsepPaths(opts = {}) {
  const workspaceDir = path.resolve(opts.workspaceDir || process.cwd());
  const sipDir = path.join(workspaceDir, '.sip');
  const isepDir = opts.isepDir ? path.resolve(opts.isepDir) : path.join(sipDir, 'isep');
  const keyringId = String(opts.keyringId || 'default');
  return {
    workspaceDir,
    sipDir,
    isepDir,
    keyringId,
    keyringPath: opts.keyringPath ? path.resolve(opts.keyringPath) : path.join(isepDir, `${keyringId}.isep.keyring`),
    logPath: opts.logPath ? path.resolve(opts.logPath) : path.join(isepDir, `${keyringId}.isep.events.jsonl`),
    blobsPath: opts.blobsPath ? path.resolve(opts.blobsPath) : path.join(isepDir, `${keyringId}.isep.blobs`),
    enclaveDir: opts.enclaveDir ? path.resolve(opts.enclaveDir) : path.join(sipDir, 'enclave'),
  };
}

/**
 * Write full `.isep.keyring` (`256B` header + `bucketCount * 288B` buckets) atomically (`0o600`).
 * @param {any} ctx
 */
function persistFullKeyringAtomic(ctx) {
  const kRootKek = ctx.enclaveAdapter.unsealRootKey(ctx.keyringId);
  try {
    const hdr256 = buildSignedKeyringHeader256({
      genCounter: ctx.genCounter,
      bucketCount: ctx.bucketCount,
      custodianPubRaw: ctx.custodianPubRaw,
      custodianPrivateKey: ctx.custodianPrivateKey,
      kRootKek,
      kTableDek: ctx.kTableDek,
      kLocator: ctx.kLocator,
      keyringId: ctx.keyringId,
    });

    const totalBytes = KR_HEADER_BYTES + ctx.bucketCount * BUCKET_DISK_BYTES;
    const fullImg = Buffer.alloc(totalBytes);
    hdr256.copy(fullImg, 0);

    for (let b = 0; b < ctx.bucketCount; b++) {
      const encBucket = encryptBucket288(ctx.kTableDek, ctx.genCounter, b, ctx.ramBuckets[b]);
      encBucket.copy(fullImg, KR_HEADER_BYTES + b * BUCKET_DISK_BYTES);
    }

    writeFileAtomic600(ctx.keyringPath, fullImg, { mode: 0o600 });
  } finally {
    zeroizeBuffer(kRootKek);
  }
}

/**
 * Flush only dirty buckets in-place to `.isep.keyring` (`fsyncSync`), keeping O(1) disk writes during normal inserts.
 * @param {any} ctx
 * @param {number[]} dirtyBucketIndices
 */
function flushDirtyBucketsInPlace(ctx, dirtyBucketIndices) {
  if (dirtyBucketIndices.length === 0) return;
  const fd = fs.openSync(ctx.keyringPath, 'r+');
  try {
    for (const b of dirtyBucketIndices) {
      const encBucket = encryptBucket288(ctx.kTableDek, ctx.genCounter, b, ctx.ramBuckets[b]);
      fs.writeSync(fd, encBucket, 0, BUCKET_DISK_BYTES, KR_HEADER_BYTES + b * BUCKET_DISK_BYTES);
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * 1) Initialize a brand-new Hardened ISEP v3.0 Keyring, `.jsonl` ledger, and `.isep.blobs` sidecar.
 *
 * @param {{
 *   workspaceDir?: string,
 *   isepDir?: string,
 *   keyringId?: string,
 *   keyringPath?: string,
 *   logPath?: string,
 *   blobsPath?: string,
 *   bucketCount?: number,
 *   force?: boolean,
 *   enclaveAdapter?: any,
 *   custodianKeypair?: { privateKey: crypto.KeyObject, publicKey: crypto.KeyObject },
 *   customLocatorKey?: Buffer,
 *   customTableDek?: Buffer,
 *   deterministicSlotSecretFn?: (canonicalTargetBuf: Buffer) => Buffer,
 * }} [opts]
 */
export function initKeyring(opts = {}) {
  const paths = resolveIsepPaths(opts);
  const bucketCount = opts.bucketCount ?? 1024;
  if (!isPowerOfTwoAtLeast4(bucketCount)) {
    throw new RangeError(`bucketCount must be a power of 2 >= 4, got ${bucketCount}`);
  }

  if (!opts.force) {
    const existingKeyringNonEmpty =
      fs.existsSync(paths.keyringPath) && fs.statSync(paths.keyringPath).size > 0;
    const existingLedgerNonEmpty =
      fs.existsSync(paths.logPath) && fs.statSync(paths.logPath).size > 0;
    if (existingKeyringNonEmpty || existingLedgerNonEmpty) {
      const err = /** @type {Error & { code?: string }} */ (
        new Error(
          `[ISEP_ALREADY_INITIALIZED] Existing non-empty ISEP v3.0 keyring or ledger detected at ${paths.isepDir}. Pass --force (or { force: true }) to explicitly re-initialize.`
        )
      );
      err.code = 'ISEP_ALREADY_INITIALIZED';
      throw err;
    }
  }

  fs.mkdirSync(paths.isepDir, { recursive: true, mode: 0o700 });
  const enclaveAdapter = opts.enclaveAdapter || createHeadlessEnclaveAdapter(paths.enclaveDir);

  const keyInfo = opts.custodianKeypair
    ? {
        privateKey: opts.custodianKeypair.privateKey,
        publicKey: opts.custodianKeypair.publicKey,
        publicKeyB64u: b64u(exportEd25519RawPublic(opts.custodianKeypair.publicKey)),
        keyId: b64u(
          domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, exportEd25519RawPublic(opts.custodianKeypair.publicKey))
        ).slice(0, 16),
      }
    : ensureDeviceEd25519Keypair(paths.sipDir);

  const custodianPubRaw = exportEd25519RawPublic(keyInfo.publicKey);

  const kRootKek = allocSecure(32);
  crypto.randomFillSync(kRootKek);
  enclaveAdapter.sealRootKey(paths.keyringId, kRootKek);
  zeroizeBuffer(kRootKek);

  const kTableDek = allocSecure(32);
  if (opts.customTableDek) {
    opts.customTableDek.copy(kTableDek, 0, 0, 32);
  } else {
    crypto.randomFillSync(kTableDek);
  }

  const kLocator = allocSecure(32);
  if (opts.customLocatorKey) {
    opts.customLocatorKey.copy(kLocator, 0, 0, 32);
  } else {
    crypto.randomFillSync(kLocator);
  }

  /** @type {Map<string, { state: number, keyTag64: Buffer, tagHex: string, fp128: Buffer, fpHex: string, rSlot: Buffer }>} */
  const subjectsByFp = new Map();
  const ramBuckets = buildCanonicalCuckooLayout([], bucketCount);

  if (!fs.existsSync(paths.logPath)) {
    writeFileAtomic600(paths.logPath, '', { mode: 0o600 });
  } else {
    writeFileAtomic600(paths.logPath, '', { mode: 0o600 });
  }
  writeFileAtomic600(paths.blobsPath, Buffer.alloc(0), { mode: 0o600 });

  const ctx = {
    ...paths,
    enclaveAdapter,
    bucketCount,
    genCounter: 1n,
    custodianPrivateKey: keyInfo.privateKey,
    custodianPublicKey: keyInfo.publicKey,
    custodianPubRaw,
    custodianPubB64u: keyInfo.publicKeyB64u,
    keyId: keyInfo.keyId,
    kTableDek,
    kLocator,
    subjectsByFp,
    ramBuckets,
    seqCounter: 0,
    prevChainHash: 'GENESIS',
    /** @type {Map<string, Array<{ seq: number, offset: number, recordByteLen: number }>>} */
    tagIndex: new Map(),
    deterministicSlotSecretFn: opts.deterministicSlotSecretFn || null,
    closed: false,
  };

  persistFullKeyringAtomic(ctx);
  return ctx;
}

/**
 * Scan `.jsonl` & `.isep.blobs` on Cold-Start Reload, truncating any incomplete crash-tail bytes
 * and reconstructing `seqCounter`, `prevChainHash`, and `tagIndex`.
 */
function recoverLedgerAndBlobsState(logPath, blobsPath) {
  let seqCounter = 0;
  let prevChainHash = 'GENESIS';
  let expectedMaxBlobEnd = 0;

  if (fs.existsSync(logPath)) {
    const rawBuf = fs.readFileSync(logPath);
    const rawStr = rawBuf.toString('utf8');
    // Truncate incomplete trailing crash line (not ending with \n or invalid JSON)
    const lastNewline = rawStr.lastIndexOf('\n');
    let cleanLines = [];
    let validByteEnd = 0;

    if (lastNewline !== -1) {
      const candidateChunk = rawStr.slice(0, lastNewline + 1);
      const lines = candidateChunk.split('\n');
      let byteCursor = 0;
      for (let i = 0; i < lines.length - 1; i++) {
        const line = lines[i];
        const lineByteLen = Buffer.byteLength(line, 'utf8') + 1;
        try {
          const parsed = JSON.parse(line);
          if (!parsed || typeof parsed !== 'object' || !parsed.chain_hash) {
            break;
          }
          cleanLines.push(parsed);
          byteCursor += lineByteLen;
          validByteEnd = byteCursor;
        } catch {
          break;
        }
      }
    }

    if (validByteEnd < rawBuf.length) {
      fs.truncateSync(logPath, validByteEnd);
    }

    for (const rec of cleanLines) {
      if (rec.record_type === 'AGENT_EVENT' && Number.isInteger(rec.seq)) {
        if (rec.seq > seqCounter) seqCounter = rec.seq;
        if (
          typeof rec.sidecar_offset === 'number' &&
          typeof rec.sidecar_byte_len === 'number'
        ) {
          const endPos = rec.sidecar_offset + rec.sidecar_byte_len;
          if (endPos > expectedMaxBlobEnd) expectedMaxBlobEnd = endPos;
        }
      }
      prevChainHash = rec.chain_hash;
    }
  } else {
    writeFileAtomic600(logPath, '', { mode: 0o600 });
  }

  /** @type {Map<string, Array<{ seq: number, offset: number, recordByteLen: number }>>} */
  const tagIndex = new Map();

  if (fs.existsSync(blobsPath)) {
    const stat = fs.statSync(blobsPath);
    let fileSize = stat.size;

    // Truncate uncommitted trailing crash bytes beyond `.jsonl` high-water mark
    if (expectedMaxBlobEnd >= 0 && fileSize > expectedMaxBlobEnd && seqCounter > 0) {
      fs.truncateSync(blobsPath, expectedMaxBlobEnd);
      fileSize = expectedMaxBlobEnd;
    } else if (seqCounter === 0 && fileSize > 0) {
      fs.truncateSync(blobsPath, 0);
      fileSize = 0;
    }

    const fd = fs.openSync(blobsPath, 'r');
    try {
      let cursor = 0;
      const hdrBuf = Buffer.alloc(BLOB_HEADER_BYTES);
      while (cursor + BLOB_HEADER_BYTES <= fileSize) {
        const readHdr = fs.readSync(fd, hdrBuf, 0, BLOB_HEADER_BYTES, cursor);
        if (readHdr < BLOB_HEADER_BYTES || !hdrBuf.subarray(0, 4).equals(MAGIC_BLOB)) {
          // Incomplete crash tail
          fs.closeSync(fd);
          fs.truncateSync(blobsPath, cursor);
          return { seqCounter, prevChainHash, tagIndex };
        }
        const state = hdrBuf[4];
        const allocTagBytes = hdrBuf.readUInt16BE(6);
        const cipherLen = hdrBuf.readUInt32BE(8);
        const seq = Number(hdrBuf.readBigUInt64BE(12));
        const recordByteLen = BLOB_HEADER_BYTES + allocTagBytes + cipherLen;

        if (cursor + recordByteLen > fileSize) {
          fs.closeSync(fd);
          fs.truncateSync(blobsPath, cursor);
          return { seqCounter, prevChainHash, tagIndex };
        }

        if (state === BLOB_STATE.ACTIVE && allocTagBytes > 0) {
          const tagsBuf = Buffer.alloc(allocTagBytes);
          fs.readSync(fd, tagsBuf, 0, allocTagBytes, cursor + BLOB_HEADER_BYTES);
          const tagCount = Math.floor(allocTagBytes / 8);
          for (let t = 0; t < tagCount; t++) {
            const tagHex = tagsBuf.subarray(t * 8, (t + 1) * 8).toString('hex');
            let arr = tagIndex.get(tagHex);
            if (!arr) {
              arr = [];
              tagIndex.set(tagHex, arr);
            }
            arr.push({ seq, offset: cursor, recordByteLen });
          }
        }

        cursor += recordByteLen;
      }
    } finally {
      try {
        fs.closeSync(fd);
      } catch {
        // already closed on truncate branch
      }
    }
  } else {
    writeFileAtomic600(blobsPath, Buffer.alloc(0), { mode: 0o600 });
  }

  return { seqCounter, prevChainHash, tagIndex };
}

/**
 * 2) Cold-Start Persistence & Crash Recovery (`openKeyring`):
 * Verifies `ISEPKR03` header `Ed25519` signature, unwraps `(K_table_dek, K_locator)` via `enclaveAdapter.unsealRootKey`,
 * decrypts all `B` buckets into RAM, and scans `.jsonl` + `.isep.blobs` to rebuild `seqCounter`, `prevChainHash`, and `tagIndex`.
 */
export function openKeyring(opts = {}) {
  const paths = resolveIsepPaths(opts);
  if (!fs.existsSync(paths.keyringPath)) {
    throw new Error(`ISEP keyring not found at ${paths.keyringPath}`);
  }
  const enclaveAdapter = opts.enclaveAdapter || createHeadlessEnclaveAdapter(paths.enclaveDir);

  const keyInfo = opts.custodianKeypair
    ? {
        privateKey: opts.custodianKeypair.privateKey,
        publicKey: opts.custodianKeypair.publicKey,
        publicKeyB64u: b64u(exportEd25519RawPublic(opts.custodianKeypair.publicKey)),
        keyId: b64u(
          domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, exportEd25519RawPublic(opts.custodianKeypair.publicKey))
        ).slice(0, 16),
      }
    : ensureDeviceEd25519Keypair(paths.sipDir);

  const rawFile = fs.readFileSync(paths.keyringPath);
  const kRootKek = enclaveAdapter.unsealRootKey(paths.keyringId);
  let parsedHdr;
  try {
    parsedHdr = parseAndUnwrapKeyringHeader256(
      rawFile.subarray(0, KR_HEADER_BYTES),
      kRootKek,
      keyInfo.publicKey
    );
  } finally {
    zeroizeBuffer(kRootKek);
  }

  const expectedTotal = KR_HEADER_BYTES + parsedHdr.bucketCount * BUCKET_DISK_BYTES;
  if (rawFile.length !== expectedTotal) {
    zeroizeBuffer(parsedHdr.kTableDek);
    zeroizeBuffer(parsedHdr.kLocator);
    throw new Error(`Corrupted keyring size: expected ${expectedTotal} bytes, got ${rawFile.length}`);
  }

  /** @type {Map<string, { state: number, keyTag64: Buffer, tagHex: string, fp128: Buffer, fpHex: string, rSlot: Buffer }>} */
  const subjectsByFp = new Map();
  const ramBuckets = new Array(parsedHdr.bucketCount);

  for (let b = 0; b < parsedHdr.bucketCount; b++) {
    const offset = KR_HEADER_BYTES + b * BUCKET_DISK_BYTES;
    const diskSlice = rawFile.subarray(offset, offset + BUCKET_DISK_BYTES);
    const decodedSlots = decryptBucket288(parsedHdr.kTableDek, parsedHdr.genCounter, b, diskSlice);
    ramBuckets[b] = decodedSlots;
    for (const s of decodedSlots) {
      if (s) {
        subjectsByFp.set(s.fpHex, s);
      }
    }
  }

  const recovered = recoverLedgerAndBlobsState(paths.logPath, paths.blobsPath);

  return {
    ...paths,
    enclaveAdapter,
    bucketCount: parsedHdr.bucketCount,
    genCounter: parsedHdr.genCounter,
    custodianPrivateKey: keyInfo.privateKey,
    custodianPublicKey: keyInfo.publicKey,
    custodianPubRaw: parsedHdr.custodianPubRaw,
    custodianPubB64u: keyInfo.publicKeyB64u,
    keyId: keyInfo.keyId,
    kTableDek: parsedHdr.kTableDek,
    kLocator: parsedHdr.kLocator,
    subjectsByFp,
    ramBuckets,
    seqCounter: recovered.seqCounter,
    prevChainHash: recovered.prevChainHash,
    tagIndex: recovered.tagIndex,
    deterministicSlotSecretFn: opts.deterministicSlotSecretFn || null,
    closed: false,
  };
}

/**
 * Open an existing ISEP keyring if present on disk, or initialize a new one cleanly.
 */
export function initOrOpenKeyring(opts = {}) {
  const paths = resolveIsepPaths(opts);
  if (fs.existsSync(paths.keyringPath)) {
    return openKeyring(opts);
  }
  return initKeyring(opts);
}

/**
 * Safely zeroize all in-memory key material when closing an ISEP context.
 * @param {any} ctx
 */
export function closeKeyring(ctx) {
  if (!ctx || ctx.closed) return;
  zeroizeBuffer(ctx.kTableDek);
  zeroizeBuffer(ctx.kLocator);
  for (const subj of ctx.subjectsByFp.values()) {
    zeroizeBuffer(subj.rSlot);
  }
  ctx.subjectsByFp.clear();
  ctx.closed = true;
}

/**
 * Inspect current active/hold slot placements `(bucketIdx, slotIdx, fpHex, tagHex, state)`
 * for History-Independence verification.
 * @param {any} ctx
 */
export function inspectActiveSlotPlacements(ctx) {
  const placements = [];
  for (let b = 0; b < ctx.bucketCount; b++) {
    for (let s = 0; s < SLOTS_PER_BUCKET; s++) {
      const entry = ctx.ramBuckets[b][s];
      if (entry) {
        placements.push({
          bucketIdx: b,
          slotIdx: s,
          state: entry.state,
          fpHex: entry.fpHex,
          tagHex: entry.tagHex,
        });
      }
    }
  }
  return placements;
}

/**
 * Lookup or insert a data subject in the Cuckoo keyring, maintaining canonical `fp128` History Independence
 * and flushing only dirty bucket(s) in-place to disk.
 *
 * @param {any} ctx
 * @param {Buffer | string} canonicalTarget
 */
function ensureSubjectSlotInKeyring(ctx, canonicalTarget) {
  const canonBuf = canonicalizeSubjectIdentifier(canonicalTarget);
  const { fp128, fpHex, keyTag64, tagHex } = computeSubjectLocators(ctx.kLocator, canonBuf);

  const existing = ctx.subjectsByFp.get(fpHex);
  if (existing) {
    return existing;
  }

  const rSlot = allocSecure(32);
  if (typeof ctx.deterministicSlotSecretFn === 'function') {
    const custom = ctx.deterministicSlotSecretFn(canonBuf);
    custom.copy(rSlot, 0, 0, 32);
  } else {
    crypto.randomFillSync(rSlot);
  }

  const newEntry = {
    state: SLOT_STATE.ACTIVE,
    keyTag64,
    tagHex,
    fp128,
    fpHex,
    rSlot,
  };

  const prevSigs = ctx.ramBuckets.map(bucketStateSignature);
  ctx.subjectsByFp.set(fpHex, newEntry);
  const nextGrid = buildCanonicalCuckooLayout(ctx.subjectsByFp.values(), ctx.bucketCount);

  const dirty = [];
  for (let b = 0; b < ctx.bucketCount; b++) {
    if (bucketStateSignature(nextGrid[b]) !== prevSigs[b]) {
      dirty.push(b);
    }
  }
  ctx.ramBuckets = nextGrid;
  flushDirtyBucketsInPlace(ctx, dirty);

  return newEntry;
}

/**
 * Derive transient key for non-subject secrets/free-text tokens (derived from `kLocator`, never occupying a subject slot).
 * @param {any} ctx
 * @param {Buffer} canonBuf
 * @returns {Buffer}
 */
function deriveTransientFieldKey(ctx, canonBuf) {
  return crypto
    .createHmac('sha256', ctx.kLocator)
    .update(Buffer.from('ISEP-v3-FIELD-TOK\0', 'ascii'))
    .update(canonBuf)
    .digest();
}

/**
 * 3) Record an Agent Event (`recordAgentEvent`):
 * - Extracts & pseudonymizes PII into Luhn/MOD-97/RFC-2606 synthetic twins in `A_i`
 * - Encrypts raw payload into 512B-aligned `ISBL` sidecar `B_i` using `m-of-m` XOR subject key gate (`I_i = XOR R_slot(u)`)
 * - Appends `0x00`/`0x01`/`0x02` Merkle-chained & Ed25519-signed `AGENT_EVENT` to `.jsonl`
 * - Zeroizes all transient key material & plaintext buffers in `finally`
 */
export function recordAgentEvent(ctx, eventInput) {
  if (!ctx || ctx.closed) {
    throw new Error('ISEP keyring context is closed');
  }

  const seq = ctx.seqCounter + 1;
  const server = String(eventInput?.server || 'mcp-server');
  const tool = String(eventInput?.tool || 'unknown-tool');
  const rawArgs = eventInput?.args ?? {};
  const rawPrompt = eventInput?.prompt ?? undefined;
  const tsBucket = quantizeTimestamp60s(eventInput?.timestamp ?? Date.now());
  const eventTweak16 = crypto
    .createHash('sha256')
    .update(`ISEP-v3-TWEAK|${server}|${tool}|${tsBucket}`, 'utf8')
    .digest()
    .subarray(0, 16);

  /** @type {Map<string, { state: number, keyTag64: Buffer, tagHex: string, fp128: Buffer, fpHex: string, rSlot: Buffer }>} */
  const touchedSubjectsByTag = new Map();

  // Optional explicit subjects list in addition to auto-discovered PII
  if (Array.isArray(eventInput?.subjects)) {
    for (const rawSubj of eventInput.subjects) {
      const slotEntry = ensureSubjectSlotInKeyring(ctx, rawSubj);
      touchedSubjectsByTag.set(slotEntry.tagHex, slotEntry);
    }
  }

  const combinedPayload =
    rawPrompt !== undefined ? { args: rawArgs, prompt: rawPrompt } : { args: rawArgs };

  const { skeletonPayload, sidecarPayload } = extractAndPseudonymizePayload(
    combinedPayload,
    (canonBuf, meta) => {
      const canonStr = canonBuf.toString('utf8');
      const isDataSubject =
        canonStr.startsWith('email:') ||
        canonStr.startsWith('pan:') ||
        canonStr.startsWith('iban:');
      if (isDataSubject || meta.kind === 'email' || meta.kind === 'pan' || meta.kind === 'iban') {
        const slotEntry = ensureSubjectSlotInKeyring(ctx, canonBuf);
        touchedSubjectsByTag.set(slotEntry.tagHex, slotEntry);
        return { rSlot32: slotEntry.rSlot, tweak16: eventTweak16 };
      }
      return { rSlot32: deriveTransientFieldKey(ctx, canonBuf), tweak16: eventTweak16 };
    }
  );

  // Sort participating subjects strictly by 8-byte `key_tag64`
  const sortedSubjects = [...touchedSubjectsByTag.values()].sort((a, b) =>
    Buffer.compare(a.keyTag64, b.keyTag64)
  );
  const subjCount = sortedSubjects.length;
  if (subjCount > 255) {
    throw new RangeError(`Event exceeds maximum 255 subjects per record (${subjCount})`);
  }

  const iKey = allocSecure(32);
  let kEvent = null;
  let plainSidecarBuf = null;
  let paddedSidecarBuf = null;

  try {
    if (subjCount > 0) {
      for (const s of sortedSubjects) {
        for (let b = 0; b < 32; b++) {
          iKey[b] ^= s.rSlot[b];
        }
      }
    } else {
      // Non-subject operational event: derive event key from kTableDek so keyring rotation also covers it
      const derived = crypto.hkdfSync(
        'sha256',
        ctx.kTableDek,
        u64be(seq),
        Buffer.from('ISEP-v3-NOSUBJ\0', 'ascii'),
        32
      );
      Buffer.from(derived).copy(iKey);
    }

    const leafSalt32 = crypto.randomBytes(32);
    const iv12 = crypto.randomBytes(12);
    const hkdfRaw = crypto.hkdfSync(
      'sha256',
      iKey,
      leafSalt32,
      Buffer.from(`ISEP-v3-BLOB-AEAD\0${seq}`, 'utf8'),
      32
    );
    kEvent = allocSecure(32);
    Buffer.from(hkdfRaw).copy(kEvent);

    plainSidecarBuf = Buffer.from(
      JSON.stringify({
        seq,
        server,
        tool,
        sidecar: sidecarPayload,
      }),
      'utf8'
    );
    paddedSidecarBuf = padIso7816_4(plainSidecarBuf);
    const cipherLen = paddedSidecarBuf.length;
    const allocTagBytes = subjCount * 8;

    // Construct 80-byte `ISBL` header
    const blobHdr = Buffer.alloc(BLOB_HEADER_BYTES, 0);
    MAGIC_BLOB.copy(blobHdr, 0); // [0..3] "ISBL"
    blobHdr[4] = BLOB_STATE.ACTIVE; // [4] 0x01
    blobHdr[5] = subjCount & 0xff; // [5] active_subj_cnt
    blobHdr.writeUInt16BE(allocTagBytes, 6); // [6..7] IMMUTABLE alloc_tag_bytes
    blobHdr.writeUInt32BE(cipherLen >>> 0, 8); // [8..11] IMMUTABLE cipher_len
    blobHdr.writeBigUInt64BE(BigInt(seq), 12); // [12..19] IMMUTABLE seq
    leafSalt32.copy(blobHdr, 20); // [20..51]
    iv12.copy(blobHdr, 52); // [52..63]

    const cipher = crypto.createCipheriv('aes-256-gcm', kEvent, iv12);
    cipher.setAAD(blobHdr.subarray(0, 20));
    const cipherBuf = Buffer.concat([cipher.update(paddedSidecarBuf), cipher.final()]);
    const gcmTag16 = cipher.getAuthTag();
    gcmTag16.copy(blobHdr, 64); // [64..79]

    const tagsArrayBuf = Buffer.alloc(allocTagBytes);
    for (let idx = 0; idx < subjCount; idx++) {
      sortedSubjects[idx].keyTag64.copy(tagsArrayBuf, idx * 8, 0, 8);
    }

    const fullBlobRecord = Buffer.concat([blobHdr, tagsArrayBuf, cipherBuf]);
    const sidecarCommitment = b64u(
      domainSha256(DOMAIN_PREFIX.SIDECAR_COMMITMENT, fullBlobRecord)
    );

    // Append `.isep.blobs` first and fsync before committing `.jsonl`
    const blobFd = fs.openSync(ctx.blobsPath, 'a+');
    let sidecarOffset = 0;
    try {
      sidecarOffset = fs.fstatSync(blobFd).size;
      fs.writeSync(blobFd, fullBlobRecord, 0, fullBlobRecord.length, sidecarOffset);
      fs.fsyncSync(blobFd);
    } finally {
      fs.closeSync(blobFd);
    }

    const skeletonCore = {
      pseudonymized_args: skeletonPayload.args,
      ...(skeletonPayload.prompt !== undefined ? { pseudonymized_prompt: skeletonPayload.prompt } : {}),
      record_type: 'AGENT_EVENT',
      seq,
      server,
      sidecar_byte_len: fullBlobRecord.length,
      sidecar_commitment: sidecarCommitment,
      sidecar_offset: sidecarOffset,
      subject_count: subjCount,
      tool,
      ts_bucket: tsBucket,
      v: 'isep-event/3.0',
    };

    const skeletonHash = b64u(
      domainSha256(DOMAIN_PREFIX.EVENT_SKELETON, jcsCanonicalize(skeletonCore))
    );
    const chainHashBytes = domainSha256(
      DOMAIN_PREFIX.CHAIN_LINK,
      ctx.prevChainHash,
      skeletonHash,
      sidecarCommitment
    );
    const chainHash = b64u(chainHashBytes);
    const signature = signDomainPayload(CHAIN_SIGN_LABEL, chainHashBytes, ctx.custodianPrivateKey);

    const committedLineObj = {
      ...skeletonCore,
      skeleton_hash: skeletonHash,
      prev_chain_hash: ctx.prevChainHash,
      chain_hash: chainHash,
      key_id: ctx.keyId,
      signature,
    };

    const logFd = fs.openSync(ctx.logPath, 'a');
    try {
      fs.writeSync(logFd, JSON.stringify(committedLineObj) + '\n', undefined, 'utf8');
      fs.fsyncSync(logFd);
    } finally {
      fs.closeSync(logFd);
    }

    // Update in-memory cursor & subject tag index
    ctx.seqCounter = seq;
    ctx.prevChainHash = chainHash;
    for (const s of sortedSubjects) {
      let arr = ctx.tagIndex.get(s.tagHex);
      if (!arr) {
        arr = [];
        ctx.tagIndex.set(s.tagHex, arr);
      }
      arr.push({
        seq,
        offset: sidecarOffset,
        recordByteLen: fullBlobRecord.length,
      });
    }

    return {
      seq,
      eventRecord: committedLineObj,
      sidecarOffset,
      sidecarByteLen: fullBlobRecord.length,
      cipherLen,
      subjectCount: subjCount,
    };
  } finally {
    zeroizeBuffer(iKey);
    if (kEvent) zeroizeBuffer(kEvent);
    if (plainSidecarBuf) plainSidecarBuf.fill(0);
    if (paddedSidecarBuf) zeroizeBuffer(paddedSidecarBuf);
  }
}

/**
 * Decrypt an unshredded sidecar record `B_i` when all `m` participating subject keys are still active.
 * Fails immediately once any participating subject has exercised GDPR Art. 17 erasure.
 */
export function decryptAgentSidecar(ctx, seqNumber) {
  if (!ctx || ctx.closed) throw new Error('ISEP context closed');
  const rawBlobFile = fs.readFileSync(ctx.blobsPath);
  let cursor = 0;

  while (cursor + BLOB_HEADER_BYTES <= rawBlobFile.length) {
    const hdr = rawBlobFile.subarray(cursor, cursor + BLOB_HEADER_BYTES);
    if (!hdr.subarray(0, 4).equals(MAGIC_BLOB)) {
      throw new Error('CORRUPT_BLOB_MAGIC');
    }
    const state = hdr[4];
    const allocTagBytes = hdr.readUInt16BE(6);
    const cipherLen = hdr.readUInt32BE(8);
    const seq = Number(hdr.readBigUInt64BE(12));
    const recLen = BLOB_HEADER_BYTES + allocTagBytes + cipherLen;

    if (seq === seqNumber) {
      if (state === BLOB_STATE.PURGED) {
        throw new Error(`SIDECAR_PURGED_GDPR_ART17: seq ${seq} has been cryptographically shredded`);
      }
      const tagCount = Math.floor(allocTagBytes / 8);
      const tagsByHex = new Map();
      for (const s of ctx.subjectsByFp.values()) {
        tagsByHex.set(s.tagHex, s);
      }

      const iKey = allocSecure(32);
      try {
        if (tagCount > 0) {
          for (let t = 0; t < tagCount; t++) {
            const tagHex = rawBlobFile
              .subarray(cursor + BLOB_HEADER_BYTES + t * 8, cursor + BLOB_HEADER_BYTES + (t + 1) * 8)
              .toString('hex');
            const subj = tagsByHex.get(tagHex);
            if (!subj) {
              throw new Error(`SUBJECT_KEY_DESTROYED: Missing R_slot for tag ${tagHex}`);
            }
            for (let b = 0; b < 32; b++) {
              iKey[b] ^= subj.rSlot[b];
            }
          }
        } else {
          const derived = crypto.hkdfSync(
            'sha256',
            ctx.kTableDek,
            u64be(seq),
            Buffer.from('ISEP-v3-NOSUBJ\0', 'ascii'),
            32
          );
          Buffer.from(derived).copy(iKey);
        }

        const leafSalt32 = hdr.subarray(20, 52);
        const iv12 = hdr.subarray(52, 64);
        const gcmTag16 = hdr.subarray(64, 80);
        const cipherSlice = rawBlobFile.subarray(
          cursor + BLOB_HEADER_BYTES + allocTagBytes,
          cursor + recLen
        );

        const kEvent = Buffer.from(
          crypto.hkdfSync(
            'sha256',
            iKey,
            leafSalt32,
            Buffer.from(`ISEP-v3-BLOB-AEAD\0${seq}`, 'utf8'),
            32
          )
        );
        try {
          const decipher = crypto.createDecipheriv('aes-256-gcm', kEvent, iv12);
          decipher.setAAD(hdr.subarray(0, 20));
          decipher.setAuthTag(gcmTag16);
          const padded = Buffer.concat([decipher.update(cipherSlice), decipher.final()]);
          const unpadded = unpadIso7816_4(padded);
          padded.fill(0);
          return JSON.parse(unpadded.toString('utf8'));
        } finally {
          kEvent.fill(0);
        }
      } finally {
        zeroizeBuffer(iKey);
      }
    }

    cursor += recLen;
  }

  throw new Error(`Sidecar record seq=${seqNumber} not found`);
}

/**
 * 4) Toggle GDPR Art. 17(3)(e) Litigation Hold (`0x02` vs `0x01`) on a subject slot,
 * persisting the updated encrypted Cuckoo bucket immediately to disk.
 */
export function setSubjectLitigationHold(ctx, { canonicalTargetBuf, holdActive }) {
  if (!ctx || ctx.closed) {
    throw new Error('ISEP context closed');
  }
  const canonBuf = canonicalizeSubjectIdentifier(canonicalTargetBuf);
  const { fpHex } = computeSubjectLocators(ctx.kLocator, canonBuf);
  const existing = ctx.subjectsByFp.get(fpHex);
  if (!existing) {
    throw new Error('SUBJECT_NOT_FOUND: Target subject has no active slot in keyring');
  }

  const nextState = holdActive ? SLOT_STATE.LITIGATION_HOLD : SLOT_STATE.ACTIVE;
  existing.state = nextState;

  const dirty = [];
  for (let b = 0; b < ctx.bucketCount; b++) {
    for (let s = 0; s < SLOTS_PER_BUCKET; s++) {
      if (ctx.ramBuckets[b][s] && ctx.ramBuckets[b][s].fpHex === fpHex) {
        ctx.ramBuckets[b][s].state = nextState;
        dirty.push(b);
      }
    }
  }
  flushDirtyBucketsInPlace(ctx, dirty);

  return {
    holdActive: Boolean(holdActive),
    slotState: nextState,
  };
}

/**
 * 5) Execute GDPR Art. 17 Cryptographic Shredding (`executeGdprShredding`):
 * - Refuses immediately if subject slot is under `0x02` `LITIGATION_HOLD` (`GDPR Art. 17(3)(e)`)
 * - Wipes all matching `.isep.blobs` tails (`[20 .. 80 + alloc_tag_bytes + cipher_len - 1] = 0x00`)
 *   while preserving `[6..19]` (`alloc_tag_bytes`, `cipher_len`, `seq`) intact on double-shred!
 * - Zeroes `R_slot`, rebuilds Cuckoo table in canonical `fp128` lexicographical order (100% History Independent)
 * - Rotates BOTH `K_table_dek` and `K_root_kek` (`genCounter++`)
 * - Appends Ed25519-signed `GDPR_SHRED_TOMBSTONE` (`0x03`, `0x04`, `0x05`)
 */
export function executeGdprShredding(ctx, { canonicalTargetBuf, dsarTicketId }) {
  if (!ctx || ctx.closed) {
    throw new Error('ISEP context closed');
  }
  if (!dsarTicketId || !String(dsarTicketId).trim()) {
    throw new Error('DSAR ticket ID is required for GDPR Art. 17 erasure');
  }

  const canonBuf = canonicalizeSubjectIdentifier(canonicalTargetBuf);
  const { fpHex, tagHex } = computeSubjectLocators(ctx.kLocator, canonBuf);
  const targetSlot = ctx.subjectsByFp.get(fpHex);
  if (!targetSlot) {
    const err = /** @type {Error & { code?: string }} */ (
      new Error('SUBJECT_NOT_FOUND_OR_ALREADY_SHREDDED: No active keyring slot for subject')
    );
    err.code = 'SUBJECT_NOT_FOUND';
    throw err;
  }

  if (targetSlot.state === SLOT_STATE.LITIGATION_HOLD) {
    const err = /** @type {Error & { code?: string }} */ (
      new Error(
        'LITIGATION_HOLD_ACTIVE: Erasure refused under GDPR Art. 17(3)(e) active legal hold (slot state 0x02)'
      )
    );
    err.code = 'LITIGATION_HOLD_ACTIVE';
    throw err;
  }

  // 1. Salted one-way key-destroy commitment BEFORE zeroizing R_slot
  const destroySalt16 = crypto.randomBytes(16);
  const destroyedSlotDigest = crypto
    .createHash('sha256')
    .update(destroySalt16)
    .update(targetSlot.rSlot)
    .digest();

  // 2. Zero matching `.isep.blobs` records in-place (DOUBLE-SHRED SAFE!)
  const indexedRefs = ctx.tagIndex.get(tagHex) || [];
  const erasedSeqsSet = new Set();

  if (indexedRefs.length > 0 && fs.existsSync(ctx.blobsPath)) {
    const fd = fs.openSync(ctx.blobsPath, 'r+');
    try {
      const hdrBuf = Buffer.alloc(BLOB_HEADER_BYTES);
      for (const ref of indexedRefs) {
        const readN = fs.readSync(fd, hdrBuf, 0, BLOB_HEADER_BYTES, ref.offset);
        if (readN !== BLOB_HEADER_BYTES || !hdrBuf.subarray(0, 4).equals(MAGIC_BLOB)) {
          throw new Error(`CORRUPT_BLOB_MAGIC at offset ${ref.offset} during GDPR shred`);
        }

        // CRITICAL RED-TEAM INVARIANT: Read immutable [6..19] and NEVER overwrite them with zero!
        const allocTagBytes = hdrBuf.readUInt16BE(6);
        const cipherLen = hdrBuf.readUInt32BE(8);
        const seq = Number(hdrBuf.readBigUInt64BE(12));

        // Update [4] state = 0x00 (PURGED) and [5] active_subj_cnt = 0x00, keeping [6..19] 100% intact!
        const statePatch = Buffer.from([BLOB_STATE.PURGED, 0x00]);
        fs.writeSync(fd, statePatch, 0, 2, ref.offset + 4);

        // Zero [20 .. 80 + alloc_tag_bytes + cipher_len - 1]
        const zeroTailLen = (BLOB_HEADER_BYTES - 20) + allocTagBytes + cipherLen;
        const zeroBuf = Buffer.alloc(zeroTailLen, 0x00);
        fs.writeSync(fd, zeroBuf, 0, zeroTailLen, ref.offset + 20);

        erasedSeqsSet.add(seq);
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }
  ctx.tagIndex.delete(tagHex);

  // 3. Zeroize subject's R_slot and rebuild Cuckoo table in canonical lexicographical fp128 order
  zeroizeBuffer(targetSlot.rSlot);
  ctx.subjectsByFp.delete(fpHex);
  ctx.ramBuckets = buildCanonicalCuckooLayout(ctx.subjectsByFp.values(), ctx.bucketCount);

  // 4. Rotate BOTH K_table_dek AND Enclave K_root_kek, increment genCounter, and rewrite `.isep.keyring`
  const newTableDek = allocSecure(32);
  crypto.randomFillSync(newTableDek);
  zeroizeBuffer(ctx.kTableDek);
  ctx.kTableDek = newTableDek;

  const newRootKek = allocSecure(32);
  crypto.randomFillSync(newRootKek);
  try {
    ctx.enclaveAdapter.rotateRootKey(ctx.keyringId, newRootKek);
  } finally {
    zeroizeBuffer(newRootKek);
  }

  ctx.genCounter = ctx.genCounter + 1n;
  persistFullKeyringAtomic(ctx);

  // 5. Append Ed25519-signed `GDPR_SHRED_TOMBSTONE` (`0x03` witness, `0x04` key-destroy, `0x05` DSAR receipt)
  const erasedSeqs = [...erasedSeqsSet].sort((a, b) => a - b);
  const tsBucket = quantizeTimestamp60s(Date.now());
  const newGenNumber = Number(ctx.genCounter);

  const tombstoneWitness = b64u(
    domainSha256(
      DOMAIN_PREFIX.TOMBSTONE_WITNESS,
      jcsCanonicalize({
        erased_seqs: erasedSeqs,
        gen_counter: newGenNumber,
        ts_bucket: tsBucket,
      })
    )
  );

  const keyDestroyCommit = b64u(
    domainSha256(
      DOMAIN_PREFIX.KEY_DESTROY,
      destroyedSlotDigest,
      u64be(ctx.genCounter)
    )
  );

  const dsarSalt16 = crypto.randomBytes(16);
  const dsarReceiptCommit = b64u(
    domainSha256(
      DOMAIN_PREFIX.DSAR_RECEIPT,
      dsarSalt16,
      Buffer.from(String(dsarTicketId).trim(), 'utf8'),
      tombstoneWitness
    )
  );

  const tombstoneSkeleton = {
    dsar_receipt_commit: dsarReceiptCommit,
    dsar_salt: b64u(dsarSalt16),
    erased_seqs: erasedSeqs,
    gen_counter: newGenNumber,
    key_destroy_commit: keyDestroyCommit,
    record_type: 'GDPR_SHRED_TOMBSTONE',
    tombstone_witness: tombstoneWitness,
    ts_bucket: tsBucket,
    v: 'isep-tombstone/3.0',
  };

  const skeletonHash = b64u(
    domainSha256(DOMAIN_PREFIX.EVENT_SKELETON, jcsCanonicalize(tombstoneSkeleton))
  );
  const chainHashBytes = domainSha256(
    DOMAIN_PREFIX.CHAIN_LINK,
    ctx.prevChainHash,
    skeletonHash,
    tombstoneWitness
  );
  const chainHash = b64u(chainHashBytes);
  const signature = signDomainPayload(CHAIN_SIGN_LABEL, chainHashBytes, ctx.custodianPrivateKey);

  const tombstoneLineObj = {
    ...tombstoneSkeleton,
    skeleton_hash: skeletonHash,
    prev_chain_hash: ctx.prevChainHash,
    chain_hash: chainHash,
    key_id: ctx.keyId,
    signature,
  };

  const logFd = fs.openSync(ctx.logPath, 'a');
  try {
    fs.writeSync(logFd, JSON.stringify(tombstoneLineObj) + '\n', undefined, 'utf8');
    fs.fsyncSync(logFd);
  } finally {
    fs.closeSync(logFd);
  }

  ctx.prevChainHash = chainHash;

  return {
    erasedSeqs,
    genCounter: newGenNumber,
    tombstoneRecord: tombstoneLineObj,
    dsarReceiptCommit,
    keyDestroyCommit,
    tombstoneWitness,
  };
}

/**
 * 6) Two-Pass Bi-Directional Integrity & Anti-Spoliation Verifier (`verifyIsepChainQuick`):
 * - Pass 1: Verifies every `.jsonl` record's `0x00` skeleton digest, `0x01` Merkle link, and `Ed25519` signature;
 *   collects expected sidecar commitments and `GDPR_SHRED_TOMBSTONE` `erased_seqs`.
 * - Pass 2: Walks `.isep.blobs` via immutable `80 + alloc_tag_bytes + cipher_len` headers, verifying:
 *   * Every unshredded `seq` has `state === 0x01` and exact `0x02` `sidecar_commitment` match (`UNAUTHORIZED_ERASURE_SPOLIATION` if altered/missing).
 *   * Every Tombstone-authorized `seq` has `state === 0x00` and EVERY byte in `[20 .. end]` strictly equal to `0x00` (`COMPLIANCE_FRAUD_UNPURGED_BYTES` if any non-zero byte remains!).
 */
export function verifyIsepChainQuick({ logPath, blobsPath, custodianPublicKey }) {
  if (!fs.existsSync(logPath) || !fs.existsSync(blobsPath)) {
    return {
      valid: false,
      status: 'MISSING_AUDIT_FILES',
      reason: 'ISEP .jsonl or .blobs file missing on disk',
      totalEvents: 0,
      tombstones: 0,
      lawfullyErasedSeqs: [],
    };
  }

  const pubKeyObj = resolveEd25519PublicKey(custodianPublicKey);
  const rawLog = fs.readFileSync(logPath, 'utf8');
  const lines = rawLog
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);

  let expectedPrevHash = 'GENESIS';
  let expectedNextSeq = 1;
  let tombstoneCount = 0;
  /** @type {Map<number, any>} */
  const eventsBySeq = new Map();
  /** @type {Set<number>} */
  const authorizedErasedSeqs = new Set();

  // PASS 1: Verify JSONL Hash Chain & Ed25519 Signatures
  for (let idx = 0; idx < lines.length; idx++) {
    let rec;
    try {
      rec = JSON.parse(lines[idx]);
    } catch {
      return {
        valid: false,
        status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
        reason: `Malformed JSON at .jsonl line ${idx + 1}`,
        totalEvents: eventsBySeq.size,
        tombstones: tombstoneCount,
        lawfullyErasedSeqs: [],
      };
    }

    if (rec.prev_chain_hash !== expectedPrevHash) {
      return {
        valid: false,
        status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
        reason: `Broken Merkle chain link at line ${idx + 1}: expected prev_chain_hash=${expectedPrevHash}`,
        totalEvents: eventsBySeq.size,
        tombstones: tombstoneCount,
        lawfullyErasedSeqs: [],
      };
    }

    if (rec.record_type === 'AGENT_EVENT') {
      if (rec.seq !== expectedNextSeq) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Sequence gap or out-of-order seq at line ${idx + 1}: expected ${expectedNextSeq}, got ${rec.seq}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }
      expectedNextSeq++;

      const skeletonCore = {
        pseudonymized_args: rec.pseudonymized_args,
        ...(rec.pseudonymized_prompt !== undefined
          ? { pseudonymized_prompt: rec.pseudonymized_prompt }
          : {}),
        record_type: 'AGENT_EVENT',
        seq: rec.seq,
        server: rec.server,
        sidecar_byte_len: rec.sidecar_byte_len,
        sidecar_commitment: rec.sidecar_commitment,
        sidecar_offset: rec.sidecar_offset,
        subject_count: rec.subject_count,
        tool: rec.tool,
        ts_bucket: rec.ts_bucket,
        v: rec.v,
      };

      const expectedSkeletonHash = b64u(
        domainSha256(DOMAIN_PREFIX.EVENT_SKELETON, jcsCanonicalize(skeletonCore))
      );
      if (rec.skeleton_hash !== expectedSkeletonHash) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Tampered 0x00 skeleton_hash at AGENT_EVENT seq=${rec.seq}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }

      const chainBytes = domainSha256(
        DOMAIN_PREFIX.CHAIN_LINK,
        rec.prev_chain_hash,
        rec.skeleton_hash,
        rec.sidecar_commitment
      );
      const expectedChainHash = b64u(chainBytes);
      if (rec.chain_hash !== expectedChainHash) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Tampered 0x01 chain_hash at AGENT_EVENT seq=${rec.seq}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }

      if (!verifyDomainPayload(CHAIN_SIGN_LABEL, chainBytes, rec.signature, pubKeyObj)) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Invalid Ed25519 signature at AGENT_EVENT seq=${rec.seq}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }

      eventsBySeq.set(rec.seq, rec);
      expectedPrevHash = rec.chain_hash;
    } else if (rec.record_type === 'GDPR_SHRED_TOMBSTONE') {
      tombstoneCount++;
      const tombstoneSkeleton = {
        dsar_receipt_commit: rec.dsar_receipt_commit,
        dsar_salt: rec.dsar_salt,
        erased_seqs: rec.erased_seqs,
        gen_counter: rec.gen_counter,
        key_destroy_commit: rec.key_destroy_commit,
        record_type: 'GDPR_SHRED_TOMBSTONE',
        tombstone_witness: rec.tombstone_witness,
        ts_bucket: rec.ts_bucket,
        v: rec.v,
      };

      const expectedWitness = b64u(
        domainSha256(
          DOMAIN_PREFIX.TOMBSTONE_WITNESS,
          jcsCanonicalize({
            erased_seqs: rec.erased_seqs,
            gen_counter: rec.gen_counter,
            ts_bucket: rec.ts_bucket,
          })
        )
      );
      if (rec.tombstone_witness !== expectedWitness) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Invalid 0x03 tombstone_witness at line ${idx + 1}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }

      const expectedSkeletonHash = b64u(
        domainSha256(DOMAIN_PREFIX.EVENT_SKELETON, jcsCanonicalize(tombstoneSkeleton))
      );
      if (rec.skeleton_hash !== expectedSkeletonHash) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Tampered 0x00 skeleton_hash on GDPR_SHRED_TOMBSTONE at line ${idx + 1}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }

      const chainBytes = domainSha256(
        DOMAIN_PREFIX.CHAIN_LINK,
        rec.prev_chain_hash,
        rec.skeleton_hash,
        rec.tombstone_witness
      );
      const expectedChainHash = b64u(chainBytes);
      if (rec.chain_hash !== expectedChainHash) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Tampered 0x01 chain_hash on GDPR_SHRED_TOMBSTONE at line ${idx + 1}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }

      if (!verifyDomainPayload(CHAIN_SIGN_LABEL, chainBytes, rec.signature, pubKeyObj)) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Invalid Ed25519 signature on GDPR_SHRED_TOMBSTONE at line ${idx + 1}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }

      if (!Array.isArray(rec.erased_seqs)) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Malformed erased_seqs array at line ${idx + 1}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [],
        };
      }
      for (const s of rec.erased_seqs) {
        if (!eventsBySeq.has(s)) {
          return {
            valid: false,
            status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
            reason: `Tombstone references nonexistent or future seq=${s}`,
            totalEvents: eventsBySeq.size,
            tombstones: tombstoneCount,
            lawfullyErasedSeqs: [],
          };
        }
        authorizedErasedSeqs.add(s);
      }
      expectedPrevHash = rec.chain_hash;
    } else {
      return {
        valid: false,
        status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
        reason: `Unknown record_type "${rec.record_type}" at line ${idx + 1}`,
        totalEvents: eventsBySeq.size,
        tombstones: tombstoneCount,
        lawfullyErasedSeqs: [],
      };
    }
  }

  // PASS 2: Bi-Directional Sidecar `.isep.blobs` Verification
  const blobsBuf = fs.readFileSync(blobsPath);
  let cursor = 0;
  /** @type {Set<number>} */
  const seenBlobSeqs = new Set();

  while (cursor < blobsBuf.length) {
    if (cursor + BLOB_HEADER_BYTES > blobsBuf.length) {
      return {
        valid: false,
        status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
        reason: `Truncated ISBL header at byte offset ${cursor} in .isep.blobs`,
        totalEvents: eventsBySeq.size,
        tombstones: tombstoneCount,
        lawfullyErasedSeqs: [...authorizedErasedSeqs],
      };
    }

    const hdr = blobsBuf.subarray(cursor, cursor + BLOB_HEADER_BYTES);
    if (!hdr.subarray(0, 4).equals(MAGIC_BLOB)) {
      return {
        valid: false,
        status: 'CORRUPT_BLOB_MAGIC',
        reason: `Corrupt ISBL magic at byte offset ${cursor}`,
        totalEvents: eventsBySeq.size,
        tombstones: tombstoneCount,
        lawfullyErasedSeqs: [...authorizedErasedSeqs],
      };
    }

    const state = hdr[4];
    const activeSubjCnt = hdr[5];
    const allocTagBytes = hdr.readUInt16BE(6);
    const cipherLen = hdr.readUInt32BE(8);
    const seq = Number(hdr.readBigUInt64BE(12));
    const recLen = BLOB_HEADER_BYTES + allocTagBytes + cipherLen;

    if (cipherLen === 0 || cipherLen % BLOB_BLOCK_ALIGN !== 0 || cursor + recLen > blobsBuf.length) {
      return {
        valid: false,
        status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
        reason: `Truncated or misaligned ISBL record seq=${seq} at offset ${cursor}`,
        totalEvents: eventsBySeq.size,
        tombstones: tombstoneCount,
        lawfullyErasedSeqs: [...authorizedErasedSeqs],
      };
    }

    const expectedEvent = eventsBySeq.get(seq);
    if (
      !expectedEvent ||
      expectedEvent.sidecar_offset !== cursor ||
      expectedEvent.sidecar_byte_len !== recLen
    ) {
      return {
        valid: false,
        status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
        reason: `Sidecar offset/length mismatch against .jsonl for seq=${seq}`,
        totalEvents: eventsBySeq.size,
        tombstones: tombstoneCount,
        lawfullyErasedSeqs: [...authorizedErasedSeqs],
      };
    }

    const fullRecSlice = blobsBuf.subarray(cursor, cursor + recLen);

    if (authorizedErasedSeqs.has(seq)) {
      // Must be physically purged: state === 0x00, active_subj_cnt === 0, and ALL bytes [20..recLen-1] === 0x00
      if (state !== BLOB_STATE.PURGED || activeSubjCnt !== 0) {
        return {
          valid: false,
          status: 'COMPLIANCE_FRAUD_UNPURGED_BYTES',
          reason: `Compliance fraud detected: Tombstone claims seq=${seq} was erased, but ISBL header state=0x${state.toString(16)}`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [...authorizedErasedSeqs],
        };
      }
      for (let k = 20; k < recLen; k++) {
        if (fullRecSlice[k] !== 0x00) {
          return {
            valid: false,
            status: 'COMPLIANCE_FRAUD_UNPURGED_BYTES',
            reason: `Compliance fraud detected: Non-zero unpurged byte (0x${fullRecSlice[k].toString(16)}) at offset ${cursor + k} in seq=${seq}`,
            totalEvents: eventsBySeq.size,
            tombstones: tombstoneCount,
            lawfullyErasedSeqs: [...authorizedErasedSeqs],
          };
        }
      }
    } else {
      // Must be ACTIVE and match 0x02 sidecar_commitment bit-for-bit
      if (state !== BLOB_STATE.ACTIVE) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Unlawful spoliation: seq=${seq} marked PURGED on disk without a signed GDPR_SHRED_TOMBSTONE`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [...authorizedErasedSeqs],
        };
      }

      const actualCommit = b64u(
        domainSha256(DOMAIN_PREFIX.SIDECAR_COMMITMENT, fullRecSlice)
      );
      if (actualCommit !== expectedEvent.sidecar_commitment) {
        return {
          valid: false,
          status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
          reason: `Sidecar 0x02 commitment mismatch at seq=${seq} (ciphertext or header modified)`,
          totalEvents: eventsBySeq.size,
          tombstones: tombstoneCount,
          lawfullyErasedSeqs: [...authorizedErasedSeqs],
        };
      }
    }

    seenBlobSeqs.add(seq);
    cursor += recLen;
  }

  // Ensure no `.jsonl` event had its blob silently deleted from EOF
  if (seenBlobSeqs.size !== eventsBySeq.size) {
    return {
      valid: false,
      status: 'UNAUTHORIZED_ERASURE_SPOLIATION',
      reason: `Missing ${eventsBySeq.size - seenBlobSeqs.size} expected sidecar record(s) in .isep.blobs`,
      totalEvents: eventsBySeq.size,
      tombstones: tombstoneCount,
      lawfullyErasedSeqs: [...authorizedErasedSeqs],
    };
  }

  const hasErasures = authorizedErasedSeqs.size > 0 || tombstoneCount > 0;
  return {
    valid: true,
    status: hasErasures ? 'VALID_WITH_LAWFUL_ERASURES' : 'VALID_UNMODIFIED',
    reason: hasErasures
      ? `Verified ${eventsBySeq.size} event(s) and ${tombstoneCount} signed GDPR Art. 17 Tombstone(s) (${authorizedErasedSeqs.size} sidecar(s) zero-verified)`
      : `Verified ${eventsBySeq.size} unmodified event(s) and 100% 0x02 sidecar commitments`,
    totalEvents: eventsBySeq.size,
    tombstones: tombstoneCount,
    lawfullyErasedSeqs: [...authorizedErasedSeqs].sort((a, b) => a - b),
    headChainHash: expectedPrevHash,
  };
}
