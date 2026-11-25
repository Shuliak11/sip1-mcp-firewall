/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Domain-Separated Cryptographic Primitives & Secure Memory
 * Zero external dependencies. Built strictly on node:crypto, node:fs, node:path.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import { writeFileAtomic600 } from './workspace-io.mjs';

export const DOMAIN_PREFIX = Object.freeze({
  EVENT_SKELETON: 0x00,
  CHAIN_LINK: 0x01,
  SIDECAR_COMMITMENT: 0x02,
  TOMBSTONE_WITNESS: 0x03,
  KEY_DESTROY: 0x04,
  DSAR_RECEIPT: 0x05,
  SCHEMA_LOCK: 0x06,
  WARRANT_ACTION: 0x07,
});

// ASN.1 DER SubjectPublicKeyInfo prefix for raw 32-byte Ed25519 public key (RFC 8410)
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Allocate unpooled slow buffer outside V8 slab allocator and zero-fill immediately.
 * @param {number} size
 * @returns {Buffer}
 */
export function allocSecure(size) {
  if (!Number.isInteger(size) || size < 0) {
    throw new RangeError(`Invalid secure buffer size: ${size}`);
  }
  const buf = Buffer.allocUnsafeSlow(size);
  buf.fill(0);
  return buf;
}

/**
 * Overwrite buffer bytes in-place with random noise followed by zeros.
 * @param {Buffer | Uint8Array | null | undefined} buf
 */
export function zeroizeBuffer(buf) {
  if (!buf || typeof buf.fill !== 'function') {
    return;
  }
  if (buf.byteLength > 0) {
    crypto.randomFillSync(buf);
    buf.fill(0);
  }
}

/**
 * Encode bytes as strict RFC 4648 Section 5 base64url without '=' padding.
 * 32B SHA-256 -> 43 chars; 64B Ed25519 signature -> 86 chars.
 * @param {Buffer | Uint8Array} buf
 * @returns {string}
 */
export function b64u(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return b
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

/**
 * Decode strict base64url string (without '=' padding) into a Buffer.
 * Rejects '+', '/', '=', whitespace, invalid lengths, and non-canonical trailing bits.
 * @param {string} str
 * @returns {Buffer}
 */
export function unb64u(str) {
  if (typeof str !== 'string') {
    throw new TypeError('base64url input must be a string');
  }
  if (!/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new Error('Invalid base64url alphabet or forbidden padding character');
  }
  if (str.length % 4 === 1) {
    throw new Error(`Invalid base64url string length: ${str.length}`);
  }
  const decoded = Buffer.from(str, 'base64url');
  if (b64u(decoded) !== str) {
    throw new Error('Non-canonical base64url encoding');
  }
  return decoded;
}

/**
 * Compute domain-separated SHA-256: SHA-256( [prefixByte] || buf_1 || ... || buf_n ).
 * @param {number} prefixByte
 * @param {...(Buffer | Uint8Array | string)} buffers
 * @returns {Buffer}
 */
export function domainSha256(prefixByte, ...buffers) {
  if (!Number.isInteger(prefixByte) || prefixByte < 0x00 || prefixByte > 0xff) {
    throw new RangeError(`Invalid domain prefix byte: ${prefixByte}`);
  }
  const hash = crypto.createHash('sha256');
  hash.update(Buffer.from([prefixByte]));
  for (const chunk of buffers) {
    if (Buffer.isBuffer(chunk) || chunk instanceof Uint8Array) {
      hash.update(chunk);
    } else if (typeof chunk === 'string') {
      hash.update(Buffer.from(chunk, 'utf8'));
    } else {
      throw new TypeError('domainSha256 chunks must be Buffer, Uint8Array, or string');
    }
  }
  return hash.digest();
}

/**
 * Extract raw 32-byte Ed25519 public key from a Node KeyObject.
 * @param {crypto.KeyObject} publicKey
 * @returns {Buffer}
 */
export function exportEd25519RawPublic(publicKey) {
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  if (spkiDer.length !== 44) {
    throw new Error(`Unexpected Ed25519 SPKI DER length: ${spkiDer.length}`);
  }
  return Buffer.from(spkiDer.subarray(12));
}

/**
 * Reconstruct a Node Ed25519 PublicKey KeyObject from raw 32B Buffer, base64url string, or PEM.
 * @param {crypto.KeyObject | Buffer | string} publicKeyInput
 * @returns {crypto.KeyObject}
 */
export function resolveEd25519PublicKey(publicKeyInput) {
  if (publicKeyInput instanceof crypto.KeyObject) {
    return publicKeyInput;
  }
  if (Buffer.isBuffer(publicKeyInput)) {
    if (publicKeyInput.length !== 32) {
      throw new Error(`Expected 32-byte raw Ed25519 public key, got ${publicKeyInput.length}`);
    }
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, publicKeyInput]);
    return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  }
  if (typeof publicKeyInput === 'string') {
    if (publicKeyInput.includes('BEGIN PUBLIC KEY')) {
      return crypto.createPublicKey(publicKeyInput);
    }
    const raw = unb64u(publicKeyInput.trim());
    if (raw.length !== 32) {
      throw new Error(`Expected 32-byte base64url Ed25519 public key, got ${raw.length} bytes`);
    }
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  }
  throw new TypeError('Unsupported Ed25519 public key input');
}

/**
 * Ensure `.sip/device.ed25519.pem` (0o600) and `.sip/device.ed25519.pub` (raw 32B base64url) exist.
 * When `ephemeralOnly` is true (used for --dry-run), generates an in-memory keypair without disk writes
 * if no keypair currently exists on disk.
 * @param {string} sipDir
 * @param {{ ephemeralOnly?: boolean }} [options]
 */
export function ensureDeviceEd25519Keypair(sipDir, options = {}) {
  const pemPath = path.join(sipDir, 'device.ed25519.pem');
  const pubPath = path.join(sipDir, 'device.ed25519.pub');

  if (fs.existsSync(pemPath)) {
    const pem = fs.readFileSync(pemPath, 'utf8');
    const privateKey = crypto.createPrivateKey(pem);
    const publicKey = crypto.createPublicKey(privateKey);
    const rawPub = exportEd25519RawPublic(publicKey);
    const publicKeyB64u = b64u(rawPub);
    const keyId = b64u(domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, rawPub)).slice(0, 16);

    if (!options.ephemeralOnly && !fs.existsSync(pubPath)) {
      writeFileAtomic600(pubPath, publicKeyB64u + '\n');
    }

    return {
      privateKey,
      publicKey,
      publicKeyB64u,
      keyId,
      pemPath,
      pubPath,
      ephemeral: false,
    };
  }

  const envPem = process.env.SIP_CUSTODIAN_PRIVATE_KEY_PEM?.trim();
  if (envPem) {
    const privateKey = crypto.createPrivateKey(envPem.split('\\n').join('\n'));
    const publicKey = crypto.createPublicKey(privateKey);
    const rawPub = exportEd25519RawPublic(publicKey);
    const publicKeyB64u = b64u(rawPub);
    const keyId = b64u(domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, rawPub)).slice(0, 16);
    if (!options?.ephemeralOnly) {
      fs.mkdirSync(sipDir, { recursive: true, mode: 0o700 });
      writeFileAtomic600(pemPath, String(privateKey.export({ type: 'pkcs8', format: 'pem' })));
      writeFileAtomic600(pubPath, publicKeyB64u + '\n');
    }
    return { privateKey, publicKey, publicKeyB64u, keyId, pemPath, pubPath, ephemeral: Boolean(options?.ephemeralOnly) };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = exportEd25519RawPublic(publicKey);
  const publicKeyB64u = b64u(rawPub);
  const keyId = b64u(domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, rawPub)).slice(0, 16);

  if (!options.ephemeralOnly) {
    fs.mkdirSync(sipDir, { recursive: true, mode: 0o700 });
    const pkcs8Pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    writeFileAtomic600(pemPath, String(pkcs8Pem));
    writeFileAtomic600(pubPath, publicKeyB64u + '\n');
  }

  return {
    privateKey,
    publicKey,
    publicKeyB64u,
    keyId,
    pemPath,
    pubPath,
    ephemeral: Boolean(options.ephemeralOnly),
  };
}

/**
 * Construct canonical domain-labeled signing buffer: ASCII(label) || 0x00 || payloadBuf.
 * @param {string} labelAscii
 * @param {Buffer | Uint8Array} payloadBuf
 * @returns {Buffer}
 */
function buildDomainSignEnvelope(labelAscii, payloadBuf) {
  if (typeof labelAscii !== 'string' || labelAscii.length === 0) {
    throw new TypeError('Domain label must be a non-empty ASCII string');
  }
  const normalizedLabel = labelAscii.endsWith('\0') ? labelAscii.slice(0, -1) : labelAscii;
  const labelBuf = Buffer.from(normalizedLabel, 'ascii');
  const bodyBuf = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(payloadBuf);
  return Buffer.concat([labelBuf, Buffer.from([0x00]), bodyBuf]);
}

/**
 * Sign a domain-separated payload using RFC 8032 Ed25519 (`crypto.sign(null, ...)`).
 * Returns 86-char base64url signature.
 * @param {string} labelAscii
 * @param {Buffer | Uint8Array} payloadBuf
 * @param {crypto.KeyObject | string} privateKey
 * @returns {string}
 */
export function signDomainPayload(labelAscii, payloadBuf, privateKey) {
  const privObj =
    privateKey instanceof crypto.KeyObject ? privateKey : crypto.createPrivateKey(privateKey);
  const msg = buildDomainSignEnvelope(labelAscii, payloadBuf);
  const sig = crypto.sign(null, msg, privObj);
  return b64u(sig);
}

/**
 * Verify an RFC 8032 Ed25519 signature over a domain-separated payload.
 * @param {string} labelAscii
 * @param {Buffer | Uint8Array} payloadBuf
 * @param {string} sigB64u
 * @param {crypto.KeyObject | Buffer | string} publicKey
 * @returns {boolean}
 */
export function verifyDomainPayload(labelAscii, payloadBuf, sigB64u, publicKey) {
  try {
    if (typeof sigB64u !== 'string' || sigB64u.length !== 86) {
      return false;
    }
    const sigBuf = unb64u(sigB64u);
    if (sigBuf.length !== 64) {
      return false;
    }
    const pubObj = resolveEd25519PublicKey(publicKey);
    const msg = buildDomainSignEnvelope(labelAscii, payloadBuf);
    return crypto.verify(null, msg, pubObj, sigBuf);
  } catch {
    return false;
  }
}
