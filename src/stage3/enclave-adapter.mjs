/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 3 Non-Blocking Headless Root Key Enclave & Atomic Rotation
 * Zero interactive GUI popups (safe for headless stdio MCP pipes & CI).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import { allocSecure, zeroizeBuffer } from '../core/crypto-primitives.mjs';
import { writeFileAtomic600 } from '../core/workspace-io.mjs';

const ENCLAVE_MAGIC = Buffer.from('SIPKEK03', 'ascii');

/**
 * Resolve the persistent 32-byte host salt path (`~/.config/shuliak/machine-salt.bin`,
 * overridable via `SIP_MACHINE_SALT_PATH` for isolated testing, with automatic fallback
 * to `<enclaveDir>/machine-salt.bin` in read-only `$HOME` containers).
 *
 * @param {string} resolvedEnclaveDir
 * @returns {string}
 */
export function resolveMachineSaltPath(resolvedEnclaveDir) {
  if (process.env.SIP_MACHINE_SALT_PATH && process.env.SIP_MACHINE_SALT_PATH.trim()) {
    return path.resolve(process.env.SIP_MACHINE_SALT_PATH.trim());
  }
  const homeDir = os.homedir();
  const xdgConfig = process.env.XDG_CONFIG_HOME
    ? path.resolve(process.env.XDG_CONFIG_HOME)
    : path.join(homeDir, '.config');
  return path.join(xdgConfig, 'shuliak', 'machine-salt.bin');
}

/**
 * Load or atomically provision the 32-byte host-bound machine salt (`0o600`).
 * Never cached across calls so rotating or removing `machine-salt.bin` immediately invalidates
 * copied `.kek` envelopes.
 *
 * @param {string} resolvedEnclaveDir
 * @returns {Buffer}
 */
function loadOrCreateMachineSalt32(resolvedEnclaveDir) {
  const candidates = [
    resolveMachineSaltPath(resolvedEnclaveDir),
    path.join(resolvedEnclaveDir, 'machine-salt.bin'),
  ];

  for (const saltPath of candidates) {
    try {
      if (fs.existsSync(saltPath)) {
        const raw = fs.readFileSync(saltPath);
        if (raw.byteLength >= 32) {
          const out = allocSecure(32);
          raw.copy(out, 0, 0, 32);
          raw.fill(0);
          return out;
        }
      }
      fs.mkdirSync(path.dirname(saltPath), { recursive: true, mode: 0o700 });
      const fresh = allocSecure(32);
      crypto.randomFillSync(fresh);
      writeFileAtomic600(saltPath, fresh, { mode: 0o600 });
      return fresh;
    } catch {
      // Fall through to enclave-local fallback if $HOME/.config/shuliak is read-only
    }
  }

  throw new Error('Unable to provision 32-byte machine-salt.bin in ~/.config/shuliak or enclaveDir');
}

/**
 * Derive a deterministic host-bound 32-byte wrapping key from local platform/arch + enclave directory
 * + persistent 32-byte `~/.config/shuliak/machine-salt.bin`.
 * Never prompts GUI dialogs or blocks stdio pipes.
 * @param {string} resolvedEnclaveDir
 * @param {Buffer} fileSalt16
 * @returns {Buffer}
 */
function deriveHostBindingKey(resolvedEnclaveDir, fileSalt16) {
  const machineSalt32 = loadOrCreateMachineSalt32(resolvedEnclaveDir);
  try {
    const hostContext = Buffer.from(
      `SIP-v3-HOST-ENCLAVE|${process.platform}|${process.arch}|${resolvedEnclaveDir}|`,
      'utf8'
    );
    const ikm = Buffer.concat([hostContext, machineSalt32]);
    try {
      const raw = crypto.hkdfSync(
        'sha256',
        ikm,
        fileSalt16,
        Buffer.from('ISEP-v3-KEK-SEAL\0', 'ascii'),
        32
      );
      const secure = allocSecure(32);
      Buffer.from(raw).copy(secure);
      return secure;
    } finally {
      ikm.fill(0);
    }
  } finally {
    zeroizeBuffer(machineSalt32);
  }
}

/**
 * Sanitize `keyringId` to a safe filename stem.
 * @param {string} id
 * @returns {string}
 */
function safeKeyringFilename(id) {
  const clean = String(id || 'default').replace(/[^A-Za-z0-9._-]/g, '_');
  return `${clean}.kek`;
}

/**
 * Seal a 32-byte `kekBuf` into a binary envelope (`SIPKEK03 || salt16 || iv12 || tag16 || cipher32` = 84B).
 * @param {string} resolvedEnclaveDir
 * @param {string} id
 * @param {Buffer} kekBuf
 * @returns {Buffer}
 */
function packEnclaveEnvelope(resolvedEnclaveDir, id, kekBuf) {
  if (!Buffer.isBuffer(kekBuf) || kekBuf.length !== 32) {
    throw new RangeError('Root KEK must be a 32-byte Buffer');
  }
  const salt16 = crypto.randomBytes(16);
  const iv12 = crypto.randomBytes(12);
  const hostKey = deriveHostBindingKey(resolvedEnclaveDir, salt16);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', hostKey, iv12);
    cipher.setAAD(Buffer.concat([ENCLAVE_MAGIC, Buffer.from(String(id), 'utf8')]));
    const enc = Buffer.concat([cipher.update(kekBuf), cipher.final()]);
    const tag16 = cipher.getAuthTag();
    return Buffer.concat([ENCLAVE_MAGIC, salt16, iv12, tag16, enc]);
  } finally {
    zeroizeBuffer(hostKey);
  }
}

/**
 * Unpack an 84-byte binary envelope into an `allocSecure(32)` buffer.
 * @param {string} resolvedEnclaveDir
 * @param {string} id
 * @param {Buffer} envelope
 * @returns {Buffer}
 */
function unpackEnclaveEnvelope(resolvedEnclaveDir, id, envelope) {
  if (!Buffer.isBuffer(envelope) || envelope.length !== 84) {
    throw new Error('Corrupted enclave KEK file length');
  }
  if (!envelope.subarray(0, 8).equals(ENCLAVE_MAGIC)) {
    throw new Error('Invalid enclave KEK magic header');
  }
  const salt16 = envelope.subarray(8, 24);
  const iv12 = envelope.subarray(24, 36);
  const tag16 = envelope.subarray(36, 52);
  const enc32 = envelope.subarray(52, 84);

  const hostKey = deriveHostBindingKey(resolvedEnclaveDir, salt16);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', hostKey, iv12);
    decipher.setAAD(Buffer.concat([ENCLAVE_MAGIC, Buffer.from(String(id), 'utf8')]));
    decipher.setAuthTag(tag16);
    const plain = Buffer.concat([decipher.update(enc32), decipher.final()]);
    const out = allocSecure(32);
    plain.copy(out);
    plain.fill(0);
    return out;
  } finally {
    zeroizeBuffer(hostKey);
  }
}

/**
 * Create a headless filesystem enclave adapter storing host-bound `0o600` `.kek` files
 * inside `enclaveDir` (e.g., `.sip/enclave/`), with fsynced atomic temp-file rotation.
 *
 * @param {string} enclaveDir
 */
export function createHeadlessEnclaveAdapter(enclaveDir) {
  const resolvedDir = path.resolve(enclaveDir);
  fs.mkdirSync(resolvedDir, { recursive: true, mode: 0o700 });

  return {
    kind: 'HEADLESS_FS_0600',
    enclaveDir: resolvedDir,

    /**
     * @param {string} id
     * @returns {boolean}
     */
    hasRootKey(id) {
      return fs.existsSync(path.join(resolvedDir, safeKeyringFilename(id)));
    },

    /**
     * @param {string} id
     * @param {Buffer} kekBuf
     */
    sealRootKey(id, kekBuf) {
      const targetPath = path.join(resolvedDir, safeKeyringFilename(id));
      const env = packEnclaveEnvelope(resolvedDir, id, kekBuf);
      writeFileAtomic600(targetPath, env, { mode: 0o600 });
    },

    /**
     * @param {string} id
     * @returns {Buffer}
     */
    unsealRootKey(id) {
      const targetPath = path.join(resolvedDir, safeKeyringFilename(id));
      if (!fs.existsSync(targetPath)) {
        throw new Error(`Enclave root key "${id}" not found at ${targetPath}`);
      }
      const raw = fs.readFileSync(targetPath);
      return unpackEnclaveEnvelope(resolvedDir, id, raw);
    },

    /**
     * Atomically overwrite sealed root KEK via fsynced `0o600` temp-file rename.
     * @param {string} id
     * @param {Buffer} newKekBuf
     */
    rotateRootKey(id, newKekBuf) {
      const targetPath = path.join(resolvedDir, safeKeyringFilename(id));
      const env = packEnclaveEnvelope(resolvedDir, id, newKekBuf);
      writeFileAtomic600(targetPath, env, { mode: 0o600 });
    },
  };
}

/**
 * Create an in-memory volatile RAM enclave adapter for unit tests and ephemeral server workers.
 */
export function createVolatileRamEnclaveAdapter() {
  /** @type {Map<string, Buffer>} */
  const store = new Map();

  return {
    kind: 'VOLATILE_RAM',

    /**
     * @param {string} id
     * @returns {boolean}
     */
    hasRootKey(id) {
      return store.has(String(id));
    },

    /**
     * @param {string} id
     * @param {Buffer} kekBuf
     */
    sealRootKey(id, kekBuf) {
      if (!Buffer.isBuffer(kekBuf) || kekBuf.length !== 32) {
        throw new RangeError('Root KEK must be a 32-byte Buffer');
      }
      const existing = store.get(String(id));
      if (existing) zeroizeBuffer(existing);
      const copy = allocSecure(32);
      kekBuf.copy(copy);
      store.set(String(id), copy);
    },

    /**
     * @param {string} id
     * @returns {Buffer}
     */
    unsealRootKey(id) {
      const existing = store.get(String(id));
      if (!existing) {
        throw new Error(`Volatile enclave root key "${id}" not found`);
      }
      const copy = allocSecure(32);
      existing.copy(copy);
      return copy;
    },

    /**
     * @param {string} id
     * @param {Buffer} newKekBuf
     */
    rotateRootKey(id, newKekBuf) {
      this.sealRootKey(id, newKekBuf);
    },
  };
}
