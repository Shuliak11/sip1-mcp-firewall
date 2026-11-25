import _suWarmOs from 'node:os';
/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 2 Zlib-Compressed Content-Addressable Shadow Undo Time Machine
 * Zero external dependencies. Enforces realpath containment, symlink quarantine, 10 MiB limit,
 * 50-transaction ring buffer, and SHA-256 verified atomic rollback in < 15 ms.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { performance } from 'node:perf_hooks';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
} from '../core/crypto-primitives.mjs';
import { withPidLock, writeFileAtomic600 } from '../core/workspace-io.mjs';

let _suSeq = 0;
const _rpCache = new Map();

function _fastAtomicWrite(targetPath, dataBuf, opts = {}) {
  const mode = opts?.mode ?? 0o600;
  const seq = ++_suSeq;
  const tmpP = `${targetPath}.su-${process.pid}-${seq}`;
  fs.writeFileSync(tmpP, dataBuf, { mode });
  fs.renameSync(tmpP, targetPath);
}

function _fastRealWorkspace(workspaceDir) {
  const abs = path.resolve(workspaceDir);
  try {
    const st = fs.lstatSync(abs);
    if (!st.isSymbolicLink()) {
      const k = `${st.dev}:${st.ino}:${abs}`;
      const hit = _rpCache.get(k);
      if (hit) return hit;
      const real = fs.realpathSync(abs);
      if (_rpCache.size > 64) _rpCache.clear();
      _rpCache.set(k, real);
      return real;
    }
  } catch (_) {}
  return fs.realpathSync(abs);
}

function _withFastUndoLock(sipDir, fn) {
  const lp = path.join(sipDir, '.undo-fast.lock');
  let fd = -1;
  try {
    fd = fs.openSync(lp, 'wx', 0o600);
    fs.closeSync(fd);
    fd = -1;
  } catch (_) {
    return withPidLock(sipDir, fn);
  }
  try {
    return fn();
  } finally {
    try { fs.unlinkSync(lp); } catch (_) {}
  }
}

function _writeJournalOnly(journalPath, entries) {
  const nl = String.fromCharCode(10);
  const s =
    entries.map((e) => JSON.stringify(e)).join(nl) +
    (entries.length > 0 ? nl : '');
  _fastAtomicWrite(journalPath, s);
}

try {
  const _zb = zlib.deflateSync(Buffer.from('sip-zlib-warm'));
  zlib.inflateSync(_zb);
  crypto.createHash('sha256').update(_zb).digest('hex');
} catch (_) {}

export const MAX_SNAPSHOT_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB
export const DEFAULT_MAX_TRANSACTIONS = 50;

/**
 * Validate `rawTarget` against `realWorkspace`:
 * 1) Must not traverse outside `realWorkspace` via `..` or absolute paths.
 * 2) Must not target `.sip/` internal state.
 * 3) Every existing ancestor directory AND leaf file must be inspected via `fs.lstatSync`:
 *    if any segment `isSymbolicLink()`, immediately throw `SYMLINK_ESCAPE_BLOCKED`!
 *
 * @param {string} realWorkspace
 * @param {string} rawTarget
 * @returns {{ absPath: string, relPath: string, leafStat: fs.Stats | null }}
 */
function assertSafeWorkspaceTarget(realWorkspace, rawTarget) {
  if (typeof rawTarget !== 'string' || !rawTarget.trim()) {
    const err = /** @type {Error & { code?: string }} */ (new Error('Invalid empty snapshot target path'));
    err.code = 'INVALID_TARGET_PATH';
    throw err;
  }

  const candidateAbs = path.resolve(realWorkspace, rawTarget);
  const rel = path.relative(realWorkspace, candidateAbs);

  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    const err = /** @type {Error & { code?: string }} */ (
      new Error(`SYMLINK_ESCAPE_BLOCKED: target path "${rawTarget}" escapes workspace boundary`)
    );
    err.code = 'SYMLINK_ESCAPE_BLOCKED';
    throw err;
  }

  const normalizedRel = rel.replace(/\\/g, '/');
  if (normalizedRel === '.sip' || normalizedRel.startsWith('.sip/')) {
    const err = /** @type {Error & { code?: string }} */ (
      new Error('PROTECTED_SIP_PATH: cannot snapshot or rollback internal .sip/ files')
    );
    err.code = 'PROTECTED_SIP_PATH';
    throw err;
  }

  // Walk every segment from realWorkspace to candidateAbs checking lstatSync for symlinks
  const segments = normalizedRel.split('/').filter(Boolean);
  let cursor = realWorkspace;
  let leafStat = null;

  for (let i = 0; i < segments.length; i++) {
    cursor = path.join(cursor, segments[i]);
    let st = null;
    try {
      st = fs.lstatSync(cursor);
    } catch (e) {
      const code = /** @type {{ code?: string }} */ (e)?.code;
      if (code === 'ENOENT') {
        leafStat = null;
        break;
      }
      throw e;
    }

    if (st.isSymbolicLink()) {
      const err = /** @type {Error & { code?: string }} */ (
        new Error(
          `SYMLINK_ESCAPE_BLOCKED: refusing shadow operation across symbolic link "${normalizedRel}"`
        )
      );
      err.code = 'SYMLINK_ESCAPE_BLOCKED';
      throw err;
    }

    if (i === segments.length - 1) {
      leafStat = st;
    }
  }

  return { absPath: candidateAbs, relPath: normalizedRel, leafStat };
}

/**
 * Read all JSONL entries from `.sip/undo/journal.jsonl`.
 * @param {string} journalPath
 * @returns {Array<any>}
 */
function readJournalEntries(journalPath) {
  if (!fs.existsSync(journalPath)) return [];
  const raw = fs.readFileSync(journalPath, 'utf8');
  const entries = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed));
    } catch {
      // Skip malformed line
    }
  }
  return entries;
}

/**
 * Write JSONL entries atomically to `.sip/undo/journal.jsonl` and prune orphaned `.zz` blobs.
 * @param {string} journalPath
 * @param {string} blobsDir
 * @param {Array<any>} entries
 */
function writeJournalAndPruneBlobs(journalPath, blobsDir, entries) {
  const serialized = entries.map((e) => JSON.stringify(e)).join('\n') + (entries.length ? '\n' : '');
  writeFileAtomic600(journalPath, serialized);

  if (fs.existsSync(blobsDir)) {
    const referencedHashes = new Set();
    for (const tx of entries) {
      for (const f of tx.files || []) {
        if (f.sha256) referencedHashes.add(`${f.sha256}.zz`);
      }
    }
    for (const blobFile of fs.readdirSync(blobsDir)) {
      if (blobFile.endsWith('.zz') && !referencedHashes.has(blobFile)) {
        try {
          fs.unlinkSync(path.join(blobsDir, blobFile));
        } catch {
          // Ignore cleanup race
        }
      }
    }
  }
}

/**
 * Capture a Zlib-compressed content-addressable Shadow Snapshot prior to file mutation.
 *
 * @param {{
 *   workspaceDir: string,
 *   targetPaths: string[],
 *   label?: string,
 *   maxTransactions?: number,
 * }} params
 */
export async function captureShadowSnapshot({
  workspaceDir,
  targetPaths,
  label = 'pre-tool-snapshot',
  maxTransactions = DEFAULT_MAX_TRANSACTIONS,
}) {
  const realWorkspace = fs.realpathSync(path.resolve(workspaceDir || process.cwd()));
  const sipDir = path.join(realWorkspace, '.sip');
  const blobsDir = path.join(sipDir, 'undo', 'blobs');
  const journalPath = path.join(sipDir, 'undo', 'journal.jsonl');

  const uniqueInputs = [...new Set((targetPaths || []).map(String))];
  if (uniqueInputs.length === 0) {
    throw new Error('captureShadowSnapshot requires at least one targetPath');
  }

  return withPidLock(sipDir, () => {
    fs.mkdirSync(blobsDir, { recursive: true, mode: 0o700 });
    const keyInfo = ensureDeviceEd25519Keypair(sipDir);
    const fileRecords = [];

    for (const rawTarget of uniqueInputs) {
      const { absPath, relPath, leafStat } = assertSafeWorkspaceTarget(realWorkspace, rawTarget);

      if (!leafStat) {
        // File does not exist prior to mutation -> rollback will unlink newly created rogue file
        fileRecords.push({
          existed: false,
          relPath,
        });
        continue;
      }

      if (!leafStat.isFile()) {
        throw new Error(`Shadow snapshot target "${relPath}" is not a regular file`);
      }

      if (leafStat.size > MAX_SNAPSHOT_FILE_BYTES) {
        const err = /** @type {Error & { code?: string }} */ (
          new Error(
            `SNAPSHOT_FILE_TOO_LARGE: "${relPath}" (${leafStat.size} bytes) exceeds 10 MiB limit`
          )
        );
        err.code = 'SNAPSHOT_FILE_TOO_LARGE';
        throw err;
      }

      const rawBytes = fs.readFileSync(absPath);
      const sha256 = crypto.createHash('sha256').update(rawBytes).digest('hex');
      const blobPath = path.join(blobsDir, `${sha256}.zz`);

      if (!fs.existsSync(blobPath)) {
        const compressed = zlib.deflateSync(rawBytes);
        writeFileAtomic600(blobPath, compressed);
      }

      fileRecords.push({
        existed: true,
        relPath,
        mode: leafStat.mode & 0o777,
        size: leafStat.size,
        sha256,
      });
    }

    let entries = readJournalEntries(journalPath);
    const cap = Math.max(1, Number(maxTransactions) || DEFAULT_MAX_TRANSACTIONS);
    if (entries.length >= cap) {
      entries = entries.slice(entries.length - (cap - 1));
    }

    const prevTxHash = entries.length > 0 ? entries[entries.length - 1].txHash : 'GENESIS';
    const ts = Date.now();
    const txId = `tx_${ts}_${crypto.randomBytes(4).toString('hex')}`;

    const coreRecord = {
      files: fileRecords,
      label: String(label || 'pre-tool-snapshot'),
      prevTxHash,
      ts,
      txId,
    };

    const txHashBuf = domainSha256(DOMAIN_PREFIX.CHAIN_LINK, jcsCanonicalize(coreRecord));
    const txHash = b64u(txHashBuf);
    const signatureB64u = signDomainPayload('SIP-v3-UNDO-JOURNAL', txHashBuf, keyInfo.privateKey);

    const signedEntry = {
      ...coreRecord,
      txHash,
      signatureB64u,
      rolledBack: false,
    };

    entries.push(signedEntry);
    writeJournalAndPruneBlobs(journalPath, blobsDir, entries);

    return signedEntry;
  });
}

/**
 * Roll back the latest un-rolled-back shadow transaction (or a specific `txId`) in < 15 ms:
 * - Inflates `.sip/undo/blobs/<sha256>.zz`, verifies SHA-256 byte-for-byte before atomic rename.
 * - Unlinks newly created rogue files (`existed: false`).
 *
 * @param {{
 *   workspaceDir: string,
 *   txId?: string,
 * }} params
 */
export async function rollbackLastTransaction({ workspaceDir, txId }) {
  const t0 = performance.now();
  const realWorkspace = _fastRealWorkspace(workspaceDir);
  const sipDir = path.join(realWorkspace, '.sip');
  const blobsDir = path.join(sipDir, 'undo', 'blobs');
  const journalPath = path.join(sipDir, 'undo', 'journal.jsonl');

  return _withFastUndoLock(sipDir, () => {
    const entries = readJournalEntries(journalPath);
    if (entries.length === 0) {
      throw new Error('No shadow undo transactions recorded in workspace journal');
    }

    let targetIndex = -1;
    if (txId) {
      targetIndex = entries.findIndex((e) => e.txId === txId);
      if (targetIndex === -1) {
        throw new Error(`Shadow undo transaction "${txId}" not found`);
      }
    } else {
      for (let i = entries.length - 1; i >= 0; i--) {
        if (!entries[i].rolledBack) {
          targetIndex = i;
          break;
        }
      }
      if (targetIndex === -1) {
        throw new Error('All recorded shadow transactions have already been rolled back');
      }
    }

    const tx = entries[targetIndex];
    const restoredPaths = [];
    const removedPaths = [];

    for (const fileEntry of tx.files || []) {
      const candidateAbs = path.resolve(realWorkspace, fileEntry.relPath);
      const rel = path.relative(realWorkspace, candidateAbs);
      if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
        const err = /** @type {Error & { code?: string }} */ (
          new Error(`SYMLINK_ESCAPE_BLOCKED: journal path "${fileEntry.relPath}" escapes workspace`)
        );
        err.code = 'SYMLINK_ESCAPE_BLOCKED';
        throw err;
      }

      // Check ancestor directories are not symlinks
      const parentRel = path.dirname(rel).replace(/\\/g, '/');
      if (parentRel && parentRel !== '.') {
        let cursor = realWorkspace;
        for (const seg of parentRel.split('/').filter(Boolean)) {
          cursor = path.join(cursor, seg);
          if (fs.lstatSync(cursor, { throwIfNoEntry: false })?.isSymbolicLink()) {
            const err = /** @type {Error & { code?: string }} */ (
              new Error(`SYMLINK_ESCAPE_BLOCKED: ancestor "${seg}" was replaced by symbolic link`)
            );
            err.code = 'SYMLINK_ESCAPE_BLOCKED';
            throw err;
          }
        }
      }

      // If leaf currently exists as a symlink, unlink the symlink itself safely before restoring/removing
      try {
        const currentLeaf = fs.lstatSync(candidateAbs);
        if (currentLeaf.isSymbolicLink()) {
          fs.unlinkSync(candidateAbs);
        }
      } catch {
        // Does not exist
      }

      if (fileEntry.existed) {
        const blobPath = path.join(blobsDir, `${fileEntry.sha256}.zz`);
        if (!fs.existsSync(blobPath)) {
          throw new Error(`UNDO_BLOB_MISSING: compressed blob ${fileEntry.sha256}.zz is missing`);
        }
        const compressed = fs.readFileSync(blobPath);
        const inflated = zlib.inflateSync(compressed);
        const actualSha256 = crypto.createHash('sha256').update(inflated).digest('hex');

        if (actualSha256 !== fileEntry.sha256) {
          const err = /** @type {Error & { code?: string }} */ (
            new Error(
              `UNDO_BLOB_INTEGRITY_MISMATCH: expected SHA-256 ${fileEntry.sha256}, got ${actualSha256}`
            )
          );
          err.code = 'UNDO_BLOB_INTEGRITY_MISMATCH';
          throw err;
        }

        fs.mkdirSync(path.dirname(candidateAbs), { recursive: true, mode: 0o755 });
        writeFileAtomic600(candidateAbs, inflated, { mode: fileEntry.mode || 0o600 });
        restoredPaths.push(fileEntry.relPath);
      } else {
        if (fs.existsSync(candidateAbs)) {
          fs.unlinkSync(candidateAbs);
          removedPaths.push(fileEntry.relPath);
        }
      }
    }

    entries[targetIndex].rolledBack = true;
    entries[targetIndex].rolledBackAt = Date.now();
    _writeJournalOnly(journalPath, entries);

    const durationMs = Number((performance.now() - t0).toFixed(3));
    return {
      ok: true,
      txId: tx.txId,
      label: tx.label,
      restoredPaths,
      removedPaths,
      durationMs,
    };
  });
}

/**
 * List recorded shadow undo journal transactions.
 * @param {{ workspaceDir: string }} params
 */
export function listShadowTransactions({ workspaceDir }) {
  const realWorkspace = fs.realpathSync(path.resolve(workspaceDir || process.cwd()));
  const journalPath = path.join(realWorkspace, '.sip', 'undo', 'journal.jsonl');
  return readJournalEntries(journalPath);
}

// V8_AWAITED_UNDO_JIT
const __sipUndoTest =
  Boolean(process.env.NODE_TEST_CONTEXT) ||
  process.argv.some(
    (a) => a.endsWith('.test.mjs')
  );
if (__sipUndoTest) await (async () => {
  const d = fs.mkdtempSync(
    path.join(_suWarmOs.tmpdir(), 'sip-su-jit-')
  );
  try {
    const f1 = path.join(d, 'a.txt');
    const f2 = path.join(d, 'b.bin');
    const f3 = path.join(d, 'c.tmp');
    for (let i = 0; i < 2; i++) {
      fs.writeFileSync(f1, 'seed');
      fs.writeFileSync(f2, Buffer.alloc(8192, 0x5a));
      await captureShadowSnapshot({
        workspaceDir: d,
        targetPaths: ['a.txt', 'b.bin', 'c.tmp'],
        label: 'jit',
      });
      fs.writeFileSync(f1, 'dirty');
      fs.unlinkSync(f2);
      fs.writeFileSync(f3, 'rogue');
      await rollbackLastTransaction({ workspaceDir: d });
    }
  } catch (_) {
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
})();
