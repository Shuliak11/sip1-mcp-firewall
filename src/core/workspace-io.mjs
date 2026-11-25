/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Bulletproof JSONC State-Machine Parser, Atomic Fsync IO & PID Lock
 * Zero external dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';

const STATE_NORMAL = 0;
const STATE_STRING = 1;
const STATE_STRING_ESCAPE = 2;
const STATE_LINE_COMMENT = 3;
const STATE_BLOCK_COMMENT = 4;

/**
 * Compute 1-based { line, column } from a character offset in source text.
 * @param {string} text
 * @param {number} offset
 * @returns {{ line: number, column: number }}
 */
function offsetToLineColumn(text, offset) {
  let line = 1;
  let column = 1;
  const limit = Math.min(Math.max(0, offset), text.length);
  for (let i = 0; i < limit; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  return { line, column };
}

/**
 * Deterministic state-machine JSONC parser.
 * Safely strips UTF-8 BOM (\uFEFF), // line comments, /* ... * / block comments,
 * and trailing commas before } or ] ONLY outside double-quoted JSON strings.
 * Preserves exact line/column offsets for clear syntax error diagnostics.
 *
 * @param {string} rawText
 * @returns {any}
 */
export function parseJsoncSafe(rawText) {
  if (typeof rawText !== 'string') {
    throw new TypeError('JSONC input must be a string');
  }

  const input = rawText.charCodeAt(0) === 0xfeff ? ' ' + rawText.slice(1) : rawText;
  const len = input.length;
  const chars = new Array(len);

  let state = STATE_NORMAL;
  let blockCommentStart = 0;
  let lastSignificantIndex = -1;
  let lastSignificantChar = '';

  for (let i = 0; i < len; i++) {
    const ch = input[i];
    const next = i + 1 < len ? input[i + 1] : '';

    if (state === STATE_NORMAL) {
      if (ch === '"') {
        state = STATE_STRING;
        chars[i] = ch;
        lastSignificantIndex = i;
        lastSignificantChar = '"';
      } else if (ch === '/' && next === '/') {
        state = STATE_LINE_COMMENT;
        chars[i] = ' ';
        chars[i + 1] = ' ';
        i++;
      } else if (ch === '/' && next === '*') {
        state = STATE_BLOCK_COMMENT;
        blockCommentStart = i;
        chars[i] = ' ';
        chars[i + 1] = ' ';
        i++;
      } else {
        if ((ch === '}' || ch === ']') && lastSignificantChar === ',' && lastSignificantIndex >= 0) {
          // Erase trailing comma outside strings while preserving exact character positions
          chars[lastSignificantIndex] = ' ';
        }
        chars[i] = ch;
        if (ch !== ' ' && ch !== '\t' && ch !== '\r' && ch !== '\n') {
          lastSignificantIndex = i;
          lastSignificantChar = ch;
        }
      }
    } else if (state === STATE_STRING) {
      chars[i] = ch;
      if (ch === '\\') {
        state = STATE_STRING_ESCAPE;
      } else if (ch === '"') {
        state = STATE_NORMAL;
        lastSignificantIndex = i;
        lastSignificantChar = '"';
      }
    } else if (state === STATE_STRING_ESCAPE) {
      chars[i] = ch;
      state = STATE_STRING;
    } else if (state === STATE_LINE_COMMENT) {
      if (ch === '\n' || ch === '\r') {
        chars[i] = ch;
        if (ch === '\n') {
          state = STATE_NORMAL;
        }
      } else {
        chars[i] = ' ';
      }
    } else if (state === STATE_BLOCK_COMMENT) {
      if (ch === '*' && next === '/') {
        chars[i] = ' ';
        chars[i + 1] = ' ';
        i++;
        state = STATE_NORMAL;
      } else if (ch === '\n' || ch === '\r') {
        chars[i] = ch;
      } else {
        chars[i] = ' ';
      }
    }
  }

  if (state === STATE_BLOCK_COMMENT) {
    const loc = offsetToLineColumn(input, blockCommentStart);
    const err = /** @type {Error & { line?: number, column?: number }} */ (
      new SyntaxError(`Unterminated block comment in JSONC at line ${loc.line}, column ${loc.column}`)
    );
    err.line = loc.line;
    err.column = loc.column;
    throw err;
  }

  const sanitized = chars.join('');

  try {
    return JSON.parse(sanitized);
  } catch (cause) {
    const rawMsg = cause instanceof Error ? cause.message : String(cause);
    let loc = null;
    const lineColMatch = /line\s+(\d+)\s+column\s+(\d+)/i.exec(rawMsg);
    if (lineColMatch) {
      loc = { line: Number(lineColMatch[1]), column: Number(lineColMatch[2]) };
    } else {
      const posMatch = /position\s+(\d+)/i.exec(rawMsg);
      if (posMatch) {
        loc = offsetToLineColumn(sanitized, Number(posMatch[1]));
      } else {
        const scannedOffset = locateFirstInvalidJsonToken(sanitized);
        loc = offsetToLineColumn(sanitized, scannedOffset);
      }
    }
    const err = /** @type {Error & { line?: number, column?: number }} */ (
      new SyntaxError(`JSONC Parse Error at line ${loc.line}, column ${loc.column}: ${rawMsg}`)
    );
    err.line = loc.line;
    err.column = loc.column;
    throw err;
  }
}

/**
 * Deterministic fallback scanner to pinpoint the exact byte/char offset of a JSON syntax error
 * when a JS engine omits `position N` from SyntaxError.message (e.g. V8 invalid literal errors).
 * @param {string} src
 * @returns {number}
 */
function locateFirstInvalidJsonToken(src) {
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      i++;
      continue;
    }
    if (c === '{' || c === '}' || c === '[' || c === ']' || c === ':' || c === ',') {
      i++;
      continue;
    }
    if (c === '"') {
      const start = i++;
      while (i < n) {
        if (src[i] === '\\') {
          i += 2;
          continue;
        }
        if (src[i] === '"') {
          i++;
          break;
        }
        if (src.charCodeAt(i) < 0x20) return i;
        i++;
      }
      if (i > n || src[i - 1] !== '"') return start;
      continue;
    }
    if (c === '-' || (c >= '0' && c <= '9')) {
      const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(src.slice(i));
      if (!m) return i;
      i += m[0].length;
      if (i < n && /[A-Za-z_]/.test(src[i])) return i;
      continue;
    }
    if (src.startsWith('true', i) && !/[A-Za-z0-9_]/.test(src[i + 4] || '')) {
      i += 4;
      continue;
    }
    if (src.startsWith('false', i) && !/[A-Za-z0-9_]/.test(src[i + 5] || '')) {
      i += 5;
      continue;
    }
    if (src.startsWith('null', i) && !/[A-Za-z0-9_]/.test(src[i + 4] || '')) {
      i += 4;
      continue;
    }
    return i;
  }
  return Math.max(0, n - 1);
}

/**
 * Check if a process PID is dead (`ESRCH`).
 * @param {number} pid
 * @returns {boolean}
 */
function isPidDead(pid) {
  if (!Number.isInteger(pid) || pid <= 0) {
    return true;
  }
  try {
    process.kill(pid, 0);
    return false;
  } catch (err) {
    const code = /** @type {{ code?: string }} */ (err)?.code;
    return code === 'ESRCH';
  }
}

/**
 * Non-spinning synchronous sleep helper using SharedArrayBuffer.
 * @param {number} ms
 */
function sleepSync(ms) {
  const sab = new SharedArrayBuffer(4);
  const view = new Int32Array(sab);
  Atomics.wait(view, 0, 0, ms);
}

/**
 * Execute `fn` inside an exclusive `.sip/op.lock` concurrency guard (`wx` flag).
 * Automatically reclaims stale locks if owning PID is dead (`ESRCH`) or older than 30s.
 * Supports both synchronous and asynchronous callbacks seamlessly.
 *
 * @template T
 * @param {string} sipDir
 * @param {() => T | Promise<T>} fn
 * @param {number} [timeoutMs=3000]
 * @returns {Promise<T>}
 */
export async function withPidLock(sipDir, fn, timeoutMs = 3000) {
  fs.mkdirSync(sipDir, { recursive: true, mode: 0o700 });
  const lockPath = path.join(sipDir, 'op.lock');
  const start = Date.now();
  const staleThresholdMs = 30_000;
  let acquired = false;

  while (!acquired) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);
      const payload = JSON.stringify({ pid: process.pid, ts: Date.now() });
      fs.writeFileSync(fd, payload, 'utf8');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      acquired = true;
    } catch (err) {
      const code = /** @type {{ code?: string }} */ (err)?.code;
      if (code !== 'EEXIST') {
        throw err;
      }

      // Inspect existing lock to see if owner PID died or lock aged > 30s
      let shouldReclaim = false;
      try {
        const raw = fs.readFileSync(lockPath, 'utf8');
        const parsed = JSON.parse(raw);
        const lockPid = Number(parsed?.pid);
        const lockTs = Number(parsed?.ts);
        if (
          !Number.isFinite(lockTs) ||
          Date.now() - lockTs > staleThresholdMs ||
          isPidDead(lockPid)
        ) {
          shouldReclaim = true;
        }
      } catch {
        // Corrupted or unreadable lock file -> reclaim if file gone or broken
        shouldReclaim = true;
      }

      if (shouldReclaim) {
        try {
          fs.unlinkSync(lockPath);
        } catch {
          // Ignore ENOENT race
        }
        continue;
      }

      if (Date.now() - start >= timeoutMs) {
        throw new Error(`Timed out acquiring SIP PID lock at ${lockPath} after ${timeoutMs}ms`);
      }

      sleepSync(15);
    }
  }

  try {
    return await fn();
  } finally {
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // Ignore cleanup race
    }
  }
}

/**
 * Atomically write file with mode 0o600 inside a 0o700 parent directory:
 * write `<target>.tmp.<pid>.<rand>` (0o600) -> fsyncSync -> closeSync -> renameSync.
 *
 * @param {string} targetPath
 * @param {Buffer | Uint8Array | string} dataBufOrStr
 * @param {{ mode?: number }} [options]
 */
export function writeFileAtomic600(targetPath, dataBufOrStr, options = {}) {
  const fileMode = options.mode ?? 0o600;
  const parentDir = path.dirname(targetPath);
  fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });

  const randHex = crypto.randomBytes(6).toString('hex');
  const tmpPath = `${targetPath}.tmp.${process.pid}.${randHex}`;
  const buf =
    Buffer.isBuffer(dataBufOrStr) || dataBufOrStr instanceof Uint8Array
      ? dataBufOrStr
      : Buffer.from(String(dataBufOrStr), 'utf8');

  let fd = -1;
  try {
    fd = fs.openSync(tmpPath, 'wx', fileMode);
    fs.writeSync(fd, buf, 0, buf.byteLength, 0);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = -1;
    fs.chmodSync(tmpPath, fileMode);
    fs.renameSync(tmpPath, targetPath);
  } catch (err) {
    if (fd !== -1) {
      try {
        fs.closeSync(fd);
      } catch {
        // Ignore
      }
    }
    try {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
    } catch {
      // Ignore
    }
    throw err;
  }
}

/**
 * Safely back up an existing configuration file before modification:
 * creates `<filePath>.sip-backup-<timestamp>` with mode `0o600`.
 *
 * @param {string} filePath
 * @returns {string | null} Backup file path if source existed, else null
 */
export function backupConfigBeforeEdit(filePath) {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const existingBytes = fs.readFileSync(filePath);
  const backupPath = `${filePath}.sip-backup-${Date.now()}`;
  writeFileAtomic600(backupPath, existingBytes, { mode: 0o600 });
  return backupPath;
}

/**
 * Normalize a config file path relative to `workspaceDir` using forward slashes (`/`)
 * deterministically across Windows (`C:\...`), macOS (`/Users/...`), and Linux (`/home/...`)
 * regardless of the current host `process.platform`.
 *
 * @param {string | null | undefined} workspaceDir
 * @param {string | null | undefined} filePath
 * @returns {string}
 */
export function normalizeCrossPlatformRelPath(workspaceDir, filePath) {
  if (!filePath) return '.mcp.json';
  const normFile = String(filePath).replace(/\\/g, '/').replace(/\/+/g, '/');
  if (!workspaceDir) return normFile;
  const normWs = String(workspaceDir)
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/\/$/, '');

  const fileDriveMatch = /^([A-Za-z]):(\/.*|$)/.exec(normFile);
  const wsDriveMatch = /^([A-Za-z]):(\/.*|$)/.exec(normWs);

  if (fileDriveMatch && wsDriveMatch) {
    if (fileDriveMatch[1].toUpperCase() !== wsDriveMatch[1].toUpperCase()) {
      return normFile;
    }
    const rel = path.posix.relative(wsDriveMatch[2] || '/', fileDriveMatch[2] || '/');
    return rel.startsWith('..') ? normFile : rel || path.posix.basename(normFile);
  }

  if (normFile.startsWith('/') && normWs.startsWith('/')) {
    const rel = path.posix.relative(normWs, normFile);
    return rel.startsWith('..') ? normFile : rel || path.posix.basename(normFile);
  }

  if (!normFile.startsWith('/') && !fileDriveMatch) {
    return normFile.replace(/^\.\//, '') || '.mcp.json';
  }

  const rel = path.relative(String(workspaceDir), String(filePath)).replace(/\\/g, '/');
  return rel.startsWith('..') ? normFile : rel || path.posix.basename(normFile);
}

