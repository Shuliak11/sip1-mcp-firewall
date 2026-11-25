/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 2 Cryptographic Canary Honeytokens & Instant Workspace Lockdown
 * Zero plaintext storage: `.sip/state/canaries.json` stores ONLY salted HMAC-SHA256 digests + masked previews.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { b64u, unb64u } from '../core/crypto-primitives.mjs';
import { withPidLock, writeFileAtomic600 } from '../core/workspace-io.mjs';
import { maskSecretPreview } from '../stage1/audit-scanner.mjs';
import { revokeAllActiveLeases } from './warrant-engine.mjs';

const UPPER_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const MIXED_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Generate cryptographically random string from alphabet using `crypto.randomBytes`.
 * @param {number} length
 * @param {string} alphabet
 * @returns {string}
 */
function randomAlphabetChars(length, alphabet) {
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

/**
 * Synthesize realistic decoy honeytoken credential by `kind`.
 * @param {'AWS_KEY' | 'OPENAI_KEY' | 'ENV_FILE' | string} kind
 * @returns {string}
 */
function generateDecoyCredential(kind) {
  const normalizedKind = String(kind || 'AWS_KEY').toUpperCase();
  if (normalizedKind === 'AWS_KEY') {
    return 'AKIA' + randomAlphabetChars(16, UPPER_ALNUM);
  }
  if (normalizedKind === 'OPENAI_KEY') {
    return 'sk-proj-' + randomAlphabetChars(32, MIXED_ALNUM);
  }
  if (normalizedKind === 'ENV_FILE') {
    return 'glpat-' + randomAlphabetChars(28, MIXED_ALNUM);
  }
  return 'sk-sip-canary-' + randomAlphabetChars(28, MIXED_ALNUM);
}

/**
 * Read registered canary records from `.sip/state/canaries.json`.
 * @param {string} canariesPath
 * @returns {Array<{
 *   canaryId: string,
 *   kind: string,
 *   saltB64u: string,
 *   hmacB64u: string,
 *   maskedPreview: string,
 *   decoyFile: string | null,
 *   tokenLength: number,
 *   plantedAt: number,
 * }>}
 */
function readCanariesRegistry(canariesPath) {
  if (!fs.existsSync(canariesPath)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(canariesPath, 'utf8'));
    return Array.isArray(parsed?.canaries) ? parsed.canaries : [];
  } catch {
    return [];
  }
}

/**
 * Plant a cryptographic Canary Honeytoken in `.sip/state/canaries.json` (and optionally `.env.sip-canary`).
 * Stores ONLY salted HMAC-SHA256 + `maskedPreview` inside `.sip/state/canaries.json` — NEVER plaintext!
 *
 * @param {{
 *   workspaceDir: string,
 *   kind?: 'AWS_KEY' | 'OPENAI_KEY' | 'ENV_FILE' | string,
 *   writeDecoyFile?: boolean,
 * }} params
 */
export async function plantCanaryToken({
  workspaceDir,
  kind = 'AWS_KEY',
  writeDecoyFile = false,
}) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const canariesPath = path.join(sipDir, 'state', 'canaries.json');
  const normalizedKind = String(kind || 'AWS_KEY').toUpperCase();

  return withPidLock(sipDir, () => {
    const decoyToken = generateDecoyCredential(normalizedKind);
    const salt = crypto.randomBytes(32);
    const hmacDigest = crypto.createHmac('sha256', salt).update(decoyToken, 'utf8').digest();
    const maskedPreview = maskSecretPreview(decoyToken);
    const canaryId = 'cnr_' + b64u(crypto.randomBytes(12));
    const plantedAt = Date.now();

    let decoyFileRel = null;
    let decoyFilePath = null;
    if (writeDecoyFile || normalizedKind === 'ENV_FILE') {
      if (writeDecoyFile) {
        decoyFileRel = '.env.sip-canary';
        decoyFilePath = path.join(resolvedWs, decoyFileRel);
        const content = `# INTERNAL PRODUCTION CREDENTIALS - DO NOT SHARE\nSIP_CANARY_TOKEN=${decoyToken}\n`;
        writeFileAtomic600(decoyFilePath, content, { mode: 0o600 });
      }
    }

    const canaries = readCanariesRegistry(canariesPath);
    canaries.push({
      canaryId,
      kind: normalizedKind,
      saltB64u: b64u(salt),
      hmacB64u: b64u(hmacDigest),
      maskedPreview,
      decoyFile: decoyFileRel,
      tokenLength: decoyToken.length,
      plantedAt,
    });

    writeFileAtomic600(canariesPath, JSON.stringify({ canaries }, null, 2) + '\n');

    return {
      canaryId,
      kind: normalizedKind,
      decoyToken,
      maskedPreview,
      decoyFilePath,
      plantedAt,
    };
  });
}

/**
 * Inspect live tool arguments / payload string in < 0.2 ms against salted HMAC-SHA256 canary registry.
 * On match:
 * 1) Writes `.sip/state/lockdown.json` (`active: true`, `CANARY_TRIPWIRE_TRIGGERED`).
 * 2) Revokes all active scoped leases via `revokeAllActiveLeases`.
 * 3) Returns `{ triggered: true, ... }` without leaking raw canary token.
 *
 * @param {{
 *   workspaceDir: string,
 *   rawPayloadStr: string,
 * }} params
 */
export async function inspectForCanaryTouch({ workspaceDir, rawPayloadStr }) {
  const t0 = performance.now();
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const canariesPath = path.join(sipDir, 'state', 'canaries.json');

  const canaries = readCanariesRegistry(canariesPath);
  if (canaries.length === 0 || !rawPayloadStr) {
    return {
      triggered: false,
      durationMs: Number((performance.now() - t0).toFixed(4)),
    };
  }

  const payload = String(rawPayloadStr);
  let matchedCanary = null;

  // 1. Check if payload directly references a planted decoy file (e.g. `cat .env.sip-canary`)
  for (const record of canaries) {
    if (record.decoyFile && payload.includes(record.decoyFile)) {
      matchedCanary = record;
      break;
    }
  }

  // 2. Extract candidate credential-shaped tokens and verify constant-time salted HMAC-SHA256
  if (!matchedCanary) {
    const tokenMatches = payload.match(/[A-Za-z0-9_-]{16,128}/g) || [];
    const uniqueCandidates = [...new Set(tokenMatches)];

    for (const candidate of uniqueCandidates) {
      for (const record of canaries) {
        if (record.tokenLength && candidate.length !== record.tokenLength) {
          continue;
        }
        try {
          const salt = unb64u(record.saltB64u);
          const expectedHmac = unb64u(record.hmacB64u);
          const actualHmac = crypto.createHmac('sha256', salt).update(candidate, 'utf8').digest();
          if (
            actualHmac.length === expectedHmac.length &&
            crypto.timingSafeEqual(actualHmac, expectedHmac)
          ) {
            matchedCanary = record;
            break;
          }
        } catch {
          // Ignore malformed entry
        }
      }
      if (matchedCanary) break;
    }
  }

  if (!matchedCanary) {
    return {
      triggered: false,
      durationMs: Number((performance.now() - t0).toFixed(4)),
    };
  }

  // Tripwire matched -> engage immediate workspace lockdown & revoke all active leases
  const lockdownPath = path.join(sipDir, 'state', 'lockdown.json');
  const triggeredAt = Date.now();
  const lockdownState = {
    active: true,
    reason: 'CANARY_TRIPWIRE_TRIGGERED',
    canaryId: matchedCanary.canaryId,
    kind: matchedCanary.kind,
    maskedPreview: matchedCanary.maskedPreview,
    triggeredAt,
  };

  await withPidLock(sipDir, () => {
    writeFileAtomic600(lockdownPath, JSON.stringify(lockdownState, null, 2) + '\n');
  });

  const leasesRevoked = await revokeAllActiveLeases({
    workspaceDir: resolvedWs,
    reason: 'CANARY_TRIPWIRE_TRIGGERED',
  });

  return {
    triggered: true,
    reason: 'CANARY_TRIPWIRE_TRIGGERED',
    canaryId: matchedCanary.canaryId,
    kind: matchedCanary.kind,
    maskedPreview: matchedCanary.maskedPreview,
    leasesRevoked,
    triggeredAt,
    durationMs: Number((performance.now() - t0).toFixed(4)),
  };
}

/**
 * Read current Canary Lockdown status for workspace.
 * @param {{ workspaceDir: string }} params
 */
export function getLockdownStatus({ workspaceDir }) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const lockdownPath = path.join(sipDir, 'state', 'lockdown.json');
  const canariesPath = path.join(sipDir, 'state', 'canaries.json');
  const canaries = readCanariesRegistry(canariesPath);

  if (!fs.existsSync(lockdownPath)) {
    return {
      active: false,
      reason: null,
      canaryCount: canaries.length,
      canaries: canaries.map((c) => ({
        canaryId: c.canaryId,
        kind: c.kind,
        maskedPreview: c.maskedPreview,
        decoyFile: c.decoyFile,
        plantedAt: c.plantedAt,
      })),
    };
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(lockdownPath, 'utf8'));
    return {
      active: Boolean(parsed?.active),
      reason: parsed?.reason || null,
      canaryId: parsed?.canaryId || null,
      kind: parsed?.kind || null,
      maskedPreview: parsed?.maskedPreview || null,
      triggeredAt: parsed?.triggeredAt || null,
      clearedAt: parsed?.clearedAt || null,
      canaryCount: canaries.length,
      canaries: canaries.map((c) => ({
        canaryId: c.canaryId,
        kind: c.kind,
        maskedPreview: c.maskedPreview,
        decoyFile: c.decoyFile,
        plantedAt: c.plantedAt,
      })),
    };
  } catch {
    return {
      active: true,
      reason: 'CORRUPTED_LOCKDOWN_STATE_FAIL_CLOSED',
      canaryCount: canaries.length,
      canaries: [],
    };
  }
}

/**
 * Explicitly lift Canary Honeytoken Lockdown (`sip1-mcp canary unlock`).
 * @param {{ workspaceDir: string }} params
 */
export async function clearLockdown({ workspaceDir }) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const lockdownPath = path.join(sipDir, 'state', 'lockdown.json');

  return withPidLock(sipDir, () => {
    const cleared = {
      active: false,
      reason: null,
      clearedAt: Date.now(),
    };
    writeFileAtomic600(lockdownPath, JSON.stringify(cleared, null, 2) + '\n');
    return cleared;
  });
}
