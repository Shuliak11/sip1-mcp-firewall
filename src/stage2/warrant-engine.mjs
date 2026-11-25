/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 2 One-Shot & 15-Min Scoped Ed25519 Capability Warrant Engine
 * Domain byte: 0x07 (`DOMAIN_PREFIX.WARRANT_ACTION`), Sign label: `"SIP-v3-WARRANT\0"`.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  unb64u,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import { withPidLock, writeFileAtomic600 } from '../core/workspace-io.mjs';
import { ACTION_TIERS, computeNormalizedActionDigest } from './blast-radius-guard.mjs';

export const WARRANT_SIGN_LABEL = 'SIP-v3-WARRANT\0';
const WARRANT_TOKEN_PREFIX = 'sipw3';

/**
 * Load or initialize `.sip/state/warrants-ledger.json`.
 * @param {string} ledgerPath
 */
function readWarrantsLedger(ledgerPath) {
  if (!fs.existsSync(ledgerPath)) {
    return { consumedJtis: {}, leases: {} };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
    return {
      consumedJtis:
        parsed && typeof parsed.consumedJtis === 'object' && parsed.consumedJtis
          ? parsed.consumedJtis
          : {},
      leases:
        parsed && typeof parsed.leases === 'object' && parsed.leases ? parsed.leases : {},
    };
  } catch {
    return { consumedJtis: {}, leases: {} };
  }
}

/**
 * Check if workspace is currently under Canary Honeytoken Lockdown without circular import.
 * @param {string} sipDir
 * @returns {boolean}
 */
function checkLockdownFileActive(sipDir) {
  const lockdownPath = path.join(sipDir, 'state', 'lockdown.json');
  if (!fs.existsSync(lockdownPath)) return false;
  try {
    const data = JSON.parse(fs.readFileSync(lockdownPath, 'utf8'));
    return Boolean(data?.active);
  } catch {
    return true; // Fail-closed if lockdown state file is corrupted
  }
}

/**
 * Encode signed warrant payload + signature into a compact `sipw3.<payloadB64u>.<sigB64u>` token.
 * @param {Record<string, any>} payload
 * @param {string} sigB64u
 * @returns {string}
 */
export function encodeWarrantToken(payload, sigB64u) {
  const payloadBytes = jcsCanonicalize(payload);
  return `${WARRANT_TOKEN_PREFIX}.${b64u(payloadBytes)}.${sigB64u}`;
}

/**
 * Decode a `sipw3.<payloadB64u>.<sigB64u>` token string.
 * @param {string} token
 * @returns {{ payload: Record<string, any>, signatureB64u: string } | null}
 */
export function decodeWarrantToken(token) {
  if (typeof token !== 'string' || !token.startsWith(`${WARRANT_TOKEN_PREFIX}.`)) {
    return null;
  }
  const parts = token.trim().split('.');
  if (parts.length !== 3) return null;
  try {
    const payloadJson = unb64u(parts[1]).toString('utf8');
    const payload = JSON.parse(payloadJson);
    return { payload, signatureB64u: parts[2] };
  } catch {
    return null;
  }
}

/**
 * Issue a signed One-Shot `Ed25519` Warrant bound to the exact `{ server, tool, args }` 0x07 JCS digest.
 *
 * @param {{
 *   workspaceDir: string,
 *   server: string,
 *   tool: string,
 *   args: unknown,
 *   ttlSeconds?: number,
 *   reason?: string,
 * }} params
 */
export function issueOneShotWarrant({
  workspaceDir,
  server,
  tool,
  args,
  ttlSeconds = 60,
  reason = 'Operator one-shot approval',
}) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const keyInfo = ensureDeviceEd25519Keypair(sipDir);

  const now = Date.now();
  const actionDigest = computeNormalizedActionDigest({ server, tool, args });
  const jti = 'wrt_' + b64u(crypto.randomBytes(16));

  const payload = {
    actionDigest,
    expiresAt: now + Math.round(Number(ttlSeconds) * 1000),
    issuedAt: now,
    jti,
    keyId: keyInfo.keyId,
    mode: 'ONE_SHOT',
    reason: String(reason || ''),
    server: String(server),
    tool: String(tool),
    v: 'sip-warrant/3.0',
  };

  const digestBuf = domainSha256(DOMAIN_PREFIX.WARRANT_ACTION, jcsCanonicalize(payload));
  const signatureB64u = signDomainPayload(WARRANT_SIGN_LABEL, digestBuf, keyInfo.privateKey);
  const token = encodeWarrantToken(payload, signatureB64u);

  return {
    token,
    jti,
    warrant: payload,
    signatureB64u,
    publicKeyB64u: keyInfo.publicKeyB64u,
  };
}

/**
 * Issue a 15-minute (default 900s) Scoped `Ed25519` Developer Capability Lease
 * bounded by `server`, `allowedTools`, `pathPrefix`, `maxCalls`, and `ttlSeconds`.
 *
 * @param {{
 *   workspaceDir: string,
 *   server: string,
 *   allowedTools?: string[],
 *   pathPrefix?: string,
 *   maxCalls?: number,
 *   ttlSeconds?: number,
 *   reason?: string,
 * }} params
 */
export async function issueScopedLease({
  workspaceDir,
  server,
  allowedTools = ['*'],
  pathPrefix = '',
  maxCalls = 10,
  ttlSeconds = 900,
  reason = 'Scoped developer migration lease',
}) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const ledgerPath = path.join(sipDir, 'state', 'warrants-ledger.json');

  return withPidLock(sipDir, () => {
    const keyInfo = ensureDeviceEd25519Keypair(sipDir);
    const now = Date.now();
    const jti = 'lse_' + b64u(crypto.randomBytes(16));
    const normalizedTools = Array.isArray(allowedTools)
      ? allowedTools.map(String)
      : [String(allowedTools)];

    const payload = {
      allowedTools: normalizedTools,
      expiresAt: now + Math.round(Number(ttlSeconds) * 1000),
      issuedAt: now,
      jti,
      keyId: keyInfo.keyId,
      maxCalls: Math.max(1, Math.floor(Number(maxCalls))),
      mode: 'SCOPED_LEASE',
      pathPrefix: String(pathPrefix || ''),
      reason: String(reason || ''),
      server: String(server),
      v: 'sip-warrant/3.0',
    };

    const digestBuf = domainSha256(DOMAIN_PREFIX.WARRANT_ACTION, jcsCanonicalize(payload));
    const signatureB64u = signDomainPayload(WARRANT_SIGN_LABEL, digestBuf, keyInfo.privateKey);
    const token = encodeWarrantToken(payload, signatureB64u);

    const ledger = readWarrantsLedger(ledgerPath);
    ledger.leases[jti] = {
      leaseId: jti,
      token,
      payload,
      signatureB64u,
      remainingCalls: payload.maxCalls,
      revoked: false,
      createdAt: now,
    };
    writeFileAtomic600(ledgerPath, JSON.stringify(ledger, null, 2) + '\n');

    return {
      token,
      leaseId: jti,
      warrant: payload,
      signatureB64u,
      remainingCalls: payload.maxCalls,
      publicKeyB64u: keyInfo.publicKeyB64u,
    };
  });
}

/**
 * Check if all path-like arguments inside `args` conform to `pathPrefix` when specified.
 * @param {unknown} args
 * @param {string} pathPrefix
 * @returns {boolean}
 */
function argsMatchPathPrefix(args, pathPrefix) {
  if (!pathPrefix) return true;
  const normPrefix = pathPrefix.replace(/\\/g, '/').replace(/\/+$/, '');
  if (!args || typeof args !== 'object') return true;

  for (const [k, v] of Object.entries(args)) {
    if (/^(?:path|file_?path|filepath|target_?path|target|dest|destination)$/i.test(k) && typeof v === 'string') {
      const normVal = v.replace(/\\/g, '/');
      if (normVal !== normPrefix && !normVal.startsWith(normPrefix + '/')) {
        return false;
      }
    }
  }
  return true;
}

/**
 * Verify and atomically consume a One-Shot Warrant or Scoped Lease.
 * - Immediately rejects `TIER_3_UNCONDITIONAL_BLOCK` and Canary Lockdown workspaces.
 * - Enforces atomic replay prevention (`REPLAY_BLOCKED`) and `remainingCalls` decrement.
 *
 * @param {{
 *   workspaceDir: string,
 *   tokenOrLeaseId?: string | null,
 *   server: string,
 *   tool: string,
 *   args: unknown,
 *   tier: string,
 * }} params
 */
export async function verifyAndConsumeWarrant({
  workspaceDir,
  tokenOrLeaseId,
  server,
  tool,
  args,
  tier,
}) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const ledgerPath = path.join(sipDir, 'state', 'warrants-ledger.json');

  // 1. TIER_3 is NEVER overridable
  if (tier === ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK) {
    return {
      allowed: false,
      code: 'TIER_3_NON_OVERRIDABLE',
      reason: 'TIER_3 unconditional security blocks cannot be overridden by any warrant or lease',
    };
  }

  // 2. Reject immediately if workspace is in Canary Lockdown
  if (checkLockdownFileActive(sipDir)) {
    return {
      allowed: false,
      code: 'WORKSPACE_LOCKDOWN_ACTIVE',
      reason: 'Workspace is locked down due to Canary Honeytoken tripwire; warrants are suspended',
    };
  }

  return withPidLock(sipDir, () => {
    const keyInfo = ensureDeviceEd25519Keypair(sipDir);
    const ledger = readWarrantsLedger(ledgerPath);
    const now = Date.now();

    let resolvedCandidate = null;
    if (tokenOrLeaseId && typeof tokenOrLeaseId === 'string' && tokenOrLeaseId.trim()) {
      const trimmed = tokenOrLeaseId.trim();
      if (trimmed.startsWith(`${WARRANT_TOKEN_PREFIX}.`)) {
        resolvedCandidate = decodeWarrantToken(trimmed);
        if (!resolvedCandidate) {
          return {
            allowed: false,
            code: 'MALFORMED_WARRANT_TOKEN',
            reason: 'Malformed sipw3 warrant token structure',
          };
        }
      } else if (ledger.leases[trimmed]) {
        const stored = ledger.leases[trimmed];
        resolvedCandidate = {
          payload: stored.payload,
          signatureB64u: stored.signatureB64u,
        };
      } else {
        return {
          allowed: false,
          code: 'UNKNOWN_LEASE_ID',
          reason: `Warrant or lease "${trimmed}" not found in workspace ledger`,
        };
      }
    } else {
      // Auto-discover an active, matching SCOPED_LEASE in workspace ledger if no explicit token passed
      let fallbackCandidate = null;
      for (const stored of Object.values(ledger.leases)) {
        const p = stored.payload;
        const scopeMatches =
          (p.server === '*' || p.server === String(server)) &&
          Array.isArray(p.allowedTools) &&
          (p.allowedTools.includes('*') || p.allowedTools.includes(String(tool))) &&
          argsMatchPathPrefix(args, p.pathPrefix);
        if (!scopeMatches) continue;

        if (!stored.revoked && stored.remainingCalls > 0 && now <= p.expiresAt) {
          resolvedCandidate = {
            payload: p,
            signatureB64u: stored.signatureB64u,
          };
          break;
        }
        fallbackCandidate = {
          payload: p,
          signatureB64u: stored.signatureB64u,
        };
      }

      if (!resolvedCandidate) {
        resolvedCandidate = fallbackCandidate;
      }

      if (!resolvedCandidate) {
        return {
          allowed: false,
          code: 'WARRANT_MISSING',
          reason: 'TIER_2 destructive action requires a signed Ed25519 Warrant or active Scoped Lease',
        };
      }
    }

    const { payload, signatureB64u } = resolvedCandidate;
    if (!payload || typeof payload !== 'object' || payload.v !== 'sip-warrant/3.0') {
      return {
        allowed: false,
        code: 'INVALID_WARRANT_SCHEMA',
        reason: 'Unsupported warrant schema version',
      };
    }

    // Cryptographically verify Ed25519 signature over 0x07 JCS digest
    const digestBuf = domainSha256(DOMAIN_PREFIX.WARRANT_ACTION, jcsCanonicalize(payload));
    const sigOk = verifyDomainPayload(
      WARRANT_SIGN_LABEL,
      digestBuf,
      signatureB64u,
      keyInfo.publicKeyB64u
    );
    if (!sigOk) {
      return {
        allowed: false,
        code: 'INVALID_WARRANT_SIGNATURE',
        reason: 'Ed25519 signature verification failed on warrant token',
      };
    }

    if (now > Number(payload.expiresAt)) {
      return {
        allowed: false,
        code: 'WARRANT_EXPIRED',
        reason: `Warrant ${payload.jti} expired at ${new Date(payload.expiresAt).toISOString()}`,
      };
    }

    if (payload.mode === 'ONE_SHOT') {
      if (ledger.consumedJtis[payload.jti]) {
        return {
          allowed: false,
          code: 'REPLAY_BLOCKED',
          reason: `Replay attack blocked: One-shot warrant ${payload.jti} was already consumed`,
        };
      }

      const expectedActionDigest = computeNormalizedActionDigest({ server, tool, args });
      if (
        payload.server !== String(server) ||
        payload.tool !== String(tool) ||
        payload.actionDigest !== expectedActionDigest
      ) {
        return {
          allowed: false,
          code: 'ACTION_DIGEST_MISMATCH',
          reason: 'Warrant parameter mismatch: live { server, tool, args } 0x07 digest differs from signed warrant',
        };
      }

      ledger.consumedJtis[payload.jti] = {
        consumedAt: now,
        actionDigest: expectedActionDigest,
      };
      writeFileAtomic600(ledgerPath, JSON.stringify(ledger, null, 2) + '\n');

      return {
        allowed: true,
        code: 'ONE_SHOT_CONSUMED',
        mode: 'ONE_SHOT',
        jti: payload.jti,
        remainingCalls: 0,
      };
    }

    if (payload.mode === 'SCOPED_LEASE') {
      if (!ledger.leases[payload.jti]) {
        ledger.leases[payload.jti] = {
          leaseId: payload.jti,
          payload,
          signatureB64u,
          remainingCalls: Number(payload.maxCalls),
          revoked: false,
          createdAt: payload.issuedAt,
        };
      }

      const leaseState = ledger.leases[payload.jti];
      if (leaseState.revoked) {
        return {
          allowed: false,
          code: 'LEASE_REVOKED',
          reason: `Scoped lease ${payload.jti} was revoked`,
        };
      }

      if (payload.server !== '*' && payload.server !== String(server)) {
        return {
          allowed: false,
          code: 'LEASE_SCOPE_MISMATCH',
          reason: `Scoped lease server "${payload.server}" does not permit "${server}"`,
        };
      }

      const allowedTools = Array.isArray(payload.allowedTools) ? payload.allowedTools : [];
      if (!allowedTools.includes('*') && !allowedTools.includes(String(tool))) {
        return {
          allowed: false,
          code: 'LEASE_TOOL_MISMATCH',
          reason: `Scoped lease allowedTools [${allowedTools.join(', ')}] does not permit "${tool}"`,
        };
      }

      if (!argsMatchPathPrefix(args, payload.pathPrefix)) {
        return {
          allowed: false,
          code: 'LEASE_PATH_MISMATCH',
          reason: `Tool arguments fall outside scoped lease pathPrefix "${payload.pathPrefix}"`,
        };
      }

      if (leaseState.remainingCalls <= 0) {
        return {
          allowed: false,
          code: 'LEASE_CALLS_EXHAUSTED',
          reason: `Scoped lease ${payload.jti} has 0 remaining calls (maxCalls=${payload.maxCalls} exhausted)`,
        };
      }

      leaseState.remainingCalls -= 1;
      leaseState.lastUsedAt = now;
      writeFileAtomic600(ledgerPath, JSON.stringify(ledger, null, 2) + '\n');

      return {
        allowed: true,
        code: 'LEASE_CALL_CONSUMED',
        mode: 'SCOPED_LEASE',
        jti: payload.jti,
        remainingCalls: leaseState.remainingCalls,
      };
    }

    return {
      allowed: false,
      code: 'UNKNOWN_WARRANT_MODE',
      reason: `Unknown warrant mode "${payload.mode}"`,
    };
  });
}

/**
 * Revoke all active scoped leases in `.sip/state/warrants-ledger.json` (invoked by Canary Lockdown).
 * @param {{ workspaceDir: string, reason?: string }} params
 */
export async function revokeAllActiveLeases({ workspaceDir, reason = 'CANARY_LOCKDOWN' }) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const ledgerPath = path.join(sipDir, 'state', 'warrants-ledger.json');
  if (!fs.existsSync(ledgerPath)) return 0;

  return withPidLock(sipDir, () => {
    const ledger = readWarrantsLedger(ledgerPath);
    let revokedCount = 0;
    for (const lease of Object.values(ledger.leases)) {
      if (!lease.revoked) {
        lease.revoked = true;
        lease.revokedReason = reason;
        lease.revokedAt = Date.now();
        revokedCount++;
      }
    }
    writeFileAtomic600(ledgerPath, JSON.stringify(ledger, null, 2) + '\n');
    return revokedCount;
  });
}
