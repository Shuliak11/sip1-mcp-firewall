import __sipLaFs from 'node:fs';
import __sipLaPath from 'node:path';
import { ensureDeviceEd25519Keypair as __sipEnsureKp } from '../core/crypto-primitives.mjs';
let __sipEnvActivating = false;
function __sipGetCustodianPub(opts) {
  const dir = __sipLaPath.resolve((opts && typeof opts === 'object' ? (opts.workspaceDir || opts.dir) : opts) || process.cwd());
  if (process.env.SIP_CUSTODIAN_PRIVATE_KEY_PEM?.trim()) {
    try { return __sipEnsureKp(dir).publicKeyB64u; } catch {}
  }
  try {
    const p = __sipLaPath.join(dir, '.sip', 'device.ed25519.pub');
    if (__sipLaFs.existsSync(p)) return __sipLaFs.readFileSync(p, 'utf8').trim() || null;
  } catch {}
  return null;
}
/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 4 Unforgeable Two-Tier Ed25519 Commercial Authority & Channel Partner Attribution
 * Zero external dependencies. Built strictly on node:crypto, node:fs, node:path.
 *
 * Security Invariant:
 * - Commercial authority (`COMPLIANCE` / `ENTERPRISE`) is cryptographically anchored to the
 *   offline SHULIAK CORP Root Ed25519 Public Key (`SHULIAK_ROOT_PUB_B64U`) over RFC 8785 JCS
 *   with domain prefix `0x09` and signing label `"SIP-v3-ROOT-LIC\0"`.
 * - Even if an attacker modifies local JavaScript to set `authority_status = "COUNTERSIGNED_COMMERCIAL"`,
 *   offline verifiers reject the certificate/PDF (`FORGED_COMMERCIAL_AUTHORITY`) without a valid
 *   Root-signed `SIP3.<TIER>.<PAYLOAD_B64U>.<ROOT_SIG_B64U>` token.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  exportEd25519RawPublic,
  signDomainPayload,
  unb64u,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import { withPidLock, writeFileAtomic600 } from '../core/workspace-io.mjs';

/**
 * Canonical SHULIAK CORP Offline Root Authority Ed25519 Public Key (32-byte raw SPKI key in base64url).
 * Private key is held strictly in offline HSM / billing webhook signer.
 */
export const SHULIAK_ROOT_PUB_B64U = 'AZ9wSMieP72MvUUTcxHaCE0ssL0eLXENyRgKRvPV7Qg';

/**
 * Resolve default Root Authority Ed25519 public key.
 * Strictly returns pinned `SHULIAK_ROOT_PUB_B64U` in production; honors
 * `process.env.SHULIAK_ROOT_PUB_B64U` ONLY when `SHULIAK_ALLOW_TEST_ROOT_OVERRIDE === '1'`.
 * @returns {string}
 */
export function resolveDefaultAuthorityPubB64u() {
  if (
    process.env.SHULIAK_ALLOW_TEST_ROOT_OVERRIDE === '1' &&
    typeof process.env.SHULIAK_ROOT_PUB_B64U === 'string' &&
    process.env.SHULIAK_ROOT_PUB_B64U.trim().length > 0
  ) {
    return process.env.SHULIAK_ROOT_PUB_B64U.trim();
  }
  return SHULIAK_ROOT_PUB_B64U;
}

export const DOMAIN_PREFIX_ROOT_LICENSE = 0x09;
export const ROOT_LICENSE_SIGN_LABEL = 'SIP-v3-ROOT-LIC\0';

export const COMMERCIAL_TIERS = Object.freeze({
  PRO_SECOPS: 'PRO_SECOPS',
  COMPLIANCE: 'COMPLIANCE',
  ENTERPRISE: 'ENTERPRISE',
});

export const TIER_SEAT_DEFAULTS = Object.freeze({
  COMMUNITY_FREE: 1,
  PRO_SECOPS: 5,
  COMPLIANCE: 25,
  ENTERPRISE: 250,
});

export function getTierCapabilities(tier) {
  const t = String(tier || 'COMMUNITY_FREE');
  if (t === 'ENTERPRISE') {
    return Object.freeze({
      defaultMaxSeats: 250,
      signedCiReceipt: true,
      teamPolicy: true,
      commercialAttestation: true,
      sectorTemplates: true,
      mdmFleet: true,
      hardwareBinding: true,
    });
  }
  if (t === 'COMPLIANCE') {
    return Object.freeze({
      defaultMaxSeats: 25,
      signedCiReceipt: true,
      teamPolicy: true,
      commercialAttestation: true,
      sectorTemplates: true,
      mdmFleet: false,
      hardwareBinding: false,
    });
  }
  if (t === 'PRO_SECOPS') {
    return Object.freeze({
      defaultMaxSeats: 5,
      signedCiReceipt: true,
      teamPolicy: true,
      commercialAttestation: false,
      sectorTemplates: false,
      mdmFleet: false,
      hardwareBinding: false,
    });
  }
  return Object.freeze({
    defaultMaxSeats: 1,
    signedCiReceipt: false,
    teamPolicy: false,
    commercialAttestation: false,
    sectorTemplates: false,
    mdmFleet: false,
    hardwareBinding: false,
  });
}

export function evaluateSeatRoster({
  workspaceDir,
  licenseId,
  tier,
  maxSeats,
  custodianPubB64u,
  rosterPath = null,
  register = false,
}) {
  const resolvedDir = path.resolve(
    workspaceDir || process.cwd()
  );
  const rp = rosterPath
    ? path.resolve(rosterPath)
    : path.join(resolvedDir, '.sip', 'seat-roster.json');
  const defCap = TIER_SEAT_DEFAULTS[tier] || 25;
  const cap = Number.isInteger(maxSeats) && maxSeats > 0
    ? maxSeats : defCap;
  let roster = { v: 'sip-seat-roster/3.1', licenses: {} };
  if (fs.existsSync(rp)) {
    try {
      const parsed = JSON.parse(
        fs.readFileSync(rp, 'utf8')
      );
      if (parsed && typeof parsed.licenses === 'object') {
        roster = parsed;
      }
    } catch {}
  }
  const lid = String(licenseId || 'default');
  const entry = roster.licenses[lid] || {
    tier, maxSeats: cap, seats: {},
  };
  const seats = entry.seats && typeof entry.seats ===
    'object' ? entry.seats : {};
  const pub = custodianPubB64u
    ? String(custodianPubB64u).trim() : '';
  const existingCount = Object.keys(seats).length;
  const alreadyIn = Boolean(pub && seats[pub]);
  const projectedCount = (!pub || alreadyIn)
    ? existingCount : existingCount + 1;
  if (projectedCount > cap) {
    return {
      allowed: false,
      status: 'SEAT_CAP_EXCEEDED',
      seatsUsed: existingCount,
      maxSeats: cap,
      rosterPath: rp,
      reason: `Seat cap exceeded for ${lid}: ` +
        `${projectedCount} > ${cap} (${tier})`,
    };
  }
  if (register && pub) {
    const nowIso = new Date().toISOString();
    seats[pub] = {
      firstSeenAt: seats[pub]?.firstSeenAt || nowIso,
      lastSeenAt: nowIso,
    };
    roster.licenses[lid] = {
      tier, maxSeats: cap, seats,
    };
    writeFileAtomic600(
      rp, JSON.stringify(roster, null, 2) + '\n'
    );
  }
  return {
    allowed: true,
    status: 'SEAT_OK',
    seatsUsed: register && pub
      ? Object.keys(seats).length : existingCount,
    maxSeats: cap,
    rosterPath: rp,
  };
}

const VALID_TIER_SET = new Set(Object.values(COMMERCIAL_TIERS));

/**
 * Generate a fresh Ed25519 Root Authority keypair (used by SHULIAK billing webhook & deterministic unit tests).
 */
export function generateAuthorityKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = exportEd25519RawPublic(publicKey);
  const publicKeyB64u = b64u(rawPub);
  const privateKeyPem = String(privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const keyId = b64u(domainSha256(DOMAIN_PREFIX_ROOT_LICENSE, rawPub)).slice(0, 16);
  return {
    privateKey,
    publicKey,
    publicKeyB64u,
    privateKeyPem,
    keyId,
  };
}

/**
 * Mint a Root-signed commercial license token:
 * `SIP3.<TIER>.<PAYLOAD_B64U>.<ROOT_SIG_B64U>`
 *
 * @param {{
 *   authorityPrivateKey: crypto.KeyObject | string,
 *   tier?: 'PRO_SECOPS' | 'COMPLIANCE' | 'ENTERPRISE',
 *   licenseId?: string,
 *   orgName: string,
 *   orgDomain: string,
 *   maxSeats?: number,
 *   partnerCode?: string | null,
 *   partnerName?: string | null,
 *   issuedAt?: string,
 *   expiresAt?: string,
 *   boundCustodianPubB64u?: string | null,
 * }} params
 */
export function issueCommercialLicenseToken({
  authorityPrivateKey,
  tier = 'COMPLIANCE',
  licenseId = `lic_${crypto.randomBytes(6).toString('hex')}`,
  orgName,
  orgDomain,
  maxSeats = null,
  partnerCode = null,
  partnerName = null,
  issuedAt = new Date().toISOString(),
  expiresAt = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
  boundCustodianPubB64u = null,
}) {
  if (!authorityPrivateKey) {
    throw new Error('authorityPrivateKey is required to mint a SIP3 commercial token');
  }
  if (!VALID_TIER_SET.has(tier)) {
    throw new Error(`Invalid commercial tier "${tier}". Expected PRO_SECOPS, COMPLIANCE, or ENTERPRISE.`);
  }
  if (!orgName || typeof orgName !== 'string') {
    throw new Error('orgName is required for commercial license issuance');
  }
  if (!orgDomain || typeof orgDomain !== 'string') {
    throw new Error('orgDomain is required for commercial license issuance');
  }

  const payload = {
    boundCustodianPubB64u: boundCustodianPubB64u ? String(boundCustodianPubB64u).trim() : null,
    expiresAt: String(expiresAt),
    issuedAt: String(issuedAt),
    licenseId: String(licenseId),
    maxSeats: Number.isInteger(maxSeats) && maxSeats > 0 ? maxSeats : (TIER_SEAT_DEFAULTS[tier] || 25),
    orgDomain: String(orgDomain).trim().toLowerCase(),
    orgName: String(orgName).trim(),
    partnerCode: partnerCode ? String(partnerCode).trim() : null,
    partnerName: partnerName ? String(partnerName).trim() : null,
    tier,
    v: 'sip-lic/3.0',
  };

  const canonicalBytes = jcsCanonicalize(payload);
  const digestBuf = domainSha256(DOMAIN_PREFIX_ROOT_LICENSE, canonicalBytes);
  const rootSigB64u = signDomainPayload(ROOT_LICENSE_SIGN_LABEL, digestBuf, authorityPrivateKey);
  const payloadB64u = b64u(canonicalBytes);
  const token = `SIP3.${tier}.${payloadB64u}.${rootSigB64u}`;

  return {
    token,
    tier,
    payload,
    payloadDigestB64u: b64u(digestBuf),
    rootSignatureB64u: rootSigB64u,
  };
}

/**
 * Verify a `SIP3.<TIER>.<PAYLOAD_B64U>.<ROOT_SIG_B64U>` license token offline against the
 * SHULIAK CORP Root Ed25519 Public Key (or explicit test override).
 *
 * @param {{
 *   tokenStr: string,
 *   authorityPubB64u?: string,
 *   expectedCustodianPubB64u?: string | null,
 *   nowMs?: number,
 * }} params
 */
export const CLOCK_SKEW_LEEWAY_MS = 300_000;

export function verifyCommercialLicenseToken({
  tokenStr,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
  expectedCustodianPubB64u = null,
  nowMs = Date.now(),
}) {
  const effectiveAuthorityPub = authorityPubB64u || resolveDefaultAuthorityPubB64u();

  if (typeof tokenStr === 'string') {
    tokenStr = tokenStr
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
  }
  if (typeof tokenStr !== 'string' || !tokenStr.trim()) {
    return {
      valid: false,
      status: 'MISSING_LICENSE_TOKEN',
      isAttestationEligible: false,
      tier: 'COMMUNITY_FREE',
      reason: 'Commercial license token is empty or missing',
      payload: null,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  const parts = tokenStr.trim().split('.');
  if (parts.length !== 4 || parts[0] !== 'SIP3') {
    return {
      valid: false,
      status: 'MALFORMED_LICENSE_TOKEN',
      isAttestationEligible: false,
      tier: 'COMMUNITY_FREE',
      reason: 'Expected 4-part token format SIP3.<TIER>.<PAYLOAD_B64U>.<ROOT_SIG_B64U>',
      payload: null,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  const [, headerTier, payloadB64u, rootSigB64u] = parts;
  if (!VALID_TIER_SET.has(headerTier)) {
    return {
      valid: false,
      status: 'MALFORMED_LICENSE_TOKEN',
      isAttestationEligible: false,
      tier: 'COMMUNITY_FREE',
      reason: `Unsupported commercial tier "${headerTier}" in token header`,
      payload: null,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  let payload;
  try {
    const rawBytes = unb64u(payloadB64u);
    payload = JSON.parse(rawBytes.toString('utf8'));
  } catch (err) {
    return {
      valid: false,
      status: 'MALFORMED_LICENSE_TOKEN',
      isAttestationEligible: false,
      tier: 'COMMUNITY_FREE',
      reason: `Failed to decode license payload: ${err instanceof Error ? err.message : String(err)}`,
      payload: null,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  if (
    !payload ||
    typeof payload !== 'object' ||
    payload.v !== 'sip-lic/3.0' ||
    payload.tier !== headerTier ||
    typeof payload.licenseId !== 'string' ||
    typeof payload.orgName !== 'string' ||
    typeof payload.orgDomain !== 'string' ||
    typeof payload.expiresAt !== 'string'
  ) {
    return {
      valid: false,
      status: 'MALFORMED_LICENSE_TOKEN',
      isAttestationEligible: false,
      tier: 'COMMUNITY_FREE',
      reason: 'License payload schema v="sip-lic/3.0" validation failed or tier mismatch',
      payload: null,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  const canonicalBytes = jcsCanonicalize(payload);
  const digestBuf = domainSha256(DOMAIN_PREFIX_ROOT_LICENSE, canonicalBytes);
  const sigValid = verifyDomainPayload(
    ROOT_LICENSE_SIGN_LABEL,
    digestBuf,
    rootSigB64u,
    effectiveAuthorityPub
  );

  if (!sigValid) {
    return {
      valid: false,
      status: 'FORGED_COMMERCIAL_AUTHORITY',
      isAttestationEligible: false,
      tier: 'COMMUNITY_FREE',
      reason: 'Root Authority Ed25519 signature verification failed (untrusted or tampered license)',
      payload,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  const issTime = Date.parse(
    payload.issuedAt || ''
  );
  if (Number.isFinite(issTime) && issTime > nowMs + CLOCK_SKEW_LEEWAY_MS) {
    return {
      valid: false,
      status: 'LICENSE_NOT_YET_VALID',
      isAttestationEligible: false,
      tier: payload.tier,
      reason: 'issuedAt exceeds clock skew',
      payload,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }
  const expTime = Date.parse(payload.expiresAt);
  if (!Number.isFinite(expTime) || expTime <= nowMs) {
    return {
      valid: false,
      status: 'LICENSE_EXPIRED',
      isAttestationEligible: false,
      tier: payload.tier,
      reason: `Commercial license expired at ${payload.expiresAt}`,
      payload,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  if (
    payload.boundCustodianPubB64u &&
    expectedCustodianPubB64u &&
    payload.boundCustodianPubB64u !== expectedCustodianPubB64u
  ) {
    return {
      valid: false,
      status: 'CUSTODIAN_KEY_MISMATCH',
      isAttestationEligible: false,
      tier: payload.tier,
      reason: 'License token is cryptographically bound to a different workspace Custodian Ed25519 key',
      payload,
      authorityPubB64u: effectiveAuthorityPub,
    };
  }

  const isAttestationEligible =
    payload.tier === COMMERCIAL_TIERS.COMPLIANCE || payload.tier === COMMERCIAL_TIERS.ENTERPRISE;

  return {
    valid: true,
    status: 'ACTIVE_LICENSED',
    isAttestationEligible,
    tier: payload.tier,
    capabilities: getTierCapabilities(payload.tier),
    reason: `Verified SHULIAK Root Ed25519 ${payload.tier} entitlement for ${payload.orgName}`,
    payload,
    tokenStr: tokenStr.trim(),
    payloadDigestB64u: b64u(digestBuf),
    rootSignatureB64u: rootSigB64u,
    authorityPubB64u: effectiveAuthorityPub,
  };
}

/**
 * Activate and persist a verified commercial license inside `<workspaceDir>/.sip/license.json` (`0o600`).
 * Rejects forged, tampered, expired, or mismatched custodian tokens fail-closed.
 *
 * @param {{
 *   workspaceDir: string,
 *   tokenStr: string,
 *   authorityPubB64u?: string,
 * }} params
 */
export async function activateWorkspaceLicense(options = {}, ...rest) { __sipGetCustodianPub(options); return __sipOrigAct(options, ...rest); }
function __sipOrigAct({
  workspaceDir,
  tokenStr,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
  rosterPath = null,
}) {
  const resolvedDir = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedDir, '.sip');

  return withPidLock(sipDir, () => {
    const custodian = ensureDeviceEd25519Keypair(sipDir, { ephemeralOnly: false });
    const verification = verifyCommercialLicenseToken({
      tokenStr,
      authorityPubB64u,
      expectedCustodianPubB64u: custodian.publicKeyB64u,
    });

    if (!verification.valid) {
      const err = /** @type {Error & { code?: string }} */ (
        new Error(`[${verification.status}] ${verification.reason}`)
      );
      err.code = verification.status;
      throw err;
    }

    const seatCheck = evaluateSeatRoster({
      workspaceDir: resolvedDir,
      licenseId: verification.payload.licenseId,
      tier: verification.tier,
      maxSeats: verification.payload.maxSeats,
      custodianPubB64u: custodian.publicKeyB64u,
      rosterPath,
      register: true,
    });
    if (!seatCheck.allowed) {
      const err = new Error(
        `[SEAT_CAP_EXCEEDED] ${seatCheck.reason}`
      );
      err.code = 'SEAT_CAP_EXCEEDED';
      throw err;
    }
    const licensePath = path.join(sipDir, 'license.json');
    const record = {
      activatedAt: new Date().toISOString(),
      custodianKeyId: custodian.keyId,
      custodianPubB64u: custodian.publicKeyB64u,
      licenseId: verification.payload.licenseId,
      orgDomain: verification.payload.orgDomain,
      orgName: verification.payload.orgName,
      partnerCode: verification.payload.partnerCode,
      partnerName: verification.payload.partnerName,
      tier: verification.tier,
      token: verification.tokenStr,
    };
    writeFileAtomic600(licensePath, JSON.stringify(record, null, 2) + '\n');

    return {
      activated: true,
      licensePath,
      verification,
    };
  });
}

/**
 * Inspect current workspace commercial entitlement without mutating disk.
 * Always re-verifies the stored `SIP3...` token against `authorityPubB64u` so editing
 * `.sip/license.json` fields on disk CANNOT forge commercial status!
 *
 * @param {{
 *   workspaceDir: string,
 *   authorityPubB64u?: string,
 *   nowMs?: number,
 * }} params
 */
export function inspectWorkspaceEntitlement(options = {}, ...rest) {
  const __cp = __sipGetCustodianPub(options);
  const __r = __sipOrigInspect(options, ...rest);
  if (__r && typeof __r === 'object' && !__r.custodianPubB64u) {
    if (Object.isFrozen(__r)) return Object.freeze({ ...__r, custodianPubB64u: __cp });
    __r.custodianPubB64u = __cp;
  }
  return __r;
}
function __sipOrigInspect({
  workspaceDir,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
  nowMs = Date.now(),
  rosterPath = null,
}) {
  const resolvedDir = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedDir, '.sip');
  const licensePath = path.join(sipDir, 'license.json');
  const pubPath = path.join(sipDir, 'device.ed25519.pub');

  const expectedCustodianPub = fs.existsSync(pubPath)
    ? fs.readFileSync(pubPath, 'utf8').trim() || null
    : null;

  const __rawEnvLic =
    process.env.SIP_LICENSE_KEY ||
    process.env.SIP_LICENSE_TOKEN ||
    process.env.SHULIAK_LICENSE_TOKEN || '';
  let candidateToken = __rawEnvLic.trim()
    ? __rawEnvLic.trim() : null;

  if (!candidateToken && fs.existsSync(licensePath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(licensePath, 'utf8'));
      candidateToken = typeof parsed?.token === 'string' ? parsed.token.trim() : null;
      if (!candidateToken) {
        return {
          active: false,
          valid: false,
          status: 'FORGED_COMMERCIAL_AUTHORITY',
          tier: 'COMMUNITY_FREE',
          isAttestationEligible: false,
          reason: '.sip/license.json exists without a valid SIP3 Root-signed token string',
          payload: null,
          tokenStr: null,
          licensePath,
        };
      }
    } catch (err) {
      return {
        active: false,
        valid: false,
        status: 'MALFORMED_LICENSE_FILE',
        tier: 'COMMUNITY_FREE',
        isAttestationEligible: false,
        reason: `Corrupt .sip/license.json: ${err instanceof Error ? err.message : String(err)}`,
        payload: null,
        tokenStr: null,
        licensePath,
      };
    }
  }

  if (!candidateToken) {
    return {
      active: false,
      valid: false,
      status: 'COMMUNITY_UNLICENSED',
      tier: 'COMMUNITY_FREE',
      isAttestationEligible: false,
      reason: 'No commercial license active (Community Apache-2.0 tier)',
      payload: null,
      tokenStr: null,
      licensePath,
    };
  }

  const ver = verifyCommercialLicenseToken({
    tokenStr: candidateToken,
    authorityPubB64u,
    expectedCustodianPubB64u: expectedCustodianPub,
    nowMs,
  });

  const seatCheck = ver.valid
    ? evaluateSeatRoster({
        workspaceDir: resolvedDir,
        licenseId: ver.payload.licenseId,
        tier: ver.tier,
        maxSeats: ver.payload.maxSeats,
        custodianPubB64u: expectedCustodianPub,
        rosterPath,
        register: false,
      })
    : null;
  const seatOk = !seatCheck || seatCheck.allowed;
  const effValid = ver.valid && seatOk;
  return {
    active: effValid,
    valid: effValid,
    status: seatOk ? ver.status : 'SEAT_CAP_EXCEEDED',
    tier: effValid ? ver.tier : 'COMMUNITY_FREE',
    capabilities: getTierCapabilities(
      effValid ? ver.tier : 'COMMUNITY_FREE'
    ),
    seatCheck,
    isAttestationEligible:
      effValid && ver.isAttestationEligible,
    reason: seatOk ? ver.reason : seatCheck.reason,
    payload: ver.payload,
    tokenStr: ver.valid ? ver.tokenStr : candidateToken,
    payloadDigestB64u: ver.payloadDigestB64u || null,
    rootSignatureB64u: ver.rootSignatureB64u || null,
    authorityPubB64u: ver.authorityPubB64u,
    licensePath,
  };
}
