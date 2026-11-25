/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 4 Commercial Attestation & Zero-Setup Trojan `attest --preview` Engine
 * Zero external dependencies.
 *
 * Verified Statutory & Technical Citations Only:
 * - GDPR Art. 5(1)(c), Art. 17(1), Art. 25, Art. 32
 * - CJEU Case C-413/23 P
 * - EU AI Act (Reg. 2024/1689) Art. 12 & Art. 26(6)
 * - SOC 2 CC7.2 & P4
 * - ISO/IEC 42001:2023 A.6.2.8
 * - PCI DSS v4.0.1 Req. 3.5.1 & 10.3
 * - NIST SP 800-88 Rev. 2 Purge
 * - NIST SP 800-38G Rev. 1 FF1
 * - IETF draft-shuliak-sip-zero-egress-00
 * - CERN DOI 10.5281/zenodo.24159380
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import { discoverMcpConfigs } from '../stage1/config-discovery.mjs';
import { runStaticMcpAudit } from '../stage1/audit-scanner.mjs';
import { verifySchemaLock } from '../stage1/schema-lock.mjs';
import { resolveIsepPaths, verifyIsepChainQuick } from '../stage3/isep-engine.mjs';
import {
  evaluateSeatRoster,
  inspectWorkspaceEntitlement,
  resolveDefaultAuthorityPubB64u,
  verifyCommercialLicenseToken,
} from './license-authority.mjs';
import { generateCycloneDxAibom } from './cyclonedx-aibom.mjs';
import { renderAttestationPdfBytes } from './pdf-generator.mjs';

export const DOMAIN_PREFIX_ATTESTATION = 0x0a;
export const ATTESTATION_SIGN_LABEL = 'SIP-v3-ATTESTATION\0';

export const VERIFIED_STATUTORY_CITATIONS = Object.freeze([
  'GDPR Art. 5(1)(c), Art. 17(1), Art. 25, Art. 32',
  'CJEU Case C-413/23 P',
  'EU AI Act (Reg. 2024/1689) Art. 12 & Art. 26(6)',
  'SOC 2 CC7.2 & P4',
  'ISO/IEC 42001:2023 A.6.2.8',
  'PCI DSS v4.0.1 Req. 3.5.1 & 10.3',
  'NIST SP 800-88 Rev. 2 Purge',
  'NIST SP 800-38G Rev. 1 FF1',
  'IETF draft-shuliak-sip-zero-egress-00',
  'CERN DOI 10.5281/zenodo.24159380',
]);


export const ATTESTATION_TEMPLATES = Object.freeze({
  general: {
    id: 'general',
    title: 'General SOC 2 / ISO 42001 Control Report',
    focus: 'SOC 2 CC7.2 & P4 | ISO/IEC 42001:2023',
  },
  hipaa: {
    id: 'hipaa',
    title: 'HIPAA 18 Safe Harbor Local PET Report',
    focus: '45 CFR 164.514(b)(2) | Clinical RAM Twins',
  },
  legal: {
    id: 'legal',
    title: 'Legal & Tax Sec. 7216 Zero-Egress Report',
    focus: '26 U.S.C. 7216 | ABA 512 | ICAO 9303 MRZ',
  },
  pci: {
    id: 'pci',
    title: 'PCI DSS v4.0.1 & EU DORA Control Report',
    focus: 'PCI DSS 4.0.1 Req. 3.5.1 | DORA Art. 17',
  },
});

export const REGULATORY_ALIGNMENT_NOTES = Object.freeze([
  'DORA (Reg. (EU) 2022/2554) Art. 17',
  'EU AI Omnibus Reg. (EU) 2026/1744',
]);

/**
 * Append optional `?ref=<partnerCode>` attribution parameter cleanly to a checkout URL.
 * @param {string} checkoutUrl
 * @param {string | null | undefined} partnerCode
 * @returns {string}
 */
export function buildPartnerUpgradeUrl(checkoutUrl, partnerCode) {
  const base = String(checkoutUrl || 'https://shuliak.dev/#pricing').trim();
  const cleanPartner = partnerCode ? String(partnerCode).trim() : '';
  if (!cleanPartner) {
    return base;
  }

  const hashIdx = base.indexOf('#');
  const beforeHash = hashIdx >= 0 ? base.slice(0, hashIdx) : base;
  const hashFragment = hashIdx >= 0 ? base.slice(hashIdx) : '';
  const sep = beforeHash.includes('?') ? '&' : '?';
  return `${beforeHash}${sep}ref=${encodeURIComponent(cleanPartner)}${hashFragment}`;
}

/**
 * Extract unsigned core fields from an attestation certificate object for deterministic `0x0A` JCS hashing.
 * @param {Record<string, any>} certObj
 */
export function extractUnsignedAttestationCore(certObj) {
  const clone = { ...certObj };
  delete clone.attestation_digest_0x0a;
  delete clone.custodian_signature_b64u;
  return clone;
}

/**
 * Generate a complete Auditor Attestation Bundle (JSON Certificate + PDF 1.7 + CycloneDX 1.6 AIBOM).
 *
 * - `previewMode = true` (Zero-Setup PLG Trojan Mode):
 *   Runs in < 50 ms on ANY directory even when `isep init` has never been executed!
 *   Discovers MCP configs, runs static audit + PCI DSS v4.0.1 Req. 3.5.1 & Rovo scope analysis,
 *   attaches real ISEP chain metrics if present or `UNINITIALIZED_READINESS_BASELINE` otherwise,
 *   sets `authority_status = "PREVIEW_WATERMARKED_EVALUATION"`, and renders a watermarked A4 PDF.
 *
 * - `previewMode = false` (Full Production Attestation Mode):
 *   Requires an initialized, valid Stage 3 ISEP chain (`verifyIsepChainQuick`). Throws if spoliation
 *   or compliance fraud is detected. Sets `authority_status = "COUNTERSIGNED_COMMERCIAL"` ONLY when
 *   a valid Root-signed `COMPLIANCE` or `ENTERPRISE` token is active in `.sip/license.json`.
 *
 * @param {{
 *   workspaceDir: string,
 *   previewMode?: boolean,
 *   partnerName?: string | null,
 *   partnerCode?: string | null,
 *   checkoutUrl?: string,
 *   includeGlobal?: boolean,
 *   authorityPubB64u?: string,
 * }} params
 */
export function generateAuditorAttestationBundle({
  workspaceDir,
  previewMode = false,
  partnerName = null,
  partnerCode = null,
  checkoutUrl = 'https://shuliak.dev/#pricing',
  includeGlobal = false,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
  template = 'general',
  rosterPath = null,
}) {
  const resolvedDir = path.resolve(workspaceDir || process.cwd());
  const isepPaths = resolveIsepPaths({ workspaceDir: resolvedDir });
  const sipDir = isepPaths.sipDir;

  const configs = discoverMcpConfigs({
    workspaceDir: resolvedDir,
    includeGlobal,
  });

  const auditResult = runStaticMcpAudit({
    configs,
    workspaceDir: resolvedDir,
  });

  const lockVerification = verifySchemaLock({
    workspaceDir: resolvedDir,
    configs,
  });

  const hasPersistedPem = fs.existsSync(path.join(sipDir, 'device.ed25519.pem'));
  const custodian = ensureDeviceEd25519Keypair(sipDir, {
    ephemeralOnly: previewMode && !hasPersistedPem,
  });

  const isepFilesExist =
    fs.existsSync(isepPaths.keyringPath) &&
    fs.existsSync(isepPaths.logPath) &&
    fs.existsSync(isepPaths.blobsPath);

  let isepSummary;
  if (isepFilesExist) {
    const chainCheck = verifyIsepChainQuick({
      logPath: isepPaths.logPath,
      blobsPath: isepPaths.blobsPath,
      custodianPublicKey: custodian.publicKey,
    });
    if (!previewMode && !chainCheck.valid) {
      const err = /** @type {Error & { code?: string }} */ (
        new Error(`[ISEP AUDIT REJECTED: ${chainCheck.status}] ${chainCheck.reason}`)
      );
      err.code = chainCheck.status;
      throw err;
    }
    isepSummary = {
      initialized: true,
      valid: chainCheck.valid,
      status: chainCheck.status,
      totalEvents: chainCheck.totalEvents,
      tombstones: chainCheck.tombstones,
      lawfullyErasedSeqs: chainCheck.lawfullyErasedSeqs || [],
      headChainHash: chainCheck.headChainHash || null,
      reason: chainCheck.reason,
    };
  } else {
    if (!previewMode) {
      const err = /** @type {Error & { code?: string }} */ (
        new Error(
          '[ISEP_NOT_INITIALIZED] Stage 3 ISEP ledger is not initialized in workspace. Run `sip1-mcp isep init` first, or use `sip1-mcp attest --preview` for zero-setup readiness evaluation.'
        )
      );
      err.code = 'ISEP_NOT_INITIALIZED';
      throw err;
    }
    isepSummary = {
      initialized: false,
      valid: false,
      status: 'UNINITIALIZED_READINESS_BASELINE',
      totalEvents: 0,
      tombstones: 0,
      lawfullyErasedSeqs: [],
      headChainHash: null,
      reason:
        'Stage 3 ISEP Blackbox not yet initialized; zero-setup readiness baseline computed from live MCP topology.',
    };
  }

  const tplId = String(template || 'general')
    .trim().toLowerCase();
  if (!ATTESTATION_TEMPLATES[tplId]) {
    throw new Error(
      `Unsupported --template "${tplId}" ` +
      '(expected hipaa, legal, pci, or general)'
    );
  }
  const entitlement = inspectWorkspaceEntitlement({
    workspaceDir: resolvedDir,
    authorityPubB64u,
    rosterPath,
  });

  if (!previewMode &&
      entitlement.status === 'SEAT_CAP_EXCEEDED') {
    const err = new Error(
      `[SEAT_CAP_EXCEEDED] ` +
      `${entitlement.seatCheck?.reason || 'Seat limit'}`
    );
    err.code = 'SEAT_CAP_EXCEEDED';
    throw err;
  }
  if (!previewMode && tplId !== 'general' &&
      (!entitlement.valid ||
       !entitlement.capabilities?.sectorTemplates)) {
    const err = new Error(
      '[COMPLIANCE_TIER_REQUIRED] Sector templates ' +
      '(--template hipaa|legal|pci) require active ' +
      'COMPLIANCE ($299) or ENTERPRISE ($990) key.'
    );
    err.code = 'COMPLIANCE_TIER_REQUIRED';
    throw err;
  }

  if (!previewMode && entitlement.status === 'FORGED_COMMERCIAL_AUTHORITY') {
    const err = /** @type {Error & { code?: string }} */ (
      new Error(`[FORGED_COMMERCIAL_AUTHORITY] ${entitlement.reason}`)
    );
    err.code = 'FORGED_COMMERCIAL_AUTHORITY';
    throw err;
  }

  if (!previewMode && entitlement.valid &&
      entitlement.payload) {
    const seatReg = evaluateSeatRoster({
      workspaceDir: resolvedDir,
      licenseId: entitlement.payload.licenseId,
      tier: entitlement.tier,
      maxSeats: entitlement.payload.maxSeats,
      custodianPubB64u: custodian.publicKeyB64u,
      rosterPath,
      register: true,
    });
    if (!seatReg.allowed) {
      const err = new Error(
        `[SEAT_CAP_EXCEEDED] ${seatReg.reason}`
      );
      err.code = 'SEAT_CAP_EXCEEDED';
      throw err;
    }
  }

  /** @type {'PREVIEW_WATERMARKED_EVALUATION' | 'UNLICENSED_COMMUNITY_DRAFT' | 'COUNTERSIGNED_COMMERCIAL'} */
  let authorityStatus = 'UNLICENSED_COMMUNITY_DRAFT';
  if (previewMode) {
    authorityStatus = 'PREVIEW_WATERMARKED_EVALUATION';
  } else if (entitlement.valid && entitlement.isAttestationEligible) {
    authorityStatus = 'COUNTERSIGNED_COMMERCIAL';
  }

  const resolvedPartnerCode =
    partnerCode ||
    entitlement.payload?.partnerCode ||
    null;
  const resolvedPartnerName =
    partnerName ||
    entitlement.payload?.partnerName ||
    (resolvedPartnerCode ? resolvedPartnerCode : null);

  const upgradeUrl = buildPartnerUpgradeUrl(checkoutUrl, resolvedPartnerCode);

  const { bom: aibom, aibomDigestB64u, scopeAnalysis } = generateCycloneDxAibom({
    workspaceDir: resolvedDir,
    configs,
    auditResult,
    isepSummary,
    lockActive: lockVerification.valid,
  });

  const unsignedCert = {
    aibom_digest_0x08: aibomDigestB64u,
    audit_posture: {
      category_penalties: auditResult.categoryPenalties,
      findings: auditResult.findings.map((f) => ({
        client: f.client,
        masked_preview: f.maskedPreview,
        message: f.message,
        relative_file: f.relativeFile,
        rule_id: f.ruleId,
        server_name: f.serverName,
        severity: f.severity,
      })),
      findings_count: auditResult.findings.length,
      grade: auditResult.grade,
      lock_status: lockVerification.valid ? 'SEALED_VERIFIED' : lockVerification.status,
      lock_manifest_digest: lockVerification.lock?.manifestDigestB64u || null,
      score: auditResult.score,
      total_configs: auditResult.totalConfigs,
      total_servers: auditResult.totalServers,
    },
    attestation_template: tplId,
    authority_status: authorityStatus,
    certificate_id: `cert_${crypto.randomBytes(8).toString('hex')}`,
    commercial_entitlement:
      authorityStatus === 'COUNTERSIGNED_COMMERCIAL' && entitlement.valid
        ? {
            authority_pub_b64u: entitlement.authorityPubB64u,
            license_id: entitlement.payload.licenseId,
            org_domain: entitlement.payload.orgDomain,
            org_name: entitlement.payload.orgName,
            partner_code: resolvedPartnerCode,
            partner_name: resolvedPartnerName,
            root_signature_b64u: entitlement.rootSignatureB64u,
            tier: entitlement.tier,
            token: entitlement.tokenStr,
          }
        : null,
    custodian_key_id: custodian.keyId,
    custodian_pub_b64u: custodian.publicKeyB64u,
    enterprise_scope: {
      detected_connectors: scopeAnalysis.detectedConnectors,
      pci_dss_scope: scopeAnalysis.pciDssScopeStatus,
      rovo_credit_pii_exposure: scopeAnalysis.rovoCreditPiiExposure,
      total_enterprise_connectors: scopeAnalysis.totalEnterpriseConnectors,
    },
    generated_at: new Date().toISOString(),
    isep_ledger: isepSummary,
    partner_attribution:
      resolvedPartnerCode || resolvedPartnerName
        ? {
            partner_code: resolvedPartnerCode,
            partner_name: resolvedPartnerName,
          }
        : null,
    preview_mode: Boolean(previewMode),
    regulatory_alignment: [...REGULATORY_ALIGNMENT_NOTES],
    statutory_citations: [...VERIFIED_STATUTORY_CITATIONS],
    upgrade_url: upgradeUrl,
    v: 'sip-attestation/3.0',
  };

  const canonicalCertBytes = jcsCanonicalize(unsignedCert);
  const certDigestBuf = domainSha256(DOMAIN_PREFIX_ATTESTATION, canonicalCertBytes);
  const certDigestB64u = b64u(certDigestBuf);
  const custodianSignatureB64u = signDomainPayload(
    ATTESTATION_SIGN_LABEL,
    certDigestBuf,
    custodian.privateKey
  );

  const certObj = {
    ...unsignedCert,
    attestation_digest_0x0a: certDigestB64u,
    custodian_signature_b64u: custodianSignatureB64u,
  };

  const pdfBuffer = renderAttestationPdfBytes(certObj);

  return {
    certObj,
    pdfBuffer,
    aibom,
    aibomDigestB64u,
    scopeAnalysis,
    auditResult,
  };
}

/**
 * Offline Two-Tier Cryptographic Verification of an Attestation Certificate JSON:
 * 1) Recomputes `0x0A` RFC 8785 JCS digest and verifies Custodian `Ed25519` signature.
 * 2) Enforces Root Authority `Ed25519` countersignature whenever `authority_status` claims
 *    `"COUNTERSIGNED_COMMERCIAL"` (or if `commercial_entitlement` is present), catching any
 *    pirated/edited JSON or forged local Root key as `FORGED_COMMERCIAL_AUTHORITY`!
 *
 * @param {{
 *   certObj: Record<string, any>,
 *   authorityPubB64u?: string,
 *   nowMs?: number,
 * }} params
 */
export function verifyAttestationCertificateOffline({
  certObj,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
  nowMs = Date.now(),
}) {
  if (!certObj || typeof certObj !== 'object' || certObj.v !== 'sip-attestation/3.0') {
    return {
      valid: false,
      status: 'INVALID_CERTIFICATE_SCHEMA',
      authorityStatus: null,
      custodianSignatureValid: false,
      rootCountersignatureValid: false,
      reason: 'Certificate is missing required schema version v="sip-attestation/3.0"',
    };
  }

  const allowedStatuses = new Set([
    'PREVIEW_WATERMARKED_EVALUATION',
    'UNLICENSED_COMMUNITY_DRAFT',
    'COUNTERSIGNED_COMMERCIAL',
  ]);
  if (!allowedStatuses.has(certObj.authority_status)) {
    return {
      valid: false,
      status: 'INVALID_CERTIFICATE_SCHEMA',
      authorityStatus: certObj.authority_status || null,
      custodianSignatureValid: false,
      rootCountersignatureValid: false,
      reason: `Unsupported authority_status "${certObj.authority_status}"`,
    };
  }

  const unsignedCore = extractUnsignedAttestationCore(certObj);
  const expectedDigestBuf = domainSha256(
    DOMAIN_PREFIX_ATTESTATION,
    jcsCanonicalize(unsignedCore)
  );
  const expectedDigestB64u = b64u(expectedDigestBuf);

  const digestMatches = expectedDigestB64u === certObj.attestation_digest_0x0a;
  const custodianSigValid =
    digestMatches &&
    typeof certObj.custodian_pub_b64u === 'string' &&
    typeof certObj.custodian_signature_b64u === 'string' &&
    verifyDomainPayload(
      ATTESTATION_SIGN_LABEL,
      expectedDigestBuf,
      certObj.custodian_signature_b64u,
      certObj.custodian_pub_b64u
    );

  if (!custodianSigValid) {
    // If someone edited `authority_status` to `COUNTERSIGNED_COMMERCIAL` in JSON, explicitly surface FORGED_COMMERCIAL_AUTHORITY
    const isCommercialClaim = certObj.authority_status === 'COUNTERSIGNED_COMMERCIAL';
    return {
      valid: false,
      status: isCommercialClaim
        ? 'FORGED_COMMERCIAL_AUTHORITY'
        : 'TAMPERED_CUSTODIAN_SIGNATURE',
      authorityStatus: certObj.authority_status,
      custodianSignatureValid: false,
      rootCountersignatureValid: false,
      reason: !digestMatches
        ? 'Certificate payload was modified after Custodian Ed25519 signing (0x0A JCS digest mismatch)'
        : 'Custodian Ed25519 signature verification failed',
    };
  }

  if (certObj.authority_status === 'COUNTERSIGNED_COMMERCIAL') {
    const ent = certObj.commercial_entitlement;
    if (!ent || typeof ent !== 'object' || typeof ent.token !== 'string') {
      return {
        valid: false,
        status: 'FORGED_COMMERCIAL_AUTHORITY',
        authorityStatus: certObj.authority_status,
        custodianSignatureValid: true,
        rootCountersignatureValid: false,
        reason:
          'Certificate claims COUNTERSIGNED_COMMERCIAL without an embedded SHULIAK Root Ed25519 license token',
      };
    }

    const licVer = verifyCommercialLicenseToken({
      tokenStr: ent.token,
      authorityPubB64u: authorityPubB64u || resolveDefaultAuthorityPubB64u(),
      expectedCustodianPubB64u: certObj.custodian_pub_b64u,
      nowMs,
    });

    if (!licVer.valid || !licVer.isAttestationEligible) {
      return {
        valid: false,
        status: 'FORGED_COMMERCIAL_AUTHORITY',
        authorityStatus: certObj.authority_status,
        custodianSignatureValid: true,
        rootCountersignatureValid: false,
        reason: !licVer.valid
          ? `Embedded Root license failed verification (${licVer.status}): ${licVer.reason}`
          : `License tier "${licVer.tier}" does not grant commercial QSA/SOC 2 attestation authority`,
      };
    }

    return {
      valid: true,
      status: 'VERIFIED_COMMERCIAL_ORIGINAL',
      authorityStatus: certObj.authority_status,
      custodianSignatureValid: true,
      rootCountersignatureValid: true,
      orgName: licVer.payload.orgName,
      orgDomain: licVer.payload.orgDomain,
      tier: licVer.tier,
      partnerName: ent.partner_name || licVer.payload.partnerName || null,
      reason: `Verified Custodian Ed25519 signature AND SHULIAK CORP Root Ed25519 countersignature (${licVer.tier} - ${licVer.payload.orgName})`,
    };
  }

  return {
    valid: true,
    status:
      certObj.authority_status === 'PREVIEW_WATERMARKED_EVALUATION'
        ? 'VERIFIED_EVALUATION_PREVIEW'
        : 'VERIFIED_COMMUNITY_DRAFT',
    authorityStatus: certObj.authority_status,
    custodianSignatureValid: true,
    rootCountersignatureValid: false,
    orgName: null,
    orgDomain: null,
    tier: 'COMMUNITY_FREE',
    partnerName: certObj.partner_attribution?.partner_name || null,
    reason:
      certObj.authority_status === 'PREVIEW_WATERMARKED_EVALUATION'
        ? 'Verified Custodian Ed25519 evaluation preview (watermarked; not valid for external QSA / SOC 2 submission)'
        : 'Verified Custodian Ed25519 community draft (unlicensed; not countersigned by SHULIAK Root Authority)',
  };
}
