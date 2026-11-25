/**
 * @license Apache-2.0
 * SHULIAK SIP v3.1 - Stage 4 Tiered Team Policy, Signed
 * CI/PR Receipts ($79 PRO_SECOPS) & MDM Fleet Generator
 * ($990 ENTERPRISE: macOS Jamf .mobileconfig, Intune,
 * and offline 250-node fleet verification).
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
import { writeFileAtomic600 } from '../core/workspace-io.mjs';
import {
  COMMERCIAL_TIERS,
  evaluateSeatRoster,
  inspectWorkspaceEntitlement,
  resolveDefaultAuthorityPubB64u,
  verifyCommercialLicenseToken,
} from './license-authority.mjs';
import {
  verifyAttestationCertificateOffline,
} from './auditor-attestation.mjs';

export const DOMAIN_PREFIX_CI_RECEIPT = 0x0c;
export const CI_RECEIPT_SIGN_LABEL = 'SIP-v3-CI-RECEIPT\0';
export const DOMAIN_PREFIX_MDM_POLICY = 0x0d;
export const MDM_POLICY_SIGN_LABEL = 'SIP-v3-MDM-POLICY\0';

function xmlEsc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function loadWorkspaceTeamPolicy({
  workspaceDir = process.cwd(),
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
} = {}) {
  const ws = path.resolve(workspaceDir || process.cwd());
  const policyPath = path.join(
    ws, '.sip', 'team-policy.json'
  );
  if (!fs.existsSync(policyPath)) {
    return {
      present: false,
      applied: false,
      status: 'NO_TEAM_POLICY',
      policy: null,
      policyPath,
    };
  }
  const ent = inspectWorkspaceEntitlement({
    workspaceDir: ws,
    authorityPubB64u,
  });
  if (!ent.valid || !ent.capabilities?.teamPolicy) {
    return {
      present: true,
      applied: false,
      status: 'PRO_SECOPS_LICENSE_REQUIRED',
      policy: null,
      policyPath,
    };
  }
  const parsed = JSON.parse(
    fs.readFileSync(policyPath, 'utf8')
  );
  return {
    present: true,
    applied: true,
    status: 'TEAM_POLICY_ACTIVE',
    tier: ent.tier,
    policy: parsed,
    policyPath,
  };
}

export function createSignedCiReceipt({
  workspaceDir = process.cwd(),
  auditResult,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
  rosterPath = null,
}) {
  const ws = path.resolve(workspaceDir || process.cwd());
  const ent = inspectWorkspaceEntitlement({
    workspaceDir: ws,
    authorityPubB64u,
    rosterPath,
  });
  if (ent.status === 'SEAT_CAP_EXCEEDED' ||
      (ent.seatCheck && !ent.seatCheck.allowed)) {
    const err = new Error(
      `[SEAT_CAP_EXCEEDED] ${ent.seatCheck?.reason}`
    );
    err.code = 'SEAT_CAP_EXCEEDED';
    throw err;
  }
  if (!ent.valid || !ent.capabilities?.signedCiReceipt) {
    const err = new Error(
      '[PRO_SECOPS_LICENSE_REQUIRED] Signed CI/PR ' +
      'receipts require an active PRO_SECOPS ($79), ' +
      'COMPLIANCE ($299), or ENTERPRISE ($990) key.'
    );
    err.code = 'PRO_SECOPS_LICENSE_REQUIRED';
    throw err;
  }

  const sipDir = path.join(ws, '.sip');
  const kp = ensureDeviceEd25519Keypair(sipDir, {
    ephemeralOnly: false,
  });
  const seatReg = evaluateSeatRoster({
    workspaceDir: ws,
    licenseId: ent.payload.licenseId,
    tier: ent.tier,
    maxSeats: ent.payload.maxSeats,
    custodianPubB64u: kp.publicKeyB64u,
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
  const unsigned = {
    custodian_key_id: kp.keyId,
    custodian_pub_b64u: kp.publicKeyB64u,
    findings_count: auditResult?.findings?.length ?? 0,
    generated_at: new Date().toISOString(),
    grade: auditResult?.grade || 'F',
    license_id: ent.payload.licenseId,
    license_tier: ent.tier,
    license_token: ent.tokenStr,
    lock_status: auditResult?.lockStatus || 'UNCHECKED',
    org_name: ent.payload.orgName,
    receipt_id: `cir_${crypto.randomBytes(8).toString('hex')}`,
    score: Number(auditResult?.score ?? 0),
    token_tax: auditResult?.tokenTax || null,
    total_servers: Number(auditResult?.totalServers ?? 0),
    v: 'sip-ci-receipt/3.1',
  };
  const digBuf = domainSha256(
    DOMAIN_PREFIX_CI_RECEIPT, jcsCanonicalize(unsigned)
  );
  const sig = signDomainPayload(
    CI_RECEIPT_SIGN_LABEL, digBuf, kp.privateKey
  );
  return {
    ...unsigned,
    receipt_digest_0x0c: b64u(digBuf),
    custodian_signature_b64u: sig,
  };
}

export function verifySignedCiReceipt({
  receipt,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
}) {
  if (!receipt || typeof receipt !== 'object' ||
      receipt.v !== 'sip-ci-receipt/3.1') {
    return { valid: false, status: 'INVALID_RECEIPT_SCHEMA' };
  }
  const {
    receipt_digest_0x0c: dig,
    custodian_signature_b64u: sig,
    ...unsigned
  } = receipt;
  const expDig = domainSha256(
    DOMAIN_PREFIX_CI_RECEIPT, jcsCanonicalize(unsigned)
  );
  if (b64u(expDig) !== dig) {
    return { valid: false, status: 'TAMPERED_RECEIPT' };
  }
  if (!verifyDomainPayload(
    CI_RECEIPT_SIGN_LABEL, expDig, sig,
    unsigned.custodian_pub_b64u
  )) {
    return { valid: false, status: 'INVALID_CUSTODIAN_SIG' };
  }
  const lic = verifyCommercialLicenseToken({
    tokenStr: unsigned.license_token,
    authorityPubB64u,
    expectedCustodianPubB64u: unsigned.custodian_pub_b64u,
  });
  if (!lic.valid) {
    return { valid: false, status: lic.status };
  }
  return {
    valid: true,
    status: 'VERIFIED_CI_RECEIPT',
    tier: lic.tier,
    orgName: lic.payload.orgName,
    grade: unsigned.grade,
    score: unsigned.score,
  };
}

export function generateMdmExportBundle({
  workspaceDir = process.cwd(),
  outDir = null,
  platform = 'all',
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
} = {}) {
  const ws = path.resolve(workspaceDir || process.cwd());
  const ent = inspectWorkspaceEntitlement({
    workspaceDir: ws,
    authorityPubB64u,
  });
  if (ent.status === 'SEAT_CAP_EXCEEDED' ||
      (ent.seatCheck && !ent.seatCheck.allowed)) {
    const err = new Error(
      `[SEAT_CAP_EXCEEDED] ${ent.seatCheck?.reason}`
    );
    err.code = 'SEAT_CAP_EXCEEDED';
    throw err;
  }
  if (!ent.valid || ent.tier !== COMMERCIAL_TIERS.ENTERPRISE) {
    const err = new Error(
      '[ENTERPRISE_TIER_REQUIRED] `mdm-export` requires ' +
      'an active ENTERPRISE ($990/mo, 250 seats) license.'
    );
    err.code = 'ENTERPRISE_TIER_REQUIRED';
    throw err;
  }

  const sipDir = path.join(ws, '.sip');
  const kp = ensureDeviceEd25519Keypair(sipDir, {
    ephemeralOnly: false,
  });
  const targetDir = outDir
    ? path.resolve(outDir) : path.join(sipDir, 'mdm');
  fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });

  const policyCore = {
    bound_custodian_pub_b64u:
      ent.payload.boundCustodianPubB64u || null,
    custodian_pub_b64u: kp.publicKeyB64u,
    generated_at: new Date().toISOString(),
    license_id: ent.payload.licenseId,
    max_seats: ent.payload.maxSeats,
    org_domain: ent.payload.orgDomain,
    org_name: ent.payload.orgName,
    policy: {
      enforceZeroEgress: true,
      enforceSchemaLock: true,
      enforceIfcTrifecta: true,
      failClosedExitCode: 2,
      sipLicenseKeyEnv: 'SIP_LICENSE_KEY',
    },
    tier: 'ENTERPRISE',
    v: 'sip-mdm-policy/3.1',
  };
  const digBuf = domainSha256(
    DOMAIN_PREFIX_MDM_POLICY, jcsCanonicalize(policyCore)
  );
  const sigB64u = signDomainPayload(
    MDM_POLICY_SIGN_LABEL, digBuf, kp.privateKey
  );
  const digB64u = b64u(digBuf);
  const payloadUuid = crypto.randomUUID().toUpperCase();
  const rootUuid = crypto.randomUUID().toUpperCase();

  const files = [];

  if (platform === 'all' || platform === 'macos') {
    const plist = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0' +
        '//EN" "http://www.apple.com/DTDs/' +
        'PropertyList-1.0.dtd">',
      '<plist version="1.0">',
      '<dict>',
      '  <key>PayloadContent</key>',
      '  <array>',
      '    <dict>',
      '      <key>PayloadDisplayName</key>',
      '      <string>SHULIAK SIP-1 Enterprise Policy' +
        '</string>',
      '      <key>PayloadIdentifier</key>',
      '      <string>com.shuliak.sip1.policy.jamf</string>',
      '      <key>PayloadType</key>',
      '      <string>com.shuliak.sip1.policy</string>',
      '      <key>PayloadUUID</key>',
      `      <string>${payloadUuid}</string>`,
      '      <key>PayloadVersion</key>',
      '      <integer>1</integer>',
      '      <key>OrgName</key>',
      `      <string>${xmlEsc(ent.payload.orgName)}</string>`,
      '      <key>LicenseId</key>',
      `      <string>${xmlEsc(ent.payload.licenseId)}` +
        '</string>',
      '      <key>MaxSeats</key>',
      `      <integer>${ent.payload.maxSeats}</integer>`,
      '      <key>EnforceZeroEgress</key>',
      '      <true/>',
      '      <key>EnforceIfcTrifecta</key>',
      '      <true/>',
      '      <key>PolicyDigest0x0d</key>',
      `      <string>${digB64u}</string>`,
      '      <key>Ed25519Signature</key>',
      `      <string>${sigB64u}</string>`,
      '      <key>CustodianPubB64u</key>',
      `      <string>${kp.publicKeyB64u}</string>`,
      '    </dict>',
      '  </array>',
      '  <key>PayloadDisplayName</key>',
      `  <string>SHULIAK SIP-1 (${xmlEsc(ent.payload.orgName)}` +
        ')</string>',
      '  <key>PayloadIdentifier</key>',
      '  <string>com.shuliak.sip1.profile</string>',
      '  <key>PayloadOrganization</key>',
      `  <string>${xmlEsc(ent.payload.orgName)}</string>`,
      '  <key>PayloadScope</key>',
      '  <string>System</string>',
      '  <key>PayloadType</key>',
      '  <string>Configuration</string>',
      '  <key>PayloadUUID</key>',
      `  <string>${rootUuid}</string>`,
      '  <key>PayloadVersion</key>',
      '  <integer>1</integer>',
      '</dict>',
      '</plist>',
      '',
    ].join('\n');
    const macPath = path.join(
      targetDir, 'shuliak-sip1-jamf.mobileconfig'
    );
    writeFileAtomic600(macPath, plist, { mode: 0o600 });
    files.push({ platform: 'macos', path: macPath });
  }

  if (platform === 'all' || platform === 'windows') {
    const intuneObj = {
      schema: 'microsoft.intune.oma-uri/1.0',
      displayName: `SHULIAK SIP-1 (${ent.payload.orgName})`,
      omaSettings: [
        {
          displayName: 'SIP1_ENFORCE_ZERO_EGRESS',
          omaUri: './Device/Vendor/MSFT/Policy/Config/' +
            'ShuliakSIP1/EnforceZeroEgress',
          dataType: 'Integer',
          value: 1,
        },
        {
          displayName: 'SIP1_POLICY_MANIFEST',
          omaUri: './Device/Vendor/MSFT/Policy/Config/' +
            'ShuliakSIP1/PolicyJson',
          dataType: 'String',
          value: JSON.stringify(policyCore),
        },
      ],
      policy_core: policyCore,
      policy_digest_0x0d: digB64u,
      signature_b64u: sigB64u,
    };
    const winPath = path.join(
      targetDir, 'shuliak-sip1-intune-policy.json'
    );
    writeFileAtomic600(
      winPath, JSON.stringify(intuneObj, null, 2) + '\n',
      { mode: 0o600 }
    );
    files.push({ platform: 'windows', path: winPath });
  }

  return {
    tier: 'ENTERPRISE',
    orgName: ent.payload.orgName,
    licenseId: ent.payload.licenseId,
    maxSeats: ent.payload.maxSeats,
    hardwareBound: Boolean(ent.payload.boundCustodianPubB64u),
    policyDigest0x0d: digB64u,
    signatureB64u: sigB64u,
    files,
  };
}

export function verifyEnterpriseFleet({
  workspaceDir = process.cwd(),
  fleetDir,
  authorityPubB64u = resolveDefaultAuthorityPubB64u(),
  maxNodesCap = 250,
} = {}) {
  const ws = path.resolve(workspaceDir || process.cwd());
  const ent = inspectWorkspaceEntitlement({
    workspaceDir: ws,
    authorityPubB64u,
  });
  if (!ent.valid || ent.tier !== COMMERCIAL_TIERS.ENTERPRISE) {
    const err = new Error(
      '[ENTERPRISE_TIER_REQUIRED] `fleet-verify` requires ' +
      'an active ENTERPRISE ($990/mo, 250 seats) license.'
    );
    err.code = 'ENTERPRISE_TIER_REQUIRED';
    throw err;
  }

  const targetDir = path.resolve(fleetDir || ws);
  if (!fs.existsSync(targetDir)) {
    throw new Error(`Fleet dir not found: ${targetDir}`);
  }
  const jsonFiles = fs.readdirSync(targetDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => path.join(targetDir, f));

  const effectiveCap = Math.min(
    maxNodesCap,
    Number(ent.payload?.maxSeats || 250)
  );
  const uniqueCustodians = new Set();
  const nodeResults = [];
  let validCount = 0;
  let invalidCount = 0;

  for (const fp of jsonFiles) {
    const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
    let ver;
    let custodianPub = raw.custodian_pub_b64u || null;
    if (raw.v === 'sip-attestation/3.0') {
      ver = verifyAttestationCertificateOffline({
        certObj: raw,
        authorityPubB64u,
      });
    } else if (raw.v === 'sip-ci-receipt/3.1') {
      ver = verifySignedCiReceipt({
        receipt: raw,
        authorityPubB64u,
      });
    } else {
      ver = { valid: false, status: 'UNSUPPORTED_ARTIFACT' };
    }
    if (custodianPub) uniqueCustodians.add(custodianPub);
    if (ver.valid) validCount++;
    else invalidCount++;
    nodeResults.push({
      file: path.basename(fp),
      valid: Boolean(ver.valid),
      status: ver.status,
      custodianPubB64u: custodianPub,
    });
  }

  const seatExceeded = uniqueCustodians.size > effectiveCap;
  const valid = invalidCount === 0 && !seatExceeded &&
    nodeResults.length > 0;
  return {
    valid,
    status: seatExceeded
      ? 'SEAT_CAP_EXCEEDED'
      : valid
        ? 'FLEET_VERIFIED'
        : 'FLEET_VERIFICATION_FAILED',
    totalNodes: nodeResults.length,
    uniqueSeats: uniqueCustodians.size,
    maxSeats: effectiveCap,
    validCount,
    invalidCount,
    orgName: ent.payload.orgName,
    nodes: nodeResults,
  };
}
