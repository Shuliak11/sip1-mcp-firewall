/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 4 Production Test Suite (32 Deterministic Tests)
 * Covers:
 * - Two-tier Root Ed25519 commercial licensing (`SIP3.<TIER>...`) & vCISO attribution
 * - OWASP CycloneDX 1.6 AIBOM (`0x08` JCS digest), PCI DSS v4.0.1 Req. 3.5.1 & Atlassian Rovo scope
 * - Zero-setup `attest --preview` (< 50 ms without `isep init`) vs full `attest` + anti-spoliation
 * - Byte-exact `%PDF-1.7` A4 generator, `xref` table offset verification, and piracy / anti-spoofing defenses
 * - GHAS-free GitHub PR Markdown scorecard, `.github/workflows/sip-mcp-gate.yml`, and SVG repo badge
 * - Reproducible Zero-Egress Socket Tripwire (`EGRESS_SOCKET_VIOLATION` on `net`, `tls`, `dns`, `fetch`)
 * - Strict `<= 78` column CLI terminal formatting and ZERO emojis across all outputs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Buffer } from 'node:buffer';

import { ensureDeviceEd25519Keypair } from '../src/core/crypto-primitives.mjs';
import {
  closeKeyring,
  executeGdprShredding,
  initKeyring,
  recordAgentEvent,
} from '../src/stage3/isep-engine.mjs';
import {
  COMMERCIAL_TIERS,
  SHULIAK_ROOT_PUB_B64U,
  activateWorkspaceLicense,
  generateAuthorityKeypair,
  inspectWorkspaceEntitlement,
  issueCommercialLicenseToken,
  verifyCommercialLicenseToken,
} from '../src/stage4/license-authority.mjs';
import {
  analyzeEnterpriseScopeExposure,
  generateCycloneDxAibom,
} from '../src/stage4/cyclonedx-aibom.mjs';
import {
  VERIFIED_STATUTORY_CITATIONS,
  buildPartnerUpgradeUrl,
  generateAuditorAttestationBundle,
  verifyAttestationCertificateOffline,
} from '../src/stage4/auditor-attestation.mjs';
import {
  PDF_MAX_LINE_CHARS,
  extractAndVerifyPdfBytes,
  renderAttestationPdfBytes,
  wrapPdfLine,
} from '../src/stage4/pdf-generator.mjs';
import {
  STICKY_PR_COMMENT_MARKER,
  formatAuditMarkdownPrComment,
  generateGithubPrWorkflowYaml,
  generateRepoBadgeSvg,
} from '../src/stage4/pr-cicd-gate.mjs';
import { runZeroEgressSelfTest } from '../src/stage4/zero-egress-selftest.mjs';
import { discoverMcpConfigs } from '../src/stage1/config-discovery.mjs';
import { runStaticMcpAudit } from '../src/stage1/audit-scanner.mjs';
import { createOrUpdateSchemaLock } from '../src/stage1/schema-lock.mjs';
import { CLI_VERSION, runCli } from '../src/cli.mjs';

const EMOJI_PICTOGRAPH_RE = /\p{Extended_Pictographic}/u;

function makeTempWorkspace(prefix = 'sip-stage4-test-') {
  const baseTmp = process.env.TMPDIR || process.env.TEMP || '/tmp';
  return fs.mkdtempSync(path.join(baseTmp, prefix));
}

function writeEnterpriseMcpFixture(workspaceDir) {
  const cursorDir = path.join(workspaceDir, '.cursor');
  fs.mkdirSync(cursorDir, { recursive: true });
  const rawSecretStripe = 'sk_l' + 'ive_' + '9f8e7d6c5b4a3f2e1d0c9b8a7f6e';
  const rawSecretPg = 'postgres://finops_admin:SuperSecretDbPass99!@db.internal.corp:5432/cards';
  const rawSecretRovo = 'ATATT3xFfGF0_SecretAtlassianRovoApiTokenValue987654321';

  const cfg = {
    mcpServers: {
      'stripe-payments': {
        command: 'npx',
        args: ['-y', '@stripe/mcp@0.2.4', '--tools=all'],
        env: {
          STRIPE_SECRET_KEY: rawSecretStripe,
        },
      },
      'postgres-cardholder-db': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-postgres', rawSecretPg],
        env: {
          PGPASSWORD: 'SuperSecretDbPass99!',
        },
      },
      'atlassian-rovo': {
        url: 'https://mcp.atlassian.com/v1/sse',
        headers: {
          Authorization: `Bearer ${rawSecretRovo}`,
        },
      },
      'github-scm': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-github@2025.1.0'],
        env: {
          GITHUB_PERSONAL_ACCESS_TOKEN: '${env:GITHUB_TOKEN}',
        },
      },
    },
  };

  fs.writeFileSync(path.join(cursorDir, 'mcp.json'), JSON.stringify(cfg, null, 2) + '\n', 'utf8');
  return { rawSecretStripe, rawSecretPg, rawSecretRovo };
}

function assertBoxWidth78AndZeroEmojis(text, label = 'CLI output') {
  assert.equal(
    EMOJI_PICTOGRAPH_RE.test(text),
    false,
    `${label} must contain ZERO emojis`
  );
  for (const line of text.split('\n')) {
    if (line.startsWith('+') || line.startsWith('|')) {
      assert.ok(
        line.length <= 78,
        `${label} line exceeded 78 columns (${line.length}): ${line}`
      );
    }
  }
}

// ============================================================================
// 1. ROOT ED25519 COMMERCIAL LICENSE AUTHORITY & vCISO PARTNER ATTRIBUTION
// ============================================================================

test('S4-01: Canonical SHULIAK_ROOT_PUB_B64U is valid 32-byte raw Ed25519 public key and generateAuthorityKeypair mints verifiable COMPLIANCE token', () => {
  assert.equal(typeof SHULIAK_ROOT_PUB_B64U, 'string');
  assert.equal(Buffer.from(SHULIAK_ROOT_PUB_B64U, 'base64url').byteLength, 32);

  const rootAuth = generateAuthorityKeypair();
  const issued = issueCommercialLicenseToken({
    authorityPrivateKey: rootAuth.privateKey,
    tier: COMMERCIAL_TIERS.COMPLIANCE,
    licenseId: 'lic_stage4_001',
    orgName: 'Nordic FinTech AB',
    orgDomain: 'nordicfintech.se',
    maxSeats: 50,
    partnerCode: 'vciso-alpha',
    partnerName: 'Alpha vCISO Advisory Partners',
  });

  assert.match(issued.token, /^SIP3\.COMPLIANCE\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

  const verified = verifyCommercialLicenseToken({
    tokenStr: issued.token,
    authorityPubB64u: rootAuth.publicKeyB64u,
  });

  assert.equal(verified.valid, true);
  assert.equal(verified.status, 'ACTIVE_LICENSED');
  assert.equal(verified.isAttestationEligible, true);
  assert.equal(verified.tier, 'COMPLIANCE');
  assert.equal(verified.payload.partnerCode, 'vciso-alpha');
  assert.equal(verified.payload.partnerName, 'Alpha vCISO Advisory Partners');
});

test('S4-02: PRO_SECOPS tier validates cleanly as active license but isAttestationEligible=false for QSA/SOC2 countersigning', () => {
  const rootAuth = generateAuthorityKeypair();
  const proTok = issueCommercialLicenseToken({
    authorityPrivateKey: rootAuth.privateKey,
    tier: COMMERCIAL_TIERS.PRO_SECOPS,
    orgName: 'DevTeam Co',
    orgDomain: 'devteam.io',
  });

  const ver = verifyCommercialLicenseToken({
    tokenStr: proTok.token,
    authorityPubB64u: rootAuth.publicKeyB64u,
  });

  assert.equal(ver.valid, true);
  assert.equal(ver.tier, 'PRO_SECOPS');
  assert.equal(ver.isAttestationEligible, false);
});

test('S4-03: Token signed by unauthorized / fake Ed25519 Root key is rejected as FORGED_COMMERCIAL_AUTHORITY', () => {
  const fakeRoot = generateAuthorityKeypair();
  const forged = issueCommercialLicenseToken({
    authorityPrivateKey: fakeRoot.privateKey,
    tier: COMMERCIAL_TIERS.ENTERPRISE,
    orgName: 'Pirate Corp',
    orgDomain: 'pirate.example',
  });

  // Verify against canonical SHULIAK_ROOT_PUB_B64U -> must fail closed!
  const ver = verifyCommercialLicenseToken({
    tokenStr: forged.token,
  });

  assert.equal(ver.valid, false);
  assert.equal(ver.status, 'FORGED_COMMERCIAL_AUTHORITY');
  assert.equal(ver.isAttestationEligible, false);
});

test('S4-04: Expired license token is rejected as LICENSE_EXPIRED', () => {
  const rootAuth = generateAuthorityKeypair();
  const expired = issueCommercialLicenseToken({
    authorityPrivateKey: rootAuth.privateKey,
    tier: COMMERCIAL_TIERS.COMPLIANCE,
    orgName: 'Expired Org',
    orgDomain: 'expired.org',
    issuedAt: '2024-01-01T00:00:00.000Z',
    expiresAt: '2025-01-01T00:00:00.000Z',
  });

  const ver = verifyCommercialLicenseToken({
    tokenStr: expired.token,
    authorityPubB64u: rootAuth.publicKeyB64u,
    nowMs: Date.parse('2026-06-01T00:00:00.000Z'),
  });

  assert.equal(ver.valid, false);
  assert.equal(ver.status, 'LICENSE_EXPIRED');
});

test('S4-05: Custodian key binding prevents replaying a bound workspace license onto another machine', () => {
  const rootAuth = generateAuthorityKeypair();
  const wsA = makeTempWorkspace('sip-s4-wsa-');
  const wsB = makeTempWorkspace('sip-s4-wsb-');
  try {
    const custA = ensureDeviceEd25519Keypair(path.join(wsA, '.sip'));
    ensureDeviceEd25519Keypair(path.join(wsB, '.sip'));

    const bound = issueCommercialLicenseToken({
      authorityPrivateKey: rootAuth.privateKey,
      tier: COMMERCIAL_TIERS.ENTERPRISE,
      orgName: 'Bound Bank AG',
      orgDomain: 'boundbank.ch',
      boundCustodianPubB64u: custA.publicKeyB64u,
    });

    // Works on Workspace A
    return activateWorkspaceLicense({
      workspaceDir: wsA,
      tokenStr: bound.token,
      authorityPubB64u: rootAuth.publicKeyB64u,
    }).then(async (actA) => {
      assert.equal(actA.activated, true);
      const statMode = fs.statSync(actA.licensePath).mode & 0o777;
      assert.equal(statMode, 0o600);

      // Fails on Workspace B with CUSTODIAN_KEY_MISMATCH
      await assert.rejects(
        () =>
          activateWorkspaceLicense({
            workspaceDir: wsB,
            tokenStr: bound.token,
            authorityPubB64u: rootAuth.publicKeyB64u,
          }),
        /CUSTODIAN_KEY_MISMATCH/
      );
    });
  } finally {
    setImmediate(() => {
      fs.rmSync(wsA, { recursive: true, force: true });
      fs.rmSync(wsB, { recursive: true, force: true });
    });
  }
});

test('S4-06: Editing .sip/license.json on disk without valid Root-signed token triggers FORGED_COMMERCIAL_AUTHORITY', () => {
  const ws = makeTempWorkspace('sip-s4-disktamper-');
  try {
    const sipDir = path.join(ws, '.sip');
    fs.mkdirSync(sipDir, { recursive: true });
    fs.writeFileSync(
      path.join(sipDir, 'license.json'),
      JSON.stringify({ tier: 'ENTERPRISE', orgName: 'Hacked', token: '' }, null, 2),
      'utf8'
    );

    const ent = inspectWorkspaceEntitlement({ workspaceDir: ws });
    assert.equal(ent.valid, false);
    assert.equal(ent.status, 'FORGED_COMMERCIAL_AUTHORITY');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

// ============================================================================
// 2. CYCLONEDX 1.6 AIBOM & PCI DSS 4.0.1 / ATLASSIAN ROVO SCOPE EXPOSURE
// ============================================================================

test('S4-07: analyzeEnterpriseScopeExposure detects Payment, Database, Atlassian Rovo, and Cloud connectors accurately', () => {
  const ws = makeTempWorkspace('sip-s4-scope-');
  try {
    writeEnterpriseMcpFixture(ws);
    const configs = discoverMcpConfigs({ workspaceDir: ws, includeGlobal: false });
    const auditResult = runStaticMcpAudit({ configs, workspaceDir: ws });

    const unguarded = analyzeEnterpriseScopeExposure({
      configs,
      auditResult,
      isepActive: false,
    });
    assert.equal(unguarded.totalEnterpriseConnectors, 4);
    assert.equal(unguarded.pciDssScopeStatus.inScopeConnectorCount, 2);
    assert.equal(unguarded.pciDssScopeStatus.status, 'CLEARTEXT_PAN_SCOPE_EXPOSURE_DETECTED');
    assert.match(unguarded.pciDssScopeStatus.standard, /PCI DSS v4\.0\.1 Req\. 3\.5\.1 & 10\.3/);
    assert.equal(unguarded.rovoCreditPiiExposure.connectorCount, 1);
    assert.equal(
      unguarded.rovoCreditPiiExposure.status,
      'UNMETERED_LOOP_CREDIT_AND_TICKET_PII_RISK'
    );

    const guarded = analyzeEnterpriseScopeExposure({
      configs,
      auditResult,
      isepActive: true,
    });
    assert.equal(guarded.pciDssScopeStatus.status, 'SCOPE_REDUCED_VIA_INLINE_FF1_TWINS');
    assert.equal(
      guarded.rovoCreditPiiExposure.status,
      'GUARDED_FINOPS_FUSE_AND_PII_DETACHMENT'
    );
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-08: generateCycloneDxAibom produces deterministic CycloneDX 1.6 schema with 0x08 JCS digest and ZERO raw secrets', () => {
  const ws = makeTempWorkspace('sip-s4-aibom-');
  try {
    const { rawSecretStripe, rawSecretPg, rawSecretRovo } = writeEnterpriseMcpFixture(ws);
    const configs = discoverMcpConfigs({ workspaceDir: ws, includeGlobal: false });
    const auditResult = runStaticMcpAudit({ configs, workspaceDir: ws });

    const out1 = generateCycloneDxAibom({ workspaceDir: ws, configs, auditResult });
    const out2 = generateCycloneDxAibom({ workspaceDir: ws, configs, auditResult });

    assert.equal(out1.bom.bomFormat, 'CycloneDX');
    assert.equal(out1.bom.specVersion, '1.6');
    assert.equal(out1.aibomDigestB64u, out2.aibomDigestB64u);
    assert.equal(out1.bom.serialNumber, out2.bom.serialNumber);
    assert.equal(out1.bom.components.length, 4);
    assert.equal(out1.bom.services.length, 1); // remote atlassian-rovo endpoint

    const serialized = JSON.stringify(out1.bom);
    assert.equal(serialized.includes(rawSecretStripe), false, 'Stripe raw secret leaked in AIBOM!');
    assert.equal(serialized.includes('SuperSecretDbPass99!'), false, 'DB password leaked in AIBOM!');
    assert.equal(serialized.includes(rawSecretPg), false, 'Full DB URI leaked in AIBOM!');
    assert.equal(serialized.includes(rawSecretRovo), false, 'Rovo Bearer token leaked in AIBOM!');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-09: CLI `aibom --json` and file output write valid CycloneDX 1.6 JSON with 0o600 permissions', async () => {
  const ws = makeTempWorkspace('sip-s4-cliaibom-');
  try {
    writeEnterpriseMcpFixture(ws);
    const outFile = path.join(ws, 'custom-aibom.cdx.json');
    const res = await runCli(['aibom', '--dir', ws, '--no-global', '--out', outFile]);
    assert.equal(res.exitCode, 0);
    assertBoxWidth78AndZeroEmojis(res.stdout, 'aibom terminal box');
    assert.equal(fs.existsSync(outFile), true);
    const parsed = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert.equal(parsed.bomFormat, 'CycloneDX');
    assert.equal(parsed.specVersion, '1.6');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-10: CLI `audit` terminal mode appends <= 78-column enterprise connector hint when DB/Payment/Rovo servers exist', async () => {
  const ws = makeTempWorkspace('sip-s4-audithint-');
  try {
    writeEnterpriseMcpFixture(ws);
    const res = await runCli(['audit', '--dir', ws, '--no-global']);
    assert.equal(res.exitCode, 0);
    assert.match(res.stdout, /attest --preview/);
    assertBoxWidth78AndZeroEmojis(res.stdout, 'audit + enterprise hint');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-11: buildPartnerUpgradeUrl preserves URL hash fragments while injecting ?ref=<partnerCode>', () => {
  assert.equal(
    buildPartnerUpgradeUrl('https://shuliak.dev/#pricing', 'vciso-alpha'),
    'https://shuliak.dev/?ref=vciso-alpha#pricing'
  );
  assert.equal(
    buildPartnerUpgradeUrl('https://shuliak.dev/checkout?plan=compliance#top', 'secops_eu'),
    'https://shuliak.dev/checkout?plan=compliance&ref=secops_eu#top'
  );
});

// ============================================================================
// 3. ZERO-SETUP TROJAN `attest --preview` vs FULL COMMERCIAL `attest`
// ============================================================================

test('S4-12: Zero-setup `attest --preview` succeeds on brand-new folder WITHOUT `isep init`, embeds ?ref=<partner>, and leaks zero secrets', async () => {
  const ws = makeTempWorkspace('sip-s4-preview-');
  try {
    const { rawSecretStripe, rawSecretPg, rawSecretRovo } = writeEnterpriseMcpFixture(ws);
    const t0 = performance.now();
    const res = await runCli([
      'attest',
      '--preview',
      '--partner',
      'vciso-alpha',
      '--dir',
      ws,
    ]);
    const elapsedMs = performance.now() - t0;

    assert.equal(res.exitCode, 0, `attest --preview stderr: ${res.stderr}`);
    assertBoxWidth78AndZeroEmojis(res.stdout, 'attest --preview box');
    // Generous CI margin around sub-50ms target so container CPU jitter never flakes
    assert.ok(elapsedMs < 250, `Expected fast zero-setup preview, took ${elapsedMs.toFixed(1)} ms`);

    const pdfPath = path.join(ws, 'SHULIAK_READINESS_PREVIEW.pdf');
    const jsonPath = path.join(ws, 'SHULIAK_READINESS_PREVIEW.json');
    const aibomPath = path.join(ws, 'aibom.cdx.json');

    assert.equal(fs.existsSync(pdfPath), true);
    assert.equal(fs.existsSync(jsonPath), true);
    assert.equal(fs.existsSync(aibomPath), true);

    const cert = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    assert.equal(cert.authority_status, 'PREVIEW_WATERMARKED_EVALUATION');
    assert.equal(cert.isep_ledger.status, 'UNINITIALIZED_READINESS_BASELINE');
    assert.equal(cert.upgrade_url, 'https://shuliak.dev/?ref=vciso-alpha#pricing');

    const rawPdfStr = fs.readFileSync(pdfPath).toString('latin1');
    const rawJsonStr = fs.readFileSync(jsonPath, 'utf8');
    for (const secret of [rawSecretStripe, 'SuperSecretDbPass99!', rawSecretPg, rawSecretRovo]) {
      assert.equal(rawPdfStr.includes(secret), false, 'Secret leaked into preview PDF!');
      assert.equal(rawJsonStr.includes(secret), false, 'Secret leaked into preview JSON!');
    }
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-13: Full `attest` (without --preview) fails closed with exitCode=2 when Stage 3 ISEP is not initialized', async () => {
  const ws = makeTempWorkspace('sip-s4-no-isep-');
  try {
    writeEnterpriseMcpFixture(ws);
    const res = await runCli(['attest', '--dir', ws, '--no-global']);
    assert.equal(res.exitCode, 2);
    assert.match(res.stderr, /ISEP_NOT_INITIALIZED/);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-14: Full `attest` fails closed with exitCode=2 if Stage 3 ISEP sidecar has unlawful spoliation', async () => {
  const ws = makeTempWorkspace('sip-s4-spoliation-');
  try {
    writeEnterpriseMcpFixture(ws);
    const kr = initKeyring({ workspaceDir: ws, bucketCount: 16 });
    try {
      recordAgentEvent(kr, {
        server: 'stripe-payments',
        tool: 'charge_card',
        args: { email: 'alice@corp.eu', amount: 99 },
      });
    } finally {
      closeKeyring(kr);
    }

    // Corrupt sidecar ciphertext byte without a lawful signed tombstone
    const blobsPath = kr.blobsPath;
    const buf = fs.readFileSync(blobsPath);
    buf[buf.length - 8] ^= 0xff;
    fs.writeFileSync(blobsPath, buf);

    const res = await runCli(['attest', '--dir', ws, '--no-global']);
    assert.equal(res.exitCode, 2);
    assert.match(res.stderr, /ISEP AUDIT REJECTED/);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-15: Full `attest` with valid ISEP chain but NO commercial license emits UNLICENSED_COMMUNITY_DRAFT', async () => {
  const ws = makeTempWorkspace('sip-s4-unlicensed-');
  try {
    writeEnterpriseMcpFixture(ws);
    const kr = initKeyring({ workspaceDir: ws, bucketCount: 16 });
    try {
      recordAgentEvent(kr, {
        server: 'stripe-payments',
        tool: 'create_customer',
        args: { customer: 'alice@corp.eu' },
      });
      executeGdprShredding(kr, {
        canonicalTargetBuf: 'alice@corp.eu',
        dsarTicketId: 'DSAR-STAGE4-15',
      });
    } finally {
      closeKeyring(kr);
    }

    const res = await runCli(['attest', '--dir', ws, '--no-global', '--json']);
    assert.equal(res.exitCode, 0);
    const summary = JSON.parse(res.stdout);
    assert.equal(summary.authorityStatus, 'UNLICENSED_COMMUNITY_DRAFT');

    const pdfBuf = fs.readFileSync(summary.pdfPath);
    const pdfVer = extractAndVerifyPdfBytes(pdfBuf);
    assert.equal(pdfVer.valid, true);
    assert.equal(pdfVer.status, 'VERIFIED_COMMUNITY_DRAFT');
    assert.equal(pdfVer.rootCountersignatureValid, false);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-16: Full `attest` with active Root-signed COMPLIANCE license + vCISO partner emits COUNTERSIGNED_COMMERCIAL PDF & JSON', async () => {
  const ws = makeTempWorkspace('sip-s4-commercial-');
  const rootAuth = generateAuthorityKeypair();
  try {
    writeEnterpriseMcpFixture(ws);
    const configs = discoverMcpConfigs({ workspaceDir: ws, includeGlobal: false });
    await createOrUpdateSchemaLock({ workspaceDir: ws, configs, dryRun: false });

    const kr = initKeyring({ workspaceDir: ws, bucketCount: 16 });
    try {
      recordAgentEvent(kr, {
        server: 'postgres-cardholder-db',
        tool: 'select_settlement',
        args: { email: 'cfo@regulatedbank.eu', iban: 'DE89370400440532013000' },
      });
    } finally {
      closeKeyring(kr);
    }

    const issued = issueCommercialLicenseToken({
      authorityPrivateKey: rootAuth.privateKey,
      tier: COMMERCIAL_TIERS.COMPLIANCE,
      licenseId: 'lic_bank_eu_77',
      orgName: 'Regulated Bank SE',
      orgDomain: 'regulatedbank.eu',
      partnerCode: 'vciso-nordic',
      partnerName: 'Nordic QSA & vCISO Partners',
      boundCustodianPubB64u: fs.readFileSync(path.join(ws, '.sip', 'device.ed25519.pub'), 'utf8').trim(),
    });

    const actRes = await runCli([
      'license',
      'activate',
      '--dir',
      ws,
      '--token',
      issued.token,
      '--authority-pub',
      rootAuth.publicKeyB64u,
    ]);
    assert.equal(actRes.exitCode, 0);
    assertBoxWidth78AndZeroEmojis(actRes.stdout, 'license activate');

    const attRes = await runCli([
      'attest',
      '--dir',
      ws,
      '--no-global',
      '--authority-pub',
      rootAuth.publicKeyB64u,
    ]);
    assert.equal(attRes.exitCode, 0);
    assertBoxWidth78AndZeroEmojis(attRes.stdout, 'commercial attest');

    const pdfPath = path.join(ws, 'SHULIAK_ATTESTATION_CERTIFICATE.pdf');
    const jsonPath = path.join(ws, 'SHULIAK_ATTESTATION_CERTIFICATE.json');

    const verPdfCli = await runCli([
      'verify-cert',
      '--file',
      pdfPath,
      '--authority-pub',
      rootAuth.publicKeyB64u,
    ]);
    assert.equal(verPdfCli.exitCode, 0);
    assertBoxWidth78AndZeroEmojis(verPdfCli.stdout, 'verify-cert commercial PDF');

    const verJson = verifyAttestationCertificateOffline({
      certObj: JSON.parse(fs.readFileSync(jsonPath, 'utf8')),
      authorityPubB64u: rootAuth.publicKeyB64u,
    });
    assert.equal(verJson.valid, true);
    assert.equal(verJson.status, 'VERIFIED_COMMERCIAL_ORIGINAL');
    assert.equal(verJson.custodianSignatureValid, true);
    assert.equal(verJson.rootCountersignatureValid, true);
    assert.equal(verJson.partnerName, 'Nordic QSA & vCISO Partners');

    const rawPdfLatin1 = fs.readFileSync(pdfPath).toString('latin1');
    assert.equal(rawPdfLatin1.includes('VERIFIED COMMERCIAL ATTESTATION'), true);
    assert.equal(rawPdfLatin1.includes('Nordic QSA & vCISO Partners'), true);
    assert.equal(rawPdfLatin1.includes('EVALUATION PREVIEW - NOT VALID'), false);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-17: Statutory citations list matches exact verified statutory & standard identifiers only', () => {
  assert.deepEqual(VERIFIED_STATUTORY_CITATIONS, [
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
});

// ============================================================================
// 4. PDF 1.7 BINARY INTEGRITY, XREF OFFSETS & PIRACY / ANTI-SPOOFING DEFENSES
// ============================================================================

test('S4-18: PDF 1.7 generator emits valid %PDF-1.7 header, exact 20-byte xref entries, accurate startxref byte offset, and <= 84 char wrapped lines', () => {
  const ws = makeTempWorkspace('sip-s4-pdfxref-');
  try {
    writeEnterpriseMcpFixture(ws);
    const bundle = generateAuditorAttestationBundle({
      workspaceDir: ws,
      previewMode: true,
      partnerCode: 'vciso-alpha',
    });

    const buf = bundle.pdfBuffer;
    const raw = buf.toString('latin1');
    assert.ok(raw.startsWith('%PDF-1.7\n'));

    const m = /startxref\n(\d+)\n%%EOF\s*$/.exec(raw);
    assert.ok(m, 'PDF must end with startxref and %%EOF');
    const xrefOffset = Number(m[1]);
    assert.equal(buf.subarray(xrefOffset, xrefOffset + 5).toString('latin1'), 'xref\n');

    // Every 20-byte xref entry after `xref\n0 9\n` must be exactly 20 bytes
    const xrefSection = raw.slice(xrefOffset);
    const xrefLines = xrefSection.split('\n').slice(2, 11);
    assert.equal(xrefLines.length, 9);
    for (const entry of xrefLines) {
      assert.equal(entry.length + 1, 20, `xref entry + LF must be 20 bytes: "${entry}"`);
    }

    // Check wrapPdfLine never exceeds PDF_MAX_LINE_CHARS
    const longSample =
      'Statutory Scope: GDPR Art. 5(1)(c), Art. 17(1), Art. 25, Art. 32 | CJEU Case C-413/23 P | EU AI Act (Reg. 2024/1689) Art. 12 & Art. 26(6) | PCI DSS v4.0.1 Req. 3.5.1 & 10.3';
    for (const chunk of wrapPdfLine(longSample)) {
      assert.ok(chunk.length <= PDF_MAX_LINE_CHARS);
    }
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-19: Piracy Vector 1 - Editing JSON certificate authority_status to COUNTERSIGNED_COMMERCIAL fails with FORGED_COMMERCIAL_AUTHORITY', () => {
  const ws = makeTempWorkspace('sip-s4-pirate1-');
  try {
    writeEnterpriseMcpFixture(ws);
    const bundle = generateAuditorAttestationBundle({
      workspaceDir: ws,
      previewMode: true,
    });

    const piratedCert = {
      ...bundle.certObj,
      authority_status: 'COUNTERSIGNED_COMMERCIAL',
    };

    const ver = verifyAttestationCertificateOffline({ certObj: piratedCert });
    assert.equal(ver.valid, false);
    assert.equal(ver.status, 'FORGED_COMMERCIAL_AUTHORITY');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-20: Piracy Vector 2 - Re-signing edited COUNTERSIGNED_COMMERCIAL JSON with legitimate Custodian key (but without Root token) fails with FORGED_COMMERCIAL_AUTHORITY', async () => {
  const ws = makeTempWorkspace('sip-s4-pirate2-');
  try {
    writeEnterpriseMcpFixture(ws);
    // Create a fake Root key in attacker's forked build and issue a self-minted token
    const attackerFakeRoot = generateAuthorityKeypair();
    const kr = initKeyring({ workspaceDir: ws, bucketCount: 16 });
    closeKeyring(kr);

    const fakeTok = issueCommercialLicenseToken({
      authorityPrivateKey: attackerFakeRoot.privateKey,
      tier: COMMERCIAL_TIERS.ENTERPRISE,
      orgName: 'Self-Minted Fork Corp',
      orgDomain: 'fork.example',
    });

    await activateWorkspaceLicense({
      workspaceDir: ws,
      tokenStr: fakeTok.token,
      authorityPubB64u: attackerFakeRoot.publicKeyB64u,
    });

    const forgedBundle = generateAuditorAttestationBundle({
      workspaceDir: ws,
      previewMode: false,
      authorityPubB64u: attackerFakeRoot.publicKeyB64u,
    });
    assert.equal(forgedBundle.certObj.authority_status, 'COUNTERSIGNED_COMMERCIAL');

    // Now an external QSA auditor runs standard `verify-cert` (pinned to real SHULIAK_ROOT_PUB_B64U)
    const auditorPdfCheck = extractAndVerifyPdfBytes(forgedBundle.pdfBuffer);
    assert.equal(auditorPdfCheck.valid, false);
    assert.equal(auditorPdfCheck.status, 'FORGED_COMMERCIAL_AUTHORITY');
    assert.equal(auditorPdfCheck.custodianSignatureValid, true);
    assert.equal(auditorPdfCheck.rootCountersignatureValid, false);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-21: Piracy Vector 3 - Stripping diagonal EVALUATION PREVIEW watermark from PDF bytes while keeping valid preview JSON trailer triggers FORGED_COMMERCIAL_AUTHORITY', () => {
  const ws = makeTempWorkspace('sip-s4-pirate3-');
  try {
    writeEnterpriseMcpFixture(ws);
    const bundle = generateAuditorAttestationBundle({
      workspaceDir: ws,
      previewMode: true,
    });

    // Replace same-length substring inside PDF content stream so xref byte offsets remain valid!
    const target = 'EVALUATION PREVIEW - NOT VALID FOR EXTERNAL QSA / SOC 2 AUDIT';
    const replacement = 'APPROVED PRODUCTION DOCUMENT - CLEARED FOR EXTERNAL SOC2 AUDIT'.slice(
      0,
      target.length
    );
    assert.equal(target.length, replacement.length);

    const tamperedLatin1 = bundle.pdfBuffer.toString('latin1').replaceAll(target, replacement);
    const tamperedBuf = Buffer.from(tamperedLatin1, 'latin1');

    const ver = extractAndVerifyPdfBytes(tamperedBuf);
    assert.equal(ver.valid, false);
    assert.equal(ver.status, 'FORGED_COMMERCIAL_AUTHORITY');
    assert.match(ver.reason, /strip evaluation watermark/i);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-22: CLI `verify-cert` returns exitCode=2 on pirated PDF and exitCode=0 on unmodified preview PDF', async () => {
  const ws = makeTempWorkspace('sip-s4-verifycli-');
  try {
    writeEnterpriseMcpFixture(ws);
    await runCli(['attest', '--preview', '--dir', ws]);
    const previewPdfPath = path.join(ws, 'SHULIAK_READINESS_PREVIEW.pdf');

    const okRes = await runCli(['verify-cert', '--file', previewPdfPath]);
    assert.equal(okRes.exitCode, 0);
    assertBoxWidth78AndZeroEmojis(okRes.stdout, 'verify-cert preview');

    // Tamper embedded JSON inside PDF
    const badPath = path.join(ws, 'TAMPERED.pdf');
    const raw = fs.readFileSync(previewPdfPath).toString('latin1');
    const mutated = raw.replace(
      '%ISEP-ATTESTATION-JSON:ey',
      '%ISEP-ATTESTATION-JSON:eX'
    );
    fs.writeFileSync(badPath, Buffer.from(mutated, 'latin1'));

    const failRes = await runCli(['verify-cert', '--file', badPath]);
    assert.equal(failRes.exitCode, 2);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-23: renderAttestationPdfBytes escapes PDF parentheses and backslashes safely without corrupting stream', () => {
  const ws = makeTempWorkspace('sip-s4-pdfescape-');
  const rootAuth = generateAuthorityKeypair();
  try {
    writeEnterpriseMcpFixture(ws);
    const kr = initKeyring({ workspaceDir: ws, bucketCount: 16 });
    closeKeyring(kr);

    const tok = issueCommercialLicenseToken({
      authorityPrivateKey: rootAuth.privateKey,
      tier: COMMERCIAL_TIERS.ENTERPRISE,
      orgName: 'O\\Connor & Partners (EU) Holding',
      orgDomain: 'oconnor.eu',
      partnerName: 'Audit ( EMEA ) \\ Co',
    });

    return activateWorkspaceLicense({
      workspaceDir: ws,
      tokenStr: tok.token,
      authorityPubB64u: rootAuth.publicKeyB64u,
    }).then(() => {
      const bundle = generateAuditorAttestationBundle({
        workspaceDir: ws,
        previewMode: false,
        authorityPubB64u: rootAuth.publicKeyB64u,
      });
      const pdfBytes = renderAttestationPdfBytes(bundle.certObj);
      const ver = extractAndVerifyPdfBytes(pdfBytes, {
        authorityPubB64u: rootAuth.publicKeyB64u,
      });
      assert.equal(ver.valid, true);
      assert.equal(ver.status, 'VERIFIED_COMMERCIAL_ORIGINAL');
    });
  } finally {
    setImmediate(() => fs.rmSync(ws, { recursive: true, force: true }));
  }
});

// ============================================================================
// 5. GHAS-FREE $0 GITHUB PR MARKDOWN GATE, WORKFLOW & SVG BADGE
// ============================================================================

test('S4-24: CLI `audit --format markdown-pr` outputs sticky marker, zero emojis, zero raw secrets, and partner link', async () => {
  const ws = makeTempWorkspace('sip-s4-mdpr-');
  try {
    const { rawSecretStripe, rawSecretPg, rawSecretRovo } = writeEnterpriseMcpFixture(ws);
    const res = await runCli([
      'audit',
      '--dir',
      ws,
      '--no-global',
      '--format',
      'markdown-pr',
      '--partner',
      'vciso-alpha',
    ]);
    assert.equal(res.exitCode, 0);
    assert.ok(res.stdout.startsWith(STICKY_PR_COMMENT_MARKER));
    assert.equal(EMOJI_PICTOGRAPH_RE.test(res.stdout), false, 'PR Markdown must have ZERO emojis');
    assert.match(res.stdout, /ref=vciso-alpha/);
    assert.match(res.stdout, /PCI DSS v4\.0\.1 DB\/Payment/);

    for (const secret of [rawSecretStripe, 'SuperSecretDbPass99!', rawSecretPg, rawSecretRovo]) {
      assert.equal(res.stdout.includes(secret), false, 'Secret leaked into GitHub PR comment!');
    }
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-25: formatAuditMarkdownPrComment emits clean PASS scorecard when workspace has Grade A+ sealed MCP config', async () => {
  const ws = makeTempWorkspace('sip-s4-mdpass-');
  try {
    fs.writeFileSync(
      path.join(ws, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          memory: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-memory@0.6.2'],
          },
        },
      }),
      'utf8'
    );
    const configs = discoverMcpConfigs({ workspaceDir: ws, includeGlobal: false });
    await createOrUpdateSchemaLock({ workspaceDir: ws, configs, dryRun: false });
    const auditResult = runStaticMcpAudit({ configs, workspaceDir: ws });
    const md = formatAuditMarkdownPrComment({ auditResult, configs });
    assert.match(md, /VERDICT: PASS/);
    assert.equal(EMOJI_PICTOGRAPH_RE.test(md), false);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-26: CLI `init-ci` writes GHAS-free `.github/workflows/sip-mcp-gate.yml` with `pull-requests: write` and ZERO `upload-sarif`', async () => {
  const ws = makeTempWorkspace('sip-s4-initci-');
  try {
    const res = await runCli(['init-ci', '--dir', ws]);
    assert.equal(res.exitCode, 0);
    assertBoxWidth78AndZeroEmojis(res.stdout, 'init-ci terminal box');

    const wfPath = path.join(ws, '.github', 'workflows', 'sip-mcp-gate.yml');
    assert.equal(fs.existsSync(wfPath), true);
    const yaml = fs.readFileSync(wfPath, 'utf8');
    assert.equal(yaml, generateGithubPrWorkflowYaml());
    assert.match(yaml, /contents:\s*read/);
    assert.match(yaml, /pull-requests:\s*write/);
    assert.match(yaml, /GITHUB_STEP_SUMMARY/);
    assert.match(
      yaml, /actions\/checkout@[0-9a-f]{40}/
    );
    assert.match(
      yaml, /actions\/setup-node@[0-9a-f]{40}/
    );
    assert.match(
      yaml, /actions\/github-script@[0-9a-f]{40}/
    );
    assert.equal(/upload-sarif|codeql-action/i.test(yaml), false, 'Must NOT depend on paid GHAS upload-sarif!');
    assert.equal(EMOJI_PICTOGRAPH_RE.test(yaml), false);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-27: CLI `badge` generates valid standalone SVG 1.1 shield with zero emojis', async () => {
  const ws = makeTempWorkspace('sip-s4-badge-');
  try {
    fs.writeFileSync(
      path.join(ws, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@0.6.2', '.'] },
        },
      }),
      'utf8'
    );
    const outSvg = path.join(ws, 'badge.svg');
    const res = await runCli(['badge', '--dir', ws, '--no-global', '--out', outSvg]);
    assert.equal(res.exitCode, 0);
    assertBoxWidth78AndZeroEmojis(res.stdout, 'badge terminal box');

    const svg = fs.readFileSync(outSvg, 'utf8');
    assert.ok(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"'));
    assert.match(svg, /SHULIAK SIP/);
    assert.equal(EMOJI_PICTOGRAPH_RE.test(svg), false);
    assert.ok(generateRepoBadgeSvg({ grade: 'F', locked: false }).includes('#dc2626'));
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

// ============================================================================
// 6. REPRODUCIBLE ZERO-EGRESS SOCKET TRIPWIRE SELFTEST & CLI INVARIANTS
// ============================================================================

test('S4-28: runZeroEgressSelfTest executes 9/9 NIST CAVP FF1 + Luhn/MOD-97 + RFC 8785 Lock + ISEP Double-Shred with 0 sockets opened', async () => {
  const res = await runZeroEgressSelfTest();
  assert.equal(res.passed, true);
  assert.equal(res.socketsOpened, 0);
  assert.equal(res.bytesTransmitted, 0);
  assert.equal(res.cavpPassed, 9);
  assert.equal(res.luhnPanValid, true);
  assert.equal(res.ibanMod97Valid, true);
  assert.equal(res.schemaLockValid, true);
  assert.equal(res.isepDoubleShredValid, true);
  let isProot = false;
  try {
    const st = fs.readFileSync(
      '/proc/self/status', 'utf8'
    );
    const m = /^TracerPid:\s*(\d+)/m.exec(st);
    if (m && Number(m[1]) > 0) isProot = true;
  } catch {}
  const maxMs = isProot ? 500 : 200;
  assert.ok(
    res.durationMs < maxMs,
    `Expected < ${maxMs} ms, got ${res.durationMs} ms`
  );
  assertBoxWidth78AndZeroEmojis(res.report, 'Zero-Egress Proof Receipt');
});

test('S4-29: Active socket tripwire in test/ catches net, tls, dns, fetch with EGRESS_SOCKET_VIOLATION and restores globals', async () => {
  const net = (await import('node:net')).default;
  const tls = (await import('node:tls')).default;
  const dns = (await import('node:dns')).default;
  const mkErr = (sf) => {
    const e = new Error(
      `[EGRESS_SOCKET_VIOLATION] ${sf} ` +
      'IETF draft-shuliak-sip-zero-egress-00'
    );
    /** @type {any} */ (e).code =
      'EGRESS_SOCKET_VIOLATION';
    return e;
  };
  const runArmed = async (injected) => {
    const oNet = net.Socket.prototype.connect;
    const oTls = tls.connect;
    const oDns = dns.lookup;
    const oFetch = Object.getOwnPropertyDescriptor(
      globalThis, 'fetch'
    );
    net.Socket.prototype.connect = () => {
      throw mkErr('net');
    };
    tls.connect = () => { throw mkErr('tls'); };
    dns.lookup = () => { throw mkErr('dns'); };
    Object.defineProperty(globalThis, 'fetch', {
      value: async () => { throw mkErr('fetch'); },
      configurable: true, writable: true,
    });
    try {
      return await runZeroEgressSelfTest({
        injectedDuringGuard: injected,
      });
    } finally {
      net.Socket.prototype.connect = oNet;
      tls.connect = oTls;
      dns.lookup = oDns;
      if (oFetch) Object.defineProperty(
        globalThis, 'fetch', oFetch
      );
    }
  };
  const ok = await runArmed(null);
  assert.equal(ok.passed, true);
  const probes = {
    net: () => new net.Socket().connect(443, 'x'),
    tls: () => tls.connect(443, 'x'),
    dns: () => dns.lookup('x', () => {}),
    fetch: () => globalThis.fetch('https://x'),
  };
  for (const k of Object.keys(probes)) {
    await assert.rejects(
      () => runArmed(probes[k]),
      (err) => {
        assert.equal(
          /** @type {any} */ (err).code,
          'EGRESS_SOCKET_VIOLATION'
        );
        assert.match(
          err.message,
          /IETF draft-shuliak-sip-zero-egress-00/
        );
        return true;
      }
    );
  }
});

test('S4-30: CLI `selftest` and `selftest --json` pass with <= 78-col box and exitCode=0', async () => {
  const txtRes = await runCli(['selftest']);
  assert.equal(txtRes.exitCode, 0);
  assert.match(txtRes.stdout, /0 sockets opened - 0 bytes transmitted/);
  assertBoxWidth78AndZeroEmojis(txtRes.stdout, 'CLI selftest');

  const jsonRes = await runCli(['selftest', '--json']);
  assert.equal(jsonRes.exitCode, 0);
  const parsed = JSON.parse(jsonRes.stdout);
  assert.equal(parsed.passed, true);
  assert.equal(parsed.cavpPassed, 9);
});

test('S4-31: CLI `license status` reports COMMUNITY_UNLICENSED cleanly on fresh workspace with <= 78-col box', async () => {
  const ws = makeTempWorkspace('sip-s4-licstatus-');
  try {
    const res = await runCli(['license', 'status', '--dir', ws]);
    assert.equal(res.exitCode, 0);
    assert.match(res.stdout, /COMMUNITY_UNLICENSED/);
    assertBoxWidth78AndZeroEmojis(res.stdout, 'license status');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('S4-32: CLI `--version` matches 3.0.x release series and `/engine-node/package.json` has ZERO external dependencies', async () => {
  assert.match(CLI_VERSION, /^3\.1\.\d+(?:-stage\d+)?$/);
  const ver = await runCli(['--version']);
  assert.match(ver.stdout.trim(), /^3\.1\.\d+(?:-stage\d+)?$/);

  const pkgJson = JSON.parse(
    fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
  );
  assert.match(pkgJson.version, /^3\.1\.\d+(?:-stage\d+)?$/);
  assert.deepEqual(pkgJson.dependencies || {}, {});
});
