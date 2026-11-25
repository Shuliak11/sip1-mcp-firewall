/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 4 OWASP CycloneDX 1.6 AIBOM & PCI DSS 4.0.1 / Atlassian Rovo Scope Analyzer
 * Zero external dependencies. Guarantees ZERO raw credential leakage.
 */

import path from 'node:path';
import { compareUtf16CodeUnits, jcsCanonicalize } from '../core/jcs.mjs';
import { b64u, domainSha256 } from '../core/crypto-primitives.mjs';
import { redactStringForLockPreview } from '../stage1/audit-scanner.mjs';

export const DOMAIN_PREFIX_AIBOM = 0x08;

const CONNECTOR_SIGNATURES = Object.freeze([
  {
    category: 'PAYMENT',
    vendor: 'Stripe / Payment Processor',
    re: /\b(?:stripe|adyen|braintree|paypal|checkout|sepa|treasury|cardholder|payment)\b/i,
    pciRelevant: true,
    rovoRelevant: false,
  },
  {
    category: 'DATABASE',
    vendor: 'Relational / NoSQL Data Store',
    re: /\b(?:postgres|postgresql|pg|mysql|mariadb|supabase|redis|mongodb|cockroach|sqlite|prisma|drizzle)\b/i,
    pciRelevant: true,
    rovoRelevant: false,
  },
  {
    category: 'TICKETING_ROVO',
    vendor: 'Atlassian Rovo / Jira / Confluence',
    re: /(?:mcp\.atlassian\.com|\b(?:rovo|atlassian|jira|confluence|servicenow|zendesk|linear)\b)/i,
    pciRelevant: false,
    rovoRelevant: true,
  },
  {
    category: 'CLOUD_DEVOPS',
    vendor: 'Cloud / SCM / Collaboration',
    re: /\b(?:github|gitlab|slack|aws|gcp|azure|kubernetes|terraform)\b/i,
    pciRelevant: false,
    rovoRelevant: false,
  },
]);

/**
 * Inspect discovered MCP servers for Database, Payment, Cloud, and Atlassian Rovo / Jira connectors.
 * Computes PCI DSS v4.0.1 Req. 3.5.1 & 10.3 scope status and Rovo credit/PII exposure posture
 * without ever exposing raw environment values or headers.
 *
 * @param {{
 *   configs: Array<any>,
 *   auditResult?: any,
 *   isepActive?: boolean,
 *   lockActive?: boolean,
 * }} params
 */
export function analyzeEnterpriseScopeExposure({
  configs,
  auditResult = null,
  isepActive = false,
  lockActive = false,
}) {
  const safeConfigs = Array.isArray(configs) ? configs : [];
  const effectiveLockActive = Boolean(lockActive || auditResult?.lockStatus === 'SEALED_VERIFIED');
  /** @type {Array<{
   *   serverName: string,
   *   client: string,
   *   transport: string,
   *   categories: string[],
   *   vendors: string[],
   *   pciRelevant: boolean,
   *   rovoRelevant: boolean,
   *   envKeysOnly: string[],
   *   redactedTarget: string,
   * }>} */
  const detectedConnectors = [];

  for (const cfg of safeConfigs) {
    for (const srv of cfg.servers || []) {
      const safeTarget =
        redactStringForLockPreview(srv.url) ||
        [
          redactStringForLockPreview(srv.command) || '',
          ...(srv.args || []).map((a) => redactStringForLockPreview(a) || ''),
        ]
          .filter(Boolean)
          .join(' ');

      const envKeys = Object.keys(srv.env || {}).sort(compareUtf16CodeUnits);
      const searchCorpus = [
        srv.serverName || '',
        srv.command || '',
        ...(srv.args || []).map((a) => redactStringForLockPreview(a) || ''),
        redactStringForLockPreview(srv.url) || '',
        ...envKeys,
      ].join(' ');

      const matchedCategories = [];
      const matchedVendors = [];
      let pciRelevant = false;
      let rovoRelevant = false;

      for (const sig of CONNECTOR_SIGNATURES) {
        if (sig.re.test(searchCorpus)) {
          matchedCategories.push(sig.category);
          matchedVendors.push(sig.vendor);
          if (sig.pciRelevant) pciRelevant = true;
          if (sig.rovoRelevant) rovoRelevant = true;
        }
      }

      if (matchedCategories.length > 0) {
        detectedConnectors.push({
          serverName: String(srv.serverName),
          client: String(srv.client || cfg.client || 'mcp-config'),
          transport: String(srv.transport || (srv.url ? 'http' : 'stdio')),
          categories: matchedCategories,
          vendors: matchedVendors,
          pciRelevant,
          rovoRelevant,
          envKeysOnly: envKeys,
          redactedTarget: safeTarget || '(stdio)',
        });
      }
    }
  }

  const pciConnectors = detectedConnectors.filter((c) => c.pciRelevant);
  const rovoConnectors = detectedConnectors.filter((c) => c.rovoRelevant);

  const pciDssScopeStatus = {
    standard: 'PCI DSS v4.0.1 Req. 3.5.1 & 10.3',
    cryptoMechanism: 'NIST SP 800-38G Rev. 1 FF1 (Luhn PAN & ISO-7064 MOD-97 IBAN Synthetic Twins)',
    inScopeConnectorCount: pciConnectors.length,
    inScopeServers: pciConnectors.map((c) => `${c.client}::${c.serverName}`),
    status:
      pciConnectors.length === 0
        ? 'NO_PAYMENT_OR_DB_CONNECTORS_DETECTED'
        : isepActive && effectiveLockActive
          ? 'INLINE_FF1_CONTROLS_ACTIVE_FOR_SCOPE_REDUCTION'
          : isepActive
            ? 'SCOPE_REDUCED_VIA_INLINE_FF1_TWINS'
            : 'CLEARTEXT_PAN_SCOPE_EXPOSURE_DETECTED',
    summary:
      pciConnectors.length === 0
        ? 'No payment or database MCP connectors detected in scanned configuration.'
        : isepActive
          ? `Inline NIST SP 800-38G Rev. 1 FF1 twin controls active across ${pciConnectors.length} payment/DB connector(s), keeping downstream LLM context and audit skeleton logs out of cleartext PAN scope under PCI DSS v4.0.1 Req. 3.5.1 & 10.3.`
          : `Detected ${pciConnectors.length} payment/DB connector(s) (${pciConnectors.map((c) => c.serverName).join(', ')}) without active ISEP FF1 twin interception; cleartext PAN/IBAN values returned by tools pull agent logs into PCI DSS v4.0.1 Req. 3.5.1 & 10.3 audit scope.`,
  };

  const rovoCreditPiiExposure = {
    standard: 'GDPR Art. 5(1)(c), Art. 17(1), Art. 25, Art. 32 & SOC 2 CC7.2 & P4',
    connectorCount: rovoConnectors.length,
    rovoServers: rovoConnectors.map((c) => `${c.client}::${c.serverName}`),
    status:
      rovoConnectors.length === 0
        ? 'NO_ROVO_OR_TICKETING_CONNECTORS'
        : isepActive
          ? 'GUARDED_FINOPS_FUSE_AND_PII_DETACHMENT'
          : 'UNMETERED_LOOP_CREDIT_AND_TICKET_PII_RISK',
    summary:
      rovoConnectors.length === 0
        ? 'No Atlassian Rovo, Jira, or Confluence MCP connectors detected.'
        : isepActive
          ? `Guarded ${rovoConnectors.length} Rovo/Jira connector(s) with Stage 2 FinOps velocity fuse and Stage 3 B_i sidecar PII detachment for GDPR Art. 17(1) erasure.`
          : `Detected ${rovoConnectors.length} Atlassian Rovo/Jira connector(s) (${rovoConnectors.map((c) => c.serverName).join(', ')}) exposed to autonomous agent loop credit drain and unredacted customer ticket PII ingestion.`,
  };

  return {
    totalEnterpriseConnectors: detectedConnectors.length,
    detectedConnectors,
    hasEnterpriseConnectors: detectedConnectors.length > 0,
    pciDssScopeStatus,
    rovoCreditPiiExposure,
    auditGrade: auditResult?.grade || 'UNSCANNED',
  };
}

/**
 * Generate a deterministic OWASP CycloneDX 1.6 AI/MCP Bill of Materials (`bomFormat: "CycloneDX"`,
 * `specVersion: "1.6"`) sealed with domain prefix `0x08` over RFC 8785 JCS.
 * Guarantees ZERO raw secrets in components, services, properties, or vulnerabilities.
 *
 * @param {{
 *   workspaceDir: string,
 *   configs: Array<any>,
 *   auditResult: any,
 *   isepSummary?: any,
 * }} params
 */
export function generateCycloneDxAibom({
  workspaceDir,
  configs,
  auditResult,
  isepSummary = null,
  lockActive = false,
}) {
  const resolvedDir = path.resolve(workspaceDir || process.cwd());
  const safeConfigs = Array.isArray(configs) ? configs : [];
  const isepActive = Boolean(
    isepSummary &&
      (isepSummary.status === 'VALID_UNMODIFIED' ||
        isepSummary.status === 'VALID_WITH_LAWFUL_ERASURES')
  );

  const scopeAnalysis = analyzeEnterpriseScopeExposure({
    configs: safeConfigs,
    auditResult,
    isepActive,
    lockActive: Boolean(lockActive || auditResult?.lockStatus === 'SEALED_VERIFIED'),
  });

  const components = [];
  const services = [];

  for (const cfg of safeConfigs) {
    const relCfg = path.relative(resolvedDir, cfg.filePath || '.mcp.json').replace(/\\/g, '/');
    for (const srv of cfg.servers || []) {
      const safeCommand = redactStringForLockPreview(srv.command);
      const safeArgs = (srv.args || []).map((a) => redactStringForLockPreview(a) || '');
      const safeUrl = redactStringForLockPreview(srv.url);
      const envKeysOnly = Object.keys(srv.env || {}).sort(compareUtf16CodeUnits);
      const headerKeysOnly = Object.keys(srv.headers || {}).sort(compareUtf16CodeUnits);
      const bomRef = `mcp-server:${srv.client || cfg.client}:${srv.serverName}`;

      components.push({
        type: 'application',
        'bom-ref': bomRef,
        name: String(srv.serverName),
        group: String(srv.client || cfg.client || 'mcp-client'),
        version: extractPinnedVersionOrUnpinned(safeArgs),
        description: `MCP ${srv.transport || 'stdio'} connector declared in ${relCfg || path.basename(cfg.filePath || '.mcp.json')}`,
        properties: [
          { name: 'shuliak:mcp:client', value: String(srv.client || cfg.client || 'mcp-config') },
          { name: 'shuliak:mcp:transport', value: String(srv.transport || (srv.url ? 'http' : 'stdio')) },
          { name: 'shuliak:mcp:command', value: safeCommand || '(remote-http)' },
          { name: 'shuliak:mcp:argsRedacted', value: safeArgs.join(' ') || '(none)' },
          { name: 'shuliak:mcp:envKeysOnly', value: envKeysOnly.join(',') || '(none)' },
          { name: 'shuliak:mcp:headerKeysOnly', value: headerKeysOnly.join(',') || '(none)' },
        ],
      });

      if (safeUrl) {
        services.push({
          'bom-ref': `mcp-endpoint:${srv.client || cfg.client}:${srv.serverName}`,
          name: `${srv.serverName}-remote-transport`,
          endpoints: [safeUrl],
          authenticated: headerKeysOnly.length > 0,
          'x-trust-boundary': true,
        });
      }
    }
  }

  components.sort((a, b) => compareUtf16CodeUnits(a['bom-ref'], b['bom-ref']));
  services.sort((a, b) => compareUtf16CodeUnits(a['bom-ref'], b['bom-ref']));

  const vulnerabilities = (auditResult?.findings || []).map((f, idx) => ({
    'bom-ref': `sip-finding-${idx + 1}-${f.ruleId}`,
    id: f.ruleId,
    source: {
      name: 'SHULIAK SIP v3.0 Deterministic Scanner',
      url: 'https://shuliak.dev',
    },
    ratings: [
      {
        severity: String(f.severity || 'MEDIUM').toLowerCase(),
        method: 'other',
      },
    ],
    description: String(f.message),
    recommendation: String(f.remediation),
    affects: [
      {
        ref: `mcp-server:${f.client}:${f.serverName}`,
      },
    ],
  }));

  const corePayloadForHash = {
    bomFormat: 'CycloneDX',
    components,
    pciDssStatus: scopeAnalysis.pciDssScopeStatus.status,
    rovoExposureStatus: scopeAnalysis.rovoCreditPiiExposure.status,
    score: auditResult?.score ?? 100,
    services,
    specVersion: '1.6',
    version: 1,
    vulnerabilities,
  };

  const digestBuf = domainSha256(DOMAIN_PREFIX_AIBOM, jcsCanonicalize(corePayloadForHash));
  const aibomDigestB64u = b64u(digestBuf);
  const deterministicUuidHex = digestBuf.subarray(0, 16).toString('hex');
  const serialUuid = [
    deterministicUuidHex.slice(0, 8),
    deterministicUuidHex.slice(8, 12),
    '4' + deterministicUuidHex.slice(13, 16),
    '8' + deterministicUuidHex.slice(17, 20),
    deterministicUuidHex.slice(20, 32),
  ].join('-');

  const bom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${serialUuid}`,
    version: 1,
    metadata: {
      timestamp: auditResult?.scannedAt || new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            group: '@shuliak-corp',
            name: 'sip1-mcp',
            version: '3.1.0',
          },
        ],
      },
      properties: [
        { name: 'shuliak:sip:domainPrefix', value: '0x08' },
        { name: 'shuliak:sip:aibomDigest0x08', value: aibomDigestB64u },
        { name: 'shuliak:sip:auditGrade', value: String(auditResult?.grade || 'A+') },
        { name: 'shuliak:sip:auditScore', value: String(auditResult?.score ?? 100) },
        { name: 'shuliak:sip:pciDssScopeStatus', value: scopeAnalysis.pciDssScopeStatus.status },
        { name: 'shuliak:sip:rovoExposureStatus', value: scopeAnalysis.rovoCreditPiiExposure.status },
        {
          name: 'shuliak:sip:isepChainStatus',
          value: String(isepSummary?.status || 'UNINITIALIZED_READINESS_BASELINE'),
        },
        {
          name: 'shuliak:sip:doraAlignment',
          value: 'DORA (Reg. (EU) 2022/2554) Art. 17',
        },
        {
          name: 'shuliak:sip:euAiOmnibusAlignment',
          value: 'EU AI Omnibus Reg. (EU) 2026/1744',
        },
      ],
    },
    components,
    services,
    vulnerabilities,
  };

  return {
    bom,
    aibomDigestB64u,
    scopeAnalysis,
  };
}

/**
 * Extract pinned package version if visible in redacted args, otherwise `'unpinned'`.
 * @param {string[]} safeArgs
 * @returns {string}
 */
function extractPinnedVersionOrUnpinned(safeArgs) {
  for (const arg of safeArgs) {
    if (!arg || arg.startsWith('-')) continue;
    const atIdx = arg.startsWith('@') ? arg.indexOf('@', 1) : arg.indexOf('@');
    if (atIdx > 0) {
      const ver = arg.slice(atIdx + 1);
      if (/^\d+\.\d+\.\d+/.test(ver)) {
        return ver;
      }
    }
    if (arg.includes('==')) {
      const ver = arg.split('==')[1];
      if (ver && /^\d+\.\d+/.test(ver)) {
        return ver;
      }
    }
  }
  return 'unpinned';
}
