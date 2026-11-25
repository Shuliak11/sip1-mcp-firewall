/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 4 GHAS-Free $0 GitHub PR Markdown Commenter, Workflow & SVG Badge Engine
 * Zero external dependencies. Zero emojis. Zero raw credential leakage.
 */

import { buildPartnerUpgradeUrl } from './auditor-attestation.mjs';
import { analyzeEnterpriseScopeExposure } from './cyclonedx-aibom.mjs';

export const STICKY_PR_COMMENT_MARKER = '<!-- shuliak-sip-mcp-pr-gate -->';

/**
 * Escape Markdown table cells (`|` and newlines) cleanly.
 * @param {string} str
 * @returns {string}
 */
function escapeMdCell(str) {
  return String(str ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\|/g, '\\|')
    .trim();
}

/**
 * Format a deterministic, Screenshot-Safe GitHub Pull Request Markdown Scorecard.
 * - Zero emojis anywhere in Markdown output.
 * - Zero raw credentials (uses masked previews only).
 * - Requires ZERO paid GitHub Advanced Security (GHAS) seats when posted via `pull-requests: write`.
 *
 * @param {{
 *   auditResult: any,
 *   lockVerification?: any,
 *   scopeAnalysis?: any,
 *   configs?: Array<any>,
 *   partnerCode?: string | null,
 *   checkoutUrl?: string,
 * }} params
 * @returns {string}
 */
export function formatAuditMarkdownPrComment({
  auditResult,
  lockVerification = null,
  scopeAnalysis = null,
  configs = [],
  partnerCode = null,
  checkoutUrl = 'https://shuliak.dev/#pricing',
}) {
  const resolvedScope =
    scopeAnalysis ||
    analyzeEnterpriseScopeExposure({
      configs,
      auditResult,
      isepActive: false,
    });

  const grade = String(auditResult?.grade || 'F');
  const score = Number(auditResult?.score ?? 0);
  const lockStatus = lockVerification
    ? lockVerification.valid
      ? 'SEALED_VERIFIED (RFC 8785 + Ed25519)'
      : `${lockVerification.status} (Unsealed / Drift)`
    : auditResult?.lockStatus || 'MISSING_LOCK';

  const findings = Array.isArray(auditResult?.findings) ? auditResult.findings : [];
  const plane14Findings = findings.filter((f) => f.ruleId === 'SIP-R03');
  const secretFindings = findings.filter((f) => f.ruleId === 'SIP-R01');

  const unicodeStatus =
    plane14Findings.length === 0
      ? 'PASS (0 invisible Plane-14 / Bidi codepoints)'
      : `CRITICAL (${plane14Findings.length} Plane-14 / Bidi smuggling vector(s))`;

  const pciCount = resolvedScope.pciDssScopeStatus?.inScopeConnectorCount ?? 0;
  const rovoCount = resolvedScope.rovoCreditPiiExposure?.connectorCount ?? 0;
  const connectorSummary =
    pciCount === 0 && rovoCount === 0
      ? '0 Payment/DB/Rovo connectors detected'
      : `${pciCount} PCI DSS v4.0.1 DB/Payment | ${rovoCount} Atlassian Rovo/Jira`;

  const secretStatus =
    secretFindings.length === 0
      ? 'PASS (0 plaintext credentials exposed)'
      : `CRITICAL (${secretFindings.length} masked credential finding(s))`;

  const upgradeLink = buildPartnerUpgradeUrl(checkoutUrl, partnerCode);

  const lines = [
    STICKY_PR_COMMENT_MARKER,
    '### SHULIAK SIP v3.0 - Zero-Egress MCP Supply-Chain & Governance Scorecard',
    '',
    '| Control Plane Dimension | Verdict / Telemetry | Statutory & Technical Standard |',
    '| :--- | :--- | :--- |',
    `| **Overall Security Grade** | **Grade ${escapeMdCell(grade)}** (${score}/100 in ${Number(auditResult?.durationMs ?? 0).toFixed(2)} ms) | SOC 2 CC7.2 & P4 / ISO/IEC 42001:2023 A.6.2.8 |`,
    `| **RFC 8785 Schema Lock** | \`${escapeMdCell(lockStatus)}\` | 0x06 JCS SHA-256 + RFC 8032 Ed25519 |`,
    `| **Unicode Plane-14 Smuggling** | \`${escapeMdCell(unicodeStatus)}\` | Trojan-Source & U+E0000..U+E007F Guard |`,
    `| **Plaintext Credential Scan** | \`${escapeMdCell(secretStatus)}\` | Screenshot-Safe Masked Entropy Filter |`,
    `| **PCI DSS 4.0.1 / Rovo Connectors** | \`${escapeMdCell(connectorSummary)}\` | PCI DSS v4.0.1 Req. 3.5.1 & 10.3 / GDPR Art. 17(1) |`,
    '',
  ];

  if (findings.length === 0) {
    lines.push(
      '> **VERDICT: PASS** - Zero configuration vulnerabilities detected across all scanned MCP manifests.'
    );
    lines.push('');
  } else {
    lines.push(`#### Detected Findings (${findings.length}) - Screenshot-Safe Redacted`);
    lines.push('');
    lines.push('| Rule | Severity | Target Server | Redacted Diagnostic | Recommended Remediation |');
    lines.push('| :--- | :--- | :--- | :--- | :--- |');
    for (const f of findings) {
      lines.push(
        `| \`${escapeMdCell(f.ruleId)}\` | **${escapeMdCell(f.severity)}** | \`${escapeMdCell(`${f.client}::${f.serverName}`)}\` | ${escapeMdCell(f.message)} | ${escapeMdCell(f.remediation)} |`
      );
    }
    lines.push('');
    lines.push('```sh');
    lines.push('# Seal MCP manifests locally with RFC 8785 JCS + Ed25519 before pushing:');
    lines.push('npx -y @shuliak-corp/sip1-mcp lock --install-hooks');
    lines.push('```');
    lines.push('');
  }

  lines.push('---');
  lines.push(
    `Need countersigned SOC 2 / ISO 42001 / PCI DSS 4.0.1 / GDPR Art. 17 audit evidence? Activate org key at ${upgradeLink}`
  );

  return lines.join('\n') + '\n';
}

/**
 * Generate a ready-to-drop `.github/workflows/sip-mcp-gate.yml` workflow that works on ANY private
 * or public GitHub repository for $0 WITHOUT requiring paid GitHub Advanced Security (GHAS) seats!
 * - Uses standard `permissions: { contents: read, pull-requests: write }`
 * - Zero `github/codeql-action/upload-sarif` dependency
 * - Writes `$GITHUB_STEP_SUMMARY` and posts/updates sticky PR comment via `actions/github-script@v7`
 *
 * @returns {string}
 */
export function generateGithubPrWorkflowYaml() {
  return `# SHULIAK SIP v3.0 - GHAS-Free $0 GitHub Pull Request MCP Governance Gate
# Zero GitHub Advanced Security (GHAS) seats required. Zero outbound telemetry.
name: SHULIAK SIP MCP Security Gate

on:
  pull_request:
    paths:
      - '.mcp.json'
      - '.cursor/**'
      - '.vscode/**'
      - '.claude/**'
      - '.sip/**'
      - '.github/workflows/sip-mcp-gate.yml'
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write

jobs:
  sip-mcp-audit:
    name: Deterministic MCP Audit & RFC 8785 Lock Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Setup Node.js 20
        uses: actions/setup-node@39370e3970a6d050c480ffad7ff0ed4d3fdee5af # v4.1.0
        with:
          node-version: '20'

      - name: Generate Screenshot-Safe PR Scorecard
        id: sip_audit
        run: |
          npx -y @shuliak-corp/sip1-mcp audit --no-global --format markdown-pr > sip-pr-scorecard.md
          cat sip-pr-scorecard.md >> "$GITHUB_STEP_SUMMARY"

      - name: Upsert Sticky Pull Request Scorecard Comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        with:
          script: |
            const fs = require('node:fs');
            const marker = '${STICKY_PR_COMMENT_MARKER}';
            const body = fs.readFileSync('sip-pr-scorecard.md', 'utf8');
            const { owner, repo } = context.repo;
            const issue_number = context.issue.number;
            const comments = await github.paginate(github.rest.issues.listComments, {
              owner,
              repo,
              issue_number,
              per_page: 100,
            });
            const existing = comments.find((c) => c.body && c.body.includes(marker));
            if (existing) {
              await github.rest.issues.updateComment({
                owner,
                repo,
                comment_id: existing.id,
                body,
              });
            } else {
              await github.rest.issues.createComment({
                owner,
                repo,
                issue_number,
                body,
              });
            }

      - name: Enforce Fail-Closed CI Threshold (Block Grade C/D/F)
        run: npx -y @shuliak-corp/sip1-mcp audit --no-global --ci --fail-on C
`;
}

/**
 * Generate a crisp, zero-dependency vector SVG shield (`SHULIAK SIP | Grade A+`).
 * Zero emojis. Valid standalone XML SVG 1.1.
 *
 * @param {{ grade?: string, locked?: boolean }} [params]
 * @returns {string}
 */
export function generateRepoBadgeSvg({ grade = 'A+', locked = true } = {}) {
  const safeGrade = String(grade || 'A+').replace(/[^A-F+]/gi, '').toUpperCase() || 'A+';
  const statusLabel = locked ? `Grade ${safeGrade} - SEALED` : `Grade ${safeGrade}`;

  const colorHex =
    safeGrade === 'A+' || safeGrade === 'A'
      ? '#059669'
      : safeGrade === 'B'
        ? '#0284c7'
        : safeGrade === 'C'
          ? '#d97706'
          : '#dc2626';

  const leftWidth = 92;
  const rightWidth = locked ? 114 : 74;
  const totalWidth = leftWidth + rightWidth;
  const rightCenter = leftWidth + Math.round(rightWidth / 2);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="SHULIAK SIP: ${statusLabel}">
  <title>SHULIAK SIP: ${statusLabel}</title>
  <clipPath id="sip-r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#sip-r)">
    <rect width="${leftWidth}" height="20" fill="#09090b"/>
    <rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${colorHex}"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="46" y="14" font-weight="bold">SHULIAK SIP</text>
    <text x="${rightCenter}" y="14" font-weight="bold">${statusLabel}</text>
  </g>
</svg>
`;
}
