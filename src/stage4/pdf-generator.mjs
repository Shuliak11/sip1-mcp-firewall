/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 4 Byte-Exact Zero-Dependency Vector PDF 1.7 A4 Generator & Verifier
 * Zero external dependencies. Uses built-in Type1 `/Helvetica`, `/Helvetica-Bold`, `/Courier`.
 *
 * Guarantees:
 * - Exact `Buffer.byteLength` `xref` table offsets (20-byte ISO 32000-1 entries)
 * - Clean `(`, `)`, `\` PDF literal escaping and strict ASCII WinAnsi normalization
 * - Max 84 chars per line across all text blocks -> ZERO right-edge clipping on A4 (595 x 842 pt)
 * - Diagonal evaluation watermark + $299/mo self-serve CTA box when unlicensed/preview
 * - Obsidian & Emerald executive banner + Channel Partner attribution when Root-countersigned
 * - Embedded `%ISEP-ATTESTATION-JSON:<base64url>` trailer + visual stream anti-spoofing check
 */

import { Buffer } from 'node:buffer';
import { b64u, unb64u } from '../core/crypto-primitives.mjs';
import { resolveDefaultAuthorityPubB64u } from './license-authority.mjs';
import { verifyAttestationCertificateOffline } from './auditor-attestation.mjs';

export const PDF_TRAILER_JSON_PREFIX = '%ISEP-ATTESTATION-JSON:';
export const PDF_MAX_LINE_CHARS = 84;

const WATERMARK_TEXT = 'EVALUATION PREVIEW - NOT VALID FOR EXTERNAL QSA / SOC 2 AUDIT';
const COMMERCIAL_BANNER_TEXT =
  '[VERIFIED COMMERCIAL ATTESTATION - SHULIAK ROOT ED25519 COUNTERSIGNED]';
const PREVIEW_BANNER_TEXT =
  '[EVALUATION READINESS PREVIEW - WATERMARKED NON-COMMERCIAL DRAFT]';

/**
 * Sanitize to printable ASCII (`0x20..0x7E`) and escape PDF string delimiters `\`, `(`, `)`.
 * @param {string} str
 * @returns {string}
 */
export function escapePdfText(str) {
  const normalized = String(str ?? '')
    .replace(/\u00b7/g, '-')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[^\x20-\x7e]/g, '?');
  return normalized
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

/**
 * Wrap a plain text line cleanly on word boundaries to `<= maxChars` characters per line
 * so no PDF text ever clips past the A4 right margin (`x = 555pt`) or slices words mid-token.
 *
 * @param {string} raw
 * @param {number} [maxChars=PDF_MAX_LINE_CHARS]
 * @returns {string[]}
 */
export function wrapPdfLine(raw, maxChars = PDF_MAX_LINE_CHARS) {
  const text = String(raw ?? '')
    .replace(/\u00b7/g, '-')
    .replace(/[\r\n]+/g, ' ')
    .replace(/[^\x20-\x7e]/g, '?')
    .trimEnd();

  if (text.length <= maxChars) {
    return [text];
  }

  const out = [];
  let rem = text;
  let isContinuation = false;

  while (rem.length > 0) {
    const prefix = isContinuation ? '  ' : '';
    const budget = maxChars - prefix.length;

    if (rem.length <= budget) {
      out.push(prefix + rem);
      break;
    }

    let split = rem.lastIndexOf(' ', budget);
    if (split <= 0) {
      // Single whitespace-free token exceeds budget -> deterministic slice
      split = budget;
    }

    out.push(prefix + rem.slice(0, split).trimEnd());
    rem = rem.slice(split).trimStart();
    isContinuation = true;
  }

  return out;
}

/**
 * Render an 86-char base64url Ed25519 signature across 2 aligned 43-char lines with zero truncation.
 * @param {string} paddedLabel
 * @param {string} sigB64u
 * @returns {string[]}
 */
function formatEd25519SignatureTwoLines(paddedLabel, sigB64u) {
  const s = String(sigB64u || '');
  const firstHalf = s.slice(0, 43);
  const secondHalf = s.slice(43);
  if (!secondHalf) {
    return [`${paddedLabel}: ${firstHalf}`];
  }
  return [
    `${paddedLabel}: ${firstHalf}`,
    `${' '.repeat(paddedLabel.length)}  ${secondHalf}`,
  ];
}

/**
 * Render an attestation certificate into a byte-exact `%PDF-1.7` A4 binary `Buffer`.
 *
 * @param {Record<string, any>} certObj
 * @returns {Buffer}
 */
export function renderAttestationPdfBytes(certObj) {
  const isCommercial = certObj.authority_status === 'COUNTERSIGNED_COMMERCIAL';
  const ops = [];

  // 1. Page Background (Crisp Alabaster White)
  ops.push('0.988 0.988 0.992 rg');
  ops.push('0 0 595 842 re f');

  // 2. True PDF /ExtGState Translucent Watermark (ca=0.12, CA=0.12) drawn BEFORE cards & foreground text!
  if (!isCommercial) {
    ops.push('q');
    ops.push('/GSWM gs');
    ops.push('0.72 0.46 0.14 rg');
    ops.push(
      `BT /F2 15.5 Tf 0.819 0.574 -0.574 0.819 68 220 Td (${escapePdfText(WATERMARK_TEXT)}) Tj ET`
    );
    ops.push(
      `BT /F2 15.5 Tf 0.819 0.574 -0.574 0.819 68 425 Td (${escapePdfText(WATERMARK_TEXT)}) Tj ET`
    );
    ops.push('Q');
  }

  // 3. Top Executive Header Banner (x=36, y=772, w=523, h=46)
  if (isCommercial) {
    // Deep Obsidian Banner + Emerald Accent Bar
    ops.push('0.055 0.082 0.145 rg');
    ops.push('36 772 523 46 re f');
    ops.push('0.063 0.725 0.506 rg');
    ops.push('36 772 523 4 re f');

    ops.push('1 1 1 rg');
    ops.push(`BT /F2 9.5 Tf 48 801 Td (${escapePdfText(COMMERCIAL_BANNER_TEXT)}) Tj ET`);
    ops.push('0.78 0.86 0.82 rg');
    ops.push(
      `BT /F1 8 Tf 48 784 Td (${escapePdfText(
        `SHULIAK SIP v3.1.0 [${String(certObj.attestation_template || 'general').toUpperCase()}] - ${certObj.commercial_entitlement?.org_name || 'ORG'} - ID: ${certObj.certificate_id}`
      )}) Tj ET`
    );
  } else {
    // Slate / Amber Evaluation Header Banner
    ops.push('0.145 0.165 0.215 rg');
    ops.push('36 772 523 46 re f');
    ops.push('0.851 0.467 0.024 rg');
    ops.push('36 772 523 4 re f');

    ops.push('0.99 0.92 0.75 rg');
    ops.push(`BT /F2 9.5 Tf 48 801 Td (${escapePdfText(PREVIEW_BANNER_TEXT)}) Tj ET`);
    ops.push('0.84 0.86 0.90 rg');
    ops.push(
      `BT /F1 8 Tf 48 784 Td (${escapePdfText(
        `SHULIAK SIP v3.1.0 Zero-Setup Readiness Report - ID: ${certObj.certificate_id}`
      )}) Tj ET`
    );
  }

  let cursorY = 758;

  /**
   * Helper to draw a crisp hairline section card on the A4 canvas.
   * When `!isCommercial`, omits opaque card fill so the `/GSWM` background watermark remains
   * subtly visible underneath while foreground text renders above at 100% crisp contrast.
   * @param {string} cardTitle
   * @param {string[]} bodyLines
   * @param {{ mono?: boolean }} [opts]
   */
  const drawSectionCard = (cardTitle, bodyLines, opts = {}) => {
    const wrapped = [];
    for (const ln of bodyLines) {
      for (const piece of wrapPdfLine(ln, opts.mono ? 82 : 84)) {
        wrapped.push(piece);
      }
    }
    const lineStep = 9.4;
    const cardHeight = 20 + wrapped.length * lineStep + 6;
    const bottomY = cursorY - cardHeight;

    if (isCommercial) {
      ops.push('1 1 1 rg');
      ops.push(`36 ${bottomY.toFixed(1)} 523 ${cardHeight.toFixed(1)} re f`);
    }
    ops.push('0.82 0.84 0.88 RG 0.6 w');
    ops.push(`36 ${bottomY.toFixed(1)} 523 ${cardHeight.toFixed(1)} re S`);

    // Card Heading
    ops.push('0.07 0.09 0.15 rg');
    ops.push(`BT /F2 8.6 Tf 46 ${(cursorY - 13).toFixed(1)} Td (${escapePdfText(cardTitle)}) Tj ET`);

    // Card Body Lines
    const fontTag = opts.mono ? '/F3' : '/F1';
    const fontSize = opts.mono ? '7.2' : '7.6';
    ops.push('0.18 0.21 0.28 rg');
    let textY = cursorY - 24.5;
    for (const wLine of wrapped) {
      ops.push(`BT ${fontTag} ${fontSize} Tf 46 ${textY.toFixed(1)} Td (${escapePdfText(wLine)}) Tj ET`);
      textY -= lineStep;
    }

    cursorY = bottomY - 6;
  };

  // Card 01: Executive Governance & Cryptographic Authority
  const ent = certObj.commercial_entitlement;
  const partnerDisplay =
    ent?.partner_name ||
    certObj.partner_attribution?.partner_name ||
    certObj.partner_attribution?.partner_code ||
    null;

  const card01Lines = [
    `Authority Status : ${certObj.authority_status} | Generated: ${certObj.generated_at}`,
    isCommercial && ent
      ? `Licensed Entity  : ${ent.org_name} (${ent.org_domain}) | Tier: ${ent.tier} | License: ${ent.license_id}`
      : 'Licensed Entity  : Unlicensed Evaluation Workspace (Community Apache-2.0 Mode)',
    `Custodian Key ID : ${certObj.custodian_key_id} | Pub: ${String(certObj.custodian_pub_b64u)}`,
    `CycloneDX 1.6    : 0x08 JCS Digest ${certObj.aibom_digest_0x08}`,
  ];
  if (partnerDisplay) {
    card01Lines.push(`Authorized Channel Partner: ${partnerDisplay}`);
  }
  drawSectionCard('01. Executive Governance & Cryptographic Authority', card01Lines, { mono: true });

  // Card 02: Discovered MCP Topology & Security Posture (word-boundary wrapped, zero mid-word slicing)
  const ap = certObj.audit_posture || {};
  const findingPreviewLines = (ap.findings || [])
    .slice(0, 3)
    .map(
      (f) => `- [${f.rule_id}] [${f.severity}] ${f.client}::${f.server_name}: ${String(f.message)}`
    );
  const card02Lines = [
    `Security Posture : Score ${ap.score ?? 100}/100 (Grade ${ap.grade || 'A+'}) | Configs: ${ap.total_configs ?? 0} | MCP Servers: ${ap.total_servers ?? 0}`,
    `RFC 8785 Lock    : ${ap.lock_status || 'MISSING_LOCK'} | Masked Findings: ${ap.findings_count ?? 0} (Zero Raw Secrets)`,
    ...(findingPreviewLines.length > 0
      ? findingPreviewLines
      : ['- Zero high/critical static configuration findings detected in scanned MCP manifests.']),
  ];
  drawSectionCard('02. Discovered MCP Topology & Screenshot-Safe Posture', card02Lines, { mono: true });

  // Card 03: PCI DSS v4.0.1 Req. 3.5.1 & Atlassian Rovo Scope Analysis
  const pci = certObj.enterprise_scope?.pci_dss_scope || {};
  const rovo = certObj.enterprise_scope?.rovo_credit_pii_exposure || {};
  const card03Lines = [
    `PCI DSS v4.0.1   : ${pci.status || 'NONE'} (${pci.inScopeConnectorCount ?? 0} DB/Payment connector(s))`,
    `Scope Summary    : ${pci.summary || 'No payment or database MCP connectors detected.'}`,
    `Rovo / Ticketing : ${rovo.status || 'NONE'} (${rovo.connectorCount ?? 0} Rovo/Jira connector(s))`,
    `Rovo Exposure    : ${rovo.summary || 'No Atlassian Rovo or Jira MCP connectors detected.'}`,
  ];
  drawSectionCard('03. PCI DSS v4.0.1 Req. 3.5.1 & Atlassian Rovo Scope Analysis', card03Lines);

  // Card 04: Stage 3 ISEP v3.0 Evidentiary Blackbox & GDPR Art. 17 Readiness (capped at 10 seq numbers)
  const isep = certObj.isep_ledger || {};
  const rawErasedSeqs = Array.isArray(isep.lawfullyErasedSeqs) ? isep.lawfullyErasedSeqs : [];
  const erasedSeqDisplay =
    rawErasedSeqs.length === 0
      ? 'none'
      : rawErasedSeqs.length <= 10
        ? rawErasedSeqs.join(', ')
        : `${rawErasedSeqs.slice(0, 10).join(', ')} (+${rawErasedSeqs.length - 10} additional lawfully purged records)`;

  const card04Lines = [
    `ISEP v3.0 Status : ${isep.status || 'UNINITIALIZED_READINESS_BASELINE'}`,
    `Ledger Telemetry : Events: ${isep.totalEvents ?? 0} | GDPR Tombstones: ${isep.tombstones ?? 0} | Erased Seqs: [${erasedSeqDisplay}]`,
    `Chain Summary    : ${isep.reason || 'Readiness baseline only.'}`,
  ];
  drawSectionCard('04. Stage 3 ISEP v3.0 Evidentiary Blackbox & GDPR Art. 17(1) Readiness', card04Lines);

  // Card 05: Statutory Citations, DORA / EU AI Omnibus Alignment & Full 2-Line 86-Char Ed25519 Signatures
  const citationsJoined = (certObj.statutory_citations || []).join(' | ');
  const regAlignmentJoined = (
    certObj.regulatory_alignment || [
      'DORA (Reg. (EU) 2022/2554) Art. 17',
      'EU AI Omnibus Reg. (EU) 2026/1744',
    ]
  ).join(' | ');
  const custodianSigLines = formatEd25519SignatureTwoLines(
    'Custodian Sig   ',
    certObj.custodian_signature_b64u
  );
  const rootSigLines =
    isCommercial && ent
      ? formatEd25519SignatureTwoLines('SHULIAK Root Sig', ent.root_signature_b64u)
      : [
          'SHULIAK Root Sig: NONE (Not countersigned for external QSA / SOC 2 / ISO 42001 submission)',
        ];

  const card05Lines = [
    `Statutory Scope : ${citationsJoined}`,
    `EU Alignment    : ${regAlignmentJoined}`,
    `0x0A Cert Digest: ${certObj.attestation_digest_0x0a}`,
    ...custodianSigLines,
    ...rootSigLines,
  ];
  drawSectionCard('05. Statutory Mapping & Offline Ed25519 Verification Anchors', card05Lines, {
    mono: true,
  });

  // 4. Conversion CTA Banner when Preview / Unlicensed
  if (!isCommercial) {
    const ctaY = Math.max(38, cursorY - 40);
    ops.push('1.0 0.968 0.902 rg');
    ops.push(`36 ${ctaY.toFixed(1)} 523 36 re f`);
    ops.push('0.851 0.467 0.024 RG 1.1 w');
    ops.push(`36 ${ctaY.toFixed(1)} 523 36 re S`);

    const ctaLine1 =
      'ACTIVATE $299/MO SELF-SERVE COMPLIANCE KEY FOR COUNTERSIGNED ORIGINAL:';
    const ctaLine2 = `${certObj.upgrade_url || 'https://shuliak.dev/#pricing'}`;

    ops.push('0.48 0.20 0.02 rg');
    ops.push(
      `BT /F2 8.0 Tf 46 ${(ctaY + 22).toFixed(1)} Td (${escapePdfText(ctaLine1)}) Tj ET`
    );
    ops.push('0.08 0.12 0.22 rg');
    ops.push(
      `BT /F3 7.8 Tf 46 ${(ctaY + 9).toFixed(1)} Td (${escapePdfText(ctaLine2)}) Tj ET`
    );
  }

  // 5. Crisp Offline Verification Footer in `/F3 8.2 Tf` (exact `--offline` CLI command)
  ops.push('0.25 0.30 0.38 rg');
  ops.push(
    `BT /F3 8.2 Tf 36 20 Td (${escapePdfText(
      'Verify: npx --offline @shuliak-corp/sip1-mcp verify-cert --file attestation.json'
    )}) Tj ET`
  );

  const contentStreamStr = ops.join('\n') + '\n';
  const contentStreamBuf = Buffer.from(contentStreamStr, 'ascii');

  // Assemble PDF 1.7 Objects with exact byte-offset tracking (8 objects, inline /ExtGState /GSWM)
  const objects = [
    // 1: Catalog
    '<< /Type /Catalog /Pages 2 0 R >>',
    // 2: Pages
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    // 3: Page (A4 595 x 842 pt) with /ExtGState /GSWM (ca 0.12, CA 0.12)
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> /ExtGState << /GSWM << /Type /ExtGState /ca 0.12 /CA 0.12 >> >> >> /Contents 7 0 R >>',
    // 4: Font /F1 Helvetica
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    // 5: Font /F2 Helvetica-Bold
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
    // 6: Font /F3 Courier
    '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>',
    // 7: Content Stream
    `<< /Length ${contentStreamBuf.byteLength} >>\nstream\n${contentStreamStr}endstream`,
    // 8: Info Dictionary
    `<< /Title (${escapePdfText(`SHULIAK SIP v3.1.0 Attestation ${certObj.certificate_id}`)}) /Producer (SHULIAK SIP v3.1.0 Zero-Egress PDF 1.7 Engine) /CreationDate (D:${formatPdfDate(certObj.generated_at)}) >>`,
  ];

  const chunks = [];
  let byteCursor = 0;

  const pushAscii = (str) => {
    const b = Buffer.from(str, 'latin1');
    chunks.push(b);
    byteCursor += b.byteLength;
  };

  // Binary comment marker per ISO 32000-1 Section 7.5.2
  pushAscii('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n');

  /** @type {number[]} */
  const objOffsets = [0]; // index 0 is free head

  for (let idx = 0; idx < objects.length; idx++) {
    objOffsets.push(byteCursor);
    const objNum = idx + 1;
    pushAscii(`${objNum} 0 obj\n${objects[idx]}\nendobj\n`);
  }

  // Embed verifiable base64url JSON certificate comment directly before xref
  const certJsonB64u = b64u(Buffer.from(JSON.stringify(certObj), 'utf8'));
  pushAscii(`${PDF_TRAILER_JSON_PREFIX}${certJsonB64u}\n`);

  const startXrefOffset = byteCursor;
  const totalObjs = objects.length + 1;

  // ISO 32000-1 Section 7.5.4: every xref entry MUST be exactly 20 bytes (`nnnnnnnnnn ggggg n \n`)
  pushAscii(`xref\n0 ${totalObjs}\n`);
  pushAscii('0000000000 65535 f \n');
  for (let i = 1; i <= objects.length; i++) {
    const offStr = String(objOffsets[i]).padStart(10, '0');
    pushAscii(`${offStr} 00000 n \n`);
  }

  pushAscii(
    `trailer\n<< /Size ${totalObjs} /Root 1 0 R /Info 8 0 R >>\nstartxref\n${startXrefOffset}\n%%EOF\n`
  );

  return Buffer.concat(chunks);
}

/**
 * Extract embedded `%ISEP-ATTESTATION-JSON:<base64url>` from raw `.pdf` bytes, validate `%PDF-1.7`
 * structure + `xref` offsets + anti-spoofing content stream consistency, and run full two-tier
 * offline cryptographic verification!
 *
 * @param {Buffer | Uint8Array} pdfBuf
 * @param {{ authorityPubB64u?: string, nowMs?: number }} [options]
 */
export function extractAndVerifyPdfBytes(pdfBuf, options = {}) {
  const buf = Buffer.isBuffer(pdfBuf) ? pdfBuf : Buffer.from(pdfBuf);
  const rawLatin1 = buf.toString('latin1');

  if (!rawLatin1.startsWith('%PDF-1.7')) {
    return {
      valid: false,
      status: 'INVALID_PDF_HEADER',
      reason: 'File does not begin with valid %PDF-1.7 header',
      certObj: null,
    };
  }

  // Verify startxref byte offset accuracy
  const startXrefMatch = /startxref\n(\d+)\n%%EOF\s*$/.exec(rawLatin1);
  if (!startXrefMatch) {
    return {
      valid: false,
      status: 'INVALID_PDF_XREF',
      reason: 'Missing startxref / %%EOF trailer in PDF binary',
      certObj: null,
    };
  }
  const declaredXrefOffset = Number(startXrefMatch[1]);
  if (
    !Number.isInteger(declaredXrefOffset) ||
    declaredXrefOffset <= 0 ||
    declaredXrefOffset >= buf.byteLength ||
    buf.subarray(declaredXrefOffset, declaredXrefOffset + 5).toString('latin1') !== 'xref\n'
  ) {
    return {
      valid: false,
      status: 'INVALID_PDF_XREF',
      reason: `PDF startxref byte offset (${declaredXrefOffset}) does not point to xref table`,
      certObj: null,
    };
  }

  const trailerMatch = /%ISEP-ATTESTATION-JSON:([A-Za-z0-9_-]+)/.exec(rawLatin1);
  if (!trailerMatch) {
    return {
      valid: false,
      status: 'MISSING_EMBEDDED_ATTESTATION',
      reason: 'PDF does not contain an embedded %ISEP-ATTESTATION-JSON cryptographic payload',
      certObj: null,
    };
  }

  let certObj;
  try {
    const jsonBytes = unb64u(trailerMatch[1]);
    certObj = JSON.parse(jsonBytes.toString('utf8'));
  } catch (err) {
    return {
      valid: false,
      status: 'CORRUPT_EMBEDDED_ATTESTATION',
      reason: `Failed to decode embedded attestation JSON: ${err instanceof Error ? err.message : String(err)}`,
      certObj: null,
    };
  }

  const certVer = verifyAttestationCertificateOffline({
    certObj,
    authorityPubB64u: options.authorityPubB64u || resolveDefaultAuthorityPubB64u(),
    nowMs: options.nowMs,
  });

  if (!certVer.valid) {
    return {
      ...certVer,
      certObj,
      xrefOffsetValid: true,
    };
  }

  // Visual Content-Stream Anti-Spoofing Guard:
  // Prevent an attacker from keeping a valid `PREVIEW_WATERMARKED_EVALUATION` trailer while editing
  // the PDF graphics stream to remove `EVALUATION PREVIEW` or inject `VERIFIED COMMERCIAL ATTESTATION`.
  if (certObj.authority_status !== 'COUNTERSIGNED_COMMERCIAL') {
    const hasWatermark = rawLatin1.includes(WATERMARK_TEXT);
    const claimsCommercialVisual = rawLatin1.includes('VERIFIED COMMERCIAL ATTESTATION');
    if (!hasWatermark || claimsCommercialVisual) {
      return {
        valid: false,
        status: 'FORGED_COMMERCIAL_AUTHORITY',
        authorityStatus: certObj.authority_status,
        custodianSignatureValid: certVer.custodianSignatureValid,
        rootCountersignatureValid: false,
        reason:
          'PDF visual stream was tampered to strip evaluation watermark or spoof commercial header without Root signature',
        certObj,
        xrefOffsetValid: true,
      };
    }
  }

  return {
    ...certVer,
    certObj,
    xrefOffsetValid: true,
  };
}

/**
 * Format ISO timestamp into PDF Date string `YYYYMMDDHHmmssZ`.
 * @param {string | undefined} iso
 * @returns {string}
 */
function formatPdfDate(iso) {
  const d = iso ? new Date(iso) : new Date();
  if (Number.isNaN(d.getTime())) {
    return '20261115000000Z';
  }
  const pad2 = (n) => String(n).padStart(2, '0');
  return (
    String(d.getUTCFullYear()) +
    pad2(d.getUTCMonth() + 1) +
    pad2(d.getUTCDate()) +
    pad2(d.getUTCHours()) +
    pad2(d.getUTCMinutes()) +
    pad2(d.getUTCSeconds()) +
    'Z'
  );
}

export const PDF_PET_LEGAL_DISCLAIMER =
  'NON-CUSTODIAL PET NOTICE: Automated local ' +
  'control telemetry; NOT a CPA attestation ' +
  'under AICPA SSAE 18 (SOC 2), PCI DSS ROC, ' +
  'and NOT a HIPAA BAA. SOC 2 and PCI DSS are ' +
  'trademarks of respective owners. Liability ' +
  'strictly capped per SHULIAK CORP EULA.';
