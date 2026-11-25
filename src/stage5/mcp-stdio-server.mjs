import {
  detectDuplicateJsonKeys,
  cleanProtoKeys,
  checkMcpMetaProtocol,
  decorateStateless2026Result,
} from './redteam-protocol-armor.mjs';
import {
  createBridgeSessionVault,
  readProtectedDocument,
  saveRestoredDocument,
} from './protected-file-bridge.mjs';
import {
  SECTOR_PACK_IDS, SECTOR_PACK_META,
} from '../stage4/sector-packs.mjs';
/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 5 Native JSON-RPC 2.0 MCP Stdio Server
 * Zero external dependencies. Built strictly on Node.js >= 20 built-ins.
 *
 * Protocol Invariant:
 * - Newline-delimited JSON-RPC 2.0 over `stdin` / `stdout`.
 * - Diagnostic logs are emitted strictly to `stderr` so `stdout` remains 100% pure JSON-RPC.
 * - Exposes 5 zero-egress security & cryptographic tools for Claude Desktop, Claude Code,
 *   Cursor, VS Code, Windsurf, and Glama.ai automated MCP inspection.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { ensureDeviceEd25519Keypair } from '../core/crypto-primitives.mjs';
import { discoverMcpConfigs } from '../stage1/config-discovery.mjs';
import { runStaticMcpAudit } from '../stage1/audit-scanner.mjs';
import { classifyToolAction } from '../stage2/blast-radius-guard.mjs';
import { extractAndPseudonymizePayload } from '../stage3/nist-ff1-twins.mjs';
import { resolveIsepPaths, verifyIsepChainQuick } from '../stage3/isep-engine.mjs';
import { analyzeEnterpriseScopeExposure } from '../stage4/cyclonedx-aibom.mjs';
import { runZeroEgressSelfTest } from '../stage4/zero-egress-selftest.mjs';

const BRIDGE_KEY = crypto.randomBytes(32);
const BRIDGE_VAULT = createBridgeSessionVault();
export const MCP_SERVER_NAME = '@shuliak-corp/sip1-mcp';
export const MCP_SERVER_VERSION = '3.1.0';
export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  '2026-07-28',
  '2025-11-25',
  '2025-03-26',
  '2024-11-05',
]);

export const MCP_TOOLS_CATALOG = Object.freeze([
  {
    name: 'sip_audit_workspace',
    title: 'Zero-Egress 9-Client MCP Config Audit',
    description:
      'Run SHULIAK SIP deterministic zero-egress MCP ' +
      'configuration audit (SIP-R01..SIP-R05) across 9 ' +
      'IDE clients, detect plaintext secrets, unpinned ' +
      '@latest packages, Plane-14/Bidi smuggling, and ' +
      'summarize PCI DSS v4.0.1 & Rovo scope exposure. ' +
      'Screenshot-Safe: never returns raw credentials.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        workspaceDir: {
          type: 'string',
          description:
            'Optional workspace directory path to scan.',
        },
        includeGlobal: {
          type: 'boolean',
          description:
            'Include OS-level IDE configs (default false).',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'sip_classify_action_guard',
    title: 'Stage 2 AST Blast-Radius Action Classifier',
    description:
      'Classify a proposed MCP tool invocation via ' +
      'Stage 2 SQL, Shell, SSRF (NAT64/IPv4-mapped), ' +
      'and Path AST Blast-Radius Guard (TIER_0..TIER_3), ' +
      'ignoring untrusted readOnlyHint flags, and compute ' +
      'its RFC 8785 0x07 action digest.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        server: {
          type: 'string',
          description: 'Target MCP server identifier.',
        },
        tool: {
          type: 'string',
          description: 'Target MCP tool name.',
        },
        args: {
          type: 'object',
          description: 'Tool arguments object to inspect.',
        },
        workspaceDir: {
          type: 'string',
          description: 'Workspace boundary directory.',
        },
        annotations: {
          type: 'object',
          description: 'Untrusted server tool annotations.',
        },
      },
      required: ['server', 'tool'],
      additionalProperties: false,
    },
  },
  {
    name: 'sip_pseudonymize_payload',
    title: 'NIST SP 800-38G FF1 Payload Pseudonymizer',
    description:
      'Scrub sensitive text or JSON in RAM using NIST ' +
      'SP 800-38G Rev. 1 FF1 format-preserving synthetic ' +
      'twins (ISO/IEC 7812 Luhn PANs, ISO-7064 MOD-97 ' +
      'IBANs, RFC 2606 emails, quantized 60s timestamps ' +
      'and monetary bands) with ephemeral CSPRNG keys.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        payload: {
          description:
            'JSON object, array, or string to pseudonymize.',
        },
      },
      required: ['payload'],
      additionalProperties: false,
    },
  },
  {
    name: 'sip_isep_ledger_status',
    title: 'ISEP v3.0 Merkle Ledger & Erasure Verifier',
    description:
      'Inspect and cryptographically verify workspace ' +
      'Stage 3 ISEP v3.0 Merkle-chained evidentiary ' +
      'ledger (.sip/isep), including Ed25519 signatures ' +
      'and GDPR Art. 17(1) erasure tombstones.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        workspaceDir: {
          type: 'string',
          description: 'Workspace containing .sip/isep.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'sip_zero_egress_selftest',
    title: 'Zero-Egress Runtime & CAVP FF1 Self-Test',
    description:
      'Execute Stage 4 deterministic zero-egress self-' +
      'test verifying 9/9 NIST CAVP FF1 vectors, Luhn/' +
      'MOD-97 twins, 0x06 RFC 8785 Schema Lock, ISEP ' +
      'double-shred, and 0 loaded network modules via ' +
      'moduleLoadList and active resource handles.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'sip_list_sector_packs',
    title: 'List Regulated Sector Compliance Packs',
    description:
      'List all built-in SHULIAK SIP sector compliance ' +
      'packs (iso42001_eu_ai, pci_dora, legal_tax, ' +
      'hipaa_clinical) with statutory control mappings ' +
      'for PCI DSS 4.0.1, SEPA, IRS 7216, ICAO MRZ, ' +
      'and HIPAA 18 Safe Harbor identifiers.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'sip_read_protected_file',
    title: 'Read Local File with FF1 Slot Isolation',
    description:
      'Read a local document from disk and apply two-' +
      'phase sentinel-slot NIST FF1 pseudonymization ' +
      '(PAN, SEPA IBAN, LEI, SSN/ITIN/EIN, ICAO MRZ, ' +
      'HIPAA NPI/MBI/VIN/dates) storing reversible twin ' +
      'mappings strictly in volatile RAM.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        filePath: {
          type: 'string',
          description: 'Local path to source document.',
        },
        packs: {
          type: 'array',
          items: { type: 'string' },
          description: 'Sector pack IDs to activate.',
        },
        shiftClinicalDates: {
          type: 'boolean',
          description: 'Enable HIPAA clinical date shift.',
        },
        watchlist: {
          type: 'array',
          items: { type: 'string' },
          description: 'Custom confidential entity terms.',
        },
      },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    name: 'sip_save_restored_document',
    title: 'Restore RAM Twins & Save Atomic Document',
    description:
      'Detokenize an AI-edited draft by replacing in-' +
      'RAM NIST FF1 synthetic twins back to original ' +
      'values via LIFO unwrapping and atomically write ' +
      'the restored document to the local filesystem.',
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: {
        aiDraftText: {
          type: 'string',
          description: 'Pseudonymized draft text to restore.',
        },
        sourcePath: {
          type: 'string',
          description: 'Original source document path.',
        },
        outputPath: {
          type: 'string',
          description: 'Target local output file path.',
        },
      },
      required: ['aiDraftText'],
      additionalProperties: false,
    },
  },
])

/**
 * Derive per-subject ephemeral `{ rSlot32, tweak16 }` inside a single `sip_pseudonymize_payload` call
 * using a volatile 32-byte CSPRNG session seed wiped immediately after the call completes.
 *
 * @param {Buffer} sessionSeed32
 * @param {Buffer} canonicalTargetBuf
 */

export const MCP_PROMPTS_CATALOG = Object.freeze([
  {
    name: 'hipaa-chart-summary',
    title: 'HIPAA Safe Harbor Clinical Chart Summary',
    description:
      'Read a local .docx/.pdf/.hl7/FHIR chart via ' +
      'local FF1 RAM bridge with HIPAA date shift.',
    arguments: [
      {
        name: 'filePath',
        description: 'Local clinical chart path.',
        required: false,
      },
    ],
  },
  {
    name: 'legal-contract-review',
    title: 'Legal & Tax Contract Review (Zero-Leak)',
    description:
      'Review a local .docx/.odt/.pdf contract with ' +
      'PARTY_A/PARTY_B isolation and SSN/EIN twins.',
    arguments: [
      {
        name: 'filePath',
        description: 'Local contract file path.',
        required: false,
      },
    ],
  },
  {
    name: 'finance-ledger-audit',
    title: 'PCI DSS & SEPA Financial Ledger Review',
    description:
      'Audit a local .xlsx/.csv ledger with Luhn ' +
      'PAN and MOD-97 SEPA IBAN synthetic twins.',
    arguments: [
      {
        name: 'filePath',
        description: 'Local spreadsheet path.',
        required: false,
      },
    ],
  },
  {
    name: 'compliance-certificate',
    title: 'Zero-Egress Security & ISEP Evidence Check',
    description:
      'Run local workspace audit, zero-egress self-' +
      'test, and ISEP Merkle ledger verification.',
    arguments: [
      {
        name: 'workspaceDir',
        description: 'Target workspace directory.',
        required: false,
      },
    ],
  },
]);

export function renderMcpPrompt(name, rawArgs = {}) {
  const a = rawArgs && typeof rawArgs === 'object'
    ? rawArgs : {};
  const fp = String(a.filePath || '<path-to-document>');
  const ws = String(a.workspaceDir || '.');
  if (name === 'hipaa-chart-summary') {
    return {
      description:
        'HIPAA Safe Harbor clinical review workflow.',
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text:
            `Call sip_read_protected_file on "${fp}" ` +
            'with packs=["hipaa_clinical"] and ' +
            'shiftClinicalDates=true. Summarize ' +
            'findings using only RAM twins ' +
            '(PATIENT_01, shifted dates). Offer to ' +
            'save via sip_save_restored_document.',
        },
      }],
    };
  }
  if (name === 'legal-contract-review') {
    return {
      description:
        'Zero-leak legal contract review workflow.',
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text:
            `Call sip_read_protected_file on "${fp}" ` +
            'with packs=["legal_tax"]. Analyze risks ' +
            'and propose redlines using PARTY_A / ' +
            'PARTY_B twins. Save restored redline via ' +
            'sip_save_restored_document.',
        },
      }],
    };
  }
  if (name === 'finance-ledger-audit') {
    return {
      description:
        'PCI DSS & SEPA financial ledger workflow.',
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text:
            `Call sip_read_protected_file on "${fp}" ` +
            'with packs=["pci_dora"]. Reconcile ' +
            'balances and anomalies using Luhn/MOD-97 ' +
            'twins, then save via ' +
            'sip_save_restored_document.',
        },
      }],
    };
  }
  if (name === 'compliance-certificate') {
    return {
      description:
        'Automated zero-egress control check.',
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text:
            `Run sip_audit_workspace (dir="${ws}"), ` +
            'sip_zero_egress_selftest, and ' +
            'sip_isep_ledger_status. Present automated ' +
            'control metrics and CLI attest command.',
        },
      }],
    };
  }
  return null;
}

function deriveEphemeralSubjectMaterial(sessionSeed32, canonicalTargetBuf) {
  const rSlot32 = crypto
    .createHmac('sha256', sessionSeed32)
    .update(Buffer.from('SIP5-MCP-FF1-KEY\0', 'utf8'))
    .update(canonicalTargetBuf)
    .digest();
  const tweak16 = crypto
    .createHmac('sha256', sessionSeed32)
    .update(Buffer.from('SIP5-MCP-FF1-TWK\0', 'utf8'))
    .update(canonicalTargetBuf)
    .digest()
    .subarray(0, 16);
  return { rSlot32, tweak16 };
}

/**
 * Execute one of the 5 built-in zero-egress MCP tools.
 * @param {string} toolName
 * @param {Record<string, any>} rawArgs
 * @param {string} defaultWorkspaceDir
 */
export async function executeNativeMcpTool(toolName, rawArgs, defaultWorkspaceDir) {
  const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};
  const targetDir =
    typeof args.workspaceDir === 'string' && args.workspaceDir.trim()
      ? path.resolve(args.workspaceDir)
      : path.resolve(defaultWorkspaceDir || process.cwd());

  if (toolName === 'sip_audit_workspace') {
    const includeGlobal = Boolean(args.includeGlobal);
    const configs = discoverMcpConfigs({
      workspaceDir: targetDir,
      includeGlobal,
    });
    const audit = runStaticMcpAudit({
      configs,
      workspaceDir: targetDir,
    });
    const scope = analyzeEnterpriseScopeExposure({
      configs,
      auditResult: audit,
    });

    return {
      engineVersion: MCP_SERVER_VERSION,
      score: audit.score,
      grade: audit.grade,
      durationMs: audit.durationMs,
      totalConfigs: audit.totalConfigs,
      totalServers: audit.totalServers,
      lockStatus: audit.lockStatus,
      findingsCount: audit.findings.length,
      findings: audit.findings.map((f) => ({
        ruleId: f.ruleId,
        severity: f.severity,
        client: f.client,
        serverName: f.serverName,
        relativeFile: f.relativeFile,
        message: f.message,
        maskedPreview: f.maskedPreview,
        remediation: f.remediation,
      })),
      enterpriseScope: {
        pciDssStatus: scope.pciDssScopeStatus.status,
        pciInScopeConnectors: scope.pciDssScopeStatus.inScopeConnectorCount,
        rovoStatus: scope.rovoCreditPiiExposure.status,
        rovoConnectors: scope.rovoCreditPiiExposure.connectorCount,
      },
    };
  }

  if (toolName === 'sip_classify_action_guard') {
    const server = typeof args.server === 'string' && args.server.trim() ? args.server.trim() : 'mcp-server';
    const tool = typeof args.tool === 'string' && args.tool.trim() ? args.tool.trim() : 'unknown-tool';
    const toolArgs = args.args && typeof args.args === 'object' ? args.args : {};

    const classification = classifyToolAction({
      server,
      tool,
      args: toolArgs,
      workspaceDir: targetDir,
      annotations: args.annotations,
    });

    return {
      server,
      tool,
      tier: classification.tier,
      ruleId: classification.ruleId,
      reason: classification.reason,
      normalizedActionDigest: classification.normalizedActionDigest,
      targetPaths: classification.targetPaths || [],
    };
  }

  if (toolName === 'sip_pseudonymize_payload') {
    if (!Object.prototype.hasOwnProperty.call(args, 'payload')) {
      throw new Error('Missing required argument "payload" for sip_pseudonymize_payload');
    }
    const ephemeralSeed = crypto.randomBytes(32);
    try {
      const scrubbed = extractAndPseudonymizePayload(args.payload, (canonBuf) =>
        deriveEphemeralSubjectMaterial(ephemeralSeed, canonBuf)
      );
      return {
        algorithm: 'NIST-SP-800-38G-FF1-AES256',
        subjectCount: scrubbed.subjects.length,
        skeletonPayload: scrubbed.skeletonPayload,
        ephemeralKeyWiped: true,
      };
    } finally {
      ephemeralSeed.fill(0);
    }
  }

  if (toolName === 'sip_isep_ledger_status') {
    const paths = resolveIsepPaths({ workspaceDir: targetDir });
    const initialized = fs.existsSync(paths.keyringPath) || fs.existsSync(paths.logPath);
    if (!initialized) {
      return {
        initialized: false,
        valid: true,
        status: 'UNINITIALIZED',
        totalEvents: 0,
        tombstones: 0,
        reason: 'No ISEP v3.0 ledger initialized in this workspace yet. Run `sip1-mcp isep init` to enable.',
      };
    }

    const kp = ensureDeviceEd25519Keypair(paths.sipDir, { ephemeralOnly: true });
    const ver = verifyIsepChainQuick({
      logPath: paths.logPath,
      blobsPath: paths.blobsPath,
      custodianPublicKey: kp.publicKey,
    });

    return {
      initialized: true,
      valid: ver.valid,
      status: ver.status,
      totalEvents: ver.totalEvents,
      tombstones: ver.tombstones,
      reason: ver.reason,
    };
  }

  if (toolName === 'sip_zero_egress_selftest') {
    const res = await runZeroEgressSelfTest();
    return {
      passed: res.passed,
      outboundSocketsOpened: res.socketsOpened,
      outboundBytesSent: res.bytesTransmitted,
      socketsOpened: res.socketsOpened,
      bytesTransmitted: res.bytesTransmitted,
      cavpPassed: res.cavpPassed,
      cavpTotal: res.cavpTotal,
      luhnPanValid: res.luhnPanValid,
      ibanMod97Valid: res.ibanMod97Valid,
      schemaLockValid: res.schemaLockValid,
      isepDoubleShredValid: res.isepDoubleShredValid,
      durationMs: res.durationMs,
      specRef: res.specRef,
    };
  }

  if (toolName === 'sip_list_sector_packs') {
      return {
        version: '3.1.0',
        packs: SECTOR_PACK_IDS.map((id) => SECTOR_PACK_META[id]),
      };
    }
  if (toolName === 'sip_read_protected_file') {
      const _a = args || {};
      const fp = String(_a.filePath || '');
      let pks = SECTOR_PACK_IDS;
      let fromDefaultEnv = false;
      if (Array.isArray(_a.packs) && _a.packs.length) {
        pks = _a.packs;
      } else if (process.env.SIP_DEFAULT_PACK) {
        const rawDef = String(
          process.env.SIP_DEFAULT_PACK
        ).split(',').map((x) => x.trim()).filter(
          (x) => SECTOR_PACK_IDS.includes(x)
        );
        if (rawDef.length > 0) {
          pks = rawDef;
          fromDefaultEnv = true;
        }
      }
      const autoShift = _a.shiftClinicalDates !==
        undefined
        ? Boolean(_a.shiftClinicalDates)
        : (fromDefaultEnv && pks.length === 1 &&
           pks[0] === 'hipaa_clinical');
      return readProtectedDocument({
        filePath: fp,
        key32: BRIDGE_KEY,
        sessionVault: BRIDGE_VAULT,
        activePacks: pks,
        shiftClinicalDates: autoShift,
        watchlist: Array.isArray(_a.watchlist)
          ? _a.watchlist : [],
      });
    }
  if (toolName === 'sip_save_restored_document') {
      const _a = args || {};
      return saveRestoredDocument({
        aiDraftText: String(_a.aiDraftText ?? ''),
        sessionVault: BRIDGE_VAULT,
        sourcePath: String(_a.sourcePath ?? ''),
        outputPath: String(_a.outputPath ?? ''),
      });
    }

  const unknownErr = /** @type {Error & { jsonRpcCode?: number }} */ (
    new Error(`Unknown MCP tool "${toolName}"`)
  );
  unknownErr.jsonRpcCode = -32602;
  throw unknownErr;
}

/**
 * Create an in-memory JSON-RPC 2.0 MCP server session.
 *
 * @param {{
 *   workspaceDir?: string,
 *   onSend?: (responseObj: Record<string, any>) => void,
 *   onDiagnostic?: (line: string) => void,
 * }} [options]
 */
export function createMcpServerSession(options = {}) {
  const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
  const onSend = typeof options.onSend === 'function' ? options.onSend : () => {};
  const onDiagnostic = typeof options.onDiagnostic === 'function' ? options.onDiagnostic : () => {};
  let initialized = false;

  /**
   * Process a parsed JSON-RPC 2.0 request/notification object.
   * Returns the response object (or `null` for notifications).
   * @param {any} msg
   */
  async function handleMessage(msg) {
    if (msg && typeof msg === 'object' &&
        !Array.isArray(msg)) {
      const pObj = msg.params && typeof msg.params ===
        'object' ? msg.params : {};
      const mChk = checkMcpMetaProtocol(pObj);
      if (!mChk.valid) {
        const vErr = {
          jsonrpc: '2.0',
          id: 'id' in msg ? msg.id : null,
          error: mChk.errorObj,
        };
        onSend(vErr);
        return vErr;
      }
      if (mChk.era === '2026-07-28') {
        const mName = String(msg.method || '');
        const send26 = (pkt) => {
          if (pkt && pkt.result && !pkt.error) {
            pkt.result = decorateStateless2026Result(
              mName, pkt.result
            );
          }
          return onSend(pkt);
        };
        return _innerHandleMessage(msg, send26);
      }
    }
    return _innerHandleMessage(msg, onSend);
  }

  async function _innerHandleMessage(msg, onSend) {
    if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') {
      const errResp = {
        jsonrpc: '2.0',
        id: msg && typeof msg === 'object' && 'id' in msg ? msg.id : null,
        error: {
          code: -32600,
          message: 'Invalid Request: expected JSON-RPC 2.0 object',
        },
      };
      onSend(errResp);
      return errResp;
    }

    const isNotification = !Object.prototype.hasOwnProperty.call(msg, 'id');
    const reqId = isNotification ? undefined : msg.id;
    const method = typeof msg.method === 'string' ? msg.method : '';
    const params = msg.params && typeof msg.params === 'object' ? msg.params : {};

    // Notifications produce zero stdout output per JSON-RPC 2.0 specification
    if (isNotification) {
      if (method === 'notifications/initialized') {
        initialized = true;
        onDiagnostic('[SIP MCP] Host client initialized notification received.');
      }
      return null;
    }

    if (method === 'initialize') {
      const requestedVersion =
        typeof params.protocolVersion === 'string' ? params.protocolVersion : '2024-11-05';
      const protocolVersion = SUPPORTED_MCP_PROTOCOL_VERSIONS.includes(requestedVersion)
        ? requestedVersion
        : '2024-11-05';
      initialized = true;
      const resp = {
        jsonrpc: '2.0',
        id: reqId,
        result: {
          protocolVersion,
          capabilities: {
            tools: { listChanged: false },
            prompts: { listChanged: false },
            discovery: { version: '2026-07-28', deterministic: true },
          },
          serverInfo: {
            name: MCP_SERVER_NAME,
            version: '3.1.0',
          },
          instructions:
            'SHULIAK SIP v3.1.0 Zero-Egress MCP Security Engine. Provides 9-client workspace auditing, AST blast-radius classification, NIST SP 800-38G FF1 pseudonymization, ISEP v3.0 ledger verification, and zero-egress socket tripwire proof.',
        },
      };
      onSend(resp);
      return resp;
    }

    if (method === 'server/discover') {
      const resp = {
        jsonrpc: '2.0',
        id: reqId,
        result: {
        resultType: 'complete',
          protocolVersion: '2026-07-28',
          supportedProtocolVersions: SUPPORTED_MCP_PROTOCOL_VERSIONS,
          serverInfo: {
            name: MCP_SERVER_NAME,
            version: '3.1.0',
            vendor: 'SHULIAK CORP',
            license: 'Apache-2.0',
          },
          securityPosture: {
            zeroEgress: true,
            networkPolicy: 'AIR_GAPPED_STDIO_ONLY',
            schemaLock: 'RFC8785-JCS-0x06-Ed25519',
            inlineProxy: 'NIST-SP-800-38G-FF1-AES256',
            auditBlackbox: 'ISEP-v3.0-GDPR-Art17',
          },
          capabilities: {
            tools: { listChanged: false },
            prompts: { listChanged: false },
            discovery: { version: '2026-07-28', deterministic: true },
          },
          tools: MCP_TOOLS_CATALOG,
        },
      };
      onSend(resp);
      return resp;
    }

    if (method === 'ping') {
      const resp = {
        jsonrpc: '2.0',
        id: reqId,
        result: {},
      };
      onSend(resp);
      return resp;
    }

    if (method === 'resources/list') {
      const resp = {
        jsonrpc: '2.0', id: reqId,
        result: { resources: [] },
      };
      onSend(resp);
      return resp;
    }

    if (method === 'prompts/list') {
      const resp = {
        jsonrpc: '2.0', id: reqId,
        result: { prompts: MCP_PROMPTS_CATALOG },
      };
      onSend(resp);
      return resp;
    }

    if (method === 'prompts/get') {
      const pName = typeof params.name === 'string'
        ? params.name : '';
      const rendered = renderMcpPrompt(
        pName, params.arguments || {}
      );
      if (!rendered) {
        const errResp = {
          jsonrpc: '2.0', id: reqId,
          error: {
            code: -32602,
            message: `Unknown MCP prompt "${pName}"`,
          },
        };
        onSend(errResp);
        return errResp;
      }
      const resp = {
        jsonrpc: '2.0', id: reqId,
        result: rendered,
      };
      onSend(resp);
      return resp;
    }

    if (method === 'tools/list') {
      const resp = {
        jsonrpc: '2.0',
        id: reqId,
        result: {
          tools: MCP_TOOLS_CATALOG,
        },
      };
      onSend(resp);
      return resp;
    }

    if (method === 'tools/call') {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const toolArgs = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};

      if (!toolName) {
        const errResp = {
          jsonrpc: '2.0',
          id: reqId,
          error: {
            code: -32602,
            message: 'Invalid params: missing required tool "name"',
          },
        };
        onSend(errResp);
        return errResp;
      }

      try {
        const output = await executeNativeMcpTool(
          toolName, toolArgs, workspaceDir
        );
        const content = [{
          type: 'text',
          text: JSON.stringify(output, null, 2),
        }];
        if ((toolName === 'sip_read_protected_file' ||
             toolName === 'sip_save_restored_document') &&
            typeof output?.protectionStatus === 'string') {
          content.push({
            type: 'text',
            text: output.protectionStatus,
          });
        }
        const resp = {
          jsonrpc: '2.0',
          id: reqId,
          result: { content, isError: false },
        };
        onSend(resp);
        return resp;
      } catch (err) {
        const rpcCode = /** @type {{ jsonRpcCode?: number }} */ (err)?.jsonRpcCode;
        if (rpcCode === -32602) {
          const errResp = {
            jsonrpc: '2.0',
            id: reqId,
            error: {
              code: -32602,
              message: err instanceof Error ? err.message : String(err),
            },
          };
          onSend(errResp);
          return errResp;
        }
        const toolErrResp = {
          jsonrpc: '2.0',
          id: reqId,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    error: err instanceof Error ? err.message : String(err),
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          },
        };
        onSend(toolErrResp);
        return toolErrResp;
      }
    }

    const notFoundResp = {
      jsonrpc: '2.0',
      id: reqId,
      error: {
        code: -32601,
        message: `Method not found: ${method || '<empty>'}`,
      },
    };
    onSend(notFoundResp);
    return notFoundResp;
  }

  /**
   * Process a single newline-delimited raw JSON-RPC frame string.
   * Never throws on malformed JSON — returns `-32700` Parse Error cleanly.
   * @param {string} rawLine
   */
  async function handleLine(rawLine) {
    const trimmed = String(rawLine ?? '').trim();
    if (!trimmed) return null;

    let parsed;
    const _dup = detectDuplicateJsonKeys(trimmed);
    if (_dup.hasDuplicate) {
      let _dId = null;
      try { _dId = JSON.parse(trimmed)?.id ?? null; }
      catch {}
      const dErr = {
        jsonrpc: '2.0', id: _dId,
        error: {
          code: -32600,
          message: `Duplicate JSON key: ${_dup.key}`,
        },
      };
      onSend(dErr);
      return dErr;
    }
    try {
      parsed = cleanProtoKeys(JSON.parse(trimmed));
    } catch {
      const parseErr = {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32700,
          message: 'Parse error: malformed JSON-RPC 2.0 frame',
        },
      };
      onSend(parseErr);
      return parseErr;
    }

    if (Array.isArray(parsed)) {
      const bMsg = parsed.length === 0
        ? 'Invalid Request: empty JSON-RPC batch'
        : 'Invalid Request: batch forbidden';
      const batchErr = {
        jsonrpc: '2.0', id: null,
        error: { code: -32600, message: bMsg },
      };
      onSend(batchErr);
      return batchErr;
    }

    return handleMessage(parsed);
  }

  return {
    get isInitialized() {
      return initialized;
    },
    handleMessage,
    handleLine,
  };
}

/**
 * Start the newline-delimited JSON-RPC 2.0 MCP server over `input` (`stdin`) and `output` (`stdout`).
 * Resolves cleanly once `input` reaches EOF and all queued frames finish executing.
 *
 * @param {{
 *   workspaceDir?: string,
 *   input?: NodeJS.ReadableStream,
 *   output?: { write: (chunk: string) => unknown },
 *   errorOutput?: { write: (chunk: string) => unknown },
 * }} [options]
 * @returns {Promise<{ processedFrames: number }>}
 */
export async function runMcpStdioServer(options = {}) {
  const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
  const input = options.input || process.stdin;
  const output = options.output || process.stdout;
  const errorOutput = options.errorOutput || process.stderr;

  let processedFrames = 0;
  const session = createMcpServerSession({
    workspaceDir,
    onSend: (respObj) => {
      output.write(JSON.stringify(respObj) + '\n');
    },
    onDiagnostic: (diagLine) => {
      errorOutput.write(diagLine + '\n');
    },
  });

  const rl = readline.createInterface({
    input,
    crlfDelay: Infinity,
  });

  /** @type {Promise<unknown>} */
  let queue = Promise.resolve();

  rl.on('line', (line) => {
    if (!line.trim()) return;
    processedFrames++;
    queue = queue.then(() => session.handleLine(line)).catch((err) => {
      errorOutput.write(
        `[SIP MCP STDERR] Internal frame handler error: ${err instanceof Error ? err.message : String(err)}\n`
      );
    });
  });

  await new Promise((resolve) => {
    rl.once('close', resolve);
  });

  await queue;
  return { processedFrames };
}
