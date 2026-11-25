import { StringDecoder } from 'node:string_decoder';
import {
  parseStrictJsonRpcFrame,
  normalizeUnicodeEvasion,
  stripTerminalControlCodes,
  sanitizeAndPinToolsList,
  isPlausiblePaymentIin,
  isSafeNumericIdKey,
  inspectElicitationOrInputRequired,
} from './redteam-protocol-armor.mjs';
import { pseudonymizeSectorText, SECTOR_PACK_IDS }
  from '../stage4/sector-packs.mjs';
/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 5 Inline Bidirectional MCP `stdio` Firewall (`wrap`)
 * Zero external dependencies. Built strictly on Node.js >= 20 built-ins.
 *
 * Enforces 3 Cryptographic Gates between Host IDE (Claude/Cursor) and ANY 3rd-party MCP Server:
 *   Gate 1 — Live `tools/list` Schema Pinning (`0x06` RFC 8785 JCS + Ed25519 + Plane-14 Tag Quarantine)
 *   Gate 2 — Live `tools/call` Stage 2 Blast-Radius AST Guard, Canary Honeytoken & Warrant Gate
 *   Gate 3 — Volatile In-RAM Bidirectional `NIST SP 800-38G FF1` Twin Vault (Luhn PAN, MOD-97 IBAN,
 *            API secrets) + Zero-PII Stage 3 `ISEP` Merkle Flight Recording
 */

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { compareUtf16CodeUnits, jcsCanonicalize } from '../core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import { withPidLock, writeFileAtomic600 } from '../core/workspace-io.mjs';
import { scanUnicodeSmuggling } from '../stage1/audit-scanner.mjs';
import {
  acquireNpxColdStartLock,
} from '../stage1/auto-shield.mjs';
import { evaluatePreToolGuard } from '../stage2/guard-runner.mjs';
import {
  beginIfcOperation,
  beginIfcOperationAsync,
  commitIfcOperation,
} from '../stage2/ifc-trifecta-bus.mjs';
import {
  detectImdsOrSensitiveFileUri,
  detectSsrfAddressEvasion,
  hasCve103572Path,
  normalizeAdversarialPathToken,
} from '../stage2/blast-radius-guard.mjs';
import {
  ibanMod97,
  isValidLuhnPan,
  synthesizeIbanTwin,
  synthesizePanTwin,
  synthesizeScopedToken,
} from '../stage3/nist-ff1-twins.mjs';
import { createHeadlessEnclaveAdapter } from '../stage3/enclave-adapter.mjs';
import {
  closeKeyring,
  openKeyring,
  recordAgentEvent,
  resolveIsepPaths,
} from '../stage3/isep-engine.mjs';


const PEM_BLOCK_RE = /-----BEGIN [A-Z0-9 ]+-----/;
const KV_PAIR_RE = new RegExp(
  '(?:^|[\\r\\n\\s])[A-Za-z_][A-Za-z0-9_]{1,48}' +
  '\\s*=\\s*\\S+'
);
const TWIN_TOK_RE = new RegExp(
  '\\b(?:tok-[0-9a-f]{16}|' +
  'u-[0-9a-f]{16}@example\\.invalid)\\b', 'gi'
);

function collectLeafStrings(node, out = []) {
  if (typeof node === 'string') {
    out.push(node);
    return out;
  }
  if (!node || typeof node !== 'object') return out;
  if (Array.isArray(node)) {
    for (const it of node) collectLeafStrings(it, out);
    return out;
  }
  for (const v of Object.values(node)) {
    collectLeafStrings(v, out);
  }
  return out;
}

export function isResultDeclassifiedByTwins(
  preScrubJson, postScrubJson, scrubbedMsg, twins = []
) {
  if (!preScrubJson || preScrubJson === postScrubJson) {
    return false;
  }
  const res = scrubbedMsg && typeof scrubbedMsg ===
    'object' ? scrubbedMsg.result : null;
  if (res === null || res === undefined) return false;
  const leaves = collectLeafStrings(res);
  if (leaves.length === 0) return false;
  const sortedTwins = [...twins]
    .filter((t) => typeof t === 'string' && t.length > 0)
    .sort((a, b) => b.length - a.length);
  for (const leaf of leaves) {
    if (PEM_BLOCK_RE.test(leaf)) return false;
    if (KV_PAIR_RE.test(leaf)) return false;
    let rem = leaf;
    for (const tw of sortedTwins) {
      if (rem.includes(tw)) rem = rem.split(tw).join('');
    }
    rem = rem.replace(TWIN_TOK_RE, '')
      .replace(/\s+/g, ' ').trim();
    if (rem.length > 64) return false;
  }
  return true;
}

function safeRealpath(target) {
  const abs = path.resolve(target);
  try { return fs.realpathSync(abs); } catch {}
  const tail = [];
  let cur = abs;
  while (true) {
    const par = path.dirname(cur);
    if (par === cur) return abs;
    tail.unshift(path.basename(cur));
    cur = par;
    try {
      return path.join(fs.realpathSync(cur), ...tail);
    } catch {}
  }
}

function isPathWithin(rootDir, targetPath) {
  const rel = path.relative(rootDir, targetPath);
  return rel === '' ||
    (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function inspectResourceReadUri(
  rawUri, workspaceDir,
  envAllowedDirs = process.env.SIP_ALLOWED_DIRS
) {
  const uri = String(rawUri || '').trim();
  if (!uri) return { allowed: true };
  if (uri.includes('\0')) {
    return {
      allowed: false, code: 'RESOURCE_NULL_BYTE',
      reason: 'Null byte forbidden in resource URI',
    };
  }
  const smug = scanUnicodeSmuggling(uri);
  if (smug.length > 0) {
    return {
      allowed: false, code: 'RESOURCE_UNICODE_SMUGGLING',
      reason: `Hidden ${smug[0].category} in URI`,
    };
  }
  const ssrf = detectSsrfAddressEvasion(uri);
  if (ssrf) {
    return {
      allowed: false, code: 'RESOURCE_SSRF_BLOCKED',
      reason: `Blocked ${ssrf} in resources/read`,
    };
  }
  const imds = detectImdsOrSensitiveFileUri(uri);
  if (imds) {
    return {
      allowed: false, code: 'RESOURCE_IMDS_BLOCKED',
      reason: `Blocked ${imds} in resources/read`,
    };
  }
  const cveP = hasCve103572Path(uri);
  if (cveP) {
    return {
      allowed: false, code: 'RESOURCE_PROTECTED_PATH',
      reason: `Blocked protected path: ${cveP}`,
    };
  }
  const isFileUri = /^file:/i.test(uri);
  const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(uri);
  if (isFileUri || !hasScheme) {
    let fsPath = uri;
    if (isFileUri) {
      try {
        fsPath = fileURLToPath(uri);
      } catch {
        try {
          fsPath = decodeURIComponent(
            uri.replace(/^file:\/\//i, '')
          );
        } catch {
          fsPath = uri.replace(/^file:\/\//i, '');
        }
      }
    }
    const normTok = normalizeAdversarialPathToken(fsPath);
    const cve2 = hasCve103572Path(fsPath) ||
      hasCve103572Path(normTok);
    if (cve2) {
      return {
        allowed: false, code: 'RESOURCE_PROTECTED_PATH',
        reason: `Blocked protected path: ${cve2}`,
      };
    }
    const realWs = safeRealpath(workspaceDir);
    const candidate = path.isAbsolute(fsPath)
      ? fsPath : path.resolve(realWs, fsPath);
    const realTarget = safeRealpath(candidate);
    const cveReal = hasCve103572Path(realTarget);
    if (cveReal ||
        isPathWithin(path.join(realWs, '.sip'),
          realTarget)) {
      return {
        allowed: false, code: 'RESOURCE_PROTECTED_PATH',
        reason: 'Resolved file targets protected path',
      };
    }
    const rawDirs = String(envAllowedDirs || '').trim();
    const allowedRoots = rawDirs
      ? rawDirs.split(path.delimiter)
        .map((d) => d.trim()).filter(Boolean)
        .map((d) => safeRealpath(d))
      : [realWs];
    const inAllowed = allowedRoots.some((r) =>
      isPathWithin(r, realTarget)
    );
    if (!inAllowed) {
      return {
        allowed: false, code: 'RESOURCE_SANDBOX_ESCAPE',
        reason: 'file:// URI escapes allowed workspace',
      };
    }
  }
  return { allowed: true };
}

export function sanitizeSamplingCreateMessage(msg) {
  if (!msg || typeof msg !== 'object' ||
      msg.method !== 'sampling/createMessage') {
    return { isSampling: false, quarantined: false,
             message: msg };
  }
  const params = msg.params &&
    typeof msg.params === 'object' ? msg.params : {};
  const smug = scanUnicodeSmuggling(
    JSON.stringify(params)
  );
  if (smug.length > 0) {
    return {
      isSampling: true,
      quarantined: true,
      code: -32012,
      reason: `Blocked ${smug[0].category} ` +
        `(${smug[0].codePointHex}) in sampling`,
      message: null,
    };
  }
  const {
    systemPrompt: _dropSp,
    includeContext: _dropIc,
    ...safeParams
  } = params;
  return {
    isSampling: true,
    quarantined: false,
    strippedFields: [
      ...('systemPrompt' in params ? ['systemPrompt'] : []),
      ...('includeContext' in params
        ? ['includeContext'] : []),
    ],
    message: { ...msg, params: safeParams },
  };
}


export const DEFAULT_SPILL_THRESHOLD_BYTES =
  100 * 1024;

function matchToolPattern(name, pat) {
  const p = String(pat || '').trim();
  if (!p) return false;
  if (p === '*' || p === name) return true;
  if (p.includes('*')) {
    const esc = p.replace(
      /[.+?^${}()|[\]\\]/g, '\\$&'
    ).replace(/\*/g, '.*');
    return new RegExp(`^${esc}$`).test(name);
  }
  return false;
}

export function isToolAllowedByDiet(
  toolName, allowTools = null, excludeTools = null
) {
  const n = String(toolName || '');
  if (Array.isArray(allowTools) &&
      allowTools.length > 0) {
    if (!allowTools.some((p) => matchToolPattern(n, p))) {
      return false;
    }
  }
  if (Array.isArray(excludeTools) &&
      excludeTools.length > 0) {
    if (excludeTools.some(
      (p) => matchToolPattern(n, p)
    )) {
      return false;
    }
  }
  return true;
}

export function applySipF03SpillGuard(
  msg, workspaceDir,
  thresholdBytes = DEFAULT_SPILL_THRESHOLD_BYTES
) {
  if (!msg || typeof msg !== 'object' || !msg.result) {
    return { spilled: false, message: msg };
  }
  const raw = JSON.stringify(msg.result);
  const byteLen = Buffer.byteLength(raw, 'utf8');
  if (byteLen <= thresholdBytes) {
    return { spilled: false, message: msg };
  }
  const spillDir = path.join(
    path.resolve(workspaceDir || process.cwd()),
    '.sip', 'spill'
  );
  fs.mkdirSync(spillDir, { recursive: true, mode: 0o700 });
  const id = `${Date.now()}-` +
    crypto.randomBytes(4).toString('hex');
  const spillPath = path.join(
    spillDir, `spill-${id}.json`
  );
  const digest = crypto.createHash('sha256')
    .update(raw, 'utf8').digest('hex');
  writeFileAtomic600(spillPath, raw + '\n', {
    mode: 0o600,
  });
  const preview = raw.slice(0, 1024);
  const summaryText =
    '[SHULIAK SIP-F03_OVERSIZED_PAYLOAD_SPILL] ' +
    `Response (${byteLen} bytes > ${thresholdBytes}B) ` +
    `spilled to ${spillPath} (sha256=${digest.slice(0, 16)}` +
    `). Preview:\n${preview}`;
  return {
    spilled: true,
    spillPath,
    originalBytes: byteLen,
    ruleId: 'SIP-F03_OVERSIZED_PAYLOAD_SPILL',
    message: {
      ...msg,
      result: {
        content: [{ type: 'text', text: summaryText }],
        isError: false,
        _sipSpill: {
          ruleId: 'SIP-F03_OVERSIZED_PAYLOAD_SPILL',
          spillPath,
          originalBytes: byteLen,
          sha256: digest,
        },
      },
    },
  };
}

export function createOrphanProcessReaper({
  onOrphan,
  getPpid = () => process.ppid,
  intervalMs = 2000,
} = {}) {
  const initialPpid = getPpid();
  let triggered = false;
  const fire = (why) => {
    if (triggered) return;
    triggered = true;
    if (typeof onOrphan === 'function') onOrphan(why);
  };
  const check = () => {
    const cur = getPpid();
    if (cur !== initialPpid ||
        (initialPpid !== 1 && cur === 1)) {
      fire('PPID_CHANGED_OR_INIT');
    }
  };
  const timer = setInterval(check, intervalMs);
  if (typeof timer.unref === 'function') timer.unref();
  return {
    check,
    stop() { clearInterval(timer); },
  };
}

export const RUNTIME_TOOLS_LOCK_SIGN_LABEL = 'SIP-v3-RUNTIME-TOOLS-LOCK';

const WIN32_CMD_SHIMS = new Set(['npx', 'npm', 'pnpm', 'pnpx', 'yarn', 'bunx']);

const IBAN_WIRE_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g;
const PAN_WIRE_RE = /\b\d(?:[ -]?\d){12,18}\b/g;
const SECRET_WIRE_RE =
  /\b(?:(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{12,}|sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{12,}|(?:AKIA|ASIA)[0-9A-Z]{16}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{30,})\b/g;
const DSN_CRED_WIRE_RE = new RegExp('(\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|rediss?|amqps?|mssql|clickhouse):\\/\\/[^:\\s/@\"\'`]+:)([^@\\s\"\'`]+)@', 'gi');

/**
 * Safely resolve downstream spawn executable without ever enabling `shell: true`.
 * On `win32`, resolves bare package-runner shims (`npx`, `npm`, etc.) to `.cmd`.
 *
 * @param {string} command
 * @param {string} [platform=process.platform]
 * @returns {{ command: string, shell: false }}
 */
export function resolveSpawnCommand(command, platform = process.platform) {
  const trimmed = String(command || '').trim();
  if (!trimmed) {
    throw new Error('Downstream MCP server command cannot be empty');
  }
  if (
    platform === 'win32' &&
    !trimmed.includes('/') &&
    !trimmed.includes('\\') &&
    !/\.[A-Za-z0-9]+$/.test(trimmed) &&
    WIN32_CMD_SHIMS.has(trimmed.toLowerCase())
  ) {
    return { command: `${trimmed}.cmd`, shell: false };
  }
  return { command: trimmed, shell: false };
}

/**
 * Compute deterministic `0x06` RFC 8785 JCS SHA-256 digest over a downstream MCP server's `tools/list` schema.
 *
 * @param {string} serverName
 * @param {Array<Record<string, any>>} tools
 * @returns {string}
 */
export function computeCanonicalToolsDigest0x06(serverName, tools) {
  const normalizedTools = (Array.isArray(tools) ? tools : [])
    .map((t) => ({
      description: typeof t?.description === 'string' ? t.description : '',
      inputSchema: t?.inputSchema && typeof t.inputSchema === 'object' ? t.inputSchema : {},
      name: String(t?.name || ''),
      ...(typeof t?.title === 'string' &&
        t.title.length > 0 ? { title: t.title } : {}),
      ...(t?.annotations &&
        typeof t.annotations === 'object' &&
        Object.keys(t.annotations).length > 0
        ? { annotations: t.annotations } : {}),
      ...(t?.outputSchema && typeof t.outputSchema === 'object' && Object.keys(t.outputSchema).length > 0
        ? { outputSchema: t.outputSchema } : {}),
    }))
    .sort((a, b) => compareUtf16CodeUnits(a.name, b.name));

  const target = {
    serverName: String(serverName || 'mcp-server'),
    tools: normalizedTools,
    v: 'sip-runtime-tools/3.0',
  };
  return b64u(domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, jcsCanonicalize(target)));
}

/**
 * Verify or pin `tools/list` digest inside `.sip/runtime-tools-lock.json` (`0x06` + Custodian Ed25519).
 *
 * @param {{
 *   workspaceDir: string,
 *   serverName: string,
 *   tools: Array<Record<string, any>>,
 * }} params
 */
export async function verifyOrPinRuntimeToolsLock({ workspaceDir, serverName, tools }) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const lockPath = path.join(sipDir, 'runtime-tools-lock.json');

  // 1. Scan all tool names, descriptions, and inputSchema strings for Plane-14 / Bidi smuggling
  for (const tool of Array.isArray(tools) ? tools : []) {
    const toolText = [
      String(tool?.name || ''),
      String(tool?.title || ''),
      String(tool?.description || ''),
      JSON.stringify(tool?.inputSchema || {}),
      JSON.stringify(tool?.annotations || {}),
      JSON.stringify(tool?.outputSchema || {}),
    ].join('\n');
    const smuggling = scanUnicodeSmuggling(toolText);
    if (smuggling.length > 0) {
      return {
        allowed: false,
        status: 'PLANE14_UNICODE_SMUGGLING_QUARANTINED',
        reason: `Downstream tool "${String(tool?.name || 'unknown')}" injected hidden ${smuggling[0].category} (${smuggling[0].codePointHex})`,
        expectedDigest: null,
        actualDigest: null,
      };
    }
  }

  const actualDigest = computeCanonicalToolsDigest0x06(serverName, tools);

  return withPidLock(sipDir, () => {
    const kp = ensureDeviceEd25519Keypair(sipDir, { ephemeralOnly: false });

    /** @type {Record<string, string>} */
    let serversMap = {};
    if (fs.existsSync(lockPath)) {
      let existing;
      try {
        existing = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
      } catch {
        return {
          allowed: false,
          status: 'CORRUPTED_RUNTIME_TOOLS_LOCK',
          reason: '.sip/runtime-tools-lock.json is malformed JSON',
          expectedDigest: null,
          actualDigest,
        };
      }

      const unsignedCore = {
        keyId: existing.keyId,
        publicKeyB64u: existing.publicKeyB64u,
        schemaVersion: 'sip-runtime-tools.lock/v3.0',
        servers: existing.servers || {},
      };
      const expectedCoreDigest = domainSha256(
        DOMAIN_PREFIX.SCHEMA_LOCK,
        jcsCanonicalize(unsignedCore)
      );
      const sigOk =
        existing.publicKeyB64u === kp.publicKeyB64u &&
        existing.manifestDigestB64u === b64u(expectedCoreDigest) &&
        verifyDomainPayload(
          RUNTIME_TOOLS_LOCK_SIGN_LABEL,
          expectedCoreDigest,
          existing.signatureB64u || '',
          kp.publicKeyB64u
        );

      if (!sigOk) {
        return {
          allowed: false,
          status: 'FORGED_RUNTIME_TOOLS_LOCK',
          reason: 'Ed25519 signature or 0x06 JCS digest mismatch on .sip/runtime-tools-lock.json',
          expectedDigest: null,
          actualDigest,
        };
      }

      serversMap = { ...(existing.servers || {}) };
      if (Object.prototype.hasOwnProperty.call(serversMap, serverName)) {
        const pinnedDigest = serversMap[serverName];
        if (pinnedDigest !== actualDigest) {
          return {
            allowed: false,
            status: 'RUNTIME_TOOLS_RUG_PULL_QUARANTINED',
            reason: `Downstream server "${serverName}" mutated its live tools/list schema mid-session (expected ${pinnedDigest.slice(0, 16)}..., got ${actualDigest.slice(0, 16)}...)`,
            expectedDigest: pinnedDigest,
            actualDigest,
          };
        }
        return {
          allowed: true,
          status: 'VERIFIED_PINNED_TOOLS',
          reason: `Verified ${Array.isArray(tools) ? tools.length : 0} pinned tool schema(s) against 0x06 lock`,
          expectedDigest: pinnedDigest,
          actualDigest,
        };
      }
    }

    // First-seen clean `tools/list` for `serverName`: pin & sign atomically
    serversMap[serverName] = actualDigest;
    const sortedServers = {};
    for (const k of Object.keys(serversMap).sort(compareUtf16CodeUnits)) {
      sortedServers[k] = serversMap[k];
    }
    const unsignedCore = {
      keyId: kp.keyId,
      publicKeyB64u: kp.publicKeyB64u,
      schemaVersion: 'sip-runtime-tools.lock/v3.0',
      servers: sortedServers,
    };
    const coreDigestBuf = domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, jcsCanonicalize(unsignedCore));
    const signatureB64u = signDomainPayload(
      RUNTIME_TOOLS_LOCK_SIGN_LABEL,
      coreDigestBuf,
      kp.privateKey
    );
    const manifest = {
      ...unsignedCore,
      manifestDigestB64u: b64u(coreDigestBuf),
      signatureB64u,
    };
    writeFileAtomic600(lockPath, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });

    return {
      allowed: true,
      status: 'PINNED_INITIAL_TOOLS',
      reason: `Pinned ${Array.isArray(tools) ? tools.length : 0} downstream tool schema(s) into .sip/runtime-tools-lock.json`,
      expectedDigest: actualDigest,
      actualDigest,
    };
  });
}

/**
 * Format PAN twin with identical separator layout (` ` or `-`) if original PAN had separators,
 * while registering both formatted and raw-digit mappings in the volatile bijective vault.
 *
 * @param {string} originalMatch
 * @param {string} twinDigits
 */
function applyPanSeparatorTemplate(originalMatch, twinDigits) {
  let digitIdx = 0;
  let out = '';
  for (let i = 0; i < originalMatch.length; i++) {
    const ch = originalMatch[i];
    if (ch >= '0' && ch <= '9') {
      out += twinDigits[digitIdx++] ?? '';
    } else {
      out += ch;
    }
  }
  return digitIdx === twinDigits.length ? out : twinDigits;
}

const VAULT_MAP_MAGIC = Buffer.from('SIPVMAP1', 'ascii');
const MAX_SCANNABLE_OPAQUE_STRING_BYTES = 262_144; // 256 KiB
const BINARY_MIME_RE =
  /^(?:image\/|audio\/|video\/|font\/|application\/(?:octet-stream|pdf|zip|gzip|wasm)\b)/i;
const DATA_URI_BASE64_RE = /^data:[a-z0-9.+-]+\/[a-z0-9.+-]+;base64,/i;

/**
 * Determine whether a string or object field represents Base64/binary media (`image`, `audio`,
 * `blob`, `data:...;base64,`, or `> 256 KiB` whitespace-free opaque blob) that MUST bypass
 * regex twin scanning to prevent main-thread stalls or corrupted media payloads.
 *
 * @param {unknown} val
 * @param {string} [keyName='']
 * @returns {boolean}
 */
export function shouldBypassMediaPayload(val, keyName = '') {
  if (shouldBypassBinaryPayload(val, keyName)) return true;

  if (typeof val === 'string') {
    if (DATA_URI_BASE64_RE.test(val)) return true;
    if (val.length > MAX_SCANNABLE_OPAQUE_STRING_BYTES && !/\s/.test(val)) {
      return true;
    }
    return false;
  }

  if (val && typeof val === 'object' && !Array.isArray(val)) {
    const obj = /** @type {Record<string, unknown>} */ (val);
    if (obj.type === 'image' || obj.type === 'audio') {
      return true;
    }
    if (
      typeof obj.mimeType === 'string' &&
      BINARY_MIME_RE.test(obj.mimeType) &&
      typeof obj.text !== 'string'
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Derive deterministic 32-byte HMAC twin seed and 32-byte AES-256-GCM map encryption key
 * from the host-salted workspace enclave (`wrap-vault.kek`).
 *
 * @param {string} resolvedWs
 * @returns {{ hmacSeed32: Buffer, aesKey32: Buffer }}
 */
function loadOrInitPersistentVaultKeys(resolvedWs) {
  const enclaveDir = path.join(resolvedWs, '.sip', 'enclave');
  const enclave = createHeadlessEnclaveAdapter(enclaveDir);
  let rootKek;
  if (enclave.hasRootKey('wrap-vault')) {
    rootKek = enclave.unsealRootKey('wrap-vault');
  } else {
    rootKek = crypto.randomBytes(32);
    enclave.sealRootKey('wrap-vault', rootKek);
  }
  try {
    const hmacSeed32 = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        rootKek,
        Buffer.from('SIP-WRAP-VAULT-SALT\0', 'ascii'),
        Buffer.from('SIP-WRAP-TWIN-HMAC-v301\0', 'ascii'),
        32
      )
    );
    const aesKey32 = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        rootKek,
        Buffer.from('SIP-WRAP-VAULT-SALT\0', 'ascii'),
        Buffer.from('SIP-WRAP-MAP-AES256GCM-v301\0', 'ascii'),
        32
      )
    );
    return { hmacSeed32, aesKey32 };
  } finally {
    rootKek.fill(0);
  }
}

/**
 * Encrypt `[raw, twin]` entries with `AES-256-GCM` and write atomically (`0o600`) to `.sip/state/vault-map.enc`.
 *
 * @param {string} vaultPath
 * @param {Buffer} aesKey32
 * @param {string} aadContext
 * @param {Map<string, string>} rawToTwin
 */
function saveEncryptedVaultMap(vaultPath, aesKey32, aadContext, rawToTwin) {
  const iv12 = crypto.randomBytes(12);
  const plainJson = Buffer.from(
    JSON.stringify({
      v: 'sip-vault-map/3.1.0',
      pairs: [...rawToTwin.entries()],
    }),
    'utf8'
  );
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey32, iv12);
    cipher.setAAD(Buffer.concat([VAULT_MAP_MAGIC, Buffer.from(aadContext, 'utf8')]));
    const enc = Buffer.concat([cipher.update(plainJson), cipher.final()]);
    const tag16 = cipher.getAuthTag();
    const envelope = Buffer.concat([VAULT_MAP_MAGIC, iv12, tag16, enc]);
    writeFileAtomic600(vaultPath, envelope, { mode: 0o600 });
  } finally {
    plainJson.fill(0);
  }
}

/**
 * Load and authenticate `AES-256-GCM` `.sip/state/vault-map.enc` into `{ rawToTwin, twinToRaw }`.
 *
 * @param {string} vaultPath
 * @param {Buffer} aesKey32
 * @param {string} aadContext
 * @param {Map<string, string>} rawToTwin
 * @param {Map<string, string>} twinToRaw
 */
function loadEncryptedVaultMap(vaultPath, aesKey32, aadContext, rawToTwin, twinToRaw) {
  if (!fs.existsSync(vaultPath)) return;
  const envelope = fs.readFileSync(vaultPath);
  if (envelope.byteLength < 36 || !envelope.subarray(0, 8).equals(VAULT_MAP_MAGIC)) {
    throw new Error('Corrupted .sip/state/vault-map.enc header');
  }
  const iv12 = envelope.subarray(8, 20);
  const tag16 = envelope.subarray(20, 36);
  const ciphertext = envelope.subarray(36);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey32, iv12);
  decipher.setAAD(Buffer.concat([VAULT_MAP_MAGIC, Buffer.from(aadContext, 'utf8')]));
  decipher.setAuthTag(tag16);
  const plainBuf = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  try {
    const parsed = JSON.parse(plainBuf.toString('utf8'));
    if (parsed && Array.isArray(parsed.pairs)) {
      for (const item of parsed.pairs) {
        if (Array.isArray(item) && typeof item[0] === 'string' && typeof item[1] === 'string') {
          rawToTwin.set(item[0], item[1]);
          twinToRaw.set(item[1], item[0]);
        }
      }
    }
  } finally {
    plainBuf.fill(0);
  }
}

/**
 * Create a stateful bidirectional MCP proxy session enforcing Gates 1, 2, and 3:
 * - Persistent in-RAM ISEP keyring handle opened at most once per proxy session
 * - Base64 / `image` / `audio` / `blob` / `>256 KiB` media bypass
 * - `tools/call` AND `resources/read` Gate 3 outbound scrubbing
 * - Host-salted AES-256-GCM persistent twin map at `.sip/state/vault-map.enc`
 *
 * @param {{
 *   serverName: string,
 *   workspaceDir?: string,
 *   enableIsep?: boolean,
 *   warrantToken?: string | null,
 *   sessionSecret32?: Buffer,
 *   persistVault?: boolean,
 * }} params
 */
export function createInlineProxySession({
  serverName,
  workspaceDir = process.cwd(),
  enableIsep = true,
  warrantToken = null,
  sessionSecret32,
  persistVault,
  strictResponseId = false,
  enableIfc = true,
  ifcSessionId = null,
  ifcHmacKeyPath = null,
  allowTools = null,
  excludeTools = null,
  spillThresholdBytes = DEFAULT_SPILL_THRESHOLD_BYTES,
}) {
  const resolvedWs = path.resolve(workspaceDir);
  const safeServer = String(serverName || 'wrapped-mcp');
  const vaultMapPath = path.join(resolvedWs, '.sip', 'state', 'vault-map.enc');
  const vaultAadContext = `|${resolvedWs}`;

  // Persist encrypted `.sip/state/vault-map.enc` by default unless ephemeral `sessionSecret32` is explicitly supplied and `persistVault` is false
  const shouldPersistVault =
    persistVault !== undefined ? Boolean(persistVault) : sessionSecret32 === undefined;

  /** @type {Buffer} */
  let secret32;
  /** @type {Buffer | null} */
  let vaultAesKey32 = null;

  /** @type {Map<string, string>} */
  const twinToRaw = new Map();
  /** @type {Map<string, string>} */
  const rawToTwin = new Map();
  /** @type {Map<string | number, { method: string, toolName: string | null, safeArgs: unknown }>} */
  const inflightRequests = new Map();
  let hostRequestCount = 0;

  if (shouldPersistVault) {
    const keys = loadOrInitPersistentVaultKeys(resolvedWs);
    secret32 = sessionSecret32 ? Buffer.from(sessionSecret32) : keys.hmacSeed32;
    if (sessionSecret32) keys.hmacSeed32.fill(0);
    vaultAesKey32 = keys.aesKey32;
    try {
      loadEncryptedVaultMap(vaultMapPath, vaultAesKey32, vaultAadContext, rawToTwin, twinToRaw);
    } catch {
      // If machine-salt rotated or vault-map was invalidated, start fresh clean map
      rawToTwin.clear();
      twinToRaw.clear();
    }
  } else {
    secret32 = Buffer.from(sessionSecret32 || crypto.randomBytes(32));
  }

  let vaultDirty = false;
  /** @type {any} */
  let activeIsepKeyring = null;
  let isepOpenCount = 0;

  function flushVaultMapToDisk() {
    if (!shouldPersistVault || !vaultDirty || !vaultAesKey32) return;
    saveEncryptedVaultMap(vaultMapPath, vaultAesKey32, vaultAadContext, rawToTwin);
    vaultDirty = false;
  }

  function ensurePersistentIsepHandle() {
    if (!enableIsep) return null;
    if (activeIsepKeyring && !activeIsepKeyring.closed) {
      return activeIsepKeyring;
    }
    const isepPaths = resolveIsepPaths({ workspaceDir: resolvedWs });
    if (!fs.existsSync(isepPaths.keyringPath)) {
      return null;
    }
    activeIsepKeyring = openKeyring({ workspaceDir: resolvedWs });
    isepOpenCount++;
    return activeIsepKeyring;
  }

  function closePersistentIsepHandle() {
    if (activeIsepKeyring && !activeIsepKeyring.closed) {
      try {
        closeKeyring(activeIsepKeyring);
      } catch {
        // Ignore already-closed handle
      }
    }
    activeIsepKeyring = null;
  }

  function deriveVaultKeyAndTweak(canonicalTag) {
    const rSlot32 = crypto
      .createHmac('sha256', secret32)
      .update(Buffer.from('SIP5-WRAP-VAULT-KEY\0', 'utf8'))
      .update(Buffer.from(canonicalTag, 'utf8'))
      .digest();
    const tweak16 = crypto
      .createHmac('sha256', secret32)
      .update(Buffer.from('SIP5-WRAP-VAULT-TWK\0', 'utf8'))
      .update(Buffer.from(canonicalTag, 'utf8'))
      .digest()
      .subarray(0, 16);
    return { rSlot32, tweak16 };
  }

  function registerBijectivePair(rawVal, twinVal) {
    if (rawToTwin.get(rawVal) !== twinVal) {
      vaultDirty = true;
    }
    rawToTwin.set(rawVal, twinVal);
    twinToRaw.set(twinVal, rawVal);
  }

  function tokenizeText(str) {
    if (typeof str === 'string') {
      str = normalizeUnicodeEvasion(str);
    }
    if (typeof str !== 'string' || str.length === 0) return str;
    if (shouldBypassMediaPayload(str)) return str;
    const P14 = /[\u{E0000}-\u{E007F}]/gu;
    let out = str.replace(P14, '');

    // 1. DSN embedded passwords
    out = out.replace(DSN_CRED_WIRE_RE, (_full, prefix, pass) => {
      let twin = rawToTwin.get(pass);
      if (!twin) {
        const { rSlot32, tweak16 } = deriveVaultKeyAndTweak(`dsn:${pass}`);
        twin = synthesizeScopedToken(rSlot32, tweak16, `dsn:${pass}`);
        registerBijectivePair(pass, twin);
      }
      return `${prefix}${twin}@`;
    });

    // 2. Vendor API secrets (Stripe sk_live_, OpenAI sk-proj-, AWS AKIA, GitHub ghp_, etc.)
    out = out.replace(SECRET_WIRE_RE, (match) => {
      if (twinToRaw.has(match)) return match;
      let twin = rawToTwin.get(match);
      if (!twin) {
        const { rSlot32, tweak16 } = deriveVaultKeyAndTweak(`secret:${match}`);
        twin = synthesizeScopedToken(rSlot32, tweak16, `secret:${match}`);
        registerBijectivePair(match, twin);
      }
      return twin;
    });

    // 3. Valid ISO-7064 MOD-97-10 IBANs
    out = out.replace(IBAN_WIRE_RE, (match) => {
      const clean = match.toUpperCase();
      if (ibanMod97(clean) !== 1) return match;
      if (twinToRaw.has(clean)) return match;
      let twin = rawToTwin.get(clean);
      if (!twin) {
        const { rSlot32, tweak16 } = deriveVaultKeyAndTweak(`iban:${clean}`);
        twin = synthesizeIbanTwin(rSlot32, tweak16, clean);
        registerBijectivePair(clean, twin);
      }
      return twin;
    });

    // 4. Valid ISO/IEC 7812 Luhn PANs
    out = out.replace(PAN_WIRE_RE, (match) => {
      const digits = match.replace(/[\s-]+/g, '');
      if (!isValidLuhnPan(digits)) return match;
      if (twinToRaw.has(digits)) return match;
      let twinDigits = rawToTwin.get(digits);
      if (!twinDigits) {
        const { rSlot32, tweak16 } = deriveVaultKeyAndTweak(`pan:${digits}`);
        twinDigits = synthesizePanTwin(rSlot32, tweak16, digits);
        registerBijectivePair(digits, twinDigits);
      }
      const formattedTwin = applyPanSeparatorTemplate(match, twinDigits);
      if (formattedTwin !== twinDigits) {
        registerBijectivePair(match, formattedTwin);
      }
      return formattedTwin;
    });

    if (vaultDirty) {
      flushVaultMapToDisk();
    }
    return out;
  }

  function tokenizeValueDeep(val, keyName = '') {
    if (keyName === 'id' || keyName === 'jsonrpc') {
      return val;
    }
    if (typeof val === 'string' &&
        isSafeNumericIdKey(keyName) &&
        /^\d{13,19}$/.test(val.trim())) {
      return val;
    }
    if (val === null || val === undefined || typeof val === 'boolean' || typeof val === 'number') {
      return val;
    }
    if (shouldBypassMediaPayload(val, keyName)) {
      return val;
    }
    if (typeof val === 'string') {
      return tokenizeText(val);
    }
    if (Array.isArray(val)) {
      return val.map((item) => tokenizeValueDeep(item));
    }
    if (typeof val === 'object') {
      /** @type {Record<string, unknown>} */
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (k === '__proto__' || k === 'constructor' ||
            k === 'prototype') continue;
        out[k] = tokenizeValueDeep(v, k);
      }
      return out;
    }
    return val;
  }

  function detokenizeText(str) {
    if (typeof str !== 'string' || str.length === 0 || twinToRaw.size === 0) return str;
    if (shouldBypassMediaPayload(str)) return str;
    let out = str;
    // Sort twins longest-first so formatted twins replace cleanly before bare-digit twins
    const entries = [...twinToRaw.entries()].sort((a, b) => b[0].length - a[0].length);
    for (const [twin, raw] of entries) {
      if (out.includes(twin)) {
        out = out.split(twin).join(raw);
      }
    }
    return out;
  }

  function detokenizeValueDeep(val, keyName = '') {
    if (val === null || val === undefined || typeof val === 'boolean' || typeof val === 'number') {
      return val;
    }
    if (shouldBypassMediaPayload(val, keyName)) {
      return val;
    }
    if (typeof val === 'string') {
      return detokenizeText(val);
    }
    if (Array.isArray(val)) {
      return val.map((item) => detokenizeValueDeep(item));
    }
    if (typeof val === 'object') {
      /** @type {Record<string, unknown>} */
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (k === '__proto__' || k === 'constructor' ||
            k === 'prototype') continue;
        out[k] = detokenizeValueDeep(v, k);
      }
      return out;
    }
    return val;
  }

  async function maybeRecordIsepFlightEvent(toolName, safeArgs, decisionMeta) {
    if (!enableIsep) return null;
    const isepPaths = resolveIsepPaths({ workspaceDir: resolvedWs });
    if (!fs.existsSync(isepPaths.keyringPath)) {
      return null;
    }
    return withPidLock(isepPaths.sipDir, () => {
      const kr = ensurePersistentIsepHandle();
      if (!kr) return null;
      return recordAgentEvent(kr, {
        server: safeServer,
        tool: toolName,
        args: {
          ...(safeArgs && typeof safeArgs === 'object' ? safeArgs : {}),
          _sipProxyGate: decisionMeta,
        },
      });
    });
  }

  /**
   * Gate 2 + Gate 3 Inbound: Inspect JSON-RPC frame sent from Host IDE -> Downstream MCP Server.
   * Returns `{ action: 'FORWARD', message }` or `{ action: 'INTERCEPT_REPLY', reply }`.
   *
   * @param {Record<string, any>} requestMsg
   */
  async function inspectHostRequest(requestMsg) {
    if (!requestMsg || typeof requestMsg !== 'object') {
      return { action: 'FORWARD', message: requestMsg };
    }

    const method = typeof requestMsg.method === 'string' ? requestMsg.method : '';
    const hasId = Object.prototype.hasOwnProperty.call(requestMsg, 'id') && requestMsg.id !== undefined;

    if (method === 'tools/list' && hasId) {
      hostRequestCount++;
      inflightRequests.set(requestMsg.id, {
        method: 'tools/list',
        toolName: null,
        safeArgs: null,
      });
      return { action: 'FORWARD', message: requestMsg };
    }

    if (method === 'resources/read') {
      const params = requestMsg.params &&
        typeof requestMsg.params === 'object'
        ? requestMsg.params : {};
      const uriChk = inspectResourceReadUri(
        params.uri, resolvedWs
      );
      if (!uriChk.allowed) {
        const reply = {
          jsonrpc: '2.0',
          id: hasId ? requestMsg.id : null,
          error: {
            code: -32011,
            message: '[SHULIAK SIP GATE 2 RESOURCE ' +
              `BLOCKED] (${uriChk.code}): ` +
              uriChk.reason,
            data: { code: uriChk.code },
          },
        };
        return {
          action: 'INTERCEPT_REPLY',
          reply,
          guardOutcome: uriChk,
        };
      }
      const twinSafeParams = /** @type {Record<string, unknown>} */ (tokenizeValueDeep(params));
      const downstreamParams = detokenizeValueDeep(params);
      let ifcOp = null;
      if (enableIfc) {
        ifcOp = beginIfcOperation({
          workspaceDir: resolvedWs,
          sessionId: ifcSessionId,
          server: safeServer,
          tool: 'resources/read',
          method: 'resources/read',
          args: downstreamParams,
          hmacKeyPath: ifcHmacKeyPath,
        });
      }
      if (hasId) {
        hostRequestCount++;
      inflightRequests.set(requestMsg.id, {
          method: 'resources/read',
          toolName: 'resources/read',
          safeArgs: twinSafeParams,
          ifcOpId: ifcOp?.opId || null,
          ifcCaps: ifcOp?.caps || null,
        });
      }
      return {
        action: 'FORWARD',
        message: {
          ...requestMsg,
          params: downstreamParams,
        },
      };
    }

    if (method === 'tools/call') {
      const params = requestMsg.params && typeof requestMsg.params === 'object' ? requestMsg.params : {};
      const toolName = typeof params.name === 'string' ? params.name : 'unknown-tool';
      if (!isToolAllowedByDiet(
        toolName, allowTools, excludeTools
      )) {
        return {
          action: 'INTERCEPT_REPLY',
          reply: {
            jsonrpc: '2.0',
            id: hasId ? requestMsg.id : null,
            error: {
              code: -32011,
              message: '[SHULIAK SIP DIET] Tool ' +
                `"${toolName}" excluded by policy`,
            },
          },
        };
      }
      const incomingArgs = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
      const metaWarrant =
        params._meta && typeof params._meta === 'object' && typeof params._meta.sipWarrantToken === 'string'
          ? params._meta.sipWarrantToken
          : null;

      // Detokenize any persistent/in-RAM twin values BEFORE AST guard & downstream forwarding
      // so the downstream tool (and exact action digest) sees the true intended arguments
      const downstreamArgs = /** @type {Record<string, unknown>} */ (detokenizeValueDeep(incomingArgs));
      // Tokenize any raw PAN/IBAN accidentally supplied by user prompt before ISEP logging
      const twinSafeArgs = /** @type {Record<string, unknown>} */ (tokenizeValueDeep(downstreamArgs));

      // Gate 2: Run Stage 2 Pre-Tool Guard
      const guardOutcome = await evaluatePreToolGuard({
        workspaceDir: resolvedWs,
        server: safeServer,
        tool: toolName,
        args: downstreamArgs,
        warrantToken: metaWarrant || warrantToken || process.env.SIP_WARRANT_TOKEN || null,
        autoSnapshot: true,
      });

      if (guardOutcome.decision === 'BLOCK') {
        await maybeRecordIsepFlightEvent(toolName, twinSafeArgs, {
          decision: 'BLOCK',
          tier: guardOutcome.tier,
          code: guardOutcome.code,
        });

        const unlockCmd = `npx -y @shuliak-corp/sip1-mcp warrant issue --server ${safeServer} --tool ${toolName} --args '${JSON.stringify(twinSafeArgs)}'`;
        const reply = {
          jsonrpc: '2.0',
          id: hasId ? requestMsg.id : null,
          result: {
            isError: true,
            content: [
              {
                type: 'text',
                text:
                  `[SHULIAK SIP GATE 2 BLOCKED] ${guardOutcome.tier} (${guardOutcome.code}): ${guardOutcome.reason}\n` +
                  `1-Command Ed25519 Warrant Unlock: ${unlockCmd}`,
              },
            ],
          },
        };
        return { action: 'INTERCEPT_REPLY', reply, guardOutcome };
      }

      let ifcOp = null;
      if (enableIfc) {
        const effWarrant = metaWarrant ||
          warrantToken ||
          process.env.SIP_WARRANT_TOKEN || null;
        const wPreOk = /WARRANT|LEASE/i.test(
          String(guardOutcome?.code || '')
        );
        ifcOp = await beginIfcOperationAsync({
          workspaceDir: resolvedWs,
          sessionId: ifcSessionId,
          server: safeServer,
          tool: toolName,
          method: 'tools/call',
          args: downstreamArgs,
          warrantToken: effWarrant,
          warrantAlreadyVerified: wPreOk,
          hmacKeyPath: ifcHmacKeyPath,
        });
        if (!ifcOp.allowed) {
          const unlockCmd =
            'npx -y @shuliak-corp/sip1-mcp warrant ' +
            `issue --server ${safeServer} ` +
            `--tool ${toolName} ` +
            `--args '${JSON.stringify(twinSafeArgs)}'`;
          const reply = {
            jsonrpc: '2.0',
            id: hasId ? requestMsg.id : null,
            result: {
              resultType: 'complete',
              isError: true,
              content: [{
                type: 'text',
                text: '[SHULIAK SIP IFC TRIFECTA ' +
                  `BLOCKED] (${ifcOp.code}): ` +
                  `${ifcOp.reason}\n` +
                  '1-Command Ed25519 Warrant Unlock: ' +
                  unlockCmd,
              }],
            },
          };
          return {
            action: 'INTERCEPT_REPLY',
            reply,
            ifcOutcome: ifcOp,
          };
        }
      }
      if (hasId) {
        hostRequestCount++;
      inflightRequests.set(requestMsg.id, {
          method: 'tools/call',
          toolName,
          safeArgs: twinSafeArgs,
          ifcOpId: ifcOp?.opId || null,
          ifcCaps: ifcOp?.caps || null,
        });
      }

      const forwardedMsg = {
        ...requestMsg,
        params: {
          ...params,
          arguments: downstreamArgs,
        },
      };
      return { action: 'FORWARD', message: forwardedMsg, guardOutcome };
    }

    if (hasId) {
      hostRequestCount++;
      inflightRequests.set(requestMsg.id, {
        method: method || 'unknown',
        toolName: null,
        safeArgs: null,
      });
    }
    return { action: 'FORWARD', message: requestMsg };
  }

  /**
   * Gate 1 + Gate 3 Outbound: Inspect JSON-RPC frame returning from Downstream MCP Server -> Host IDE.
   * Covers `tools/list` schema lock, `tools/call` results, and `resources/read` (`result.contents[].text`) results,
   * while bypassing `image`, `audio`, `blob`, and `>256 KiB` opaque binary payloads.
   *
   * @param {Record<string, any>} responseMsg
   */
  async function inspectDownstreamResponse(responseMsg) {
    if (!responseMsg || typeof responseMsg !== 'object') {
      return { quarantined: false, message: responseMsg };
    }

    const hasId = Object.prototype.hasOwnProperty.
      call(responseMsg, 'id') &&
      responseMsg.id !== undefined;
    const isRespFrame =
      typeof responseMsg.method !== 'string' &&
      ('result' in responseMsg ||
        'error' in responseMsg);
    const reqMeta = hasId
      ? inflightRequests.get(responseMsg.id) || null
      : null;
    if (hasId) {
      inflightRequests.delete(responseMsg.id);
    }
    if (isRespFrame && hasId && !reqMeta &&
        (strictResponseId || hostRequestCount > 0)) {
      return {
        dropped: true,
        quarantined: true,
        reason: 'FOREIGN_RESPONSE_ID',
        message: null,
      };
    }
    const sampChk =
      sanitizeSamplingCreateMessage(responseMsg);
    if (sampChk.quarantined) {
      return {
        quarantined: true,
        message: {
          jsonrpc: '2.0',
          id: responseMsg.id ?? null,
          error: {
            code: -32012,
            message: '[SHULIAK SIP SAMPLING] ' +
              sampChk.reason,
          },
        },
      };
    }
    if (sampChk.isSampling) {
      responseMsg = sampChk.message;
    }
    const elicCheck =
      inspectElicitationOrInputRequired(responseMsg);
    if (elicCheck.blocked) {
      return {
        quarantined: true,
        message: {
          jsonrpc: '2.0',
          id: responseMsg.id ?? null,
          error: {
            code: -32012,
            message: '[SHULIAK SIP CVE-2026-120779] ' +
              elicCheck.reason,
          },
        },
      };
    }

    // Also inspect spontaneous tool list or response bearing result.tools
    const isToolsListReply =
      reqMeta?.method === 'tools/list' ||
      (responseMsg.result && Array.isArray(responseMsg.result.tools));

    if (isToolsListReply && responseMsg.result && Array.isArray(responseMsg.result.tools)) {
      const lockCheck = await verifyOrPinRuntimeToolsLock({
        workspaceDir: resolvedWs,
        serverName: safeServer,
        tools: responseMsg.result.tools,
      });

      if (!lockCheck.allowed) {
        const quarantinedFrame = {
          jsonrpc: '2.0',
          id: responseMsg.id ?? null,
          error: {
            code: -32011,
            message: `[SHULIAK SIP GATE 1 QUARANTINE] ${lockCheck.status}: ${lockCheck.reason}`,
            data: {
              server: safeServer,
              status: lockCheck.status,
              expectedDigest: lockCheck.expectedDigest,
              actualDigest: lockCheck.actualDigest,
            },
          },
        };
        return {
          quarantined: true,
          lockCheck,
          message: quarantinedFrame,
        };
      }
    }

    if (isToolsListReply && responseMsg.result &&
        Array.isArray(responseMsg.result.tools)) {
      const _cTl = sanitizeAndPinToolsList(
        responseMsg.result.tools, null
      );
      const _dietTools = _cTl.tools.filter((t) =>
        isToolAllowedByDiet(
          t?.name, allowTools, excludeTools
        )
      );
      responseMsg = {
        ...responseMsg,
        result: {
          ...responseMsg.result, tools: _dietTools,
        },
      };
    }
    // Gate 3 Outbound: Scrub PANs, IBANs, and API secrets in `tools/call` & `resources/read` text results
    const preScrubJson = enableIfc && reqMeta?.ifcOpId
      ? JSON.stringify(responseMsg) : '';
    const scrubbedMsg = /** @type {Record<string, any>} */ (tokenizeValueDeep(responseMsg));
    if (enableIfc && reqMeta?.ifcOpId) {
      const postScrubJson = JSON.stringify(scrubbedMsg);
      commitIfcOperation({
        workspaceDir: resolvedWs,
        sessionId: ifcSessionId,
        opId: reqMeta.ifcOpId,
        caps: reqMeta.ifcCaps,
        declassifiedByTwins:
          isResultDeclassifiedByTwins(
            preScrubJson, postScrubJson,
            scrubbedMsg, twinToRaw.keys()
          ),
        failed: Boolean(responseMsg.error),
        hmacKeyPath: ifcHmacKeyPath,
      });
    }

    if (
      (reqMeta?.method === 'tools/call' || reqMeta?.method === 'resources/read') &&
      reqMeta.toolName
    ) {
      await maybeRecordIsepFlightEvent(reqMeta.toolName, reqMeta.safeArgs, {
        decision: 'ALLOW_FORWARDED',
        vaultSize: twinToRaw.size,
      });
    }

    let finalMsg = scrubbedMsg;
    if (reqMeta?.method === 'tools/call' ||
        reqMeta?.method === 'resources/read') {
      const sp = applySipF03SpillGuard(
        scrubbedMsg, resolvedWs, spillThresholdBytes
      );
      if (sp.spilled) finalMsg = sp.message;
    }
    return {
      quarantined: false,
      message: finalMsg,
    };
  }

  /**
   * Gracefully flush `.sip/state/vault-map.enc`, close the persistent ISEP keyring handle,
   * and zeroize in-RAM key/twin buffers on normal proxy shutdown (`SIGINT`/`SIGTERM`/`EOF`).
   */
  function closeSession() {
    try {
      flushVaultMapToDisk();
    } catch {
      // Ignore disk errors during teardown
    }
    closePersistentIsepHandle();
    secret32.fill(0);
    if (vaultAesKey32) vaultAesKey32.fill(0);
    twinToRaw.clear();
    rawToTwin.clear();
    inflightRequests.clear();
  }

  /**
   * Emergency cryptographic shred: zeroize RAM buffers, close ISEP handle, AND unlink `.sip/state/vault-map.enc`.
   */
  function wipeVault() {
    closePersistentIsepHandle();
    secret32.fill(0);
    if (vaultAesKey32) vaultAesKey32.fill(0);
    twinToRaw.clear();
    rawToTwin.clear();
    inflightRequests.clear();
    vaultDirty = false;
    try {
      if (fs.existsSync(vaultMapPath)) {
        fs.unlinkSync(vaultMapPath);
      }
    } catch {
      // Ignore if already removed
    }
  }

  return {
    inspectHostRequest,
    scrubStderrText: (s) => tokenizeValueDeep(s),
    inspectDownstreamResponse,
    closeSession,
    wipeVault,
    getVaultSize: () => twinToRaw.size,
    getTwinSnapshot: () => [...twinToRaw.keys()],
    getIsepOpenCount: () => isepOpenCount,
    vaultMapPath,
  };
}

/**
 * Run the live transparent `stdio` MCP firewall wrapping a downstream MCP server process.
 *
 * @param {{
 *   serverName: string,
 *   command: string,
 *   args?: string[],
 *   workspaceDir?: string,
 *   enableIsep?: boolean,
 *   warrantToken?: string | null,
 *   persistVault?: boolean,
 *   input?: NodeJS.ReadableStream,
 *   output?: { write: (chunk: string) => unknown },
 *   errorOutput?: { write: (chunk: string) => unknown },
 *   env?: NodeJS.ProcessEnv,
 * }} params
 * @returns {Promise<{ exitCode: number }>}
 */
export async function runMcpWrapProxy({
  serverName,
  command,
  args = [],
  workspaceDir = process.cwd(),
  enableIsep = true,
  warrantToken = null,
  persistVault = true,
  input = process.stdin,
  output = process.stdout,
  errorOutput = process.stderr,
  env = process.env,
  allowTools = null,
  excludeTools = null,
  spillThresholdBytes = DEFAULT_SPILL_THRESHOLD_BYTES,
}) {
  const resolvedWs = path.resolve(workspaceDir);
  const spawnSpec = resolveSpawnCommand(command);
  const session = createInlineProxySession({
    serverName,
    workspaceDir: resolvedWs,
    enableIsep,
    warrantToken,
    persistVault,
    strictResponseId: true,
    allowTools,
    excludeTools,
    spillThresholdBytes,
  });
  const cmdBase = path.basename(spawnSpec.command)
    .toLowerCase();
  const npxLock = (cmdBase === 'npx' ||
    cmdBase === 'npx.cmd')
    ? acquireNpxColdStartLock({
        lockDir: path.join(resolvedWs, '.sip', 'locks'),
      })
    : null;
  const child = spawn(spawnSpec.command, args, {
    cwd: resolvedWs,
    env,
    shell: spawnSpec.shell,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (npxLock) {
    let released = false;
    const rel = () => {
      if (released) return;
      released = true;
      npxLock.release();
    };
    child.stdout.once('data', rel);
    child.once('close', rel);
    const tRel = setTimeout(rel, 2500);
    if (typeof tRel.unref === 'function') tRel.unref();
  }

  let closedOnce = false;
  const safeCloseSession = () => {
    if (closedOnce) return;
    closedOnce = true;
    session.closeSession();
  };

  const onSigInt = () => {
    safeCloseSession();
    if (!child.killed) child.kill('SIGINT');
  };
  const onSigTerm = () => {
    safeCloseSession();
    if (!child.killed) child.kill('SIGTERM');
  };
  const reapChild = (sig = 'SIGTERM') => {
    safeCloseSession();
    if (!child.killed) {
      try { child.kill(sig); } catch {}
      const kt = setTimeout(() => {
        if (!child.killed) {
          try { child.kill('SIGKILL'); } catch {}
        }
      }, 1500);
      if (typeof kt.unref === 'function') kt.unref();
    }
  };
  const onSigHup = () => reapChild('SIGTERM');
  const orphanReaper = createOrphanProcessReaper({
    onOrphan: () => reapChild('SIGTERM'),
  });
  process.once('SIGINT', onSigInt);
  process.once('SIGTERM', onSigTerm);
  process.once('SIGHUP', onSigHup);

  const _errDec = new StringDecoder('utf8');
  child.stderr.on('data', (chunk) => {
    const decS = _errDec.write(chunk);
    const noOsc = stripTerminalControlCodes(decS);
    const safeS = session.scrubStderrText
      ? session.scrubStderrText(noOsc) : noOsc;
    errorOutput.write(safeS);
  });

  const hostRl = readline.createInterface({
    input,
    crlfDelay: Infinity,
  });

  const childRl = readline.createInterface({
    input: child.stdout,
    crlfDelay: Infinity,
  });

  /** @type {Promise<unknown>} */
  let hostQueue = Promise.resolve();
  /** @type {Promise<unknown>} */
  let childQueue = Promise.resolve();

  hostRl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    hostQueue = hostQueue
      .then(async () => {
        let parsed;
        try {
          const sf = parseStrictJsonRpcFrame(trimmed);
          if (!sf.ok) {
            const eS = JSON.stringify(
              sf.errorResponse
            );
            output.write(eS + '\n');
            return;
          }
          parsed = sf.message;
        } catch {
          output.write(
            JSON.stringify({
              jsonrpc: '2.0',
              id: null,
              error: { code: -32700, message: 'Parse error on host JSON-RPC frame' },
            }) + '\n'
          );
          return;
        }

        const decision = await session.inspectHostRequest(parsed);
        if (decision.action === 'INTERCEPT_REPLY') {
          output.write(JSON.stringify(decision.reply) + '\n');
          return;
        }

        if (child.stdin && !child.stdin.destroyed && child.stdin.writable) {
          child.stdin.write(JSON.stringify(decision.message) + '\n');
        }
      })
      .catch((err) => {
        errorOutput.write(
          `[SIP WRAP STDERR] Host frame error: ${err instanceof Error ? err.message : String(err)}\n`
        );
      });
  });

  childRl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    childQueue = childQueue
      .then(async () => {
        let parsed;
        try {
          const sf = parseStrictJsonRpcFrame(trimmed);
          if (!sf.ok) {
            errorOutput.write(
              '[SIP WRAP STDERR] Quarantined child ' +
              `${sf.reason}\n`
            );
            return;
          }
          parsed = sf.message;
        } catch {
          errorOutput.write(
            '[SIP WRAP STDERR] Dropped non-JSON ' +
            'downstream frame\n'
          );
          return;
        }
        const elicChk =
          inspectElicitationOrInputRequired(parsed);
        const isSrvCb =
          parsed && typeof parsed === 'object' &&
          typeof parsed.method === 'string' &&
          /^(?:sampling|elicitation)\//.test(
            parsed.method
          );
        if (elicChk.blocked ||
            (isSrvCb &&
             !process.env.SIP_ALLOW_SERVER_CALLBACKS)) {
          if (parsed.id !== undefined &&
              child.stdin && !child.stdin.destroyed) {
            child.stdin.write(JSON.stringify({
              jsonrpc: '2.0', id: parsed.id,
              error: {
                code: -32012,
                message: elicChk.blocked
                  ? elicChk.reason
                  : 'Blocked server callback',
              },
            }) + '\n');
          }
          return;
        }

        if (parsed && typeof parsed === 'object' &&
            parsed.method === 'sampling/createMessage') {
          const sc =
            sanitizeSamplingCreateMessage(parsed);
          if (sc.quarantined) {
            if (parsed.id !== undefined &&
                child.stdin && !child.stdin.destroyed) {
              child.stdin.write(JSON.stringify({
                jsonrpc: '2.0', id: parsed.id,
                error: {
                  code: -32012, message: sc.reason,
                },
              }) + '\n');
            }
            return;
          }
          parsed = sc.message;
        }
        const inspected = await
          session.inspectDownstreamResponse(parsed);
        if (inspected.dropped || !inspected.message) {
          errorOutput.write(
            '[SIP WRAP STDERR] Dropped foreign-id ' +
            'downstream response\n'
          );
          return;
        }
        output.write(
          JSON.stringify(inspected.message) + '\n'
        );
      })
      .catch((err) => {
        errorOutput.write(
          `[SIP WRAP STDERR] Downstream frame error: ${err instanceof Error ? err.message : String(err)}\n`
        );
      });
  });

  hostRl.once('close', () => {
    hostQueue.finally(() => {
      if (child.stdin && !child.stdin.destroyed) {
        child.stdin.end();
      }
    });
  });

  const exitCode = await new Promise((resolve, reject) => {
    child.once('error', (err) => {
      reject(err);
    });
    child.once('close', (code) => {
      resolve(typeof code === 'number' ? code : 0);
    });
  }).finally(async () => {
    orphanReaper.stop();
    process.removeListener('SIGINT', onSigInt);
    process.removeListener('SIGTERM', onSigTerm);
    process.removeListener('SIGHUP', onSigHup);
    await Promise.allSettled([hostQueue, childQueue]);
    hostRl.close();
    childRl.close();
    safeCloseSession();
  });

  return { exitCode };
}

// === BEGIN V310 shouldBypassBinaryPayload ===
export function shouldBypassBinaryPayload(a, b = '') {
  const keyName = a === 'blob' && typeof b === 'string'
    ? a : b;
  const val = a === 'blob' && typeof b === 'string'
    ? b : a;
  if (typeof val !== 'string') {
    return Buffer.isBuffer(val) || ArrayBuffer.isView(val);
  }
  if (/^data:[^;,]{1,80};base64,/i.test(val)) return true;
  const isPureB64 = /^[A-Za-z0-9+/=_-]+$/.test(val);
  if (keyName === 'blob' && val.length >= 4 && isPureB64) {
    return true;
  }
  if (val.length > 262144 && isPureB64) {
    return true;
  }
  return false;
}
// === END V310 shouldBypassBinaryPayload ===
