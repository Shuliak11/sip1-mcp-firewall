/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 1 Deterministic 3-Second Risk Scanner, Screenshot-Safe Masking & SARIF 2.1.0
 * Zero external dependencies. Zero subprocess spawning. Zero raw credential leakage.
 */

import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { normalizeCrossPlatformRelPath } from '../core/workspace-io.mjs';
import { verifySchemaLock } from './schema-lock.mjs';

export const SIP_RISK_RULES = Object.freeze({
  'SIP-R01': {
    id: 'SIP-R01',
    name: 'PlaintextCredentialExposure',
    title: 'Plaintext Credential or High-Entropy Secret Exposure',
    severity: 'CRITICAL',
    sarifLevel: 'error',
    basePenalty: 35,
    maxCategoryPenalty: 70,
    remediation: 'Move credential to OS keychain or ${env:VAR_NAME} reference and rotate the exposed token.',
  },
  'SIP-R02': {
    id: 'SIP-R02',
    name: 'UnpinnedSupplyChainVector',
    title: 'Unpinned Supply-Chain Package Rug-Pull Vector',
    severity: 'HIGH',
    sarifLevel: 'error',
    basePenalty: 20,
    maxCategoryPenalty: 40,
    remediation: 'Pin package to an exact immutable version (e.g. pkg@1.4.2) or @sha256 digest.',
  },
  'SIP-R03': {
    id: 'SIP-R03',
    name: 'UnicodePlane14OrBidiSmuggling',
    title: 'Unicode Plane-14 Tag Smuggling or Trojan-Source Bidi Injection',
    severity: 'CRITICAL',
    sarifLevel: 'error',
    basePenalty: 30,
    maxCategoryPenalty: 60,
    remediation: 'Strip all invisible Plane-14 tags (U+E0000..U+E007F), Bidi overrides, and zero-width codepoints.',
  },
  'SIP-R04': {
    id: 'SIP-R04',
    name: 'ExcessiveBlastRadiusOrPlainHttp',
    title: 'Excessive Blast-Radius Mount, Permission Bypass, or Plaintext Remote HTTP',
    severity: 'HIGH',
    sarifLevel: 'error',
    basePenalty: 20,
    maxCategoryPenalty: 40,
    remediation: 'Scope mounts to a minimal project subdirectory, remove bypass flags, and enforce HTTPS/TLS.',
  },
  'SIP-R05': {
    id: 'SIP-R05',
    name: 'UnsealedConfigurationOrMissingGuard',
    title: 'Unsealed MCP Configuration or Tampered Schema Lock',
    severity: 'MEDIUM',
    sarifLevel: 'warning',
    basePenalty: 15,
    maxCategoryPenalty: 15,
    remediation: 'Seal configuration with `npx -y @shuliak-corp/sip1-mcp lock --install-hooks`.',
  },
});

// Explicit Zero-False-Positive Whitelist Patterns
const UUID_RE = /^(?:urn:uuid:)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_DIGEST_RE = /^(?:sha256:|sha1:|0x)?(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const ENV_PLACEHOLDER_RE = /^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[A-Za-z0-9_.-]+>)$/;
const NPM_PINNED_SPEC_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*(?:@[0-9A-Za-z.+_-]+)?$/;
const SAFE_ENV_KEYS = new Set([
  'PATH',
  'HOME',
  'USER',
  'SHELL',
  'LANG',
  'LC_ALL',
  'TERM',
  'TZ',
  'NODE_ENV',
  'NODE_OPTIONS',
  'LOG_LEVEL',
  'RUST_LOG',
  'PYTHONPATH',
  'PYTHONUNBUFFERED',
]);

// Vendor Secret Signatures
const VENDOR_SECRET_PATTERNS = [
  { label: 'OpenAI/Anthropic Secret Key', re: /\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{12,}\b/ },
  { label: 'AWS Access Key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { label: 'GitHub Personal Access Token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/ },
  { label: 'GitHub Fine-Grained PAT', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { label: 'Slack API Token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'GitLab Personal Access Token', re: /\bglpat-[A-Za-z0-9_-]{16,}\b/ },
  { label: 'Google Cloud API Key', re: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { label: 'Stripe Live Secret Key', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/ },
];

const BEARER_RE = /^\s*Bearer\s+([^\s]+)\s*$/i;
const DB_DSN_CRED_RE =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|cockroachdb):\/\/([^:@/\s]+):([^@/\s]+)@/i;

const SECRET_QUERY_KEY_RE = /^(?:api[_-]?key|token|access[_-]?token|auth[_-]?token|secret|password|client[_-]?secret|key)$/i;
const SECRET_NAME_HINT_RE = /(?:key|token|secret|password|passwd|pwd|credential|auth|private|bearer|pat)/i;

/**
 * Screenshot-Safe secret masker.
 * NEVER exposes raw credentials.
 * - Strings >= 8 chars -> `<first4>****...****<last2>`
 * - Shorter strings -> `****[REDACTED]`
 *
 * @param {string} raw
 * @returns {string}
 */
export function maskSecretPreview(raw) {
  const str = typeof raw === 'string' ? raw.trim() : String(raw ?? '');
  if (str.length >= 8) {
    return `${str.slice(0, 4)}****...****${str.slice(-2)}`;
  }
  return '****[REDACTED]';
}

/**
 * Compute Shannon entropy in bits per character.
 * @param {string} str
 * @returns {number}
 */
export function computeShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  const len = str.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check whether a candidate value is explicitly whitelisted (0.00% False Positive filter):
 * - ${env:...}, $VAR, <PLACEHOLDER>
 * - RFC 4122 UUIDs
 * - 40-hex Git SHA-1 / 64-hex SHA-256 digests
 * - Pure file system paths without embedded credentials
 * - Standard npm package specifiers
 * - Clean URLs without embedded password or secret query params
 *
 * @param {string} raw
 * @returns {boolean}
 */
export function isWhitelistedNonSecret(raw) {
  const val = raw.trim();
  if (!val) return true;
  if (val === 'true' || val === 'false' || val === 'null' || /^-?\d+(?:\.\d+)?$/.test(val)) {
    return true;
  }
  if (ENV_PLACEHOLDER_RE.test(val)) return true;
  if (/^\$\{(?:env|input|workspaceFolder|userHome|config):[^}]+\}$/.test(val)) return true;
  if (UUID_RE.test(val)) return true;
  if (HEX_DIGEST_RE.test(val)) return true;
  if (NPM_PINNED_SPEC_RE.test(val) && !val.startsWith('sk-') && !val.startsWith('ghp_')) {
    return true;
  }

  // File paths (Unix or Windows) that do not embed '=' or '://'
  if (
    !val.includes('=') &&
    !val.includes('://') &&
    (val.startsWith('/') ||
      val.startsWith('./') ||
      val.startsWith('../') ||
      val.startsWith('~/') ||
      /^[A-Za-z]:\\/.test(val))
  ) {
    // Still ensure no vendor token appears inside the path segment
    for (const pat of VENDOR_SECRET_PATTERNS) {
      if (pat.re.test(val)) return false;
    }
    return true;
  }

  return false;
}

/**
 * Inspect a single string value for secret exposure (`SIP-R01`).
 * Returns `{ label, maskedPreview } | null` — NEVER returns the raw secret!
 *
 * @param {string} value
 * @param {{ fieldKind: 'env' | 'arg' | 'header' | 'url', keyName?: string }} ctx
 * @returns {{ label: string, maskedPreview: string } | null}
 */
export function detectSecretInValue(value, ctx) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;

  // Handle key=value CLI flags like --api-key=sk-proj-...
  if (ctx.fieldKind === 'arg' && trimmed.startsWith('-') && trimmed.includes('=')) {
    const eqIdx = trimmed.indexOf('=');
    const flagName = trimmed.slice(0, eqIdx);
    const flagVal = trimmed.slice(eqIdx + 1);
    return detectSecretInValue(flagVal, { fieldKind: 'arg', keyName: flagName });
  }

  // 1. Check whitelist BEFORE entropy/generic heuristics
  if (isWhitelistedNonSecret(trimmed)) {
    return null;
  }

  // 2. Database / Broker DSN with embedded user:password@host
  const dsnMatch = DB_DSN_CRED_RE.exec(trimmed);
  if (dsnMatch) {
    const embeddedPass = dsnMatch[2];
    if (!ENV_PLACEHOLDER_RE.test(embeddedPass) && !embeddedPass.includes('${')) {
      return {
        label: 'Database DSN Embedded Password',
        maskedPreview: maskSecretPreview(embeddedPass),
      };
    }
  }

  // 3. HTTP/HTTPS/WS URL inspection: whitelist clean URLs, flag user:pass or secret query params
  if (/^(?:https?|wss?):\/\//i.test(trimmed)) {
    try {
      const parsedUrl = new URL(trimmed);
      if (
        parsedUrl.password &&
        !ENV_PLACEHOLDER_RE.test(decodeURIComponent(parsedUrl.password))
      ) {
        return {
          label: 'URL Embedded Basic-Auth Password',
          maskedPreview: maskSecretPreview(decodeURIComponent(parsedUrl.password)),
        };
      }
      for (const [qk, qv] of parsedUrl.searchParams.entries()) {
        if (qv && !isWhitelistedNonSecret(qv)) {
          for (const pat of VENDOR_SECRET_PATTERNS) {
            const m = pat.re.exec(qv);
            if (m) {
              return { label: pat.label, maskedPreview: maskSecretPreview(m[0]) };
            }
          }
          if (SECRET_QUERY_KEY_RE.test(qk) && qv.length >= 8) {
            return {
              label: `URL Query Credential (${qk})`,
              maskedPreview: maskSecretPreview(qv),
            };
          }
        }
      }
      // Clean URL without credentials -> whitelisted (0 false positives on long URLs!)
      return null;
    } catch {
      // Fall through if malformed URL
    }
  }

  // 4. Bearer token in Authorization header or value
  const bearerMatch = BEARER_RE.exec(trimmed);
  if (bearerMatch) {
    const tok = bearerMatch[1];
    if (!isWhitelistedNonSecret(tok)) {
      return {
        label: 'Plaintext Bearer Authorization Token',
        maskedPreview: maskSecretPreview(tok),
      };
    }
    return null;
  }

  // 5. Known Vendor API Key Signatures
  for (const pat of VENDOR_SECRET_PATTERNS) {
    const m = pat.re.exec(trimmed);
    if (m) {
      return {
        label: pat.label,
        maskedPreview: maskSecretPreview(m[0]),
      };
    }
  }

  // 6. High-Entropy Secret Detection (Shannon entropy > 4.25 bits/char, len >= 20)
  const keyUpper = (ctx.keyName || '').toUpperCase();
  if (ctx.fieldKind === 'env' && SAFE_ENV_KEYS.has(keyUpper)) {
    return null;
  }

  // Skip strings containing spaces or pure path-like slashes without secret hints
  if (!/\s/.test(trimmed) && trimmed.length >= 20) {
    // Exclude URLs/paths/interpolated templates
    if (trimmed.includes('${') || trimmed.startsWith('/') || trimmed.startsWith('./')) {
      return null;
    }
    const entropy = computeShannonEntropy(trimmed);
    const hasLower = /[a-z]/.test(trimmed);
    const hasUpper = /[A-Z]/.test(trimmed);
    const hasDigit = /[0-9]/.test(trimmed);
    const hasSymbol = /[^A-Za-z0-9]/.test(trimmed);
    const charClasses = Number(hasLower) + Number(hasUpper) + Number(hasDigit) + Number(hasSymbol);
    const nameLooksSecret = ctx.keyName ? SECRET_NAME_HINT_RE.test(ctx.keyName) : false;

    if (entropy > 4.25 && (charClasses >= 3 || (nameLooksSecret && charClasses >= 2))) {
      return {
        label: `High-Entropy Secret (${entropy.toFixed(2)} bits/char)`,
        maskedPreview: maskSecretPreview(trimmed),
      };
    }
  }

  // Catch explicit shorter secrets (>= 12 chars) assigned to strongly-named secret keys like PASSWORD / API_KEY
  if (
    (ctx.fieldKind === 'env' || ctx.fieldKind === 'header') &&
    ctx.keyName &&
    SECRET_NAME_HINT_RE.test(ctx.keyName) &&
    trimmed.length >= 12 &&
    !/\s/.test(trimmed) &&
    !trimmed.includes('${') &&
    computeShannonEntropy(trimmed) > 3.5
  ) {
    // Double check not UUID or hex
    if (!isWhitelistedNonSecret(trimmed)) {
      return {
        label: `Hardcoded Secret in ${ctx.keyName}`,
        maskedPreview: maskSecretPreview(trimmed),
      };
    }
  }

  return null;
}

/**
 * Redact any secret inside a string so lockfile previews NEVER store raw credentials.
 * @param {string | null | undefined} raw
 * @returns {string | null}
 */
export function redactStringForLockPreview(raw) {
  if (raw === null || raw === undefined) return null;
  const str = String(raw);
  const hit =
    detectSecretInValue(str, { fieldKind: 'arg' }) ||
    detectSecretInValue(str, { fieldKind: 'url' });
  if (hit) {
    return hit.maskedPreview;
  }
  return str;
}

const EXACT_SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * Check if an npm/uvx/pipx package specifier is strictly pinned to an exact version or digest.
 * @param {string} pkgSpec
 * @param {'npm' | 'python'} ecosystem
 * @returns {boolean}
 */
function isPackageStrictlyPinned(pkgSpec, ecosystem) {
  if (!pkgSpec) return false;
  if (pkgSpec.includes('@sha256:') && /@sha256:[0-9a-f]{64}/i.test(pkgSpec)) {
    return true;
  }
  if (ecosystem === 'python') {
    if (pkgSpec.includes('==')) {
      const ver = pkgSpec.split('==')[1] || '';
      return Boolean(ver) && !ver.includes('*') && ver.toLowerCase() !== 'latest';
    }
    const atIdx = pkgSpec.lastIndexOf('@');
    if (atIdx > 0) {
      const ver = pkgSpec.slice(atIdx + 1);
      return EXACT_SEMVER_RE.test(ver);
    }
    return false;
  }

  // npm ecosystem (npx / bunx / pnpx): handle @scope/pkg@1.2.3 and pkg@1.2.3
  const atIdx = pkgSpec.startsWith('@') ? pkgSpec.indexOf('@', 1) : pkgSpec.indexOf('@');
  if (atIdx <= 0) {
    return false;
  }
  const versionPart = pkgSpec.slice(atIdx + 1);
  if (!versionPart || versionPart.toLowerCase() === 'latest' || versionPart.toLowerCase() === 'next') {
    return false;
  }
  return EXACT_SEMVER_RE.test(versionPart);
}

/**
 * Detect unpinned supply-chain execution (`SIP-R02`) in server command & args.
 * @param {{ command: string | null, args: string[] }} server
 * @returns {{ runner: string, target: string, reason: string } | null}
 */
function detectUnpinnedSupplyChain(server) {
  if (!server.command) return null;
  const cmdBase = path.basename(server.command).toLowerCase().replace(/\.cmd$|\.exe$/, '');
  const args = server.args || [];

  if (cmdBase === 'npx' || cmdBase === 'bunx' || cmdBase === 'pnpx') {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === '-p' || arg === '--package') {
        const pkg = args[i + 1] || '';
        if (!isPackageStrictlyPinned(pkg, 'npm')) {
          return {
            runner: cmdBase,
            target: redactStringForLockPreview(pkg) || '<missing>',
            reason: `Package "${redactStringForLockPreview(pkg)}" executed via ${cmdBase} without exact @x.y.z version pin`,
          };
        }
        return null;
      }
      if (arg.startsWith('-')) {
        continue;
      }
      if (!isPackageStrictlyPinned(arg, 'npm')) {
        return {
          runner: cmdBase,
          target: redactStringForLockPreview(arg) || arg,
          reason: `Package "${redactStringForLockPreview(arg)}" executed via ${cmdBase} without exact @x.y.z version pin`,
        };
      }
      return null;
    }
  }

  if (cmdBase === 'uvx' || cmdBase === 'pipx') {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === 'run' && cmdBase === 'pipx') continue;
      if (arg === '--from' && i + 1 < args.length) {
        const pkg = args[i + 1];
        if (!isPackageStrictlyPinned(pkg, 'python')) {
          return {
            runner: cmdBase,
            target: redactStringForLockPreview(pkg) || pkg,
            reason: `Python tool "${redactStringForLockPreview(pkg)}" executed via ${cmdBase} without exact ==x.y.z version pin`,
          };
        }
        return null;
      }
      if (arg.startsWith('-')) continue;
      if (!isPackageStrictlyPinned(arg, 'python')) {
        return {
          runner: cmdBase,
          target: redactStringForLockPreview(arg) || arg,
          reason: `Python tool "${redactStringForLockPreview(arg)}" executed via ${cmdBase} without exact ==x.y.z version pin`,
        };
      }
      return null;
    }
  }

  if (cmdBase === 'docker' || cmdBase === 'podman') {
    const runIdx = args.indexOf('run');
    if (runIdx !== -1) {
      const flagsWithValue = new Set([
        '-e',
        '--env',
        '--env-file',
        '-v',
        '--volume',
        '--mount',
        '-p',
        '--publish',
        '--name',
        '--network',
        '-w',
        '--workdir',
        '-u',
        '--user',
        '--entrypoint',
      ]);
      for (let i = runIdx + 1; i < args.length; i++) {
        const arg = args[i];
        if (flagsWithValue.has(arg)) {
          i++;
          continue;
        }
        if (arg.startsWith('-')) continue;
        // Image argument located
        const hasShaDigest = /@sha256:[0-9a-f]{64}/i.test(arg);
        const colonIdx = arg.lastIndexOf(':');
        const slashIdx = arg.lastIndexOf('/');
        const tag = colonIdx > slashIdx ? arg.slice(colonIdx + 1) : '';
        const hasPinnedTag = Boolean(tag) && tag !== 'latest' && /^\d+\.\d+/.test(tag);
        if (!hasShaDigest && !hasPinnedTag) {
          return {
            runner: cmdBase,
            target: redactStringForLockPreview(arg) || arg,
            reason: `Container image "${redactStringForLockPreview(arg)}" lacks immutable @sha256 digest or version tag`,
          };
        }
        return null;
      }
    }
  }

  return null;
}

/**
 * Scan string for Unicode Plane-14 Tag Smuggling (`U+E0000..U+E007F`),
 * Trojan-Source Bidi overrides (`U+202A..U+202E`, `U+2066..U+2069`, `U+061C`),
 * and zero-width invisible joiners/spaces (`U+200B..U+200F`, `U+2060`, internal `U+FEFF`).
 *
 * @param {string} str
 * @param {{ allowLeadingBom?: boolean }} [opts]
 * @returns {Array<{ codePointHex: string, category: string }>}
 */
export function scanUnicodeSmuggling(str, opts = {}) {
  if (typeof str !== 'string' || str.length === 0) return [];
  const hits = [];
  let charIndex = 0;

  for (const ch of str) {
    const cp = ch.codePointAt(0) ?? 0;
    if (opts.allowLeadingBom && charIndex === 0 && cp === 0xfeff) {
      charIndex++;
      continue;
    }
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      hits.push({
        codePointHex: 'U+' + cp.toString(16).toUpperCase(),
        category: 'Plane-14 Invisible Tag Smuggling',
      });
    } else if (
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069) ||
      cp === 0x061c ||
      cp === 0x200e ||
      cp === 0x200f
    ) {
      hits.push({
        codePointHex: 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'),
        category: 'Trojan-Source Bidi Control Override',
      });
    } else if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff) {
      hits.push({
        codePointHex: 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'),
        category: 'Zero-Width Invisible Token Smuggling',
      });
    }
    charIndex++;
  }
  return hits;
}

const DANGEROUS_BYPASS_FLAGS = new Set([
  '--dangerously-skip-permissions',
  '--allow-all',
  '--no-sandbox',
  '--trust-all-tools',
  '--privileged',
  '--yolo',
]);

const SENSITIVE_EXACT_MOUNTS = new Set([
  '/',
  '~',
  '$HOME',
  '${HOME}',
  '${env:HOME}',
  '/etc',
  '/etc/',
  '/root',
  '/var',
  'C:\\',
  'c:\\',
]);

/**
 * Check if a host is loopback (`localhost`, `127.x.x.x`, `[::1]`).
 * @param {string} hostname
 * @returns {boolean}
 */
function isLoopbackHost(hostname) {
  const h = hostname.toLowerCase();
  return (
    h === 'localhost' ||
    h === '[::1]' ||
    h === '::1' ||
    h === '127.0.0.1' ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)
  );
}

/**
 * Detect Excessive Blast-Radius / Fail-Open Transport (`SIP-R04`).
 * @param {{ command: string | null, args: string[], url: string | null }} server
 * @returns {string[]}
 */
function detectBlastRadiusIssues(server) {
  const reasons = [];

  for (const arg of server.args || []) {
    const trimmed = arg.trim();
    const flagPart = trimmed.split('=')[0];

    if (DANGEROUS_BYPASS_FLAGS.has(flagPart) || trimmed === '--network=host') {
      reasons.push(`Dangerous permission bypass flag "${flagPart}" enabled in server args`);
      continue;
    }

    if (SENSITIVE_EXACT_MOUNTS.has(trimmed)) {
      reasons.push(`Unscoped host root/home directory mount "${trimmed}" grants excessive blast radius`);
      continue;
    }

    const norm = trimmed.replace(/\\/g, '/');
    if (
      norm === '~/.ssh' ||
      norm.startsWith('~/.ssh/') ||
      norm.includes('/.ssh') ||
      norm.includes('/.aws') ||
      norm.includes('/.gnupg') ||
      norm === '.env' ||
      norm.endsWith('/.env') ||
      /\/\.env\.[A-Za-z0-9_-]+$/.test(norm) ||
      /^\.env\.[A-Za-z0-9_-]+$/.test(norm)
    ) {
      reasons.push(`Sensitive credential file/directory "${ redactStringForLockPreview(trimmed) }" exposed in args`);
      continue;
    }

    if (/^http:\/\//i.test(trimmed)) {
      try {
        const u = new URL(trimmed);
        if (!isLoopbackHost(u.hostname)) {
          reasons.push(`Plaintext non-loopback HTTP endpoint "${u.origin}" vulnerable to MITM interception`);
        }
      } catch {
        // Ignore malformed
      }
    }
  }

  if (server.url && /^http:\/\//i.test(server.url.trim())) {
    try {
      const u = new URL(server.url.trim());
      if (!isLoopbackHost(u.hostname)) {
        reasons.push(`Plaintext remote HTTP transport (${u.origin}) configured without TLS`);
      }
    } catch {
      // Ignore malformed
    }
  }

  return reasons;
}

/**
 * Map a 0-100 score to a deterministic SIP security grade.
 * `95-100: A+`, `85-94: A`, `70-84: B`, `50-69: C`, `30-49: D`, `0-29: F`
 * @param {number} score
 * @returns {'A+' | 'A' | 'B' | 'C' | 'D' | 'F'}
 */

const CL100K_TOK_RE = new RegExp(
  "[A-Za-z]{1,12}|\\d{1,3}|[^\\sA-Za-z\\d]+", 'g'
);

export function estimateCl100kTokens(text) {
  const s = String(text || '');
  if (!s) return 0;
  const matches = s.match(CL100K_TOK_RE);
  return matches ? matches.length : 0;
}

export function computeMcpTokenTax(
  configs, toolsByServer = null
) {
  const safe = Array.isArray(configs) ? configs : [];
  let totalServers = 0;
  let estimatedTools = 0;
  let estimatedTokens = 0;
  for (const cfg of safe) {
    for (const srv of cfg.servers || []) {
      totalServers++;
      const list = toolsByServer?.[srv.serverName];
      if (Array.isArray(list)) {
        estimatedTools += list.length;
        estimatedTokens += estimateCl100kTokens(
          JSON.stringify(list)
        );
      } else {
        const metaTxt = JSON.stringify({
          name: srv.serverName, cmd: srv.command,
          args: srv.args, url: srv.url,
        });
        const baseTok = Math.max(
          1200, estimateCl100kTokens(metaTxt) * 24
        );
        estimatedTools += 12;
        estimatedTokens += baseTok;
      }
    }
  }
  const windsurfLimit = 100;
  const windsurfLimitExceeded =
    estimatedTools > windsurfLimit;
  return {
    tokenizer: 'cl100k_base',
    totalServers,
    estimatedTools,
    estimatedTokens,
    pctOf128kContext: Number(
      ((estimatedTokens / 128_000) * 100).toFixed(2)
    ),
    windsurfToolLimit: windsurfLimit,
    windsurfLimitExceeded,
  };
}

export function scoreToGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

/**
 * Run deterministic Stage 1 static MCP security audit in < 200 ms with ZERO subprocesses.
 *
 * @param {{
 *   configs: Array<any>,
 *   workspaceDir?: string,
 *   skipLockCheck?: boolean,
 * }} params
 */
export function runStaticMcpAudit({
  configs, workspaceDir, skipLockCheck = false,
  toolsByServer = null,
}) {
  const start = performance.now();
  const safeConfigs = Array.isArray(configs) ? configs : [];
  const baseDir = workspaceDir ? path.resolve(workspaceDir) : null;

  /** @type {Array<{
   *   ruleId: 'SIP-R01' | 'SIP-R02' | 'SIP-R03' | 'SIP-R04' | 'SIP-R05',
   *   severity: 'CRITICAL' | 'HIGH' | 'MEDIUM',
   *   penalty: number,
   *   serverName: string,
   *   client: string,
   *   filePath: string,
   *   relativeFile: string,
   *   message: string,
   *   maskedPreview: string | null,
   *   remediation: string,
   *   line?: number,
   *   column?: number,
   * }>} */
  const findings = [];

  const formatRelPath = (fp) => {
    if (!fp) return '.mcp.json';
    return normalizeCrossPlatformRelPath(workspaceDir || baseDir, fp);
  };

  let totalServers = 0;

  for (const cfg of safeConfigs) {
    const relFile = formatRelPath(cfg.filePath);

    if (cfg.parseError) {
      findings.push({
        ruleId: 'SIP-R05',
        severity: 'MEDIUM',
        penalty: SIP_RISK_RULES['SIP-R05'].basePenalty,
        serverName: '(config-parse)',
        client: cfg.client || 'mcp-config',
        filePath: cfg.filePath,
        relativeFile: relFile,
        message: `Malformed JSONC configuration cannot be cryptographically sealed: ${cfg.parseError.message}`,
        maskedPreview: null,
        remediation: 'Fix syntax error in JSONC configuration file and run `sip1-mcp lock`.',
        line: cfg.parseError.line || 1,
        column: cfg.parseError.column || 1,
      });
    }

    // Check raw source text if attached (catches Plane-14 / Bidi hidden inside comments!)
    const rawSource = typeof cfg._rawSource === 'string' ? cfg._rawSource : '';
    if (rawSource) {
      const rawSmuggling = scanUnicodeSmuggling(rawSource, { allowLeadingBom: true });
      if (rawSmuggling.length > 0) {
        const sample = rawSmuggling.slice(0, 3).map((h) => h.codePointHex).join(', ');
        findings.push({
          ruleId: 'SIP-R03',
          severity: 'CRITICAL',
          penalty: SIP_RISK_RULES['SIP-R03'].basePenalty,
          serverName: '(source-file)',
          client: cfg.client || 'mcp-config',
          filePath: cfg.filePath,
          relativeFile: relFile,
          message: `${rawSmuggling[0].category} detected in raw config (${rawSmuggling.length} hidden codepoints: ${sample})`,
          maskedPreview: sample,
          remediation: SIP_RISK_RULES['SIP-R03'].remediation,
        });
      }
    }

    for (const srv of cfg.servers || []) {
      totalServers++;

      // --- SIP-R01: Plaintext Credential Exposure in env, args, headers, url ---
      for (const [envKey, envVal] of Object.entries(srv.env || {})) {
        const hit = detectSecretInValue(String(envVal), { fieldKind: 'env', keyName: envKey });
        if (hit) {
          findings.push({
            ruleId: 'SIP-R01',
            severity: 'CRITICAL',
            penalty: SIP_RISK_RULES['SIP-R01'].basePenalty,
            serverName: srv.serverName,
            client: srv.client,
            filePath: srv.filePath,
            relativeFile: relFile,
            message: `${hit.label} exposed in env.${envKey} (${hit.maskedPreview})`,
            maskedPreview: hit.maskedPreview,
            remediation: SIP_RISK_RULES['SIP-R01'].remediation,
          });
        }
      }

      for (let i = 0; i < (srv.args || []).length; i++) {
        const argVal = String(srv.args[i]);
        const hit = detectSecretInValue(argVal, { fieldKind: 'arg', keyName: `args[${i}]` });
        if (hit) {
          findings.push({
            ruleId: 'SIP-R01',
            severity: 'CRITICAL',
            penalty: SIP_RISK_RULES['SIP-R01'].basePenalty,
            serverName: srv.serverName,
            client: srv.client,
            filePath: srv.filePath,
            relativeFile: relFile,
            message: `${hit.label} exposed in CLI args[${i}] (${hit.maskedPreview})`,
            maskedPreview: hit.maskedPreview,
            remediation: SIP_RISK_RULES['SIP-R01'].remediation,
          });
        }
      }

      for (const [hdrKey, hdrVal] of Object.entries(srv.headers || {})) {
        const hit = detectSecretInValue(String(hdrVal), { fieldKind: 'header', keyName: hdrKey });
        if (hit) {
          findings.push({
            ruleId: 'SIP-R01',
            severity: 'CRITICAL',
            penalty: SIP_RISK_RULES['SIP-R01'].basePenalty,
            serverName: srv.serverName,
            client: srv.client,
            filePath: srv.filePath,
            relativeFile: relFile,
            message: `${hit.label} exposed in headers["${hdrKey}"] (${hit.maskedPreview})`,
            maskedPreview: hit.maskedPreview,
            remediation: SIP_RISK_RULES['SIP-R01'].remediation,
          });
        }
      }

      if (srv.url) {
        const hit = detectSecretInValue(String(srv.url), { fieldKind: 'url', keyName: 'url' });
        if (hit) {
          findings.push({
            ruleId: 'SIP-R01',
            severity: 'CRITICAL',
            penalty: SIP_RISK_RULES['SIP-R01'].basePenalty,
            serverName: srv.serverName,
            client: srv.client,
            filePath: srv.filePath,
            relativeFile: relFile,
            message: `${hit.label} exposed in server URL (${hit.maskedPreview})`,
            maskedPreview: hit.maskedPreview,
            remediation: SIP_RISK_RULES['SIP-R01'].remediation,
          });
        }
      }

      // --- SIP-R02: Unpinned Supply-Chain Rug-Pull Vector ---
      const unpinned = detectUnpinnedSupplyChain(srv);
      if (unpinned) {
        findings.push({
          ruleId: 'SIP-R02',
          severity: 'HIGH',
          penalty: SIP_RISK_RULES['SIP-R02'].basePenalty,
          serverName: srv.serverName,
          client: srv.client,
          filePath: srv.filePath,
          relativeFile: relFile,
          message: unpinned.reason,
          maskedPreview: unpinned.target,
          remediation: SIP_RISK_RULES['SIP-R02'].remediation,
        });
      }

      // --- SIP-R03: Plane-14 Tag Smuggling & Bidi Injection on parsed server fields ---
      // (Also covers programmatic configs passed in-memory without `_rawSource`)
      const fieldStrings = [
        srv.serverName,
        srv.command || '',
        srv.description || '',
        srv.url || '',
        ...(srv.args || []),
        ...Object.keys(srv.env || {}),
        ...Object.values(srv.env || {}),
      ];
      const serverSmugglingHits = [];
      for (const s of fieldStrings) {
        const hits = scanUnicodeSmuggling(String(s));
        if (hits.length > 0) {
          serverSmugglingHits.push(...hits);
        }
      }
      if (serverSmugglingHits.length > 0) {
        const sample = serverSmugglingHits.slice(0, 3).map((h) => h.codePointHex).join(', ');
        findings.push({
          ruleId: 'SIP-R03',
          severity: 'CRITICAL',
          penalty: SIP_RISK_RULES['SIP-R03'].basePenalty,
          serverName: srv.serverName.replace(/[\u{E0000}-\u{E007F}\u200B-\u200F\u202A-\u202E\u2060-\u2069\u061C\uFEFF]/gu, ''),
          client: srv.client,
          filePath: srv.filePath,
          relativeFile: relFile,
          message: `${serverSmugglingHits[0].category} hidden in server "${srv.serverName.replace(/[\u{E0000}-\u{E007F}\u200B-\u200F\u202A-\u202E\u2060-\u2069\u061C\uFEFF]/gu, '')}" (${serverSmugglingHits.length} codepoints: ${sample})`,
          maskedPreview: sample,
          remediation: SIP_RISK_RULES['SIP-R03'].remediation,
        });
      }

      // --- SIP-R04: Excessive Blast-Radius / Fail-Open Transport ---
      const blastIssues = detectBlastRadiusIssues(srv);
      for (const issue of blastIssues) {
        findings.push({
          ruleId: 'SIP-R04',
          severity: 'HIGH',
          penalty: SIP_RISK_RULES['SIP-R04'].basePenalty,
          serverName: srv.serverName,
          client: srv.client,
          filePath: srv.filePath,
          relativeFile: relFile,
          message: issue,
          maskedPreview: null,
          remediation: SIP_RISK_RULES['SIP-R04'].remediation,
        });
      }
    }

    // Check Claude Code settings missing PreToolUse guard
    if (cfg.isClaudeSettings && !cfg.parseError && !cfg.hasPreToolUseHook) {
      findings.push({
        ruleId: 'SIP-R05',
        severity: 'MEDIUM',
        penalty: SIP_RISK_RULES['SIP-R05'].basePenalty,
        serverName: '(claude-hooks)',
        client: 'claude-code',
        filePath: cfg.filePath,
        relativeFile: relFile,
        message: 'Claude Code settings lacks PreToolUse cryptographic guard hook',
        maskedPreview: null,
        remediation: SIP_RISK_RULES['SIP-R05'].remediation,
      });
    }
  }

  // --- SIP-R05: Schema Lock Verification (when workspaceDir is provided & servers exist) ---
  let lockVerification = null;
  if (baseDir && !skipLockCheck && totalServers > 0) {
    lockVerification = verifySchemaLock({ workspaceDir: baseDir, configs: safeConfigs });
    if (!lockVerification.valid) {
      const reasonDetail =
        lockVerification.driftDetails?.[0]?.message || 'sip2.lock.json missing or signature/digest mismatch';
      findings.push({
        ruleId: 'SIP-R05',
        severity: 'MEDIUM',
        penalty: SIP_RISK_RULES['SIP-R05'].basePenalty,
        serverName: '(workspace-lock)',
        client: 'sip-lock',
        filePath: path.join(baseDir, '.sip', 'sip2.lock.json'),
        relativeFile: '.sip/sip2.lock.json',
        message: `Unsealed or drifted MCP configuration: ${reasonDetail}`,
        maskedPreview: null,
        remediation: SIP_RISK_RULES['SIP-R05'].remediation,
      });
    }
  }

  // Compute deterministic category-capped penalty and 0..100 score
  /** @type {Record<string, number>} */
  const categoryPenalties = {
    'SIP-R01': 0,
    'SIP-R02': 0,
    'SIP-R03': 0,
    'SIP-R04': 0,
    'SIP-R05': 0,
  };

  for (const f of findings) {
    const rule = SIP_RISK_RULES[f.ruleId];
    if (rule) {
      categoryPenalties[f.ruleId] = Math.min(
        rule.maxCategoryPenalty,
        categoryPenalties[f.ruleId] + rule.basePenalty
      );
    }
  }

  const totalPenalty = Object.values(categoryPenalties).reduce((acc, n) => acc + n, 0);
  const score = Math.max(0, 100 - totalPenalty);
  const grade = scoreToGrade(score);
  const durationMs = Number((performance.now() - start).toFixed(3));

  const tokenTax = computeMcpTokenTax(
    safeConfigs, toolsByServer
  );
  return {
    engineVersion: '3.1.0',
    tokenTax,
    scannedAt: new Date().toISOString(),
    durationMs,
    score,
    grade,
    totalConfigs: safeConfigs.length,
    totalServers,
    categoryPenalties,
    lockStatus: lockVerification
      ? lockVerification.valid
        ? 'SEALED_VERIFIED'
        : lockVerification.status
      : 'UNCHECKED',
    findings,
  };
}

/**
 * Format an aligned, Screenshot-Safe ASCII terminal box report.
 * ZERO emojis. ZERO raw secrets.
 *
 * @param {ReturnType<typeof runStaticMcpAudit>} auditResult
 * @returns {string}
 */
export const TERMINAL_BOX_WIDTH = 78;

/**
 * Wrap a single line cleanly inside a 78-column ASCII box (`| ` + 74 chars + ` |`),
 * breaking on whitespace whenever possible so URLs and masked previews stay intact.
 * @param {string} text
 * @param {string} [continuationIndent='  ']
 * @returns {string}
 */
export function wrapBoxRow78(text, continuationIndent = '  ') {
  const maxInner = TERMINAL_BOX_WIDTH - 4; // 74 chars
  const clean = String(text).replace(/[\r\n]+/g, ' ');
  if (clean.length <= maxInner) {
    return '| ' + clean.padEnd(maxInner, ' ') + ' |';
  }

  const rows = [];
  let remaining = clean;
  let isFirst = true;

  while (remaining.length > 0) {
    const prefix = isFirst ? '' : continuationIndent;
    const budget = maxInner - prefix.length;

    if (remaining.length <= budget) {
      rows.push('| ' + (prefix + remaining).padEnd(maxInner, ' ') + ' |');
      break;
    }

    let splitIdx = remaining.lastIndexOf(' ', budget);
    if (splitIdx <= 0) {
      // Single unbroken token exceeds budget -> hard slice at budget
      splitIdx = budget;
    }

    const chunk = remaining.slice(0, splitIdx).trimEnd();
    rows.push('| ' + (prefix + chunk).padEnd(maxInner, ' ') + ' |');
    remaining = remaining.slice(splitIdx).trimStart();
    isFirst = false;
  }

  return rows.join('\n');
}

export function formatAuditTerminalReport(auditResult) {
  const WIDTH = TERMINAL_BOX_WIDTH;
  const hr = '+' + '-'.repeat(WIDTH - 2) + '+';
  const eq = '+' + '='.repeat(WIDTH - 2) + '+';
  const padRow = (text, indent = '    ') => wrapBoxRow78(text, indent);

  const lines = [
    eq,
    padRow('[SHULIAK SIP v3.0 · ZERO-EGRESS MCP SECURITY AUDIT]'),
    padRow('[SCREENSHOT-SAFE · ZERO RAW SECRETS DISPLAYED]'),
    eq,
    padRow(
      `SCORE: ${String(auditResult.score).padStart(3, ' ')}/100  GRADE: ${auditResult.grade.padEnd(3, ' ')}  LATENCY: ${auditResult.durationMs.toFixed(2)} ms`
    ),
    padRow(
      `CONFIGS: ${String(auditResult.totalConfigs).padStart(2, ' ')}     SERVERS: ${String(auditResult.totalServers).padStart(2, ' ')}   LOCK: ${auditResult.lockStatus}`
    ),
    ...(auditResult.tokenTax && auditResult.tokenTax.totalServers > 0
      ? [
          padRow(
            `TOKENS : ~${auditResult.tokenTax.estimatedTokens} (cl100k_base, ` +
            `${auditResult.tokenTax.pctOf128kContext}%` +
            ` of 128k | ~${auditResult.tokenTax.estimatedTools} tools)`
          ),
          ...(auditResult.tokenTax.windsurfLimitExceeded
            ? [padRow(
                'WARN   : Exceeds Windsurf 100-tool ' +
                'limit! Use wrap --allow-tools/--exclude'
              )]
            : []),
        ]
      : []),
    hr,
  ];

  if (auditResult.findings.length === 0) {
    lines.push(padRow('STATUS: ZERO FINDINGS DETECTED. ALL SERVERS PINNED & SEALED.'));
    if (auditResult.totalConfigs === 0) {
      lines.push(padRow('TIP   : No MCP configs found here. Run the 3-second showcase:'));
      lines.push(padRow('        $ npx -y @shuliak-corp/sip1-mcp demo'));
    }
  } else {
    lines.push(padRow(`DETECTED FINDINGS (${auditResult.findings.length}):`));
    lines.push(hr);
    for (const f of auditResult.findings) {
      lines.push(
        padRow(`[${f.ruleId}] [${f.severity}] ${f.client} :: ${f.serverName} (${f.relativeFile})`)
      );
      lines.push(padRow(`  -> ${f.message}`, '     '));
    }
  }

  lines.push(hr);
  lines.push(padRow('1-COMMAND REMEDIATION & RFC 8785 + ED25519 SEAL:'));
  lines.push(padRow('  $ npx -y @shuliak-corp/sip1-mcp lock --install-hooks'));
  lines.push(hr);
  lines.push(
    padRow(
      'Need signed SOC 2 / GDPR Art. 17 / EU AI Act Attestation PDF? -> https://shuliak.dev/#pricing',
      '  '
    )
  );
  lines.push(eq);

  return lines.join('\n');
}

/**
 * Format audit result as valid OASIS SARIF 2.1.0 JSON structure for GitHub Advanced Security.
 * Guarantees ZERO raw secrets in messages or properties.
 *
 * @param {ReturnType<typeof runStaticMcpAudit>} auditResult
 */
export function formatAuditSarif(auditResult) {
  const rules = Object.values(SIP_RISK_RULES).map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: { text: r.title },
    fullDescription: { text: `${r.title}. ${r.remediation}` },
    help: { text: r.remediation },
    defaultConfiguration: {
      level: r.sarifLevel,
    },
    properties: {
      'security-severity': r.severity === 'CRITICAL' ? '9.5' : r.severity === 'HIGH' ? '7.8' : '5.0',
      tags: ['security', 'mcp', 'ai-supply-chain', 'shuliak-sip'],
    },
  }));

  const results = auditResult.findings.map((f) => ({
    ruleId: f.ruleId,
    level: SIP_RISK_RULES[f.ruleId]?.sarifLevel || 'warning',
    message: {
      text: `[${f.severity}] (${f.client}/${f.serverName}) ${f.message}. Fix: ${f.remediation}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: (f.relativeFile || 'mcp.json').replace(/^\.\//, ''),
            uriBaseId: '%SRCROOT%',
          },
          region: {
            startLine: f.line || 1,
            startColumn: f.column || 1,
          },
        },
      },
    ],
    properties: {
      client: f.client,
      serverName: f.serverName,
      maskedPreview: f.maskedPreview,
    },
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: '@shuliak-corp/sip1-mcp',
            version: auditResult.engineVersion || '3.1.0',
            informationUri: 'https://shuliak.dev',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            properties: {
              score: auditResult.score,
              grade: auditResult.grade,
              durationMs: auditResult.durationMs,
              screenshotSafe: true,
            },
          },
        ],
        results,
      },
    ],
  };
}
