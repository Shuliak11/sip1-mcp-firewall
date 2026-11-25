/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 2 Deterministic SQL / Shell / Path Blast-Radius Classifier
 * Zero external dependencies. Evaluates in < 0.25 ms.
 */

import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { jcsCanonicalize } from '../core/jcs.mjs';
import { DOMAIN_PREFIX, b64u, domainSha256 } from '../core/crypto-primitives.mjs';
import { redactStringForLockPreview, scanUnicodeSmuggling } from '../stage1/audit-scanner.mjs';

function safeSnippet(raw, maxLen = 56) {
  const masked = String(raw || '').replace(/[A-Za-z0-9_:/@-]{12,}/g, (tok) => {
    return redactStringForLockPreview(tok) ?? tok;
  });
  return masked.length > maxLen ? masked.slice(0, maxLen) + '...' : masked;
}

export const ACTION_TIERS = Object.freeze({
  TIER_0_SAFE_READ: 'TIER_0_SAFE_READ',
  TIER_1_REVERSIBLE_WRITE: 'TIER_1_REVERSIBLE_WRITE',
  TIER_2_WARRANT_REQUIRED: 'TIER_2_WARRANT_REQUIRED',
  TIER_3_UNCONDITIONAL_BLOCK: 'TIER_3_UNCONDITIONAL_BLOCK',
});

/**
 * Compute domain-separated 0x07 RFC 8785 JCS digest of `{ server, tool, args }`.
 * @param {{ server: string, tool: string, args: unknown }} params
 * @returns {string} 43-char base64url digest
 */
export function computeNormalizedActionDigest({ server, tool, args }) {
  const canonicalPayload = {
    args: args ?? {},
    server: String(server ?? ''),
    tool: String(tool ?? ''),
  };
  return b64u(domainSha256(DOMAIN_PREFIX.WARRANT_ACTION, jcsCanonicalize(canonicalPayload)));
}

/**
 * Recursively collect all string keys/values and numeric/array metadata from `args`.
 * @param {unknown} value
 * @param {string} [prefix='args']
 * @param {Array<{ keyPath: string, keyName: string, value: string }>} [strings=[]]
 * @param {Array<{ keyName: string, num: number }>} [numbers=[]]
 * @param {Array<{ keyName: string, length: number, items: unknown[] }>} [arrays=[]]
 */
function collectArgsTelemetry(value, prefix = 'args', strings = [], numbers = [], arrays = []) {
  if (typeof value === 'string') {
    const lastSeg = prefix.split('.').pop() || prefix;
    strings.push({ keyPath: prefix, keyName: lastSeg, value });
    return { strings, numbers, arrays };
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    const lastSeg = prefix.split('.').pop() || prefix;
    numbers.push({ keyName: lastSeg, num: value });
    return { strings, numbers, arrays };
  }
  if (Array.isArray(value)) {
    const lastSeg = prefix.split('.').pop() || prefix;
    arrays.push({ keyName: lastSeg, length: value.length, items: value });
    for (let i = 0; i < value.length; i++) {
      collectArgsTelemetry(value[i], `${prefix}[${i}]`, strings, numbers, arrays);
    }
    return { strings, numbers, arrays };
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      strings.push({ keyPath: `${prefix}.${k}@key`, keyName: '@key', value: k });
      collectArgsTelemetry(v, `${prefix}.${k}`, strings, numbers, arrays);
    }
  }
  return { strings, numbers, arrays };
}

/**
 * Strip SQL comments (`/* ... * /`, `-- ...`, and MySQL `# ...`) while preserving
 * single/double-quoted literals (including backslash `\'`, `\"`, `\\` and doubled `''`, `""` escapes),
 * collapse whitespace, and split statements on `;` outside quotes.
 *
 * @param {string} raw
 * @returns {string[]}
 */
export function normalizeAndSplitSqlStatements(raw) {
  let out = '';
  const len = raw.length;
  let i = 0;

  while (i < len) {
    const ch = raw[i];
    const next = i + 1 < len ? raw[i + 1] : '';

    // Single-quoted SQL string literal (supports both '' and \' / \\ escapes)
    if (ch === "'") {
      out += ch;
      i++;
      while (i < len) {
        const sc = raw[i];
        out += sc;
        i++;
        if (sc === '\\' && i < len) {
          out += raw[i];
          i++;
          continue;
        }
        if (sc === "'" && raw[i] === "'") {
          out += raw[i];
          i++;
          continue;
        }
        if (sc === "'") break;
      }
      continue;
    }

    // Double-quoted SQL identifier/literal (supports both "" and \" / \\ escapes)
    if (ch === '"') {
      out += ch;
      i++;
      while (i < len) {
        const dc = raw[i];
        out += dc;
        i++;
        if (dc === '\\' && i < len) {
          out += raw[i];
          i++;
          continue;
        }
        if (dc === '"' && raw[i] === '"') {
          out += raw[i];
          i++;
          continue;
        }
        if (dc === '"') break;
      }
      continue;
    }

    // Block comment /* ... */ -> replace with single space so DROP/**/TABLE -> DROP TABLE
    if (ch === '/' && next === '*') {
      out += ' ';
      i += 2;
      while (i < len && !(raw[i] === '*' && raw[i + 1] === '/')) {
        i++;
      }
      i += 2;
      continue;
    }

    // Line comment -- ... \n -> replace with space
    if (ch === '-' && next === '-') {
      out += ' ';
      i += 2;
      while (i < len && raw[i] !== '\n' && raw[i] !== '\r') {
        i++;
      }
      continue;
    }

    // MySQL line comment # ... \n -> replace with space
    if (ch === '#') {
      out += ' ';
      i++;
      while (i < len && raw[i] !== '\n' && raw[i] !== '\r') {
        i++;
      }
      continue;
    }

    out += ch;
    i++;
  }

  // Split statements on ';' outside quotes (respecting \' / \" / \\ and '' / "")
  const statements = [];
  let buf = '';
  let inSingle = false;
  let inDouble = false;

  for (let j = 0; j < out.length; j++) {
    const c = out[j];
    if (inSingle) {
      buf += c;
      if (c === '\\' && j + 1 < out.length) {
        buf += out[++j];
      } else if (c === "'" && out[j + 1] === "'") {
        buf += out[++j];
      } else if (c === "'") {
        inSingle = false;
      }
    } else if (inDouble) {
      buf += c;
      if (c === '\\' && j + 1 < out.length) {
        buf += out[++j];
      } else if (c === '"' && out[j + 1] === '"') {
        buf += out[++j];
      } else if (c === '"') {
        inDouble = false;
      }
    } else if (c === "'") {
      inSingle = true;
      buf += c;
    } else if (c === '"') {
      inDouble = true;
      buf += c;
    } else if (c === ';') {
      const collapsed = buf.replace(/\s+/g, ' ').trim();
      if (collapsed) statements.push(collapsed);
      buf = '';
    } else {
      buf += c;
    }
  }
  const tail = buf.replace(/\s+/g, ' ').trim();
  if (tail) statements.push(tail);

  return statements;
}

/**
 * Replace single-quoted SQL string literal contents with empty `''` so structural
 * keyword inspection never false-positives on `'DROP TABLE fake'` or `'COPY x TO PROGRAM'`.
 * @param {string} stmt
 * @returns {string}
 */
function stripSingleQuotedLiteralContents(stmt) {
  let out = '';
  let i = 0;
  while (i < stmt.length) {
    const c = stmt[i];
    if (c === "'") {
      out += "''";
      i++;
      while (i < stmt.length) {
        const sc = stmt[i++];
        if (sc === '\\' && i < stmt.length) {
          i++;
          continue;
        }
        if (sc === "'" && stmt[i] === "'") {
          i++;
          continue;
        }
        if (sc === "'") break;
      }
      continue;
    }
    if (c === '"') {
      out += c;
      i++;
      while (i < stmt.length) {
        const dc = stmt[i++];
        out += dc;
        if (dc === '\\' && i < stmt.length) {
          out += stmt[i++];
          continue;
        }
        if (dc === '"' && stmt[i] === '"') {
          out += stmt[i++];
          continue;
        }
        if (dc === '"') break;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * Extract top-level statement plus any balanced parenthesized subquery/CTE bodies (outside quotes)
 * and the trailing main statement after `WITH [RECURSIVE] ... AS (...)`.
 * @param {string} stmt
 * @returns {string[]}
 */
function expandSqlStatementsAndSubqueries(stmt) {
  const candidates = [stmt];
  const stack = [];
  let inSingle = false;
  let inDouble = false;
  let lastTopCloseIdx = -1;
  const startsWithWith = /^WITH\b/i.test(stmt);

  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i];
    if (inSingle) {
      if (c === '\\') i++;
      else if (c === "'" && stmt[i + 1] === "'") i++;
      else if (c === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (c === '\\') i++;
      else if (c === '"' && stmt[i + 1] === '"') i++;
      else if (c === '"') inDouble = false;
      continue;
    }
    if (c === "'") {
      inSingle = true;
    } else if (c === '"') {
      inDouble = true;
    } else if (c === '(') {
      stack.push(i);
    } else if (c === ')' && stack.length > 0) {
      const openIdx = stack.pop();
      const inner = stmt.slice(openIdx + 1, i).trim();
      if (inner) candidates.push(inner);
      if (startsWithWith && stack.length === 0) {
        const restAfterParen = stmt.slice(i + 1).trim();
        // If not followed by `, next_cte AS (` then `restAfterParen` is the main query body after WITH CTEs
        if (restAfterParen && !/^,\s*[A-Za-z0-9_"`[\].]+(?:\s*\([^)]*\))?\s+AS\s*\(/i.test(restAfterParen)) {
          lastTopCloseIdx = i;
        }
      }
    }
  }

  if (startsWithWith && lastTopCloseIdx >= 0) {
    const afterCte = stmt.slice(lastTopCloseIdx + 1).trim();
    if (afterCte) candidates.push(afterCte);
  }

  return candidates;
}

/**
 * Detect PostgreSQL `COPY ... TO PROGRAM` / `COPY ... FROM PROGRAM` RCE outside string literals.
 * @param {string} rawCandidate
 * @returns {string | null}
 */
export function detectPostgresCopyProgramRce(rawCandidate) {
  if (!/\bCOPY\b/i.test(rawCandidate) || !/\bPROGRAM\b/i.test(rawCandidate)) {
    return null;
  }
  const statements = normalizeAndSplitSqlStatements(rawCandidate);
  for (const stmt of statements) {
    for (const sub of expandSqlStatementsAndSubqueries(stmt)) {
      const literalMasked = stripSingleQuotedLiteralContents(sub);
      if (/(?:^|\b)COPY\b[\s\S]*?\b(?:TO|FROM)\s+PROGRAM\b/i.test(literalMasked)) {
        return `PostgreSQL COPY ... PROGRAM arbitrary OS command execution blocked ("${safeSnippet(sub, 56)}")`;
      }
    }
  }
  return null;
}

/**
 * Evaluate whether a SQL `WHERE` predicate is tautological (`WHERE 1=1`, `WHERE true`,
 * `WHERE 'a'='a'`, `WHERE col IS NOT NULL`, `WHERE 1<2`, `WHERE 1 OR 1`, `OR 1=1`).
 * @param {string} whereClause
 * @returns {boolean}
 */
function isTautologicalWherePredicate(whereClause) {
  const cleaned = whereClause
    .replace(/\b(?:RETURNING|ORDER\s+BY|LIMIT|OFFSET)\b[\s\S]*$/i, '')
    .trim()
    .replace(/^\(+|\)+$/g, '')
    .trim();

  if (!cleaned) return true;

  // Direct boolean tautology: WHERE true / WHERE NOT false / WHERE 1 / WHERE 1 OR 1
  if (/^(?:true|not\s+false|not\s+0|[1-9]\d*)$/i.test(cleaned)) return true;

  // Disjunctive boolean literal tautology: ... OR true / ... OR NOT false / ... OR 1
  if (/\bOR\s+\(?\s*(?:true|not\s+false|not\s+0|[1-9]\d*)\s*\)?(?:\s|$)/i.test(cleaned)) return true;

  // Column IS NOT NULL tautology on whole-table DELETE/UPDATE (`WHERE id IS NOT NULL` or `... OR id IS NOT NULL`)
  if (/^[A-Za-z_"`[\]][A-Za-z0-9_."`[\]]*\s+IS\s+NOT\s+NULL$/i.test(cleaned)) return true;
  if (/\bOR\s+\(?\s*[A-Za-z_"`[\]][A-Za-z0-9_."`[\]]*\s+IS\s+NOT\s+NULL\s*\)?(?:\s|$)/i.test(cleaned)) {
    return true;
  }

  // Numeric comparison tautologies: 1=1, 1<2, 2>1, 1<=2, 2>=2, 1!=2, 1<>2 (standalone or after OR)
  const numCmpRe =
    /(?:^|\bOR\s+\(?)\s*(-?\d+(?:\.\d+)?)\s*(=|!=|<>|<=|>=|<|>)\s*(-?\d+(?:\.\d+)?)\s*\)?(?:\s|$)/gi;
  let m;
  while ((m = numCmpRe.exec(cleaned)) !== null) {
    const lhs = Number(m[1]);
    const op = m[2];
    const rhs = Number(m[3]);
    if (
      (op === '=' && lhs === rhs) ||
      ((op === '!=' || op === '<>') && lhs !== rhs) ||
      (op === '<' && lhs < rhs) ||
      (op === '>' && lhs > rhs) ||
      (op === '<=' && lhs <= rhs) ||
      (op === '>=' && lhs >= rhs)
    ) {
      return true;
    }
  }

  // Single-quoted literal comparison tautology: 'a'='a', ''='', 'a'!='b', 'a'<>'b'
  const singleCmpRe = /(?:^|\bOR\s+\(?)\s*'([^']*)'\s*(=|!=|<>)\s*'([^']*)'\s*\)?(?:\s|$)/gi;
  while ((m = singleCmpRe.exec(cleaned)) !== null) {
    if ((m[2] === '=' && m[1] === m[3]) || ((m[2] === '!=' || m[2] === '<>') && m[1] !== m[3])) {
      return true;
    }
  }

  // Double-quoted comparison tautology: "a"="a"
  const doubleEqRe = /(?:^|\bOR\s+\(?)\s*"([^"]*)"\s*=\s*"([^"]*)"\s*\)?(?:\s|$)/gi;
  while ((m = doubleEqRe.exec(cleaned)) !== null) {
    if (m[1] === m[2]) return true;
  }

  return false;
}

/**
 * Inspect a single unwrapped SQL clause/statement for destructive DDL/DML.
 * @param {string} stmt
 * @returns {string | null}
 */
function inspectSingleSqlClause(stmt) {
  const trimmed = stmt.replace(/^\(+|\)+$/g, '').trim();
  if (!trimmed) return null;

  if (
    /^DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|MATERIALIZED\s+VIEW|ROLE|USER|FUNCTION|TRIGGER)\b/i.test(
      trimmed
    )
  ) {
    return `Destructive SQL DDL statement detected ("${safeSnippet(trimmed, 48)}")`;
  }
  if (/^TRUNCATE\s+(?:TABLE\s+)?[A-Za-z0-9_"`[\].]+/i.test(trimmed)) {
    return `Destructive SQL TRUNCATE statement detected ("${safeSnippet(trimmed, 48)}")`;
  }
  if (/^ALTER\s+TABLE\s+[A-Za-z0-9_"`[\].]+\s+DROP\b/i.test(trimmed)) {
    return `Destructive SQL ALTER TABLE ... DROP detected ("${safeSnippet(trimmed, 56)}")`;
  }

  // DELETE FROM <table> [WHERE ...]
  if (/^DELETE\s+(?:FROM\s+)?[A-Za-z0-9_"`[\].]+/i.test(trimmed)) {
    const whereMatch = /\bWHERE\s+([\s\S]+)$/i.exec(trimmed);
    if (!whereMatch) {
      return `Unbounded SQL DELETE without WHERE clause ("${safeSnippet(trimmed, 56)}")`;
    }
    if (isTautologicalWherePredicate(whereMatch[1])) {
      return `Tautological SQL WHERE clause in DELETE ("${safeSnippet(trimmed, 64)}")`;
    }
  }

  // UPDATE <table> SET ... [WHERE ...]
  if (/^UPDATE\s+[A-Za-z0-9_"`[\].]+\s+SET\s+/i.test(trimmed)) {
    const whereMatch = /\bWHERE\s+([\s\S]+)$/i.exec(trimmed);
    if (!whereMatch) {
      return `Unbounded SQL UPDATE without WHERE clause ("${safeSnippet(trimmed, 56)}")`;
    }
    if (isTautologicalWherePredicate(whereMatch[1])) {
      return `Tautological SQL WHERE clause in UPDATE ("${safeSnippet(trimmed, 64)}")`;
    }
  }

  return null;
}

/**
 * Inspect a normalized SQL string for destructive Stage 2 `SIP-W01` / `COPY PROGRAM` patterns,
 * including statements nested inside `WITH ... AS (...)` CTEs or parenthesized subqueries.
 * @param {string} rawCandidate
 * @returns {string | null} Reason if destructive, else null
 */
export function detectDestructiveSql(rawCandidate) {
  const copyRce = detectPostgresCopyProgramRce(rawCandidate);
  if (copyRce) return copyRce;

  if (!/(?:\bDROP\b|\bTRUNCATE\b|\bALTER\b|\bDELETE\b|\bUPDATE\b)/i.test(rawCandidate)) {
    return null;
  }

  const statements = normalizeAndSplitSqlStatements(rawCandidate);
  for (const stmt of statements) {
    for (const sub of expandSqlStatementsAndSubqueries(stmt)) {
      const hit = inspectSingleSqlClause(sub);
      if (hit) return hit;
    }
  }

  return null;
}

/**
 * Split shell command strings across `;`, `&&`, `||`, `|`, `\r?\n` newlines, `$(...)`, and backticks.
 * @param {string} raw
 * @returns {string[]}
 */
export function splitShellSegments(raw) {
  const segments = [];
  // Extract subshells $(...) and `...` as additional segments to inspect
  const subshellRe = /\$\(([^)]+)\)|`([^`]+)`/g;
  let sub;
  while ((sub = subshellRe.exec(raw)) !== null) {
    const inner = (sub[1] || sub[2] || '').trim();
    if (inner) segments.push(inner);
  }

  const parts = raw.split(/\s*(?:;|&&|\|\||\|+|\r?\n)\s*/);
  for (const p of parts) {
    const trimmed = p.trim();
    if (trimmed) segments.push(trimmed);
  }
  return segments;
}

const CVE_103572_PATH_RE = new RegExp(
  '(?:^|[\\/])(?:' +
  '(?:\\.sip|\\.git\\/(?:hooks|config)|' +
  '\\.github\\/hooks|\\.(?:devin|roo|gemini))' +
  '(?:[\\/]|$)|' +
  '(?:sip2\\.lock\\.json|\\.mcp\\.json|' +
  '\\.cursor\\/hooks\\.json|' +
  '\\.claude\\/settings(?:\\.local)?\\.json|' +
  '\\.npmrc|\\.netrc)$)', 'i'
);

export function normalizeAdversarialPathToken(raw) {
  let t = String(raw || '').trim();
  for (let p = 0; p < 2; p++) {
    try { t = decodeURIComponent(t); } catch {}
  }
  t = t.replace(/\\/g, '/').replace(/\/+$/g, '');
  const segs = t.split('/').map((seg, idx) => {
    let x = seg;
    const drv = idx === 0 && /^[A-Za-z]:$/.test(x);
    if (!drv && x.includes(':')) {
      x = x.split(':')[0];
    }
    if (x !== '.' && x !== '..') {
      x = x.replace(/[. ]+$/g, '');
    }
    return x;
  });
  return segs.join('/');
}

export function hasCve103572Path(val) {
  const parts = String(val || '')
    .split(/[\s'"`=;,]+/);
  for (const part of parts) {
    if (!part) continue;
    const norm = normalizeAdversarialPathToken(part);
    if (CVE_103572_PATH_RE.test(norm)) return norm;
  }
  return null;
}

const NAT64_RE = /(?<![0-9a-f:])64:ff9b(?::1)?::/i;
const IPV4_MAP_DEC_RE = new RegExp(
  '(?:::ffff:|0:0:0:0:0:ffff:)' +
  '(?:127\\.|10\\.|0\\.|169\\.254\\.|' +
  '192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.)',
  'i'
);
const IPV4_MAP_HEX_RE = new RegExp(
  '(?:::ffff:|0:0:0:0:0:ffff:)' +
  '(?:7f[0-9a-f]{2}:|a9fe:|c0a8:|' +
  '0?a[0-9a-f]{2}:|ac1[0-9a-f]:|' +
  '0{1,4}:0{1,4}(?:[^0-9a-f:]|$))', 'i'
);
const IPV6_PRIV_URL_RE = new RegExp(
  'https?:\\/\\/\\[(?:' +
  '::1|(?:0+:){7}1|fe80:|fc[0-9a-f]{2}:|' +
  'fd[0-9a-f]{2}:)[^\\]]*\\]', 'i'
);
const OBFUSCATED_IP_URL_RE = new RegExp(
  'https?:\\/\\/(?:2852039166|0xa9fea9fe|' +
  '2130706433|0x7f000001|0177\\.|0251\\.0376\\.)',
  'i'
);

const IMDS_URI_RE = new RegExp(
  '(?:https?:\\/\\/(?:169\\.254\\.169\\.254|' +
  '100\\.100\\.100\\.200|' +
  '\\[?fd00:ec2::254\\]?|' +
  'metadata\\.google\\.internal|' +
  'metadata\\.azure\\.internal)|' +
  '^file:\\/\\/\\/(?:etc\\/|proc\\/|sys\\/|' +
  'Users\\/[^/]+\\/\\.(?:ssh|aws|gnupg|npmrc)|' +
  'Windows\\/System32))', 'i'
);

export function detectImdsOrSensitiveFileUri(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  if (IMDS_URI_RE.test(s)) {
    return 'IMDS/sensitive file URI SSRF';
  }
  return null;
}

export function detectSsrfAddressEvasion(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  if (NAT64_RE.test(s)) {
    return 'NAT64 64:ff9b::/96 SSRF (CVE-2026-125926)';
  }
  if (IPV4_MAP_DEC_RE.test(s) ||
      IPV4_MAP_HEX_RE.test(s)) {
    return 'IPv4-mapped IPv6 SSRF (CVE-2026-125926)';
  }
  if (IPV6_PRIV_URL_RE.test(s) ||
      OBFUSCATED_IP_URL_RE.test(s)) {
    return 'Private IPv6/obfuscated IP SSRF';
  }
  return null;
}

const SIP_SELF_TAMPER_RE =
  /(?:^|[\\/'"`\s=])\.sip(?:[\\/'"`\s]|$)|(?:^|[\\/'"`\s=])(?:sip2\.lock\.json|device\.ed25519\.(?:pem|pub)|warrants-ledger\.json|finops-window\.json|canaries\.json|lockdown\.json|\.env\.sip-canary)(?:['"`\s]|$)/i;

const RCE_PIPE_RE =
  /\b(?:curl|wget|fetch)\b[\s\S]*?\|\s*(?:sudo\s+)?(?:\/usr\/bin\/|\/bin\/)?(?:ba|z|da|k|a)?sh\b|\bbase64\s+(?:-d|--decode|-D)\b[\s\S]*?\|\s*(?:sudo\s+)?(?:\/usr\/bin\/|\/bin\/)?(?:ba|z|da|k|a)?sh\b/i;

const SHELL_EVAL_RE = /(?:^|[;&|\r\n]\s*|\$\(\s*|`\s*)eval\s+\S+/;

const EXFIL_SENSITIVE_PATH_RE =
  /(?:^|[\\/'"`\s=])(?:~\/\.ssh|\/\.ssh\/|id_rsa\b|id_ed25519\b|~\/\.aws|\/\.aws\/|\/etc\/shadow\b|\/etc\/sudoers\b|\.git\/config\b|\.git\/hooks(?:[\\/'"`\s]|$))/i;

/**
 * Detect Tier 2 destructive CLI / Git / Cloud mutations (`SIP-W02`).
 * @param {string} fullStr
 * @returns {string | null}
 */
function detectDestructiveCliOrCloud(fullStr) {
  const segments = splitShellSegments(fullStr);
  for (const seg of segments) {
    // rm -rf / rm -fr / rm --recursive / rm -r -f
    if (
      /^rm\s+(?:-[A-Za-z]*[rR][A-Za-z]*f|-[A-Za-z]*f[A-Za-z]*[rR]|--recursive\b|-[rR]\s+-[fF]|-[fF]\s+-[rR])\b/.test(
        seg
      )
    ) {
      return `Destructive recursive deletion command ("${safeSnippet(seg, 64)}")`;
    }
    if (/^find\b[\s\S]*\s-delete\b/.test(seg)) {
      return `Destructive find -delete mutation ("${safeSnippet(seg, 64)}")`;
    }
    if (/^git\s+push\b[\s\S]*(?:\s--force(?:-with-lease)?\b|\s-f(?:\s|$))/.test(seg)) {
      return `Destructive force-push rewrite ("${safeSnippet(seg, 64)}")`;
    }
    if (/^git\s+reset\s+--hard\b/.test(seg) || /^git\s+clean\s+-[A-Za-z]*f/.test(seg)) {
      return `Destructive git working-tree reset/clean ("${safeSnippet(seg, 64)}")`;
    }
    if (/^(?:terraform|tofu|pulumi)\s+destroy\b/i.test(seg)) {
      return `Destructive infrastructure destroy ("${safeSnippet(seg, 64)}")`;
    }
    if (/^kubectl\s+delete\b/i.test(seg)) {
      return `Destructive Kubernetes resource deletion ("${safeSnippet(seg, 64)}")`;
    }
    if (
      /^aws\s+s3\s+(?:rb\b|rm\b[\s\S]*--recursive)/i.test(seg) ||
      /^aws\s+rds\s+delete-[a-z0-9-]+/i.test(seg) ||
      /^aws\s+ec2\s+terminate-instances\b/i.test(seg)
    ) {
      return `Destructive AWS cloud resource deletion ("${safeSnippet(seg, 64)}")`;
    }
  }
  return null;
}

const FINANCIAL_FIELD_RE = /^(?:amount|amount_?usd|total|transfer_?amount|payment_?amount|charge_?amount|price|value)$/i;
const FINANCIAL_CENTS_RE = /^(?:amount_?cents|total_?cents)$/i;
const MASS_MUTATION_TOOL_RE = /(?:delete|remove|archive|purge|send|transfer|drop|bulk|destroy|terminate|revoke)/i;
const BATCH_ARRAY_KEY_RE = /^(?:ids|items|records|paths|files|recipients|targets|users|emails|messages|rows)$/i;
const BATCH_COUNT_KEY_RE = /^(?:batch_?size|count|num_?items|delete_?count)$/i;

const PATH_KEY_RE = /^(?:path|file_?path|filepath|target_?path|dest_?path|source_?path|filename|file)$/i;
const WRITE_TOOL_HINT_RE =
  /(?:write|edit|patch|create|save|delete|remove|unlink|rename|move|mv|cp|append|replace|touch|put|update_file)/i;
const READ_ONLY_TOOL_HINT_RE = /^(?:read|get|list|search|grep|find|inspect|view|cat|ls|status|select|query_readonly)/i;

/**
 * Deterministic Stage 2 Blast-Radius AST & Lexical Classifier.
 * Completes in < 0.25 ms with zero subprocesses.
 *
 * @param {{
 *   server: string,
 *   tool: string,
 *   args: Record<string, unknown> | unknown,
 *   workspaceDir?: string,
 * }} params
 */
export function classifyToolAction({
  server, tool, args, workspaceDir,
  annotations: _ignoredAnnotations,
  toolAnnotations: _ignoredToolAnnotations,
}) {
  const t0 = performance.now();
  const safeServer = String(server ?? 'unknown-server');
  const safeTool = String(tool ?? 'unknown-tool');
  const safeArgs = args && typeof args === 'object' ? args : {};
  const normalizedActionDigest = computeNormalizedActionDigest({
    server: safeServer,
    tool: safeTool,
    args: safeArgs,
  });

  const { strings, numbers, arrays } = collectArgsTelemetry(safeArgs);
  const allInspectableStrings = [
    { keyPath: 'server', keyName: 'server', value: safeServer },
    { keyPath: 'tool', keyName: 'tool', value: safeTool },
    ...strings,
  ];

  // Also synthesize CLI string when args are passed as { command, args: [...] }
  if (
    safeArgs &&
    typeof safeArgs === 'object' &&
    !Array.isArray(safeArgs) &&
    Array.isArray(/** @type {any} */ (safeArgs).args)
  ) {
    const cmdPrefix =
      typeof (/** @type {any} */ (safeArgs).command) === 'string'
        ? /** @type {any} */ (safeArgs).command + ' '
        : `${safeTool} `;
    const joinedCli = cmdPrefix + /** @type {any} */ (safeArgs).args.map(String).join(' ');
    strings.push({ keyPath: 'args.@joinedCli', keyName: 'command', value: joinedCli });
  }

  // ==========================================================================
  // 1. TIER_3_UNCONDITIONAL_BLOCK (NEVER overridable even with valid Warrant!)
  // ==========================================================================

  // SIP-G03: Plane-14 Tag Smuggling or Bidi Trojan-Source Overrides
  for (const entry of allInspectableStrings) {
    const hits = scanUnicodeSmuggling(entry.value, { allowLeadingBom: false });
    if (hits.length > 0) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G03',
        reason: `${hits[0].category} (${hits[0].codePointHex}) detected in ${entry.keyPath}`,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
  }

  // SIP-G05..G07: Config Mutate, IMDS & SQL RCE
  const IMDS_RE = new RegExp(
    '(?:https?:\\/\\/(?:169\\.254\\.169\\.254|'
    + '100\\.100\\.100\\.200|'
    + '\\[?fd00:ec2::254\\]?|'
    + 'metadata\\.google\\.internal|'
    + 'metadata\\.azure\\.internal)|'
    + '^file:\\/\\/\\/(?:etc\\/|proc\\/|'
    + 'Users\\/[^/]+\\/\\.(?:ssh|aws|gnupg|npmrc)|'
    + 'Windows\\/System32))', 'i'
  );
  const SQL_RCE_RE = new RegExp(
    '\\b(?:pg_read_file|pg_read_binary_file|pg_ls_dir|'
    + 'lo_import|lo_export|dblink_exec|xp_cmdshell|'
    + 'INTO\\s+(?:OUTFILE|DUMPFILE))\\b|'
    + '\\bMERGE\\s+INTO\\b[\\s\\S]{0,240}'
    + '\\bDELETE\\b', 'i'
  );
  const MUT_RE = /^(?:set_config_value|update_config)$/i;
  const dur = () => Number(
    (performance.now() - t0).toFixed(4)
  );
  const HOOK_TAMPER_RE = new RegExp(
    '(?:^|[\\\\/\"\'])(?:\\.sip(?:[\\\\/\"\']|$)|'
    + 'sip2\\.lock\\.json|\\.cursor[\\\\/]hooks\\.json|'
    + '\\.claude[\\\\/]settings(?:\\.local)?\\.json|'
    + '\\.mcp\\.json|\\.npmrc|\\.netrc)(?:[\"\'\\s]|$)',
    'i'
  );
  const rawArgsDump = JSON.stringify(safeArgs);
  if (HOOK_TAMPER_RE.test(rawArgsDump)) {
    return {
      tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
      ruleId: 'SIP-G01',
      reason: 'Blocked self-tampering on config/hooks',
      normalizedActionDigest,
      targetPaths: [],
      durationMs: dur(),
    };
  }
  if (MUT_RE.test(safeTool)) {
    const rawCfg = JSON.stringify(safeArgs);
    if (/allowedDirectories|blockedCommands|defaultShell/i
        .test(rawCfg)) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G05',
        reason: 'Blocked runtime policy mutation',
        normalizedActionDigest,
        targetPaths: [],
        durationMs: dur(),
      };
    }
  }
  for (const entry of allInspectableStrings) {
    const v = entry.value.trim();
    const cvePath = hasCve103572Path(v);
    if (cvePath) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: /(?:^|\/)\.git\/(?:hooks|config)(?:\/|$)/i
          .test(cvePath) ? 'SIP-G02' : 'SIP-G01',
        reason: 'Blocked CVE-2026-103572 path: ' +
          cvePath,
        normalizedActionDigest,
        targetPaths: [cvePath.slice(0, 80)],
        durationMs: dur(),
      };
    }
    const ssrfHit = detectSsrfAddressEvasion(v);
    if (ssrfHit) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G06',
        reason: `Blocked ${ssrfHit} in ` +
          entry.keyPath,
        normalizedActionDigest,
        targetPaths: [v.slice(0, 80)],
        durationMs: dur(),
      };
    }
    if (SIP_SELF_TAMPER_RE.test(v)) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G01',
        reason: 'Blocked agent self-tampering: ' + v,
        normalizedActionDigest,
        targetPaths: [v.slice(0, 80)],
        durationMs: dur(),
      };
    }
    if (IMDS_RE.test(v)) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G06',
        reason: 'Blocked IMDS/file SSRF: ' + entry.keyPath,
        normalizedActionDigest,
        targetPaths: [v.slice(0, 80)],
        durationMs: dur(),
      };
    }
    if (SQL_RCE_RE.test(v)) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G07',
        reason: 'Blocked SQL file-RCE / MERGE DELETE',
        normalizedActionDigest,
        targetPaths: [],
        durationMs: dur(),
      };
    }
  }

  // SIP-G01: Agent Self-Tampering targeting `.sip/` control directory or lock/key files
  for (const entry of strings) {
    const val = entry.value.trim();
    if (SIP_SELF_TAMPER_RE.test(val)) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G01',
        reason: `Unconditional self-protection block: tool attempted to access protected .sip/ security state in ${entry.keyPath}`,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
    if (workspaceDir && PATH_KEY_RE.test(entry.keyName)) {
      const resolved = path.resolve(workspaceDir, val);
      const sipRoot = path.resolve(workspaceDir, '.sip');
      if (resolved === sipRoot || resolved.startsWith(sipRoot + path.sep)) {
        return {
          tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
          ruleId: 'SIP-G01',
          reason: `Unconditional self-protection block: resolved path targets .sip/ directory`,
          normalizedActionDigest,
          targetPaths: [],
          durationMs: Number((performance.now() - t0).toFixed(4)),
        };
      }
    }
  }

  // SIP-G02: RCE Shell Pipes (`curl | sh`, `wget | bash`, `base64 -d | sh`, `eval `), PostgreSQL `COPY ... PROGRAM`, & Exfiltration Paths
  for (const entry of strings) {
    const val = entry.value;
    if (RCE_PIPE_RE.test(val) || SHELL_EVAL_RE.test(val)) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G02',
        reason: `Remote code execution / arbitrary shell evaluation pipe blocked in ${entry.keyPath}`,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
    if (entry.keyName !== '@key') {
      const pgCopyRce = detectPostgresCopyProgramRce(val);
      if (pgCopyRce) {
        return {
          tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
          ruleId: 'SIP-G02',
          reason: `${pgCopyRce} in ${entry.keyPath}`,
          normalizedActionDigest,
          targetPaths: [],
          durationMs: Number((performance.now() - t0).toFixed(4)),
        };
      }
    }
    if (EXFIL_SENSITIVE_PATH_RE.test(val)) {
      return {
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-G02',
        reason: `Credential / Git hook tampering path blocked (CVE-2025-68145 / SSH / AWS / shadow) in ${entry.keyPath}`,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
  }

  // ==========================================================================
  // 2. TIER_2_WARRANT_REQUIRED (Fail-Closed unless Ed25519 Warrant / Lease)
  // ==========================================================================

  // SIP-W01: Destructive or Unbounded SQL
  for (const entry of strings) {
    if (entry.keyName === '@key') continue;
    const sqlReason = detectDestructiveSql(entry.value);
    if (sqlReason) {
      return {
        tier: ACTION_TIERS.TIER_2_WARRANT_REQUIRED,
        ruleId: 'SIP-W01',
        reason: sqlReason,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
  }

  // SIP-W02: Destructive CLI / Git / Cloud Mutations
  for (const entry of strings) {
    if (entry.keyName === '@key') continue;
    const cliReason = detectDestructiveCliOrCloud(entry.value);
    if (cliReason) {
      return {
        tier: ACTION_TIERS.TIER_2_WARRANT_REQUIRED,
        ruleId: 'SIP-W02',
        reason: cliReason,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
  }

  // SIP-W03: Bulk / Financial / Mass-Mutation Thresholds (`amount > 100`, batch `> 5`)
  for (const numEntry of numbers) {
    if (FINANCIAL_FIELD_RE.test(numEntry.keyName) && numEntry.num > 100) {
      return {
        tier: ACTION_TIERS.TIER_2_WARRANT_REQUIRED,
        ruleId: 'SIP-W03',
        reason: `Financial threshold exceeded: ${numEntry.keyName}=${numEntry.num} (> 100 limit requires Ed25519 warrant)`,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
    if (FINANCIAL_CENTS_RE.test(numEntry.keyName) && numEntry.num > 10_000) {
      return {
        tier: ACTION_TIERS.TIER_2_WARRANT_REQUIRED,
        ruleId: 'SIP-W03',
        reason: `Financial threshold exceeded: ${numEntry.keyName}=${numEntry.num} cents (> $100.00 requires Ed25519 warrant)`,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
    if (
      MASS_MUTATION_TOOL_RE.test(safeTool) &&
      BATCH_COUNT_KEY_RE.test(numEntry.keyName) &&
      numEntry.num > 5
    ) {
      return {
        tier: ACTION_TIERS.TIER_2_WARRANT_REQUIRED,
        ruleId: 'SIP-W03',
        reason: `Mass-mutation batch size ${numEntry.keyName}=${numEntry.num} (> 5 items) on "${safeTool}" requires warrant`,
        normalizedActionDigest,
        targetPaths: [],
        durationMs: Number((performance.now() - t0).toFixed(4)),
      };
    }
  }

  if (MASS_MUTATION_TOOL_RE.test(safeTool)) {
    for (const arrEntry of arrays) {
      if (BATCH_ARRAY_KEY_RE.test(arrEntry.keyName) && arrEntry.length > 5) {
        return {
          tier: ACTION_TIERS.TIER_2_WARRANT_REQUIRED,
          ruleId: 'SIP-W03',
          reason: `Mass-mutation batch array "${arrEntry.keyName}" contains ${arrEntry.length} items (> 5 limit) on "${safeTool}"`,
          normalizedActionDigest,
          targetPaths: [],
          durationMs: Number((performance.now() - t0).toFixed(4)),
        };
      }
    }
  }

  // ==========================================================================
  // 3. TIER_1_REVERSIBLE_WRITE vs TIER_0_SAFE_READ
  // ==========================================================================

  /** @type {string[]} */
  const candidatePaths = [];
  for (const entry of strings) {
    if (PATH_KEY_RE.test(entry.keyName) && entry.value.trim()) {
      candidatePaths.push(entry.value.trim());
    }
  }
  for (const arrEntry of arrays) {
    if (/^(?:files|paths|target_?paths)$/i.test(arrEntry.keyName)) {
      for (const item of arrEntry.items) {
        if (typeof item === 'string' && item.trim()) {
          candidatePaths.push(item.trim());
        }
      }
    }
  }

  // Also detect shell redirection writes (`echo ... > foo.txt`, `tee foo.txt`, `rm foo.txt`)
  let hasShellFileMutation = false;
  for (const entry of strings) {
    if (/^(?:command|cmd|script)$/i.test(entry.keyName)) {
      const redirMatch = /(?:>>?|\btee\s+|\brm\s+(?:-[fFiI]\s+)*|\btouch\s+)([A-Za-z0-9_./-]+)\b/.exec(
        entry.value
      );
      if (redirMatch && redirMatch[1] && !redirMatch[1].startsWith('/dev/')) {
        hasShellFileMutation = true;
        candidatePaths.push(redirMatch[1]);
      }
    }
  }

  // Server readOnlyHint is strictly untrusted
  const isMutatingTool =
    hasShellFileMutation ||
    (!READ_ONLY_TOOL_HINT_RE.test(safeTool) &&
      WRITE_TOOL_HINT_RE.test(safeTool));

  if (isMutatingTool && candidatePaths.length > 0) {
    if (workspaceDir) {
      const wsRoot = path.resolve(workspaceDir);
      for (const p of candidatePaths) {
        const resolved = path.resolve(wsRoot, p);
        const rel = path.relative(wsRoot, resolved);
        if (rel.startsWith('..') || path.isAbsolute(rel)) {
          return {
            tier: ACTION_TIERS.TIER_2_WARRANT_REQUIRED,
            ruleId: 'SIP-W02',
            reason: `File mutation target "${p}" escapes workspace root boundary`,
            normalizedActionDigest,
            targetPaths: [],
            durationMs: Number((performance.now() - t0).toFixed(4)),
          };
        }
      }
    }

    return {
      tier: ACTION_TIERS.TIER_1_REVERSIBLE_WRITE,
      ruleId: null,
      reason: `Scoped reversible workspace write (${candidatePaths.length} target ${
        candidatePaths.length === 1 ? 'path' : 'paths'
      })`,
      normalizedActionDigest,
      targetPaths: [...new Set(candidatePaths)],
      durationMs: Number((performance.now() - t0).toFixed(4)),
    };
  }

  return {
    tier: ACTION_TIERS.TIER_0_SAFE_READ,
    ruleId: null,
    reason: 'Read-only or scoped non-destructive query',
    normalizedActionDigest,
    targetPaths: [],
    durationMs: Number((performance.now() - t0).toFixed(4)),
  };
}

// V8_IRREGEXP_WARMUP
for (const _rx of [SIP_SELF_TAMPER_RE, RCE_PIPE_RE, SHELL_EVAL_RE, EXFIL_SENSITIVE_PATH_RE, FINANCIAL_FIELD_RE, FINANCIAL_CENTS_RE, MASS_MUTATION_TOOL_RE, BATCH_ARRAY_KEY_RE, BATCH_COUNT_KEY_RE, PATH_KEY_RE, WRITE_TOOL_HINT_RE, READ_ONLY_TOOL_HINT_RE]) {
  if (_rx instanceof RegExp) {
    _rx.test('postgres://u:p@h/d sk_live_000');
    _rx.lastIndex = 0;
  }
}
