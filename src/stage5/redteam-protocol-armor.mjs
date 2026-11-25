import crypto from 'node:crypto';
import {
  compareUtf16CodeUnits,
  jcsCanonicalize,
} from '../core/jcs.mjs';

export const MCP_SUPPORTED_VERSIONS = Object.freeze([
  '2026-07-28',
  '2025-11-25',
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
]);

export const MCP_META_PROTO_KEY =
  'io.modelcontextprotocol/protocolVersion';
export const MCP_META_SERVER_KEY =
  'io.modelcontextprotocol/serverInfo';

const ZW_BIDI_TAG_RE = new RegExp(
  '[\\u00AD\\u200B-\\u200F\\u202A-\\u202E' +
  '\\u2060-\\u2069\\uFEFF\\u061C\\u{E0000}-\\u{E007F}\\u{E0100}-\\u{E01EF}]',
  'gu'
);

const ANSI_OSC_RE = new RegExp(
  '\\x1B\\x5D[\\s\\S]*?(?:\\x07|\\x1B\\\\)|' +
  '\\x1B\\x5B[0-?]*[ -/]*[@-~]|' +
  '[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]',
  'g'
);

const CONFUSABLE_MAP = Object.freeze({
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K',
  '\u041C': 'M', '\u041D': 'H', '\u041E': 'O', '\u0420': 'P',
  '\u0421': 'C', '\u0422': 'T', '\u0425': 'X', '\u0406': 'I',
  '\u0405': 'S', '\u0408': 'J', '\u0391': 'A', '\u0392': 'B',
  '\u0395': 'E', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N',
  '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T', '\u03A7': 'X',
  '\u0399': 'I',
});

const MIXED_ID_TOK_RE =
  /[0-9A-Za-z\u0400-\u04FF\u0370-\u03FF]{4,}/g;

const SAFE_ID_KEY_RE = new RegExp(
  '(?:^|_)(?:id|uid|uuid|guid|snowflake|timestamp|ts|' +
  'created_?at|updated_?at|deleted_?at|expires_?at|epoch|' +
  'seq|sequence|offset|cursor|version|inode|span_?id|' +
  'trace_?id|request_?id|order_?id|user_?id|org_?id)$',
  'i'
);

export function stripTerminalControlCodes(input) {
  if (typeof input !== 'string' || !input) return input || '';
  return input.replace(ANSI_OSC_RE, '');
}

export function normalizeUnicodeEvasion(input) {
  if (typeof input !== 'string' || !input) return input || '';
  let s = input.replace(ZW_BIDI_TAG_RE, '');
  let folded = '';
  let mutated = false;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xff10 && cp <= 0xff19) {
      folded += String.fromCharCode(cp - 0xff10 + 0x30);
      mutated = true;
    } else if (cp >= 0xff21 && cp <= 0xff3a) {
      folded += String.fromCharCode(cp - 0xff21 + 0x41);
      mutated = true;
    } else if (cp >= 0xff41 && cp <= 0xff5a) {
      folded += String.fromCharCode(cp - 0xff41 + 0x61);
      mutated = true;
    } else if (cp >= 0x1d7ce && cp <= 0x1d7ff) {
      const d = ((cp - 0x1d7ce) % 10) + 0x30;
      folded += String.fromCharCode(d);
      mutated = true;
    } else {
      folded += ch;
    }
  }
  if (mutated) s = folded;
  if (/[\u0370-\u04FF]/.test(s)) {
    s = s.replace(MIXED_ID_TOK_RE, (tok) => {
      if (!/[0-9A-Za-z]/.test(tok)) return tok;
      let out = '';
      for (let i = 0; i < tok.length; i++) {
        const c = tok[i];
        out += CONFUSABLE_MAP[c] || c;
      }
      return out;
    });
  }
  return s;
}

export function detectDuplicateJsonKeys(rawJson) {
  if (typeof rawJson !== 'string') {
    return { hasDuplicate: false, key: null };
  }
  const n = rawJson.length;
  const stack = [];
  let i = 0;
  while (i < n) {
    const ch = rawJson[i];
    if (ch === ' ' || ch === '\t' ||
        ch === '\r' || ch === '\n') {
      i++;
      continue;
    }
    if (ch === '{') {
      stack.push(new Set());
      i++;
      continue;
    }
    if (ch === '}') {
      if (stack.length > 0) stack.pop();
      i++;
      continue;
    }
    if (ch === '[') {
      stack.push(null);
      i++;
      continue;
    }
    if (ch === ']') {
      if (stack.length > 0) stack.pop();
      i++;
      continue;
    }
    if (ch === '"') {
      const start = i;
      i++;
      let hasEsc = false;
      while (i < n) {
        const c = rawJson[i];
        if (c === '\\') {
          hasEsc = true;
          i += 2;
          continue;
        }
        if (c === '"') break;
        i++;
      }
      if (i >= n) return { hasDuplicate: false, key: null };
      const rawTok = rawJson.slice(start, i + 1);
      i++;
      let j = i;
      while (
        j < n &&
        (rawJson[j] === ' ' || rawJson[j] === '\t' ||
         rawJson[j] === '\r' || rawJson[j] === '\n')
      ) {
        j++;
      }
      const topSet = stack.length > 0
        ? stack[stack.length - 1] : null;
      if (j < n && rawJson[j] === ':' && topSet !== null) {
        let keyStr;
        if (hasEsc) {
          try {
            keyStr = JSON.parse(rawTok);
          } catch (_) {
            keyStr = rawTok.slice(1, -1);
          }
        } else {
          keyStr = rawTok.slice(1, -1);
        }
        if (topSet.has(keyStr)) {
          return { hasDuplicate: true, key: keyStr };
        }
        topSet.add(keyStr);
        i = j + 1;
      }
      continue;
    }
    i++;
  }
  return { hasDuplicate: false, key: null };
}

export function cleanProtoKeys(val) {
  if (!val || typeof val !== 'object') return val;
  if (Array.isArray(val)) return val.map(cleanProtoKeys);
  const out = {};
  for (const [k, v] of Object.entries(val)) {
    if (k === '__proto__' || k === 'constructor' ||
        k === 'prototype') {
      continue;
    }
    out[k] = cleanProtoKeys(v);
  }
  return out;
}

export function parseStrictJsonRpcFrame(rawLine) {
  const trimmed = String(rawLine || '').trim();
  if (trimmed.codePointAt(0) === 0x5b) {
    return {
      ok: false,
      reason: 'ERR_BATCH_FORBIDDEN',
      errorResponse: {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32600,
          message: 'JSON-RPC batch arrays are forbidden in MCP',
        },
      },
    };
  }
  const dup = detectDuplicateJsonKeys(trimmed);
  if (dup.hasDuplicate) {
    let reqId = null;
    try {
      const parsedTmp = JSON.parse(trimmed);
      if (parsedTmp && parsedTmp.id !== undefined) {
        reqId = parsedTmp.id;
      }
    } catch (_) {}
    return {
      ok: false,
      reason: 'ERR_DUPLICATE_JSON_KEY',
      duplicateKey: dup.key,
      errorResponse: {
        jsonrpc: '2.0',
        id: reqId,
        error: {
          code: -32600,
          message:
            `Duplicate JSON key blocked: "${dup.key}"`,
        },
      },
    };
  }
  const parsed = JSON.parse(trimmed);
  if (!parsed || typeof parsed !== 'object' ||
      Array.isArray(parsed)) {
    return {
      ok: false,
      reason: 'ERR_INVALID_REQUEST',
      errorResponse: {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Invalid Request' },
      },
    };
  }
  return { ok: true, message: cleanProtoKeys(parsed) };
}

function scrubSchemaStrings(node) {
  if (typeof node === 'string') {
    return stripTerminalControlCodes(
      normalizeUnicodeEvasion(node)
    );
  }
  if (!node || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map(scrubSchemaStrings);
  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (k === '__proto__' || k === 'constructor' ||
        k === 'prototype') {
      continue;
    }
    out[k] = scrubSchemaStrings(v);
  }
  return out;
}

export function sanitizeAndPinToolsList(
  tools, previousHash = null
) {
  const arr = Array.isArray(tools) ? tools : [];
  const cleanTools = arr
    .map((t) => scrubSchemaStrings(t))
    .sort((a, b) => compareUtf16CodeUnits(
      String(a?.name || ''),
      String(b?.name || '')
    ));
  const canonical = jcsCanonicalize(cleanTools);
  const hash = crypto
    .createHash('sha256')
    .update(canonical)
    .digest('hex');
  if (previousHash && previousHash !== hash) {
    return {
      ok: false,
      rugPullDetected: true,
      hash,
      previousHash,
      tools: cleanTools,
    };
  }
  return {
    ok: true,
    rugPullDetected: false,
    hash,
    tools: cleanTools,
  };
}

export function isPlausiblePaymentIin(digitsStr) {
  const d = String(digitsStr || '').replace(/\D/g, '');
  const n = d.length;
  if (n < 13 || n > 19) return false;
  if (/^(\d)\1+$/.test(d)) return false;
  const p1 = d[0];
  const p2 = Number(d.slice(0, 2));
  const p4 = Number(d.slice(0, 4));
  if (p1 === '4') return true;
  if (p2 >= 50 && p2 <= 59) return true;
  if (p2 >= 60 && p2 <= 69) return true;
  if ((p2 === 34 || p2 === 37) && n === 15) return true;
  if (p2 === 30 || p2 === 35 || p2 === 36 ||
      p2 === 38 || p2 === 39) {
    return true;
  }
  if (p4 >= 2200 && p4 <= 2720) return true;
  return false;
}

export function isSafeNumericIdKey(keyName) {
  return SAFE_ID_KEY_RE.test(String(keyName || '').trim());
}

export function checkMcpMetaProtocol(params) {
  const meta = params?._meta;
  if (!meta || typeof meta !== 'object') {
    return { era: '2025-11-25', valid: true, version: null };
  }
  const ver = meta[MCP_META_PROTO_KEY];
  if (ver === undefined || ver === null) {
    return { era: '2025-11-25', valid: true, version: null };
  }
  const sVer = String(ver);
  if (!MCP_SUPPORTED_VERSIONS.includes(sVer)) {
    return {
      era: 'unsupported',
      valid: false,
      version: sVer,
      errorObj: {
        code: -32022,
        message: `Unsupported protocol version: ${sVer}`,
        data: { supported: ['2026-07-28', '2025-11-25'] },
      },
    };
  }
  return {
    era: sVer === '2026-07-28' ? '2026-07-28' : '2025-11-25',
    valid: true,
    version: sVer,
  };
}

export function buildDiscoverResult(serverInfo) {
  const info = serverInfo || {
    name: '@shuliak-corp/sip1-mcp',
    version: '3.1.0',
  };
  return {
    resultType: 'complete',
    protocolVersion: '2026-07-28',
    supportedProtocolVersions: ['2026-07-28', '2025-11-25'],
    protocolVersions: ['2026-07-28', '2025-11-25'],
    serverInfo: info,
    capabilities: { tools: {} },
    _meta: { [MCP_META_SERVER_KEY]: info },
  };
}

export function decorateStateless2026Result(
  method, baseResult, serverInfo
) {
  const info = serverInfo || {
    name: '@shuliak-corp/sip1-mcp',
    version: '3.1.0',
  };
  const out = {
    ...(baseResult && typeof baseResult === 'object'
      ? baseResult : {}),
    resultType: baseResult?.resultType || 'complete',
    _meta: {
      ...(baseResult?._meta || {}),
      [MCP_META_SERVER_KEY]: info,
    },
  };
  if (method === 'tools/list') {
    if (Array.isArray(out.tools)) {
      out.tools = [...out.tools].sort((a, b) =>
        compareUtf16CodeUnits(
          String(a?.name || ''),
          String(b?.name || '')
        )
      );
    }
    out.ttlMs = out.ttlMs ?? 3600000;
    out.cacheScope = out.cacheScope ?? 'private';
  }
  return out;
}

const ELIC_URI_RE = new RegExp(
  '(?:^|[\\s"\'(<])(?:command|vscode|' +
  'vscode-insiders|jetbrains|cursor|windsurf|' +
  'javascript):', 'i'
);
const ELIC_SENSITIVE_FIELD_RE = new RegExp(
  '(?:^|[_\\s-])(?:password|passwd|passphrase|' +
  'secret|api[_-]?key|access[_-]?token|auth[_-]?token|' +
  'bearer|private[_-]?key|ssh[_-]?key|seed[_-]?phrase|' +
  'mnemonic|card[_-]?number|credit[_-]?card|' +
  'cvv|cvc|pan|iban|ssn|pin|otp)(?:$|[_\\s-])', 'i'
);

function walkElicStrings(node, out = []) {
  if (typeof node === 'string') {
    out.push(node);
    return out;
  }
  if (!node || typeof node !== 'object') return out;
  if (Array.isArray(node)) {
    for (const it of node) walkElicStrings(it, out);
    return out;
  }
  for (const [k, v] of Object.entries(node)) {
    out.push(k);
    walkElicStrings(v, out);
  }
  return out;
}

export function inspectElicitationOrInputRequired(msg) {
  if (!msg || typeof msg !== 'object') {
    return { blocked: false };
  }
  const method = typeof msg.method === 'string'
    ? msg.method : '';
  const res = msg.result && typeof msg.result === 'object'
    ? msg.result : null;
  const isElic = /^elicitation\//i.test(method);
  const rt = String(res?.resultType || '');
  const isInpReq = /^input[_-]?required/i.test(rt) ||
    Boolean(res?.elicitation) ||
    res?.mode === 'form';
  if (!isElic && !isInpReq) {
    return { blocked: false };
  }
  const body = isElic ? (msg.params || {}) : res;
  for (const s of walkElicStrings(body)) {
    const norm = normalizeUnicodeEvasion(s);
    if (ELIC_URI_RE.test(norm)) {
      return {
        blocked: true,
        code: -32012,
        ruleId: 'CVE-2026-120779',
        reason: 'Forbidden URI scheme in elicitation' +
          '/InputRequiredResult',
      };
    }
  }
  const mode = String(
    body?.mode || body?.elicitation?.mode || ''
  ).toLowerCase();
  const schema = body?.requestedSchema ||
    body?.elicitation?.requestedSchema ||
    body?.schema || null;
  if (mode === 'form' || schema) {
    const props = schema?.properties || body?.fields ||
      body?.properties || {};
    for (const [k, def] of Object.entries(props)) {
      const txt = [k, def?.title, def?.description,
        def?.format].filter(Boolean).join(' ');
      if (ELIC_SENSITIVE_FIELD_RE.test(txt)) {
        return {
          blocked: true,
          code: -32012,
          ruleId: 'CVE-2026-120779',
          reason: 'Blocked form elicitation for ' +
            `sensitive credential field "${k}"`,
        };
      }
    }
  }
  return { blocked: false };
}
