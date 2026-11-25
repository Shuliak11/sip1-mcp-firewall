import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  pseudonymizeSectorText,
  SECTOR_PACK_IDS,
} from '../stage4/sector-packs.mjs';
import {
  captureAndReplaceHeaderEntities,
  extractDocxText,
  extractOdtText,
  extractPdfText,
  extractXlsxText,
  formatProtectionBanner,
  isFhirR4Object,
  isHl7V2Text,
  pseudonymizeFhirR4,
  pseudonymizeHl7V2,
  rebuildDocxBuffer,
  rebuildOdtBuffer,
  rebuildXlsxBuffer,
} from './office-clinical-bridge.mjs';

const MAX_BRIDGE_BYTES = 10 * 1024 * 1024;
const MAX_VAULT_ENTRIES = 25_000;

const BLOCKED_EXTS = new Set([
  '.sh', '.bash', '.zsh', '.bat', '.cmd', '.ps1', '.vbs',
  '.exe', '.dll', '.so', '.dylib', '.mjs', '.cjs', '.js',
  '.ts', '.py', '.rb', '.php', '.pl', '.app', '.dmg', '.msi',
]);

const SYS_ROOT_RE = new RegExp(
  '^(?:\\/(?:etc|proc|sys|dev|boot|var\\/run)(?:\\/|$)|' +
  '[a-z]:\\\\(?:windows|programdata)(?:\\\\|$))',
  'i'
);

const CSV_FORMULA_RE =
  /^\s*[=+\-@](?:cmd\s*\||powershell|[A-Za-z_]{2,}\s*\()/i;

const EMAIL_RE =
  /\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,24})\b/g;

const SENSITIVE_KEY_RE = new RegExp(
  '(?:^|[_-])(?:full[_-]?name|first[_-]?name|last[_-]?name|' +
  'patient[_-]?name|client[_-]?name|street|home[_-]?address|' +
  'birth[_-]?date|dob|mrn|medical[_-]?record|passport|' +
  'driver[_-]?lic|password|passwd|secret|api[_-]?key|' +
  'private[_-]?key|access[_-]?token|refresh[_-]?token|' +
  'cookie|authorization|session[_-]?id)(?:$|[_-])',
  'i'
);

export function decodeSmartTextBuffer(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new TypeError('Expected Buffer');
  }
  const CTRL_RE = new RegExp(
    '[\\u{E0000}-\\u{E007F}' +
    '\\u202A-\\u202E\\u2066-\\u2069]',
    'gu'
  );
  const clean = (s) => s.normalize('NFC').replace(CTRL_RE, '');

  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    const rest = buf.subarray(2);
    const len2 = rest.length - (rest.length % 2);
    const s = rest.subarray(0, len2).toString('utf16le');
    return clean(s);
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const rest = buf.subarray(2);
    const len2 = rest.length - (rest.length % 2);
    const even = Buffer.from(rest.subarray(0, len2));
    even.swap16();
    return clean(even.toString('utf16le'));
  }
  const slice = (
    buf.length >= 3 &&
    buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf
  ) ? buf.subarray(3) : buf;

  const probeLen = Math.min(slice.length, 4096);
  for (let i = 0; i < probeLen; i++) {
    if (slice[i] === 0x00) {
      throw new Error(
        'ERR_BINARY_FILE: Export document as UTF-8/CSV/MD/TXT'
      );
    }
  }
  return clean(slice.toString('utf8'));
}

export function assertSafeBridgePath(
  targetPath, { mustExist = true } = {}
) {
  if (typeof targetPath !== 'string' || !targetPath.trim() ||
      targetPath.includes('\0')) {
    throw new Error('ERR_INVALID_PATH');
  }
  const abs = path.resolve(targetPath);
  const resolved = mustExist
    ? fs.realpathSync(abs)
    : path.join(
        fs.realpathSync(path.dirname(abs)),
        path.basename(abs)
      );
  const norm = resolved.normalize('NFC');
  if (SYS_ROOT_RE.test(norm)) {
    throw new Error('ERR_BLOCKED_SYSTEM_PATH: ' + norm);
  }
  const parts = norm.split(/[\\/]+/).filter(Boolean);
  for (const seg of parts) {
    const low = seg.toLowerCase();
    if (low.startsWith('.') || low.endsWith('.env') ||
        low === 'id_rsa' || low === 'id_ed25519') {
      throw new Error(
        'ERR_BLOCKED_SENSITIVE_DOTPATH: ' + seg
      );
    }
  }
  return resolved;
}

export function createBridgeSessionVault(epochOverride = '') {
  return {
    sessionEpochId:
      epochOverride || new Date().toISOString().slice(0, 10),
    twinToReal: new Map(),
    realToTwin: new Map(),
    officeDocs: new Map(),
    roleCounters: {},
  };
}

function storePair(vault, syn, orig) {
  if (syn === orig) return;
  if (vault.twinToReal.size >= MAX_VAULT_ENTRIES &&
      !vault.twinToReal.has(syn)) {
    const oldest = vault.twinToReal.keys().next().value;
    const oldOrig = vault.twinToReal.get(oldest);
    vault.twinToReal.delete(oldest);
    vault.realToTwin.delete(oldOrig);
  }
  vault.twinToReal.set(syn, orig);
  vault.realToTwin.set(orig, syn);
}

export function sanitizeStructuredJson(
  val, key32, sessionVault, parentKey = ''
) {
  if (val === null || val === undefined) return val;
  if (typeof val === 'string') {
    if (val.length > 1 && SENSITIVE_KEY_RE.test(parentKey)) {
      if (sessionVault.realToTwin.has(val)) {
        return sessionVault.realToTwin.get(val);
      }
      const tag = crypto.createHmac('sha256', key32)
        .update('KV|' + parentKey.toLowerCase() + '|' + val)
        .digest('hex').slice(0, 10);
      const syn = `SYNTH_${tag.toUpperCase()}`;
      storePair(sessionVault, syn, val);
      return syn;
    }
    return val;
  }
  if (Array.isArray(val)) {
    return val.map((it) =>
      sanitizeStructuredJson(it, key32, sessionVault, parentKey)
    );
  }
  if (typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      if (k === '__proto__' || k === 'constructor' ||
          k === 'prototype') {
        continue;
      }
      out[k] = sanitizeStructuredJson(
        v, key32, sessionVault, k
      );
    }
    return out;
  }
  return val;
}

function _baseReadProtectedDocument({
  filePath,
  key32,
  sessionVault,
  activePacks = SECTOR_PACK_IDS,
  shiftClinicalDates = false,
  watchlist = [],
}) {
  const realPath = assertSafeBridgePath(
    filePath, { mustExist: true }
  );
  const st = fs.statSync(realPath);
  if (!st.isFile()) throw new Error('ERR_NOT_REGULAR_FILE');
  if (st.size > MAX_BRIDGE_BYTES) {
    throw new Error('ERR_FILE_TOO_LARGE_10MB');
  }

  const rawBuf = fs.readFileSync(realPath);
  const inputSha256 = crypto.createHash('sha256')
    .update(rawBuf).digest('hex');
  const vault = sessionVault ||
    createBridgeSessionVault();
  if (!vault.officeDocs) vault.officeDocs = new Map();
  const extLow = path.extname(realPath).toLowerCase();
  const extraCounts = {};
  let formatKind = 'text';
  let plainText;

  if (extLow === '.docx') {
    const dx = extractDocxText(rawBuf);
    plainText = dx.text;
    formatKind = 'docx';
    vault.officeDocs.set(realPath, {
      kind: 'docx', entries: dx.entries,
      xmlNames: dx.xmlNames,
    });
  } else if (extLow === '.xlsx') {
    const xx = extractXlsxText(rawBuf);
    plainText = xx.text;
    formatKind = 'xlsx';
    vault.officeDocs.set(realPath, {
      kind: 'xlsx', entries: xx.entries,
      sheetNames: xx.sheetNames,
    });
  } else if (extLow === '.odt') {
    const od = extractOdtText(rawBuf);
    plainText = od.text;
    formatKind = 'odt';
    vault.officeDocs.set(realPath, {
      kind: 'odt', entries: od.entries,
    });
  } else if (extLow === '.pdf') {
    const pd = extractPdfText(rawBuf);
    plainText = pd.text;
    formatKind = 'pdf';
  } else {
    plainText = decodeSmartTextBuffer(rawBuf);
  }

  if (extLow === '.json') {
    try {
      const parsed = JSON.parse(plainText);
      if (isFhirR4Object(parsed)) {
        formatKind = 'fhir_r4';
        const fr = pseudonymizeFhirR4(
          parsed, key32, vault,
          { subjectScope: path.basename(realPath) }
        );
        plainText = fr.text;
        if (fr.count > 0) extraCounts.FHIR_R4 = fr.count;
      } else {
        const scrubbed = sanitizeStructuredJson(
          parsed, key32, vault
        );
        plainText = JSON.stringify(scrubbed, null, 2);
      }
    } catch (_) {}
  } else if (isHl7V2Text(plainText, extLow)) {
    formatKind = 'hl7_v2';
    const hl = pseudonymizeHl7V2(
      plainText, key32, vault,
      { subjectScope: path.basename(realPath) }
    );
    plainText = hl.text;
    if (hl.count > 0) extraCounts.HL7_PID = hl.count;
  } else {
    const hdr = captureAndReplaceHeaderEntities(
      plainText, vault
    );
    plainText = hdr.text;
    if (hdr.count > 0) {
      extraCounts.HEADER_COREF = hdr.count;
    }
  }

  const twk = Buffer.from(
    'BRIDGE|' + vault.sessionEpochId, 'utf8'
  );
  const secRes = pseudonymizeSectorText(
    plainText, key32, twk, activePacks, {
      shiftDates: shiftClinicalDates,
      subjectScope: path.basename(realPath),
      watchlist,
    }
  );
  for (const [syn, orig] of secRes.pairs) {
    storePair(vault, syn, orig);
  }

  let emailCount = 0;
  const safeText = secRes.text.replace(
    EMAIL_RE,
    (full) => {
      if (vault.realToTwin.has(full)) {
        emailCount++;
        return vault.realToTwin.get(full);
      }
      const tag = crypto.createHmac('sha256', key32)
        .update('EMAIL|' + vault.sessionEpochId + '|' + full)
        .digest('hex').slice(0, 8);
      const syn = `alias-${tag}@example.invalid`;
      storePair(vault, syn, full);
      emailCount++;
      return syn;
    }
  );

  const counts = Object.assign(
    {}, extraCounts, secRes.counts
  );
  if (emailCount > 0) counts.EMAIL = emailCount;
  const totalRedactions = Object.values(counts)
    .reduce((a, b) => a + b, 0);
  const protectionStatus = formatProtectionBanner(counts);

  return {
    sourcePath: realPath,
    format: formatKind,
    sessionEpochId: vault.sessionEpochId,
    inputSha256,
    totalRedactions,
    counts,
    protectionStatus,
    safeText,
  };
}

function sanitizeCsvFormulas(text) {
  let neutralized = 0;
  const lines = text.split(/\r?\n/);
  const outLines = lines.map((ln) => {
    const cells = ln.split(',');
    return cells.map((cell) => {
      const trimmed = cell.replace(/^"/, '');
      if (CSV_FORMULA_RE.test(trimmed)) {
        neutralized++;
        return cell.startsWith('"')
          ? '"\'' + cell.slice(1)
          : '\'' + cell;
      }
      return cell;
    }).join(',');
  });
  return { text: outLines.join('\n'), neutralized };
}

function deriveSafeRestoredPath(sourcePath, outputPath) {
  if (outputPath && outputPath.trim()) {
    const resolved = assertSafeBridgePath(
      outputPath, { mustExist: false }
    );
    const ext = path.extname(resolved).toLowerCase();
    if (BLOCKED_EXTS.has(ext)) {
      throw new Error('ERR_BLOCKED_EXEC_EXTENSION: ' + ext);
    }
    if (fs.existsSync(resolved)) {
      throw new Error(
        'ERR_REFUSE_OVERWRITE_EXISTING: ' + resolved
      );
    }
    return resolved;
  }
  if (!sourcePath) throw new Error('ERR_MISSING_OUTPUT_PATH');
  const srcSafe = assertSafeBridgePath(
    sourcePath, { mustExist: true }
  );
  const dir = path.dirname(srcSafe);
  const rawExt = path.extname(srcSafe) || '.txt';
  const ext = rawExt.toLowerCase() === '.pdf'
    ? '.txt' : rawExt;
  if (BLOCKED_EXTS.has(ext.toLowerCase())) {
    throw new Error('ERR_BLOCKED_EXEC_EXTENSION: ' + ext);
  }
  const stem = path.basename(srcSafe, ext);
  let cand = path.join(dir, `${stem}.restored${ext}`);
  let n = 1;
  while (fs.existsSync(cand)) {
    cand = path.join(dir, `${stem}.restored.${n}${ext}`);
    n++;
  }
  return cand;
}

function _baseSaveRestoredDocument({
  aiDraftText,
  sessionVault,
  sourcePath = '',
  outputPath = '',
}) {
  const validMap = sessionVault &&
    (sessionVault.twinToReal instanceof Map);
  if (!validMap) {
    throw new Error('ERR_MISSING_SESSION_VAULT');
  }
  const dest = deriveSafeRestoredPath(sourcePath, outputPath);
  const keys = Array.from(sessionVault.twinToReal.keys())
    .sort((a, b) => b.length - a.length);

  let restoredText = String(aiDraftText ?? '');
  let restoredCount = 0;
  for (const syn of keys) {
    if (!restoredText.includes(syn)) continue;
    const orig = sessionVault.twinToReal.get(syn);
    const parts = restoredText.split(syn);
    restoredCount += parts.length - 1;
    restoredText = parts.join(orig);
  }

  let neutralizedCsvFormulas = 0;
  const ext = path.extname(dest).toLowerCase();
  if (ext === '.csv' || ext === '.tsv') {
    const cRes = sanitizeCsvFormulas(restoredText);
    restoredText = cRes.text;
    neutralizedCsvFormulas = cRes.neutralized;
  }

  let outBuf = Buffer.from(restoredText, 'utf8');
  const srcKey = sourcePath
    ? (() => {
        try { return fs.realpathSync(sourcePath); }
        catch { return path.resolve(sourcePath); }
      })()
    : '';
  const docMeta = sessionVault.officeDocs?.get(srcKey);
  if (ext === '.docx' && docMeta?.kind === 'docx') {
    outBuf = rebuildDocxBuffer(
      docMeta.entries, docMeta.xmlNames, restoredText
    );
  } else if (ext === '.xlsx' &&
             docMeta?.kind === 'xlsx') {
    const xr = rebuildXlsxBuffer(
      docMeta.entries, docMeta.sheetNames, restoredText
    );
    outBuf = xr.buffer;
    neutralizedCsvFormulas += xr.neutralizedFormulas;
  } else if (ext === '.odt' && docMeta?.kind === 'odt') {
    outBuf = rebuildOdtBuffer(
      docMeta.entries, restoredText
    );
  }
  const outputSha256 = crypto.createHash('sha256')
    .update(outBuf).digest('hex');
  const pid = process.pid;
  const tmp = `${dest}.sip-tmp-${pid}-${Date.now()}`;
  fs.writeFileSync(tmp, outBuf, { mode: 0o600 });
  fs.renameSync(tmp, dest);

  return {
    savedPath: dest,
    sessionEpochId: sessionVault.sessionEpochId,
    restoredCount,
    neutralizedCsvFormulas,
    protectionStatus: formatProtectionBanner(
      {}, restoredCount
    ),
    outputSha256,
  };
}

// === BEGIN V310 TABULAR ENGINE ===
const TAB_PII_COL_RE = new RegExp(
  '(?:^|[_.\\s-])(?:' +
  'name|full_?name|first_?name|last_?name|middle_?name|' +
  'fname|lname|surname|client|customer|patient|employee|' +
  'staff|member|vendor|supplier|beneficiary|payor|payee|' +
  'borrower|lender|guarantor|insured|claimant|witness|' +
  'signatory|attorney|counsel|doctor|physician|provider|' +
  'guardian|spouse|contact|person|owner|holder|cardholder|' +
  'recipient|sender|address|street|addr|line1|line2|apt|' +
  'apartment|suite|city|town|village|passport|' +
  'driver_?licen[cs]e|dl_?num(?:ber)?|mrn|medical_?record|' +
  'chart_?no|policy_?no|tax_?id|tin|account_?no|acct|' +
  'secret|password|passwd|pwd|api_?key|token|private_?key|' +
  'fio|\\u0444\\u0438\\u043e|\\u0438\\u043c\\u044f|' +
  '\\u0444\\u0430\\u043c\\u0438\\u043b\\u0438\\u044f|' +
  '\\u043a\\u043b\\u0438\\u0435\\u043d\\u0442|' +
  '\\u043f\\u0430\\u0446\\u0438\\u0435\\u043d\\u0442|' +
  '\\u0430\\u0434\\u0440\\u0435\\u0441|' +
  '\\u0443\\u043b\\u0438\\u0446\\u0430|' +
  '\\u0433\\u043e\\u0440\\u043e\\u0434|' +
  '\\u043f\\u0430\\u0441\\u043f\\u043e\\u0440\\u0442' +
  ')(?:$|[_.\\s-])',
  'i'
);

const TAB_SAFE_COL_RE = new RegExp(
  '^(?:file_?name|dir_?name|path_?name|table_?name|' +
  'col(?:umn)?_?name|db_?name|database_?name|schema_?name|' +
  'server_?name|host_?name|service_?name|tool_?name|' +
  'app_?name|pkg_?name|package_?name|module_?name|' +
  'class_?name|func_?name|method_?name|event_?name|' +
  'metric_?name|stage_?name|step_?name|job_?name|' +
  'branch_?name|repo_?name|tag_?name|product_?name|' +
  'item_?name|plan_?name|tier_?name|role_?name|group_?name|' +
  'team_?name|dept_?name|category_?name|currency_?name|' +
  'country_?name|state_?name|model_?name|amount|balance|' +
  'total|subtotal|tax_?amount|fee|price|cost|rate|qty|' +
  'quantity|count|score|status|state|type|kind|mode|flag|' +
  'active|enabled|currency|formula)$',
  'i'
);

const TAB_SKIP_VAL_RE = new RegExp(
  '^(?:null|none|nil|n\\/a|na|true|false|-+|' +
  '\\d{4}-\\d{2}-\\d{2}|[+-]?\\d+(?:[.,]\\d+)?)$',
  'i'
);
const TAB_DDE_VAL_RE = new RegExp(
  '^\\s*[=+\\-@](?:cmd\\s*\\||powershell|' +
  '[A-Za-z_]{2,}\\s*\\x28)',
  'i'
);
const TAB_SYNTH_RE = new RegExp(
  '^(?:PER|ADR|IDN|SEC|VAL)-[0-9A-F]{8}$|' +
  '^alias-[0-9a-f]{8}@example\\.invalid$',
  'i'
);

function classifyColumnPrefix(rawHeader) {
  const h = String(rawHeader || '')
    .trim().replace(/^["']|["']$/g, '');
  if (!h || TAB_SAFE_COL_RE.test(h)) return null;
  if (!TAB_PII_COL_RE.test(h)) return null;
  const adrRe = new RegExp(
    'address|street|addr|line1|line2|apt|suite|city|town|' +
    '\\u0430\\u0434\\u0440|\\u0443\\u043b\\u0438\\u0446|' +
    '\\u0433\\u043e\\u0440\\u043e\\u0434',
    'i'
  );
  if (adrRe.test(h)) return 'ADR';
  if (/secret|password|passwd|pwd|api_?key|token|private_?key/i
      .test(h)) {
    return 'SEC';
  }
  const idnRe = new RegExp(
    'passport|licen[cs]e|dl_|mrn|medical|chart|policy|' +
    'tax_?id|tin|account|acct|\\u043f\\u0430\\u0441\\u043f',
    'i'
  );
  if (idnRe.test(h)) return 'IDN';
  return 'PER';
}

function registerVaultTwin(vault, realStr, twinStr) {
  if (!vault || !realStr || !twinStr || realStr === twinStr) {
    return;
  }
  if (vault.realToTwin.get(realStr) === twinStr) return;
  if (vault.twinToReal.size >= 25000 &&
      !vault.twinToReal.has(twinStr)) {
    const oldTw = vault.twinToReal.keys().next().value;
    const oldRl = vault.twinToReal.get(oldTw);
    vault.twinToReal.delete(oldTw);
    vault.realToTwin.delete(oldRl);
  }
  vault.realToTwin.set(realStr, twinStr);
  vault.twinToReal.set(twinStr, realStr);
}

function makeTabularTwin(key32, vault, prefix, restoreStr) {
  const hit = vault?.realToTwin?.get(restoreStr);
  if (hit) return hit;
  const epoch = vault?.epochId || 'v310';
  const digest = crypto
    .createHmac('sha256', key32)
    .update(`${prefix}:${epoch}:${restoreStr}`, 'utf8')
    .digest('hex')
    .slice(0, 8)
    .toUpperCase();
  const twin = `${prefix}-${digest}`;
  registerVaultTwin(vault, restoreStr, twin);
  return twin;
}

function parseDelimitedRows(text, delim) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  let cellWasQuoted = false;
  let flags = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (i + 1 < n && text[i + 1] === '"') {
          cell += '"';
          i += 2;
          continue;
        }
        quoted = false;
        i += 1;
        continue;
      }
      cell += ch;
      i += 1;
      continue;
    }
    if (ch === '"' && cell.length === 0) {
      quoted = true;
      cellWasQuoted = true;
      i += 1;
      continue;
    }
    if (ch === delim) {
      row.push(cell);
      flags.push(cellWasQuoted);
      cell = '';
      cellWasQuoted = false;
      i += 1;
      continue;
    }
    if (ch === '\r' || ch === '\n') {
      const nl = (
        ch === '\r' && i + 1 < n && text[i + 1] === '\n'
      ) ? '\r\n' : ch;
      if (nl.length === 2) i += 1;
      row.push(cell);
      flags.push(cellWasQuoted);
      rows.push({ cells: row, quoted: flags, eol: nl });
      row = [];
      flags = [];
      cell = '';
      cellWasQuoted = false;
      i += 1;
      continue;
    }
    cell += ch;
    i += 1;
  }
  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    flags.push(cellWasQuoted);
    rows.push({ cells: row, quoted: flags, eol: '' });
  }
  return rows;
}

function encodeCsvCell(val, wasQuoted, delim) {
  const needsQuote = wasQuoted ||
    val.includes(delim) ||
    val.includes('"') ||
    val.includes('\n') ||
    val.includes('\r');
  if (!needsQuote) return val;
  return '"' + val.replace(/"/g, '""') + '"';
}

export function sanitizeTabularDocument(
  text, key32, vault, ext = '.csv'
) {
  if (!text || typeof text !== 'string') {
    return { text: text || '', count: 0 };
  }
  const firstNl = text.indexOf('\n');
  const firstLine = firstNl === -1
    ? text : text.slice(0, firstNl);
  let delim = ',';
  if (ext === '.tsv') {
    delim = '\t';
  } else {
    const cComma = (firstLine.match(/,/g) || []).length;
    const cSemi = (firstLine.match(/;/g) || []).length;
    const cTab = (firstLine.match(/\t/g) || []).length;
    if (cTab > cComma && cTab >= cSemi) delim = '\t';
    else if (cSemi > cComma) delim = ';';
  }

  const parsed = parseDelimitedRows(text, delim);
  if (parsed.length < 2) return { text, count: 0 };

  const colPrefixes = parsed[0].cells.map(classifyColumnPrefix);
  if (!colPrefixes.some(Boolean)) return { text, count: 0 };

  let count = 0;
  for (let r = 1; r < parsed.length; r++) {
    const rObj = parsed[r];
    if (rObj.cells.length === 1 && rObj.cells[0] === '') {
      continue;
    }
    for (let c = 0; c < rObj.cells.length; c++) {
      const pref = colPrefixes[c];
      if (!pref) continue;
      const rawCell = rObj.cells[c];
      const trimmed = rawCell.trim();
      if (!trimmed) continue;
      if (TAB_SKIP_VAL_RE.test(trimmed)) continue;
      if (TAB_DDE_VAL_RE.test(trimmed)) continue;
      if (TAB_SYNTH_RE.test(trimmed)) continue;
      if (vault?.twinToReal?.has(trimmed)) continue;

      const restoreRaw = encodeCsvCell(
        rawCell, rObj.quoted[c], delim
      );
      const twin = makeTabularTwin(
        key32, vault, pref, restoreRaw
      );
      rObj.cells[c] = twin;
      rObj.quoted[c] = false;
      count++;
    }
  }

  if (count === 0) return { text, count: 0 };
  let out = '';
  for (const rObj of parsed) {
    const enc = (v, ix) => encodeCsvCell(
      v, rObj.quoted[ix], delim
    );
    const lineStr = rObj.cells.map(enc).join(delim);
    out += lineStr + rObj.eol;
  }
  return { text: out, count };
}

export function sanitizeMarkdownPipeTables(text, key32, vault) {
  if (!text || !text.includes('|')) return { text, count: 0 };
  const lines = text.split('\n');
  let count = 0;
  let activeCols = null;

  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const t = ln.trim();
    if (!t.startsWith('|') || !t.endsWith('|')) {
      activeCols = null;
      continue;
    }
    const parts = ln.split('|');
    const inner = parts.slice(1, -1);
    const isSep = inner.every(
      (c) => /^\s*:?-{2,}:?\s*$/.test(c)
    );
    if (isSep) continue;

    if (!activeCols) {
      const nextLn = (lines[i + 1] || '').trim();
      if (nextLn.startsWith('|') && /^[\s|:-]+$/.test(nextLn)) {
        const prefs = inner.map(classifyColumnPrefix);
        activeCols = prefs.some(Boolean) ? prefs : null;
      }
      continue;
    }

    let rowChanged = false;
    for (let c = 0; c < inner.length; c++) {
      const pref = activeCols[c];
      if (!pref) continue;
      const cellVal = inner[c].trim();
      if (!cellVal || TAB_SKIP_VAL_RE.test(cellVal)) continue;
      if (TAB_DDE_VAL_RE.test(cellVal)) continue;
      if (TAB_SYNTH_RE.test(cellVal)) continue;
      if (vault?.twinToReal?.has(cellVal)) continue;

      const twin = makeTabularTwin(
        key32, vault, pref, cellVal
      );
      inner[c] = ` ${twin} `;
      rowChanged = true;
      count++;
    }
    if (rowChanged) {
      const tail = parts[parts.length - 1];
      lines[i] = parts[0] + '|' + inner.join('|') + '|' + tail;
    }
  }
  return { text: count > 0 ? lines.join('\n') : text, count };
}


function safeBridgeRealpath(target) {
  const abs = path.resolve(String(target || ''));
  try { return fs.realpathSync(abs); } catch {}
  const tail = [];
  let cur = abs;
  while (true) {
    const par = path.dirname(cur);
    if (par === cur) return abs;
    tail.unshift(path.basename(cur));
    cur = par;
    try {
      return path.join(
        fs.realpathSync(cur), ...tail
      );
    } catch {}
  }
}

function collectConfiguredAllowedDirs() {
  const dirs = [];
  const raw = String(process.env.SIP_ALLOWED_DIRS || '').trim();
  if (raw && !raw.startsWith('${user_config.')) {
    const sep = raw.includes(path.delimiter)
      ? path.delimiter : ',';
    for (const part of raw.split(sep)) {
      if (part.trim()) dirs.push(path.resolve(part.trim()));
    }
  }
  const av = process.argv || [];
  for (let i = 0; i < av.length; i++) {
    if (av[i] === '--allow-dir' && av[i + 1]) {
      const nxt = String(av[i + 1]).trim();
      if (nxt && !nxt.startsWith('${user_config.')) {
        dirs.push(path.resolve(nxt));
      }
    }
  }
  return dirs;
}

export function assertAllowedWorkspaceDir(targetPath) {
  const roots = collectConfiguredAllowedDirs()
    .map((r) => safeBridgeRealpath(r));
  if (roots.length === 0) return;
  const resP = safeBridgeRealpath(targetPath);
  const ok = roots.some(
    (r) => resP === r || resP.startsWith(r + path.sep)
  );
  if (!ok) {
    throw new Error(
      `ERR_OUTSIDE_ALLOWED_DIRS: Forbidden path (${resP})`
    );
  }
}

export function readProtectedDocument(opts = {}) {
  if (opts?.filePath) {
    assertAllowedWorkspaceDir(opts.filePath);
  }
  const base = _baseReadProtectedDocument(opts);
  const fp = String(opts?.filePath || '');
  const ext = path.extname(fp).toLowerCase();
  const k32 = opts?.key32;
  const vlt = opts?.sessionVault;
  if (!k32 || !vlt || !base?.safeText) return base;

  let extra = 0;
  let txt = base.safeText;
  if (ext === '.csv' || ext === '.tsv') {
    const rTab = sanitizeTabularDocument(txt, k32, vlt, ext);
    txt = rTab.text;
    extra += rTab.count;
  } else if (ext === '.jsonl' || ext === '.ndjson') {
    const outLines = txt.split('\n').map((ln) => {
      const tr = ln.trim();
      if (!tr) return ln;
      try {
        const obj = JSON.parse(tr);
        const cleanObj = sanitizeStructuredJson(obj, k32, vlt);
        extra++;
        return JSON.stringify(cleanObj);
      } catch (_) {
        return ln;
      }
    });
    txt = outLines.join('\n');
  } else if (txt.includes('|')) {
    const rMd = sanitizeMarkdownPipeTables(txt, k32, vlt);
    txt = rMd.text;
    extra += rMd.count;
  }

  if (extra > 0) {
    base.safeText = txt;
    base.totalRedactions =
      (base.totalRedactions || 0) + extra;
    if (base.counts) base.counts.TABULAR_PII = extra;
    base.protectionStatus =
      formatProtectionBanner(base.counts || {});
    if (base.redactionBreakdown) {
      base.redactionBreakdown.tabular_pii = extra;
    }
  }
  return base;
}
const FAST_REST_TOK_RE =
  /[0-9A-Za-z][0-9A-Za-z.@-]{2,}[0-9A-Za-z]/g;
const EXACT_FAST_TOK_RE =
  /^[0-9A-Za-z][0-9A-Za-z.@-]{2,}[0-9A-Za-z]$/;


const PURE_SIGNED_DEC_RE =
  /^\s*[+-]?(?:\d+(?:[.,]\d+)?|\.\d+)\s*$/;
const OWASP_DDE_START_RE = /^[\t\r ]*[=+\-@]/;

function normalizeOwaspCsvSavedFile(savedPath) {
  const sStr = String(savedPath || '');
  const ext = path.extname(sStr).toLowerCase();
  if (ext !== '.csv' && ext !== '.tsv') return;
  const raw = fs.readFileSync(savedPath, 'utf8');
  const firstNl = raw.indexOf('\n');
  const firstLn = firstNl === -1 ? raw : raw.slice(0, firstNl);
  let delim = ext === '.tsv' ? '\t' : ',';
  if (ext !== '.tsv') {
    const cC = (firstLn.match(/,/g) || []).length;
    const cS = (firstLn.match(/;/g) || []).length;
    if (cS > cC) delim = ';';
  }
  const parsed = parseDelimitedRows(raw, delim);
  let changed = false;
  for (let r = 0; r < parsed.length; r++) {
    const rObj = parsed[r];
    for (let c = 0; c < rObj.cells.length; c++) {
      const v = rObj.cells[c];
      if (!v) continue;
      const vTail = v.slice(1);
      if (v.startsWith("'") && PURE_SIGNED_DEC_RE.test(vTail)) {
        rObj.cells[c] = vTail;
        changed = true;
      } else if (
        !v.startsWith("'") &&
        !PURE_SIGNED_DEC_RE.test(v) &&
        OWASP_DDE_START_RE.test(v)
      ) {
        rObj.cells[c] = "'" + v;
        changed = true;
      }
    }
  }
  if (!changed) return;
  let out = '';
  for (const rObj of parsed) {
    const enc = (val, ix) => encodeCsvCell(
      val, rObj.quoted[ix], delim
    );
    out += rObj.cells.map(enc).join(delim) + rObj.eol;
  }
  const dir = path.dirname(savedPath);
  const tmp = path.join(
    dir, `.sip-tmp-${process.pid}-${Date.now()}`
  );
  fs.writeFileSync(tmp, out, 'utf8');
  fs.renameSync(tmp, savedPath);
}

export function saveRestoredDocument(opts = {}) {
  if (opts?.outputPath) {
    assertAllowedWorkspaceDir(opts.outputPath);
  }
  if (opts?.sourcePath) {
    assertAllowedWorkspaceDir(opts.sourcePath);
  }
  const vlt = opts?.sessionVault;
  const draft = String(opts?.aiDraftText ?? '');
  if (!vlt?.twinToReal || vlt.twinToReal.size === 0 || !draft) {
    return _baseSaveRestoredDocument(opts);
  }
  const fastMap = new Map();
  const slowMap = new Map();
  for (const [tw, rl] of vlt.twinToReal.entries()) {
    if (EXACT_FAST_TOK_RE.test(tw)) {
      fastMap.set(tw, rl);
    } else {
      slowMap.set(tw, rl);
    }
  }
  let fastHits = 0;
  const preRestored = fastMap.size > 0
    ? draft.replace(FAST_REST_TOK_RE, (m) => {
        const hit = fastMap.get(m);
        if (hit !== undefined) {
          fastHits++;
          return hit;
        }
        return m;
      })
    : draft;

  const res = _baseSaveRestoredDocument({
    ...opts,
    aiDraftText: preRestored,
    sessionVault: vlt,
  });
  if (res && typeof res === 'object') {
    res.restoredCount =
      (res.restoredCount || 0) + fastHits;
    res.protectionStatus = formatProtectionBanner(
      {}, res.restoredCount
    );
  }
  if (res?.savedPath) {
    normalizeOwaspCsvSavedFile(res.savedPath);
  }
  return res;
}
// === END V310 TABULAR ENGINE ===

