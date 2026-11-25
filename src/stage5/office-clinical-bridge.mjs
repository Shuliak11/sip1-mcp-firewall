/**
 * @license Apache-2.0
 * SHULIAK SIP v3.1 - Zero-Dep Office & Clinical Bridge
 * Pure node:zlib + node:crypto. 0 network imports.
 */

import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { Buffer } from 'node:buffer';
import {
  maskHipaaSafeZip,
  shiftIsoDateString,
  transformUsSsn,
} from '../stage4/sector-packs.mjs';

export const MAX_ZIP_OUTPUT_BYTES = 25 * 1024 * 1024;
export const MAX_ZIP_FILES = 256;

const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32_TABLE[i] = c >>> 0;
}

export function crc32(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) {
    c = CRC32_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

export function parseZipArchive(rawBuf, opts = {}) {
  const buf = Buffer.isBuffer(rawBuf)
    ? rawBuf : Buffer.from(rawBuf);
  const maxOut = opts.maxOutputLength ??
    MAX_ZIP_OUTPUT_BYTES;
  const maxFiles = opts.maxFiles ?? MAX_ZIP_FILES;
  if (buf.length < 22) {
    throw new Error('ERR_INVALID_ZIP_TRUNCATED');
  }

  let eocd = -1;
  const minPos = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= minPos; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      const cLen = buf.readUInt16LE(i + 20);
      if (i + 22 + cLen <= buf.length) {
        eocd = i;
        break;
      }
    }
  }
  if (eocd < 0) throw new Error('ERR_INVALID_ZIP_EOCD');

  const count = buf.readUInt16LE(eocd + 10);
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (count > maxFiles) {
    throw new Error(
      `ERR_ZIP_BOMB_TOO_MANY_FILES: ${count} > ${maxFiles}`
    );
  }

  const entries = [];
  let pos = cdOff;
  let totalBytes = 0;

  for (let idx = 0; idx < count; idx++) {
    if (pos + 46 > buf.length ||
        buf.readUInt32LE(pos) !== 0x02014b50) {
      throw new Error('ERR_INVALID_ZIP_CD');
    }
    const method = buf.readUInt16LE(pos + 10);
    const expCrc = buf.readUInt32LE(pos + 16);
    const cSz = buf.readUInt32LE(pos + 20);
    const uSz = buf.readUInt32LE(pos + 24);
    const nLen = buf.readUInt16LE(pos + 28);
    const exLen = buf.readUInt16LE(pos + 30);
    const cmLen = buf.readUInt16LE(pos + 32);
    const lhOff = buf.readUInt32LE(pos + 42);
    const name = buf
      .subarray(pos + 46, pos + 46 + nLen).toString('utf8');
    pos += 46 + nLen + exLen + cmLen;

    const norm = name.replace(/\\/g, '/');
    if (norm.startsWith('/') ||
        norm.split('/').includes('..')) {
      throw new Error('ERR_ZIP_PATH_TRAVERSAL: ' + name);
    }
    if (uSz > maxOut || totalBytes + uSz > maxOut) {
      throw new Error('ERR_ZIP_BOMB_LIMIT_EXCEEDED');
    }
    if (lhOff + 30 > buf.length ||
        buf.readUInt32LE(lhOff) !== 0x04034b50) {
      throw new Error('ERR_INVALID_ZIP_LOCAL_HDR');
    }
    const lhN = buf.readUInt16LE(lhOff + 26);
    const lhEx = buf.readUInt16LE(lhOff + 28);
    const dStart = lhOff + 30 + lhN + lhEx;
    if (dStart + cSz > buf.length) {
      throw new Error('ERR_INVALID_ZIP_BOUNDS');
    }
    const comp = buf.subarray(dStart, dStart + cSz);
    let data;
    if (method === 0) {
      data = Buffer.from(comp);
    } else if (method === 8) {
      try {
        data = zlib.inflateRawSync(comp, {
          maxOutputLength: Math.max(1, maxOut - totalBytes),
        });
      } catch (e) {
        const msg = String(e?.message || '');
        if (e?.code === 'ERR_BUFFER_TOO_LARGE' ||
            /maxOutputLength|too large/i.test(msg)) {
          throw new Error('ERR_ZIP_BOMB_LIMIT_EXCEEDED');
        }
        throw e;
      }
    } else {
      throw new Error('ERR_UNSUPPORTED_ZIP_METHOD: ' +
        method);
    }
    if (totalBytes + data.length > maxOut) {
      throw new Error('ERR_ZIP_BOMB_LIMIT_EXCEEDED');
    }
    if ((data.length > 0 || expCrc !== 0) &&
        crc32(data) !== expCrc) {
      throw new Error('ERR_ZIP_CRC_MISMATCH: ' + name);
    }
    totalBytes += data.length;
    entries.push({ name, data, method });
  }
  return entries;
}

export function buildZipArchive(entries) {
  const localParts = [];
  const cdParts = [];
  let offset = 0;

  for (const ent of entries) {
    const nameBuf = Buffer.from(String(ent.name), 'utf8');
    const raw = Buffer.isBuffer(ent.data)
      ? ent.data : Buffer.from(String(ent.data), 'utf8');
    const crc = crc32(raw);
    const doDeflate = ent.compress !== false &&
      ent.method !== 0 && raw.length > 0;
    const body = doDeflate
      ? zlib.deflateRawSync(raw) : raw;
    const method = doDeflate ? 8 : 0;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);

    localParts.push(lh, nameBuf, body);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0x0800, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(body.length, 20);
    cd.writeUInt32LE(raw.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42);

    cdParts.push(cd, nameBuf);
    offset += lh.length + nameBuf.length + body.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

export function xmlUnescape(str) {
  return String(str || '').replace(
    /&(#x[0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g,
    (_, ent) => {
      if (ent === 'amp') return '&';
      if (ent === 'lt') return '<';
      if (ent === 'gt') return '>';
      if (ent === 'quot') return '"';
      if (ent === 'apos') return "'";
      if (ent.startsWith('#x')) {
        return String.fromCodePoint(
          parseInt(ent.slice(2), 16)
        );
      }
      return String.fromCodePoint(parseInt(ent.slice(1), 10));
    }
  );
}

export function xmlEscape(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

const WT_RE = /<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/g;
const WP_RE = /<w:p(?:\s[^>]*)?>([\s\S]*?)<\/w:p>/g;

export function extractDocxText(rawBuf) {
  const entries = parseZipArchive(rawBuf);
  const xmlNames = entries
    .map((e) => e.name)
    .filter((n) => /^word\/(?:document|header\d*|footer\d*)\.xml$/i
      .test(n));
  if (!xmlNames.includes('word/document.xml')) {
    throw new Error('ERR_INVALID_DOCX_NO_DOCUMENT_XML');
  }
  const paragraphs = [];
  for (const name of xmlNames) {
    const ent = entries.find((e) => e.name === name);
    const xml = ent.data.toString('utf8');
    let m;
    WP_RE.lastIndex = 0;
    while ((m = WP_RE.exec(xml)) !== null) {
      const inner = m[1];
      let joined = '';
      let tm;
      WT_RE.lastIndex = 0;
      while ((tm = WT_RE.exec(inner)) !== null) {
        joined += xmlUnescape(tm[1]);
      }
      if (joined.length > 0) paragraphs.push(joined);
    }
  }
  return {
    entries,
    xmlNames,
    paragraphs,
    text: paragraphs.join('\n'),
  };
}

export function rebuildDocxBuffer(
  origEntries, xmlNames, restoredText
) {
  const lines = String(restoredText ?? '').split(/\r?\n/);
  let cursor = 0;
  const outEntries = origEntries.map((ent) => {
    if (!xmlNames.includes(ent.name)) return ent;
    const xml = ent.data.toString('utf8');
    let nextXml = xml.replace(WP_RE, (full, inner) => {
      let hasText = false;
      let tm;
      WT_RE.lastIndex = 0;
      while ((tm = WT_RE.exec(inner)) !== null) {
        if (tm[1].length > 0) hasText = true;
      }
      if (!hasText) return full;
      const replacement = cursor < lines.length
        ? lines[cursor++] : '';
      let firstDone = false;
      const patched = full.replace(WT_RE, () => {
        if (!firstDone) {
          firstDone = true;
          return '<w:t xml:space="preserve">' +
            xmlEscape(replacement) + '</w:t>';
        }
        return '<w:t></w:t>';
      });
      return patched;
    });
    if (ent.name === 'word/document.xml' &&
        cursor < lines.length) {
      const extra = lines.slice(cursor)
        .filter((l) => l.length > 0)
        .map((l) =>
          '<w:p><w:r><w:t xml:space="preserve">' +
          xmlEscape(l) + '</w:t></w:r></w:p>'
        ).join('');
      if (extra) {
        if (nextXml.includes('<w:sectPr')) {
          nextXml = nextXml.replace(
            '<w:sectPr', extra + '<w:sectPr'
          );
        } else if (nextXml.includes('</w:body>')) {
          nextXml = nextXml.replace(
            '</w:body>', extra + '</w:body>'
          );
        }
      }
    }
    return {
      ...ent,
      data: Buffer.from(nextXml, 'utf8'),
    };
  });
  return buildZipArchive(outEntries);
}

const XLSX_DDE_TEXT_RE = /^[\t\r ]*[=+\-@]/;
const PURE_NUM_RE = /^\s*[+-]?(?:\d+(?:[.,]\d+)?|\.\d+)\s*$/;
const XLSX_BAD_FORMULA_RE = new RegExp(
  '(?:cmd\\s*\\||powershell|WEBSERVICE|HYPERLINK|' +
  'IMPORTXML|REGISTER\\.ID|EXEC\\s*\\()', 'i'
);

function neutralizeExcelCellText(val) {
  const s = String(val ?? '');
  if (!s || s.startsWith("'") || PURE_NUM_RE.test(s)) {
    return { text: s, neutralized: false };
  }
  if (XLSX_DDE_TEXT_RE.test(s)) {
    return { text: "'" + s, neutralized: true };
  }
  return { text: s, neutralized: false };
}

const SI_RE = /<si(?:\s[^>]*)?>([\s\S]*?)<\/si>/g;
const IS_RE = /<is(?:\s[^>]*)?>([\s\S]*?)<\/is>/g;
const T_TAG_RE = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g;
const F_TAG_RE = /<f(?:\s[^>]*)?>([\s\S]*?)<\/f>/g;

export function extractXlsxText(rawBuf) {
  const entries = parseZipArchive(rawBuf);
  const lines = [];
  let ssCount = 0;
  const ssEnt = entries.find(
    (e) => e.name === 'xl/sharedStrings.xml'
  );
  if (ssEnt) {
    const xml = ssEnt.data.toString('utf8');
    let m;
    SI_RE.lastIndex = 0;
    while ((m = SI_RE.exec(xml)) !== null) {
      let acc = '';
      let tm;
      T_TAG_RE.lastIndex = 0;
      while ((tm = T_TAG_RE.exec(m[1])) !== null) {
        acc += xmlUnescape(tm[1]);
      }
      lines.push(acc);
      ssCount++;
    }
  }
  const sheetNames = entries
    .map((e) => e.name)
    .filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/i
      .test(n))
    .sort();
  let inlineCount = 0;
  for (const sName of sheetNames) {
    const ent = entries.find((e) => e.name === sName);
    const xml = ent.data.toString('utf8');
    let m;
    IS_RE.lastIndex = 0;
    while ((m = IS_RE.exec(xml)) !== null) {
      let acc = '';
      let tm;
      T_TAG_RE.lastIndex = 0;
      while ((tm = T_TAG_RE.exec(m[1])) !== null) {
        acc += xmlUnescape(tm[1]);
      }
      lines.push(acc);
      inlineCount++;
    }
  }
  if (!ssEnt && sheetNames.length === 0) {
    throw new Error('ERR_INVALID_XLSX_ARCHIVE');
  }
  return {
    entries,
    sheetNames,
    ssCount,
    inlineCount,
    text: lines.join('\n'),
  };
}

export function rebuildXlsxBuffer(
  origEntries, sheetNames, restoredText
) {
  const lines = String(restoredText ?? '').split(/\r?\n/);
  let cursor = 0;
  let neutralized = 0;

  const replaceBlockT = (block, nextVal) => {
    const chk = neutralizeExcelCellText(nextVal);
    if (chk.neutralized) neutralized++;
    let first = false;
    return block.replace(T_TAG_RE, () => {
      if (!first) {
        first = true;
        return '<t xml:space="preserve">' +
          xmlEscape(chk.text) + '</t>';
      }
      return '<t></t>';
    });
  };

  const outEntries = origEntries.map((ent) => {
    if (ent.name === 'xl/sharedStrings.xml') {
      const xml = ent.data.toString('utf8');
      const nextXml = xml.replace(SI_RE, (full) => {
        if (cursor >= lines.length) return full;
        return replaceBlockT(full, lines[cursor++]);
      });
      return { ...ent, data: Buffer.from(nextXml, 'utf8') };
    }
    if (sheetNames.includes(ent.name)) {
      let xml = ent.data.toString('utf8');
      xml = xml.replace(IS_RE, (full) => {
        if (cursor >= lines.length) return full;
        return replaceBlockT(full, lines[cursor++]);
      });
      xml = xml.replace(F_TAG_RE, (full, body) => {
        if (XLSX_BAD_FORMULA_RE.test(xmlUnescape(body))) {
          neutralized++;
          return '<f>"BLOCKED_DDE_FORMULA"</f>';
        }
        return full;
      });
      return { ...ent, data: Buffer.from(xml, 'utf8') };
    }
    return ent;
  });

  return {
    buffer: buildZipArchive(outEntries),
    neutralizedFormulas: neutralized,
  };
}

const ODT_BLK_RE =
  /<(text:[ph])(\s[^>]*)?>([\s\S]*?)<\/\1>/g;

export function extractOdtText(rawBuf) {
  const entries = parseZipArchive(rawBuf);
  const cEnt = entries.find((e) => e.name === 'content.xml');
  if (!cEnt) throw new Error('ERR_INVALID_ODT_NO_CONTENT');
  const xml = cEnt.data.toString('utf8');
  const paragraphs = [];
  let m;
  ODT_BLK_RE.lastIndex = 0;
  while ((m = ODT_BLK_RE.exec(xml)) !== null) {
    const plain = xmlUnescape(
      m[3].replace(/<[^>]+>/g, '')
    );
    if (plain.length > 0) paragraphs.push(plain);
  }
  return { entries, paragraphs, text: paragraphs.join('\n') };
}

export function rebuildOdtBuffer(origEntries, restoredText) {
  const lines = String(restoredText ?? '').split(/\r?\n/);
  let cursor = 0;
  const sorted = [...origEntries].sort((a, b) =>
    a.name === 'mimetype' ? -1 : b.name === 'mimetype' ? 1 : 0
  );
  const outEntries = sorted.map((ent) => {
    if (ent.name === 'mimetype') {
      return { ...ent, compress: false, method: 0 };
    }
    if (ent.name !== 'content.xml') return ent;
    const xml = ent.data.toString('utf8');
    const nextXml = xml.replace(
      ODT_BLK_RE,
      (full, tag, attrs, inner) => {
        const plain = xmlUnescape(
          inner.replace(/<[^>]+>/g, '')
        );
        if (!plain.length) return full;
        const rep = cursor < lines.length
          ? lines[cursor++] : '';
        return `<${tag}${attrs || ''}>` +
          xmlEscape(rep) + `</${tag}>`;
      }
    );
    return { ...ent, data: Buffer.from(nextXml, 'utf8') };
  });
  return buildZipArchive(outEntries);
}

function unescapePdfLit(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== '\\' || i + 1 >= s.length) {
      out += c;
      continue;
    }
    const nxt = s[++i];
    if (nxt === 'n') out += '\n';
    else if (nxt === 'r') out += '\r';
    else if (nxt === 't') out += '\t';
    else if (nxt === 'b') out += '\b';
    else if (nxt === 'f') out += '\f';
    else if (nxt === '(' || nxt === ')' || nxt === '\\') {
      out += nxt;
    } else if (/[0-7]/.test(nxt)) {
      let oct = nxt;
      for (let k = 0; k < 2 && /[0-7]/.test(s[i + 1] || '');
           k++) {
        oct += s[++i];
      }
      out += String.fromCharCode(parseInt(oct, 8));
    } else {
      out += nxt;
    }
  }
  return out;
}

function decodePdfHex(hexStr) {
  let clean = hexStr.replace(/\s+/g, '');
  if (clean.length % 2 === 1) clean += '0';
  const buf = Buffer.from(clean, 'hex');
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const b2 = Buffer.from(buf.subarray(2));
    if (b2.length % 2 === 1) return '';
    b2.swap16();
    return b2.toString('utf16le');
  }
  return buf.toString('latin1');
}

function extractPdfOpsText(streamStr) {
  const chunks = [];
  const n = streamStr.length;
  let i = 0;
  const readLit = () => {
    let depth = 1;
    let body = '';
    i++;
    while (i < n && depth > 0) {
      const ch = streamStr[i++];
      if (ch === '\\' && i < n) {
        body += ch + streamStr[i++];
        continue;
      }
      if (ch === '(') { depth++; body += ch; }
      else if (ch === ')') {
        depth--;
        if (depth > 0) body += ch;
      } else {
        body += ch;
      }
    }
    return unescapePdfLit(body);
  };

  while (i < n) {
    if (streamStr[i] === '(') {
      const lit = readLit();
      let j = i;
      while (j < n && /\s/.test(streamStr[j])) j++;
      if (streamStr.slice(j, j + 2) === 'Tj' ||
          streamStr[j] === "'") {
        chunks.push(lit);
        i = j + 2;
      }
      continue;
    }
    if (streamStr[i] === '[') {
      const save = i++;
      let arrTxt = '';
      while (i < n && streamStr[i] !== ']') {
        if (streamStr[i] === '(') {
          arrTxt += readLit();
        } else if (streamStr[i] === '<' &&
                   streamStr[i + 1] !== '<') {
          const endH = streamStr.indexOf('>', i + 1);
          if (endH < 0) break;
          arrTxt += decodePdfHex(
            streamStr.slice(i + 1, endH)
          );
          i = endH + 1;
        } else {
          i++;
        }
      }
      if (i < n && streamStr[i] === ']') {
        let j = i + 1;
        while (j < n && /\s/.test(streamStr[j])) j++;
        if (streamStr.slice(j, j + 2) === 'TJ') {
          if (arrTxt) chunks.push(arrTxt);
          i = j + 2;
          continue;
        }
      }
      i = save + 1;
      continue;
    }
    i++;
  }
  return chunks.join('\n');
}

export function extractPdfText(rawBuf, opts = {}) {
  const buf = Buffer.isBuffer(rawBuf)
    ? rawBuf : Buffer.from(rawBuf);
  const maxOut = opts.maxOutputLength ??
    MAX_ZIP_OUTPUT_BYTES;
  const latin = buf.toString('latin1');
  if (!latin.startsWith('%PDF-')) {
    throw new Error('ERR_INVALID_PDF_HEADER');
  }
  const parts = [];
  let cursor = 0;
  let totalOut = 0;

  while (cursor < buf.length) {
    const sIdx = latin.indexOf('stream', cursor);
    if (sIdx < 0) break;
    let dStart = sIdx + 6;
    if (buf[dStart] === 0x0d && buf[dStart + 1] === 0x0a) {
      dStart += 2;
    } else if (buf[dStart] === 0x0a || buf[dStart] === 0x0d) {
      dStart += 1;
    } else {
      cursor = dStart;
      continue;
    }
    const eIdx = latin.indexOf('endstream', dStart);
    if (eIdx < 0) break;
    let dEnd = eIdx;
    while (dEnd > dStart &&
           (buf[dEnd - 1] === 0x0a ||
            buf[dEnd - 1] === 0x0d)) {
      dEnd--;
    }
    const hdrWin = latin.slice(Math.max(0, sIdx - 512), sIdx);
    const isFlate = /\/FlateDecode\b/.test(hdrWin);
    const slice = buf.subarray(dStart, dEnd);
    let plainBuf = slice;
    if (isFlate) {
      try {
        plainBuf = zlib.inflateSync(slice, {
          maxOutputLength: Math.max(1, maxOut - totalOut),
        });
      } catch (e) {
        if (e?.code === 'ERR_BUFFER_TOO_LARGE') {
          throw new Error('ERR_ZIP_BOMB_LIMIT_EXCEEDED');
        }
        try {
          plainBuf = zlib.inflateRawSync(slice, {
            maxOutputLength: Math.max(1, maxOut - totalOut),
          });
        } catch {
          plainBuf = Buffer.alloc(0);
        }
      }
    }
    totalOut += plainBuf.length;
    if (totalOut > maxOut) {
      throw new Error('ERR_ZIP_BOMB_LIMIT_EXCEEDED');
    }
    if (plainBuf.length > 0) {
      const txt = extractPdfOpsText(
        plainBuf.toString('latin1')
      );
      if (txt.trim()) parts.push(txt);
    }
    cursor = eIdx + 9;
  }
  return { text: parts.join('\n') };
}

function storeVault(vault, syn, orig) {
  if (!vault || !syn || !orig || syn === orig) return;
  vault.twinToReal.set(syn, orig);
  vault.realToTwin.set(orig, syn);
}

function makeHmacTwin(key32, vault, prefix, orig) {
  const hit = vault?.realToTwin?.get(orig);
  if (hit) return hit;
  const ep = vault?.sessionEpochId || 'v311';
  const hex = crypto.createHmac('sha256', key32)
    .update(`${prefix}|${ep}|${orig}`, 'utf8')
    .digest('hex').slice(0, 8).toUpperCase();
  const syn = `${prefix}-${hex}`;
  storeVault(vault, syn, orig);
  return syn;
}

function allocNamedAlias(vault, baseRole, orig) {
  const clean = String(orig || '').trim();
  if (!clean) return clean;
  const hit = vault?.realToTwin?.get(clean);
  if (hit) return hit;
  if (!vault.roleCounters) vault.roleCounters = {};
  if (baseRole === 'PARTY_A' || baseRole === 'PARTY_B') {
    const used = vault.twinToReal.has(baseRole);
    const alias = used
      ? `${baseRole}_${++vault.roleCounters[baseRole]}`
      : (vault.roleCounters[baseRole] = 1, baseRole);
    storeVault(vault, alias, clean);
    return alias;
  }
  const n = (vault.roleCounters[baseRole] || 0) + 1;
  vault.roleCounters[baseRole] = n;
  const alias = `${baseRole}_${String(n).padStart(2, '0')}`;
  storeVault(vault, alias, clean);
  return alias;
}

const HEADER_RULES = [
  {
    role: 'PATIENT',
    re: new RegExp(
      '(?:^|[\\r\\n])([ \\t]*(?:' +
      '\\u041f\\u0430\\u0446\\u0438\\u0435\\u043d\\u0442|' +
      '\\u0424\\u0418\\u041e|' +
      '\\u0424\\.\\u0418\\.\\u041e\\.|' +
      'Patient\\s+Name|Patient' +
      ')\\s*:\\s*)([^\\r\\n|;,{\\[]{2,80})',
      'gi'
    ),
  },
  {
    role: 'DOCTOR',
    re: new RegExp(
      '(?:^|[\\r\\n])([ \\t]*(?:' +
      '\\u0412\\u0440\\u0430\\u0447|' +
      '\\u041b\\u0435\\u0447\\u0430\\u0449\\u0438\\u0439' +
      '\\s+\\u0432\\u0440\\u0430\\u0447|' +
      'Doctor|Physician|Attending' +
      ')\\s*:\\s*)([^\\r\\n|;,{\\[]{2,80})',
      'gi'
    ),
  },
  {
    role: 'PARTY_A',
    re: new RegExp(
      '(?:^|[\\r\\n])([ \\t]*(?:' +
      'Party\\s+A|' +
      '\\u0417\\u0430\\u043a\\u0430\\u0437\\u0447\\u0438' +
      '\\u043a|Seller' +
      ')\\s*:\\s*)([^\\r\\n|;,{\\[]{2,80})',
      'gi'
    ),
  },
  {
    role: 'PARTY_B',
    re: new RegExp(
      '(?:^|[\\r\\n])([ \\t]*(?:' +
      'Party\\s+B|' +
      '\\u0418\\u0441\\u043f\\u043e\\u043b\\u043d\\u0438' +
      '\\u0442\\u0435\\u043b\\u044c|Buyer' +
      ')\\s*:\\s*)([^\\r\\n|;,{\\[]{2,80})',
      'gi'
    ),
  },
  {
    role: 'CLIENT',
    re: new RegExp(
      '(?:^|[\\r\\n])([ \\t]*(?:' +
      'Client|' +
      '\\u041a\\u043b\\u0438\\u0435\\u043d\\u0442' +
      ')\\s*:\\s*)([^\\r\\n|;,{\\[]{2,80})',
      'gi'
    ),
  },
];

const INLINE_PARTY_RE = new RegExp(
  '([A-Z\\u0410-\\u042f\\u0401]' +
  '[A-Za-z\\u0410-\\u044f\\u0401\\u04510-9 ."\'\\-]{2,64}?)' +
  '\\s*\\(\\s*(?:hereinafter\\s+|' +
  '\\u0434\\u0430\\u043b\\u0435\\u0435\\s*[\\u2014-]\\s*)?' +
  '["\\u00ab](Seller|Buyer|Party A|Party B|' +
  '\\u0417\\u0430\\u043a\\u0430\\u0437\\u0447\\u0438' +
  '\\u043a|' +
  '\\u0418\\u0441\\u043f\\u043e\\u043b\\u043d\\u0438' +
  '\\u0442\\u0435\\u043b\\u044c)["\\u00bb]\\s*\\)',
  'g'
);

const ALREADY_ALIAS_RE =
  /^(?:PATIENT|DOCTOR|PARTY_[AB]|CLIENT|PER|ADR|IDN|SYNTH)[_-]/;

export function captureAndReplaceHeaderEntities(
  text, vault
) {
  if (typeof text !== 'string' || !text) {
    return { text: text || '', count: 0, entities: [] };
  }
  const captured = [];

  for (const rule of HEADER_RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) !== null) {
      const val = m[2].trim().replace(/[.;]+$/, '');
      if (val.length < 3 || ALREADY_ALIAS_RE.test(val)) {
        continue;
      }
      const alias = allocNamedAlias(vault, rule.role, val);
      captured.push({ orig: val, alias, role: rule.role });
    }
  }

  INLINE_PARTY_RE.lastIndex = 0;
  let im;
  while ((im = INLINE_PARTY_RE.exec(text)) !== null) {
    const val = im[1].trim();
    const tag = im[2].toLowerCase();
    if (val.length < 3 || ALREADY_ALIAS_RE.test(val)) {
      continue;
    }
    const role = (tag.includes('buyer') ||
      tag.includes('party b') ||
      tag.startsWith('\u0438\u0441\u043f'))
      ? 'PARTY_B' : 'PARTY_A';
    const alias = allocNamedAlias(vault, role, val);
    captured.push({ orig: val, alias, role });
  }

  if (captured.length === 0) {
    return { text, count: 0, entities: [] };
  }

  const uniq = new Map();
  for (const item of captured) {
    if (!uniq.has(item.orig)) uniq.set(item.orig, item.alias);
  }
  const sorted = [...uniq.entries()].sort(
    (a, b) => b[0].length - a[0].length
  );

  let out = text;
  let count = 0;
  for (const [orig, alias] of sorted) {
    if (!out.includes(orig)) continue;
    const parts = out.split(orig);
    count += parts.length - 1;
    out = parts.join(alias);
  }
  return { text: out, count, entities: captured };
}

export function isHl7V2Text(text, ext = '') {
  if (String(ext).toLowerCase() === '.hl7') return true;
  return typeof text === 'string' &&
    /^MSH\|/m.test(text) && /\r|\nPID\|/m.test(text);
}

export function pseudonymizeHl7V2(
  text, key32, vault, opts = {}
) {
  const eol = text.includes('\r\n')
    ? '\r\n' : (text.includes('\r') ? '\r' : '\n');
  const lines = text.split(/\r\n|\r|\n/);
  const coref = [];
  let count = 0;
  const twk = Buffer.from(
    'HL7|' + (vault?.sessionEpochId || 'v311'), 'utf8'
  );

  const outLines = lines.map((ln) => {
    if (!ln.startsWith('PID|')) return ln;
    const f = ln.split('|');
    if (f[3] && f[3].trim()) {
      const orig = f[3].trim();
      f[3] = makeHmacTwin(key32, vault, 'MRN', orig);
      count++;
    }
    if (f[5] && f[5].trim()) {
      const orig = f[5].trim();
      const alias = allocNamedAlias(vault, 'PATIENT', orig);
      f[5] = alias;
      count++;
      const parts = orig.split('^').filter(Boolean);
      if (parts.length >= 2) {
        const full1 = `${parts[1]} ${parts[0]}`;
        const full2 = `${parts[0]} ${parts[1]}`;
        storeVault(vault, alias, orig);
        coref.push([full1, alias], [full2, alias]);
      }
    }
    if (f[7] && /^\d{8}/.test(f[7].trim())) {
      const rawDob = f[7].trim();
      const iso = `${rawDob.slice(0, 4)}-` +
        `${rawDob.slice(4, 6)}-${rawDob.slice(6, 8)}`;
      const shifted = shiftIsoDateString(
        iso, key32, opts.subjectScope || 'hl7-pid', false
      ).replace(/-/g, '');
      const synDob = shifted + rawDob.slice(8);
      storeVault(vault, synDob, rawDob);
      f[7] = synDob;
      count++;
    }
    if (f[11] && f[11].trim()) {
      const orig = f[11].trim();
      f[11] = makeHmacTwin(key32, vault, 'ADR', orig);
      count++;
    }
    if (f[19] && f[19].trim()) {
      const orig = f[19].trim();
      const tr = transformUsSsn(key32, twk, orig, false);
      const syn = tr !== orig
        ? tr : makeHmacTwin(key32, vault, 'IDN', orig);
      storeVault(vault, syn, orig);
      f[19] = syn;
      count++;
    }
    return f.join('|');
  });

  let joined = outLines.join(eol);
  for (const [nameVariant, alias] of coref) {
    if (joined.includes(nameVariant)) {
      const p = joined.split(nameVariant);
      count += p.length - 1;
      joined = p.join(alias);
    }
  }
  return { text: joined, count };
}

const FHIR_TYPES = new Set([
  'Patient', 'Practitioner', 'Bundle',
  'Observation', 'Encounter', 'DiagnosticReport',
]);

export function isFhirR4Object(obj) {
  return Boolean(
    obj && typeof obj === 'object' &&
    !Array.isArray(obj) &&
    FHIR_TYPES.has(obj.resourceType)
  );
}

export function pseudonymizeFhirR4(
  obj, key32, vault, opts = {}
) {
  let count = 0;
  const nameVariants = [];

  const scrubPerson = (res, role) => {
    const out = { ...res };
    if (Array.isArray(res.name)) {
      out.name = res.name.map((nm) => {
        if (!nm || typeof nm !== 'object') return nm;
        const nObj = { ...nm };
        const fullTxt = nm.text || [
          ...(Array.isArray(nm.given) ? nm.given : []),
          nm.family || '',
        ].filter(Boolean).join(' ').trim();
        const alias = fullTxt
          ? allocNamedAlias(vault, role, fullTxt) : null;
        if (nm.family) {
          const fSyn = makeHmacTwin(
            key32, vault, role === 'DOCTOR' ? 'DOC' : 'PAT',
            nm.family
          );
          nObj.family = fSyn;
          count++;
        }
        if (Array.isArray(nm.given)) {
          nObj.given = nm.given.map((g) => {
            count++;
            return makeHmacTwin(key32, vault, 'GIV', g);
          });
        }
        if (nm.text && alias) {
          nObj.text = alias;
          count++;
        }
        if (fullTxt && alias) {
          nameVariants.push([fullTxt, alias]);
        }
        return nObj;
      });
    }
    if (Array.isArray(res.identifier)) {
      out.identifier = res.identifier.map((idObj) => {
        if (!idObj || typeof idObj !== 'object' ||
            !idObj.value) {
          return idObj;
        }
        count++;
        return {
          ...idObj,
          value: makeHmacTwin(
            key32, vault, 'IDN', String(idObj.value)
          ),
        };
      });
    }
    if (Array.isArray(res.telecom)) {
      out.telecom = res.telecom.map((tObj) => {
        if (!tObj || typeof tObj !== 'object' ||
            !tObj.value) {
          return tObj;
        }
        const v = String(tObj.value);
        count++;
        if (v.includes('@')) {
          const tag = crypto.createHmac('sha256', key32)
            .update('EMAIL|' + v).digest('hex').slice(0, 8);
          const syn = `alias-${tag}@example.invalid`;
          storeVault(vault, syn, v);
          return { ...tObj, value: syn };
        }
        return {
          ...tObj,
          value: makeHmacTwin(key32, vault, 'TEL', v),
        };
      });
    }
    if (typeof res.birthDate === 'string' &&
        /^\d{4}-\d{2}-\d{2}$/.test(res.birthDate)) {
      const shifted = shiftIsoDateString(
        res.birthDate, key32,
        opts.subjectScope || 'fhir-dob', false
      );
      storeVault(vault, shifted, res.birthDate);
      out.birthDate = shifted;
      count++;
    }
    if (Array.isArray(res.address)) {
      out.address = res.address.map((ad) => {
        if (!ad || typeof ad !== 'object') return ad;
        const aObj = { ...ad };
        if (Array.isArray(ad.line)) {
          aObj.line = ad.line.map((l) => {
            count++;
            return makeHmacTwin(key32, vault, 'ADR', l);
          });
        }
        if (ad.city) {
          aObj.city = makeHmacTwin(
            key32, vault, 'ADR', String(ad.city)
          );
          count++;
        }
        if (ad.text) {
          aObj.text = makeHmacTwin(
            key32, vault, 'ADR', String(ad.text)
          );
          count++;
        }
        if (ad.postalCode) {
          const masked = maskHipaaSafeZip(
            String(ad.postalCode)
          );
          const syn = masked !== ad.postalCode
            ? masked
            : makeHmacTwin(
                key32, vault, 'ZIP', String(ad.postalCode)
              );
          storeVault(vault, syn, String(ad.postalCode));
          aObj.postalCode = syn;
          count++;
        }
        return aObj;
      });
    }
    return out;
  };

  const walk = (node) => {
    if (!node || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map(walk);
    if (node.resourceType === 'Patient') {
      return scrubPerson(node, 'PATIENT');
    }
    if (node.resourceType === 'Practitioner') {
      return scrubPerson(node, 'DOCTOR');
    }
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      if (k === '__proto__' || k === 'constructor' ||
          k === 'prototype') continue;
      out[k] = walk(v);
    }
    return out;
  };

  const scrubbed = walk(obj);
  let jsonStr = JSON.stringify(scrubbed, null, 2);
  for (const [orig, alias] of nameVariants) {
    if (jsonStr.includes(orig)) {
      jsonStr = jsonStr.split(orig).join(alias);
    }
  }
  return {
    obj: JSON.parse(jsonStr),
    text: jsonStr,
    count,
  };
}

export function formatProtectionBanner(
  counts = {}, restoredCount = null
) {
  if (typeof restoredCount === 'number') {
    return '[SHULIAK SIP-1 ACTIVE | 0 Sockets | ' +
      `Restored in RAM: ${restoredCount} item(s)]`;
  }
  const entries = Object.entries(counts)
    .filter(([, v]) => Number(v) > 0);
  const total = entries.reduce((a, [, v]) => a + Number(v), 0);
  const detail = entries.length > 0
    ? ' (' + entries.map(([k, v]) => `${k}:${v}`)
        .join(', ') + ')'
    : '';
  return '[SHULIAK SIP-1 ACTIVE | 0 Sockets | ' +
    `Protected in RAM: ${total} item(s)${detail}]`;
}
