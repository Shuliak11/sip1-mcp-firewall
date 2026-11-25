/**
 * @license Apache-2.0
 * SHULIAK SIP v3.1 - Stage 1 Auto-Shield Offset Patcher
 * Preserves 100% of JSONC/TOML comments, fixes GUI PATH
 * via realpathSync(execPath), npx cold-start mutex, and
 * 9+ IDE multi-dialect PreToolUse hook formatter.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseJsoncSafe,
  writeFileAtomic600,
} from '../core/workspace-io.mjs';
import {
  discoverMcpConfigs,
  parseTomlMcpConfigSafe,
} from './config-discovery.mjs';

export const HOOK_DIALECTS = Object.freeze([
  'claude',
  'cursor',
  'codex',
  'cline',
  'devin',
]);

export function applyEdits(source, edits) {
  const src = String(source ?? '');
  if (!Array.isArray(edits) || edits.length === 0) {
    return src;
  }
  const sorted = [...edits].sort((a, b) => {
    if (b.start !== a.start) return b.start - a.start;
    return b.end - a.end;
  });
  let prevStart = src.length + 1;
  let out = src;
  for (const e of sorted) {
    const st = Number(e.start);
    const en = Number(e.end);
    if (!Number.isInteger(st) || !Number.isInteger(en) ||
        st < 0 || en < st || en > src.length) {
      throw new RangeError(
        `Invalid edit span [${st}, ${en}]`
      );
    }
    if (en > prevStart) {
      throw new Error(
        `Overlapping edit span [${st}, ${en}]`
      );
    }
    out = out.slice(0, st) + String(e.replacement) +
      out.slice(en);
    prevStart = st;
  }
  return out;
}

export function resolveRealNodeRuntime() {
  let nodePath = process.execPath;
  try {
    nodePath = fs.realpathSync(process.execPath);
  } catch {}
  const nodeDir = path.dirname(nodePath);
  const selfDir = path.dirname(
    fileURLToPath(import.meta.url)
  );
  const rawCli = path.resolve(selfDir, '..', 'cli.mjs');
  let cliPath = rawCli;
  try {
    cliPath = fs.realpathSync(rawCli);
  } catch {}
  return { nodePath, nodeDir, cliPath };
}

function buildInjectedPath(existingPath, nodeDir) {
  const sep = path.delimiter;
  const base = existingPath ||
    process.env.PATH ||
    '/usr/local/bin:/usr/bin:/bin';
  const parts = String(base).split(sep).filter(Boolean);
  if (parts[0] === nodeDir) return parts.join(sep);
  return [nodeDir, ...parts.filter((p) => p !== nodeDir)]
    .join(sep);
}

function isAlreadyWrappedCommand(cmd, args) {
  const c = String(cmd || '').toLowerCase();
  const a = Array.isArray(args) ? args.map(String) : [];
  if (c.includes('sip1-mcp')) return true;
  if (a.some((x) =>
    /(?:@shuliak-corp\/)?sip1-mcp/i.test(x))) {
    return true;
  }
  const hasCli = a.some((x) => {
    const n = x.replace(/\\/g, '/').toLowerCase();
    return n.endsWith('/cli.mjs') || n === 'cli.mjs';
  });
  if (hasCli && (a.includes('wrap') ||
                 a.includes('serve'))) {
    return true;
  }
  return false;
}

function skipWsAndComments(src, idx) {
  const n = src.length;
  let i = idx;
  while (i < n) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t' ||
        ch === '\r' || ch === '\n') {
      i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') {
      i += 2;
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      i += 2;
      while (i + 1 < n &&
             !(src[i] === '*' && src[i + 1] === '/')) {
        i++;
      }
      i = Math.min(n, i + 2);
      continue;
    }
    break;
  }
  return i;
}

function scanJsoncStringEnd(src, start) {
  const n = src.length;
  let i = start + 1;
  while (i < n) {
    const c = src[i++];
    if (c === '\\') { i++; continue; }
    if (c === '"') return i;
  }
  return n;
}

function scanJsoncValueSpan(src, start) {
  const n = src.length;
  const ch = src[start];
  if (ch === '"') {
    return { start, end: scanJsoncStringEnd(src, start) };
  }
  if (ch === '{' || ch === '[') {
    const open = ch;
    const close = ch === '{' ? '}' : ']';
    let depth = 0;
    let i = start;
    while (i < n) {
      i = skipWsAndComments(src, i);
      if (i >= n) break;
      const c = src[i];
      if (c === '"') {
        i = scanJsoncStringEnd(src, i);
        continue;
      }
      if (c === open) depth++;
      else if (c === close) {
        depth--;
        if (depth === 0) return { start, end: i + 1 };
      }
      i++;
    }
    return { start, end: n };
  }
  let i = start;
  while (i < n && !/[\s,}\]]/.test(src[i])) i++;
  return { start, end: i };
}

function parseJsoncObjectProps(src, objStart, objEnd) {
  const props = new Map();
  let i = skipWsAndComments(src, objStart + 1);
  while (i < objEnd - 1) {
    i = skipWsAndComments(src, i);
    if (i >= objEnd - 1 || src[i] === '}') break;
    if (src[i] === ',') { i++; continue; }
    if (src[i] !== '"') break;
    const kEnd = scanJsoncStringEnd(src, i);
    let keyName;
    try {
      keyName = JSON.parse(src.slice(i, kEnd));
    } catch {
      keyName = src.slice(i + 1, kEnd - 1);
    }
    const colon = skipWsAndComments(src, kEnd);
    if (src[colon] !== ':') break;
    const vStart = skipWsAndComments(src, colon + 1);
    const vSpan = scanJsoncValueSpan(src, vStart);
    props.set(keyName, {
      keyStart: i,
      keyEnd: kEnd,
      valStart: vSpan.start,
      valEnd: vSpan.end,
    });
    i = skipWsAndComments(src, vSpan.end);
    if (src[i] === ',') i++;
  }
  return props;
}

function findTrailingInsertPos(src, objEnd) {
  let i = objEnd - 1;
  while (i > 0 && /[\s]/.test(src[i - 1])) i--;
  return i;
}

function findLastPropInsertAnchor(
  src, propsMap, objEnd
) {
  if (!propsMap || propsMap.size === 0) {
    return {
      pos: findTrailingInsertPos(src, objEnd),
      needsComma: false,
    };
  }
  let lastProp = null;
  for (const prop of propsMap.values()) {
    if (!lastProp || prop.valEnd > lastProp.valEnd) {
      lastProp = prop;
    }
  }
  const afterVal = skipWsAndComments(
    src, lastProp.valEnd
  );
  if (src[afterVal] === ',') {
    return { pos: afterVal + 1, needsComma: false };
  }
  return { pos: lastProp.valEnd, needsComma: true };
}

function lineIndentAt(src, pos) {
  const nl = src.lastIndexOf('\n', Math.max(0, pos - 1));
  const seg = src.slice(nl + 1, pos);
  const m = /^[ \t]*/.exec(seg);
  return m ? m[0] : '  ';
}

export function computeJsoncShieldEdits(rawText, runtime) {
  const rt = runtime || resolveRealNodeRuntime();
  const edits = [];
  const wrappedServers = [];
  const rootStart = skipWsAndComments(rawText, 0);
  if (rawText[rootStart] !== '{') {
    return { edits, wrappedServers };
  }
  const rootSpan = scanJsoncValueSpan(rawText, rootStart);
  const rootProps = parseJsoncObjectProps(
    rawText, rootSpan.start, rootSpan.end
  );

  const containers = [];
  for (const k of ['mcpServers', 'servers',
                   'context_servers']) {
    if (rootProps.has(k)) containers.push(rootProps.get(k));
  }
  if (rootProps.has('mcp')) {
    const mp = rootProps.get('mcp');
    if (rawText[mp.valStart] === '{') {
      const sub = parseJsoncObjectProps(
        rawText, mp.valStart, mp.valEnd
      );
      if (sub.has('servers')) {
        containers.push(sub.get('servers'));
      }
    }
  }

  for (const cont of containers) {
    if (rawText[cont.valStart] !== '{') continue;
    const srvMap = parseJsoncObjectProps(
      rawText, cont.valStart, cont.valEnd
    );
    for (const [srvName, srvMeta] of srvMap.entries()) {
      if (rawText[srvMeta.valStart] !== '{') continue;
      const fields = parseJsoncObjectProps(
        rawText, srvMeta.valStart, srvMeta.valEnd
      );
      if (!fields.has('command')) continue;
      const cmdF = fields.get('command');
      if (rawText[cmdF.valStart] !== '"') continue;
      let origCmd;
      try {
        origCmd = parseJsoncSafe(
          rawText.slice(cmdF.valStart, cmdF.valEnd)
        );
      } catch {
        continue;
      }
      let origArgs = [];
      const argsF = fields.get('args');
      if (argsF) {
        try {
          const pa = parseJsoncSafe(
            rawText.slice(argsF.valStart, argsF.valEnd)
          );
          if (Array.isArray(pa)) origArgs = pa.map(String);
        } catch {
          continue;
        }
      }
      if (isAlreadyWrappedCommand(origCmd, origArgs)) {
        continue;
      }
      const nextArgs = [
        rt.cliPath, 'wrap', '--server', srvName,
        '--', String(origCmd), ...origArgs,
      ];
      edits.push({
        start: cmdF.valStart,
        end: cmdF.valEnd,
        replacement: JSON.stringify(rt.nodePath),
      });
      const indent = lineIndentAt(rawText, cmdF.keyStart);
      if (argsF) {
        edits.push({
          start: argsF.valStart,
          end: argsF.valEnd,
          replacement: JSON.stringify(nextArgs),
        });
      } else {
        edits.push({
          start: cmdF.valEnd,
          end: cmdF.valEnd,
          replacement: `,\n${indent}"args": ` +
            JSON.stringify(nextArgs),
        });
      }
      const envF = fields.get('env');
      if (envF && rawText[envF.valStart] === '{') {
        const envProps = parseJsoncObjectProps(
          rawText, envF.valStart, envF.valEnd
        );
        if (envProps.has('PATH')) {
          const pf = envProps.get('PATH');
          let curP = '';
          try {
            curP = String(parseJsoncSafe(
              rawText.slice(pf.valStart, pf.valEnd)
            ) || '');
          } catch {}
          edits.push({
            start: pf.valStart,
            end: pf.valEnd,
            replacement: JSON.stringify(
              buildInjectedPath(curP, rt.nodeDir)
            ),
          });
        } else {
          const anc = findLastPropInsertAnchor(
            rawText, envProps, envF.valEnd
          );
          const comma = anc.needsComma ? ',' : '';
          edits.push({
            start: anc.pos,
            end: anc.pos,
            replacement: `${comma}\n${indent}  "PATH": ` +
              JSON.stringify(
                buildInjectedPath('', rt.nodeDir)
              ),
          });
        }
      } else {
        const anc = findLastPropInsertAnchor(
          rawText, fields, srvMeta.valEnd
        );
        const comma = anc.needsComma ? ',' : '';
        edits.push({
          start: anc.pos,
          end: anc.pos,
          replacement: `${comma}\n${indent}"env": ` +
            JSON.stringify({
              PATH: buildInjectedPath('', rt.nodeDir),
            }),
        });
      }
      wrappedServers.push(srvName);
    }
  }
  return { edits, wrappedServers };
}

function splitTomlLineComment(line) {
  let inD = false;
  let inS = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inD) {
      if (c === '\\') i++;
      else if (c === '"') inD = false;
    } else if (inS) {
      if (c === "'") inS = false;
    } else {
      if (c === '"') inD = true;
      else if (c === "'") inS = true;
      else if (c === '#') return i;
    }
  }
  return -1;
}

export function computeTomlShieldEdits(rawText, runtime) {
  const rt = runtime || resolveRealNodeRuntime();
  const edits = [];
  const wrappedServers = [];
  let parsed;
  try {
    parsed = parseTomlMcpConfigSafe(rawText);
  } catch {
    return { edits, wrappedServers };
  }
  const srvObj = parsed?.mcpServers || {};
  const lines = rawText.split(/\r?\n/);
  const offsets = [];
  let off = 0;
  for (let i = 0; i < lines.length; i++) {
    offsets.push(off);
    off += lines[i].length;
    if (rawText[off] === '\r' && rawText[off + 1] === '\n') {
      off += 2;
    } else if (rawText[off] === '\n') {
      off += 1;
    }
  }

  let curSection = '';
  const secMeta = new Map();
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const cIdx = splitTomlLineComment(ln);
    const code = (cIdx >= 0 ? ln.slice(0, cIdx) : ln).trim();
    if (!code) continue;
    if (code.startsWith('[') && code.endsWith(']') &&
        !code.startsWith('[[')) {
      curSection = code.slice(1, -1).trim();
      if (!secMeta.has(curSection)) {
        secMeta.set(curSection, {
          headerLine: i, endLine: i,
          cmdLine: -1, argsStart: -1, argsEnd: -1,
          pathLine: -1,
        });
      }
      continue;
    }
    const meta = secMeta.get(curSection);
    if (!meta) continue;
    meta.endLine = i;
    const eq = code.indexOf('=');
    if (eq > 0) {
      const k = code.slice(0, eq).trim();
      if (k === 'command') meta.cmdLine = i;
      if (k === 'args') {
        meta.argsStart = i;
        let bal = 0;
        let j = i;
        while (j < lines.length) {
          const lj = lines[j];
          const cj = splitTomlLineComment(lj);
          const sub = cj >= 0 ? lj.slice(0, cj) : lj;
          for (const ch of sub) {
            if (ch === '[') bal++;
            else if (ch === ']') bal--;
          }
          if (bal <= 0) break;
          j++;
        }
        meta.argsEnd = Math.min(j, lines.length - 1);
        meta.endLine = Math.max(meta.endLine, meta.argsEnd);
      }
      if (k === 'PATH') meta.pathLine = i;
    }
  }

  for (const [secName, meta] of secMeta.entries()) {
    const m = /^(?:mcp_servers|mcpServers)\.([^\.]+)$/
      .exec(secName);
    if (!m) continue;
    const srvName = m[1].replace(/^["']|["']$/g, '');
    const def = srvObj[srvName];
    if (!def || typeof def.command !== 'string') continue;
    const origArgs = Array.isArray(def.args)
      ? def.args.map(String) : [];
    if (isAlreadyWrappedCommand(def.command, origArgs)) {
      continue;
    }
    if (meta.cmdLine < 0) continue;

    const cLn = lines[meta.cmdLine];
    const eqIdx = cLn.indexOf('=');
    const cmtIdx = splitTomlLineComment(cLn);
    const valEnd = cmtIdx >= 0
      ? cLn.slice(0, cmtIdx).trimEnd().length
      : cLn.trimEnd().length;
    const lineOff = offsets[meta.cmdLine];
    edits.push({
      start: lineOff + eqIdx + 1,
      end: lineOff + valEnd,
      replacement: ' ' + JSON.stringify(rt.nodePath),
    });

    const nextArgs = [
      rt.cliPath, 'wrap', '--server', srvName,
      '--', def.command, ...origArgs,
    ];
    if (meta.argsStart >= 0) {
      const aLn = lines[meta.argsStart];
      const aEq = aLn.indexOf('=');
      const eLn = lines[meta.argsEnd];
      const eCmt = splitTomlLineComment(eLn);
      const eEnd = eCmt >= 0
        ? eLn.slice(0, eCmt).trimEnd().length
        : eLn.trimEnd().length;
      edits.push({
        start: offsets[meta.argsStart] + aEq + 1,
        end: offsets[meta.argsEnd] + eEnd,
        replacement: ' ' + JSON.stringify(nextArgs),
      });
    } else {
      const insPos = lineOff + cLn.length;
      edits.push({
        start: insPos,
        end: insPos,
        replacement: '\nargs = ' + JSON.stringify(nextArgs),
      });
    }

    const envSecName = `${secName}.env`;
    const envMeta = secMeta.get(envSecName);
    const newPathVal = buildInjectedPath(
      def?.env?.PATH || '', rt.nodeDir
    );
    if (envMeta && envMeta.pathLine >= 0) {
      const pLn = lines[envMeta.pathLine];
      const pEq = pLn.indexOf('=');
      const pCmt = splitTomlLineComment(pLn);
      const pEnd = pCmt >= 0
        ? pLn.slice(0, pCmt).trimEnd().length
        : pLn.trimEnd().length;
      edits.push({
        start: offsets[envMeta.pathLine] + pEq + 1,
        end: offsets[envMeta.pathLine] + pEnd,
        replacement: ' ' + JSON.stringify(newPathVal),
      });
    } else if (envMeta) {
      const endPos = offsets[envMeta.endLine] +
        lines[envMeta.endLine].length;
      edits.push({
        start: endPos,
        end: endPos,
        replacement: '\nPATH = ' + JSON.stringify(newPathVal),
      });
    } else {
      const endPos = offsets[meta.endLine] +
        lines[meta.endLine].length;
      edits.push({
        start: endPos,
        end: endPos,
        replacement: `\n[${envSecName}]\nPATH = ` +
          JSON.stringify(newPathVal),
      });
    }
    wrappedServers.push(srvName);
  }
  return { edits, wrappedServers };
}

function sha256Buf(buf) {
  return crypto.createHash('sha256').update(buf)
    .digest('hex');
}

export function applyShieldToWorkspace({
  workspaceDir = process.cwd(),
  includeGlobal = false,
  dryRun = false,
  configs = null,
  runtime = null,
} = {}) {
  const ws = path.resolve(workspaceDir || process.cwd());
  const rt = runtime || resolveRealNodeRuntime();
  const discovered = configs || discoverMcpConfigs({
    workspaceDir: ws,
    includeGlobal,
  });
  const sipDir = path.join(ws, '.sip');
  const manifestPath = path.join(
    sipDir, 'shield-manifest.json'
  );
  const backupDir = path.join(sipDir, 'shield-backups');

  let manifest = { v: 'sip-shield/3.1', files: {} };
  if (fs.existsSync(manifestPath)) {
    try {
      const p = JSON.parse(
        fs.readFileSync(manifestPath, 'utf8')
      );
      if (p && p.files) manifest = p;
    } catch {}
  }

  const results = [];
  let modifiedCount = 0;

  for (const cfg of discovered) {
    if (cfg.parseError || !cfg.filePath) continue;
    const rawBuf = fs.readFileSync(cfg.filePath);
    const rawText = rawBuf.toString('utf8');
    const isToml = cfg.filePath.toLowerCase()
      .endsWith('.toml');
    const plan = isToml
      ? computeTomlShieldEdits(rawText, rt)
      : computeJsoncShieldEdits(rawText, rt);
    if (plan.edits.length === 0) {
      results.push({
        filePath: cfg.filePath,
        changed: false,
        wrappedServers: [],
      });
      continue;
    }
    const nextText = applyEdits(rawText, plan.edits);
    const nextBuf = Buffer.from(nextText, 'utf8');
    const origSha256 = sha256Buf(rawBuf);
    const nextSha256 = sha256Buf(nextBuf);

    if (!dryRun) {
      fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
      if (!manifest.files[cfg.filePath]) {
        const bId = crypto.createHash('sha256')
          .update(cfg.filePath).digest('hex').slice(0, 16);
        const bkpPath = path.join(backupDir, `${bId}.orig`);
        writeFileAtomic600(bkpPath, rawBuf, { mode: 0o600 });
        const mode = fs.statSync(cfg.filePath).mode & 0o777;
        manifest.files[cfg.filePath] = {
          backupPath: bkpPath,
          origSha256,
          origMode: mode,
        };
      }
      manifest.files[cfg.filePath].shieldedSha256 =
        nextSha256;
      manifest.files[cfg.filePath].wrappedServers =
        plan.wrappedServers;
      const stMode = manifest.files[cfg.filePath].origMode ||
        0o600;
      writeFileAtomic600(cfg.filePath, nextBuf, {
        mode: stMode,
      });
    }
    modifiedCount++;
    results.push({
      filePath: cfg.filePath,
      changed: true,
      wrappedServers: plan.wrappedServers,
      origSha256,
      nextSha256,
      editsCount: plan.edits.length,
    });
  }

  if (!dryRun && modifiedCount > 0) {
    writeFileAtomic600(
      manifestPath,
      JSON.stringify(manifest, null, 2) + '\n',
      { mode: 0o600 }
    );
  }

  return {
    dryRun: Boolean(dryRun),
    nodePath: rt.nodePath,
    nodeDir: rt.nodeDir,
    cliPath: rt.cliPath,
    modifiedCount,
    files: results,
    manifestPath,
  };
}

export function rollbackShieldInWorkspace({
  workspaceDir = process.cwd(),
  dryRun = false,
} = {}) {
  const ws = path.resolve(workspaceDir || process.cwd());
  const manifestPath = path.join(
    ws, '.sip', 'shield-manifest.json'
  );
  if (!fs.existsSync(manifestPath)) {
    return {
      restoredCount: 0,
      files: [],
      status: 'NO_SHIELD_MANIFEST',
    };
  }
  const manifest = JSON.parse(
    fs.readFileSync(manifestPath, 'utf8')
  );
  const files = [];
  let restoredCount = 0;

  for (const [fp, rec] of Object.entries(
    manifest.files || {}
  )) {
    if (!rec?.backupPath || !fs.existsSync(rec.backupPath)) {
      throw new Error(
        `Missing shield backup for ${fp}`
      );
    }
    const origBuf = fs.readFileSync(rec.backupPath);
    const actualSha = sha256Buf(origBuf);
    if (actualSha !== rec.origSha256) {
      throw new Error(
        `Backup SHA-256 mismatch for ${fp}`
      );
    }
    if (!dryRun) {
      writeFileAtomic600(fp, origBuf, {
        mode: rec.origMode || 0o600,
      });
    }
    restoredCount++;
    files.push({
      filePath: fp,
      restoredSha256: actualSha,
      exactMatch: actualSha === rec.origSha256,
    });
  }

  if (!dryRun) {
    try { fs.unlinkSync(manifestPath); } catch {}
  }

  return {
    dryRun: Boolean(dryRun),
    restoredCount,
    files,
    status: 'ROLLED_BACK_EXACT',
  };
}

function sleepSync(ms) {
  const sab = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(sab), 0, 0, ms);
}

function isPidDead(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return false;
  } catch (e) {
    return e?.code === 'ESRCH';
  }
}

export function acquireNpxColdStartLock({
  lockDir = path.join(os.homedir(), '.sip', 'locks'),
  timeoutMs = 15_000,
  staleMs = 15_000,
} = {}) {
  fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 });
  const lockPath = path.join(lockDir, 'npx-coldstart.lock');
  const token = crypto.randomBytes(6).toString('hex');
  const start = Date.now();

  while (true) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);
      try {
        fs.writeFileSync(
          fd,
          JSON.stringify({ pid: process.pid, ts: Date.now(),
                           token }),
          'utf8'
        );
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      return {
        lockPath,
        release() {
          try {
            const cur = JSON.parse(
              fs.readFileSync(lockPath, 'utf8')
            );
            if (cur?.token === token) {
              fs.unlinkSync(lockPath);
            }
          } catch {}
        },
      };
    } catch (err) {
      if (err?.code !== 'EEXIST') throw err;
      let reclaim = false;
      try {
        const raw = fs.readFileSync(lockPath, 'utf8');
        const parsed = JSON.parse(raw);
        if (!parsed?.ts ||
            Date.now() - Number(parsed.ts) > staleMs ||
            isPidDead(Number(parsed.pid))) {
          reclaim = true;
        }
      } catch {
        reclaim = true;
      }
      if (reclaim) {
        try { fs.unlinkSync(lockPath); } catch {}
        continue;
      }
      if (Date.now() - start >= timeoutMs) {
        throw new Error('NPX cold-start lock timeout');
      }
      sleepSync(15);
    }
  }
}

export function formatMultiDialectHookDecision(
  dialect, { blocked, reason, code = 'SIP_BLOCKED',
             reportText = '' }
) {
  const d = String(dialect || 'claude').toLowerCase();
  if (!blocked) {
    if (d === 'cursor') {
      return { exitCode: 0, stdout: '{"continue":true}\n',
               stderr: '' };
    }
    if (d === 'cline') {
      return { exitCode: 0, stdout: '{"cancel":false}\n',
               stderr: '' };
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  }
  const msg = String(reason || code || 'Blocked by SIP-1');
  if (d === 'cursor') {
    return {
      exitCode: 2,
      stdout: JSON.stringify({
        continue: false,
        permission: 'deny',
        userMessage: msg,
        agentMessage: msg,
      }) + '\n',
      stderr: '',
    };
  }
  if (d === 'codex') {
    return {
      exitCode: 2,
      stdout: JSON.stringify({
        decision: 'block',
        permissionDecision: 'deny',
        reason: msg,
      }) + '\n',
      stderr: '',
    };
  }
  if (d === 'cline') {
    return {
      exitCode: 2,
      stdout: JSON.stringify({
        cancel: true,
        errorMessage: msg,
      }) + '\n',
      stderr: '',
    };
  }
  if (d === 'devin') {
    return {
      exitCode: 2,
      stdout: JSON.stringify({
        decision: 'block',
        reason: msg,
      }) + '\n',
      stderr: '',
    };
  }
  return {
    exitCode: 2,
    stdout: '',
    stderr: (reportText || `[SHULIAK SIP BLOCKED] ${msg}`) +
      '\n',
  };
}
