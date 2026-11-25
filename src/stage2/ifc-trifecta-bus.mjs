/**
 * @license Apache-2.0
 * SHULIAK SIP v3.1 - Stage 2 Two-Phase IFC Trifecta Bus
 * Zero external deps. Zero network imports.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  unb64u,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import { writeFileAtomic600 } from '../core/workspace-io.mjs';
import {
  computeNormalizedActionDigest,
} from './blast-radius-guard.mjs';
import {
  verifyAndConsumeWarrant,
} from './warrant-engine.mjs';

export const IFC_WARRANT_LABEL = 'SIP-v3-IFC-WARRANT\0';
const IFC_HMAC_LABEL = 'SIP1-IFC-STATE-v1\0';
const STALE_LOCK_MS = 500;
const STALE_INFLIGHT_MS = 120_000;

const lastSeenSeqByScope = new Map();

function sleepSync(ms) {
  const sab = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(sab), 0, 0, ms);
}

function isPidDead(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return false;
  } catch (err) {
    return err?.code === 'ESRCH';
  }
}

export function resolveIfcHmacKeyPath(options = {}) {
  if (typeof options.hmacKeyPath === 'string' &&
      options.hmacKeyPath.trim()) {
    return path.resolve(options.hmacKeyPath.trim());
  }
  const envP = process.env.SIP_IFC_HMAC_KEY_PATH;
  if (typeof envP === 'string' && envP.trim()) {
    return path.resolve(envP.trim());
  }
  return path.join(os.homedir(), '.sip', 'keys',
    'ifc-hmac.key');
}

export function loadOrCreateIfcHmacKey(options = {}) {
  const keyPath = resolveIfcHmacKeyPath(options);
  if (fs.existsSync(keyPath)) {
    const raw = fs.readFileSync(keyPath, 'utf8').trim();
    if (/^[0-9a-f]{64}$/i.test(raw)) {
      return { key32: Buffer.from(raw, 'hex'), keyPath };
    }
    const rawBin = fs.readFileSync(keyPath);
    if (rawBin.byteLength === 32) {
      return { key32: rawBin, keyPath };
    }
  }
  const key32 = crypto.randomBytes(32);
  const dir = path.dirname(keyPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    const fd = fs.openSync(keyPath, 'wx', 0o600);
    try {
      fs.writeFileSync(fd, key32.toString('hex') + '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(keyPath, 0o600);
    return { key32, keyPath };
  } catch (err) {
    if (err?.code === 'EEXIST') {
      const hex = fs.readFileSync(keyPath, 'utf8').trim();
      return { key32: Buffer.from(hex, 'hex'), keyPath };
    }
    throw err;
  }
}

export function computeIfcScopeHash({
  workspaceDir = process.cwd(),
  sessionId = null,
} = {}) {
  const sid = sessionId || process.env.SIP_IFC_SESSION_ID;
  let basis;
  if (typeof sid === 'string' && sid.trim()) {
    basis = 'sid:' + sid.trim();
  } else {
    const abs = path.resolve(workspaceDir || process.cwd());
    let realCwd = abs;
    try {
      realCwd = fs.realpathSync(abs);
    } catch {}
    basis = `proc:${process.ppid}:${realCwd}`;
  }
  return crypto.createHash('sha256')
    .update(basis, 'utf8').digest('hex').slice(0, 16);
}

export function resolveIfcPaths({
  workspaceDir = process.cwd(),
  sessionId = null,
} = {}) {
  const resolvedWs = path.resolve(
    workspaceDir || process.cwd()
  );
  const scopeHash = computeIfcScopeHash({
    workspaceDir: resolvedWs,
    sessionId,
  });
  const stateDir = path.join(resolvedWs, '.sip', 'state');
  const statePath = path.join(
    stateDir, `ifc-${scopeHash}.json`
  );
  const lockPath = path.join(
    stateDir, `ifc-${scopeHash}.lock`
  );
  return {
    resolvedWs, scopeHash, stateDir, statePath, lockPath,
  };
}

export function withIfcLock(lockPath, fn, options = {}) {
  const staleMs = options.staleMs ?? STALE_LOCK_MS;
  const timeoutMs = options.timeoutMs ?? 15000;
  fs.mkdirSync(path.dirname(lockPath), {
    recursive: true, mode: 0o700,
  });
  const myToken = crypto.randomBytes(6).toString('hex');
  const start = Date.now();
  let backoff = 3;
  let acquired = false;

  while (!acquired) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);
      try {
        const body = JSON.stringify({
          pid: process.pid,
          acquiredAtMs: Date.now(),
          token: myToken,
        });
        fs.writeFileSync(fd, body, 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      acquired = true;
    } catch (err) {
      if (err?.code !== 'EEXIST') throw err;
      let reclaim = false;
      try {
        const st = fs.statSync(lockPath);
        const raw = fs.readFileSync(lockPath, 'utf8');
        if (!raw.trim()) {
          if (Date.now() - st.mtimeMs > 80) reclaim = true;
        } else {
          const parsed = JSON.parse(raw);
          const ownerPid = Number(parsed?.pid);
          const acqMs = Number(parsed?.acquiredAtMs);
          if (!Number.isFinite(acqMs) ||
              Date.now() - acqMs > staleMs ||
              isPidDead(ownerPid)) {
            reclaim = true;
          }
        }
      } catch (rErr) {
        if (rErr?.code === 'ENOENT') continue;
        try {
          const st2 = fs.statSync(lockPath);
          if (Date.now() - st2.mtimeMs > 80) reclaim = true;
        } catch {}
      }
      if (reclaim) {
        try { fs.unlinkSync(lockPath); } catch {}
        continue;
      }
      if (Date.now() - start >= timeoutMs) {
        throw new Error(
          `IFC lock timeout (${timeoutMs}ms): ${lockPath}`
        );
      }
      const jitter = crypto.randomInt(0, 4);
      sleepSync(Math.min(15, backoff + jitter));
      backoff = Math.min(15, backoff + 2);
    }
  }

  try {
    return fn();
  } finally {
    try {
      const cur = JSON.parse(
        fs.readFileSync(lockPath, 'utf8')
      );
      if (cur?.token === myToken) {
        fs.unlinkSync(lockPath);
      }
    } catch {}
  }
}

function signStateBody(key32, body) {
  return crypto
    .createHmac('sha256', key32)
    .update(IFC_HMAC_LABEL, 'ascii')
    .update(jcsCanonicalize(body))
    .digest('hex');
}

function verifyStateHmac(key32, fullObj) {
  if (!fullObj || typeof fullObj !== 'object') return false;
  const sig = String(fullObj.hmac || '');
  if (!/^[0-9a-f]{64}$/i.test(sig)) return false;
  const { hmac: _drop, ...body } = fullObj;
  const expected = signStateBody(key32, body);
  return crypto.timingSafeEqual(
    Buffer.from(sig, 'hex'),
    Buffer.from(expected, 'hex')
  );
}

function createInitialState(scopeHash) {
  return {
    v: 'sip-ifc/3.1.1',
    scopeHash,
    seq: 0,
    updatedAtMs: Date.now(),
    taints: {
      A: false,
      B_raw: false,
      B_twin: false,
      C_local_count: 0,
      C_egress_count: 0,
    },
    inFlight: {},
    committedOps: 0,
    tampered: false,
  };
}

function readAndVerifyState(statePath, scopeHash, key32) {
  if (!fs.existsSync(statePath)) {
    return {
      state: createInitialState(scopeHash),
      tampered: false,
    };
  }
  try {
    const parsed = JSON.parse(
      fs.readFileSync(statePath, 'utf8')
    );
    const macOk = verifyStateHmac(key32, parsed);
    const prevSeq = lastSeenSeqByScope.get(scopeHash) || 0;
    const seqNum = Number(parsed?.seq);
    const seqOk = Number.isInteger(seqNum) &&
      seqNum >= prevSeq &&
      parsed?.scopeHash === scopeHash;
    if (!macOk || !seqOk) {
      const failSt = createInitialState(scopeHash);
      failSt.seq = Math.max(prevSeq, seqNum || 0);
      failSt.taints.A = true;
      failSt.taints.B_raw = true;
      failSt.tampered = true;
      return { state: failSt, tampered: true };
    }
    lastSeenSeqByScope.set(scopeHash, seqNum);
    const { hmac: _h, ...body } = parsed;
    return { state: body, tampered: false };
  } catch {
    const failSt = createInitialState(scopeHash);
    failSt.taints.A = true;
    failSt.taints.B_raw = true;
    failSt.tampered = true;
    return { state: failSt, tampered: true };
  }
}

function persistState(statePath, state, key32) {
  const next = {
    ...state,
    seq: (Number(state.seq) || 0) + 1,
    updatedAtMs: Date.now(),
  };
  const hmac = signStateBody(key32, next);
  const envelope = { ...next, hmac };
  writeFileAtomic600(
    statePath,
    JSON.stringify(envelope, null, 2) + '\n',
    { mode: 0o600 }
  );
  lastSeenSeqByScope.set(next.scopeHash, next.seq);
  return envelope;
}

function pruneStaleInFlight(state) {
  const now = Date.now();
  const cur = state.inFlight &&
    typeof state.inFlight === 'object'
    ? state.inFlight : {};
  const clean = {};
  for (const [id, rec] of Object.entries(cur)) {
    const age = now - Number(rec?.ts || 0);
    if (age <= STALE_INFLIGHT_MS && !isPidDead(rec?.pid)) {
      clean[id] = rec;
    }
  }
  state.inFlight = clean;
}

const UNTRUSTED_A_RE = new RegExp(
  '(?:^|[_-])(?:fetch_?url|http_?get|web_?fetch|' +
  'web_?search|search_?web|browse|browser|scrape|' +
  'crawl|read_?email|get_?email|get_?issue|read_?issue|' +
  'get_?pr|read_?pr|read_?comment|read_?ticket|' +
  'slack_?read|read_?web|download)(?:$|[_-])|' +
  '^(?:fetch|curl|wget)$', 'i'
);
const PRIVATE_B_RE = new RegExp(
  '(?:read_?file|open_?file|get_?file|cat_?file|' +
  'read_?secret|get_?secret|read_?env|query|select|' +
  'sql|db_?read|fetch_?customer|get_?customer|' +
  'read_?protected|resources\/read|list_?secrets|' +
  'get_?credentials)', 'i'
);
const EGRESS_C_RE = new RegExp(
  '(?:send_?email|send_?mail|send_?message|send_?slack|' +
  'post_?message|post_?webhook|http_?post|http_?put|' +
  'upload|exfil|publish|broadcast|notify|webhook|' +
  'submit_?remote|git_?push|wire_?transfer|' +
  'send_?http|curl_?post)', 'i'
);
const LOCAL_WRITE_RE = new RegExp(
  '(?:write_?file|edit_?file|patch_?file|create_?file|' +
  'save_?file|update_?file|append_?file|save_?restored)',
  'i'
);
const URL_ARG_RE = /https?:\/\/[^\s'"]+/i;
const SHELL_EGRESS_RE =
  /\b(?:curl|wget|nc|ncat|scp|rsync|sftp)\b|\bgit\s+push\b/i;

export function classifyIfcAction({
  server = '',
  tool = '',
  method = 'tools/call',
  args = {},
  workspaceDir = process.cwd(),
} = {}) {
  const sTool = String(tool || '');
  const sSrv = String(server || '');
  const sDump = JSON.stringify(args || {});
  const hasUrl = URL_ARG_RE.test(sDump);

  const egressC =
    EGRESS_C_RE.test(sTool) ||
    SHELL_EGRESS_RE.test(sDump) ||
    (/(?:post|send|upload|webhook|exfil)/i.test(sTool) &&
      hasUrl);

  const mutatesLocalC = !egressC &&
    LOCAL_WRITE_RE.test(sTool);

  const readsUntrustedA = !egressC && (
    UNTRUSTED_A_RE.test(sTool) ||
    (/(?:web|browser|email|slack|github|jira|rovo)/i
      .test(sSrv) &&
      /^(?:get|read|list|fetch|search)/i.test(sTool)) ||
    (hasUrl && /^(?:get|read|fetch|open|load)/i
      .test(sTool))
  );

  const readsPrivateB = !egressC && !mutatesLocalC && (
    method === 'resources/read' ||
    PRIVATE_B_RE.test(sTool) ||
    /(?:postgres|mysql|sqlite|vault|fs|files|db|secret)/i
      .test(sSrv) &&
      /^(?:get|read|query|select|fetch|list)/i.test(sTool)
  );

  return {
    readsUntrustedA,
    readsPrivateB,
    mutatesLocalC,
    egressC,
  };
}

export function issueIfcWarrant0x07({
  workspaceDir,
  server,
  tool,
  args = {},
  scopeHash,
  ttlMs = 300_000,
}) {
  const sipDir = path.join(path.resolve(workspaceDir), '.sip');
  const kp = ensureDeviceEd25519Keypair(sipDir, {
    ephemeralOnly: false,
  });
  const actionDigest = computeNormalizedActionDigest({
    server, tool, args,
  });
  const payload = {
    actionDigest,
    exp: Date.now() + ttlMs,
    jti: crypto.randomBytes(12).toString('hex'),
    scopeHash: String(scopeHash || '*'),
    v: 'sip-ifc-warrant/0x07',
  };
  const digest = domainSha256(
    DOMAIN_PREFIX.WARRANT_ACTION,
    jcsCanonicalize(payload)
  );
  const sig = signDomainPayload(
    IFC_WARRANT_LABEL, digest, kp.privateKey
  );
  const payB64 = b64u(jcsCanonicalize(payload));
  return {
    token: `SIPIFC07.${payB64}.${sig}`,
    payload,
    actionDigest,
  };
}

export function verifyIfcWarrant0x07({
  workspaceDir,
  token,
  server,
  tool,
  args = {},
  scopeHash,
}) {
  try {
    if (typeof token !== 'string') {
      return { valid: false, reason: 'Missing warrant' };
    }
    const parts = token.trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'SIPIFC07') {
      return { valid: false, reason: 'Bad warrant format' };
    }
    const payBuf = unb64u(parts[1]);
    const payload = JSON.parse(payBuf.toString('utf8'));
    if (Date.now() > Number(payload.exp || 0)) {
      return { valid: false, reason: 'Warrant expired' };
    }
    const expectedDigest = computeNormalizedActionDigest({
      server, tool, args,
    });
    if (payload.actionDigest !== expectedDigest) {
      return { valid: false, reason: 'Digest mismatch' };
    }
    if (payload.scopeHash !== '*' &&
        scopeHash &&
        payload.scopeHash !== scopeHash) {
      return { valid: false, reason: 'Scope mismatch' };
    }
    const sipDir = path.join(
      path.resolve(workspaceDir), '.sip'
    );
    const kp = ensureDeviceEd25519Keypair(sipDir, {
      ephemeralOnly: true,
    });
    const digest = domainSha256(
      DOMAIN_PREFIX.WARRANT_ACTION,
      jcsCanonicalize(payload)
    );
    const ok = verifyDomainPayload(
      IFC_WARRANT_LABEL, digest, parts[2], kp.publicKey
    );
    if (!ok) {
      return { valid: false, reason: 'Invalid Ed25519 sig' };
    }
    const usedPath = path.join(
      sipDir, 'state', 'ifc-warrants-used.json'
    );
    let used = [];
    try {
      if (fs.existsSync(usedPath)) {
        used = JSON.parse(fs.readFileSync(usedPath, 'utf8'));
      }
    } catch {}
    if (used.includes(payload.jti)) {
      return { valid: false, reason: 'Warrant replayed' };
    }
    used.push(payload.jti);
    writeFileAtomic600(
      usedPath, JSON.stringify(used.slice(-256)) + '\n'
    );
    return { valid: true, jti: payload.jti };
  } catch {
    return { valid: false, reason: 'Warrant verify error' };
  }
}

export function beginIfcOperation({
  workspaceDir = process.cwd(),
  sessionId = null,
  server = 'mcp-server',
  tool = 'unknown',
  method = 'tools/call',
  args = {},
  warrantToken = null,
  warrantAlreadyVerified = false,
  hmacKeyPath = null,
  staleLockMs = STALE_LOCK_MS,
} = {}) {
  const paths = resolveIfcPaths({ workspaceDir, sessionId });
  const { key32 } = loadOrCreateIfcHmacKey({ hmacKeyPath });
  const caps = classifyIfcAction({
    server, tool, method, args,
    workspaceDir: paths.resolvedWs,
  });
  const opId = `${process.pid}-${Date.now()}-` +
    crypto.randomBytes(4).toString('hex');

  return withIfcLock(paths.lockPath, () => {
    const { state, tampered } = readAndVerifyState(
      paths.statePath, paths.scopeHash, key32
    );
    pruneStaleInFlight(state);

    const inflightVals = Object.values(state.inFlight);
    const inflightA = inflightVals.some((x) => x.A);
    const inflightBRaw = inflightVals.some((x) => x.B_raw);

    const activeA = state.taints.A || inflightA ||
      caps.readsUntrustedA;
    const activeBRaw = state.taints.B_raw || inflightBRaw ||
      caps.readsPrivateB;

    if (caps.egressC && (tampered || (activeA &&
        activeBRaw))) {
      let authorized = Boolean(warrantAlreadyVerified);
      if (!authorized && warrantToken) {
        const wv = verifyIfcWarrant0x07({
          workspaceDir: paths.resolvedWs,
          token: warrantToken,
          server, tool, args,
          scopeHash: paths.scopeHash,
        });
        authorized = wv.valid;
      }
      if (!authorized) {
        const saved = persistState(
          paths.statePath, state, key32
        );
        return {
          allowed: false,
          code: tampered
            ? 'IFC_STATE_TAMPERED_BLOCKED'
            : 'IFC_TRIFECTA_BLOCKED',
          ruleId: 'SIP-IFC-01',
          reason: tampered
            ? 'IFC state HMAC/seq tampered (fail-closed)'
            : 'Lethal Trifecta [A]+[B_raw]+[C_egress] ' +
              'blocked without 0x07 Ed25519 warrant',
          scopeHash: paths.scopeHash,
          seq: saved.seq,
          actionDigest: computeNormalizedActionDigest({
            server, tool, args,
          }),
          caps,
        };
      }
    }

    state.inFlight[opId] = {
      pid: process.pid,
      ts: Date.now(),
      server: String(server),
      tool: String(tool),
      A: caps.readsUntrustedA,
      B_raw: caps.readsPrivateB,
      C_local: caps.mutatesLocalC,
      C_egress: caps.egressC,
    };
    const saved = persistState(paths.statePath, state, key32);
    return {
      allowed: true,
      opId,
      scopeHash: paths.scopeHash,
      seq: saved.seq,
      caps,
      statePath: paths.statePath,
    };
  }, { staleMs: staleLockMs });
}

export function commitIfcOperation({
  workspaceDir = process.cwd(),
  sessionId = null,
  opId,
  caps = {},
  declassifiedByTwins = false,
  failed = false,
  hmacKeyPath = null,
  staleLockMs = STALE_LOCK_MS,
} = {}) {
  const paths = resolveIfcPaths({ workspaceDir, sessionId });
  const { key32 } = loadOrCreateIfcHmacKey({ hmacKeyPath });

  return withIfcLock(paths.lockPath, () => {
    const { state } = readAndVerifyState(
      paths.statePath, paths.scopeHash, key32
    );
    pruneStaleInFlight(state);
    if (opId && state.inFlight[opId]) {
      delete state.inFlight[opId];
    }
    if (!failed) {
      if (caps.readsUntrustedA) state.taints.A = true;
      if (caps.readsPrivateB) {
        if (declassifiedByTwins) {
          state.taints.B_twin = true;
        } else {
          state.taints.B_raw = true;
        }
      }
      if (caps.mutatesLocalC) {
        state.taints.C_local_count =
          (state.taints.C_local_count || 0) + 1;
      }
      if (caps.egressC) {
        state.taints.C_egress_count =
          (state.taints.C_egress_count || 0) + 1;
      }
      state.committedOps = (state.committedOps || 0) + 1;
    }
    const saved = persistState(paths.statePath, state, key32);
    return {
      ok: true,
      seq: saved.seq,
      taints: saved.taints,
      committedOps: saved.committedOps,
    };
  }, { staleMs: staleLockMs });
}

export function readIfcStateSnapshot({
  workspaceDir = process.cwd(),
  sessionId = null,
  hmacKeyPath = null,
} = {}) {
  const paths = resolveIfcPaths({ workspaceDir, sessionId });
  const { key32 } = loadOrCreateIfcHmacKey({ hmacKeyPath });
  return readAndVerifyState(
    paths.statePath, paths.scopeHash, key32
  );
}

export function resetIfcTurn({
  workspaceDir = process.cwd(),
  sessionId = null,
  hmacKeyPath = null,
} = {}) {
  const paths = resolveIfcPaths({ workspaceDir, sessionId });
  const { key32 } = loadOrCreateIfcHmacKey({ hmacKeyPath });
  return withIfcLock(paths.lockPath, () => {
    const { state } = readAndVerifyState(
      paths.statePath, paths.scopeHash, key32
    );
    state.taints.A = false;
    state.taints.B_raw = false;
    state.taints.B_twin = false;
    state.inFlight = {};
    state.tampered = false;
    return persistState(paths.statePath, state, key32);
  });
}

export async function beginIfcOperationAsync(
  opts = {}
) {
  const first = beginIfcOperation(opts);
  if (first.allowed ||
      first.code !== 'IFC_TRIFECTA_BLOCKED') {
    return first;
  }
  const tok = typeof opts.warrantToken === 'string'
    ? opts.warrantToken.trim() : '';
  if (!tok || tok.startsWith('SIPIFC07.')) {
    return first;
  }
  const wv = await verifyAndConsumeWarrant({
    workspaceDir: opts.workspaceDir || process.cwd(),
    tokenOrLeaseId: tok,
    server: opts.server || 'mcp-server',
    tool: opts.tool || 'unknown',
    args: opts.args || {},
    tier: 'TIER_2_WARRANT_REQUIRED',
  });
  if (wv.allowed) {
    return beginIfcOperation({
      ...opts,
      warrantAlreadyVerified: true,
    });
  }
  return {
    ...first,
    warrantError: wv.reason || wv.code || 'DENIED',
  };
}
