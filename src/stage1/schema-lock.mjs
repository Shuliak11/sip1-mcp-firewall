/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 1 RFC 8785 JCS + Ed25519 Schema Lock & Safe PreToolUse Hook Installer
 * Zero external dependencies. NEVER writes secret values into sip2.lock.json.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compareUtf16CodeUnits, jcsCanonicalize } from '../core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import {
  backupConfigBeforeEdit,
  normalizeCrossPlatformRelPath,
  parseJsoncSafe,
  withPidLock,
  writeFileAtomic600,
} from '../core/workspace-io.mjs';
import { redactStringForLockPreview } from './audit-scanner.mjs';

export { normalizeCrossPlatformRelPath };

export const SCHEMA_LOCK_SIGN_LABEL = 'SIP-v3-STAGE1-SCHEMA-LOCK';

/**
 * Normalize relative config path cleanly with forward slashes across macOS/Linux/Windows.
 * @param {string} workspaceDir
 * @param {string} filePath
 * @returns {string}
 */
function normalizeRelConfigPath(workspaceDir, filePath) {
  return normalizeCrossPlatformRelPath(workspaceDir, filePath);
}

/**
 * Build the canonical in-memory server specification hashed via RFC 8785 JCS + 0x06 SHA-256.
 * Notice: `env` and `headers` include ONLY sorted key names (`envKeysOnly`, `headerKeysOnly`).
 * Exact `command`, `args`, `transport`, `url` are committed into the one-way SHA-256 digest so
 * even a 1-byte Rug-Pull mutation is caught immediately, while `sip2.lock.json` only persists
 * redacted previews on disk!
 *
 * @param {any} srv
 * @param {string} workspaceDir
 */
export function buildCanonicalServerLockEntry(srv, workspaceDir) {
  const configPath = normalizeRelConfigPath(workspaceDir, srv.filePath);
  const envKeysOnly = Object.keys(srv.env || {}).sort(compareUtf16CodeUnits);
  const headerKeysOnly = Object.keys(srv.headers || {}).sort(compareUtf16CodeUnits);

  // Exact structural payload hashed in memory via RFC 8785 JCS
  const hashTarget = {
    args: Array.isArray(srv.args) ? srv.args.map((a) => String(a)) : [],
    client: String(srv.client || 'mcp-config'),
    command: srv.command ?? null,
    configPath,
    envKeysOnly,
    headerKeysOnly,
    serverName: String(srv.serverName),
    transport: String(srv.transport || (srv.url ? 'http' : 'stdio')),
    url: srv.url ?? null,
  };

  const jcsBuf = jcsCanonicalize(hashTarget);
  const digestBuf = domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, jcsBuf);
  const jcsSha256 = b64u(digestBuf);

  // Safe disk-serializable descriptor: NEVER contains raw env values, header values, or secret args/urls
  const persistedRecord = {
    argsCount: hashTarget.args.length,
    argsPreview: hashTarget.args.map((a) => redactStringForLockPreview(a) ?? ''),
    client: hashTarget.client,
    command: redactStringForLockPreview(hashTarget.command),
    configPath,
    envKeysOnly,
    headerKeysOnly,
    jcsSha256,
    serverName: hashTarget.serverName,
    transport: hashTarget.transport,
    url: redactStringForLockPreview(hashTarget.url),
  };

  return {
    serverKey: `${configPath}::${hashTarget.serverName}`,
    persistedRecord,
    jcsSha256,
  };
}

/**
 * Compute unsigned manifest core for deterministic signing and verification.
 * @param {{
 *   keyId: string,
 *   publicKeyB64u: string,
 *   servers: Array<any>,
 * }} params
 */
function buildUnsignedManifestCore({ keyId, publicKeyB64u, servers }) {
  return {
    canonicalization: 'RFC8785-JCS',
    domainPrefix: '0x06',
    keyId,
    publicKeyB64u,
    schemaVersion: 'sip2.lock/v3.0',
    servers,
    signatureAlgorithm: 'Ed25519',
    stage: 1,
  };
}

/**
 * Generate standalone `.sip/hooks/pre-tool-guard.mjs` script source.
 * Blocks execution with exit code 2 if `.sip/sip2.lock.json` is tampered/missing
 * or if Plane-14 / Bidi smuggling is detected in tool input stdin.
 *
 * @param {string} engineRootDir
 * @returns {string}
 */
function generatePreToolGuardScript(engineRootDir) {
  const discoveryImport = JSON.stringify(
    pathToFileURL(path.join(engineRootDir, 'stage1', 'config-discovery.mjs')).href
  );
  const lockImport = JSON.stringify(
    pathToFileURL(path.join(engineRootDir, 'stage1', 'schema-lock.mjs')).href
  );
  const scannerImport = JSON.stringify(
    pathToFileURL(path.join(engineRootDir, 'stage1', 'audit-scanner.mjs')).href
  );
  const stage2GuardImport = JSON.stringify(
    pathToFileURL(path.join(engineRootDir, 'stage2', 'guard-runner.mjs')).href
  );
  const shieldImport = JSON.stringify(
    pathToFileURL(path.join(engineRootDir, 'stage1',
      'auto-shield.mjs')).href
  );

  return `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

try {
  const [{ discoverMcpConfigs }, { verifySchemaLock },
    { scanUnicodeSmuggling },
    { evaluatePreToolGuard, formatGuardTerminalReport },
    { formatMultiDialectHookDecision }] =
    await Promise.all([
      import(${discoveryImport}),
      import(${lockImport}),
      import(${scannerImport}),
      import(${stage2GuardImport}),
      import(${shieldImport}),
    ]);
  const argD = process.argv.find(
    (a) => a.startsWith('--dialect=')
  );
  const dialect = (argD ? argD.slice(10) :
    process.env.SIP_HOOK_DIALECT || 'claude'
  ).toLowerCase();
  const emitBlock = (reason, code, report) => {
    const d = formatMultiDialectHookDecision(dialect, {
      blocked: true, reason, code, reportText: report,
    });
    if (d.stdout) process.stdout.write(d.stdout);
    if (d.stderr) process.stderr.write(d.stderr);
    process.exit(d.exitCode);
  };

  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const inferredRoot = path.resolve(scriptDir, '..', '..');
  const workspaceDir = path.resolve(
    process.env.CLAUDE_PROJECT_DIR ||
      process.env.CURSOR_PROJECT_DIR ||
      (fs.existsSync(path.join(process.cwd(), '.sip')) ? process.cwd() : inferredRoot)
  );

  let stdinPayload = '';
  try {
    if (!process.stdin.isTTY) {
      stdinPayload = fs.readFileSync(0, 'utf8');
    }
  } catch {
    // Ignore empty stdin
  }

  if (stdinPayload) {
    const smuggling = scanUnicodeSmuggling(stdinPayload);
    if (smuggling.length > 0) {
      process.stderr.write(
        '[SHULIAK SIP QUARANTINE] Blocked tool execution: Unicode Plane-14 / Bidi smuggling payload detected (' +
          smuggling[0].codePointHex +
          ').\\n'
      );
      process.exit(2);
    }
  }

  const configs = discoverMcpConfigs({ workspaceDir, includeGlobal: false });
  const verification = verifySchemaLock({ workspaceDir, configs });
  if (!verification.valid) {
    const reason = verification.driftDetails?.[0]?.message || verification.status;
    process.stderr.write(
      '[SHULIAK SIP QUARANTINE] Blocked tool execution: MCP schema lock verification failed (' +
        reason +
        ').\\n'
    );
    process.exit(2);
  }

  if (stdinPayload && stdinPayload.trim()) {
    let hookEvent = null;
    try {
      hookEvent = JSON.parse(stdinPayload);
    } catch {
      hookEvent = null;
    }
    if (hookEvent && typeof hookEvent === 'object') {
      const resolvedToolName =
        typeof hookEvent.tool_name === 'string'
          ? hookEvent.tool_name
          : typeof hookEvent.toolName === 'string'
            ? hookEvent.toolName
            : typeof hookEvent.tool === 'string'
              ? hookEvent.tool
              : typeof hookEvent.command === 'string'
                ? 'Bash'
                : null;

      if (resolvedToolName) {
        const serverName =
          typeof hookEvent.server_name === 'string'
            ? hookEvent.server_name
            : typeof hookEvent.serverName === 'string'
              ? hookEvent.serverName
              : typeof hookEvent.mcpServer === 'string'
                ? hookEvent.mcpServer
                : 'ide-hook';
        const rawInput =
          hookEvent.tool_input ??
          hookEvent.arguments ??
          hookEvent.parameters ??
          hookEvent.input ??
          (typeof hookEvent.command === 'string' ? { command: hookEvent.command } : {});
        const toolInput = rawInput && typeof rawInput === 'object' ? rawInput : {};

        const outcome = await evaluatePreToolGuard({
          workspaceDir,
          server: serverName,
          tool: resolvedToolName,
          args: toolInput,
          warrantToken: process.env.SIP_WARRANT_TOKEN || null,
        });
        if (outcome.exitCode !== 0) {
          emitBlock(
            outcome.reason,
            outcome.code,
            formatGuardTerminalReport(outcome)
          );
        }
      }
    }
  }

  process.exit(0);
} catch (err) {
  process.stderr.write(
    '[SHULIAK SIP FAIL-CLOSED GUARD ERROR] Blocking tool execution due to guard integrity failure: ' +
      (err && err.message ? err.message : String(err)) +
      '\\n'
  );
  process.exit(2);
}
`;
}

/**
 * Create or update `.sip/sip2.lock.json` using RFC 8785 JCS + 0x06 SHA-256 + Ed25519 signature.
 * - When `dryRun: true`, performs zero disk writes (leaves zero files/directories on disk).
 * - When `installHooks: true` (and not `dryRun`), backs up `.claude/settings.local.json` (if present),
 *   writes `.sip/hooks/pre-tool-guard.mjs`, registers `PreToolUse` guard, and installs `.git/hooks/pre-commit`
 *   if `.git` exists.
 *
 * @param {{
 *   workspaceDir: string,
 *   configs: Array<any>,
 *   dryRun?: boolean,
 *   installHooks?: boolean,
 * }} params
 */
export async function createOrUpdateSchemaLock({
  workspaceDir,
  configs,
  dryRun = false,
  installHooks = false,
}) {
  const resolvedWorkspace = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWorkspace, '.sip');
  const lockPath = path.join(sipDir, 'sip2.lock.json');

  const allEntries = [];
  for (const cfg of configs || []) {
    if (cfg.parseError) {
      throw new Error(`Cannot seal malformed config ${cfg.filePath}: ${cfg.parseError.message}`);
    }
    for (const srv of cfg.servers || []) {
      allEntries.push(buildCanonicalServerLockEntry(srv, resolvedWorkspace));
    }
  }

  allEntries.sort((a, b) => compareUtf16CodeUnits(a.serverKey, b.serverKey));
  const sortedServerRecords = allEntries.map((e) => e.persistedRecord);

  if (dryRun) {
    const keyInfo = ensureDeviceEd25519Keypair(sipDir, { ephemeralOnly: true });
    const unsignedCore = buildUnsignedManifestCore({
      keyId: keyInfo.keyId,
      publicKeyB64u: keyInfo.publicKeyB64u,
      servers: sortedServerRecords,
    });
    const coreJcsBuf = jcsCanonicalize(unsignedCore);
    const manifestDigestBuf = domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, coreJcsBuf);
    const manifestDigestB64u = b64u(manifestDigestBuf);
    const signatureB64u = signDomainPayload(
      SCHEMA_LOCK_SIGN_LABEL,
      manifestDigestBuf,
      keyInfo.privateKey
    );

    const lockManifest = {
      ...unsignedCore,
      manifestDigestB64u,
      signatureB64u,
    };

    return {
      dryRun: true,
      written: false,
      lockPath,
      backupsCreated: [],
      hooksInstalled: [],
      lockManifest,
    };
  }

  return withPidLock(sipDir, async () => {
    const backupsCreated = [];
    const hooksInstalled = [];

    if (fs.existsSync(lockPath)) {
      const bkp = backupConfigBeforeEdit(lockPath);
      if (bkp) backupsCreated.push(bkp);
    }

    const keyInfo = ensureDeviceEd25519Keypair(sipDir, { ephemeralOnly: false });
    const unsignedCore = buildUnsignedManifestCore({
      keyId: keyInfo.keyId,
      publicKeyB64u: keyInfo.publicKeyB64u,
      servers: sortedServerRecords,
    });
    const coreJcsBuf = jcsCanonicalize(unsignedCore);
    const manifestDigestBuf = domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, coreJcsBuf);
    const manifestDigestB64u = b64u(manifestDigestBuf);
    const signatureB64u = signDomainPayload(
      SCHEMA_LOCK_SIGN_LABEL,
      manifestDigestBuf,
      keyInfo.privateKey
    );

    const lockManifest = {
      ...unsignedCore,
      manifestDigestB64u,
      signatureB64u,
    };

    writeFileAtomic600(lockPath, JSON.stringify(lockManifest, null, 2) + '\n');

    if (installHooks) {
      const engineSrcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
      const guardPath = path.join(sipDir, 'hooks', 'pre-tool-guard.mjs');
      writeFileAtomic600(guardPath, generatePreToolGuardScript(engineSrcDir), { mode: 0o700 });
      hooksInstalled.push(guardPath);

      // Safely back up `.claude/settings.local.json` if present and wire PreToolUse guard
      const claudeSettingsPath = path.join(resolvedWorkspace, '.claude', 'settings.local.json');
      let settingsObj = {};
      if (fs.existsSync(claudeSettingsPath)) {
        const bkp = backupConfigBeforeEdit(claudeSettingsPath);
        if (bkp) backupsCreated.push(bkp);
        try {
          settingsObj = parseJsoncSafe(fs.readFileSync(claudeSettingsPath, 'utf8')) || {};
        } catch {
          settingsObj = {};
        }
      }

      if (!settingsObj.hooks || typeof settingsObj.hooks !== 'object') {
        settingsObj.hooks = {};
      }
      const claudeGuardCommand = 'node "$CLAUDE_PROJECT_DIR/.sip/hooks/pre-tool-guard.mjs"';
      const existingPre = Array.isArray(settingsObj.hooks.PreToolUse)
        ? settingsObj.hooks.PreToolUse
        : [];
      const alreadyWired = existingPre.some((entry) => JSON.stringify(entry).includes('pre-tool-guard.mjs'));
      if (!alreadyWired) {
        existingPre.push({
          matcher: '.*',
          hooks: [{ type: 'command', command: claudeGuardCommand }],
        });
      }
      settingsObj.hooks.PreToolUse = existingPre;
      writeFileAtomic600(claudeSettingsPath, JSON.stringify(settingsObj, null, 2) + '\n');
      hooksInstalled.push(claudeSettingsPath);

      // Safely back up `.cursor/hooks.json` if present and wire Cursor `beforeMCPExecution` failClosed hook
      const cursorHooksPath = path.join(resolvedWorkspace, '.cursor', 'hooks.json');
      let cursorHooksObj = { version: 1, hooks: {} };
      if (fs.existsSync(cursorHooksPath)) {
        const bkp = backupConfigBeforeEdit(cursorHooksPath);
        if (bkp) backupsCreated.push(bkp);
        try {
          const parsedCursor = parseJsoncSafe(fs.readFileSync(cursorHooksPath, 'utf8'));
          if (parsedCursor && typeof parsedCursor === 'object' && !Array.isArray(parsedCursor)) {
            cursorHooksObj = parsedCursor;
          }
        } catch {
          cursorHooksObj = { version: 1, hooks: {} };
        }
      }
      if (!cursorHooksObj.version) {
        cursorHooksObj.version = 1;
      }
      if (!cursorHooksObj.hooks || typeof cursorHooksObj.hooks !== 'object') {
        cursorHooksObj.hooks = {};
      }
      const cursorGuardCommand = 'node .sip/hooks/pre-tool-guard.mjs';
      const existingBeforeMcp = Array.isArray(cursorHooksObj.hooks.beforeMCPExecution)
        ? cursorHooksObj.hooks.beforeMCPExecution
        : [];
      const cursorAlreadyWired = existingBeforeMcp.some((entry) =>
        JSON.stringify(entry).includes('pre-tool-guard.mjs')
      );
      if (!cursorAlreadyWired) {
        existingBeforeMcp.push({
          command: cursorGuardCommand,
          failClosed: true,
        });
      }
      cursorHooksObj.hooks.beforeMCPExecution = existingBeforeMcp;
      writeFileAtomic600(cursorHooksPath, JSON.stringify(cursorHooksObj, null, 2) + '\n');
      hooksInstalled.push(cursorHooksPath);

      // Optional `.git/hooks/pre-commit` verifier if `.git` exists
      const gitDir = path.join(resolvedWorkspace, '.git');
      if (fs.existsSync(gitDir) && fs.statSync(gitDir).isDirectory()) {
        const preCommitPath = path.join(gitDir, 'hooks', 'pre-commit');
        if (fs.existsSync(preCommitPath)) {
          const bkp = backupConfigBeforeEdit(preCommitPath);
          if (bkp) backupsCreated.push(bkp);
        }
        const cliScriptPath = path.join(engineSrcDir, 'cli.mjs').replace(/\\/g, '/');
        const hookScript = `#!/bin/sh\n# SHULIAK SIP v3.0 Pre-Commit Schema Lock Verifier\nnode "${cliScriptPath}" verify-lock --no-global || exit 1\n`;
        writeFileAtomic600(preCommitPath, hookScript, { mode: 0o755 });
        hooksInstalled.push(preCommitPath);
      }
    }

    return {
      dryRun: false,
      written: true,
      lockPath,
      backupsCreated,
      hooksInstalled,
      lockManifest,
    };
  });
}

/**
 * Verify `.sip/sip2.lock.json` cryptographic integrity and check current MCP configs for drift.
 * Catches both:
 * 1) Manual forgery/edits inside `sip2.lock.json` (Ed25519 signature or manifest JCS digest mismatch)
 * 2) Even a 1-character Rug-Pull mutation in server `args`, `command`, `url`, `envKeysOnly`, etc.
 *
 * @param {{
 *   workspaceDir: string,
 *   configs: Array<any>,
 * }} params
 */
export function verifySchemaLock({ workspaceDir, configs }) {
  const resolvedWorkspace = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWorkspace, '.sip');
  const lockPath = path.join(sipDir, 'sip2.lock.json');
  const pubPath = path.join(sipDir, 'device.ed25519.pub');

  if (!fs.existsSync(lockPath)) {
    return {
      valid: false,
      status: 'MISSING_LOCK',
      signatureValid: false,
      manifestDigestValid: false,
      driftDetails: [
        {
          reason: 'MISSING_LOCK',
          message: '.sip/sip2.lock.json does not exist in workspace',
        },
      ],
      lock: null,
    };
  }

  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  } catch (err) {
    return {
      valid: false,
      status: 'CORRUPTED_LOCK_JSON',
      signatureValid: false,
      manifestDigestValid: false,
      driftDetails: [
        {
          reason: 'CORRUPTED_LOCK_JSON',
          message: `sip2.lock.json is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
      lock: null,
    };
  }

  if (
    !lock ||
    typeof lock !== 'object' ||
    lock.schemaVersion !== 'sip2.lock/v3.0' ||
    !Array.isArray(lock.servers) ||
    typeof lock.publicKeyB64u !== 'string' ||
    typeof lock.manifestDigestB64u !== 'string' ||
    typeof lock.signatureB64u !== 'string'
  ) {
    return {
      valid: false,
      status: 'INVALID_LOCK_SCHEMA',
      signatureValid: false,
      manifestDigestValid: false,
      driftDetails: [
        {
          reason: 'INVALID_LOCK_SCHEMA',
          message: 'sip2.lock.json schema structure is invalid or incomplete',
        },
      ],
      lock,
    };
  }

  // Verify device public key pinning against `.sip/device.ed25519.pub` if present on disk
  let trustedPublicKeyB64u = lock.publicKeyB64u;
  if (fs.existsSync(pubPath)) {
    const diskPub = fs.readFileSync(pubPath, 'utf8').trim();
    if (diskPub && diskPub !== lock.publicKeyB64u) {
      return {
        valid: false,
        status: 'DEVICE_KEY_MISMATCH',
        signatureValid: false,
        manifestDigestValid: false,
        driftDetails: [
          {
            reason: 'DEVICE_KEY_MISMATCH',
            message: 'sip2.lock.json publicKeyB64u does not match pinned .sip/device.ed25519.pub',
          },
        ],
        lock,
      };
    }
    if (diskPub) {
      trustedPublicKeyB64u = diskPub;
    }
  }

  // Recompute RFC 8785 JCS manifest digest over unsigned fields
  const unsignedCore = buildUnsignedManifestCore({
    keyId: lock.keyId,
    publicKeyB64u: lock.publicKeyB64u,
    servers: lock.servers,
  });
  const expectedDigestBuf = domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, jcsCanonicalize(unsignedCore));
  const expectedDigestB64u = b64u(expectedDigestBuf);
  const manifestDigestValid = expectedDigestB64u === lock.manifestDigestB64u;

  const signatureValid =
    manifestDigestValid &&
    verifyDomainPayload(
      SCHEMA_LOCK_SIGN_LABEL,
      expectedDigestBuf,
      lock.signatureB64u,
      trustedPublicKeyB64u
    );

  if (!manifestDigestValid || !signatureValid) {
    return {
      valid: false,
      status: 'SIGNATURE_FORGERY_DETECTED',
      signatureValid,
      manifestDigestValid,
      driftDetails: [
        {
          reason: 'SIGNATURE_FORGERY_DETECTED',
          message: !manifestDigestValid
            ? 'RFC 8785 JCS manifest digest mismatch inside sip2.lock.json (tampered lockfile)'
            : 'Ed25519 signature verification failed on sip2.lock.json (forged lockfile)',
        },
      ],
      lock,
    };
  }

  // Compare live discovered server JCS digests against sealed lock entries
  /** @type {Map<string, string>} */
  const lockedMap = new Map();
  for (const s of lock.servers) {
    const key = `${s.configPath}::${s.serverName}`;
    lockedMap.set(key, s.jcsSha256);
  }

  /** @type {Map<string, string>} */
  const liveMap = new Map();
  const driftDetails = [];

  for (const cfg of configs || []) {
    if (cfg.parseError) {
      driftDetails.push({
        reason: 'CONFIG_PARSE_ERROR',
        serverKey: normalizeRelConfigPath(resolvedWorkspace, cfg.filePath),
        message: `Config file ${cfg.filePath} contains syntax errors`,
      });
      continue;
    }
    for (const srv of cfg.servers || []) {
      const liveEntry = buildCanonicalServerLockEntry(srv, resolvedWorkspace);
      liveMap.set(liveEntry.serverKey, liveEntry.jcsSha256);

      if (!lockedMap.has(liveEntry.serverKey)) {
        driftDetails.push({
          reason: 'UNSEALED_SERVER_ADDED',
          serverKey: liveEntry.serverKey,
          expectedDigest: null,
          actualDigest: liveEntry.jcsSha256,
          message: `Unsealed MCP server "${liveEntry.serverKey}" added after lock`,
        });
      } else if (lockedMap.get(liveEntry.serverKey) !== liveEntry.jcsSha256) {
        driftDetails.push({
          reason: 'SERVER_DIGEST_DRIFT',
          serverKey: liveEntry.serverKey,
          expectedDigest: lockedMap.get(liveEntry.serverKey),
          actualDigest: liveEntry.jcsSha256,
          message: `RFC 8785 JCS digest mismatch on "${liveEntry.serverKey}" (Rug-Pull / config mutation detected)`,
        });
      }
    }
  }

  for (const [lockedKey, lockedDigest] of lockedMap.entries()) {
    if (!liveMap.has(lockedKey)) {
      driftDetails.push({
        reason: 'LOCKED_SERVER_REMOVED',
        serverKey: lockedKey,
        expectedDigest: lockedDigest,
        actualDigest: null,
        message: `Locked MCP server "${lockedKey}" was removed from workspace configuration`,
      });
    }
  }

  const valid = driftDetails.length === 0;
  return {
    valid,
    status: valid ? 'VERIFIED' : 'DRIFT_DETECTED',
    signatureValid: true,
    manifestDigestValid: true,
    driftDetails,
    lock,
  };
}
