#!/usr/bin/env node
import { realpathSync as __sipRealpathSync } from 'node:fs';
if (process.argv[1]) {
  try {
    process.argv[1] = __sipRealpathSync(process.argv[1]);
  } catch {
    // Preserve original argv[1] when virtual or non-existent
  }
}
/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 (@shuliak-corp/sip1-mcp v3.1.0) - Executable Zero-Dependency CLI & Stdio Server
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SipPipelineBus } from './core/pipeline-bus.mjs';
import { discoverMcpConfigs } from './stage1/config-discovery.mjs';
import {
  TERMINAL_BOX_WIDTH,
  formatAuditSarif,
  formatAuditTerminalReport,
  runStaticMcpAudit,
  wrapBoxRow78,
} from './stage1/audit-scanner.mjs';
import { createOrUpdateSchemaLock, verifySchemaLock } from './stage1/schema-lock.mjs';
import {
  applyShieldToWorkspace,
  rollbackShieldInWorkspace,
} from './stage1/auto-shield.mjs';
import {
  clearLockdown,
  getLockdownStatus,
  plantCanaryToken,
} from './stage2/canary-trap.mjs';
import { resetFinOpsFuse } from './stage2/finops-fuse.mjs';
import { evaluatePreToolGuard, formatGuardTerminalReport } from './stage2/guard-runner.mjs';
import {
  captureShadowSnapshot,
  listShadowTransactions,
  rollbackLastTransaction,
} from './stage2/shadow-undo.mjs';
import { issueOneShotWarrant, issueScopedLease } from './stage2/warrant-engine.mjs';
import { ensureDeviceEd25519Keypair } from './core/crypto-primitives.mjs';
import { backupConfigBeforeEdit, withPidLock, writeFileAtomic600 } from './core/workspace-io.mjs';
import {
  closeKeyring,
  executeGdprShredding,
  initKeyring,
  initOrOpenKeyring,
  openKeyring,
  recordAgentEvent,
  resolveIsepPaths,
  setSubjectLitigationHold,
  verifyIsepChainQuick,
} from './stage3/isep-engine.mjs';
import {
  activateWorkspaceLicense,
  inspectWorkspaceEntitlement,
} from './stage4/license-authority.mjs';
import {
  analyzeEnterpriseScopeExposure,
  generateCycloneDxAibom,
} from './stage4/cyclonedx-aibom.mjs';
import {
  generateAuditorAttestationBundle,
  verifyAttestationCertificateOffline,
} from './stage4/auditor-attestation.mjs';
import { extractAndVerifyPdfBytes } from './stage4/pdf-generator.mjs';
import {
  formatAuditMarkdownPrComment,
  generateGithubPrWorkflowYaml,
  generateRepoBadgeSvg,
} from './stage4/pr-cicd-gate.mjs';
import { runZeroEgressSelfTest } from './stage4/zero-egress-selftest.mjs';
import {
  generateSignedIsepMerkleProof,
} from './stage3/rfc9162-merkle.mjs';
import {
  createSignedCiReceipt,
  generateMdmExportBundle,
  loadWorkspaceTeamPolicy,
  verifyEnterpriseFleet,
} from './stage4/mdm-fleet.mjs';
import { runMcpStdioServer } from './stage5/mcp-stdio-server.mjs';
import { runMcpWrapProxy } from './stage5/mcp-wrap-proxy.mjs';
import { runHardwareBenchmark, runInteractiveDemo } from './stage5/instant-demo-bench.mjs';

export const CLI_VERSION = '3.1.0';

const GRADE_SEVERITY_RANK = Object.freeze({
  'A+': 0,
  A: 1,
  B: 2,
  C: 3,
  D: 4,
  F: 5,
});

function buildQuickstartHelpText() {
  const eq = '+' + '='.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
  const hr = '+' + '-'.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
  const row = (txt, indent = '  ') => wrapBoxRow78(txt, indent);
  return (
    [
      eq,
      row(`[SHULIAK SIP v3.0 - @shuliak-corp/sip1-mcp v${CLI_VERSION}]`),
      row('[ZERO-EGRESS MCP FIREWALL, RFC 8785 LOCK, ISEP v3.0 & ATTESTATION]'),
      eq,
      row('1. Free Open-Core (Apache-2.0):'),
      row('   demo | audit | shield | lock | verify-lock | wrap | serve | bench'),
      row('2. Runtime SecOps ($79/mo):'),
      row('   guard | warrant | undo | canary | finops | audit --signed-receipt'),
      row('3. Compliance Shield ($299/mo):'),
      row('   isep | prove | attest | verify-cert | aibom | license | init-ci'),
      row('4. Enterprise Sovereign ($990/mo):'),
      row('   mdm-export | fleet-verify'),
      hr,
      row('QUICKSTART COMMANDS:'),
      row('  $ sip1-mcp demo [--out-dir <dir>] [--json]'),
      row('  $ sip1-mcp audit [--dir <p>] [--signed-receipt] [--ci]'),
      row('  $ sip1-mcp shield [--dir <p>] [--apply | --rollback | --dry-run]'),
      row('  $ sip1-mcp lock [--dir <p>] [--install-hooks] [--dry-run]'),
      row('  $ sip1-mcp prove --seq <N> [--compare-size <M>] [--json]'),
      row('  $ sip1-mcp mdm-export [--platform macos|windows|all]'),
      row('  $ sip1-mcp fleet-verify --fleet-dir <dir> [--json]'),
      row('  $ sip1-mcp wrap --server <name> [--no-isep] -- <cmd> [args...]'),
      row('  $ sip1-mcp serve [--dir <p>]   (auto-started when stdin is piped)'),
      row('  $ sip1-mcp bench [--iterations <200>] [--json]'),
      row('  $ sip1-mcp guard --server <s> --tool <t> [--args <json>]'),
      row('  $ sip1-mcp isep <init|record|shred|hold|verify> [--dir <p>]'),
      row('  $ sip1-mcp attest [--preview] [--partner <code>] [--out-dir <dir>]'),
      hr,
      row('FLAGS: --dir <p> | --no-global | --json | --no-color | --version | --help'),
      row('DOCS & COMMERCIAL LICENSING: https://shuliak.dev/#pricing'),
      eq,
    ].join('\n') + '\n'
  );
}

const HELP_TEXT = buildQuickstartHelpText();

const ANSI_ESCAPE_RE = /\x1b\[[0-9;]*m/g;

/**
 * Parse CLI argv into structured command, subcommand & flags without external dependencies.
 * Preserves verbatim downstream arguments after `--` for `sip1-mcp wrap`.
 * @param {string[]} argv
 */
export function parseCliArgs(argv) {
  const rawArgs = Array.isArray(argv) ? [...argv] : [];
  const dashDashIdx = rawArgs.indexOf('--');
  const args = dashDashIdx >= 0 ? rawArgs.slice(0, dashDashIdx) : rawArgs;
  const passthroughArgs = dashDashIdx >= 0 ? rawArgs.slice(dashDashIdx + 1) : [];
  let command = '';
  let subcommand = '';
  let dir = process.cwd();
  let includeGlobal = true;
  let json = false;
  let format = 'terminal';
  let ci = false;
  /** @type {'A' | 'B' | 'C' | 'D' | 'F' | null} */
  let failOn = null;
  let dryRun = false;
  let installHooks = false;
  let help = false;
  let version = false;

  // Stage 2 flags
  let server = '';
  let tool = '';
  let toolArgsRaw = '{}';
  /** @type {string | null} */
  let warrant = null;
  let lease = false;
  /** @type {string[] | null} */
  let allowedTools = null;
  let pathPrefix = '';
  /** @type {number | null} */
  let ttl = null;
  /** @type {number | null} */
  let maxCalls = null;
  let reason = '';
  let tx = '';
  /** @type {string[]} */
  let files = [];
  let label = '';
  let kind = 'AWS_KEY';
  let decoyFile = false;

  // Stage 3 ISEP flags
  /** @type {number | null} */
  let buckets = null;
  /** @type {string | null} */
  let prompt = null;
  let subject = '';
  let ticket = '';
  let release = false;
  let force = false;

  // Stage 4 Commercial & CI/CD flags
  let preview = false;
  /** @type {string | null} */
  let partner = null;
  /** @type {string | null} */
  let outDir = null;
  /** @type {string | null} */
  let out = null;
  /** @type {string | null} */
  let file = null;
  /** @type {string | null} */
  let licenseToken = null;
  /** @type {string | null} */
  let authorityPub = null;

  // Stage 5 Unified MCP / Proxy / Demo / Benchmark flags
  let noColor = Boolean(process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '');
  let enableIsep = true;
  /** @type {number | null} */
  let iterations = null;
  /** @type {string | null} */
  let wrapCommandFlag = null;
  let apply = false;
  let rollback = false;
  let excludeTools = null;
  let spillBytes = null;
  let seq = null;
  let compareSize = null;
  let signedReceipt = false;
  let template = 'general';
  let platform = 'all';
  let fleetDir = null;

  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    if (token === '--help' || token === '-h') {
      help = true;
    } else if (token === '--version' || token === '-v') {
      version = true;
    } else if (token === '--dir' && i + 1 < args.length) {
      dir = path.resolve(args[++i]);
    } else if (token.startsWith('--dir=')) {
      dir = path.resolve(token.slice('--dir='.length));
    } else if (token === '--no-global') {
      includeGlobal = false;
    } else if (token === '--json') {
      json = true;
      format = 'json';
    } else if (token === '--format' && i + 1 < args.length) {
      format = args[++i].toLowerCase();
    } else if (token.startsWith('--format=')) {
      format = token.slice('--format='.length).toLowerCase();
    } else if (token === '--ci') {
      ci = true;
    } else if (token === '--fail-on' && i + 1 < args.length) {
      const g = args[++i].toUpperCase();
      if (!['A', 'B', 'C', 'D', 'F'].includes(g)) {
        throw new Error(`Invalid --fail-on grade "${g}". Expected A, B, C, D, or F.`);
      }
      failOn = /** @type {'A' | 'B' | 'C' | 'D' | 'F'} */ (g);
    } else if (token.startsWith('--fail-on=')) {
      const g = token.slice('--fail-on='.length).toUpperCase();
      if (!['A', 'B', 'C', 'D', 'F'].includes(g)) {
        throw new Error(`Invalid --fail-on grade "${g}". Expected A, B, C, D, or F.`);
      }
      failOn = /** @type {'A' | 'B' | 'C' | 'D' | 'F'} */ (g);
    } else if (token === '--dry-run') {
      dryRun = true;
    } else if (token === '--install-hooks') {
      installHooks = true;
    } else if (token === '--server' && i + 1 < args.length) {
      server = args[++i];
    } else if (token.startsWith('--server=')) {
      server = token.slice('--server='.length);
    } else if (token === '--tool' && i + 1 < args.length) {
      tool = args[++i];
    } else if (token.startsWith('--tool=')) {
      tool = token.slice('--tool='.length);
    } else if (token === '--args' && i + 1 < args.length) {
      toolArgsRaw = args[++i];
    } else if (token.startsWith('--args=')) {
      toolArgsRaw = token.slice('--args='.length);
    } else if (token === '--warrant' && i + 1 < args.length) {
      warrant = args[++i];
    } else if (token.startsWith('--warrant=')) {
      warrant = token.slice('--warrant='.length);
    } else if (token === '--lease') {
      lease = true;
    } else if (token === '--allowed-tools' && i + 1 < args.length) {
      allowedTools = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (token.startsWith('--allowed-tools=')) {
      allowedTools = token.slice('--allowed-tools='.length).split(',').map((s) => s.trim()).filter(Boolean);
    } else if (token === '--allow-tools' &&
               i + 1 < args.length) {
      allowedTools = args[++i].split(',')
        .map((x) => x.trim()).filter(Boolean);
    } else if (token.startsWith('--allow-tools=')) {
      allowedTools = token.slice(14).split(',')
        .map((x) => x.trim()).filter(Boolean);
    } else if (token === '--exclude-tools' &&
               i + 1 < args.length) {
      excludeTools = args[++i].split(',')
        .map((x) => x.trim()).filter(Boolean);
    } else if (token.startsWith('--exclude-tools=')) {
      excludeTools = token.slice(16).split(',')
        .map((x) => x.trim()).filter(Boolean);
    } else if (token === '--apply') {
      apply = true;
    } else if (token === '--rollback') {
      rollback = true;
    } else if (token === '--spill-bytes' &&
               i + 1 < args.length) {
      spillBytes = Number(args[++i]);
    } else if (token.startsWith('--spill-bytes=')) {
      spillBytes = Number(token.slice(14));
    } else if (token === '--seq' &&
               i + 1 < args.length) {
      seq = Number(args[++i]);
    } else if (token.startsWith('--seq=')) {
      seq = Number(token.slice(6));
    } else if (token === '--compare-size' &&
               i + 1 < args.length) {
      compareSize = Number(args[++i]);
    } else if (token.startsWith('--compare-size=')) {
      compareSize = Number(token.slice(15));
    } else if (token === '--signed-receipt') {
      signedReceipt = true;
    } else if (token === '--template' &&
               i + 1 < args.length) {
      template = args[++i].toLowerCase();
    } else if (token.startsWith('--template=')) {
      template = token.slice(11).toLowerCase();
    } else if (token === '--platform' &&
               i + 1 < args.length) {
      platform = args[++i].toLowerCase();
    } else if (token.startsWith('--platform=')) {
      platform = token.slice(11).toLowerCase();
    } else if (token === '--fleet-dir' &&
               i + 1 < args.length) {
      fleetDir = path.resolve(args[++i]);
    } else if (token.startsWith('--fleet-dir=')) {
      fleetDir = path.resolve(token.slice(12));
    } else if (token === '--path-prefix' && i + 1 < args.length) {
      pathPrefix = args[++i];
    } else if (token.startsWith('--path-prefix=')) {
      pathPrefix = token.slice('--path-prefix='.length);
    } else if (token === '--ttl' && i + 1 < args.length) {
      ttl = Number(args[++i]);
    } else if (token.startsWith('--ttl=')) {
      ttl = Number(token.slice('--ttl='.length));
    } else if (token === '--max-calls' && i + 1 < args.length) {
      maxCalls = Number(args[++i]);
    } else if (token.startsWith('--max-calls=')) {
      maxCalls = Number(token.slice('--max-calls='.length));
    } else if (token === '--reason' && i + 1 < args.length) {
      reason = args[++i];
    } else if (token.startsWith('--reason=')) {
      reason = token.slice('--reason='.length);
    } else if (token === '--tx' && i + 1 < args.length) {
      tx = args[++i];
    } else if (token.startsWith('--tx=')) {
      tx = token.slice('--tx='.length);
    } else if (token === '--files' && i + 1 < args.length) {
      files = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if (token.startsWith('--files=')) {
      files = token.slice('--files='.length).split(',').map((s) => s.trim()).filter(Boolean);
    } else if (token === '--label' && i + 1 < args.length) {
      label = args[++i];
    } else if (token.startsWith('--label=')) {
      label = token.slice('--label='.length);
    } else if (token === '--kind' && i + 1 < args.length) {
      kind = args[++i];
    } else if (token.startsWith('--kind=')) {
      kind = token.slice('--kind='.length);
    } else if (token === '--decoy-file') {
      decoyFile = true;
    } else if (token === '--buckets' && i + 1 < args.length) {
      buckets = Number(args[++i]);
    } else if (token.startsWith('--buckets=')) {
      buckets = Number(token.slice('--buckets='.length));
    } else if (token === '--prompt' && i + 1 < args.length) {
      prompt = args[++i];
    } else if (token.startsWith('--prompt=')) {
      prompt = token.slice('--prompt='.length);
    } else if (token === '--subject' && i + 1 < args.length) {
      subject = args[++i];
    } else if (token.startsWith('--subject=')) {
      subject = token.slice('--subject='.length);
    } else if (token === '--ticket' && i + 1 < args.length) {
      ticket = args[++i];
    } else if (token.startsWith('--ticket=')) {
      ticket = token.slice('--ticket='.length);
    } else if (token === '--release') {
      release = true;
    } else if (token === '--force') {
      force = true;
    } else if (token === '--preview') {
      preview = true;
    } else if (token === '--partner' && i + 1 < args.length) {
      partner = args[++i];
    } else if (token.startsWith('--partner=')) {
      partner = token.slice('--partner='.length);
    } else if (token === '--out-dir' && i + 1 < args.length) {
      outDir = path.resolve(args[++i]);
    } else if (token.startsWith('--out-dir=')) {
      outDir = path.resolve(token.slice('--out-dir='.length));
    } else if (token === '--out' && i + 1 < args.length) {
      out = args[++i];
    } else if (token.startsWith('--out=')) {
      out = token.slice('--out='.length);
    } else if (token === '--file' && i + 1 < args.length) {
      file = args[++i];
    } else if (token.startsWith('--file=')) {
      file = token.slice('--file='.length);
    } else if (token === '--token' && i + 1 < args.length) {
      licenseToken = args[++i];
    } else if (token.startsWith('--token=')) {
      licenseToken = token.slice('--token='.length);
    } else if (token === '--key' && i + 1 < args.length) {
      licenseToken = args[++i];
    } else if (token.startsWith('--key=')) {
      licenseToken = token.slice('--key='.length);
    } else if (token === '--authority-pub' && i + 1 < args.length) {
      authorityPub = args[++i];
    } else if (token.startsWith('--authority-pub=')) {
      authorityPub = token.slice('--authority-pub='.length);
    } else if (token === '--no-color') {
      noColor = true;
    } else if (token === '--no-isep') {
      enableIsep = false;
    } else if (token === '--iterations' && i + 1 < args.length) {
      iterations = Number(args[++i]);
    } else if (token.startsWith('--iterations=')) {
      iterations = Number(token.slice('--iterations='.length));
    } else if (token === '--command' && i + 1 < args.length) {
      wrapCommandFlag = args[++i];
    } else if (token.startsWith('--command=')) {
      wrapCommandFlag = token.slice('--command='.length);
    } else if (!token.startsWith('-') && !command) {
      command = token;
    } else if (!token.startsWith('-') && command && !subcommand) {
      subcommand = token;
    }
  }

  const wrapCommand = passthroughArgs.length > 0 ? passthroughArgs[0] : wrapCommandFlag || '';
  const wrapArgs = passthroughArgs.length > 1 ? passthroughArgs.slice(1) : [];

  return {
    command,
    subcommand,
    dir,
    includeGlobal,
    json,
    format,
    ci,
    failOn,
    dryRun,
    installHooks,
    help,
    version,
    server,
    tool,
    toolArgsRaw,
    warrant,
    lease,
    allowedTools,
    pathPrefix,
    ttl,
    maxCalls,
    reason,
    tx,
    files,
    label,
    kind,
    decoyFile,
    buckets,
    prompt,
    subject,
    ticket,
    release,
    force,
    preview,
    partner,
    outDir,
    out,
    file,
    licenseToken,
    authorityPub,
    noColor,
    enableIsep,
    iterations,
    wrapCommand,
    wrapArgs,
    apply,
    rollback,
    excludeTools,
    spillBytes,
    seq,
    compareSize,
    signedReceipt,
    template,
    platform,
    fleetDir,
  };
}

/**
 * Format a compact 78-column ASCII box from title + body lines.
 * @param {string} title
 * @param {string[]} bodyRows
 * @returns {string}
 */
function formatCompactBox78(title, bodyRows) {
  const eq = '+' + '='.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
  const hr = '+' + '-'.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
  const out = [eq, wrapBoxRow78(title), hr];
  for (const r of bodyRows) {
    out.push(wrapBoxRow78(r, '  '));
  }
  out.push(eq);
  return out.join('\n');
}

/**
 * Execute the SHULIAK SIP v3.0 CLI in-process (ideal for sub-millisecond testing and CLI entry).
 * @param {string[]} argv
 * @param {{
 *   stdin?: NodeJS.ReadableStream,
 *   stdinIsTTY?: boolean,
 *   stdout?: (s: string) => void,
 *   stderr?: (s: string) => void,
 * }} [io]
 * @returns {Promise<{ exitCode: number, stdout: string, stderr: string }>}
 */
export async function runCli(argv, io = {}) {
  let outBuf = '';
  let errBuf = '';
  let stripAnsi = Boolean(process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '');

  const writeOut = (s) => {
    const text = stripAnsi ? String(s).replace(ANSI_ESCAPE_RE, '') : String(s);
    outBuf += text;
    if (io.stdout) io.stdout(text);
  };
  const writeErr = (s) => {
    const text = stripAnsi ? String(s).replace(ANSI_ESCAPE_RE, '') : String(s);
    errBuf += text;
    if (io.stderr) io.stderr(text);
  };

  let parsed;
  try {
    parsed = parseCliArgs(argv);
    if (parsed.noColor) {
      stripAnsi = true;
    }
  } catch (err) {
    writeErr(`[SIP CLI ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
    return { exitCode: 2, stdout: outBuf, stderr: errBuf };
  }

  if (parsed.version) {
    writeOut(`${CLI_VERSION}\n`);
    return { exitCode: 0, stdout: outBuf, stderr: errBuf };
  }

  if (parsed.help) {
    writeOut(HELP_TEXT);
    return { exitCode: 0, stdout: outBuf, stderr: errBuf };
  }

  // Smart Default Entrypoint:
  // - `serve` OR zero arguments when stdin is piped (`stdinIsTTY === false`) -> Native MCP JSON-RPC 2.0 Server
  // - Zero arguments in an interactive terminal (`stdinIsTTY !== false`) -> 3-Tier <= 78-col Quickstart Menu
  if (parsed.command === 'serve' || (!parsed.command && io.stdinIsTTY === false && io.stdin)) {
    await runMcpStdioServer({
      workspaceDir: parsed.dir,
      input: io.stdin || process.stdin,
      output: { write: writeOut },
      errorOutput: { write: writeErr },
    });
    return { exitCode: 0, stdout: outBuf, stderr: errBuf };
  }

  if (!parsed.command) {
    writeOut(HELP_TEXT);
    return { exitCode: 0, stdout: outBuf, stderr: errBuf };
  }

  const bus = new SipPipelineBus();

  // ==========================================================================
  // STAGE 1 COMMANDS
  // ==========================================================================

  if (parsed.command === 'audit') {
    bus.register('onConfigAudit', 'stage1.discover-and-scan', (ctx) => {
      const configs = discoverMcpConfigs({
        workspaceDir: ctx.dir,
        includeGlobal: ctx.includeGlobal,
      });
      const result = runStaticMcpAudit({
        configs,
        workspaceDir: ctx.dir,
      });
      return { ...ctx, configs, result };
    });

    const { context } = await
      bus.executeSlot('onConfigAudit', parsed);
    const auditResult = context.result;
    const teamPol = loadWorkspaceTeamPolicy({
      workspaceDir: parsed.dir,
      authorityPubB64u: parsed.authorityPub || undefined,
    });
    if (teamPol.present) {
      auditResult.teamPolicy = {
        status: teamPol.status,
        applied: teamPol.applied,
        policy: teamPol.applied ? teamPol.policy : null,
      };
    }
    if (parsed.signedReceipt) {
      try {
        const rec = createSignedCiReceipt({
          workspaceDir: parsed.dir,
          auditResult,
          authorityPubB64u:
            parsed.authorityPub || undefined,
        });
        auditResult.signedCiReceipt = rec;
      } catch (err) {
        writeErr(
          `[SIP AUDIT RECEIPT] ${err?.message || err}\n`
        );
        return { exitCode: 2, stdout: outBuf,
                 stderr: errBuf };
      }
    }

    if (parsed.format === 'sarif') {
      writeOut(JSON.stringify(formatAuditSarif(auditResult), null, 2) + '\n');
    } else if (parsed.format === 'markdown-pr') {
      const lockVer = verifySchemaLock({ workspaceDir: parsed.dir, configs: context.configs });
      const scopeAnalysis = analyzeEnterpriseScopeExposure({
        configs: context.configs,
        auditResult,
      });
      writeOut(
        formatAuditMarkdownPrComment({
          auditResult,
          lockVerification: lockVer,
          scopeAnalysis,
          configs: context.configs,
          partnerCode: parsed.partner,
        })
      );
    } else if (parsed.json || parsed.format === 'json') {
      writeOut(JSON.stringify(auditResult, null, 2) + '\n');
    } else {
      writeOut(formatAuditTerminalReport(auditResult) + '\n');
      const scopeAnalysis = analyzeEnterpriseScopeExposure({
        configs: context.configs,
        auditResult,
      });
      if (scopeAnalysis.hasEnterpriseConnectors) {
        writeOut(
          formatCompactBox78('[SHULIAK SIP v3.0 - ENTERPRISE PCI DSS / ROVO SCOPE HINT]', [
            `CONNECTORS: ${scopeAnalysis.totalEnterpriseConnectors} DB/Payment/Rovo/Cloud MCP server(s) detected.`,
            'PREVIEW   : $ npx -y @shuliak-corp/sip1-mcp attest --preview',
          ]) + '\n'
        );
      }
    }

    const effectiveThreshold = parsed.failOn || (parsed.ci ? 'C' : null);
    if (effectiveThreshold) {
      const actualRank = GRADE_SEVERITY_RANK[auditResult.grade] ?? 5;
      const thresholdRank = GRADE_SEVERITY_RANK[effectiveThreshold] ?? 3;
      if (actualRank >= thresholdRank) {
        return { exitCode: 1, stdout: outBuf, stderr: errBuf };
      }
    }

    return { exitCode: 0, stdout: outBuf, stderr: errBuf };
  }

  if (parsed.command === 'shield') {
    try {
      if (parsed.rollback) {
        const rb = rollbackShieldInWorkspace({
          workspaceDir: parsed.dir,
          dryRun: parsed.dryRun,
        });
        if (parsed.json) {
          writeOut(JSON.stringify(rb, null, 2) + '\n');
        } else {
          writeOut(formatCompactBox78(
            '[SHULIAK SIP v3.1 - SHIELD ROLLBACK]',
            [
              `STATUS   : ${rb.status}`,
              `RESTORED : ${rb.restoredCount} file(s)`,
            ]
          ) + '\n');
        }
        return { exitCode: 0, stdout: outBuf,
                 stderr: errBuf };
      }
      const isDry = parsed.dryRun || !parsed.apply;
      const sh = applyShieldToWorkspace({
        workspaceDir: parsed.dir,
        includeGlobal: parsed.includeGlobal,
        dryRun: isDry,
      });
      if (parsed.json) {
        writeOut(JSON.stringify(sh, null, 2) + '\n');
      } else {
        writeOut(formatCompactBox78(
          '[SHULIAK SIP v3.1 - AUTO-SHIELD]',
          [
            `MODE     : ${isDry ? 'DRY-RUN' : 'APPLIED'}`,
            `MODIFIED : ${sh.modifiedCount} config(s)`,
            `NODE BIN : ${sh.nodePath}`,
          ]
        ) + '\n');
      }
      return { exitCode: 0, stdout: outBuf,
               stderr: errBuf };
    } catch (err) {
      writeErr(
        `[SIP SHIELD ERROR] ${err?.message || err}\n`
      );
      return { exitCode: 2, stdout: outBuf,
               stderr: errBuf };
    }
  }

  if (parsed.command === 'lock') {
    bus.register('onSchemaLock', 'stage1.jcs-ed25519-lock', async (ctx) => {
      const configs = discoverMcpConfigs({
        workspaceDir: ctx.dir,
        includeGlobal: ctx.includeGlobal,
      });
      const lockOutcome = await createOrUpdateSchemaLock({
        workspaceDir: ctx.dir,
        configs,
        dryRun: ctx.dryRun,
        installHooks: ctx.installHooks,
      });
      return { ...ctx, configs, lockOutcome };
    });

    try {
      const { context } = await bus.executeSlot('onSchemaLock', parsed);
      const { lockOutcome } = context;
      if (parsed.json) {
        writeOut(JSON.stringify(lockOutcome, null, 2) + '\n');
      } else if (lockOutcome.dryRun) {
        writeOut(
          `[SHULIAK SIP DRY-RUN] Computed RFC 8785 + Ed25519 manifest (${lockOutcome.lockManifest.servers.length} servers). Zero files written.\n`
        );
        writeOut(JSON.stringify(lockOutcome.lockManifest, null, 2) + '\n');
      } else {
        writeOut(
          `[SHULIAK SIP SEALED] Wrote ${lockOutcome.lockPath} (${lockOutcome.lockManifest.servers.length} servers, digest ${lockOutcome.lockManifest.manifestDigestB64u}).\n`
        );
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SHULIAK SIP LOCK ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 1, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'verify-lock') {
    const configs = discoverMcpConfigs({
      workspaceDir: parsed.dir,
      includeGlobal: parsed.includeGlobal,
    });
    const verification = verifySchemaLock({
      workspaceDir: parsed.dir,
      configs,
    });

    if (parsed.json) {
      writeOut(JSON.stringify(verification, null, 2) + '\n');
    } else if (verification.valid) {
      writeOut(
        `[SHULIAK SIP VERIFIED] Schema lock intact (${verification.lock.servers.length} servers, Ed25519 key ${verification.lock.keyId}).\n`
      );
    } else {
      writeErr(`[SHULIAK SIP QUARANTINE] Schema lock verification FAILED (${verification.status}):\n`);
      for (const d of verification.driftDetails) {
        writeErr(`  - ${d.message}\n`);
      }
    }

    return { exitCode: verification.valid ? 0 : 2, stdout: outBuf, stderr: errBuf };
  }

  // ==========================================================================
  // STAGE 2 COMMANDS (`guard`, `warrant`, `undo`, `canary`, `finops`)
  // ==========================================================================

  if (parsed.command === 'guard') {
    if (!parsed.server || !parsed.tool) {
      writeErr('[SIP GUARD ERROR] --server <name> and --tool <name> are required.\n');
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }

    let parsedToolArgs = {};
    try {
      parsedToolArgs = parsed.toolArgsRaw ? JSON.parse(parsed.toolArgsRaw) : {};
    } catch (err) {
      writeErr(
        `[SIP GUARD ERROR] Malformed --args JSON: ${err instanceof Error ? err.message : String(err)}\n`
      );
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }

    const outcome = await evaluatePreToolGuard({
      workspaceDir: parsed.dir,
      server: parsed.server,
      tool: parsed.tool,
      args: parsedToolArgs,
      warrantToken: parsed.warrant || process.env.SIP_WARRANT_TOKEN || null,
      bus,
    });

    if (parsed.json) {
      writeOut(JSON.stringify(outcome, null, 2) + '\n');
    } else {
      const report = formatGuardTerminalReport(outcome) + '\n';
      if (outcome.exitCode === 0) {
        writeOut(report);
      } else {
        writeErr(report);
      }
    }

    return { exitCode: outcome.exitCode, stdout: outBuf, stderr: errBuf };
  }

  if (parsed.command === 'warrant') {
    const action = parsed.subcommand || 'issue';
    if (action !== 'issue') {
      writeErr(`Unknown warrant subcommand "${action}". Expected \`sip1-mcp warrant issue ...\`.\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
    if (!parsed.server) {
      writeErr('[SIP WARRANT ERROR] --server <name> is required.\n');
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }

    try {
      if (parsed.lease) {
        const toolsList =
          parsed.allowedTools && parsed.allowedTools.length > 0
            ? parsed.allowedTools
            : parsed.tool
              ? [parsed.tool]
              : ['*'];
        const issuedLease = await issueScopedLease({
          workspaceDir: parsed.dir,
          server: parsed.server,
          allowedTools: toolsList,
          pathPrefix: parsed.pathPrefix || '',
          maxCalls: parsed.maxCalls ?? 10,
          ttlSeconds: parsed.ttl ?? 900,
          reason: parsed.reason || 'CLI scoped developer lease',
        });

        if (parsed.json) {
          writeOut(JSON.stringify(issuedLease, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · ED25519 SCOPED LEASE ISSUED]', [
              `LEASE ID : ${issuedLease.leaseId}`,
              `SERVER   : ${issuedLease.warrant.server} :: [${issuedLease.warrant.allowedTools.join(', ')}]`,
              `CALLS    : ${issuedLease.remainingCalls} max · TTL: ${Math.round((issuedLease.warrant.expiresAt - issuedLease.warrant.issuedAt) / 1000)}s`,
              `TOKEN    : ${issuedLease.token}`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (!parsed.tool) {
        writeErr('[SIP WARRANT ERROR] --tool <name> is required for one-shot warrants.\n');
        return { exitCode: 2, stdout: outBuf, stderr: errBuf };
      }

      const parsedToolArgs = parsed.toolArgsRaw ? JSON.parse(parsed.toolArgsRaw) : {};
      const issued = issueOneShotWarrant({
        workspaceDir: parsed.dir,
        server: parsed.server,
        tool: parsed.tool,
        args: parsedToolArgs,
        ttlSeconds: parsed.ttl ?? 60,
        reason: parsed.reason || 'CLI one-shot operator warrant',
      });

      if (parsed.json) {
        writeOut(JSON.stringify(issued, null, 2) + '\n');
      } else {
        writeOut(
          formatCompactBox78('[SHULIAK SIP v3.0 · ED25519 ONE-SHOT WARRANT ISSUED]', [
            `JTI      : ${issued.jti}`,
            `TARGET   : ${issued.warrant.server} :: ${issued.warrant.tool}`,
            `0x07 JCS : ${issued.warrant.actionDigest}`,
            `TOKEN    : ${issued.token}`,
          ]) + '\n'
        );
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP WARRANT ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'undo') {
    const sub = parsed.subcommand || 'rollback';
    try {
      if (sub === 'list') {
        const list = listShadowTransactions({ workspaceDir: parsed.dir });
        if (parsed.json) {
          writeOut(JSON.stringify(list, null, 2) + '\n');
        } else {
          const rows =
            list.length === 0
              ? ['No shadow snapshots recorded yet in .sip/undo/journal.jsonl.']
              : list.map(
                  (t) =>
                    `${t.txId} · ${t.rolledBack ? 'ROLLED_BACK' : 'ACTIVE'} · ${t.files.length} file(s) · ${t.label}`
                );
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · SHADOW UNDO JOURNAL]', rows) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'capture') {
        if (parsed.files.length === 0) {
          writeErr('[SIP UNDO ERROR] --files <path1,path2> is required for `undo capture`.\n');
          return { exitCode: 2, stdout: outBuf, stderr: errBuf };
        }
        const snap = await captureShadowSnapshot({
          workspaceDir: parsed.dir,
          targetPaths: parsed.files,
          label: parsed.label || 'manual-cli-snapshot',
        });
        if (parsed.json) {
          writeOut(JSON.stringify(snap, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · SHADOW SNAPSHOT SEALED]', [
              `TX ID    : ${snap.txId}`,
              `FILES    : ${snap.files.length} captured (${snap.files.map((f) => f.relPath).join(', ')})`,
              `0x01 HASH: ${snap.txHash}`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'rollback') {
        const res = await rollbackLastTransaction({
          workspaceDir: parsed.dir,
          txId: parsed.tx || undefined,
        });
        if (parsed.json) {
          writeOut(JSON.stringify(res, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · SHADOW ROLLBACK COMPLETE]', [
              `TX ID    : ${res.txId} (${res.durationMs.toFixed(2)} ms)`,
              `RESTORED : ${res.restoredPaths.length ? res.restoredPaths.join(', ') : 'none'}`,
              `REMOVED  : ${res.removedPaths.length ? res.removedPaths.join(', ') : 'none'}`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      writeErr(`Unknown undo subcommand "${sub}". Expected rollback, list, or capture.\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP UNDO ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'canary') {
    const sub = parsed.subcommand || 'status';
    try {
      if (sub === 'plant') {
        const planted = await plantCanaryToken({
          workspaceDir: parsed.dir,
          kind: parsed.kind || 'AWS_KEY',
          writeDecoyFile: parsed.decoyFile,
        });
        if (parsed.json) {
          writeOut(JSON.stringify(planted, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · CANARY HONEYTOKEN PLANTED]', [
              `CANARY ID: ${planted.canaryId} (${planted.kind})`,
              `MASKED   : ${planted.maskedPreview} (HMAC-SHA256 stored; zero plaintext in .sip)`,
              planted.decoyFilePath
                ? `DECOY    : ${path.basename(planted.decoyFilePath)}`
                : 'DECOY    : In-memory / operator env token issued',
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'unlock') {
        const unlocked = await clearLockdown({ workspaceDir: parsed.dir });
        if (parsed.json) {
          writeOut(JSON.stringify(unlocked, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · WORKSPACE LOCKDOWN CLEARED]', [
              'STATUS   : ACTIVE=false (Workspace unlocked by operator)',
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'status') {
        const status = getLockdownStatus({ workspaceDir: parsed.dir });
        if (parsed.json) {
          writeOut(JSON.stringify(status, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · CANARY & LOCKDOWN STATUS]', [
              `LOCKDOWN : ${status.active ? `ACTIVE (${status.reason})` : 'INACTIVE (NOMINAL)'}`,
              `CANARIES : ${status.canaryCount} registered in .sip/state/canaries.json`,
            ]) + '\n'
          );
        }
        return { exitCode: status.active ? 2 : 0, stdout: outBuf, stderr: errBuf };
      }

      writeErr(`Unknown canary subcommand "${sub}". Expected plant, status, or unlock.\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP CANARY ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'finops') {
    const sub = parsed.subcommand || 'reset';
    if (sub === 'reset') {
      const cleaned = await resetFinOpsFuse({ workspaceDir: parsed.dir });
      if (parsed.json) {
        writeOut(JSON.stringify(cleaned, null, 2) + '\n');
      } else {
        writeOut(
          formatCompactBox78('[SHULIAK SIP v3.0 · FINOPS CIRCUIT BREAKER RESET]', [
            'STATUS   : Sliding 10s velocity & 60s error-loop counters cleared.',
          ]) + '\n'
        );
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    }
  }

  // ==========================================================================
  // STAGE 3 COMMANDS (`isep init | record | shred | hold | verify`)
  // ==========================================================================

  if (parsed.command === 'isep') {
    const sub = parsed.subcommand || 'verify';
    const sipDir = path.join(parsed.dir, '.sip');

    try {
      if (sub === 'init') {
        const initRes = await withPidLock(sipDir, () => {
          const ctx = initKeyring({
            workspaceDir: parsed.dir,
            bucketCount: parsed.buckets ?? 1024,
            force: parsed.force,
          });
          const summary = {
            keyringPath: ctx.keyringPath,
            logPath: ctx.logPath,
            blobsPath: ctx.blobsPath,
            bucketCount: ctx.bucketCount,
            genCounter: Number(ctx.genCounter),
            keyId: ctx.keyId,
            custodianPubB64u: ctx.custodianPubB64u,
          };
          closeKeyring(ctx);
          return summary;
        });

        if (parsed.json) {
          writeOut(JSON.stringify(initRes, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · ISEP v3.0 KEYRING INITIALIZED]', [
              `KEY ID   : ${initRes.keyId} (gen=${initRes.genCounter})`,
              `BUCKETS  : ${initRes.bucketCount} x 288B AES-256-GCM Cuckoo Buckets`,
              `KEYRING  : ${path.basename(initRes.keyringPath)}`,
              `LEDGER   : ${path.basename(initRes.logPath)}`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'record') {
        if (!parsed.server || !parsed.tool) {
          writeErr('[SIP ISEP ERROR] --server <s> and --tool <t> are required for `isep record`.\n');
          return { exitCode: 2, stdout: outBuf, stderr: errBuf };
        }
        const parsedArgs = parsed.toolArgsRaw ? JSON.parse(parsed.toolArgsRaw) : {};

        bus.register('onIsepRecord', 'stage3.isep-record-event', (c) => {
          const kr = initOrOpenKeyring({ workspaceDir: c.dir });
          try {
            const recorded = recordAgentEvent(kr, {
              server: c.server,
              tool: c.tool,
              args: parsedArgs,
              prompt: c.prompt ?? undefined,
            });
            return { ...c, recorded };
          } finally {
            closeKeyring(kr);
          }
        });

        const { context } = await withPidLock(sipDir, () => bus.executeSlot('onIsepRecord', parsed));
        const recOut = context.recorded;

        if (parsed.json) {
          writeOut(JSON.stringify(recOut, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · ISEP v3.0 AGENT EVENT SEALED]', [
              `SEQ      : #${recOut.seq} (${recOut.eventRecord.server}::${recOut.eventRecord.tool})`,
              `SUBJECTS : ${recOut.subjectCount} m-of-m XOR · Sidecar: ${recOut.sidecarByteLen}B`,
              `0x01 HASH: ${recOut.eventRecord.chain_hash}`,
              `0x02 BLOB: ${recOut.eventRecord.sidecar_commitment}`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'shred') {
        if (!parsed.subject || !parsed.ticket) {
          writeErr('[SIP ISEP ERROR] --subject <id> and --ticket <DSAR-ID> are required for `isep shred`.\n');
          return { exitCode: 2, stdout: outBuf, stderr: errBuf };
        }

        bus.register('onIsepShred', 'stage3.isep-gdpr-shred', (c) => {
          const kr = openKeyring({ workspaceDir: c.dir });
          try {
            const shredRes = executeGdprShredding(kr, {
              canonicalTargetBuf: c.subject,
              dsarTicketId: c.ticket,
            });
            return { ...c, shredRes };
          } finally {
            closeKeyring(kr);
          }
        });

        const { context } = await withPidLock(sipDir, () => bus.executeSlot('onIsepShred', parsed));
        const sr = context.shredRes;

        if (parsed.json) {
          writeOut(JSON.stringify(sr, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · GDPR ART. 17 CRYPTO-SHRED COMPLETE]', [
              `GENERATN : Keyring gen=${sr.genCounter} (DEK + Root KEK rotated)`,
              `ERASED   : [${sr.erasedSeqs.join(', ') || 'key-only'}]`,
              `0x03 WIT : ${sr.tombstoneWitness}`,
              `0x05 DSAR: ${sr.dsarReceiptCommit}`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'hold') {
        if (!parsed.subject) {
          writeErr('[SIP ISEP ERROR] --subject <id> is required for `isep hold`.\n');
          return { exitCode: 2, stdout: outBuf, stderr: errBuf };
        }
        const holdRes = await withPidLock(sipDir, () => {
          const kr = openKeyring({ workspaceDir: parsed.dir });
          try {
            return setSubjectLitigationHold(kr, {
              canonicalTargetBuf: parsed.subject,
              holdActive: !parsed.release,
            });
          } finally {
            closeKeyring(kr);
          }
        });

        if (parsed.json) {
          writeOut(JSON.stringify(holdRes, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 · GDPR ART. 17(3)(e) LITIGATION HOLD]', [
              `HOLD     : ${holdRes.holdActive ? 'ACTIVE (0x02)' : 'RELEASED (0x01)'}`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'verify') {
        bus.register('onAuditVerify', 'stage3.isep-verify-chain', (c) => {
          const paths = resolveIsepPaths({ workspaceDir: c.dir });
          const kp = ensureDeviceEd25519Keypair(paths.sipDir, { ephemeralOnly: true });
          const ver = verifyIsepChainQuick({
            logPath: paths.logPath,
            blobsPath: paths.blobsPath,
            custodianPublicKey: kp.publicKey,
          });
          return { ...c, ver };
        });

        const { context } = await bus.executeSlot('onAuditVerify', parsed);
        const ver = context.ver;

        if (parsed.json) {
          writeOut(JSON.stringify(ver, null, 2) + '\n');
        } else {
          const box =
            formatCompactBox78('[SHULIAK SIP v3.0 · ISEP v3.0 BI-DIRECTIONAL VERIFIER]', [
              `STATUS   : ${ver.status}`,
              `EVENTS   : ${ver.totalEvents} · Tombstones: ${ver.tombstones}`,
              `DETAIL   : ${ver.reason}`,
            ]) + '\n';
          if (ver.valid) {
            writeOut(box);
          } else {
            writeErr(box);
          }
        }
        return { exitCode: ver.valid ? 0 : 2, stdout: outBuf, stderr: errBuf };
      }

      writeErr(`Unknown isep subcommand "${sub}". Expected init, record, shred, hold, or verify.\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP ISEP ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  // ==========================================================================
  // STAGE 4 COMMANDS (`attest`, `verify-cert`, `license`, `aibom`, `init-ci`, `badge`, `selftest`)
  // ==========================================================================

  if (parsed.command === 'attest') {
    try {
      const targetOutDir = parsed.outDir || parsed.dir;
      const partnerRaw = parsed.partner ? parsed.partner.trim() : null;
      const partnerIsSlug = partnerRaw ? /^[a-z0-9_-]+$/i.test(partnerRaw) : false;

      const bundle = generateAuditorAttestationBundle({
        workspaceDir: parsed.dir,
        previewMode: parsed.preview,
        partnerCode: partnerIsSlug ? partnerRaw : null,
        partnerName: partnerRaw,
        includeGlobal: parsed.preview ? false : parsed.includeGlobal,
        authorityPubB64u: parsed.authorityPub || undefined,
        template: parsed.template,
      });

      const baseName = parsed.preview
        ? 'SHULIAK_READINESS_PREVIEW'
        : 'SHULIAK_ATTESTATION_CERTIFICATE';
      const pdfPath = path.join(targetOutDir, `${baseName}.pdf`);
      const certJsonPath = path.join(targetOutDir, `${baseName}.json`);
      const aibomPath = path.join(targetOutDir, 'aibom.cdx.json');

      writeFileAtomic600(pdfPath, bundle.pdfBuffer, { mode: 0o600 });
      writeFileAtomic600(certJsonPath, JSON.stringify(bundle.certObj, null, 2) + '\n', {
        mode: 0o600,
      });
      writeFileAtomic600(aibomPath, JSON.stringify(bundle.aibom, null, 2) + '\n', {
        mode: 0o600,
      });

      const summaryOut = {
        authorityStatus: bundle.certObj.authority_status,
        certificateId: bundle.certObj.certificate_id,
        pdfPath,
        certJsonPath,
        aibomPath,
        aibomDigest0x08: bundle.aibomDigestB64u,
        attestationDigest0x0a: bundle.certObj.attestation_digest_0x0a,
        pciDssScopeStatus: bundle.scopeAnalysis.pciDssScopeStatus.status,
        rovoExposureStatus: bundle.scopeAnalysis.rovoCreditPiiExposure.status,
        upgradeUrl: bundle.certObj.upgrade_url,
      };

      if (parsed.json) {
        writeOut(JSON.stringify(summaryOut, null, 2) + '\n');
      } else {
        const rows = [
          `AUTHORITY: ${bundle.certObj.authority_status}`,
          `PDF 1.7  : ${path.basename(pdfPath)} (${bundle.pdfBuffer.byteLength} bytes)`,
          `AIBOM    : ${path.basename(aibomPath)} (0x08=${bundle.aibomDigestB64u.slice(0, 20)}...)`,
          `PCI/ROVO : ${bundle.scopeAnalysis.pciDssScopeStatus.inScopeConnectorCount} PCI | ${bundle.scopeAnalysis.rovoCreditPiiExposure.connectorCount} Rovo`,
        ];
        if (bundle.certObj.authority_status !== 'COUNTERSIGNED_COMMERCIAL') {
          rows.push(`UPGRADE  : ${bundle.certObj.upgrade_url}`);
        }
        writeOut(
          formatCompactBox78('[SHULIAK SIP v3.0 - AUDITOR ATTESTATION BUNDLE GENERATED]', rows) +
            '\n'
        );
      }

      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP ATTEST ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'verify-cert') {
    if (!parsed.file) {
      writeErr('[SIP VERIFY-CERT ERROR] --file <attestation.json_or_pdf> is required.\n');
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }

    try {
      const targetPath = path.isAbsolute(parsed.file)
        ? parsed.file
        : path.resolve(parsed.dir, parsed.file);
      const rawBuf = fs.readFileSync(targetPath);
      const isPdf =
        targetPath.toLowerCase().endsWith('.pdf') ||
        rawBuf.subarray(0, 5).toString('latin1') === '%PDF-';

      const ver = isPdf
        ? extractAndVerifyPdfBytes(rawBuf, {
            authorityPubB64u: parsed.authorityPub || undefined,
          })
        : verifyAttestationCertificateOffline({
            certObj: JSON.parse(rawBuf.toString('utf8')),
            authorityPubB64u: parsed.authorityPub || undefined,
          });

      if (parsed.json) {
        writeOut(JSON.stringify(ver, null, 2) + '\n');
      } else {
        const box =
          formatCompactBox78('[SHULIAK SIP v3.0 - OFFLINE CERTIFICATE VERIFIER]', [
            `VERDICT  : ${ver.status} (valid=${ver.valid})`,
            `AUTHORITY: ${ver.authorityStatus || 'UNKNOWN'}`,
            `SIGNERS  : Custodian=${Boolean(ver.custodianSignatureValid)} | Root=${Boolean(ver.rootCountersignatureValid)}`,
            `DETAIL   : ${ver.reason}`,
          ]) + '\n';
        if (ver.valid) {
          writeOut(box);
        } else {
          writeErr(box);
        }
      }

      return { exitCode: ver.valid ? 0 : 2, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP VERIFY-CERT ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'activate') {
    parsed.command = 'license';
    if (!parsed.licenseToken &&
        parsed.subcommand) {
      parsed.licenseToken = parsed.subcommand;
    }
    parsed.subcommand = 'activate';
  }

  if (parsed.command === 'license') {
    const sub = parsed.subcommand || 'status';
    try {
      if (sub === 'activate') {
        if (!parsed.licenseToken) {
          writeErr('[SIP LICENSE ERROR] --token <SIP3...> is required for `license activate`.\n');
          return { exitCode: 2, stdout: outBuf, stderr: errBuf };
        }
        const act = await activateWorkspaceLicense({
          workspaceDir: parsed.dir,
          tokenStr: parsed.licenseToken,
          authorityPubB64u: parsed.authorityPub || undefined,
        });
        if (parsed.json) {
          writeOut(JSON.stringify(act, null, 2) + '\n');
        } else {
          writeOut(
            formatCompactBox78('[SHULIAK SIP v3.0 - COMMERCIAL LICENSE ACTIVATED]', [
              `TIER     : ${act.verification.tier} (${act.verification.payload.orgName})`,
              `LICENSE  : ${act.verification.payload.licenseId} (${act.verification.payload.orgDomain})`,
              `PARTNER  : ${act.verification.payload.partnerName || act.verification.payload.partnerCode || 'direct-self-serve'}`,
              `SAVED TO : .sip/license.json`,
            ]) + '\n'
          );
        }
        return { exitCode: 0, stdout: outBuf, stderr: errBuf };
      }

      if (sub === 'status') {
        const ent = inspectWorkspaceEntitlement({
          workspaceDir: parsed.dir,
          authorityPubB64u: parsed.authorityPub || undefined,
        });
        if (parsed.json) {
          writeOut(JSON.stringify(ent, null, 2) + '\n');
        } else {
          const box =
            formatCompactBox78('[SHULIAK SIP v3.0 - COMMERCIAL ENTITLEMENT STATUS]', [
              `STATUS   : ${ent.status}`,
              `TIER     : ${ent.tier} (Attestation Eligible: ${ent.isAttestationEligible})`,
              `CUSTODIAN: ${ent.custodianPubB64u || '(run sip1-mcp lock or isep init first)'}`,
              `DETAIL   : ${ent.reason}`,
            ]) + '\n';
          if (ent.status === 'FORGED_COMMERCIAL_AUTHORITY') {
            writeErr(box);
          } else {
            writeOut(box);
          }
        }
        return {
          exitCode: ent.status === 'FORGED_COMMERCIAL_AUTHORITY' ? 2 : 0,
          stdout: outBuf,
          stderr: errBuf,
        };
      }

      writeErr(`Unknown license subcommand "${sub}". Expected activate or status.\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP LICENSE ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'aibom') {
    try {
      const configs = discoverMcpConfigs({
        workspaceDir: parsed.dir,
        includeGlobal: parsed.includeGlobal,
      });
      const auditResult = runStaticMcpAudit({
        configs,
        workspaceDir: parsed.dir,
      });
      const { bom, aibomDigestB64u, scopeAnalysis } = generateCycloneDxAibom({
        workspaceDir: parsed.dir,
        configs,
        auditResult,
      });

      const outPath = parsed.out
        ? path.isAbsolute(parsed.out)
          ? parsed.out
          : path.resolve(parsed.dir, parsed.out)
        : !parsed.json
          ? path.join(parsed.dir, 'aibom.cdx.json')
          : null;

      if (outPath) {
        writeFileAtomic600(outPath, JSON.stringify(bom, null, 2) + '\n', { mode: 0o600 });
      }

      if (parsed.json) {
        writeOut(JSON.stringify(bom, null, 2) + '\n');
      } else {
        writeOut(
          formatCompactBox78('[SHULIAK SIP v3.0 - CYCLONEDX 1.6 AIBOM GENERATED]', [
            `SPEC     : CycloneDX 1.6 (${bom.components.length} component(s), ${bom.vulnerabilities.length} finding(s))`,
            `0x08 JCS : ${aibomDigestB64u}`,
            `PCI/ROVO : ${scopeAnalysis.pciDssScopeStatus.status}`,
            `OUTPUT   : ${outPath ? path.basename(outPath) : 'stdout'}`,
          ]) + '\n'
        );
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP AIBOM ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'init-ci') {
    try {
      const wfPath = path.join(parsed.dir, '.github', 'workflows', 'sip-mcp-gate.yml');
      const backupPath = backupConfigBeforeEdit(wfPath);
      const yamlText = generateGithubPrWorkflowYaml();
      writeFileAtomic600(wfPath, yamlText, { mode: 0o644 });

      if (parsed.json) {
        writeOut(
          JSON.stringify(
            { workflowPath: wfPath, backupPath, ghasRequired: false },
            null,
            2
          ) + '\n'
        );
      } else {
        writeOut(
          formatCompactBox78('[SHULIAK SIP v3.0 - GHAS-FREE GITHUB PR GATE INSTALLED]', [
            'WORKFLOW : .github/workflows/sip-mcp-gate.yml',
            'LICENSE  : $0 GitHub Free/Team compatible (Zero GHAS seats required)',
            'PERMS    : contents: read | pull-requests: write',
          ]) + '\n'
        );
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP INIT-CI ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'badge') {
    try {
      const configs = discoverMcpConfigs({
        workspaceDir: parsed.dir,
        includeGlobal: parsed.includeGlobal,
      });
      const auditResult = runStaticMcpAudit({
        configs,
        workspaceDir: parsed.dir,
      });
      const locked = auditResult.lockStatus === 'SEALED_VERIFIED';
      const svg = generateRepoBadgeSvg({ grade: auditResult.grade, locked });
      const targetSvgPath = parsed.out
        ? path.isAbsolute(parsed.out)
          ? parsed.out
          : path.resolve(parsed.dir, parsed.out)
        : path.join(parsed.dir, 'sip-security-badge.svg');

      writeFileAtomic600(targetSvgPath, svg, { mode: 0o644 });

      if (parsed.json) {
        writeOut(
          JSON.stringify(
            { badgePath: targetSvgPath, grade: auditResult.grade, locked },
            null,
            2
          ) + '\n'
        );
      } else {
        writeOut(
          formatCompactBox78('[SHULIAK SIP v3.0 - REPOSITORY SECURITY BADGE GENERATED]', [
            `GRADE    : ${auditResult.grade} (Locked: ${locked})`,
            `FILE     : ${path.basename(targetSvgPath)}`,
          ]) + '\n'
        );
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP BADGE ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'selftest') {
    try {
      const res = await runZeroEgressSelfTest();
      if (parsed.json) {
        const clone = { ...res };
        delete clone.report;
        writeOut(JSON.stringify(clone, null, 2) + '\n');
      } else {
        writeOut(res.report + '\n');
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP SELFTEST FAILED] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  // ==========================================================================
  // STAGE 5 COMMANDS (`demo`, `bench`, `wrap`)
  // ==========================================================================

  if (parsed.command === 'prove') {
    try {
      const proof = generateSignedIsepMerkleProof({
        workspaceDir: parsed.dir,
        seq: parsed.seq,
        compareSize: parsed.compareSize,
      });
      if (parsed.out) {
        const op = path.isAbsolute(parsed.out)
          ? parsed.out
          : path.resolve(parsed.dir, parsed.out);
        writeFileAtomic600(
          op, JSON.stringify(proof, null, 2) + '\n'
        );
      }
      if (parsed.json) {
        writeOut(JSON.stringify(proof, null, 2) + '\n');
      } else {
        writeOut(formatCompactBox78(
          '[SHULIAK SIP v3.1 - RFC 9162 MERKLE PROOF]',
          [
            `SEQ      : #${proof.seq} (leaf ` +
              `${proof.leaf_index}/${proof.tree_size})`,
            `ROOT     : ${proof.merkle_root_hex}`,
            `PATH LEN : ${proof.inclusion_path_hex.length}`,
            `0x0B DIG : ${proof.proof_digest_0x0b}`,
          ]
        ) + '\n');
      }
      return { exitCode: 0, stdout: outBuf,
               stderr: errBuf };
    } catch (err) {
      writeErr(
        `[SIP PROVE ERROR] ${err?.message || err}\n`
      );
      return { exitCode: 2, stdout: outBuf,
               stderr: errBuf };
    }
  }

  if (parsed.command === 'mdm-export') {
    try {
      const exp = generateMdmExportBundle({
        workspaceDir: parsed.dir,
        outDir: parsed.outDir,
        platform: parsed.platform,
        authorityPubB64u:
          parsed.authorityPub || undefined,
      });
      if (parsed.json) {
        writeOut(JSON.stringify(exp, null, 2) + '\n');
      } else {
        writeOut(formatCompactBox78(
          '[SHULIAK SIP v3.1 - ENTERPRISE MDM EXPORT]',
          [
            `ORG      : ${exp.orgName} ` +
              `(seats: ${exp.maxSeats})`,
            `0x0D DIG : ${exp.policyDigest0x0d}`,
            ...exp.files.map(
              (f) => `FILE     : [${f.platform}] ` +
                path.basename(f.path)
            ),
          ]
        ) + '\n');
      }
      return { exitCode: 0, stdout: outBuf,
               stderr: errBuf };
    } catch (err) {
      writeErr(
        `[SIP MDM-EXPORT ERROR] ${err?.message || err}\n`
      );
      return { exitCode: 2, stdout: outBuf,
               stderr: errBuf };
    }
  }

  if (parsed.command === 'fleet-verify') {
    try {
      const fv = verifyEnterpriseFleet({
        workspaceDir: parsed.dir,
        fleetDir: parsed.fleetDir || parsed.dir,
        authorityPubB64u:
          parsed.authorityPub || undefined,
      });
      if (parsed.json) {
        writeOut(JSON.stringify(fv, null, 2) + '\n');
      } else {
        writeOut(formatCompactBox78(
          '[SHULIAK SIP v3.1 - ENTERPRISE FLEET VERIFY]',
          [
            `STATUS   : ${fv.status} (valid=${fv.valid})`,
            `NODES    : ${fv.validCount}/${fv.totalNodes}`,
            `SEATS    : ${fv.uniqueSeats}/${fv.maxSeats}`,
          ]
        ) + '\n');
      }
      return { exitCode: fv.valid ? 0 : 2,
               stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(
        `[SIP FLEET ERROR] ${err?.message || err}\n`
      );
      return { exitCode: 2, stdout: outBuf,
               stderr: errBuf };
    }
  }

  if (parsed.command === 'demo') {
    try {
      const res = await runInteractiveDemo({
        outDir: parsed.outDir,
      });
      if (parsed.json) {
        const clone = { ...res };
        delete clone.report;
        writeOut(JSON.stringify(clone, null, 2) + '\n');
      } else {
        writeOut(res.report + '\n');
      }
      return { exitCode: res.passed ? 0 : 2, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP DEMO ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'bench') {
    try {
      const res = await runHardwareBenchmark({
        iterations: parsed.iterations ?? 200,
      });
      if (parsed.json) {
        const clone = { ...res };
        delete clone.report;
        writeOut(JSON.stringify(clone, null, 2) + '\n');
      } else {
        writeOut(res.report + '\n');
      }
      return { exitCode: 0, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP BENCH ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  if (parsed.command === 'wrap') {
    if (!parsed.wrapCommand) {
      writeErr(
        '[SIP WRAP ERROR] Downstream command is required: `sip1-mcp wrap --server <name> -- <command> [args...]`\n'
      );
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
    try {
      const targetServer =
        parsed.server || path.basename(parsed.wrapCommand).replace(/\.[A-Za-z0-9]+$/, '') || 'wrapped-mcp';
      const wrapRes = await runMcpWrapProxy({
        serverName: targetServer,
        command: parsed.wrapCommand,
        args: parsed.wrapArgs,
        workspaceDir: parsed.dir,
        enableIsep: parsed.enableIsep,
        warrantToken: parsed.warrant || process.env.SIP_WARRANT_TOKEN || null,
        allowTools: parsed.allowedTools,
        excludeTools: parsed.excludeTools,
        ...(Number.isFinite(parsed.spillBytes)
          ? { spillThresholdBytes: parsed.spillBytes }
          : {}),
        input: io.stdin || process.stdin,
        output: { write: writeOut },
        errorOutput: { write: writeErr },
      });
      return { exitCode: wrapRes.exitCode, stdout: outBuf, stderr: errBuf };
    } catch (err) {
      writeErr(`[SIP WRAP ERROR] ${err instanceof Error ? err.message : String(err)}\n`);
      return { exitCode: 2, stdout: outBuf, stderr: errBuf };
    }
  }

  writeErr(`Unknown command "${parsed.command}". Run \`sip1-mcp --help\` for usage.\n`);
  return { exitCode: 2, stdout: outBuf, stderr: errBuf };
}

const __sipResolvedSelfPath = (() => {
  const selfPath = fileURLToPath(import.meta.url);
  try {
    return __sipRealpathSync(selfPath);
  } catch {
    return path.resolve(selfPath);
  }
})();

const isDirectExecution =
  Boolean(process.argv[1]) && path.resolve(process.argv[1]) === path.resolve(__sipResolvedSelfPath);

if (isDirectExecution) {
  runCli(process.argv.slice(2), {
    stdin: process.stdin,
    stdinIsTTY: Boolean(process.stdin.isTTY),
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
  }).then(({ exitCode }) => {
    process.exitCode = exitCode;
  });
}
