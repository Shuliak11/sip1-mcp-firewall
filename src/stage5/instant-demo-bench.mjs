/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 5 Zero-Config 3-Second `demo` & Real CPU `bench`
 * Zero external dependencies. Built strictly on Node.js >= 20 built-ins.
 *
 * Guarantees:
 * - `runInteractiveDemo` runs inside an isolated `os.tmpdir()` sandbox and cleans up 100%
 *   of temporary state in `finally` (zero leftover files in `process.cwd()`).
 * - All ASCII terminal boxes are strictly `<= 78 columns` with ZERO emojis.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { jcsCanonicalize } from '../core/jcs.mjs';
import {
  DOMAIN_PREFIX,
  b64u,
  domainSha256,
  ensureDeviceEd25519Keypair,
  signDomainPayload,
  verifyDomainPayload,
} from '../core/crypto-primitives.mjs';
import { writeFileAtomic600 } from '../core/workspace-io.mjs';
import { discoverMcpConfigs } from '../stage1/config-discovery.mjs';
import {
  TERMINAL_BOX_WIDTH,
  runStaticMcpAudit,
  wrapBoxRow78,
} from '../stage1/audit-scanner.mjs';
import { createOrUpdateSchemaLock } from '../stage1/schema-lock.mjs';
import { classifyToolAction } from '../stage2/blast-radius-guard.mjs';
import { evaluatePreToolGuard } from '../stage2/guard-runner.mjs';
import { issueOneShotWarrant } from '../stage2/warrant-engine.mjs';
import {
  ibanMod97,
  isValidLuhnPan,
  synthesizeIbanTwin,
  synthesizePanTwin,
} from '../stage3/nist-ff1-twins.mjs';
import {
  closeKeyring,
  executeGdprShredding,
  initKeyring,
  recordAgentEvent,
  verifyIsepChainQuick,
} from '../stage3/isep-engine.mjs';
import { generateAuditorAttestationBundle } from '../stage4/auditor-attestation.mjs';

/**
 * Compute percentile (`0..100`) on a pre-sorted ascending numeric array.
 * @param {number[]} sortedAsc
 * @param {number} pct
 * @returns {number}
 */
function computePercentile(sortedAsc, pct) {
  if (sortedAsc.length === 0) return 0;
  const idx = Math.min(
    sortedAsc.length - 1,
    Math.max(0, Math.ceil((pct / 100) * sortedAsc.length) - 1)
  );
  return sortedAsc[idx];
}

/**
 * Format duration in milliseconds cleanly (`0.042 ms`).
 * @param {number} ms
 * @returns {string}
 */
function fmtMs(ms) {
  return ms < 1 ? `${ms.toFixed(3)}ms` : `${ms.toFixed(2)}ms`;
}

/**
 * Run the zero-setup 4-step SHULIAK SIP v3.0 interactive sandbox showcase in `< 400 ms`.
 *
 * @param {{
 *   outDir?: string | null,
 * }} [options]
 */
export async function runInteractiveDemo(options = {}) {
  const tStart = performance.now();
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sip-v3-demo-'));

  try {
    // ========================================================================
    // STEP 1: Stage 1 Multi-IDE Audit (Grade F -> Sealed Grade A+)
    // ========================================================================
    const tStep1Start = performance.now();
    const cursorDir = path.join(sandboxDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true, mode: 0o700 });
    const mcpPath = path.join(cursorDir, 'mcp.json');

    const vulnerableConfig = {
      mcpServers: {
        'stripe-billing-mcp': {
          command: 'npx',
          args: ['-y', '@stripe/mcp', '/', '--dangerously-skip-permissions'],
          description: 'Billing connector\u{E0069}\u{E0067}',
          env: {
            STRIPE_SECRET_KEY: 'sk_' + 'live_51Demo99887766554433221100AaBbCcDd',
          },
        },
      },
    };
    fs.writeFileSync(mcpPath, JSON.stringify(vulnerableConfig, null, 2) + '\n', 'utf8');

    const vulnConfigs = discoverMcpConfigs({ workspaceDir: sandboxDir, includeGlobal: false });
    const beforeAudit = runStaticMcpAudit({ configs: vulnConfigs, workspaceDir: sandboxDir });

    const remediatedConfig = {
      mcpServers: {
        'stripe-billing-mcp': {
          command: 'npx',
          args: ['-y', '@stripe/mcp@0.2.4', './billing-readonly'],
          env: {
            STRIPE_SECRET_KEY: '${env:STRIPE_SECRET_KEY}',
          },
        },
      },
    };
    fs.writeFileSync(mcpPath, JSON.stringify(remediatedConfig, null, 2) + '\n', 'utf8');

    const cleanConfigs = discoverMcpConfigs({ workspaceDir: sandboxDir, includeGlobal: false });
    const lockRes = await createOrUpdateSchemaLock({
      workspaceDir: sandboxDir,
      configs: cleanConfigs,
      installHooks: false,
    });
    const afterAudit = runStaticMcpAudit({ configs: cleanConfigs, workspaceDir: sandboxDir });
    const step1Ms = Number((performance.now() - tStep1Start).toFixed(2));

    // ========================================================================
    // STEP 2: Stage 2 SQL Comment-Bypass Block + Ed25519 Warrant + Replay Gate
    // ========================================================================
    const tStep2Start = performance.now();
    const sqlArgs = { sql: 'DROP/*bypass*/TABLE users;' };
    const blockedGuard = await evaluatePreToolGuard({
      workspaceDir: sandboxDir,
      server: 'postgres-mcp',
      tool: 'query',
      args: sqlArgs,
      autoSnapshot: false,
    });

    const warrant = issueOneShotWarrant({
      workspaceDir: sandboxDir,
      server: 'postgres-mcp',
      tool: 'query',
      args: sqlArgs,
      ttlSeconds: 60,
      reason: 'Demo operator one-shot approval',
    });

    const authorizedGuard = await evaluatePreToolGuard({
      workspaceDir: sandboxDir,
      server: 'postgres-mcp',
      tool: 'query',
      args: sqlArgs,
      warrantToken: warrant.token,
      autoSnapshot: false,
    });

    const replayGuard = await evaluatePreToolGuard({
      workspaceDir: sandboxDir,
      server: 'postgres-mcp',
      tool: 'query',
      args: sqlArgs,
      warrantToken: warrant.token,
      autoSnapshot: false,
    });
    const step2Ms = Number((performance.now() - tStep2Start).toFixed(2));

    // ========================================================================
    // STEP 3: Stage 3 NIST FF1 Twins + Multi-Subject GDPR Art. 17 Double-Shred
    // ========================================================================
    const tStep3Start = performance.now();
    const demoKey = crypto.randomBytes(32);
    const demoTweak = crypto.randomBytes(16);
    const rawPan = '4532015112830366';
    const rawIban = 'GE29NB0000000101904917';
    const panTwin = synthesizePanTwin(demoKey, demoTweak, rawPan);
    const ibanTwin = synthesizeIbanTwin(demoKey, demoTweak, rawIban);
    demoKey.fill(0);

    const panTwinLuhnValid = isValidLuhnPan(panTwin) && panTwin !== rawPan;
    const ibanTwinMod97Valid = ibanMod97(ibanTwin) === 1 && ibanTwin !== rawIban;

    const kr = initKeyring({ workspaceDir: sandboxDir, bucketCount: 32 });
    let isepVerification;
    let shredAlice;
    let shredBob;
    try {
      recordAgentEvent(kr, {
        server: 'stripe-billing-mcp',
        tool: 'create_settlement',
        args: {
          payerEmail: 'alice@corp.eu',
          coSignerEmail: 'bob@corp.eu',
          cardPan: rawPan,
          iban: rawIban,
          amount: 1450.0,
        },
      });

      shredAlice = executeGdprShredding(kr, {
        canonicalTargetBuf: 'alice@corp.eu',
        dsarTicketId: 'DSAR-DEMO-ALICE',
      });
      shredBob = executeGdprShredding(kr, {
        canonicalTargetBuf: 'bob@corp.eu',
        dsarTicketId: 'DSAR-DEMO-BOB',
      });

      const kp = ensureDeviceEd25519Keypair(path.join(sandboxDir, '.sip'), { ephemeralOnly: true });
      isepVerification = verifyIsepChainQuick({
        logPath: kr.logPath,
        blobsPath: kr.blobsPath,
        custodianPublicKey: kp.publicKey,
      });
    } finally {
      closeKeyring(kr);
    }

    let exportedPdfPath = null;
    if (options.outDir) {
      const targetOutDir = path.resolve(options.outDir);
      const bundle = generateAuditorAttestationBundle({
        workspaceDir: sandboxDir,
        previewMode: true,
        includeGlobal: false,
      });
      exportedPdfPath = path.join(targetOutDir, 'SHULIAK_DEMO_READINESS.pdf');
      writeFileAtomic600(exportedPdfPath, bundle.pdfBuffer, { mode: 0o600 });
    }
    const step3Ms = Number((performance.now() - tStep3Start).toFixed(2));
    const totalDurationMs = Number((performance.now() - tStart).toFixed(2));

    // ========================================================================
    // STEP 4: <= 78-Column Executive Showcase Report
    // ========================================================================
    const eq = '+' + '='.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
    const hr = '+' + '-'.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
    const row = (txt, indent = '  ') => wrapBoxRow78(txt, indent);

    const lines = [
      eq,
      row('[SHULIAK SIP v3.1.0 - 3-SECOND INTERACTIVE SANDBOX SHOWCASE]'),
      row(`[ZERO-EGRESS ISOLATED SANDBOX | TOTAL TIME: ${totalDurationMs.toFixed(2)} ms]`),
      eq,
      row(
        `STEP 1 [AUDIT & LOCK]: ${beforeAudit.grade} (${beforeAudit.score}/100) -> ${afterAudit.grade} (${afterAudit.score}/100) [${step1Ms.toFixed(1)}ms]`
      ),
      row(`  0x06 RFC 8785 Seal : ${lockRes.lockManifest.manifestDigestB64u.slice(0, 32)}...`),
      hr,
      row(
        `STEP 2 [AEGIS GUARD] : DROP/*bypass*/TABLE -> ${blockedGuard.decision} (${blockedGuard.ruleId}) [${step2Ms.toFixed(1)}ms]`
      ),
      row(
        `  Ed25519 Warrant    : 1st=${authorizedGuard.decision} (0x07) | Replay=${replayGuard.decision} (${replayGuard.code})`
      ),
      hr,
      row(
        `STEP 3 [FF1 & ISEP]  : PAN->${panTwin} (Luhn=${panTwinLuhnValid}) [${step3Ms.toFixed(1)}ms]`
      ),
      row(`  MOD-97 IBAN Twin   : ${ibanTwin} (MOD97=${ibanTwinMod97Valid})`),
      row(
        `  GDPR Art.17 Shred  : Alice+Bob erased (gen=${shredBob.genCounter}) -> ${isepVerification.status}`
      ),
    ];

    if (exportedPdfPath) {
      lines.push(row(`  Attestation PDF    : ${exportedPdfPath}`));
    }

    lines.push(
      hr,
      row('STEP 4 [NEXT STEPS FOR YOUR WORKSPACE]:'),
      row('  1. Scan your repo  : $ npx -y @shuliak-corp/sip1-mcp audit'),
      row('  2. Wrap MCP server : $ npx -y @shuliak-corp/sip1-mcp wrap --server db -- <cmd>'),
      row('  3. Auditor PDF 1.7 : $ npx -y @shuliak-corp/sip1-mcp attest --preview'),
      row('  4. Compliance Tier : https://shuliak.dev/#pricing'),
      eq
    );

    return {
      passed:
        beforeAudit.grade === 'F' &&
        afterAudit.grade === 'A+' &&
        blockedGuard.decision === 'BLOCK' &&
        authorizedGuard.decision === 'ALLOW' &&
        replayGuard.decision === 'BLOCK' &&
        panTwinLuhnValid &&
        ibanTwinMod97Valid &&
        isepVerification.valid &&
        isepVerification.status === 'VALID_WITH_LAWFUL_ERASURES',
      totalDurationMs,
      step1: {
        beforeGrade: beforeAudit.grade,
        beforeScore: beforeAudit.score,
        afterGrade: afterAudit.grade,
        afterScore: afterAudit.score,
        manifestDigest0x06: lockRes.lockManifest.manifestDigestB64u,
        durationMs: step1Ms,
      },
      step2: {
        initialDecision: blockedGuard.decision,
        warrantDecision: authorizedGuard.decision,
        replayDecision: replayGuard.decision,
        replayCode: replayGuard.code,
        durationMs: step2Ms,
      },
      step3: {
        panTwin,
        panTwinLuhnValid,
        ibanTwin,
        ibanTwinMod97Valid,
        isepStatus: isepVerification.status,
        tombstones: isepVerification.tombstones,
        genCounter: shredBob.genCounter,
        shreddedSeqs: shredBob.erasedSeqs,
        aliceGen: shredAlice.genCounter,
        exportedPdfPath,
        durationMs: step3Ms,
      },
      report: lines.join('\n'),
    };
  } finally {
    fs.rmSync(sandboxDir, { recursive: true, force: true });
  }
}

/**
 * Execute real CPU latency benchmark (`p50`, `p95`, `p99`) across all 5 cryptographic primitives.
 *
 * @param {{
 *   iterations?: number,
 * }} [options]
 */
export async function runHardwareBenchmark(options = {}) {
  const iterations = Math.min(2000, Math.max(10, Number(options.iterations) || 200));
  const tSuiteStart = performance.now();
  const benchSandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sip-v3-bench-'));

  try {
    const samplePayload = {
      args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2', 'postgresql://localhost:5432/prod'],
      client: 'cursor',
      command: 'npx',
      configPath: '.cursor/mcp.json',
      envKeysOnly: ['PGPASSWORD', 'PGUSER'],
      headerKeysOnly: [],
      serverName: 'postgres-prod',
      transport: 'stdio',
      url: null,
    };

    // 1. RFC 8785 JCS + 0x06 SHA-256
    const jcsTimes = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      domainSha256(DOMAIN_PREFIX.SCHEMA_LOCK, jcsCanonicalize(samplePayload));
      jcsTimes.push(performance.now() - t0);
    }

    // 2. Stage 2 SQL/Shell AST Guard
    const astTimes = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      classifyToolAction({
        server: 'postgres-prod',
        tool: 'execute_sql',
        args: { query: 'SELECT 1; DROP/*comment_bypass*/TABLE customers CASCADE;' },
        workspaceDir: benchSandbox,
      });
      astTimes.push(performance.now() - t0);
    }

    // 3. NIST SP 800-38G FF1-AES256 Luhn PAN Twin
    const ff1Key = crypto.randomBytes(32);
    const ff1Tweak = crypto.randomBytes(16);
    const ff1Times = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      synthesizePanTwin(ff1Key, ff1Tweak, '4532015112830366');
      ff1Times.push(performance.now() - t0);
    }
    ff1Key.fill(0);

    // 4. Ed25519 Sign + Verify (0x07 Action Digest)
    const kp = ensureDeviceEd25519Keypair(path.join(benchSandbox, '.sip'), { ephemeralOnly: true });
    const digest32 = domainSha256(DOMAIN_PREFIX.WARRANT_ACTION, Buffer.from('bench-action-payload', 'utf8'));
    const edTimes = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      const sig = signDomainPayload('SIP-v3-BENCH', digest32, kp.privateKey);
      verifyDomainPayload('SIP-v3-BENCH', digest32, sig, kp.publicKeyB64u);
      edTimes.push(performance.now() - t0);
    }

    // 5. ISEP v3.0 Merkle Event Commit (capped at min(iterations, 50) fsync commits to stay fast on CI disks)
    const isepIterations = Math.min(iterations, 50);
    const kr = initKeyring({ workspaceDir: benchSandbox, bucketCount: 64 });
    const isepTimes = [];
    try {
      for (let i = 0; i < isepIterations; i++) {
        const t0 = performance.now();
        recordAgentEvent(kr, {
          server: 'stripe-mcp',
          tool: 'charge',
          args: { email: 'bench@corp.eu', amount: 99 },
        });
        isepTimes.push(performance.now() - t0);
      }
    } finally {
      closeKeyring(kr);
    }

    const summarizeOp = (id, label, samples) => {
      const sorted = [...samples].sort((a, b) => a - b);
      const mean = sorted.reduce((acc, n) => acc + n, 0) / Math.max(1, sorted.length);
      return {
        id,
        label,
        samples: sorted.length,
        p50Ms: Number(computePercentile(sorted, 50).toFixed(4)),
        p95Ms: Number(computePercentile(sorted, 95).toFixed(4)),
        p99Ms: Number(computePercentile(sorted, 99).toFixed(4)),
        meanMs: Number(mean.toFixed(4)),
      };
    };

    const operations = [
      summarizeOp('jcs_sha256', 'RFC 8785 JCS + 0x06 SHA-256', jcsTimes),
      summarizeOp('stage2_ast_guard', 'Stage 2 SQL/Shell AST Guard', astTimes),
      summarizeOp('nist_ff1_pan', 'NIST FF1-AES256 Luhn PAN Twin', ff1Times),
      summarizeOp('ed25519_sign_verify', 'Ed25519 Sign + Verify (0x07)', edTimes),
      summarizeOp('isep_merkle_commit', 'ISEP v3.0 Event + Sidecar Commit', isepTimes),
    ];

    const totalDurationMs = Number((performance.now() - tSuiteStart).toFixed(2));
    const cpuModel = (os.cpus()?.[0]?.model || 'Generic CPU').trim().slice(0, 42);

    const eq = '+' + '='.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
    const hr = '+' + '-'.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
    const row = (txt, indent = '  ') => wrapBoxRow78(txt, indent);

    const lines = [
      eq,
      row('[SHULIAK SIP v3.1.0 - HARDWARE CRYPTOGRAPHIC LATENCY BENCHMARK]'),
      row(`NODE ${process.version} | ${os.platform()}-${os.arch()} | CPU: ${cpuModel}`),
      eq,
      row(
        `${'OPERATION'.padEnd(34, ' ')} ${'P50'.padStart(11, ' ')} ${'P95'.padStart(11, ' ')} ${'P99'.padStart(11, ' ')}`
      ),
      hr,
    ];

    for (const op of operations) {
      lines.push(
        row(
          `${op.label.padEnd(34, ' ')} ${fmtMs(op.p50Ms).padStart(11, ' ')} ${fmtMs(op.p95Ms).padStart(11, ' ')} ${fmtMs(op.p99Ms).padStart(11, ' ')}`
        )
      );
    }

    lines.push(
      hr,
      row(
        `ITERATIONS: ${iterations} (ISEP fsync=${isepIterations}) | TOTAL ELAPSED: ${totalDurationMs.toFixed(2)} ms`
      ),
      eq
    );

    return {
      nodeVersion: process.version,
      platform: os.platform(),
      arch: os.arch(),
      cpuModel,
      iterations,
      totalDurationMs,
      operations,
      report: lines.join('\n'),
    };
  } finally {
    fs.rmSync(benchSandbox, { recursive: true, force: true });
  }
}
