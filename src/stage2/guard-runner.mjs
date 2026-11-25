/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 2 Pre-Tool Execution Guard Orchestrator & 78-Column ASCII Reporter
 * Evaluates in deterministic Fail-Closed pipeline order via `SipPipelineBus`:
 *   1) Workspace Lockdown Check
 *   2) Canary Honeytoken Tripwire Inspection
 *   3) Deterministic Blast-Radius AST & Lexical Classification
 *   4) FinOps Velocity & Idempotent Loop Circuit Breaker
 *   5) Ed25519 One-Shot Warrant / 15-Min Scoped Lease Verification & Replay Consumption
 *   6) Automatic Pre-Execution Shadow Snapshot (`TIER_1_REVERSIBLE_WRITE` / `TIER_2_WARRANT_REQUIRED` file targets)
 */

import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { SipPipelineBus } from '../core/pipeline-bus.mjs';
import {
  TERMINAL_BOX_WIDTH,
  redactStringForLockPreview,
  wrapBoxRow78,
} from '../stage1/audit-scanner.mjs';
import { ACTION_TIERS, classifyToolAction } from './blast-radius-guard.mjs';
import { getLockdownStatus, inspectForCanaryTouch } from './canary-trap.mjs';
import { evaluateFinOpsFuse } from './finops-fuse.mjs';
import { captureShadowSnapshot } from './shadow-undo.mjs';
import { verifyAndConsumeWarrant } from './warrant-engine.mjs';

/**
 * Redact any vendor secrets or tokens embedded inside arbitrary strings before rendering reports.
 * @param {string} str
 * @returns {string}
 */
function sanitizeReportText(str) {
  if (!str) return '';
  return String(str).replace(/[A-Za-z0-9_:/@-]{12,}/g, (tok) => {
    return redactStringForLockPreview(tok) ?? tok;
  });
}

/**
 * Run full Stage 2 Pre-Tool Guard through `SipPipelineBus` (`onPreToolWarrant` + `onPostToolUndo`).
 *
 * @param {{
 *   workspaceDir: string,
 *   server: string,
 *   tool: string,
 *   args: unknown,
 *   warrantToken?: string | null,
 *   autoSnapshot?: boolean,
 *   estimatedCostUsd?: number,
 *   finopsPolicy?: Record<string, number>,
 *   bus?: SipPipelineBus,
 * }} params
 */
export async function evaluatePreToolGuard({
  workspaceDir,
  server,
  tool,
  args,
  warrantToken = null,
  autoSnapshot = true,
  estimatedCostUsd = 0.01,
  finopsPolicy = {},
  bus = new SipPipelineBus(),
}) {
  const t0 = performance.now();
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const safeServer = String(server || 'mcp-server');
  const safeTool = String(tool || 'unknown-tool');
  const safeArgs = args && typeof args === 'object' ? args : {};

  bus.register('onPreToolWarrant', 'stage2.lockdown-and-canary', async (ctx) => {
    const lockdown = getLockdownStatus({ workspaceDir: ctx.workspaceDir });
    if (lockdown.active) {
      return {
        ...ctx,
        halted: true,
        decision: 'BLOCK',
        exitCode: 2,
        stage: 'LOCKDOWN_GATE',
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-LOCKDOWN',
        code: 'WORKSPACE_LOCKDOWN_ACTIVE',
        reason: `Workspace locked down (${lockdown.reason || 'CANARY_TRIPWIRE_TRIGGERED'}). Run \`sip1-mcp canary unlock\` after incident review.`,
      };
    }

    const rawPayloadStr = JSON.stringify({
      server: ctx.server,
      tool: ctx.tool,
      args: ctx.args,
    });
    const canaryHit = await inspectForCanaryTouch({
      workspaceDir: ctx.workspaceDir,
      rawPayloadStr,
    });
    if (canaryHit.triggered) {
      return {
        ...ctx,
        halted: true,
        decision: 'BLOCK',
        exitCode: 2,
        stage: 'CANARY_TRIPWIRE',
        tier: ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK,
        ruleId: 'SIP-CANARY',
        code: 'CANARY_TRIPWIRE_TRIGGERED',
        reason: `Canary honeytoken touched (${canaryHit.kind} ${canaryHit.maskedPreview}). Workspace locked down & ${canaryHit.leasesRevoked} active lease(s) revoked.`,
        canaryHit,
      };
    }

    return ctx;
  });

  bus.register('onPreToolWarrant', 'stage2.blast-radius-ast', (ctx) => {
    if (ctx.halted) return ctx;
    const classification = classifyToolAction({
      server: ctx.server,
      tool: ctx.tool,
      args: ctx.args,
      workspaceDir: ctx.workspaceDir,
    });

    if (classification.tier === ACTION_TIERS.TIER_3_UNCONDITIONAL_BLOCK) {
      return {
        ...ctx,
        classification,
        halted: true,
        decision: 'BLOCK',
        exitCode: 2,
        stage: 'BLAST_RADIUS_TIER_3',
        tier: classification.tier,
        ruleId: classification.ruleId,
        code: 'TIER_3_UNCONDITIONAL_BLOCK',
        reason: classification.reason,
      };
    }

    return {
      ...ctx,
      classification,
      tier: classification.tier,
      ruleId: classification.ruleId,
    };
  });

  bus.register('onPreToolWarrant', 'stage2.finops-circuit-breaker', async (ctx) => {
    if (ctx.halted) return ctx;
    const finops = await evaluateFinOpsFuse({
      workspaceDir: ctx.workspaceDir,
      server: ctx.server,
      tool: ctx.tool,
      actionDigest: ctx.classification.normalizedActionDigest,
      estimatedCostUsd: ctx.estimatedCostUsd,
      policy: ctx.finopsPolicy,
    });

    if (!finops.allowed) {
      return {
        ...ctx,
        finops,
        halted: true,
        decision: 'BLOCK',
        exitCode: 2,
        stage: 'FINOPS_CIRCUIT_BREAKER',
        ruleId: finops.ruleId,
        code: finops.ruleId,
        reason: finops.reason,
      };
    }

    return { ...ctx, finops };
  });

  bus.register('onPreToolWarrant', 'stage2.ed25519-warrant-gate', async (ctx) => {
    if (ctx.halted) return ctx;
    if (ctx.classification.tier !== ACTION_TIERS.TIER_2_WARRANT_REQUIRED) {
      return {
        ...ctx,
        decision: 'ALLOW',
        exitCode: 0,
        stage: 'ALLOW_SCOPED',
        code: 'ALLOWED',
        reason: ctx.classification.reason,
      };
    }

    const warrantOutcome = await verifyAndConsumeWarrant({
      workspaceDir: ctx.workspaceDir,
      tokenOrLeaseId: ctx.warrantToken,
      server: ctx.server,
      tool: ctx.tool,
      args: ctx.args,
      tier: ctx.classification.tier,
    });

    if (!warrantOutcome.allowed) {
      return {
        ...ctx,
        warrantOutcome,
        halted: true,
        decision: 'BLOCK',
        exitCode: 2,
        stage: 'WARRANT_GATE',
        code: warrantOutcome.code,
        reason: `${ctx.classification.reason} — ${warrantOutcome.reason}`,
      };
    }

    return {
      ...ctx,
      warrantOutcome,
      decision: 'ALLOW',
      exitCode: 0,
      stage: 'WARRANT_VERIFIED',
      code: warrantOutcome.code,
      reason: `Authorized via Ed25519 ${warrantOutcome.mode} (${warrantOutcome.jti})`,
    };
  });

  const initialCtx = {
    workspaceDir: resolvedWs,
    server: safeServer,
    tool: safeTool,
    args: safeArgs,
    warrantToken,
    estimatedCostUsd,
    finopsPolicy,
    halted: false,
    decision: 'BLOCK',
    exitCode: 2,
    stage: 'INIT',
    tier: ACTION_TIERS.TIER_0_SAFE_READ,
    ruleId: null,
    code: 'UNINITIALIZED',
    reason: '',
    classification: null,
    finops: null,
    warrantOutcome: null,
    snapshotTx: null,
  };

  const { context: preCtx } = await bus.executeSlot('onPreToolWarrant', initialCtx);

  let finalCtx = preCtx;
  if (
    !preCtx.halted &&
    preCtx.decision === 'ALLOW' &&
    autoSnapshot &&
    preCtx.classification &&
    Array.isArray(preCtx.classification.targetPaths) &&
    preCtx.classification.targetPaths.length > 0
  ) {
    bus.register('onPostToolUndo', 'stage2.pre-mutation-shadow-snapshot', async (uCtx) => {
      const snapshotTx = await captureShadowSnapshot({
        workspaceDir: uCtx.workspaceDir,
        targetPaths: uCtx.classification.targetPaths,
        label: `${uCtx.server}:${uCtx.tool}`,
      });
      return { ...uCtx, snapshotTx };
    });

    try {
      const { context: postCtx } = await bus.executeSlot('onPostToolUndo', preCtx);
      finalCtx = postCtx;
    } catch (snapErr) {
      // Fail-closed if symlink escape or oversized file blocks safe snapshotting
      const errCode = /** @type {{ code?: string }} */ (snapErr)?.code || 'SHADOW_SNAPSHOT_FAILED';
      finalCtx = {
        ...preCtx,
        halted: true,
        decision: 'BLOCK',
        exitCode: 2,
        stage: 'SHADOW_UNDO_GUARD',
        ruleId: errCode,
        code: errCode,
        reason: snapErr instanceof Error ? snapErr.message : String(snapErr),
      };
    }
  }

  const durationMs = Number((performance.now() - t0).toFixed(3));
  return {
    decision: /** @type {'ALLOW' | 'BLOCK'} */ (finalCtx.decision),
    exitCode: finalCtx.exitCode,
    stage: finalCtx.stage,
    server: safeServer,
    tool: safeTool,
    tier: finalCtx.tier,
    ruleId: finalCtx.ruleId,
    code: finalCtx.code,
    reason: sanitizeReportText(finalCtx.reason),
    actionDigest: finalCtx.classification?.normalizedActionDigest || null,
    warrant: finalCtx.warrantOutcome || null,
    finops: finalCtx.finops || null,
    snapshotTxId: finalCtx.snapshotTx?.txId || null,
    durationMs,
  };
}

/**
 * Format Stage 2 Pre-Tool Guard outcome inside a strict 78-column max ASCII terminal box.
 * ZERO emojis. ZERO raw secrets.
 *
 * @param {Awaited<ReturnType<typeof evaluatePreToolGuard>>} outcome
 * @returns {string}
 */
export function formatGuardTerminalReport(outcome) {
  const hr = '+' + '-'.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
  const eq = '+' + '='.repeat(TERMINAL_BOX_WIDTH - 2) + '+';
  const row = (txt, indent = '  ') => wrapBoxRow78(txt, indent);

  const lines = [
    eq,
    row('[SHULIAK SIP v3.0 · STAGE 2 AEGIS PRE-TOOL EXECUTION GUARD]'),
    eq,
    row(
      `DECISION: ${outcome.decision.padEnd(6, ' ')} EXIT: ${String(outcome.exitCode)}   LATENCY: ${outcome.durationMs.toFixed(2)} ms`
    ),
    row(`TARGET  : ${outcome.server} :: ${outcome.tool}`),
    row(`TIER    : ${outcome.tier}${outcome.ruleId ? ` (${outcome.ruleId})` : ''}`),
  ];

  if (outcome.actionDigest) {
    lines.push(row(`0x07 JCS: ${outcome.actionDigest}`));
  }
  lines.push(hr);
  lines.push(row(`CODE    : ${outcome.code}`));
  lines.push(row(`REASON  : ${outcome.reason}`, '          '));

  if (outcome.warrant && outcome.warrant.allowed) {
    lines.push(
      row(
        `WARRANT : ${outcome.warrant.mode} [${outcome.warrant.jti}] (rem: ${outcome.warrant.remainingCalls})`
      )
    );
  }
  if (outcome.finops) {
    lines.push(
      row(
        `FINOPS  : ${outcome.finops.callsIn10s} calls/10s · repeat ${outcome.finops.repeatCount}x · $${outcome.finops.sessionSpendUsd.toFixed(2)} USD`
      )
    );
  }
  if (outcome.snapshotTxId) {
    lines.push(row(`SHADOW  : Snapshot ${outcome.snapshotTxId} sealed (.sip/undo)`));
  }

  if (outcome.decision === 'BLOCK' && outcome.tier === ACTION_TIERS.TIER_2_WARRANT_REQUIRED) {
    lines.push(hr);
    lines.push(row('TO ISSUE 1-SHOT ED25519 WARRANT FOR THIS EXACT 0x07 DIGEST:'));
    lines.push(
      row(
        `  $ sip1-mcp warrant issue --server ${outcome.server} --tool ${outcome.tool} --args '<json>'`,
        '    '
      )
    );
  }

  lines.push(eq);
  return lines.join('\n');
}
