/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 2 FinOps Velocity & Idempotent Error-Loop Circuit Breaker
 * Persisted atomically in `.sip/state/finops-window.json`.
 */

import fs from 'node:fs';
import path from 'node:path';
import { withPidLock, writeFileAtomic600 } from '../core/workspace-io.mjs';

const DEFAULT_POLICY = Object.freeze({
  maxCallsPer10s: 25,
  maxSessionUsd: 5.0,
  loopRepeatThreshold: 4,
  loopWindowMs: 60_000,
  ringBufferMax: 200,
});

function readFinOpsState(statePath) {
  if (!fs.existsSync(statePath)) {
    return {
      sessionSpendUsd: 0,
      callTimestampsMs: [],
      recentActions: [],
      circuitTripped: null,
    };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    return {
      sessionSpendUsd: typeof parsed?.sessionSpendUsd === 'number' ? parsed.sessionSpendUsd : 0,
      callTimestampsMs: Array.isArray(parsed?.callTimestampsMs) ? parsed.callTimestampsMs : [],
      recentActions: Array.isArray(parsed?.recentActions) ? parsed.recentActions : [],
      circuitTripped: parsed?.circuitTripped || null,
    };
  } catch {
    return {
      sessionSpendUsd: 0,
      callTimestampsMs: [],
      recentActions: [],
      circuitTripped: null,
    };
  }
}

/**
 * Evaluate FinOps Velocity (`SIP-F01_VELOCITY_SPIKE`) & Runaway Loop (`SIP-F02_INFINITE_ERROR_LOOP`) tripwires.
 *
 * @param {{
 *   workspaceDir: string,
 *   server: string,
 *   tool: string,
 *   actionDigest: string,
 *   estimatedCostUsd?: number,
 *   policy?: Partial<typeof DEFAULT_POLICY>,
 * }} params
 */
export async function evaluateFinOpsFuse({
  workspaceDir,
  server,
  tool,
  actionDigest,
  estimatedCostUsd = 0.01,
  policy = {},
}) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const statePath = path.join(sipDir, 'state', 'finops-window.json');

  const maxCallsPer10s = policy.maxCallsPer10s ?? DEFAULT_POLICY.maxCallsPer10s;
  const maxSessionUsd = policy.maxSessionUsd ?? DEFAULT_POLICY.maxSessionUsd;
  const loopRepeatThreshold = policy.loopRepeatThreshold ?? DEFAULT_POLICY.loopRepeatThreshold;
  const loopWindowMs = policy.loopWindowMs ?? DEFAULT_POLICY.loopWindowMs;

  return withPidLock(sipDir, () => {
    const now = Date.now();
    const state = readFinOpsState(statePath);

    // Prune rolling windows
    const recent10s = state.callTimestampsMs.filter((ts) => now - ts <= 10_000);
    const recentLoopWindow = state.recentActions.filter((entry) => now - entry.ts <= loopWindowMs);

    const nextCallsIn10s = recent10s.length + 1;
    const nextSpendUsd = Number((state.sessionSpendUsd + Number(estimatedCostUsd)).toFixed(6));

    const matchingRecentCount =
      recentLoopWindow.filter(
        (e) =>
          e.server === String(server) &&
          e.tool === String(tool) &&
          e.actionDigest === String(actionDigest)
      ).length + 1;

    // Tripwire 1: SIP-F01_VELOCITY_SPIKE
    if (nextCallsIn10s > maxCallsPer10s || nextSpendUsd > maxSessionUsd) {
      const reason =
        nextCallsIn10s > maxCallsPer10s
          ? `Velocity spike: ${nextCallsIn10s} tool calls in 10s exceeds cap (${maxCallsPer10s})`
          : `Session FinOps budget exceeded: $${nextSpendUsd.toFixed(2)} > $${maxSessionUsd.toFixed(2)} cap`;

      state.callTimestampsMs = recent10s;
      state.recentActions = recentLoopWindow.slice(-DEFAULT_POLICY.ringBufferMax);
      state.circuitTripped = {
        ruleId: 'SIP-F01_VELOCITY_SPIKE',
        reason,
        trippedAt: now,
      };
      writeFileAtomic600(statePath, JSON.stringify(state, null, 2) + '\n');

      return {
        allowed: false,
        tripped: true,
        ruleId: 'SIP-F01_VELOCITY_SPIKE',
        reason,
        repeatCount: matchingRecentCount,
        callsIn10s: nextCallsIn10s,
        sessionSpendUsd: state.sessionSpendUsd,
      };
    }

    // Tripwire 2: SIP-F02_INFINITE_ERROR_LOOP
    if (matchingRecentCount >= loopRepeatThreshold) {
      const reason = `Idempotent agent loop circuit breaker: identical (${server}:${tool}) call repeated ${matchingRecentCount}x within 60s`;
      recentLoopWindow.push({
        ts: now,
        server: String(server),
        tool: String(tool),
        actionDigest: String(actionDigest),
      });
      state.callTimestampsMs = recent10s;
      state.recentActions = recentLoopWindow.slice(-DEFAULT_POLICY.ringBufferMax);
      state.circuitTripped = {
        ruleId: 'SIP-F02_INFINITE_ERROR_LOOP',
        reason,
        trippedAt: now,
      };
      writeFileAtomic600(statePath, JSON.stringify(state, null, 2) + '\n');

      return {
        allowed: false,
        tripped: true,
        ruleId: 'SIP-F02_INFINITE_ERROR_LOOP',
        reason,
        repeatCount: matchingRecentCount,
        callsIn10s: nextCallsIn10s,
        sessionSpendUsd: state.sessionSpendUsd,
      };
    }

    // Record healthy call
    recent10s.push(now);
    recentLoopWindow.push({
      ts: now,
      server: String(server),
      tool: String(tool),
      actionDigest: String(actionDigest),
    });

    state.sessionSpendUsd = nextSpendUsd;
    state.callTimestampsMs = recent10s;
    state.recentActions = recentLoopWindow.slice(-DEFAULT_POLICY.ringBufferMax);
    state.circuitTripped = null;

    writeFileAtomic600(statePath, JSON.stringify(state, null, 2) + '\n');

    return {
      allowed: true,
      tripped: false,
      ruleId: null,
      reason: null,
      repeatCount: matchingRecentCount,
      callsIn10s: nextCallsIn10s,
      sessionSpendUsd: nextSpendUsd,
    };
  });
}

/**
 * Reset FinOps sliding window & spend counters for workspace.
 * @param {{ workspaceDir: string }} params
 */
export async function resetFinOpsFuse({ workspaceDir }) {
  const resolvedWs = path.resolve(workspaceDir || process.cwd());
  const sipDir = path.join(resolvedWs, '.sip');
  const statePath = path.join(sipDir, 'state', 'finops-window.json');

  return withPidLock(sipDir, () => {
    const clean = {
      sessionSpendUsd: 0,
      callTimestampsMs: [],
      recentActions: [],
      circuitTripped: null,
    };
    writeFileAtomic600(statePath, JSON.stringify(clean, null, 2) + '\n');
    return clean;
  });
}
