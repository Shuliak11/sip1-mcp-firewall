/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Unicorn Foundation Microkernel Pipeline Bus
 * Deterministic Stage 1-4 hook orchestration with high-resolution performance.now() telemetry.
 */

import { performance } from 'node:perf_hooks';

export const SIP_PIPELINE_SLOTS = Object.freeze([
  // Stage 1: Discovery, Risk Audit & RFC 8785 Schema Lock
  'onConfigAudit',
  'onSchemaLock',
  // Stage 2: Pre-Tool Execution Warrant & Transactional Post-Tool Undo
  'onPreToolWarrant',
  'onPostToolUndo',
  // Stage 3: ISEP Cryptographic Recording & Crypto-Shredding
  'onIsepRecord',
  'onIsepShred',
  // Stage 4: Deterministic Compliance Verification
  'onAuditVerify',
]);

export class SipPipelineBus {
  constructor() {
    /** @type {Map<string, Array<{ id: string, fn: (ctx: any) => any }>>} */
    this._slots = new Map();
    for (const slot of SIP_PIPELINE_SLOTS) {
      this._slots.set(slot, []);
    }
    /** @type {Array<{ slot: string, handlerId: string, durationMs: number, ok: boolean, ts: number }>} */
    this._telemetry = [];
  }

  /**
   * List all canonical Stage 1-4 pipeline slots.
   * @returns {readonly string[]}
   */
  listSlots() {
    return SIP_PIPELINE_SLOTS;
  }

  /**
   * Register a deterministic handler into a named microkernel slot.
   * @param {string} slotName
   * @param {string} handlerId
   * @param {(ctx: any) => any} handlerFn
   * @returns {() => void} Unsubscribe callback
   */
  register(slotName, handlerId, handlerFn) {
    const handlers = this._slots.get(slotName);
    if (!handlers) {
      throw new Error(
        `Unknown SIP pipeline slot "${slotName}". Expected one of: ${SIP_PIPELINE_SLOTS.join(', ')}`
      );
    }
    if (typeof handlerId !== 'string' || !handlerId.trim()) {
      throw new TypeError('handlerId must be a non-empty string');
    }
    if (typeof handlerFn !== 'function') {
      throw new TypeError('handlerFn must be a function');
    }

    const entry = { id: handlerId, fn: handlerFn };
    handlers.push(entry);

    return () => {
      const idx = handlers.indexOf(entry);
      if (idx !== -1) {
        handlers.splice(idx, 1);
      }
    };
  }

  /**
   * Execute all registered handlers for `slotName` sequentially in registration order,
   * recording sub-millisecond `performance.now()` latency telemetry.
   *
   * @template T
   * @param {string} slotName
   * @param {T} context
   * @returns {Promise<{ context: T, slotDurationMs: number, steps: Array<{ handlerId: string, durationMs: number }> }>}
   */
  async executeSlot(slotName, context) {
    const handlers = this._slots.get(slotName);
    if (!handlers) {
      throw new Error(`Unknown SIP pipeline slot "${slotName}"`);
    }

    const slotStart = performance.now();
    const steps = [];
    let currentCtx = context;

    for (const handler of handlers) {
      const stepStart = performance.now();
      let ok = true;
      try {
        const maybeUpdated = await handler.fn(currentCtx);
        if (maybeUpdated !== undefined) {
          currentCtx = maybeUpdated;
        }
      } catch (err) {
        ok = false;
        throw err;
      } finally {
        const durationMs = Number((performance.now() - stepStart).toFixed(4));
        steps.push({ handlerId: handler.id, durationMs });
        this._telemetry.push({
          slot: slotName,
          handlerId: handler.id,
          durationMs,
          ok,
          ts: Date.now(),
        });
      }
    }

    const slotDurationMs = Number((performance.now() - slotStart).toFixed(4));
    return { context: currentCtx, slotDurationMs, steps };
  }

  /**
   * Return recorded execution telemetry entries.
   */
  getTelemetry() {
    return [...this._telemetry];
  }

  /**
   * Clear recorded execution telemetry.
   */
  clearTelemetry() {
    this._telemetry.length = 0;
  }
}
