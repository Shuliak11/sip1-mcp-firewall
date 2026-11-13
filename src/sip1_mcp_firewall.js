// MODULE 9: SHULIAK SIP-1 STDIO & HTTP JSON-RPC 2.0 MCP FIREWALL
"use strict";

const { verifyLicenseKeyOffline } = require("./sip1_license_engine");


const crypto = require("crypto");
const { SIP1Scanner } = require("./sip1_scanner");
const { encryptPanStatelessFF1, decryptPanStatelessFF1, encryptIbanStatelessFF1, decryptIbanStatelessFF1, Sip1AuditLedger } = require("./sip1_ff1_crypto");
const { validateLuhnMod10, validateIbanIso7064 } = require("./sip1_math_validators");
const { loadSip1WasmKernelSync } = require("./sip1_wasm_builder");

class Sip1McpFirewall {
  constructor(opts) {
    const options = opts || {};
    this.masterKey = options.masterKey || "shuliak-sip1-enterprise-key";
    this.tweak = options.tweak || "MCP_STDIO_V1";
    this.mode = options.mode || "FF1_STATELESS_HYBRID";
    this.licenseKey = options.licenseKey !== undefined ? options.licenseKey : (process.env.SIP1_LICENSE_KEY || "");
    this.enforcePaywall = options.enforcePaywall === true;
    this.callCount = 0;
    this.scanner = new SIP1Scanner();
    this.session = this.scanner.createSession("mcp01");
    this.fpeReverseMap = new Map();
    this.ledger = new Sip1AuditLedger();
    this.wasm = loadSip1WasmKernelSync();
    this._jitWarmup = encryptPanStatelessFF1("4532015112830366", this.masterKey, this.tweak);
  }

  transformStringOutbound(str) {
    let text = String(str || "");
    let fpeCount = 0;

    // 1. Stateless Checksum-Invariant IBAN FPE
    text = text.replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, (m) => {
      if (!validateIbanIso7064(m)) return m;
      const fpeIban = encryptIbanStatelessFF1(m, this.masterKey, this.tweak);
      this.fpeReverseMap.set(fpeIban, m);
      this.ledger.append("MCP_FF1_IBAN", "IBAN_ISO7064", fpeIban.slice(0, 8));
      fpeCount++;
      return fpeIban;
    });

    // 2. Stateless Checksum-Invariant Payment Card FPE
    text = text.replace(/\b(?:\d[ -]*?){13,19}\b/g, (m) => {
      const clean = m.replace(/\D/g, "");
      if (!validateLuhnMod10(clean)) return m;
      const fpePan = encryptPanStatelessFF1(clean, this.masterKey, this.tweak);
      this.fpeReverseMap.set(fpePan, m);
      this.ledger.append("MCP_FF1_PAN", "PAN_LUHN", fpePan.slice(0, 6));
      fpeCount++;
      return fpePan;
    });

    // 3. Protect FPE twins before running 7-Stage Scanner so they remain valid 16-digit/22-char twins!
    const fpeGuards = [];
    for (const fpeKey of this.fpeReverseMap.keys()) {
      if (text.includes(fpeKey)) {
        const gId = `__FPE_GUARD_${fpeGuards.length}__`;
        fpeGuards.push({ gId, fpeKey });
        text = text.split(fpeKey).join(gId);
      }
    }
    const scanRes = this.scanner.scanText(text, { session: this.session });
    let finalOut = scanRes.sanitizedText;
    for (const item of fpeGuards) {
      finalOut = finalOut.split(item.gId).join(item.fpeKey);
    }
    return {
      text: finalOut,
      findingsCount: fpeCount + scanRes.findingsCount,
      zeroWidthStripped: scanRes.zeroWidthStripped
    };
  }

  restoreStringInbound(str) {
    let out = this.scanner.rehydrateText(String(str || ""), this.session);
    for (const [fpeVal, origVal] of this.fpeReverseMap.entries()) {
      if (out.includes(fpeVal)) {
        out = out.split(fpeVal).join(origVal);
      }
    }
    return out;
  }

  interceptJsonRpcRequest(packet) {
    const t0 = process.hrtime.bigint();
    const isStr = typeof packet === "string";
    const obj = isStr ? JSON.parse(packet) : JSON.parse(JSON.stringify(packet || {}));

    // Check for OWASP MCP05 / MCP06 exploits first
    const baseCheck = this.scanner.scanMcpPacket(obj, { session: this.session });
    if (!baseCheck.safe) {
      this.ledger.append("QUARANTINE_BLOCK", baseCheck.threats[0].code, "BLOCKED");
      const errResp = {
        jsonrpc: "2.0",
        id: obj.id !== undefined ? obj.id : null,
        error: {
          code: -32001,
          message: "SHULIAK SIP-1 MCP Firewall Blocked Exploit: " + baseCheck.threats.map(t => t.code).join(", "),
          data: { threats: baseCheck.threats, protocol: "SIP-1" }
        }
      };
      return { allowed: false, quarantined: true, threats: baseCheck.threats, packet: isStr ? JSON.stringify(errResp) : errResp };
    }

    let totalProtected = 0;
    const walkOut = (node) => {
      if (typeof node === "string") {
        const r = this.transformStringOutbound(node);
        totalProtected += r.findingsCount;
        return r.text;
      }
      if (Array.isArray(node)) return node.map(walkOut);
      if (node && typeof node === "object") {
        const res = {};
        for (const k of Object.keys(node)) res[k] = walkOut(node[k]);
        return res;
      }
      return node;
    };

    const scrubbedObj = walkOut(obj);
    const t1 = process.hrtime.bigint();
    return {
      allowed: true,
      quarantined: false,
      threats: [],
      findingsProtected: totalProtected,
      latencyUs: Number(t1 - t0) / 1000.0,
      packet: isStr ? JSON.stringify(scrubbedObj) : scrubbedObj
    };
  }

  interceptJsonRpcResponse(packet) {
    const isStr = typeof packet === "string";
    const obj = isStr ? JSON.parse(packet) : JSON.parse(JSON.stringify(packet || {}));

    // Strip any indirect prompt injections / tool poisoning in response
    const secCheck = this.scanner.scanMcpPacket(obj, { session: this.session });
    if (!secCheck.safe) {
      this.ledger.append("RESPONSE_POISON_BLOCK", secCheck.threats[0].code, "BLOCKED");
      return { safe: false, threats: secCheck.threats, quarantined: true };
    }

    const walkIn = (node) => {
      if (typeof node === "string") return this.restoreStringInbound(node);
      if (Array.isArray(node)) return node.map(walkIn);
      if (node && typeof node === "object") {
        const res = {};
        for (const k of Object.keys(node)) res[k] = walkIn(node[k]);
        return res;
      }
      return node;
    };

    const restoredObj = walkIn(obj);
    return {
      safe: true,
      quarantined: false,
      packet: isStr ? JSON.stringify(restoredObj) : restoredObj
    };
  }

  generateAibomAttestation(orgName) {
    return {
      schema: "SHULIAK-SIP1-AIBOM-2026-v1",
      ietfDraft: "draft-shuliak-sip-zero-egress-00",
      organization: orgName || "Enterprise Tenant",
      timestamp: new Date().toISOString(),
      wasmKernelVersion: this.wasm.exports.sip1ProtocolVersion(),
      fpeStandard: "NIST-SP-800-38G-Rev1-FF1-BIGINT",
      auditChainIntact: this.ledger.verifyIntegrity(),
      totalAuditEvents: this.ledger.chain.length,
      merkleHeadHash: this.ledger.headHash
    };
  }
}

module.exports = { Sip1McpFirewall };
