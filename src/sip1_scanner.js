// UNIFIED MASTER SCANNER v2.5 (ZERO-CONFLICT EDITION)
"use strict";

const crypto = require("crypto");
const { SIP1_CONTRACT, formatSip1Token } = require("./sip1_contract");
const { AhoCorasickAutomaton, DEFAULT_PREFIXES } = require("./sip1_aho_corasick");
const { validateLuhnMod10, validateIbanIso7064, validateVerhoeffD5, validateUsSsn } = require("./sip1_math_validators");
const { evaluate26FeatureSecretVector } = require("./sip1_entropy_26vec");
const { sanitizeZeroWidthUnicode, inspectMcpJsonRpcPayload } = require("./sip1_mcp_sanitizer");

class VaultSessionMap {
  constructor(keyId) {
    this.keyId = keyId || "k01";
    this.tokenToPlain = new Map();
    this.plainToToken = new Map();
  }
  store(cls, plainVal, mask, tag) {
    const p = String(plainVal);
    if (this.plainToToken.has(p)) return this.plainToToken.get(p);
    const tok = formatSip1Token(cls, this.keyId, mask, tag);
    this.tokenToPlain.set(tok, p);
    this.plainToToken.set(p, tok);
    return tok;
  }
  rehydrate(text) {
    let out = String(text || "");
    const entries = Array.from(this.tokenToPlain.entries()).reverse();
    for (const [tok, plain] of entries) {
      if (out.includes(tok)) out = out.split(tok).join(plain);
    }
    return out;
  }
}

class SIP1Scanner {
  constructor() {
    this.ac = new AhoCorasickAutomaton(DEFAULT_PREFIXES);
    this.automaton = this.ac;
  }
  makeTag(val) {
    return crypto.createHash("sha256").update(String(val)).digest("hex").slice(0, 8);
  }
  createSession(keyId) {
    return new VaultSessionMap(keyId || "k01");
  }
  scanText(input, opts) {
    const t0 = process.hrtime.bigint();
    const options = opts || {};
    const session = options.session || new VaultSessionMap(options.keyId || "k01");
    const findings = [];

    // Protect existing SIP1 tokens & FPE guards from double-tokenization
    const guards = [];
    let raw = String(input || "").replace(/(\[SIP1:v\d+:[^\]]+\]|__FPE_GUARD_\d+__)/g, (m) => {
      const idx = guards.length;
      guards.push(m);
      return `__SIP1_TOK_${idx}__`;
    });

    const zw = sanitizeZeroWidthUnicode(raw);
    let working = zw.cleanText;
    if (zw.detected) findings.push({ cls: "MCP_UNICODE_INJ", count: zw.strippedCount });

    // PEM Keys & DB URIs
    working = working.replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, (m) => {
      const tok = session.store("PRIVATE_KEY", m, "PEM....KEY", this.makeTag(m));
      findings.push({ cls: "PRIVATE_KEY", token: tok });
      return tok;
    });
    working = working.replace(/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s"'<>]+/gi, (m) => {
      const tok = session.store("CLOUD_KEY", m, m.split("://")[0] + "://....", this.makeTag(m));
      findings.push({ cls: "CLOUD_KEY", token: tok });
      return tok;
    });

    // Cloud, API & 2026 AI Keys
    const tokenRx = /(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,82}|xox[baprs]-[A-Za-z0-9-]{10,48}|sk-ant-api03-[A-Za-z0-9_-]{20,}|xai-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|sbp_[A-Za-z0-9]{20,}|dop_v1_[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-live-[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|AIzaSy[A-Za-z0-9_-]{33}|eyJhbGciOi[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/g;
    working = working.replace(tokenRx, (m) => {
      const tok = session.store("CLOUD_KEY", m, m.slice(0, 4) + "...." + m.slice(-4), this.makeTag(m));
      findings.push({ cls: "CLOUD_KEY", token: tok });
      return tok;
    });

    // ISO-7064 Mod-97 IBAN
    working = working.replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, (m) => {
      if (!validateIbanIso7064(m)) return m;
      const tok = session.store("IBAN_ISO7064", m, m.slice(0, 4) + "...." + m.slice(-4), this.makeTag(m));
      findings.push({ cls: "IBAN_ISO7064", token: tok });
      return tok;
    });

    // Luhn Mod-10 Cards, US SSN, Verhoeff D5
    working = working.replace(/\b(?:\d[ -]*?){13,19}\b/g, (m) => {
      if (!validateLuhnMod10(m)) return m;
      const clean = m.replace(/\D/g, "");
      const tok = session.store("PAN_LUHN", m, clean.slice(0, 4) + "...." + clean.slice(-4), this.makeTag(clean));
      findings.push({ cls: "PAN_LUHN", token: tok });
      return tok;
    });
    working = working.replace(/\b\d{3}-\d{2}-\d{4}\b/g, (m) => {
      if (!validateUsSsn(m)) return m;
      const tok = session.store("US_SSN", m, "***-**-" + m.slice(-4), this.makeTag(m));
      findings.push({ cls: "US_SSN", token: tok });
      return tok;
    });
    working = working.replace(/(\b(?:verhoeff_id|id_verhoeff|national_id|uid_d5)\s*[:=]\s*)(\d{2,32})\b/gi, (full, pfx, num) => {
      if (!validateVerhoeffD5(num)) return full;
      const tok = session.store("ID_VERHOEFF", num, num.slice(0, 2) + ".." + num.slice(-1), this.makeTag(num));
      findings.push({ cls: "ID_VERHOEFF", token: tok });
      return pfx + tok;
    });

    // 26-Feature Entropy Context Assignments
    working = working.replace(/((?:password|passwd|pwd|secret|api_key|apikey|token|bearer|private_key|client_secret|auth_secret)\s*[:=]\s*["']?)([^\s"',;]{12,128})(["']?)/gi, (full, ctx, cand, q) => {
      if (cand.startsWith("[SIP1:") || cand.startsWith("__SIP1_TOK_")) return full;
      const ev = evaluate26FeatureSecretVector(cand, ctx);
      if (!ev.isSecret) return full;
      const tok = session.store("ENTROPY_SECRET", cand, cand.slice(0, 2) + "...." + cand.slice(-2), this.makeTag(cand));
      findings.push({ cls: "ENTROPY_SECRET", token: tok });
      return ctx + tok + q;
    });

    for (let i = 0; i < guards.length; i++) {
      working = working.replace(`__SIP1_TOK_${i}__`, guards[i]);
    }

    const t1 = process.hrtime.bigint();
    return {
      sanitizedText: working,
      maskedText: working,
      text: working,
      findingsCount: findings.length,
      findings,
      session,
      zeroWidthStripped: zw.strippedCount,
      latencyMicroseconds: Number(t1 - t0) / 1000.0
    };
  }

  rehydrateText(maskedText, session) {
    if (!session || typeof session.rehydrate !== "function") return String(maskedText || "");
    return session.rehydrate(maskedText);
  }

  scanMcpPacket(packet, opts) {
    const options = opts || {};
    const session = options.session || new VaultSessionMap(options.keyId || "k01");
    const isStr = typeof packet === "string";
    const obj = isStr ? JSON.parse(packet) : JSON.parse(JSON.stringify(packet || {}));
    const secAudit = inspectMcpJsonRpcPayload(obj);
    let totalFindings = 0;
    const walk = (node) => {
      if (typeof node === "string") {
        const r = this.scanText(node, { session });
        totalFindings += r.findingsCount;
        return r.sanitizedText;
      }
      if (Array.isArray(node)) return node.map(walk);
      if (node && typeof node === "object") {
        const out = {};
        for (const k of Object.keys(node)) out[k] = walk(node[k]);
        return out;
      }
      return node;
    };
    const sanitizedObj = walk(obj);
    return { safe: secAudit.safe, threats: secAudit.threats, findingsCount: totalFindings, session, packet: isStr ? JSON.stringify(sanitizedObj) : sanitizedObj };
  }
}

SIP1Scanner.prototype.rehydrateMcpPacket = function(p, s) { const isS = typeof p === "string"; const o = isS ? JSON.parse(p) : JSON.parse(JSON.stringify(p||{})); const w = (n) => typeof n === "string" ? this.rehydrateText(n, s) : (Array.isArray(n) ? n.map(w) : (n && typeof n === "object" ? Object.fromEntries(Object.entries(n).map(([k,v])=>[k,w(v)])) : n)); const r = w(o); return isS ? JSON.stringify(r) : r; };
module.exports = { SIP1Scanner, VaultSessionMap };
