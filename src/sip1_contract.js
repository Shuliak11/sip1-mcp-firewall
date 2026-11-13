// MODULE 1: SIP-1 IMMUTABLE PROTOCOL CONTRACT & VAULT SESSION MAP
"use strict";

const SIP1_CONTRACT = Object.freeze({
  PROTOCOL_ID: "SIP1",
  VERSION: "v1",
  IETF_DRAFT: "draft-shuliak-sip-zero-egress-00",
  NIST_FPE_STANDARD: "NIST-SP-800-38G-Rev1-FF1-ONLY",
  FF3_STATUS: "WITHDRAWN_FEB_2025",
  MIN_DOMAIN_SIZE: 1000000n,
  ALLOW_FLOAT_MATH: false,
  CLASSES: Object.freeze({
    PAN_LUHN: "PAN_LUHN", IBAN_ISO7064: "IBAN_ISO7064", ID_VERHOEFF: "ID_VERHOEFF",
    US_SSN: "US_SSN", CLOUD_KEY: "CLOUD_KEY", PRIVATE_KEY: "PRIVATE_KEY",
    ENTROPY_SECRET: "ENTROPY_SECRET", MCP_UNICODE_INJ: "MCP_UNICODE_INJ",
    MCP_PATH_TRAV: "MCP_PATH_TRAV", MCP_CMD_INJ: "MCP_CMD_INJ"
  })
});

function formatSip1Token(cls, keyId, mask, tag) {
  return `[SIP1:v1:${cls||"SECRET"}:${keyId||"k01"}:${mask||"MASK"}:${String(tag||"00000000").slice(0,8)}]`;
}

function parseSip1Token(str) {
  const m = String(str||"").match(/^\[SIP1:(v\d+):([A-Z0-9_]+):([^:]+):([^:]+):([a-f0-9]{8})\]$/i);
  return m ? { version: m[1], cls: m[2], keyId: m[3], mask: m[4], tag: m[5] } : null;
}

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

module.exports = { SIP1_CONTRACT, formatSip1Token, parseSip1Token, VaultSessionMap };
