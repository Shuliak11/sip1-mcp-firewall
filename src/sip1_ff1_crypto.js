// MODULE 7: NIST SP 800-38G REV. 1 (FF1) BIGINT & STATELESS FPE ENGINE
"use strict";

const crypto = require("crypto");
const { validateLuhnMod10, computeLuhnCheckDigit, validateIbanIso7064 } = require("./sip1_math_validators");

const ALPHABET_36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const MIN_DOMAIN = 1000000n;

function deriveKey32(masterKey) {
  return crypto.createHash("sha256").update(String(masterKey || "shuliak-sip1-default-key")).digest();
}

function aes256EcbBlock(key32, block16) {
  const cipher = crypto.createCipheriv("aes-256-ecb", key32, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block16), cipher.final()]);
}

function strToNumBigInt(str, radix) {
  const r = BigInt(radix);
  let val = 0n;
  for (let i = 0; i < str.length; i++) {
    const d = ALPHABET_36.indexOf(str[i]);
    if (d < 0 || d >= radix) throw new Error("Invalid char for radix " + radix);
    val = val * r + BigInt(d);
  }
  return val;
}

function numToStrBigInt(num, radix, length) {
  const r = BigInt(radix);
  let v = num;
  const out = new Array(length);
  for (let i = length - 1; i >= 0; i--) {
    const rem = Number(v % r);
    v = v / r;
    out[i] = ALPHABET_36[rem];
  }
  return out.join("");
}

function prfFeistelRound(key32, tweakStr, roundIdx, rightNum, radix, n) {
  const h = crypto.createHmac("sha256", key32);
  h.update(Buffer.from(String(tweakStr || ""), "utf8"));
  h.update(Buffer.from([roundIdx, radix & 0xff, n & 0xff]));
  h.update(Buffer.from(rightNum.toString(16).padStart(32, "0"), "hex"));
  const digest = h.digest();
  const ciph = aes256EcbBlock(key32, digest.subarray(0, 16));
  return BigInt("0x" + ciph.toString("hex"));
}

// Strict 10-Round Feistel FF1 over BigInt (Zero Floating-Point Math)
function ff1Encrypt(plainStr, masterKey, tweakStr, radix) {
  const r = Number(radix || 10);
  const s = String(plainStr || "").toUpperCase();
  const n = s.length;
  const domainSize = BigInt(r) ** BigInt(n);
  if (domainSize < MIN_DOMAIN) {
    throw new Error("ERR_NIST_FF1_DOMAIN_TOO_SMALL: radix^n must be >= 1,000,000");
  }
  const key32 = deriveKey32(masterKey);
  const u = Math.floor(n / 2);
  const v = n - u;
  const modU = BigInt(r) ** BigInt(u);
  const modV = BigInt(r) ** BigInt(v);

  let A = strToNumBigInt(s.slice(0, u), r);
  let B = strToNumBigInt(s.slice(u), r);

  for (let i = 0; i < 10; i++) {
    const m = (i % 2 === 0) ? modU : modV;
    const y = prfFeistelRound(key32, tweakStr, i, B, r, n);
    const c = (A + y) % m;
    A = B;
    B = c;
  }
  return numToStrBigInt(A, r, u) + numToStrBigInt(B, r, v);
}

function ff1Decrypt(cipherStr, masterKey, tweakStr, radix) {
  const r = Number(radix || 10);
  const s = String(cipherStr || "").toUpperCase();
  const n = s.length;
  const domainSize = BigInt(r) ** BigInt(n);
  if (domainSize < MIN_DOMAIN) {
    throw new Error("ERR_NIST_FF1_DOMAIN_TOO_SMALL: radix^n must be >= 1,000,000");
  }
  const key32 = deriveKey32(masterKey);
  const u = Math.floor(n / 2);
  const v = n - u;
  const modU = BigInt(r) ** BigInt(u);
  const modV = BigInt(r) ** BigInt(v);

  let A = strToNumBigInt(s.slice(0, u), r);
  let B = strToNumBigInt(s.slice(u), r);

  for (let i = 9; i >= 0; i--) {
    const m = (i % 2 === 0) ? modU : modV;
    const C = B;
    B = A;
    const y = prfFeistelRound(key32, tweakStr, i, B, r, n);
    let diff = (C - (y % m)) % m;
    if (diff < 0n) diff += m;
    A = diff;
  }
  return numToStrBigInt(A, r, u) + numToStrBigInt(B, r, v);
}

// 1. Stateless Checksum-Invariant Payment Card Bijection (Luhn Mod-10)
function encryptPanStatelessFF1(panStr, masterKey, tweakStr) {
  const clean = String(panStr || "").replace(/\D/g, "");
  if (!validateLuhnMod10(clean)) {
    throw new Error("ERR_INVALID_LUHN_PAN");
  }
  const payload = clean.slice(0, -1);
  const encPayload = ff1Encrypt(payload, masterKey, tweakStr || "PAN_V1", 10);
  const newCheck = computeLuhnCheckDigit(encPayload);
  return encPayload + newCheck;
}

function decryptPanStatelessFF1(fpePanStr, masterKey, tweakStr) {
  const clean = String(fpePanStr || "").replace(/\D/g, "");
  if (!validateLuhnMod10(clean)) {
    throw new Error("ERR_INVALID_FPE_PAN_CHECKSUM");
  }
  const encPayload = clean.slice(0, -1);
  const decPayload = ff1Decrypt(encPayload, masterKey, tweakStr || "PAN_V1", 10);
  const origCheck = computeLuhnCheckDigit(decPayload);
  return decPayload + origCheck;
}

// 2. Stateless Checksum-Invariant IBAN Bijection (ISO/IEC 7064 MOD 97-10)
function computeIbanCheckDigits(cc, bban) {
  const rearranged = (bban + cc + "00").toUpperCase();
  let numStr = "";
  for (let i = 0; i < rearranged.length; i++) {
    const c = rearranged.charCodeAt(i);
    numStr += (c >= 65 && c <= 90) ? String(c - 55) : rearranged[i];
  }
  const rem = BigInt(numStr) % 97n;
  const cd = 98n - rem;
  return String(cd).padStart(2, "0");
}

function encryptIbanStatelessFF1(ibanStr, masterKey, tweakStr) {
  const clean = String(ibanStr || "").replace(/\s+/g, "").toUpperCase();
  if (!validateIbanIso7064(clean)) {
    throw new Error("ERR_INVALID_ISO7064_IBAN");
  }
  const cc = clean.slice(0, 2);
  const bban = clean.slice(4);
  const isDigitsOnly = /^\d+$/.test(bban);
  const radix = isDigitsOnly ? 10 : 36;
  const encBban = ff1Encrypt(bban, masterKey, (tweakStr || "IBAN_V1") + ":" + cc, radix);
  const newCd = computeIbanCheckDigits(cc, encBban);
  return cc + newCd + encBban;
}

function decryptIbanStatelessFF1(fpeIbanStr, masterKey, tweakStr) {
  const clean = String(fpeIbanStr || "").replace(/\s+/g, "").toUpperCase();
  if (!validateIbanIso7064(clean)) {
    throw new Error("ERR_INVALID_FPE_IBAN_CHECKSUM");
  }
  const cc = clean.slice(0, 2);
  const encBban = clean.slice(4);
  const isDigitsOnly = /^\d+$/.test(encBban);
  const radix = isDigitsOnly ? 10 : 36;
  const origBban = ff1Decrypt(encBban, masterKey, (tweakStr || "IBAN_V1") + ":" + cc, radix);
  const origCd = computeIbanCheckDigits(cc, origBban);
  return cc + origCd + origBban;
}

// 3. Authenticated AES-256-GCM Capsule (for short/arbitrary secrets)
function encryptCapsuleAes256Gcm(plainText, masterKey, aadContext) {
  const key32 = deriveKey32(masterKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key32, iv);
  if (aadContext) cipher.setAAD(Buffer.from(String(aadContext), "utf8"));
  const enc = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString("hex") + ":" + tag.toString("hex") + ":" + enc.toString("hex");
}

function decryptCapsuleAes256Gcm(capsuleStr, masterKey, aadContext) {
  const parts = String(capsuleStr || "").split(":");
  if (parts.length !== 3) throw new Error("ERR_INVALID_CAPSULE_FORMAT");
  const key32 = deriveKey32(masterKey);
  const iv = Buffer.from(parts[0], "hex");
  const tag = Buffer.from(parts[1], "hex");
  const enc = Buffer.from(parts[2], "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key32, iv);
  if (aadContext) decipher.setAAD(Buffer.from(String(aadContext), "utf8"));
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString("utf8");
}

// 4. Tamper-Evident SHA-256 Hash-Chained Audit Ledger
class Sip1AuditLedger {
  constructor() {
    this.chain = [];
    this.headHash = "0".repeat(64);
  }
  append(action, cls, tokenTag) {
    const idx = this.chain.length + 1;
    const ts = new Date().toISOString();
    const payload = `${idx}|${ts}|${action}|${cls}|${tokenTag}|${this.headHash}`;
    const currHash = crypto.createHash("sha256").update(payload).digest("hex");
    const entry = { index: idx, timestamp: ts, action, cls, tokenTag, prevHash: this.headHash, hash: currHash };
    this.chain.push(entry);
    this.headHash = currHash;
    return entry;
  }
  verifyIntegrity() {
    let prev = "0".repeat(64);
    for (const item of this.chain) {
      if (item.prevHash !== prev) return false;
      const payload = `${item.index}|${item.timestamp}|${item.action}|${item.cls}|${item.tokenTag}|${prev}`;
      const expected = crypto.createHash("sha256").update(payload).digest("hex");
      if (expected !== item.hash) return false;
      prev = item.hash;
    }
    return true;
  }
}

module.exports = {
  ff1Encrypt,
  ff1Decrypt,
  encryptPanStatelessFF1,
  decryptPanStatelessFF1,
  encryptIbanStatelessFF1,
  decryptIbanStatelessFF1,
  encryptCapsuleAes256Gcm,
  decryptCapsuleAes256Gcm,
  Sip1AuditLedger
};
