// MODULE 7: EXACT NIST SP 800-38G REV. 1 (FF1) CAVP-VERIFIED ENGINE
"use strict";

const crypto = require("crypto");
const { validateLuhnMod10, computeLuhnCheckDigit, validateIbanIso7064 } = require("./sip1_math_validators");

const ALPH_LOWER = "0123456789abcdefghijklmnopqrstuvwxyz";
const ALPH_UPPER = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const MIN_DOMAIN = 1000000n;

function resolveAesKeyAndMode(masterKey) {
  if (Buffer.isBuffer(masterKey) && (masterKey.length === 16 || masterKey.length === 24 || masterKey.length === 32)) {
    return { keyBuf: masterKey, alg: `aes-${masterKey.length * 8}-ecb` };
  }
  const keyBuf = crypto.createHash("sha256").update(String(masterKey || "shuliak-sip1-default-key")).digest();
  return { keyBuf, alg: "aes-256-ecb" };
}

function aesEcbBlock(alg, keyBuf, block16) {
  const c = crypto.createCipheriv(alg, keyBuf, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block16), c.final()]);
}

function prfCbcMac(alg, keyBuf, dataBuf) {
  let y = Buffer.alloc(16, 0);
  for (let off = 0; off < dataBuf.length; off += 16) {
    const blk = Buffer.alloc(16, 0);
    for (let k = 0; k < 16; k++) blk[k] = y[k] ^ dataBuf[off + k];
    y = aesEcbBlock(alg, keyBuf, blk);
  }
  return y;
}

function strToBigInt(str, radix, alph) {
  const r = BigInt(radix);
  let v = 0n;
  for (let i = 0; i < str.length; i++) {
    const idx = alph.indexOf(str[i]);
    if (idx < 0 || idx >= radix) throw new Error("ERR_INVALID_RADIX_CHAR");
    v = v * r + BigInt(idx);
  }
  return v;
}

function bigIntToStr(num, radix, len, alph) {
  const r = BigInt(radix);
  let v = num;
  const out = new Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = alph[Number(v % r)];
    v = v / r;
  }
  return out.join("");
}

function prepareNistParams(strInput, masterKey, tweakInput, radix) {
  const r = Number(radix || 10);
  const rawStr = String(strInput || "");
  const hasLower = /[a-z]/.test(rawStr);
  const alph = hasLower ? ALPH_LOWER : ALPH_UPPER;
  const s = hasLower ? rawStr.toLowerCase() : rawStr.toUpperCase();
  const n = s.length;
  if ((BigInt(r) ** BigInt(n)) < MIN_DOMAIN) {
    throw new Error("ERR_NIST_FF1_DOMAIN_TOO_SMALL: radix^n must be >= 1,000,000");
  }
  const { keyBuf, alg } = resolveAesKeyAndMode(masterKey);
  const tweakBuf = Buffer.isBuffer(tweakInput) ? tweakInput : Buffer.from(String(tweakInput || ""), "utf8");
  const t = tweakBuf.length;
  const u = Math.floor(n / 2);
  const v = n - u;
  const maxVal = (BigInt(r) ** BigInt(v)) - 1n;
  const bitlen = maxVal > 0n ? maxVal.toString(2).length : 1;
  const b = Math.floor((bitlen + 7) / 8);
  const d = 4 * Math.floor((b + 3) / 4) + 4;

  const P = Buffer.alloc(16, 0);
  P[0] = 1; P[1] = 2; P[2] = 1;
  P[3] = (r >>> 16) & 0xff; P[4] = (r >>> 8) & 0xff; P[5] = r & 0xff;
  P[6] = 10; P[7] = u & 0xff;
  P.writeUInt32BE(n, 8);
  P.writeUInt32BE(t, 12);

  const padLen = ((-t - b - 1) % 16 + 16) % 16;
  return { r, alph, s, n, keyBuf, alg, tweakBuf, t, u, v, b, d, P, padLen };
}

function computeRoundY(alg, keyBuf, P, tweakBuf, padLen, b, d, roundIdx, numB) {
  const bHex = numB.toString(16).padStart(b * 2, "0");
  const bBytes = Buffer.from(bHex, "hex");
  const Q = Buffer.concat([tweakBuf, Buffer.alloc(padLen, 0), Buffer.from([roundIdx & 0xff]), bBytes]);
  const R = prfCbcMac(alg, keyBuf, Buffer.concat([P, Q]));
  let S = Buffer.from(R);
  let j = 1;
  while (S.length < d) {
    const jBuf = Buffer.alloc(16, 0);
    jBuf.writeUInt32BE(j, 12);
    const xored = Buffer.alloc(16, 0);
    for (let k = 0; k < 16; k++) xored[k] = R[k] ^ jBuf[k];
    S = Buffer.concat([S, aesEcbBlock(alg, keyBuf, xored)]);
    j++;
  }
  return BigInt("0x" + S.subarray(0, d).toString("hex"));
}

function ff1Encrypt(plainStr, masterKey, tweakInput, radix) {
  const p = prepareNistParams(plainStr, masterKey, tweakInput, radix);
  let A = p.s.slice(0, p.u);
  let B = p.s.slice(p.u);
  const modU = BigInt(p.r) ** BigInt(p.u);
  const modV = BigInt(p.r) ** BigInt(p.v);

  for (let i = 0; i < 10; i++) {
    const numB = strToBigInt(B, p.r, p.alph);
    const y = computeRoundY(p.alg, p.keyBuf, p.P, p.tweakBuf, p.padLen, p.b, p.d, i, numB);
    const m = (i % 2 === 0) ? p.u : p.v;
    const modM = (i % 2 === 0) ? modU : modV;
    const numA = strToBigInt(A, p.r, p.alph);
    const c = (numA + y) % modM;
    const C = bigIntToStr(c, p.r, m, p.alph);
    A = B;
    B = C;
  }
  return A + B;
}

function ff1Decrypt(cipherStr, masterKey, tweakInput, radix) {
  const p = prepareNistParams(cipherStr, masterKey, tweakInput, radix);
  let A = p.s.slice(0, p.u);
  let B = p.s.slice(p.u);
  const modU = BigInt(p.r) ** BigInt(p.u);
  const modV = BigInt(p.r) ** BigInt(p.v);

  for (let i = 9; i >= 0; i--) {
    const C = B;
    B = A;
    const numB = strToBigInt(B, p.r, p.alph);
    const y = computeRoundY(p.alg, p.keyBuf, p.P, p.tweakBuf, p.padLen, p.b, p.d, i, numB);
    const m = (i % 2 === 0) ? p.u : p.v;
    const modM = (i % 2 === 0) ? modU : modV;
    const numC = strToBigInt(C, p.r, p.alph);
    let aVal = (numC - (y % modM)) % modM;
    if (aVal < 0n) aVal += modM;
    A = bigIntToStr(aVal, p.r, m, p.alph);
  }
  return A + B;
}

function encryptPanStatelessFF1(panStr, masterKey, tweakStr) {
  const clean = String(panStr || "").replace(/\D/g, "");
  if (!validateLuhnMod10(clean)) throw new Error("ERR_INVALID_LUHN_PAN");
  const encPayload = ff1Encrypt(clean.slice(0, -1), masterKey, tweakStr || "PAN_V1", 10);
  return encPayload + computeLuhnCheckDigit(encPayload);
}

function decryptPanStatelessFF1(fpePanStr, masterKey, tweakStr) {
  const clean = String(fpePanStr || "").replace(/\D/g, "");
  if (!validateLuhnMod10(clean)) throw new Error("ERR_INVALID_FPE_PAN_CHECKSUM");
  const decPayload = ff1Decrypt(clean.slice(0, -1), masterKey, tweakStr || "PAN_V1", 10);
  return decPayload + computeLuhnCheckDigit(decPayload);
}

function computeIbanCheckDigits(cc, bban) {
  const r = (bban + cc + "00").toUpperCase();
  let numStr = "";
  for (let i = 0; i < r.length; i++) {
    const c = r.charCodeAt(i);
    numStr += (c >= 65 && c <= 90) ? String(c - 55) : r[i];
  }
  return String(98n - (BigInt(numStr) % 97n)).padStart(2, "0");
}

function encryptIbanStatelessFF1(ibanStr, masterKey, tweakStr) {
  const clean = String(ibanStr || "").replace(/\s+/g, "").toUpperCase();
  if (!validateIbanIso7064(clean)) throw new Error("ERR_INVALID_ISO7064_IBAN");
  const cc = clean.slice(0, 2), bban = clean.slice(4);
  const radix = /^\d+$/.test(bban) ? 10 : 36;
  const encBban = ff1Encrypt(bban, masterKey, (tweakStr || "IBAN_V1") + ":" + cc, radix);
  return cc + computeIbanCheckDigits(cc, encBban) + encBban;
}

function decryptIbanStatelessFF1(fpeIbanStr, masterKey, tweakStr) {
  const clean = String(fpeIbanStr || "").replace(/\s+/g, "").toUpperCase();
  if (!validateIbanIso7064(clean)) throw new Error("ERR_INVALID_FPE_IBAN_CHECKSUM");
  const cc = clean.slice(0, 2), encBban = clean.slice(4);
  const radix = /^\d+$/.test(encBban) ? 10 : 36;
  const origBban = ff1Decrypt(encBban, masterKey, (tweakStr || "IBAN_V1") + ":" + cc, radix);
  return cc + computeIbanCheckDigits(cc, origBban) + origBban;
}

function encryptCapsuleAes256Gcm(plainText, masterKey, aadContext) {
  const { keyBuf } = resolveAesKeyAndMode(String(masterKey || "gcm-key"));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, iv);
  if (aadContext) cipher.setAAD(Buffer.from(String(aadContext), "utf8"));
  const enc = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  return iv.toString("hex") + ":" + cipher.getAuthTag().toString("hex") + ":" + enc.toString("hex");
}

function decryptCapsuleAes256Gcm(capsuleStr, masterKey, aadContext) {
  const parts = String(capsuleStr || "").split(":");
  if (parts.length !== 3) throw new Error("ERR_INVALID_CAPSULE_FORMAT");
  const { keyBuf } = resolveAesKeyAndMode(String(masterKey || "gcm-key"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, Buffer.from(parts[0], "hex"));
  if (aadContext) decipher.setAAD(Buffer.from(String(aadContext), "utf8"));
  decipher.setAuthTag(Buffer.from(parts[1], "hex"));
  return Buffer.concat([decipher.update(Buffer.from(parts[2], "hex")), decipher.final()]).toString("utf8");
}

class Sip1AuditLedger {
  constructor() { this.chain = []; this.headHash = "0".repeat(64); }
  append(action, cls, tokenTag) {
    const idx = this.chain.length + 1, ts = new Date().toISOString();
    const payload = `${idx}|${ts}|${action}|${cls}|${tokenTag}|${this.headHash}`;
    const currHash = crypto.createHash("sha256").update(payload).digest("hex");
    const entry = { index: idx, timestamp: ts, action, cls, tokenTag, prevHash: this.headHash, hash: currHash };
    this.chain.push(entry); this.headHash = currHash;
    return entry;
  }
  verifyIntegrity() {
    let prev = "0".repeat(64);
    for (const item of this.chain) {
      if (item.prevHash !== prev) return false;
      const expected = crypto.createHash("sha256").update(`${item.index}|${item.timestamp}|${item.action}|${item.cls}|${item.tokenTag}|${prev}`).digest("hex");
      if (expected !== item.hash) return false;
      prev = item.hash;
    }
    return true;
  }
}

module.exports = {
  ff1Encrypt, ff1Decrypt,
  encryptPanStatelessFF1, decryptPanStatelessFF1,
  encryptIbanStatelessFF1, decryptIbanStatelessFF1,
  encryptCapsuleAes256Gcm, decryptCapsuleAes256Gcm,
  Sip1AuditLedger
};
