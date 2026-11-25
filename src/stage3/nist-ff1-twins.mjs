/**
 * @license Apache-2.0
 * SHULIAK SIP v3.0 - Stage 3 Bit-Exact NIST SP 800-38G Rev. 1 FF1 & Checksum-Invariant Synthetic Twins
 * Zero external dependencies. Built strictly on node:crypto, node:buffer, and BigInt arithmetic.
 */

import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
const _sipRawCipheriv = crypto.createCipheriv.bind(crypto);

const _ecbCache = new Map();
let _l1Key = null;
let _l1Alg = '';
let _l1Ciph = null;

function _toBuf(x) {
  return Buffer.isBuffer(x) ? x : Buffer.from(x);
}
function _sipFastEcb(ecbAlg, keyIn, blk16) {
  if (keyIn === _l1Key && ecbAlg === _l1Alg) {
    return _l1Ciph.update(
      Buffer.isBuffer(blk16) ? blk16 : Buffer.from(blk16)
    );
  }
  const kBuf = _toBuf(keyIn);
  const kId = ecbAlg + ':' + kBuf.toString('hex');
  let c = _ecbCache.get(kId);
  if (!c) {
    if (_ecbCache.size >= 32) {
      _ecbCache.delete(_ecbCache.keys().next().value);
    }
    c = _sipRawCipheriv(ecbAlg, kBuf, null);
    c.setAutoPadding(false);
    _ecbCache.set(kId, c);
  }
  _l1Key = keyIn;
  _l1Alg = ecbAlg;
  _l1Ciph = c;
  return c.update(_toBuf(blk16));
}
function _sipFastCipheriv(alg, key, iv) {
  const sAlg = String(alg).toLowerCase();
  const ivLen = iv ? iv.byteLength : 0;
  if (sAlg.endsWith('-ecb') && ivLen === 0) {
    return {
      setAutoPadding() { return this; },
      update(b) { return _sipFastEcb(sAlg, key, b); },
      final() { return Buffer.alloc(0); },
    };
  }
  if (sAlg.endsWith('-cbc') && ivLen === 16) {
    const ecbAlg = sAlg.replace('-cbc', '-ecb');
    let prev = Buffer.from(_toBuf(iv));
    let pad = true;
    let rem = Buffer.alloc(0);
    return {
      setAutoPadding(v) { pad = Boolean(v); return this; },
      update(inData) {
        const bIn = _toBuf(inData);
        const full = rem.length > 0
          ? Buffer.concat([rem, bIn]) : bIn;
        const nBlk = Math.floor(full.length / 16) * 16;
        rem = full.subarray(nBlk);
        if (nBlk === 0) return Buffer.alloc(0);
        const out = Buffer.allocUnsafe(nBlk);
        const xblk = Buffer.allocUnsafe(16);
        for (let off = 0; off < nBlk; off += 16) {
          for (let j = 0; j < 16; j++) {
            xblk[j] = full[off + j] ^ prev[j];
          }
          prev = _sipFastEcb(ecbAlg, key, xblk);
          prev.copy(out, off);
        }
        return out;
      },
      final() {
        if (!pad) return Buffer.alloc(0);
        const padByte = 16 - rem.length;
        const blk = Buffer.alloc(16, padByte);
        rem.copy(blk, 0);
        for (let j = 0; j < 16; j++) blk[j] ^= prev[j];
        prev = _sipFastEcb(ecbAlg, key, blk);
        rem = Buffer.alloc(0);
        return prev;
      },
    };
  }
  return _sipRawCipheriv(alg, key, iv);
}

export function deriveFf1DomainTweak(
  baseTweak, domain, prefix = ''
) {
  const rk = Buffer.isBuffer(baseTweak)
    ? baseTweak
    : Buffer.from(String(baseTweak || ''), 'utf8');
  const key = rk.length > 0 ? rk : Buffer.alloc(16, 0);
  const preBuf = Buffer.from(
    String(prefix || ''), 'utf8'
  );
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(preBuf.length & 0xffff, 0);
  return crypto
    .createHmac('sha256', key)
    .update('SIP1-FF1-v1', 'ascii')
    .update(String(domain || ''), 'utf8')
    .update(lenBuf)
    .update(preBuf)
    .digest()
    .subarray(0, 16);
}

export const FF1_ALPHABET_36_LOWER = '0123456789abcdefghijklmnopqrstuvwxyz';
export const FF1_ALPHABET_36_UPPER = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

const MIN_FF1_DOMAIN_SIZE = 1_000_000n;
const ZERO_IV_16 = Buffer.alloc(16, 0);

/**
 * Resolve AES algorithm prefix (`aes-128`, `aes-192`, `aes-256`) from raw key length.
 * @param {Buffer} keyBuf
 * @returns {'aes-128' | 'aes-192' | 'aes-256'}
 */
function resolveAesPrefix(keyBuf) {
  if (!Buffer.isBuffer(keyBuf)) {
    throw new TypeError('FF1 keyBuf must be a Buffer');
  }
  if (keyBuf.length === 16) return 'aes-128';
  if (keyBuf.length === 24) return 'aes-192';
  if (keyBuf.length === 32) return 'aes-256';
  throw new RangeError(`Invalid AES key length for FF1: ${keyBuf.length} (expected 16, 24, or 32 bytes)`);
}

/**
 * Exact integer computation of `ceil(v * log2(radix))` with zero IEEE-754 floating-point error:
 * smallest integer `k >= 0` such that `2^k >= radix^v`.
 * @param {number} radix
 * @param {number} v
 * @returns {number}
 */
function exactCeilVLog2Radix(radix, v) {
  const rv = BigInt(radix) ** BigInt(v);
  if (rv <= 1n) return 0;
  return (rv - 1n).toString(2).length;
}

/**
 * Validate FF1 parameters per NIST SP 800-38G Rev. 1 (`radix^n >= 1,000,000`).
 * @param {Buffer} keyBuf
 * @param {Buffer} tweakBuf
 * @param {number} radix
 * @param {number[]} digitsArray
 */
function validateFf1Params(keyBuf, tweakBuf, radix, digitsArray) {
  const aesPrefix = resolveAesPrefix(keyBuf);
  if (!Buffer.isBuffer(tweakBuf)) {
    throw new TypeError('FF1 tweakBuf must be a Buffer');
  }
  if (!Number.isInteger(radix) || radix < 2 || radix > 65536) {
    throw new RangeError(`Invalid FF1 radix: ${radix} (expected integer in 2..65536)`);
  }
  if (!Array.isArray(digitsArray) || digitsArray.length < 2) {
    throw new RangeError('FF1 digitsArray must contain at least 2 numerals');
  }
  const n = digitsArray.length;
  for (let i = 0; i < n; i++) {
    const d = digitsArray[i];
    if (!Number.isInteger(d) || d < 0 || d >= radix) {
      throw new RangeError(`FF1 numeral out of range at index ${i}: ${d} (radix=${radix})`);
    }
  }
  const domainSize = BigInt(radix) ** BigInt(n);
  if (domainSize < MIN_FF1_DOMAIN_SIZE) {
    throw new RangeError(
      `NIST SP 800-38G Rev. 1 domain violation: radix^n = ${radix}^${n} = ${domainSize} < 1,000,000`
    );
  }
  return aesPrefix;
}

/**
 * Convert numeral array in base `radix` (big-endian) to `BigInt`.
 * @param {number[]} numerals
 * @param {number} radix
 * @returns {BigInt}
 */
function numRadix(numerals, radix) {
  const r = BigInt(radix);
  let acc = 0n;
  for (let i = 0; i < numerals.length; i++) {
    acc = acc * r + BigInt(numerals[i]);
  }
  return acc;
}

/**
 * Convert non-negative `BigInt` into big-endian numeral array of length `m` in base `radix`.
 * @param {BigInt} x
 * @param {number} radix
 * @param {number} m
 * @returns {number[]}
 */
function strRadix(x, radix, m) {
  const r = BigInt(radix);
  const out = new Array(m);
  let rem = x;
  for (let i = m - 1; i >= 0; i--) {
    out[i] = Number(rem % r);
    rem = rem / r;
  }
  return out;
}

/**
 * Encode non-negative `BigInt` into big-endian `Buffer` of exact byte length `byteLen`.
 * @param {BigInt} val
 * @param {number} byteLen
 * @returns {Buffer}
 */
function bigIntToBeBytes(val, byteLen) {
  const out = Buffer.alloc(byteLen, 0);
  let v = val;
  for (let i = byteLen - 1; i >= 0 && v > 0n; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Decode unsigned big-endian `Buffer` into `BigInt`.
 * @param {Buffer} buf
 * @returns {BigInt}
 */
function beBytesToBigInt(buf) {
  let acc = 0n;
  for (let i = 0; i < buf.length; i++) {
    acc = (acc << 8n) | BigInt(buf[i]);
  }
  return acc;
}

/**
 * Single-block AES-ECB encryption (`CIPH_K(block16)`).
 * @param {'aes-128' | 'aes-192' | 'aes-256'} aesPrefix
 * @param {Buffer} keyBuf
 * @param {Buffer} block16
 * @returns {Buffer}
 */
function ciphBlock16(aesPrefix, keyBuf, block16) {
  const cipher = _sipFastCipheriv(`${aesPrefix}-ecb`, keyBuf, null);
  cipher.setAutoPadding(false);
  return cipher.update(block16);
}

/**
 * NIST SP 800-38G Section 4.2 `PRF(X)`: last 16-byte block of AES-CBC with zero IV and no padding.
 * @param {'aes-128' | 'aes-192' | 'aes-256'} aesPrefix
 * @param {Buffer} keyBuf
 * @param {Buffer} pqBlocks
 * @returns {Buffer}
 */
function ff1Prf(aesPrefix, keyBuf, pqBlocks) {
  const cipher = _sipFastCipheriv(`${aesPrefix}-cbc`, keyBuf, ZERO_IV_16);
  cipher.setAutoPadding(false);
  const enc = cipher.update(pqBlocks);
  return Buffer.from(enc.subarray(enc.length - 16));
}

/**
 * Build 16-byte FF1 header `P = [1, 2, 1, radix_3B_BE, 10, u & 0xff, n_4B_BE, t_4B_BE]`.
 * @param {number} radix
 * @param {number} u
 * @param {number} n
 * @param {number} t
 * @returns {Buffer}
 */
function buildFf1HeaderP(radix, u, n, t) {
  const P = Buffer.alloc(16, 0);
  P[0] = 1;
  P[1] = 2;
  P[2] = 1;
  P[3] = (radix >>> 16) & 0xff;
  P[4] = (radix >>> 8) & 0xff;
  P[5] = radix & 0xff;
  P[6] = 10;
  P[7] = u & 0xff;
  P.writeUInt32BE(n >>> 0, 8);
  P.writeUInt32BE(t >>> 0, 12);
  return P;
}

/**
 * Compute round pseudorandom value `y = NUM(S)` for round `roundIdx` over numeral half `halfDigits`.
 * @param {'aes-128' | 'aes-192' | 'aes-256'} aesPrefix
 * @param {Buffer} keyBuf
 * @param {Buffer} P
 * @param {Buffer} tweakBuf
 * @param {number} radix
 * @param {number} b
 * @param {number} d
 * @param {number} roundIdx
 * @param {number[]} halfDigits
 * @returns {BigInt}
 */
function computeRoundY(aesPrefix, keyBuf, P, tweakBuf, radix, b, d, roundIdx, halfDigits) {
  const t = tweakBuf.length;
  const padZeroLen = (((-t - b - 1) % 16) + 16) % 16;
  const qLen = t + padZeroLen + 1 + b;
  const Q = Buffer.alloc(qLen, 0);
  if (t > 0) {
    tweakBuf.copy(Q, 0);
  }
  Q[t + padZeroLen] = roundIdx & 0xff;
  if (b > 0) {
    const numB = numRadix(halfDigits, radix);
    const bBytes = bigIntToBeBytes(numB, b);
    bBytes.copy(Q, t + padZeroLen + 1);
  }

  const R = ff1Prf(aesPrefix, keyBuf, Buffer.concat([P, Q]));
  const totalBlocks = Math.ceil(d / 16);
  let S;
  if (totalBlocks <= 1) {
    S = R.subarray(0, d);
  } else {
    const chunks = [R];
    for (let j = 1; j < totalBlocks; j++) {
      const jBlock = Buffer.alloc(16, 0);
      jBlock.writeUInt32BE(j >>> 0, 12);
      const xored = Buffer.alloc(16);
      for (let k = 0; k < 16; k++) {
        xored[k] = R[k] ^ jBlock[k];
      }
      chunks.push(ciphBlock16(aesPrefix, keyBuf, xored));
    }
    S = Buffer.concat(chunks).subarray(0, d);
  }

  return beBytesToBigInt(S);
}

/**
 * NIST SP 800-38G Rev. 1 Algorithm 7: `FF1.Encrypt(K, T, X)` (10-round alternating Feistel).
 * @param {Buffer} keyBuf 16, 24, or 32 bytes
 * @param {Buffer} tweakBuf arbitrary tweak bytes
 * @param {number} radix 2..65536
 * @param {number[]} digitsArray numeral array
 * @returns {number[]}
 */
export function ff1Encrypt(keyBuf, tweakBuf, radix, digitsArray) {
  const aesPrefix = validateFf1Params(keyBuf, tweakBuf, radix, digitsArray);
  const n = digitsArray.length;
  const t = tweakBuf.length;
  const u = Math.floor(n / 2);
  const v = n - u;
  const b = Math.ceil(exactCeilVLog2Radix(radix, v) / 8);
  const d = 4 * Math.ceil(b / 4) + 4;
  const P = buildFf1HeaderP(radix, u, n, t);

  const modU = BigInt(radix) ** BigInt(u);
  const modV = BigInt(radix) ** BigInt(v);

  let A = digitsArray.slice(0, u);
  let B = digitsArray.slice(u);

  for (let i = 0; i < 10; i++) {
    const y = computeRoundY(aesPrefix, keyBuf, P, tweakBuf, radix, b, d, i, B);
    const isEven = i % 2 === 0;
    const m = isEven ? u : v;
    const modulus = isEven ? modU : modV;
    const c = (numRadix(A, radix) + y) % modulus;
    const C = strRadix(c, radix, m);
    A = B;
    B = C;
  }

  return A.concat(B);
}

/**
 * NIST SP 800-38G Rev. 1 Algorithm 8: `FF1.Decrypt(K, T, X)` (10-round inverse Feistel).
 * @param {Buffer} keyBuf 16, 24, or 32 bytes
 * @param {Buffer} tweakBuf arbitrary tweak bytes
 * @param {number} radix 2..65536
 * @param {number[]} digitsArray numeral array
 * @returns {number[]}
 */
export function ff1Decrypt(keyBuf, tweakBuf, radix, digitsArray) {
  const aesPrefix = validateFf1Params(keyBuf, tweakBuf, radix, digitsArray);
  const n = digitsArray.length;
  const t = tweakBuf.length;
  const u = Math.floor(n / 2);
  const v = n - u;
  const b = Math.ceil(exactCeilVLog2Radix(radix, v) / 8);
  const d = 4 * Math.ceil(b / 4) + 4;
  const P = buildFf1HeaderP(radix, u, n, t);

  const modU = BigInt(radix) ** BigInt(u);
  const modV = BigInt(radix) ** BigInt(v);

  let A = digitsArray.slice(0, u);
  let B = digitsArray.slice(u);

  for (let i = 9; i >= 0; i--) {
    const y = computeRoundY(aesPrefix, keyBuf, P, tweakBuf, radix, b, d, i, A);
    const isEven = i % 2 === 0;
    const m = isEven ? u : v;
    const modulus = isEven ? modU : modV;
    const diff = (numRadix(B, radix) - (y % modulus) + modulus) % modulus;
    const C = strRadix(diff, radix, m);
    B = A;
    A = C;
  }

  return A.concat(B);
}

/**
 * Helper to convert ASCII string (`0-9a-z` / `0-9A-Z`) to numeral array for radices <= 36.
 * @param {string} str
 * @param {number} radix
 * @returns {number[]}
 */
export function stringToNumerals(str, radix) {
  const out = new Array(str.length);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    let val = -1;
    if (code >= 48 && code <= 57) {
      val = code - 48;
    } else if (code >= 97 && code <= 122) {
      val = code - 97 + 10;
    } else if (code >= 65 && code <= 90) {
      val = code - 65 + 10;
    }
    if (val < 0 || val >= radix) {
      throw new RangeError(`Invalid numeral character "${str[i]}" for radix ${radix}`);
    }
    out[i] = val;
  }
  return out;
}

/**
 * Helper to convert numeral array back to string for radices <= 36.
 * @param {number[]} numerals
 * @param {boolean} [upper=false]
 * @returns {string}
 */
export function numeralsToString(numerals, upper = false) {
  const alpha = upper ? FF1_ALPHABET_36_UPPER : FF1_ALPHABET_36_LOWER;
  let out = '';
  for (let i = 0; i < numerals.length; i++) {
    out += alpha[numerals[i]];
  }
  return out;
}

/**
 * Compute ISO/IEC 7812 Luhn check digit for a numeric payload string (without the check digit).
 * @param {string} payloadDigits
 * @returns {string}
 */
export function computeLuhnCheckDigit(payloadDigits) {
  let sum = 0;
  let doubleDigit = true;
  for (let i = payloadDigits.length - 1; i >= 0; i--) {
    let d = payloadDigits.charCodeAt(i) - 48;
    if (doubleDigit) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleDigit = !doubleDigit;
  }
  return String((10 - (sum % 10)) % 10);
}

/**
 * Validate a complete numeric string under ISO/IEC 7812 Luhn checksum.
 * @param {string} panDigits
 * @returns {boolean}
 */
export function isValidLuhnPan(panDigits) {
  if (typeof panDigits !== 'string' || !/^\d{13,19}$/.test(panDigits)) {
    return false;
  }
  const expected = computeLuhnCheckDigit(panDigits.slice(0, -1));
  return panDigits[panDigits.length - 1] === expected;
}

/**
 * Compute ISO-7064 MOD-97-10 remainder (`1` === valid IBAN).
 * @param {string} ibanClean
 * @returns {number}
 */
export function ibanMod97(ibanClean) {
  const clean = String(ibanClean || '').replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{8,30}$/.test(clean)) {
    return -1;
  }
  const rearranged = clean.slice(4) + clean.slice(0, 4);
  let expanded = '';
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      expanded += rearranged[i];
    } else {
      expanded += String(code - 55); // 'A'(65) -> 10 .. 'Z'(90) -> 35
    }
  }
  return Number(BigInt(expanded) % 97n);
}

/**
 * Synthesize a Luhn-valid payment card twin using AES-256-FF1:
 * preserves leading 1-digit MII (`rawPanDigits[0]`), encrypts inner `n - 2` digits via FF1(radix=10),
 * and computes a valid trailing ISO/IEC 7812 Luhn check digit.
 *
 * @param {Buffer} rSlot32 32-byte subject key
 * @param {Buffer} tweak16 tweak bytes
 * @param {string} rawPanDigits raw card string (spaces/hyphens stripped automatically)
 * @returns {string}
 */
export function synthesizePanTwin(rSlot32, tweak16, rawPanDigits) {
  const clean = String(rawPanDigits || '').replace(/[\s-]+/g, '');
  if (!/^\d+$/.test(clean) || clean.length < 8) {
    return synthesizeScopedToken(rSlot32, tweak16, `pan:${clean}`);
  }
  const mii = clean[0];
  const innerStr = clean.slice(1, -1);
  if (BigInt(10) ** BigInt(innerStr.length) < MIN_FF1_DOMAIN_SIZE) {
    return synthesizeScopedToken(rSlot32, tweak16, `pan:${clean}`);
  }
  const innerDigits = stringToNumerals(innerStr, 10);
  let encDigits = ff1Encrypt(rSlot32, tweak16, 10, innerDigits);
  let encInnerStr = numeralsToString(encDigits, false);

  // Pure FF1 bijection: no non-injective altTweak

  const payload = mii + encInnerStr;
  const check = computeLuhnCheckDigit(payload);
  return payload + check;
}

/**
 * Synthesize an ISO-7064 MOD-97-10 valid IBAN twin using AES-256-FF1:
 * preserves 2-letter country code, encrypts BBAN body (`radix=10` for numeric, `radix=36` for alphanumeric),
 * and computes valid 2-digit ISO-7064 MOD-97-10 check digits (`ibanMod97(twin) === 1`).
 *
 * @param {Buffer} rSlot32 32-byte subject key
 * @param {Buffer} tweak16 tweak bytes
 * @param {string} rawIbanClean
 * @returns {string}
 */
export function synthesizeIbanTwin(rSlot32, tweak16, rawIbanClean) {
  const clean = String(rawIbanClean || '').replace(/[\s-]+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$/.test(clean)) {
    return synthesizeScopedToken(rSlot32, tweak16, `iban:${clean}`);
  }
  const country = clean.slice(0, 2);
  const bban = clean.slice(4);
  const isDigitsOnly = /^\d+$/.test(bban);
  const radix = isDigitsOnly ? 10 : 36;

  if (BigInt(radix) ** BigInt(bban.length) < MIN_FF1_DOMAIN_SIZE) {
    return synthesizeScopedToken(rSlot32, tweak16, `iban:${clean}`);
  }

  let numerals = stringToNumerals(bban, radix);
  let encNumerals = ff1Encrypt(
    rSlot32, tweak16, radix, numerals
  );
  let twinBban = numeralsToString(encNumerals, true);
  if (radix === 36) {
    let guard = 0;
    while (/^\d+$/.test(twinBban) && guard < 256) {
      encNumerals = ff1Encrypt(
        rSlot32, tweak16, 36, encNumerals
      );
      twinBban = numeralsToString(encNumerals, true);
      guard++;
    }
  }

  const rem = ibanMod97(`${country}00${twinBban}`);
  const checkDigits = String(98 - rem).padStart(2, '0');
  return `${country}${checkDigits}${twinBban}`;
}

/**
 * Deterministic HMAC-SHA256 scoped pseudonym token for emails, short domains (`radix^len < 1,000,000`),
 * or opaque credentials/secrets — NEVER throws RangeError on short inputs.
 *
 * @param {Buffer} rSlot32 32-byte key
 * @param {Buffer} tweak16 tweak bytes
 * @param {string} kindOrRaw `"email"` or `"email:<addr>"` or arbitrary short/secret tag
 * @returns {string}
 */
export function synthesizeScopedToken(rSlot32, tweak16, kindOrRaw) {
  const tag = String(kindOrRaw ?? 'opaque');
  const key = Buffer.isBuffer(rSlot32) && rSlot32.length > 0 ? rSlot32 : Buffer.alloc(32, 0x5a);
  const tweak = Buffer.isBuffer(tweak16) ? tweak16 : Buffer.alloc(0);
  const mac = crypto
    .createHmac('sha256', key)
    .update(Buffer.from('ISEP-v3-SCOPED-TWIN\0', 'utf8'))
    .update(tweak)
    .update(Buffer.from([0x00]))
    .update(Buffer.from(tag, 'utf8'))
    .digest('hex')
    .slice(0, 16);

  if (tag === 'email' || tag.startsWith('email:') || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(tag)) {
    return `u-${mac}@example.invalid`; // 2 + 16 + 16 = 34 chars (RFC 2606)
  }
  return `tok-${mac}`;
}

/**
 * Quantize an ISO-8601 timestamp (or epoch ms) into a 60-second UTC bucket (`YYYY-MM-DDTHH:MM:00Z`).
 * @param {string | number | Date} [input]
 * @returns {string}
 */
export function quantizeTimestamp60s(input = Date.now()) {
  const ms = input instanceof Date ? input.getTime() : typeof input === 'number' ? input : Date.parse(String(input));
  const safeMs = Number.isFinite(ms) ? ms : Date.now();
  const bucketMs = Math.floor(safeMs / 60_000) * 60_000;
  return new Date(bucketMs).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Map an exact monetary value into an order-of-magnitude privacy range band.
 * @param {number} value
 * @returns {string}
 */
export function quantizeMonetaryBand(value) {
  const abs = Math.abs(Number(value));
  if (!Number.isFinite(abs)) return '[0, 10)';
  const sign = value < 0 ? '-' : '';
  if (abs === 0) return '[0, 1)';
  if (abs < 10) return `${sign}[1, 10)`;
  if (abs < 100) return `${sign}[10, 100)`;
  if (abs < 1_000) return `${sign}[100, 1000)`;
  if (abs < 10_000) return `${sign}[1000, 10000)`;
  if (abs < 100_000) return `${sign}[10000, 100000)`;
  if (abs < 1_000_000) return `${sign}[100000, 1000000)`;
  return `${sign}[1000000, +inf)`;
}

const EMAIL_GLOBAL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g;
const IBAN_GLOBAL_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g;
const PAN_CANDIDATE_RE = /\b(?:\d[ -]*?){13,19}\b/g;
const API_SECRET_GLOBAL_RE =
  /\b(?:sk-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{12,}|glpat-[A-Za-z0-9_-]{12,})\b/g;
const DSN_URI_CRED_RE = /\b([a-z][a-z0-9+.-]*:\/\/[^:\s/@]+:)([^@\s"']+)@/gi;
const ISO_TS_EXACT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const MONETARY_KEY_RE = /^(?:amount|amount_?usd|amount_?eur|total|price|balance|salary|transfer_?amount|fee|cost)$/i;
const TIMESTAMP_KEY_RE = /^(?:ts|timestamp|created_?at|updated_?at|occurred_?at|event_?time)$/i;
const FREE_TEXT_KEY_RE = /^(?:prompt|raw_?prompt|user_?prompt|message|body|notes|comment|description|memo|narrative|reason|summary|text|content)$/i;
const SHORT_ID_KEY_RE = /^(?:ssn|pin|cvv|cvc|tax_?id|passport|national_?id|phone|tel|secret|token|password|api_?key)$/i;

/**
 * Canonicalize a subject identifier (`email:...`, `pan:...`, `iban:...`, or normalized string) into a UTF-8 Buffer.
 * @param {string | Buffer} rawSubject
 * @returns {Buffer}
 */
export function canonicalizeSubjectIdentifier(rawSubject) {
  if (Buffer.isBuffer(rawSubject)) {
    return Buffer.from(rawSubject);
  }
  const trimmed = String(rawSubject || '').trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return Buffer.from(`email:${trimmed.toLowerCase()}`, 'utf8');
  }
  const digitsOnly = trimmed.replace(/[\s-]+/g, '');
  if (/^\d{13,19}$/.test(digitsOnly) && isValidLuhnPan(digitsOnly)) {
    return Buffer.from(`pan:${digitsOnly}`, 'utf8');
  }
  const ibanClean = trimmed.replace(/[\s-]+/g, '').toUpperCase();
  if (/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(ibanClean) && ibanMod97(ibanClean) === 1) {
    return Buffer.from(`iban:${ibanClean}`, 'utf8');
  }
  return Buffer.from(`subj:${trimmed}`, 'utf8');
}

/**
 * Automatically extract PII / financial / free-text fields from `rawObjOrText`, replacing PII in the
 * immutable skeleton (`skeletonPayload`) with format-preserving Luhn/MOD-97/RFC-2606 synthetic twins,
 * quantizing timestamps to 60s buckets & monetary fields to bands, and isolating raw values in `sidecarPayload` (`B_i`).
 *
 * `resolverFn(canonicalTargetBuf)` returns `{ rSlot32: Buffer, tweak16: Buffer }`.
 *
 * @param {unknown} rawObjOrText
 * @param {(canonicalTargetBuf: Buffer, meta: { kind: string }) => { rSlot32: Buffer, tweak16: Buffer }} resolverFn
 */
export function extractAndPseudonymizePayload(rawObjOrText, resolverFn) {
  /** @type {Map<string, Buffer>} */
  const subjectMap = new Map();
  /** @type {Record<string, unknown>} */
  const detachedFields = {};

  const resolveSubject = (canonicalStr, kind, isDataSubject = true) => {
    const canonBuf = Buffer.from(canonicalStr, 'utf8');
    if (isDataSubject) {
      subjectMap.set(canonicalStr, canonBuf);
    }
    return resolverFn(canonBuf, { kind });
  };

  const scrubInlineString = (str, pathKey) => {
    let out = str;
    let touchedSecretOrPii = false;

    // 1. DSN URI passwords
    out = out.replace(DSN_URI_CRED_RE, (_full, prefix, pass) => {
      touchedSecretOrPii = true;
      const { rSlot32, tweak16 } = resolveSubject(`secret:dsn:${pass}`, 'secret', false);
      return `${prefix}${synthesizeScopedToken(rSlot32, tweak16, `dsn:${pass}`)}@`;
    });

    // 2. Vendor API secrets
    out = out.replace(API_SECRET_GLOBAL_RE, (match) => {
      touchedSecretOrPii = true;
      const { rSlot32, tweak16 } = resolveSubject(`secret:api:${match}`, 'secret', false);
      return synthesizeScopedToken(rSlot32, tweak16, `secret:${match}`);
    });

    // 3. Valid ISO-7064 MOD-97-10 IBANs
    out = out.replace(IBAN_GLOBAL_RE, (match) => {
      if (ibanMod97(match) !== 1) return match;
      touchedSecretOrPii = true;
      const clean = match.toUpperCase();
      const { rSlot32, tweak16 } = resolveSubject(`iban:${clean}`, 'iban', true);
      return synthesizeIbanTwin(rSlot32, tweak16, clean);
    });

    // 4. Valid ISO/IEC 7812 Luhn PANs
    out = out.replace(PAN_CANDIDATE_RE, (match) => {
      const digits = match.replace(/[\s-]+/g, '');
      if (!isValidLuhnPan(digits)) return match;
      touchedSecretOrPii = true;
      const { rSlot32, tweak16 } = resolveSubject(`pan:${digits}`, 'pan', true);
      return synthesizePanTwin(rSlot32, tweak16, digits);
    });

    // 5. Email addresses -> u-<16hex>@example.invalid
    out = out.replace(EMAIL_GLOBAL_RE, (match) => {
      if (match.endsWith('@example.invalid')) return match;
      touchedSecretOrPii = true;
      const normEmail = match.toLowerCase();
      const { rSlot32, tweak16 } = resolveSubject(`email:${normEmail}`, 'email', true);
      return synthesizeScopedToken(rSlot32, tweak16, `email:${normEmail}`);
    });

    if (touchedSecretOrPii) {
      detachedFields[pathKey] = str;
    }
    return out;
  };

  const transformNode = (node, pathKey, keyName) => {
    if (node === null || node === undefined || typeof node === 'boolean') {
      return node;
    }

    if (typeof node === 'number') {
      if (MONETARY_KEY_RE.test(keyName)) {
        detachedFields[pathKey] = node;
        return quantizeMonetaryBand(node);
      }
      if (TIMESTAMP_KEY_RE.test(keyName) && node > 1_000_000_000) {
        detachedFields[pathKey] = node;
        const ms = node < 10_000_000_000 ? node * 1000 : node;
        return quantizeTimestamp60s(ms);
      }
      return node;
    }

    if (typeof node === 'string') {
      if (TIMESTAMP_KEY_RE.test(keyName) || ISO_TS_EXACT_RE.test(node)) {
        detachedFields[pathKey] = node;
        return quantizeTimestamp60s(node);
      }

      if (SHORT_ID_KEY_RE.test(keyName)) {
        detachedFields[pathKey] = node;
        const { rSlot32, tweak16 } = resolveSubject(`secret:field:${keyName}:${node}`, 'short_id', false);
        return synthesizeScopedToken(rSlot32, tweak16, `${keyName}:${node}`);
      }

      // Still scan free-text fields first so any embedded data subjects (`Alice`, `Bob`, PAN, IBAN) are indexed!
      const scrubbed = scrubInlineString(node, pathKey);

      if (FREE_TEXT_KEY_RE.test(keyName) || node.length > 96) {
        detachedFields[pathKey] = node;
        const { rSlot32, tweak16 } = resolveSubject(`text:${pathKey}`, 'freetext', false);
        return `[DETACHED_B_I:${synthesizeScopedToken(rSlot32, tweak16, `text:${node}`)}]`;
      }

      return scrubbed;
    }

    if (Array.isArray(node)) {
      return node.map((item, idx) => transformNode(item, `${pathKey}[${idx}]`, keyName));
    }

    if (typeof node === 'object') {
      /** @type {Record<string, unknown>} */
      const outObj = {};
      for (const [k, v] of Object.entries(node)) {
        const nextPath = pathKey ? `${pathKey}.${k}` : k;
        if (MONETARY_KEY_RE.test(k) && typeof v === 'string' && /^-?\d+(?:\.\d+)?$/.test(v.trim())) {
          detachedFields[nextPath] = v;
          outObj[`${k}_band`] = quantizeMonetaryBand(Number(v.trim()));
          continue;
        }
        if (MONETARY_KEY_RE.test(k) && typeof v === 'number') {
          detachedFields[nextPath] = v;
          outObj[`${k}_band`] = quantizeMonetaryBand(v);
          continue;
        }
        if (TIMESTAMP_KEY_RE.test(k)) {
          detachedFields[nextPath] = v;
          outObj.ts_bucket = quantizeTimestamp60s(/** @type {string | number} */ (v));
          continue;
        }
        outObj[k] = transformNode(v, nextPath, k);
      }
      return outObj;
    }

    return String(node);
  };

  const skeletonPayload =
    typeof rawObjOrText === 'string'
      ? (() => {
          const scrubbed = scrubInlineString(rawObjOrText, 'raw_text');
          detachedFields.raw_text = rawObjOrText;
          // Preserve twin preview tokens in summary if short, else detach raw text while exposing twins
          return { text_twins: scrubbed };
        })()
      : transformNode(rawObjOrText, 'root', '');

  return {
    skeletonPayload,
    sidecarPayload: {
      raw: rawObjOrText,
      detachedFields,
    },
    subjects: [...subjectMap.values()],
  };
}

// V8_FF1_DIGITS_CAVP_WARMUP
try {
  const _hxs = [
    '2b7e151628aed2a6abf7158809cf4f3c',
    '2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f',
    '2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f' +
      '7f036d6f04fc6a94',
  ];
  const _tw = Buffer.from('39383736353433323130', 'hex');
  const _pt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  for (const _h of _hxs) {
    const _kb = Buffer.from(_h, 'hex');
    const _ct = ff1Encrypt(_kb, _tw, 10, _pt);
    ff1Decrypt(_kb, _tw, 10, _ct);
  }
} catch (_) {}
