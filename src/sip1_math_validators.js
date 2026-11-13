// MODULE 3: DETERMINISTIC MATHEMATICAL CHECKSUM ENGINE
"use strict";

function luhnCheck(input) {
  const d = String(input || "").replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  if (/^(\d)\1+$/.test(d)) return false;
  let sum = 0, dbl = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (dbl) { n *= 2; if (n > 9) n -= 9; }
    sum += n; dbl = !dbl;
  }
  return sum > 0 && (sum % 10 === 0);
}

function luhnCompute(payload) {
  const d = String(payload || "").replace(/\D/g, "");
  let sum = 0, dbl = true;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (dbl) { n *= 2; if (n > 9) n -= 9; }
    sum += n; dbl = !dbl;
  }
  return String((10 - (sum % 10)) % 10);
}

const IBAN_LEN = { DE:22, GB:22, GE:22, FR:27, ES:24, IT:27, NL:18, CH:21, PL:28, TR:26, UA:29, BE:16, AT:20 };

function ibanCheck(input) {
  const s = String(input || "").replace(/\s+/g, "").toUpperCase();
  if (s.length < 15 || s.length > 34 || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  const cc = s.slice(0, 2);
  if (IBAN_LEN[cc] && s.length !== IBAN_LEN[cc]) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let numStr = "";
  for (let i = 0; i < rearranged.length; i++) {
    const c = rearranged.charCodeAt(i);
    numStr += (c >= 65 && c <= 90) ? String(c - 55) : rearranged[i];
  }
  try { return (BigInt(numStr) % 97n) === 1n; } catch (e) { return false; }
}

function ibanComputeDigits(cc, bban) {
  const rearranged = (String(bban) + String(cc) + "00").toUpperCase();
  let numStr = "";
  for (let i = 0; i < rearranged.length; i++) {
    const c = rearranged.charCodeAt(i);
    numStr += (c >= 65 && c <= 90) ? String(c - 55) : rearranged[i];
  }
  const rem = BigInt(numStr) % 97n;
  return String(98n - rem).padStart(2, "0");
}

const V_D = [
  [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],
  [2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
  [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
  [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
  [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]
];
const V_P = [
  [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],
  [5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
  [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
  [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
];
const V_INV = [0,4,3,2,1,5,6,7,8,9];

function verhoeffCheck(input) {
  const s = String(input || "").replace(/\s+/g, "");
  if (!/^\d{2,32}$/.test(s)) return false;
  let c = 0;
  for (let i = 0; i < s.length; i++) {
    const digit = s.charCodeAt(s.length - 1 - i) - 48;
    c = V_D[c][V_P[i % 8][digit]];
  }
  return c === 0;
}

function verhoeffCompute(payload) {
  const s = String(payload || "").replace(/\D/g, "");
  let c = 0;
  for (let i = 0; i < s.length; i++) {
    const digit = s.charCodeAt(s.length - 1 - i) - 48;
    c = V_D[c][V_P[(i + 1) % 8][digit]];
  }
  return String(V_INV[c]);
}

function ssnCheck(input) {
  const m = String(input || "").trim().match(/^(\d{3})-(\d{2})-(\d{4})$/);
  if (!m) return false;
  const a = parseInt(m[1], 10), g = parseInt(m[2], 10), s = parseInt(m[3], 10);
  return !(a === 0 || a === 666 || a >= 900 || g === 0 || s === 0);
}

module.exports = {
  validateLuhnMod10: luhnCheck,
  validateLuhnCard: luhnCheck,
  isValidLuhn: luhnCheck,
  computeLuhnCheckDigit: luhnCompute,
  validateIbanIso7064: ibanCheck,
  validateIBAN: ibanCheck,
  isValidIBAN: ibanCheck,
  computeIbanCheckDigits: ibanComputeDigits,
  computeIbanMod97CheckDigits: ibanComputeDigits,
  validateVerhoeffD5: verhoeffCheck,
  validateVerhoeff: verhoeffCheck,
  computeVerhoeffDigit: verhoeffCompute,
  generateVerhoeffCheckDigit: verhoeffCompute,
  validateUsSsn: ssnCheck,
  validateUSSSN: ssnCheck
};
