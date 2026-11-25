import {
  normalizeUnicodeEvasion, isPlausiblePaymentIin,
} from '../stage5/redteam-protocol-armor.mjs';
import crypto from 'node:crypto';
import {
  deriveFf1DomainTweak,
  ff1Encrypt,
  ff1Decrypt,
  stringToNumerals,
  numeralsToString,
  computeLuhnCheckDigit,
  ibanMod97,
} from '../stage3/nist-ff1-twins.mjs';

export const SECTOR_PACK_IDS = Object.freeze([
  'iso42001_eu_ai',
  'pci_dora',
  'legal_tax',
  'hipaa_clinical',
]);

export const SECTOR_PACK_META = Object.freeze({
  iso42001_eu_ai: {
    id: 'iso42001_eu_ai',
    title: 'ISO/IEC 42001, EU AI Act & EU CRA Pack',
    controls: [
      'ISO/IEC 42001 A.6.2.6 / A.8.4',
      'EU AI Act Art. 12 / Art. 19 / Art. 50',
      'EU CRA Art. 14 CycloneDX 1.6 SBOM',
    ],
  },
  pci_dora: {
    id: 'pci_dora',
    title: 'PCI DSS v4.0.1, SEPA IBAN, LEI & FinTech Pack',
    controls: [
      'PCI DSS v4.0.1 Req. 3.4 / 3.5.1 / 10.2',
      'SEPA Checksums (FR/ES/IT/BE/NO) & ISO 17442 LEI',
      'US ABA 3-7-1 Routing & EVM/BTC Wallet Twins',
    ],
  },
  legal_tax: {
    id: 'legal_tax',
    title: 'IRS 26 U.S.C. 7216 Global Tax & Legal Pack',
    controls: [
      '26 U.S.C. 7216 & Rev. Proc. 2013-14',
      'US SSN/ITIN/EIN, UK NINO, ES NIF/NIE, CA SIN',
      'ISIN / CUSIP / EU VAT & ICAO Passport MRZ',
    ],
  },
  hipaa_clinical: {
    id: 'hipaa_clinical',
    title: 'HIPAA 18-Identifier Safe Harbor & ICH E6(R3)',
    controls: [
      '45 CFR 164.514(b)(2) All 18 Safe Harbor Rules',
      'US NPI / MBI / DEA / Census 17-ZIP / Age 90+',
      'ISO 3779 VIN / IMEI / Non-Zero Date Shift',
    ],
  },
});

const ALPHA36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const MBI_A = 'ACDEFGHJKMNPQRTUVWXY';
const MBI_AN = '0123456789' + MBI_A;
const MBI_SLOTS = [
  '123456789', MBI_A, MBI_AN, '0123456789',
  MBI_A, MBI_AN, '0123456789', MBI_A,
  MBI_A, '0123456789', '0123456789',
];
const MBI_RE = new RegExp(
  '\\b[1-9][' + MBI_A + '][' + MBI_AN + ']\\d-?' +
  '[' + MBI_A + '][' + MBI_AN + ']\\d-?' +
  '[' + MBI_A + ']{2}\\d{2}\\b',
  'gi'
);
const MBI_SPACE = 12_960_000_000_000n;
const SSN_SPACE = 888_931_098n;

const ITIN_GROUPS = [
  50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,
  70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,
  86,87,88,90,91,92,94,95,96,97,98,99,
];
const ITIN_SPACE = BigInt(100 * ITIN_GROUPS.length * 9999);

const EIN_PREFIXES = [
  1,2,3,4,5,6,10,11,12,13,14,15,16,20,21,22,23,24,
  25,26,27,30,31,32,33,34,35,36,37,38,39,40,41,42,
  43,44,45,46,47,48,50,51,52,53,54,55,56,57,58,59,
  60,61,62,63,64,65,66,67,68,71,72,73,74,75,76,77,
  80,81,82,83,84,85,86,87,88,90,91,92,93,94,95,98,99,
];
const EIN_SET = new Set(EIN_PREFIXES);
const EIN_SPACE = BigInt(EIN_PREFIXES.length * 10_000_000);

const ABA_PREFIXES = [
  1,2,3,4,5,6,7,8,9,10,11,12,
  21,22,23,24,25,26,27,28,29,30,31,32,
  61,62,63,64,65,66,67,68,69,70,71,72,80,
];
const ABA_SET = new Set(ABA_PREFIXES);
const ABA_SPACE = BigInt(ABA_PREFIXES.length * 1_000_000);

const HIPAA_ZERO_ZIPS = new Set([
  '036','059','063','102','203','556','692','790',
  '821','823','830','831','878','879','884','890','893',
]);

const ES_NIF_TBL = 'TRWAGMYFPDXBNJZSQVHLCKE';

const VIN_MAP = {
  A:1,B:2,C:3,D:4,E:5,F:6,G:7,H:8,J:1,K:2,L:3,M:4,N:5,
  P:7,R:9,S:2,T:3,U:4,V:5,W:6,X:7,Y:8,Z:9,
  '0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,
};
const VIN_W = [8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2];

function mkTweak(baseTweak, domain, prefix = '') {
  return deriveFf1DomainTweak(
    baseTweak, domain, prefix
  );
}

function ff1Alpha36CycleWalk(
  key32, twk, str, dec = false
) {
  let cur = str;
  for (let i = 0; i < 256; i++) {
    cur = ff1Str(key32, twk, 36, cur, dec);
    if (!/^\d+$/.test(cur)) return cur;
  }
  throw new Error('FF1 radix=36 cycle-walk bound');
}

function ff1Str(key32, tweakBuf, radix, s, dec = false) {
  const nums = stringToNumerals(s.toLowerCase(), radix);
  const out = dec
    ? ff1Decrypt(key32, tweakBuf, radix, nums)
    : ff1Encrypt(key32, tweakBuf, radix, nums);
  return numeralsToString(out, true);
}

function bigToRadixFixed(val, radix, len) {
  const r = BigInt(radix);
  let v = BigInt(val);
  const chars = new Array(len);
  for (let i = len - 1; i >= 0; i--) {
    chars[i] = ALPHA36[Number(v % r)];
    v /= r;
  }
  return chars.join('');
}

function radixToBig(s, radix) {
  const r = BigInt(radix);
  let v = 0n;
  for (let i = 0; i < s.length; i++) {
    const d = ALPHA36.indexOf(s[i].toUpperCase());
    v = v * r + BigInt(d);
  }
  return v;
}

function cycleWalkRank(
  rankBig, spaceBig, radix, width, key32, twk, dec = false
) {
  let cur = BigInt(rankBig);
  for (let step = 0; step < 256; step++) {
    const enc = ff1Str(
      key32, twk, radix,
      bigToRadixFixed(cur, radix, width), dec
    );
    cur = radixToBig(enc, radix);
    if (cur < spaceBig) return cur;
  }
  throw new Error('FF1 cycle-walk exceeded bound');
}

function applyMask(template, cleanChars) {
  let idx = 0;
  let out = '';
  for (let i = 0; i < template.length; i++) {
    const c = template[i];
    if (/[0-9A-Za-z]/.test(c) && idx < cleanChars.length) {
      out += cleanChars[idx++];
    } else {
      out += c;
    }
  }
  return out;
}

export function getIso7812PrefixLen(digits) {
  if (!/^\d{13,19}$/.test(digits)) return 0;
  if (digits[0] === '4') return 1;
  const p2 = Number(digits.slice(0, 2));
  const p3 = Number(digits.slice(0, 3));
  const p4 = Number(digits.slice(0, 4));
  if (p2 >= 51 && p2 <= 55) return 2;
  if (p4 >= 2200 && p4 <= 2204) return 4;
  if (p4 >= 2221 && p4 <= 2720) return 4;
  if (p2 === 34 || p2 === 37) return 2;
  if (p3 >= 300 && p3 <= 305) return 3;
  if (p4 === 3095) return 4;
  if (p2 === 36 || p2 === 38 || p2 === 39) return 2;
  if (p4 === 6011) return 4;
  if (p2 === 65) return 2;
  if (p3 >= 644 && p3 <= 649) return 3;
  if (p4 >= 3528 && p4 <= 3589) return 4;
  if (p2 === 62) return 2;
  return 0;
}

export function isValidStrictPan(raw) {
  const d = String(raw || '').replace(/[ -]/g, '');
  const plen = getIso7812PrefixLen(d);
  if (plen === 0 || d.length - plen - 1 < 6) return false;
  const chk = computeLuhnCheckDigit(d.slice(0, -1));
  return d[d.length - 1] === chk;
}

export function transformStrictPan(
  key32, tweak, formattedPan, decrypt = false
) {
  const d = formattedPan.replace(/[ -]/g, '');
  if (!isValidStrictPan(d)) return formattedPan;
  const plen = getIso7812PrefixLen(d);
  const prefix = d.slice(0, plen);
  const mid = d.slice(plen, -1);
  const twk = mkTweak(tweak, 'PAN', prefix);
  const nextMid = ff1Str(key32, twk, 10, mid, decrypt);
  const chk = computeLuhnCheckDigit(prefix + nextMid);
  return applyMask(formattedPan, prefix + nextMid + chk);
}

export function computeAbaCheck(d8) {
  const w = [3, 7, 1, 3, 7, 1, 3, 7];
  let s = 0;
  for (let i = 0; i < 8; i++) s += Number(d8[i]) * w[i];
  return String((10 - (s % 10)) % 10);
}

export function isValidAbaRouting(s) {
  if (!/^\d{9}$/.test(s)) return false;
  const p2 = Number(s.slice(0, 2));
  if (!ABA_SET.has(p2)) return false;
  return s[8] === computeAbaCheck(s.slice(0, 8));
}

export function transformAbaRouting(
  key32, tweak, s9, decrypt = false
) {
  if (!isValidAbaRouting(s9)) return s9;
  const pIdx = ABA_PREFIXES.indexOf(Number(s9.slice(0, 2)));
  const body = BigInt(s9.slice(2, 8));
  const rk = BigInt(pIdx) * 1_000_000n + body;
  const twk = mkTweak(tweak, 'ABA');
  const nr = cycleWalkRank(
    rk, ABA_SPACE, 10, 8, key32, twk, decrypt
  );
  const np = ABA_PREFIXES[Number(nr / 1_000_000n)];
  const nb = String(nr % 1_000_000n).padStart(6, '0');
  const d8 = String(np).padStart(2, '0') + nb;
  return d8 + computeAbaCheck(d8);
}

export function isValidIsoLei(s) {
  const u = String(s || '').toUpperCase();
  if (!/^[0-9A-Z]{4}00[0-9A-Z]{12}\d{2}$/.test(u)) {
    return false;
  }
  return mod97Pure(u) === 1;
}

function mod97Pure(alnum) {
  let rem = 0;
  const u = alnum.toUpperCase();
  for (let i = 0; i < u.length; i++) {
    const c = u[i];
    const s = /\d/.test(c)
      ? c : String(c.charCodeAt(0) - 55);
    for (let j = 0; j < s.length; j++) {
      rem = (rem * 10 + Number(s[j])) % 97;
    }
  }
  return rem;
}

export function transformIsoLei(
  key32, tweak, s20, decrypt = false
) {
  const u = String(s20 || '').toUpperCase();
  if (!/^[0-9A-Z]{4}00[0-9A-Z]{12}\d{2}$/.test(u)) return s20;
  if (mod97Pure(u) !== 1) return s20;
  const lou = u.slice(0, 6);
  const ent = ff1Str(
    key32, mkTweak(tweak, 'LEI', lou), 36,
    u.slice(6, 18), decrypt
  );
  const chk = String(98 - mod97Pure(lou + ent + '00'))
    .padStart(2, '0');
  return lou + ent + chk;
}

const FR_RIB_MAP = {
  A:'1',J:'1',B:'2',K:'2',S:'2',C:'3',L:'3',T:'3',
  D:'4',M:'4',U:'4',E:'5',N:'5',V:'5',F:'6',O:'6',W:'6',
  G:'7',P:'7',X:'7',H:'8',Q:'8',Y:'8',I:'9',R:'9',Z:'9',
};

function frRib(b5, g5, c11) {
  const toN = (x) => BigInt(
    x.toUpperCase().replace(/[A-Z]/g, (m) => FR_RIB_MAP[m])
  );
  const rem = (89n * toN(b5) + 15n * toN(g5) + 3n * toN(c11))
    % 97n;
  return String(97n - rem).padStart(2, '0');
}

const ES_W = [1, 2, 4, 8, 5, 10, 9, 7, 3, 6];
function esDc1(s10) {
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += Number(s10[i]) * ES_W[i];
  }
  const r = 11 - (sum % 11);
  return r === 11 ? '0' : (r === 10 ? '1' : String(r));
}

const IT_ODD = {
  '0':1,'1':0,'2':5,'3':7,'4':9,'5':13,'6':15,'7':17,'8':19,
  '9':21,A:1,B:0,C:5,D:7,E:9,F:13,G:15,H:17,I:19,J:21,K:2,
  L:4,M:18,N:20,O:11,P:3,Q:6,R:8,S:12,T:14,U:16,V:10,W:22,
  X:25,Y:24,Z:23,
};
function itCin(b22) {
  let t = 0;
  const u = b22.toUpperCase();
  for (let i = 0; i < 22; i++) {
    const c = u[i];
    if (i % 2 === 0) t += IT_ODD[c] ?? 0;
    else t += /\d/.test(c) ? Number(c) : c.charCodeAt(0) - 65;
  }
  return String.fromCharCode(65 + (t % 26));
}

const NO_W = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
function noMod11(d10) {
  let s = 0;
  for (let i = 0; i < 10; i++) s += Number(d10[i]) * NO_W[i];
  const r = s % 11;
  if (r === 0) return '0';
  if (r === 1) return null;
  return String(11 - r);
}

function ibanCheckDigits(cc, bban) {
  const rem = ibanMod97(cc + '00' + bban);
  return String(98 - rem).padStart(2, '0');
}

export function transformSepaIban(
  key32, tweak, rawIban, decrypt = false
) {
  const clean = rawIban.replace(/\s+/g, '').toUpperCase();
  if (clean.length < 15 || clean.length > 34) return rawIban;
  if (ibanMod97(clean) !== 1) return rawIban;
  const cc = clean.slice(0, 2);
  const bban = clean.slice(4);
  let newBban = null;

  if (cc === 'FR' && clean.length === 27 &&
      /^\d{10}[0-9A-Z]{11}\d{2}$/.test(bban)) {
    const b5 = bban.slice(0, 5);
    const g5 = bban.slice(5, 10);
    const ac = bban.slice(10, 21);
    if (bban.slice(21) === frRib(b5, g5, ac)) {
      const twk = mkTweak(tweak, 'IBAN:FR', b5 + g5);
      const na = /^\d+$/.test(ac)
        ? ff1Str(key32, twk, 10, ac, decrypt)
        : ff1Alpha36CycleWalk(key32, twk, ac, decrypt);
      newBban = b5 + g5 + na + frRib(b5, g5, na);
    }
  } else if (cc === 'ES' && clean.length === 24 &&
             /^\d{20}$/.test(bban)) {
    const b4 = bban.slice(0, 4);
    const g4 = bban.slice(4, 8);
    const dc = bban.slice(8, 10);
    const ac = bban.slice(10, 20);
    if (dc === esDc1('00' + b4 + g4) + esDc1(ac)) {
      const na = ff1Str(
        key32, mkTweak(tweak, 'IBAN:ES', b4 + g4),
        10, ac, decrypt
      );
      newBban = b4 + g4 + esDc1('00' + b4 + g4) +
        esDc1(na) + na;
    }
  } else if (cc === 'IT' && clean.length === 27 &&
             /^[A-Z]\d{10}[0-9A-Z]{12}$/.test(bban)) {
    const cin = bban[0];
    const rest = bban.slice(1);
    if (cin === itCin(rest)) {
      const b10 = rest.slice(0, 10);
      const ac = rest.slice(10);
      const twk = mkTweak(tweak, 'IBAN:IT', b10);
      const na = /^\d+$/.test(ac)
        ? ff1Str(key32, twk, 10, ac, decrypt)
        : ff1Alpha36CycleWalk(key32, twk, ac, decrypt);
      newBban = itCin(b10 + na) + b10 + na;
    }
  } else if (cc === 'BE' && clean.length === 16 &&
             /^\d{12}$/.test(bban)) {
    const d10 = bban.slice(0, 10);
    const r = Number(BigInt(d10) % 97n);
    const exp = r === 0 ? '97' : String(r).padStart(2, '0');
    if (bban.slice(10) === exp) {
      const nd = ff1Str(
        key32, mkTweak(tweak, 'IBAN:BE'), 10, d10, decrypt
      );
      const nr = Number(BigInt(nd) % 97n);
      const nk = nr === 0
        ? '97' : String(nr).padStart(2, '0');
      newBban = nd + nk;
    }
  } else if (cc === 'NO' && clean.length === 15 &&
             /^\d{11}$/.test(bban)) {
    const d10 = bban.slice(0, 10);
    if (bban[10] === noMod11(d10)) {
      let cur = d10;
      const twk = mkTweak(tweak, 'IBAN:NO');
      for (let i = 0; i < 64; i++) {
        cur = ff1Str(key32, twk, 10, cur, decrypt);
        const nk = noMod11(cur);
        if (nk !== null) {
          newBban = cur + nk;
          break;
        }
      }
    }
  }

  if (!newBban) {
    const twk = mkTweak(tweak, 'IBAN', cc);
    newBban = /^\d+$/.test(bban)
      ? ff1Str(key32, twk, 10, bban, decrypt)
      : ff1Alpha36CycleWalk(key32, twk, bban, decrypt);
  }
  const chk = ibanCheckDigits(cc, newBban);
  return applyMask(rawIban, cc + chk + newBban);
}

export function isValidUsSsn(raw) {
  const d = String(raw || '').replace(/-/g, '');
  if (!/^\d{9}$/.test(d)) return false;
  const a = Number(d.slice(0, 3));
  const g = Number(d.slice(3, 5));
  const s = Number(d.slice(5, 9));
  return a >= 1 && a <= 899 && a !== 666 && g >= 1 && s >= 1;
}

export function transformUsSsn(
  key32, tweak, raw, decrypt = false
) {
  const d = raw.replace(/-/g, '');
  if (!isValidUsSsn(d)) return raw;
  const a = Number(d.slice(0, 3));
  const g = Number(d.slice(3, 5));
  const s = Number(d.slice(5, 9));
  const ai = BigInt(a < 666 ? a - 1 : a - 2);
  const rk = (ai * 99n + BigInt(g - 1)) * 9999n +
    BigInt(s - 1);
  const twk = mkTweak(tweak, 'SSN');
  const nr = cycleWalkRank(
    rk, SSN_SPACE, 10, 9, key32, twk, decrypt
  );
  const ns = Number(nr % 9999n) + 1;
  const q1 = nr / 9999n;
  const ng = Number(q1 % 99n) + 1;
  const nai = Number(q1 / 99n);
  const na = nai < 665 ? nai + 1 : nai + 2;
  const out = String(na).padStart(3, '0') +
    String(ng).padStart(2, '0') +
    String(ns).padStart(4, '0');
  return applyMask(raw, out);
}

export function isValidUsItin(raw) {
  const d = String(raw || '').replace(/-/g, '');
  if (!/^9\d{8}$/.test(d)) return false;
  const g = Number(d.slice(3, 5));
  const s = Number(d.slice(5, 9));
  return ITIN_GROUPS.includes(g) && s >= 1;
}

export function transformUsItin(
  key32, tweak, raw, decrypt = false
) {
  const d = raw.replace(/-/g, '');
  if (!isValidUsItin(d)) return raw;
  const aIdx = BigInt(Number(d.slice(1, 3)));
  const gVal = Number(d.slice(3, 5));
  const gIdx = BigInt(ITIN_GROUPS.indexOf(gVal));
  const sIdx = BigInt(Number(d.slice(5, 9)) - 1);
  const rk = (aIdx * BigInt(ITIN_GROUPS.length) + gIdx) *
    9999n + sIdx;
  const nr = cycleWalkRank(
    rk, ITIN_SPACE, 10, 8, key32,
    mkTweak(tweak, 'ITIN'), decrypt
  );
  const ns = Number(nr % 9999n) + 1;
  const q1 = nr / 9999n;
  const gl = BigInt(ITIN_GROUPS.length);
  const ng = ITIN_GROUPS[Number(q1 % gl)];
  const na = Number(q1 / gl);
  const out = '9' + String(na).padStart(2, '0') +
    String(ng).padStart(2, '0') +
    String(ns).padStart(4, '0');
  return applyMask(raw, out);
}

export function isValidUsEin(raw) {
  const d = String(raw || '').replace(/-/g, '');
  if (!/^\d{9}$/.test(d)) return false;
  return EIN_SET.has(Number(d.slice(0, 2)));
}

export function transformUsEin(
  key32, tweak, raw, decrypt = false
) {
  const d = raw.replace(/-/g, '');
  if (!isValidUsEin(d)) return raw;
  const pIdx = BigInt(
    EIN_PREFIXES.indexOf(Number(d.slice(0, 2)))
  );
  const body = BigInt(d.slice(2));
  const rk = pIdx * 10_000_000n + body;
  const twk = mkTweak(tweak, 'EIN');
  const nr = cycleWalkRank(
    rk, EIN_SPACE, 10, 9, key32, twk, decrypt
  );
  const np = EIN_PREFIXES[Number(nr / 10_000_000n)];
  const nb = String(nr % 10_000_000n).padStart(7, '0');
  return applyMask(raw, String(np).padStart(2, '0') + nb);
}

export function computeCusipCheck(c8) {
  let s = 0;
  const u = c8.toUpperCase();
  for (let i = 0; i < 8; i++) {
    let v = /\d/.test(u[i])
      ? Number(u[i]) : u.charCodeAt(i) - 55;
    if (i % 2 === 1) v *= 2;
    s += Math.floor(v / 10) + (v % 10);
  }
  return String((10 - (s % 10)) % 10);
}

export function computeIsinCheck(c11) {
  let exp = '';
  const u = c11.toUpperCase();
  for (let i = 0; i < 11; i++) {
    exp += /\d/.test(u[i])
      ? u[i] : String(u.charCodeAt(i) - 55);
  }
  return computeLuhnCheckDigit(exp);
}

export function isValidIsin(s) {
  if (!/^[A-Z]{2}[0-9A-Z]{9}\d$/.test(s)) return false;
  return s[11] === computeIsinCheck(s.slice(0, 11));
}

export function transformIsin(
  key32, tweak, s12, decrypt = false
) {
  const u = s12.toUpperCase();
  if (!isValidIsin(u)) return s12;
  const cc = u.slice(0, 2);
  const body = ff1Str(
    key32, mkTweak(tweak, 'ISIN', cc), 36,
    u.slice(2, 11), decrypt
  );
  return cc + body + computeIsinCheck(cc + body);
}

export function isValidEsNif(raw) {
  const u = String(raw || '').toUpperCase().replace(/-/g, '');
  if (!/^[0-9XYZ]\d{7}[A-Z]$/.test(u)) return false;
  const pMap = { X: '0', Y: '1', Z: '2' };
  const d8 = (pMap[u[0]] ?? u[0]) + u.slice(1, 8);
  return u[8] === ES_NIF_TBL[Number(d8) % 23];
}

export function transformEsNif(
  key32, tweak, raw, decrypt = false
) {
  const u = String(raw || '').toUpperCase().replace(/-/g, '');
  if (!isValidEsNif(u)) return raw;
  const pMap = { X: '0', Y: '1', Z: '2' };
  const lead = u[0];
  const d7 = ff1Str(
    key32, mkTweak(tweak, 'ESNIF', lead), 10,
    u.slice(1, 8), decrypt
  );
  const num8 = Number((pMap[lead] ?? lead) + d7);
  const chk = ES_NIF_TBL[num8 % 23];
  return applyMask(raw, lead + d7 + chk);
}

export function isValidUsNpi(s) {
  if (!/^[12]\d{9}$/.test(s)) return false;
  const chk = computeLuhnCheckDigit('80840' + s.slice(0, 9));
  return s[9] === chk;
}

export function transformUsNpi(
  key32, tweak, s10, decrypt = false
) {
  if (!isValidUsNpi(s10)) return s10;
  const p1 = s10[0];
  const mid = ff1Str(
    key32, mkTweak(tweak, 'NPI', p1), 10,
    s10.slice(1, 9), decrypt
  );
  return p1 + mid + computeLuhnCheckDigit('80840' + p1 + mid);
}

export function isValidMedicareMbi(raw) {
  const s = String(raw || '').replace(/-/g, '').toUpperCase();
  if (s.length !== 11) return false;
  for (let i = 0; i < 11; i++) {
    if (!MBI_SLOTS[i].includes(s[i])) return false;
  }
  return true;
}

export function transformMedicareMbi(
  key32, tweak, raw, decrypt = false
) {
  const s = raw.replace(/-/g, '').toUpperCase();
  if (!isValidMedicareMbi(s)) return raw;
  let rk = 0n;
  for (let i = 0; i < 11; i++) {
    rk = rk * BigInt(MBI_SLOTS[i].length) +
      BigInt(MBI_SLOTS[i].indexOf(s[i]));
  }
  const twk = mkTweak(tweak, 'MBI');
  const nr = cycleWalkRank(
    rk, MBI_SPACE, 30, 9, key32, twk, decrypt
  );
  let rem = nr;
  const out = new Array(11);
  for (let i = 10; i >= 0; i--) {
    const b = BigInt(MBI_SLOTS[i].length);
    out[i] = MBI_SLOTS[i][Number(rem % b)];
    rem /= b;
  }
  return applyMask(raw, out.join(''));
}

export function isValidDeaNumber(s) {
  const u = String(s || '').toUpperCase();
  if (!/^[ABFGMPRX][A-Z]\d{7}$/.test(u)) return false;
  const d = u.slice(2, 8);
  const odd = Number(d[0]) + Number(d[2]) + Number(d[4]);
  const evn = Number(d[1]) + Number(d[3]) + Number(d[5]);
  return u[8] === String((odd + 2 * evn) % 10);
}

export function transformDeaNumber(
  key32, tweak, s9, decrypt = false
) {
  const u = s9.toUpperCase();
  if (!isValidDeaNumber(u)) return s9;
  const p2 = u.slice(0, 2);
  const d6 = ff1Str(
    key32, mkTweak(tweak, 'DEA', p2), 10,
    u.slice(2, 8), decrypt
  );
  const odd = Number(d6[0]) + Number(d6[2]) + Number(d6[4]);
  const evn = Number(d6[1]) + Number(d6[3]) + Number(d6[5]);
  return p2 + d6 + String((odd + 2 * evn) % 10);
}

export function isValidIsoVin(s) {
  const u = String(s || '').toUpperCase();
  if (u.length !== 17) return false;
  if (!/^\d{6}$/.test(u.slice(11, 17))) return false;
  let lets = 0, digs = 0, sum = 0;
  for (let i = 0; i < 17; i++) {
    const v = VIN_MAP[u[i]];
    if (v === undefined) return false;
    if (i !== 8) {
      if (/\d/.test(u[i])) digs++; else lets++;
      sum += v * VIN_W[i];
    }
  }
  if (lets < 3 || digs < 5) return false;
  const r = sum % 11;
  return u[8] === (r === 10 ? 'X' : String(r));
}

export function transformIsoVin(
  key32, tweak, s17, decrypt = false
) {
  const u = String(s17 || '').toUpperCase();
  if (!isValidIsoVin(u)) return s17;
  const wmi = u.slice(0, 3);
  const vds = u.slice(3, 8);
  const myp = u.slice(9, 11);
  const seq = ff1Str(
    key32, mkTweak(tweak, 'VIN', wmi + vds + myp),
    10, u.slice(11, 17), decrypt
  );
  const cand = wmi + vds + '0' + myp + seq;
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    if (i !== 8) sum += VIN_MAP[cand[i]] * VIN_W[i];
  }
  const r = sum % 11;
  const chk = r === 10 ? 'X' : String(r);
  return wmi + vds + chk + myp + seq;
}

export function maskHipaaSafeZip(zipStr) {
  const m = /^(\d{5})(-\d{4})?$/.exec(String(zipStr || ''));
  if (!m) return zipStr;
  const p3 = m[1].slice(0, 3);
  const base = HIPAA_ZERO_ZIPS.has(p3) ? '00000' : p3 + '00';
  return m[2] ? base + '-0000' : base;
}

export function computeClinicalDayShift(key32, scope) {
  const mac = crypto.createHmac('sha256', key32)
    .update('HIPAA-SHIFT|' + String(scope || 'default'))
    .digest();
  const idx = mac.readUInt32BE(0) % 360;
  return idx < 180 ? idx - 180 : idx - 179;
}

export function shiftIsoDateString(
  isoDate, key32, subjectScope, reverse = false
) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(isoDate);
  if (!m) return isoDate;
  const dt = Date.UTC(
    Number(m[1]), Number(m[2]) - 1, Number(m[3])
  );
  if (Number.isNaN(dt)) return isoDate;
  const delta = computeClinicalDayShift(key32, subjectScope);
  const days = reverse ? -delta : delta;
  const shifted = new Date(dt + days * 86_400_000);
  return shifted.toISOString().slice(0, 10);
}

const EIN_CTX_RE =
  /(\b(?:ein|fein|tax[ _-]?id)[^0-9]{0,14})(\d{2}-\d{7})\b/gi;
const ABA_CTX_RE =
  /(\b(?:routing|aba|rtn)[^0-9]{0,16})(\d{9})\b/gi;
const NPI_CTX_RE =
  /(\b(?:npi|provider[ _-]?id)[^0-9]{0,14})([12]\d{9})\b/gi;
const ZIP_CTX_RE = new RegExp(
  '(\\b(?:zip|postal)(?:[ _-]?code)?[^0-9]{0,12})' +
  '(\\d{5}(?:-\\d{4})?)\\b', 'gi'
);
const AGE_CTX_RE =
  /(\b(?:age|aged)\s*[:=]?\s*)(9\d|1[01]\d)\b/gi;
const UK_NINO_RE = new RegExp(
  '\\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]' +
  '[A-CEGHJ-NPR-TW-Z]\\d{6}[A-D]\\b', 'g'
);

const ICAO_MRZ_EXACT_RE = new RegExp(
  '^[A-Z0-9<]{9}\\d[A-Z<]{3}\\d{6}\\d[MF<]' +
  '\\d{6}\\d[A-Z0-9<]{14}[0-9<]\\d$'
);
const ICAO_MRZ_TEXT_RE = new RegExp(
  '(?<![A-Z0-9<])[A-Z0-9<]{9}\\d[A-Z<]{3}\\d{6}' +
  '\\d[MF<]\\d{6}\\d[A-Z0-9<]{14}[0-9<]\\d' +
  '(?![A-Z0-9<])', 'g'
);

export function computeIcaoMrzCheckDigit(str) {
  const w = [7, 3, 1];
  let sum = 0;
  const u = String(str || '').toUpperCase();
  for (let i = 0; i < u.length; i++) {
    const c = u.charCodeAt(i);
    let v = 0;
    if (c >= 48 && c <= 57) v = c - 48;
    else if (c >= 65 && c <= 90) v = c - 55;
    else if (c === 60) v = 0;
    else return null;
    sum += v * w[i % 3];
  }
  return String(sum % 10);
}

export function isValidIcaoMrz(line2) {
  const u = String(line2 || '').toUpperCase();
  if (u.length !== 44 || !ICAO_MRZ_EXACT_RE.test(u)) {
    return false;
  }
  if (u[9] !== computeIcaoMrzCheckDigit(
    u.slice(0, 9))) return false;
  if (u[19] !== computeIcaoMrzCheckDigit(
    u.slice(13, 19))) return false;
  if (u[27] !== computeIcaoMrzCheckDigit(
    u.slice(21, 27))) return false;
  const opt = u.slice(28, 42);
  const optChk = u[42];
  if (opt === '<<<<<<<<<<<<<<') {
    if (optChk !== '<' && optChk !== '0') return false;
  } else if (optChk !== computeIcaoMrzCheckDigit(opt)) {
    return false;
  }
  const comp = u.slice(0, 10) + u.slice(13, 20) +
    u.slice(21, 43);
  return u[43] === computeIcaoMrzCheckDigit(comp);
}

function transformMrzField(key32, twk, field, dec) {
  if (/^<+$/.test(field)) return field;
  const mNum = /^(\d{6,})(<*)$/.exec(field);
  if (mNum) {
    return ff1Str(key32, twk, 10, mNum[1], dec) +
      mNum[2];
  }
  const mAlp = /^([0-9A-Z]{4,})(<*)$/.exec(field);
  if (mAlp && !/^\d+$/.test(mAlp[1])) {
    return ff1Alpha36CycleWalk(
      key32, twk, mAlp[1], dec
    ) + mAlp[2];
  }
  return field;
}

export function transformIcaoMrz(
  key32, tweak, line2, decrypt = false
) {
  const u = String(line2 || '').toUpperCase();
  if (!isValidIcaoMrz(u)) return line2;
  const nat = u.slice(10, 13);
  const mid = u.slice(13, 28);
  const docTwk = mkTweak(tweak, 'MRZ:DOC', nat + mid);
  const optTwk = mkTweak(tweak, 'MRZ:OPT', nat + mid);
  const doc = transformMrzField(
    key32, docTwk, u.slice(0, 9), decrypt
  );
  const docChk = computeIcaoMrzCheckDigit(doc);
  const rawOpt = u.slice(28, 42);
  const opt = transformMrzField(
    key32, optTwk, rawOpt, decrypt
  );
  const optChk = rawOpt === '<<<<<<<<<<<<<<'
    ? u[42] : computeIcaoMrzCheckDigit(opt);
  const head = doc + docChk + nat + mid + opt + optChk;
  const comp = head.slice(0, 10) + head.slice(13, 20) +
    head.slice(21, 43);
  return head + computeIcaoMrzCheckDigit(comp);
}

export function pseudonymizeSectorText(
  text, key32, tweak, activePacks = [], options = {}
) {
  text = normalizeUnicodeEvasion(text);
  if (typeof text !== 'string' || !text) {
    return { text, counts: {}, pairs: [] };
  }
  const useAll = activePacks.includes('all');
  const packs = new Set(
    useAll ? SECTOR_PACK_IDS : activePacks
  );
  const pairs = [];
  const counts = {};
  let out = text;
  const slotTag = out.includes('\x00SIP_SLOT_')
    ? 'SIP_SLOT_' + crypto.randomBytes(4).toString('hex')
      + '_'
    : 'SIP_SLOT_';
  const slots = [];
  const bump = (k, orig, syn) => {
    if (orig === syn) return orig;
    counts[k] = (counts[k] || 0) + 1;
    pairs.push([syn, orig, k]);
    const id = slots.length;
    slots.push(syn);
    return `\x00${slotTag}${id}\x00`;
  };

  if (packs.has('legal_tax')) {
    out = out.replace(ICAO_MRZ_TEXT_RE, (m) =>
      isValidIcaoMrz(m)
        ? bump('ICAO_MRZ', m,
               transformIcaoMrz(key32, tweak, m, false))
        : m
    );
  }

  if (Array.isArray(options.watchlist)) {
    for (const term of options.watchlist) {
      if (typeof term !== 'string' || term.length < 3) continue;
      if (!out.includes(term)) continue;
      const h = crypto.createHmac('sha256', key32)
        .update('WATCH|' + term).digest('hex').slice(0, 8);
      const syn = `ENTITY_${h.toUpperCase()}`;
      out = out.split(term).join(bump('WATCHLIST', term, syn));
    }
  }

  if (packs.has('pci_dora')) {
    out = out.replace(
      /\b[0-9A-Z]{4}00[0-9A-Z]{12}\d{2}\b/g,
      (m) => isValidIsoLei(m)
        ? bump('ISO_LEI', m,
               transformIsoLei(key32, tweak, m, false))
        : m
    );
    out = out.replace(
      /\b[A-Z]{2}\d{2}(?:[ ]?[0-9A-Z]{2,4}){3,8}\b/g,
      (m) => bump('SEPA_IBAN', m,
                  transformSepaIban(key32, tweak, m, false))
    );
    out = out.replace(
      /\b\d(?:[ -]?\d){12,18}\b/g,
      (m) => isValidStrictPan(m)
        ? bump('STRICT_PAN', m,
               transformStrictPan(key32, tweak, m, false))
        : m
    );
    out = out.replace(ABA_CTX_RE, (full, pre, d9) => {
      if (!isValidAbaRouting(d9)) return full;
      const syn = transformAbaRouting(
        key32, tweak, d9, false
      );
      return pre + bump('ABA_RTN', d9, syn);
    });
    out = out.replace(/\b0x[a-fA-F0-9]{40}\b/g, (m) => {
      const h = crypto.createHmac('sha256', key32)
        .update('ETH|' + m.toLowerCase())
        .digest('hex').slice(0, 40);
      return bump('EVM_WALLET', m, '0x' + h);
    });
  }

  if (packs.has('legal_tax')) {
    out = out.replace(
      /\b9\d{2}-\d{2}-\d{4}\b/g,
      (m) => isValidUsItin(m)
        ? bump('US_ITIN', m,
               transformUsItin(key32, tweak, m, false))
        : m
    );
    out = out.replace(
      /\b\d{3}-\d{2}-\d{4}\b/g,
      (m) => isValidUsSsn(m)
        ? bump('US_SSN', m,
               transformUsSsn(key32, tweak, m, false))
        : m
    );
    out = out.replace(EIN_CTX_RE, (full, pre, ein) => {
      if (!isValidUsEin(ein)) return full;
      const syn = transformUsEin(key32, tweak, ein, false);
      return pre + bump('US_EIN', ein, syn);
    });
    out = out.replace(
      /\b[A-Z]{2}[0-9A-Z]{9}\d\b/g,
      (m) => isValidIsin(m)
        ? bump('ISIN', m,
               transformIsin(key32, tweak, m, false))
        : m
    );
    out = out.replace(
      /\b[0-9XYZ]\d{7}[A-Z]\b/g,
      (m) => isValidEsNif(m)
        ? bump('ES_NIF', m,
               transformEsNif(key32, tweak, m, false))
        : m
    );
    out = out.replace(UK_NINO_RE, (m) => {
      const d6 = ff1Str(
        key32, mkTweak(tweak, 'NINO', m.slice(0, 2)),
        10, m.slice(2, 8), false
      );
      return bump('UK_NINO', m, m.slice(0, 2) + d6 + m[8]);
    });
  }

  if (packs.has('hipaa_clinical')) {
    out = out.replace(MBI_RE, (m) =>
      isValidMedicareMbi(m)
        ? bump('MEDICARE_MBI', m,
               transformMedicareMbi(key32, tweak, m, false))
        : m
    );
    out = out.replace(
      /\b[ABFGMPRX][A-Z]\d{7}\b/g,
      (m) => isValidDeaNumber(m)
        ? bump('DEA_NUMBER', m,
               transformDeaNumber(key32, tweak, m, false))
        : m
    );
    out = out.replace(
      /\b[A-HJ-NPR-Z0-9]{17}\b/g,
      (m) => isValidIsoVin(m)
        ? bump('VEHICLE_VIN', m,
               transformIsoVin(key32, tweak, m, false))
        : m
    );
    out = out.replace(NPI_CTX_RE, (full, pre, npi) => {
      if (!isValidUsNpi(npi)) return full;
      const syn = transformUsNpi(key32, tweak, npi, false);
      return pre + bump('US_NPI', npi, syn);
    });
    out = out.replace(ZIP_CTX_RE, (full, pre, zp) =>
      pre + bump('HIPAA_ZIP', zp, maskHipaaSafeZip(zp))
    );
    out = out.replace(AGE_CTX_RE, (full, pre, ag) =>
      pre + bump('HIPAA_AGE90', ag, '90')
    );
    if (options.shiftDates) {
      const subj = options.subjectScope || 'clinical-session';
      out = out.replace(
        /\b((?:19|20)\d{2}-\d{2}-\d{2})\b/g,
        (m) => bump('HIPAA_DATE', m,
                    shiftIsoDateString(m, key32, subj, false))
      );
    }
  }

  for (let k = slots.length - 1; k >= 0; k--) {
    const marker = `\x00${slotTag}${k}\x00`;
    out = out.split(marker).join(slots[k]);
  }
  return { text: out, counts, pairs };
}

export function transformCardPan(
  panVal, key32, tweak, decrypt = false
) {
  if (!isPlausiblePaymentIin(panVal)) return panVal;
  return transformStrictPan(
    key32, tweak, String(panVal), Boolean(decrypt)
  );
}
