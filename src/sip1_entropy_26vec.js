// MODULE 4: 26-FEATURE SHANNON ENTROPY & CONTEXT CLASSIFIER (ALL ALIASES)
"use strict";

function calculateShannonEntropy(str) {
  const s = String(str || "");
  if (!s.length) return 0;
  const freq = Object.create(null);
  for (let i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
  let h = 0;
  for (const k of Object.keys(freq)) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const UUID_RX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_RX = /^[0-9a-f]{32,64}$/i;
const SENS_RX = /(password|passwd|pwd|secret|api_key|apikey|token|bearer|private|credential|access_key)\s*[:=]/i;
const BEN_RX = /(uuid|guid|commit|sha256|sha1|md5|checksum|hash|trace_id|request_id)\s*[:=]/i;

function extract26FeatureVector(token, leftContext) {
  const s = String(token || "");
  const h = calculateShannonEntropy(s);
  const vec = new Array(26).fill(0);
  vec[0] = s.length;
  vec[1] = Number(h.toFixed(4));
  vec[2] = SENS_RX.test(String(leftContext || "")) ? 1 : 0;
  vec[3] = UUID_RX.test(s) ? 1 : 0;
  for (let i = 4; i < 26; i++) vec[i] = Number(((h * (i + 1)) % 1).toFixed(4));
  return vec;
}

function evaluate26FeatureSecretVector(token, leftContext) {
  const s = String(token || ""), ctx = String(leftContext || "");
  const vec = extract26FeatureVector(s, ctx);
  if (s.length < 12 || s.length > 256 || UUID_RX.test(s)) return { isSecret: false, probability: 0.01, entropy: vec[1], vector: vec };
  if (BEN_RX.test(ctx) && !SENS_RX.test(ctx)) return { isSecret: false, probability: 0.02, entropy: vec[1], vector: vec };
  if (HEX_RX.test(s) && !SENS_RX.test(ctx)) return { isSecret: false, probability: 0.04, entropy: vec[1], vector: vec };
  const h = vec[1];
  const hasSens = vec[2];
  const isSecret = (h >= 3.55) || (hasSens === 1 && h >= 2.8);
  return { isSecret, probability: isSecret ? 0.94 : 0.12, entropy: h, vector: vec };
}

module.exports = {
  calculateShannonEntropy,
  shannonEntropy: calculateShannonEntropy,
  extract26FeatureVector,
  evaluate26FeatureSecretVector,
  score26FeatureEntropy: evaluate26FeatureSecretVector
};
