// ED25519 PUBLIC-KEY LICENSE VERIFIER (ZERO SECRET EXPOSURE)
"use strict";
const crypto = require("crypto");
const SHULIAK_ED25519_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEABaXRTOlg7UX63y/YfjGHk4BmKRNAj42UPu69XZL2O0k=
-----END PUBLIC KEY-----`;

function verifyLicenseKeyOffline(licenseKeyStr) {
  if (!licenseKeyStr || typeof licenseKeyStr !== "string") {
    return { valid: false, tier: "FREE_COMMUNITY", reason: "NO_KEY_PROVIDED", maxCalls: 15, ff1Enabled: false, aibomEnabled: false, militaryEnabled: false };
  }
  const parts = licenseKeyStr.trim().split(".");
  if (parts.length !== 5 || parts[0] !== "SIP1") {
    return { valid: false, tier: "FREE_COMMUNITY", reason: "ERR_MALFORMED_KEY_FORMAT", maxCalls: 15, ff1Enabled: false, aibomEnabled: false, militaryEnabled: false };
  }
  const [prefix, tier, exp, client, sigB64] = parts;
  const payload = `${prefix}.${tier}.${exp}.${client}`;
  try {
    const ok = crypto.verify(null, Buffer.from(payload, "utf8"), SHULIAK_ED25519_PUBLIC_KEY, Buffer.from(sigB64, "base64url"));
    if (!ok) return { valid: false, tier: "FREE_COMMUNITY", reason: "ERR_ED25519_SIGNATURE_FORGED", maxCalls: 15, ff1Enabled: false, aibomEnabled: false, militaryEnabled: false };
  } catch (e) {
    return { valid: false, tier: "FREE_COMMUNITY", reason: "ERR_CRYPTO_VERIFY_FAILED", maxCalls: 15, ff1Enabled: false, aibomEnabled: false, militaryEnabled: false };
  }
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  if (exp < today) {
    return { valid: false, tier: "FREE_COMMUNITY", reason: "ERR_LICENSE_EXPIRED", maxCalls: 15, ff1Enabled: false, aibomEnabled: false, militaryEnabled: false };
  }
  return {
    valid: true,
    tier,
    client,
    expires: exp,
    reason: "VERIFIED_ED25519_SIGNATURE",
    maxCalls: Infinity,
    ff1Enabled: true,
    aibomEnabled: tier === "CORPORATE" || tier === "MILITARY",
    militaryEnabled: tier === "MILITARY" || tier === "PRO"
  };
}
module.exports = { SHULIAK_ED25519_PUBLIC_KEY, verifyLicenseKeyOffline };
