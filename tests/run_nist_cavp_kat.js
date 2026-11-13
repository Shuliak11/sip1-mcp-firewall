// OFFICIAL NIST SP 800-38G CAVP 9-VECTOR KNOWN-ANSWER TEST (KAT) SUITE
"use strict";
const assert = require("assert");
const { ff1Encrypt, ff1Decrypt } = require("../src/sip1_ff1_crypto");

const VECTORS = [
  [10, "2B7E151628AED2A6ABF7158809CF4F3C", "", "0123456789", "2433477484"],
  [10, "2B7E151628AED2A6ABF7158809CF4F3C", "39383736353433323130", "0123456789", "6124200773"],
  [36, "2B7E151628AED2A6ABF7158809CF4F3C", "3737373770717273373737", "0123456789abcdefghi", "a9tv40mll9kdu509eum"],
  [10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "", "0123456789", "2830668132"],
  [10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "39383736353433323130", "0123456789", "2496655549"],
  [36, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "3737373770717273373737", "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"],
  [10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "", "0123456789", "6657667009"],
  [10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "39383736353433323130", "0123456789", "1001623463"],
  [36, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "3737373770717273373737", "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"]
];

console.log("=== RUNNING OFFICIAL NIST SP 800-38G CAVP 9-VECTOR KAT SUITE ===");
let passed = 0;
for (let i = 0; i < VECTORS.length; i++) {
  const [rad, kHex, tHex, pt, expectedCt] = VECTORS[i];
  const keyBuf = Buffer.from(kHex, "hex");
  const twBuf = tHex ? Buffer.from(tHex, "hex") : Buffer.alloc(0);
  const ct = ff1Encrypt(pt, keyBuf, twBuf, rad);
  const dec = ff1Decrypt(ct, keyBuf, twBuf, rad);
  assert.strictEqual(ct, expectedCt, `NIST Vector #${i+1} Ciphertext mismatch: got ${ct}`);
  assert.strictEqual(dec, pt, `NIST Vector #${i+1} Decrypt mismatch: got ${dec}`);
  passed++;
  console.log(`  [PASS] NIST CAVP #0${passed} (AES-${keyBuf.length*8}, Radix-${rad}): ${pt} -> ${ct}`);
}
console.log("=================================================================");
console.log(`NIST CAVP VERIFICATION COMPLETE: ALL ${passed}/9 OFFICIAL VECTORS MATCH!`);
console.log("=================================================================");
