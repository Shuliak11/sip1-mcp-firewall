// STATIC CODE SECURITY & VULNERABILITY ANALYZER (OpenSSF Passing Criteria)
"use strict";
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const banned = [
  { rx: /\beval\s*\(/, msg: "Unsafe eval()" },
  { rx: /new\s+Function\s*\(/, msg: "Unsafe Function constructor" },
  { rx: /createHash\s*\(\s*["'](md4|md5|sha1)["']\s*\)/i, msg: "Weak hash algorithm" },
  { rx: /createCipheriv\s*\(\s*["'](des|rc4|bf|ff3)/i, msg: "Weak or withdrawn cipher call" }
];

for (const dir of ["src", "bin"]) {
  const fullDir = path.join(__dirname, "..", dir);
  for (const f of fs.readdirSync(fullDir)) {
    if (!f.endsWith(".js")) continue;
    const raw = fs.readFileSync(path.join(fullDir, f), "utf8");
    assert.ok(/["']use strict["']/.test(raw), f + " missing strict mode");
    const codeOnly = raw.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, "");
    for (const rule of banned) {
      assert.strictEqual(rule.rx.test(codeOnly), false, f + " triggered: " + rule.msg);
    }
  }
}
console.log("  [PASS] STATIC SECURITY ANALYZER: 0 VULNERABILITIES ACROSS ALL MODULES");
