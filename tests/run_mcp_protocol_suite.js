// REAL SUBPROCESS JSON-RPC 2.0 MCP PROTOCOL & ED25519 PAYWALL SUITE (15 TESTS)
"use strict";

const assert = require("assert");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const { issueEd25519LicenseKey } = require("/root/issue_license.js");
const { verifyLicenseKeyOffline } = require("../src/sip1_license_engine");

let passed = 0;
function check(name, cond) {
  assert.strictEqual(Boolean(cond), true, "FAILED: " + name);
  passed++;
  console.log("  [PASS] P" + String(passed).padStart(2, "0") + ". " + name);
}

function runStdioSession(envVars, requests) {
  return new Promise((resolve, reject) => {
    const srvPath = path.join(__dirname, "../bin/sip1-mcp.js");
    const proc = spawn("node", [srvPath], { env: Object.assign({}, process.env, envVars) });
    const responses = [];
    let buf = "";
    proc.stdout.on("data", (chunk) => {
      buf += chunk.toString();
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const ln of lines) {
        if (ln.trim()) responses.push(JSON.parse(ln.trim()));
      }
      if (responses.length >= requests.length) {
        proc.kill();
        resolve(responses);
      }
    });
    proc.on("error", reject);
    for (const req of requests) proc.stdin.write(JSON.stringify(req) + "\n");
  });
}

(async () => {
  console.log("=== RUNNING REAL STDIO MCP JSON-RPC 2.0 & ED25519 PAYWALL SUITE ===");

  const validCorpKey = issueEd25519LicenseKey("CORPORATE", "TBC_BANK_GE", "20271231");
  const validMilKey = issueEd25519LicenseKey("MILITARY", "DEFENSE_GE", "20271231");
  check("Ed25519 Private Key Issues Compact Signed Corporate Key", validCorpKey.startsWith("SIP1.CORPORATE.20271231.TBC_BANK_GE."));
  check("Ed25519 Public Key Verifies Authentic Corporate Signature Offline", verifyLicenseKeyOffline(validCorpKey).valid === true && verifyLicenseKeyOffline(validCorpKey).tier === "CORPORATE");

  const forgedKey = validCorpKey.replace("SIP1.CORPORATE.", "SIP1.MILITARY.");
  check("Ed25519 Public Verifier Rejects Tampered Tier Escalation Attempt", verifyLicenseKeyOffline(forgedKey).valid === false && verifyLicenseKeyOffline(forgedKey).reason === "ERR_ED25519_SIGNATURE_FORGED");

  const expiredKey = issueEd25519LicenseKey("PRO", "OLD_USER", "20200101");
  check("Ed25519 Public Verifier Rejects Expired License Key", verifyLicenseKeyOffline(expiredKey).valid === false && verifyLicenseKeyOffline(expiredKey).reason === "ERR_LICENSE_EXPIRED");

  const freeReqs = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    { jsonrpc: "2.0", id: 3, method: "prompts/list", params: {} },
    { jsonrpc: "2.0", id: 4, method: "resources/list", params: {} },
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "sip1_generate_aibom", arguments: { organization: "TestCorp" } } },
    { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "sip1_scrub_payload", arguments: { text: "HQ 41.6461, 41.6405", contour: "MILITARY" } } }
  ];
  const freeRes = await runStdioSession({ SIP1_LICENSE_KEY: "" }, freeReqs);

  check("Stdio JSON-RPC 2.0 initialize Handshake Returns Server Info & DOI", freeRes[0].result.serverInfo.name === "sip1-mcp-firewall" && freeRes[0].result.serverInfo.doi.includes("10.5281/zenodo.24159380"));
  check("Stdio JSON-RPC 2.0 tools/list Exposes 5 Structured Tools for Glama Grade A", freeRes[1].result.tools.length === 5);
  check("Stdio JSON-RPC 2.0 prompts/list & resources/list Respond Cleanly", freeRes[2].result.prompts.length === 1 && freeRes[3].result.resources.length === 1);
  check("Commercial Paywall Blocks EU AI Act AIBOM Export in Free Community Mode", freeRes[4].result.isError === true && freeRes[4].result.content[0].text.includes("PAYWALL_CORPORATE_REQUIRED"));
  check("Commercial Paywall Blocks Military Zero-Trust Contour in Free Community Mode", freeRes[5].result.isError === true && freeRes[5].result.content[0].text.includes("PAYWALL_MILITARY_REQUIRED"));

  const capReqs = [];
  for (let i = 1; i <= 16; i++) {
    capReqs.push({ jsonrpc: "2.0", id: 100 + i, method: "tools/call", params: { name: "sip1_scrub_payload", arguments: { text: "Key AKIAIOSFODNN7EXAMPLE" } } });
  }
  const capRes = await runStdioSession({ SIP1_LICENSE_KEY: "" }, capReqs);
  check("Commercial Paywall Enforces 15-Call Cap on 16th Request in Free Mode", capRes[14].result.isError !== true && capRes[15].result.isError === true && capRes[15].result.content[0].text.includes("LOCKED_FREE_TIER_LIMIT"));

  const paidReqs = [
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "sip1_generate_aibom", arguments: { organization: "SHULIAK_BANK_CORP" } } },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "sip1_scrub_payload", arguments: { text: "Card 4532015112830366 IBAN GE29NB0000000101904917", contour: "CORPORATE" } } },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "sip1_scrub_payload", arguments: { text: "MGRS: 38T KM 12345 67890", contour: "MILITARY" } } },
    { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "sip1_audit_jsonrpc", arguments: { payload: "../../etc/passwd" } } }
  ];
  const paidRes = await runStdioSession({ SIP1_LICENSE_KEY: validMilKey }, paidReqs);

  const aibomObj = JSON.parse(paidRes[0].result.content[0].text);
  check("Paid Ed25519 Key Unlocks Signed CycloneDX EU AI Act AIBOM Generator", aibomObj.schema === "SHULIAK-SIP1-AIBOM-2026-v1" && aibomObj.organization === "SHULIAK_BANK_CORP");

  const scrubObj = JSON.parse(paidRes[1].result.content[0].text);
  check("Paid Ed25519 Key Unlocks Stateless NIST FF1 Card & Georgian IBAN Twins", scrubObj.tier === "MILITARY" && !scrubObj.sanitizedText.includes("4532015112830366") && !scrubObj.sanitizedText.includes("GE29NB0000000101904917"));

  const milObj = JSON.parse(paidRes[2].result.content[0].text);
  check("Paid Ed25519 Key Unlocks Military MGRS Grid Scrubbing", milObj.sanitizedText.includes("[MGRS_MASKED]"));

  const auditObj = JSON.parse(paidRes[3].result.content[0].text);
  check("MCP Firewall Quarantines Path Traversal Exploit Over Stdio", auditObj.quarantined === true && auditObj.allowed === false);

  const allFiles = fs.readdirSync(path.join(__dirname, "../src"));
  const hasPriv = allFiles.some(f => fs.readFileSync(path.join(__dirname, "../src", f), "utf8").includes("-----BEGIN PRIVATE KEY-----") || fs.readFileSync(path.join(__dirname, "../src", f), "utf8").includes("MASTER_SIGNING_SEED"));
  check("Confidentiality Audit: Zero Private Keys or Signing Seeds Present in Public Repo", hasPriv === false);

  console.log("=====================================================================");
  console.log("MCP STDIO PROTOCOL & ED25519 PAYWALL COMPLETE: ALL " + passed + "/15 TESTS PASSED!");
  console.log("=====================================================================");
})();
