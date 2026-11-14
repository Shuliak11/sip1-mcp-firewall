#!/usr/bin/env node
"use strict";

const readline = require("readline");
const { Sip1McpFirewall } = require("../src/sip1_mcp_firewall");
const { Sip1OmniEngineV2 } = require("../src/sip1_omni_v2");
const { verifyLicenseKeyOffline } = require("../src/sip1_license_engine");

const activeKey = process.env.SIP1_LICENSE_KEY || "";
let licenseInfo = verifyLicenseKeyOffline(activeKey);
let sessionCallCount = 0;

const fw = new Sip1McpFirewall({ masterKey: activeKey || "community-seed", tweak: "MCP_STDIO" });
const omni = new Sip1OmniEngineV2(licenseInfo.valid ? "CORPORATE" : "PERSONAL");

if (process.argv.includes("--version") || process.argv.includes("-v")) {
  process.stdout.write("sip1-mcp-firewall v2.6.2 (CERN DOI: 10.5281/zenodo.24159380)\n");
  process.exit(0);
}

function sendJsonRpc(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

const wrapIdx = process.argv.indexOf("--wrap");
if (wrapIdx !== -1 && process.argv.length > wrapIdx + 1) {
  const { spawn } = require("child_process");
  const cmd = process.argv[wrapIdx + 1];
  const cmdArgs = process.argv.slice(wrapIdx + 2);
  const child = spawn(cmd, cmdArgs, { stdio: ["pipe", "pipe", "inherit"], env: process.env });

  const rlClient = readline.createInterface({ input: process.stdin, terminal: false });
  rlClient.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const pkt = JSON.parse(trimmed);
      sessionCallCount++;
      if (!licenseInfo.valid && sessionCallCount > licenseInfo.maxCalls) {
        sendJsonRpc({ jsonrpc: "2.0", id: pkt.id || null, error: { code: -32002, message: "LOCKED_FREE_TIER_LIMIT: Upgrade at https://shuliak.dev/#pricing" } });
        return;
      }
      const res = fw.interceptJsonRpcRequest(pkt);
      if (res.quarantined) sendJsonRpc(res.packet);
      else child.stdin.write(JSON.stringify(res.packet) + "\n");
    } catch (e) {
      child.stdin.write(line + "\n");
    }
  });

  const rlChild = readline.createInterface({ input: child.stdout, terminal: false });
  rlChild.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const pkt = JSON.parse(trimmed);
      const restored = fw.interceptJsonRpcResponse(pkt);
      if (!restored.quarantined) sendJsonRpc(restored.packet);
    } catch (e) {
      process.stdout.write(line + "\n");
    }
  });
  child.on("exit", (code) => process.exit(code || 0));
  return;
}

const MCP_TOOLS = [
  {
    name: "sip1_scrub_payload",
    description: "Scrub sensitive PII, Luhn payment cards, ISO-7064 IBANs, and cloud API secrets from text or JSON using on-device NIST SP 800-38G FF1 pseudonymization.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        text: { type: "string", description: "Raw prompt, code snippet, or JSON payload to sanitize locally before external transmission." },
        contour: { type: "string", enum: ["PERSONAL", "CORPORATE", "MILITARY"], description: "Operational security contour threshold (default: CORPORATE)." }
      },
      required: ["text"]
    },
    annotations: { title: "SIP-1 Scrub Payload", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "sip1_rehydrate_response",
    description: "Deterministically restore synthetic SIP-1 twins and session tokens back to original plaintext values in local memory.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        maskedText: { type: "string", description: "Inbound LLM or tool response string containing SIP-1 tokens or FF1 synthetic twins." }
      },
      required: ["maskedText"]
    },
    annotations: { title: "SIP-1 Rehydrate Response", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "sip1_audit_jsonrpc",
    description: "Inspect MCP JSON-RPC 2.0 tool call payloads for OWASP MCP05/06 Path Traversal, Command Injection, Prototype Pollution, and covert Zero-Width Unicode smuggling.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        payload: { type: "string", description: "Raw JSON-RPC 2.0 request or tool argument payload string to audit for security threats." }
      },
      required: ["payload"]
    },
    annotations: { title: "SIP-1 Audit JSON-RPC", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: "sip1_generate_aibom",
    description: "Generate a cryptographically signed CycloneDX AI Bill of Materials (AIBOM) & SHA-256 Merkle attestation for EU AI Act, GDPR Art. 4(5), SOC 2, and NIST 800-171 compliance.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        organization: { type: "string", description: "Legal entity or workspace identifier to bind into the signed CycloneDX AIBOM manifest." }
      },
      required: ["organization"]
    },
    annotations: { title: "SIP-1 Generate AIBOM", readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  },
  {
    name: "sip1_license_status",
    description: "Check active SHULIAK SIP-1 license tier, remaining free session quota, or verify and activate an offline Ed25519 license key.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        licenseKey: { type: "string", description: "Optional Ed25519 signed license token (SIP1.TIER.YYYYMMDD.ORG.SIGNATURE) to verify offline." }
      }
    },
    annotations: { title: "SIP-1 License Status", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }
];

const MCP_PROMPTS = [
  {
    name: "sip1-zero-egress-audit",
    description: "Run a structured OWASP MCP Top 10 and EU AI Act Art. 15 zero-egress security audit on a target payload.",
    arguments: [{ name: "target", description: "Target configuration or prompt text to inspect.", required: true }]
  }
];

const MCP_RESOURCES = [
  {
    uri: "sip1://policy/status",
    name: "SHULIAK SIP-1 Kernel & Compliance Telemetry",
    description: "Live status of the on-device WebAssembly kernel, 9/9 NIST CAVP FF1 engine, and active license contour.",
    mimeType: "application/json"
  }
];

function handleRpcMessage(msg) {
  if (!msg || typeof msg !== "object") return;
  const { id, method, params } = msg;

  // JSON-RPC 2.0 Notifications have no id and MUST NOT receive a response
  if (id === undefined) return;

  if (method === "initialize") {
    return sendJsonRpc({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: (params && params.protocolVersion) ? params.protocolVersion : "2025-06-18",
        capabilities: {
          tools: { listChanged: false },
          prompts: { listChanged: false },
          resources: { subscribe: false, listChanged: false }
        },
        serverInfo: {
          name: "sip1-mcp-firewall",
          version: "2.6.2",
          vendor: "SHULIAK CORP (https://shuliak.dev)",
          doi: "https://doi.org/10.5281/zenodo.24159380"
        }
      }
    });
  }

  if (method === "ping" || method === "logging/setLevel") {
    return sendJsonRpc({ jsonrpc: "2.0", id, result: {} });
  }
  if (method === "tools/list") {
    return sendJsonRpc({ jsonrpc: "2.0", id, result: { tools: MCP_TOOLS } });
  }
  if (method === "prompts/list") {
    return sendJsonRpc({ jsonrpc: "2.0", id, result: { prompts: MCP_PROMPTS } });
  }
  if (method === "prompts/get") {
    const t = (params && params.arguments && params.arguments.target) ? String(params.arguments.target) : "";
    return sendJsonRpc({
      jsonrpc: "2.0",
      id,
      result: {
        description: "SHULIAK SIP-1 Zero-Egress Security Audit",
        messages: [{ role: "user", content: { type: "text", text: "Perform OWASP MCP05/06 & NIST FF1 audit on: " + t } }]
      }
    });
  }
  if (method === "resources/list") {
    return sendJsonRpc({ jsonrpc: "2.0", id, result: { resources: MCP_RESOURCES } });
  }
  if (method === "resources/templates/list") {
    return sendJsonRpc({ jsonrpc: "2.0", id, result: { resourceTemplates: [] } });
  }
  if (method === "resources/read") {
    return sendJsonRpc({
      jsonrpc: "2.0",
      id,
      result: {
        contents: [{
          uri: "sip1://policy/status",
          mimeType: "application/json",
          text: JSON.stringify({ protocol: "SIP-1 v2.6.2", cavp: "9/9_VERIFIED", tier: licenseInfo.tier, valid: licenseInfo.valid, doi: "10.5281/zenodo.24159380" })
        }]
      }
    });
  }
  if (method === "completion/complete") {
    return sendJsonRpc({ jsonrpc: "2.0", id, result: { completion: { values: [], total: 0, hasMore: false } } });
  }

  if (method === "tools/call") {
    const toolName = (params && params.name) || "";
    const args = (params && params.arguments) || {};

    if (toolName === "sip1_license_status") {
      if (args.licenseKey) licenseInfo = verifyLicenseKeyOffline(args.licenseKey);
      return sendJsonRpc({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify({ license: licenseInfo, callsUsed: sessionCallCount, upgradeUrl: "https://shuliak.dev/#pricing" }) }] } });
    }

    sessionCallCount++;
    if (!licenseInfo.valid && sessionCallCount > licenseInfo.maxCalls) {
      return sendJsonRpc({
        jsonrpc: "2.0",
        id,
        result: { isError: true, content: [{ type: "text", text: "LOCKED_FREE_TIER_LIMIT: Free Community Edition is limited to 15 operations per session. Unlock at https://shuliak.dev/#pricing" }] }
      });
    }

    if (toolName === "sip1_generate_aibom") {
      if (!licenseInfo.aibomEnabled) {
        return sendJsonRpc({
          jsonrpc: "2.0",
          id,
          result: { isError: true, content: [{ type: "text", text: "PAYWALL_CORPORATE_REQUIRED: Signed EU AI Act CycloneDX AIBOM requires a Corporate or Military key (https://shuliak.dev/#pricing)" }] }
        });
      }
      return sendJsonRpc({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(fw.generateAibomAttestation(args.organization || licenseInfo.client)) }] } });
    }

    if (toolName === "sip1_scrub_payload") {
      const reqContour = String(args.contour || "CORPORATE").toUpperCase();
      if (reqContour === "MILITARY" && !licenseInfo.militaryEnabled) {
        return sendJsonRpc({
          jsonrpc: "2.0",
          id,
          result: { isError: true, content: [{ type: "text", text: "PAYWALL_MILITARY_REQUIRED: Military Contour requires a Pro or Military key (https://shuliak.dev/#pricing)." }] }
        });
      }
      if (!licenseInfo.valid) {
        const basicRes = omni.baseScanner.scanText(String(args.text || ""));
        return sendJsonRpc({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify({ tier: "FREE_COMMUNITY", sanitizedText: basicRes.sanitizedText, findingsCount: basicRes.findingsCount }) }] }
        });
      }
      omni.setProfile(reqContour);
      const paidOut = fw.transformStringOutbound(omni.scrubWithProfile(String(args.text || "")).sanitizedText);
      return sendJsonRpc({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: JSON.stringify({ tier: licenseInfo.tier, sanitizedText: paidOut.text, findingsCount: paidOut.findingsCount }) }] }
      });
    }

    if (toolName === "sip1_rehydrate_response") {
      const restored = omni.rehydrateAll(fw.restoreStringInbound(String(args.maskedText || "")));
      return sendJsonRpc({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: restored }] } });
    }

    if (toolName === "sip1_audit_jsonrpc") {
      const audit = fw.interceptJsonRpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { raw: String(args.payload || "") } });
      return sendJsonRpc({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify({ allowed: audit.allowed, quarantined: audit.quarantined, threats: audit.threats }) }] } });
    }

    return sendJsonRpc({ jsonrpc: "2.0", id, error: { code: -32601, message: "Tool not found: " + toolName } });
  }

  // Mandatory fallback so Glama Inspector never hangs on unknown methods
  return sendJsonRpc({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found: " + String(method) } });
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on("line", (line) => {
  const t = line.trim();
  if (!t) return;
  try { handleRpcMessage(JSON.parse(t)); } catch (e) { sendJsonRpc({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); }
});
