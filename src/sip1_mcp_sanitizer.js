// MODULE 5: OWASP MCP TOP 10 & CROSS-OS SANITIZER v2.5
"use strict";

const ZW_RX = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u{E0000}-\u{E007F}]/gu;
const PATH_RX = /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\/etc\/passwd|\/etc\/shadow|c:\\windows|appdata\\roaming|~\/\.ssh|~\/\.aws|\.kube\/config|\.env\b|claude_desktop_config\.json)/i;
const CMD_RX = /(?:;\s*(?:rm|curl|wget|bash|sh|nc|python|node|powershell|cmd\.exe)\b|\|\s*(?:bash|sh|nc|powershell)\b|`[^`]+`|\$\([^)]+\))/i;
const INJ_RX = /(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s+prompt\s+override|exfiltrate\s+(?:all\s+)?(?:data|context|keys)|<\/?tool_call>)/i;

function sanitizeZeroWidthUnicode(text) {
  const s = String(text || "").normalize("NFC");
  const m = s.match(ZW_RX);
  if (!m) return { cleanText: s, strippedCount: 0, detected: false };
  return { cleanText: s.replace(ZW_RX, ""), strippedCount: m.length, detected: true };
}

function inspectMcpJsonRpcPayload(payload) {
  const raw = typeof payload === "string" ? payload : JSON.stringify(payload || {});
  let dec = raw;
  try { dec = decodeURIComponent(raw); } catch (e) {}
  const zw = sanitizeZeroWidthUnicode(raw);
  const threats = [];
  if (zw.detected) threats.push({ code: "OWASP_MCP06_ZERO_WIDTH", severity: "CRITICAL" });
  if (PATH_RX.test(zw.cleanText) || PATH_RX.test(dec)) threats.push({ code: "OWASP_MCP05_PATH_TRAVERSAL", severity: "CRITICAL" });
  if (CMD_RX.test(zw.cleanText)) threats.push({ code: "OWASP_MCP05_COMMAND_INJECTION", severity: "CRITICAL" });
  if (INJ_RX.test(zw.cleanText)) threats.push({ code: "OWASP_MCP03_MCP06_PROMPT_POISONING", severity: "HIGH" });
  if (raw.includes("\"__proto__\"") || raw.includes("\"constructor\"")) threats.push({ code: "CRITICAL_PROTOTYPE_POLLUTION", severity: "CRITICAL" });
  return { safe: threats.length === 0, threats, sanitizedRaw: zw.cleanText };
}

module.exports = {
  sanitizeZeroWidthUnicode,
  inspectMcpJsonRpcPayload,
  scanMcpJsonRpc: inspectMcpJsonRpcPayload,
  sanitizeMcpPayload: inspectMcpJsonRpcPayload
};
