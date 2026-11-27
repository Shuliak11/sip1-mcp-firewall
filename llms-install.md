# SHULIAK SIP-1 v3.1.0 -- Autonomous MCP Install

## Zero-Input Agent Instructions (Cline / Claude / Cursor)

- **Zero API Keys Required:** Do NOT ask the user for any
  API key, token, or account. Open-Core (Apache-2.0) runs
  100% locally with 0 runtime dependencies and 0 outbound
  network sockets.
- **Runtime Requirement:** Node.js >= 20 (npx).

## 1. Install MCP STDIO Server (Zero Configuration)

Add the following entry to cline_mcp_settings.json
(or .mcp.json / .cursor/mcp.json) with an empty env:

```json
{
  "mcpServers": {
    "shuliak-sip1": {
      "command": "npx",
      "args": ["-y", "@shuliak-corp/sip1-mcp@3.1.0", "serve"],
      "env": {}
    }
  }
}
```

> Optional: SIP_LICENSE_KEY is only needed later if the
> user activates a commercial offline Ed25519 key. Leave
> env empty during initial installation.

## 2. Verify Installation Automatically

1. Call MCP tools/list -> expects **8 tools**
   (sip_audit_workspace, sip_classify_action_guard,
   sip_pseudonymize_payload, sip_isep_ledger_status,
   sip_zero_egress_selftest, sip_list_sector_packs,
   sip_read_protected_file, sip_save_restored_document).
2. Call MCP prompts/list -> expects **4 prompts**.
3. Optionally call sip_zero_egress_selftest -> expects
   passed: true, socketsOpened: 0, cavpPassed: 9.

## 3. Standalone CLI Commands (Zero Sign-Up)

```bash
# Audit local AI IDE configs (12+ clients, SIP-R01..R04)
npx -y @shuliak-corp/sip1-mcp@3.1.0 audit

# Wrap existing MCP servers with atomic rollback support
npx -y @shuliak-corp/sip1-mcp@3.1.0 shield --apply
npx -y @shuliak-corp/sip1-mcp@3.1.0 shield --rollback

# Run 3-second isolated sandbox showcase
npx -y @shuliak-corp/sip1-mcp@3.1.0 demo
```
