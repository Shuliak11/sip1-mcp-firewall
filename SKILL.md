---
name: sip1-mcp-firewall
description: >-
  Audit AI IDE MCP configs, scrub PAN/IBAN/PHI via NIST
  SP 800-38G FF1 in RAM, block destructive SQL or shell
  calls via AST, and read DOCX/XLSX/PDF/HL7/FHIR files
  with zero outbound sockets.
license: Apache-2.0
compatibility: Node.js >= 20, 0 runtime deps, 0 sockets
metadata:
  author: SHULIAK CORP
  version: "3.1.0"
  homepage: https://shuliak.dev
---

# SHULIAK SIP-1 Zero-Egress MCP Firewall Skill

## 1. Local AI IDE Security Audit (0 Sockets, 0 Sign-Up)

```bash
npx -y @shuliak-corp/sip1-mcp@3.1.0 audit
```

Detects plaintext secrets (SIP-R01), unpinned packages
(SIP-R02), dangerous flags (SIP-R03), and missing
RFC 8785 schema locks (SIP-R04) across 12+ AI IDEs.

## 2. Reversible STDIO Firewall Wrapping

```bash
npx -y @shuliak-corp/sip1-mcp@3.1.0 shield --apply
npx -y @shuliak-corp/sip1-mcp@3.1.0 shield --rollback
```

## 3. MCP Tools Exposed (serve Mode)

- sip_audit_workspace: Static 12-client MCP risk audit.
- sip_classify_action_guard: SQL/shell/SSRF AST guard.
- sip_pseudonymize_payload: NIST FF1 Luhn/IBAN twins.
- sip_read_protected_file: In-RAM DOCX/XLSX/PDF/HL7/FHIR.
- sip_save_restored_document: Atomic twin restoration.
- sip_zero_egress_selftest: 9/9 CAVP & 0-socket proof.
