# @shuliak-corp/sip1-mcp -- SHULIAK SIP-1 v3.1.0 Zero-Egress AI & MCP Firewall

[![CERN Zenodo DOI](https://img.shields.io/badge/CERN_Zenodo_DOI-10.5281%2Fzenodo.24159380-0A66C2)](https://doi.org/10.5281/zenodo.24159380)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16690/badge)](https://www.bestpractices.dev/en/projects/16690)
[![npm version](https://img.shields.io/npm/v/@shuliak-corp/sip1-mcp.svg)](https://www.npmjs.com/package/@shuliak-corp/sip1-mcp)
[![NIST CAVP](https://img.shields.io/badge/NIST_SP_800--38G_FF1-9%2F9_CAVP_Verified-059669)](https://shuliak.dev)

**Zero-egress local JSON-RPC 2.0 STDIO firewall** built in pure Node.js >=20 ESM with **0 runtime dependencies**, **0 outbound network sockets**, and **251/251 deterministic OpenSSL & Red-Team tests passing**.

- **Portal, Live Sandbox & Offline Verifier:** [https://shuliak.dev](https://shuliak.dev)
- **IETF Internet-Draft:** [draft-shuliak-sip-zero-egress](https://datatracker.ietf.org/doc/draft-shuliak-sip-zero-egress/)
- **CERN Zenodo Monograph:** [https://doi.org/10.5281/zenodo.24159380](https://doi.org/10.5281/zenodo.24159380)
- **Elsevier SSRN #7704879:** [Paper](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=7704879)
- **Author ORCID:** [0009-0005-1272-0368](https://orcid.org/0009-0005-1272-0368) | **X:** [@Shuliak_dev](https://x.com/Shuliak_dev)

<!-- mcp-name: io.github.Shuliak11/sip1-mcp-firewall -->

## Gold Master v3.1.0 Capabilities

- **9/9 NIST SP 800-38G Rev. 1 (FF1) CAVP:** Bit-exact 10-round Feistel twins for PAN (Visa, MC, Amex, Discover 6011, Mir, Diners), ISO-7064 IBAN (radix-10 & radix-36 cycle-walk), ISO VIN, and ICAO 9303 MRZ passports with two-phase slot isolation.
- **Office & Clinical Bridge (`serve`):** Native `node:zlib` zero-dep parser for `.docx`, `.xlsx`, `.odt`, `.pdf`, `HL7 v2` (`PID|`), `FHIR R4`, CSV, Markdown, and JSONL with header co-reference (`PATIENT_01`, `PARTY_A`/`PARTY_B`) and Excel DDE formula neutralization.
- **Comment-Safe Auto-Shield (`shield --apply` / `--rollback`):** Byte-offset JSONC/TOML patcher preserving 100% of comments across 12 local AI clients (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, GitHub Copilot, OpenAI Codex TOML, Devin, Cline, Roo Code, Gemini CLI, Zed).
- **IFC Trifecta Bus & Blast-Radius Guard:** Blocks destructive SQL/shell/IAM ops (`SIP-W01..W03`), enforces `0x07` Ed25519 one-shot warrants, session spend cap (`SIP-F01`), 4-call retry halt (`SIP-F02`), and `>100 KiB` spill guard (`SIP-F03`).
- **RFC 9162 Merkle Proofs & MDM Fleet:** `prove` generates signed `0x0B` inclusion `PATH` and consistency `PROOF` bundles; `mdm-export` / `fleet-verify` deploy macOS `.mobileconfig` and Windows Intune policies up to 250 seats.

## 1-Click Claude Desktop Bundles (`.mcpb` v0.3)

- [Enterprise All-Sectors](https://github.com/Shuliak11/sip1-mcp-firewall/releases/download/v3.1.0/sip1-enterprise-all-3.1.0.mcpb)
- [Healthcare HIPAA Safe Harbor](https://github.com/Shuliak11/sip1-mcp-firewall/releases/download/v3.1.0/sip1-hipaa-clinical-3.1.0.mcpb)
- [Legal & Tax IRS Sec. 7216](https://github.com/Shuliak11/sip1-mcp-firewall/releases/download/v3.1.0/sip1-legal-tax-3.1.0.mcpb)
- [FinTech PCI DSS & DORA](https://github.com/Shuliak11/sip1-mcp-firewall/releases/download/v3.1.0/sip1-pci-dora-3.1.0.mcpb)

## Quickstart (macOS, Windows & Linux)

```bash
# 1. Audit 12 local AI IDE configs offline (0 sockets)
npx -y @shuliak-corp/sip1-mcp@3.1.0 audit

# 2. Run 3-second local firewall demo
npx -y @shuliak-corp/sip1-mcp@3.1.0 demo

# 3. Wrap IDE configs safely (reversible)
npx -y @shuliak-corp/sip1-mcp@3.1.0 shield --apply

# 4. Export signed preview PDF & RFC 9162 proof
npx -y @shuliak-corp/sip1-mcp@3.1.0 attest --preview
npx -y @shuliak-corp/sip1-mcp@3.1.0 prove --seq 1
```

## Offline Licensing & Verification

Community Open-Core is **Apache-2.0**. Commercial workstation keys (`SIP_LICENSE_KEY`) are offline Ed25519 tokens anchored to Sovereign Root Public Key `AZ9wSMieP72MvUUTcxHaCE0ssL0eLXENyRgKRvPV7Qg`:

```bash
npx -y @shuliak-corp/sip1-mcp@3.1.0 activate --key "<TOKEN>"
```

Verify certificates offline at [https://shuliak.dev/verify](https://shuliak.dev/verify). Contributions require [CLA.md](./CLA.md). Automated COTS software only (non-CPA, non-QSA, non-HIPAA BA).
