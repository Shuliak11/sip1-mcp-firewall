# @shuliak-corp/sip1-mcp — SHULIAK SIP-1 v2.6 Zero-Egress AI & MCP Firewall

[![CERN Zenodo DOI](https://img.shields.io/badge/CERN_Zenodo_DOI-10.5281%2Fzenodo.24159380-0A66C2)](https://doi.org/10.5281/zenodo.24159380)
[![npm version](https://img.shields.io/npm/v/@shuliak-corp/sip1-mcp.svg)](https://www.npmjs.com/package/@shuliak-corp/sip1-mcp)
[![NIST CAVP](https://img.shields.io/badge/NIST_SP_800--38G_FF1-9%2F9_CAVP_Vectors_Verified-emerald)](https://github.com/Shuliak11/sip1-mcp-firewall)

**Author:** Dmitrii Shuliak (Founder & Chief Systems Architect, **SHULIAK CORP**)
**Monograph & ARM64 Benchmark (CERN Zenodo):** [https://doi.org/10.5281/zenodo.24159380](https://doi.org/10.5281/zenodo.24159380)
**Enterprise Portal, Live Sandbox & License Keys:** [https://shuliak.dev](https://shuliak.dev)

## Key Capabilities
- **9/9 Official NIST SP 800-38G Rev. 1 (FF1) CAVP Test Vectors Verified:** Bit-exact BigInt 10-round Feistel network with stateless Luhn Mod-10 & ISO/IEC 7064 IBAN bijections.
- **Dual-Mode MCP Architecture:** Standalone MCP security server (`npx -y @shuliak-corp/sip1-mcp`) or transparent downstream stdio proxy (`--wrap <cmd>`).
- **OWASP MCP Top 10 Quarantine & EU AI Act CycloneDX AIBOM:** Blocks path traversal, command injection, prototype pollution, and covert zero-width Unicode smuggled prompts.

## Quickstart
```bash
npx -y @shuliak-corp/sip1-mcp --version
npm test
```
