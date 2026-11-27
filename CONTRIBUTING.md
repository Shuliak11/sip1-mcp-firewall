# Contributing to SHULIAK SIP-1

1. Fork https://github.com/Shuliak11/sip1-mcp-firewall
   and install Node.js >= 20 (pure ESM, 0 runtime deps).
2. Run the full **251/251** verification suite (0 outbound
   sockets, 9/9 NIST FF1 CAVP, RFC 8785 JCS, RFC 9162
   Merkle, and OWASP MCP guards) via npm test.
3. Keep src/ strictly free of external dependencies and
   network module imports (node:net, node:http, fetch).
4. Review ./CLA.md (Apache-2.0) and open a Pull Request
   referencing DOI: 10.5281/zenodo.24159380 and
   draft-shuliak-sip-zero-egress-00.
