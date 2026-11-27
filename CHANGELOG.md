# Changelog

## [3.1.0] - 2026-11-25 (Gold Master)

- **Zero-Egress Local Engine:** Pure Node.js >= 20 ESM,
  0 runtime dependencies, 0 outbound sockets, **251/251**
  automated security & cryptographic checks passing.
- **NIST SP 800-38G Rev. 1 FF1 Twins:** 9/9 official CAVP
  vectors + 10,000-iteration fuzzing across Luhn PAN,
  ISO 7064 MOD-97 IBAN, ISO VIN, and ICAO 9303 MRZ with
  domain-separated tweaks and two-phase slot isolation.
- **Protocol & Runtime Hardening:** RFC 8785 JCS pinning
  (0x06), RFC 9162 Merkle inclusion/consistency proofs
  (0x0B prove), two-phase IFC bus, AST SQL/shell/SSRF
  guard, orphan process reaper, and shield --apply.
- **Zero-Dep Office & Clinical Bridge:** In-RAM scrubbing
  for .docx, .xlsx, .odt, .pdf, HL7 v2, and FHIR R4 with
  8 MCP tools and 4 desktop prompts.
- **Distribution & Provenance:** Published to npm with
  OIDC SLSA v1 provenance, Official MCP Registry, and
  4 standalone .mcpb v0.3 desktop bundles (SHA256SUMS).
