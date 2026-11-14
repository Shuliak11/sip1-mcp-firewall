# SHULIAK SIP-1 Documentation & Interface Reference

## 1. Installation & Quickstart
Run directly via Node.js (>=20) with zero external dependencies:
`npx -y @shuliak-corp/sip1-mcp --version`
Or wrap any downstream local MCP server over stdio:
`npx -y @shuliak-corp/sip1-mcp --wrap npx -y @modelcontextprotocol/server-filesystem /workspace`

## 2. External JSON-RPC 2.0 Interface (Inputs & Outputs)
- `sip1_scrub_payload({ text, contour })` -> Returns sanitized text with stateless NIST SP 800-38G FF1 twins.
- `sip1_rehydrate_response({ maskedText })` -> Restores original plaintext values in local memory.
- `sip1_audit_jsonrpc({ payload })` -> Quarantines OWASP MCP05/06 path traversal, command injection, and Unicode smuggling.
- `sip1_generate_aibom({ organization })` -> Outputs SHA-256 CycloneDX AIBOM JSON for EU AI Act & GDPR Art. 4(5).
- `sip1_license_status({ licenseKey })` -> Verifies offline Ed25519 license signatures.

## 3. Secure Usage Guidelines
Keep Ed25519 license tokens in environment variable `SIP1_LICENSE_KEY`. Never commit raw keys to public repositories.
Full specification: https://doi.org/10.5281/zenodo.24159380 | Portal: https://shuliak.dev/docs.html
