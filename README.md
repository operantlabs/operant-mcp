# operant-mcp

[![NPM Version](https://img.shields.io/npm/v/operant-mcp?color=red)](https://www.npmjs.com/package/operant-mcp) [![npm downloads](https://img.shields.io/npm/dw/operant-mcp)](https://www.npmjs.com/package/operant-mcp) [![GitHub stars](https://img.shields.io/github/stars/operantlabs/operant-mcp?style=social)](https://github.com/operantlabs/operant-mcp) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/) ![MCP Server](https://badge.mcpx.dev?type=server&features=tools,prompts 'MCP Server with Tools and Prompts') [![smithery badge](https://smithery.ai/badge/operant-mcp)](https://smithery.ai/server/operant-mcp)

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=operant-mcp&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIm9wZXJhbnQtbWNwIl19) [![Install in Cursor](https://img.shields.io/badge/Cursor-Install_Server-000000?style=flat-square&logo=cursor&logoColor=white)](https://cursor.com/en/install-mcp?name=operant-mcp&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIm9wZXJhbnQtbWNwIl19)

<a href="https://glama.ai/mcp/servers/operantlabs/operant-mcp">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/operantlabs/operant-mcp/badge" alt="operant-mcp MCP server" />
</a>

Security testing MCP server with 51 tools for penetration testing, network forensics, memory analysis, and vulnerability assessment.

## Quick Start

```bash
npx operant-mcp
```

Or install globally:

```bash
npm install -g operant-mcp
operant-mcp
```

## Usage with Claude Code

Add to your MCP config:

```json
{
  "mcpServers": {
    "operant": {
      "command": "npx",
      "args": ["-y", "operant-mcp"]
    }
  }
}
```

## Tools (51)

### SQL Injection (6)
- `sqli_where_bypass` — Test OR-based WHERE clause bypass
- `sqli_login_bypass` — Test login form SQL injection
- `sqli_union_extract` — UNION-based data extraction
- `sqli_blind_boolean` — Boolean-based blind SQLi
- `sqli_blind_time` — Time-based blind SQLi
- `sqli_file_read` — Read files via LOAD_FILE()

### XSS (2)
- `xss_reflected_test` — Test reflected XSS with 10 payloads
- `xss_payload_generate` — Generate context-aware XSS payloads

### Command Injection (2)
- `cmdi_test` — Test OS command injection
- `cmdi_blind_detect` — Blind command injection via sleep timing

### Path Traversal (1)
- `path_traversal_test` — Test directory traversal with encoding variants

### SSRF (2)
- `ssrf_test` — Test SSRF with localhost bypass variants
- `ssrf_cloud_metadata` — Test cloud metadata access via SSRF

### PCAP/Network Forensics (8)
- `pcap_overview` — Protocol hierarchy and endpoint stats
- `pcap_extract_credentials` — Extract FTP/HTTP/SMTP credentials
- `pcap_dns_analysis` — DNS query analysis
- `pcap_http_objects` — Export HTTP objects
- `pcap_detect_scan` — Detect port scanning
- `pcap_follow_stream` — Follow TCP/UDP streams
- `pcap_tls_analysis` — TLS/SNI analysis
- `pcap_llmnr_ntlm` — Detect LLMNR/NTLM attacks

### Reconnaissance (7)
- `recon_quick` — Quick recon (robots.txt, headers, common dirs)
- `recon_dns` — Full DNS enumeration
- `recon_vhost` — Virtual host discovery
- `recon_tls_sans` — Extract SANs from TLS certificates
- `recon_directory_bruteforce` — Directory brute-force
- `recon_git_secrets` — Search git repos for secrets
- `recon_s3_bucket` — Test S3 bucket permissions

### Memory Forensics (3)
- `volatility_linux` — Linux memory analysis (Volatility 2)
- `volatility_windows` — Windows memory analysis (Volatility 3)
- `memory_detect_rootkit` — Linux rootkit detection

### Malware Analysis (2)
- `maldoc_analyze` — Full OLE document analysis pipeline
- `maldoc_extract_macros` — Extract VBA macros

### Cloud Security (2)
- `cloudtrail_analyze` — CloudTrail log analysis
- `cloudtrail_find_anomalies` — Detect anomalous CloudTrail events

### Authentication (3)
- `auth_csrf_extract` — Extract CSRF tokens
- `auth_bruteforce` — Username enumeration + credential brute-force
- `auth_cookie_tamper` — Cookie tampering test

### Access Control (2)
- `idor_test` — Test for IDOR vulnerabilities
- `role_escalation_test` — Test privilege escalation

### Business Logic (2)
- `price_manipulation_test` — Test price/quantity manipulation
- `coupon_abuse_test` — Test coupon stacking/reuse

### Clickjacking (2)
- `clickjacking_test` — Test X-Frame-Options/CSP
- `frame_buster_bypass` — Test frame-busting bypass

### CORS (1)
- `cors_test` — Test CORS misconfigurations

### File Upload (1)
- `file_upload_test` — Test file upload bypasses

### NoSQL Injection (2)
- `nosqli_auth_bypass` — MongoDB auth bypass
- `nosqli_detect` — NoSQL injection detection

### Deserialization (1)
- `deserialization_test` — Test insecure deserialization

### GraphQL (2)
- `graphql_introspect` — Full schema introspection
- `graphql_find_hidden` — Discover hidden fields

## Prompts (8)

Methodology guides for structured security assessments:

- `web_app_pentest` — Full web app pentest methodology
- `pcap_forensics` — PCAP analysis workflow
- `memory_forensics` — Memory dump analysis (Linux/Windows)
- `recon_methodology` — Reconnaissance checklist
- `malware_analysis` — Malware document analysis
- `cloud_security_audit` — CloudTrail analysis workflow
- `sqli_methodology` — SQL injection testing guide
- `xss_methodology` — XSS testing guide

## System Requirements

Tools require various CLI utilities depending on the module:

- **Most tools**: `curl`
- **PCAP analysis**: `tshark` (Wireshark CLI)
- **DNS recon**: `dig`, `host`
- **Memory forensics**: `volatility` / `vol.py` / `vol3`
- **Malware analysis**: `olevba`, `oledump.py`
- **Cloud analysis**: `jq`
- **Secrets scanning**: `git`

## License

MIT
