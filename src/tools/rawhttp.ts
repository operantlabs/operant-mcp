/**
 * Raw HTTP/H2 tools for sending hand-crafted requests.
 *
 * Bypasses standard HTTP libraries to enable smuggling, CRLF injection,
 * and connection reuse attacks via raw TLS sockets and Python h2.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runShell } from "../runner.js";
import { randomUUID } from "node:crypto";
import { writeFile, readFile, unlink } from "node:fs/promises";

export function register(server: McpServer): void {
  server.tool(
    "raw_http_send",
    "Send raw bytes over a TLS socket to a target host. Bypasses HTTP library normalization — useful for smuggling, CRLF injection, malformed requests. Returns the first 4096 bytes of the raw response.",
    {
      target_host: z.string().describe("Target hostname, e.g. example.com"),
      target_port: z.number().default(443).describe("Target port (default 443)"),
      raw_request: z.string().describe("The literal HTTP request bytes to send (use \\r\\n for CRLF)"),
    },
    async ({ target_host, target_port, raw_request }) => {
      const scriptId = randomUUID().slice(0, 8);
      const scriptPath = `/tmp/rawhttp-${scriptId}.py`;

      const pyScript = `
import ssl, socket, sys

host = ${JSON.stringify(target_host)}
port = ${target_port}
raw = ${JSON.stringify(raw_request)}.encode().decode('unicode_escape').encode('latin-1')

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = socket.create_connection((host, port), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.sendall(raw)

response = b""
try:
    while True:
        chunk = ssock.recv(4096)
        if not chunk:
            break
        response += chunk
        if len(response) >= 4096:
            break
except socket.timeout:
    pass
finally:
    ssock.close()

sys.stdout.buffer.write(response[:4096])
`;

      await writeFile(scriptPath, pyScript);

      try {
        const res = await runShell(`python3 ${scriptPath}`, { timeout: 20 });
        const result = {
          target: `${target_host}:${target_port}`,
          response_bytes: res.stdout.slice(0, 4096),
          stderr: res.stderr || undefined,
          success: res.success,
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } finally {
        await unlink(scriptPath).catch(() => {});
      }
    }
  );

  server.tool(
    "raw_h2_smuggle",
    "HTTP/2 request smuggling via Python h2 library with header validation disabled. Allows CRLF in header values and appending smuggled HTTP/1.1 requests in the body. Returns all responses received.",
    {
      target_url: z.string().describe("Target URL, e.g. https://example.com"),
      method: z.string().default("GET").describe("HTTP method"),
      headers: z.array(z.array(z.string()).length(2))
        .describe("Array of [name, value] pairs — CRLF allowed in values for smuggling"),
      body: z.string().optional().describe("Request body"),
      smuggled_request: z.string().optional()
        .describe("Optional complete HTTP/1.1 request to append after body for CL.0 / H2.CL smuggling"),
    },
    async ({ target_url, method, headers, body, smuggled_request }) => {
      const scriptId = randomUUID().slice(0, 8);
      const scriptPath = `/tmp/h2smuggle-${scriptId}.py`;
      const parsed = new URL(target_url);
      const host = parsed.hostname;
      const port = parsed.port ? parseInt(parsed.port, 10) : 443;
      const path = parsed.pathname + parsed.search;

      const fullBody = (body ?? "") + (smuggled_request ?? "");

      const pyScript = `
import ssl, socket, sys, json
import h2.connection
import h2.config
import h2.events

host = ${JSON.stringify(host)}
port = ${port}
method = ${JSON.stringify(method)}
path = ${JSON.stringify(path)}
req_headers = ${JSON.stringify(headers)}
req_body = ${JSON.stringify(fullBody)}.encode()

config = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
config.validate_outbound_headers = False
config.normalize_outbound_headers = False

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2'])

sock = socket.create_connection((host, port), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)

conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
ssock.sendall(conn.data_to_send())

h2_headers = [
    (':method', method),
    (':path', path),
    (':authority', host),
    (':scheme', 'https'),
] + [(n, v) for n, v in req_headers]

stream_id = conn.get_next_available_stream_id()
conn.send_headers(stream_id, h2_headers, end_stream=(not req_body))
ssock.sendall(conn.data_to_send())

if req_body:
    conn.send_data(stream_id, req_body, end_stream=True)
    ssock.sendall(conn.data_to_send())

responses = []
done = False
while not done:
    data = ssock.recv(65535)
    if not data:
        break
    events = conn.receive_data(data)
    for event in events:
        if isinstance(event, h2.events.ResponseReceived):
            resp = {'headers': [(n.decode() if isinstance(n, bytes) else n, v.decode() if isinstance(v, bytes) else v) for n, v in event.headers]}
            responses.append(resp)
        elif isinstance(event, h2.events.DataReceived):
            if responses:
                body_str = event.data.decode('utf-8', errors='replace')
                responses[-1]['body'] = responses[-1].get('body', '') + body_str
            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        elif isinstance(event, h2.events.StreamEnded):
            done = True
        elif isinstance(event, h2.events.StreamReset):
            done = True
    ssock.sendall(conn.data_to_send())

ssock.close()
print(json.dumps(responses, indent=2))
`;

      await writeFile(scriptPath, pyScript);

      try {
        const res = await runShell(`python3 ${scriptPath}`, { timeout: 20 });
        let responses: any[] = [];
        try {
          responses = JSON.parse(res.stdout);
        } catch {
          responses = [{ raw: res.stdout }];
        }

        const result = {
          target: target_url,
          method,
          smuggled: !!smuggled_request,
          responses,
          stderr: res.stderr || undefined,
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } finally {
        await unlink(scriptPath).catch(() => {});
      }
    }
  );

  server.tool(
    "raw_connection_reuse",
    "Send multiple raw HTTP requests on a single TLS connection. Useful for testing connection-level attacks like request smuggling, pipeline confusion, and socket poisoning.",
    {
      target_host: z.string().describe("Target hostname"),
      target_port: z.number().default(443).describe("Target port (default 443)"),
      requests: z.array(z.string()).describe("Array of raw HTTP request strings to send sequentially on one connection"),
    },
    async ({ target_host, target_port, requests }) => {
      const scriptId = randomUUID().slice(0, 8);
      const scriptPath = `/tmp/rawreuse-${scriptId}.py`;

      const pyScript = `
import ssl, socket, sys, json, time

host = ${JSON.stringify(target_host)}
port = ${target_port}
requests = ${JSON.stringify(requests)}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = socket.create_connection((host, port), timeout=15)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.settimeout(5)

responses = []
for i, req in enumerate(requests):
    raw = req.encode().decode('unicode_escape').encode('latin-1')
    ssock.sendall(raw)
    time.sleep(0.1)

    response = b""
    try:
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Simple heuristic: if we got headers + some body, move on
            if b"\\r\\n\\r\\n" in response:
                # Check Content-Length or just grab what we have
                time.sleep(0.2)
                try:
                    more = ssock.recv(4096)
                    if more:
                        response += more
                except socket.timeout:
                    pass
                break
    except socket.timeout:
        pass

    responses.append({
        'request_index': i,
        'response': response[:4096].decode('utf-8', errors='replace'),
        'response_length': len(response),
    })

ssock.close()
print(json.dumps(responses, indent=2))
`;

      await writeFile(scriptPath, pyScript);

      try {
        const res = await runShell(`python3 ${scriptPath}`, { timeout: 30 });
        let responses: any[] = [];
        try {
          responses = JSON.parse(res.stdout);
        } catch {
          responses = [{ raw: res.stdout }];
        }

        const result = {
          target: `${target_host}:${target_port}`,
          requests_sent: requests.length,
          responses,
          stderr: res.stderr || undefined,
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } finally {
        await unlink(scriptPath).catch(() => {});
      }
    }
  );
}
