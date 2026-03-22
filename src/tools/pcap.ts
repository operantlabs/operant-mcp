/**
 * PCAP Forensics tools.
 *
 * Wraps tshark commands for protocol analysis, credential extraction,
 * DNS analysis, HTTP object export, scan detection, stream following,
 * TLS analysis, and LLMNR/NTLM extraction.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, runShell, requireTool, parseLines } from "../runner.js";
import * as fs from "node:fs";
import * as path from "node:path";

export function register(server: McpServer): void {
  function validatePcap(pcapPath: string): string {
    const abspath = path.resolve(pcapPath);
    if (!fs.existsSync(abspath) || !fs.statSync(abspath).isFile()) {
      throw new Error(`PCAP file not found: ${abspath}`);
    }
    return abspath;
  }

  server.tool(
    "pcap_overview",
    "Get protocol hierarchy and endpoint statistics from a PCAP. Returns protocol_hierarchy, endpoints, packet_count, and capture_info. Read-only file analysis, no network access.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
    },
    async ({ pcap_path }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);

      const phs = await runCmd("tshark", ["-r", pcap, "-q", "-z", "io,phs"]);
      const endpoints = await runCmd("tshark", ["-r", pcap, "-q", "-z", "endpoints,ip"]);
      const count = await runShell(`tshark -r '${pcap}' | wc -l`);
      const capinfos = await runShell(`capinfos -u '${pcap}' 2>/dev/null || echo 'capinfos not available'`);

      const countStr = count.stdout.trim();
      const packetCount = /^\d+$/.test(countStr) ? parseInt(countStr, 10) : 0;

      const result = {
        protocol_hierarchy: phs.stdout.slice(0, 3000),
        endpoints: endpoints.stdout.slice(0, 3000),
        packet_count: packetCount,
        capture_info: capinfos.stdout.slice(0, 1000),
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "pcap_extract_credentials",
    "Extract credentials from FTP, HTTP, and SMTP traffic. Returns ftp_credentials, http_authorization_headers, http_post_data, and smtp_data. Read-only, may contain sensitive credentials.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
      protocol: z
        .enum(["ftp", "http", "smtp", "all"])
        .describe("Protocol to extract credentials from")
        .default("all"),
    },
    async ({ pcap_path, protocol }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);

      const results: Record<string, string[]> = {};

      if (protocol === "ftp" || protocol === "all") {
        const ftpRes = await runCmd("tshark", [
          "-r", pcap,
          "-Y", "ftp.request.command == USER || ftp.request.command == PASS",
          "-T", "fields",
          "-e", "ftp.request.command",
          "-e", "ftp.request.arg",
        ]);
        results["ftp_credentials"] = parseLines(ftpRes.stdout);
      }

      if (protocol === "http" || protocol === "all") {
        const httpAuth = await runCmd("tshark", [
          "-r", pcap,
          "-Y", "http.authorization",
          "-T", "fields",
          "-e", "ip.src",
          "-e", "http.request.uri",
          "-e", "http.authorization",
        ]);
        const httpPost = await runCmd("tshark", [
          "-r", pcap,
          "-Y", "http.request.method == POST",
          "-T", "fields",
          "-e", "ip.src",
          "-e", "http.request.uri",
          "-e", "http.file_data",
        ]);
        results["http_authorization_headers"] = parseLines(httpAuth.stdout).slice(0, 50);
        results["http_post_data"] = parseLines(httpPost.stdout).slice(0, 50);
      }

      if (protocol === "smtp" || protocol === "all") {
        const smtpRes = await runShell(
          `tshark -r '${pcap}' -Y 'smtp' -T fields -e smtp.req.parameter 2>/dev/null | head -50`
        );
        results["smtp_data"] = parseLines(smtpRes.stdout);
      }

      return { content: [{ type: "text", text: JSON.stringify(results, null, 2) }] };
    }
  );

  server.tool(
    "pcap_dns_analysis",
    "Extract and analyze DNS queries from a PCAP. Returns dns_queries_by_frequency, dns_servers, and ipv6_dns_endpoints. Read-only file analysis.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
      source_ip: z
        .string()
        .optional()
        .describe("Filter DNS queries from a specific source IP"),
    },
    async ({ pcap_path, source_ip }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);

      let filterExpr = "dns.flags.response == 0";
      if (source_ip) {
        filterExpr += ` && ip.src == ${source_ip}`;
      }

      const queries = await runShell(
        `tshark -r '${pcap}' -Y '${filterExpr}' -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -100`
      );

      const dnsServers = await runShell(
        `tshark -r '${pcap}' -Y 'dns.flags.response == 0' -T fields -e ip.dst 2>/dev/null | sort -u`
      );

      const ipv6Dns = await runShell(
        `tshark -r '${pcap}' -Y 'dns && ipv6' -T fields -e ipv6.dst -e ipv6.src 2>/dev/null | sort -u | head -20`
      );

      const result = {
        dns_queries_by_frequency: queries.stdout.slice(0, 3000),
        dns_servers: parseLines(dnsServers.stdout),
        ipv6_dns_endpoints: parseLines(ipv6Dns.stdout),
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "pcap_http_objects",
    "Export HTTP objects (files) from a PCAP to a directory. Returns exported_count, output_dir, files list, and tshark_output. Creates files in the output directory.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
      output_dir: z.string().describe("Directory to export HTTP objects to"),
    },
    async ({ pcap_path, output_dir }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);
      fs.mkdirSync(output_dir, { recursive: true });

      const res = await runCmd("tshark", [
        "-r", pcap,
        "--export-objects", `http,${output_dir}`,
      ]);

      let files: string[] = [];
      if (fs.existsSync(output_dir) && fs.statSync(output_dir).isDirectory()) {
        files = fs.readdirSync(output_dir);
      }

      const result = {
        exported_count: files.length,
        output_dir,
        files: files.slice(0, 100),
        tshark_output: res.stderr ? res.stderr.slice(0, 500) : "",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "pcap_detect_scan",
    "Detect port scans by analyzing SYN packets without ACK. Returns scanners (ip + syn_count), top_scanned_ports, and a hint. Read-only file analysis.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
    },
    async ({ pcap_path }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);

      const synBySrc = await runShell(
        `tshark -r '${pcap}' -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -20`
      );

      const topPorts = await runShell(
        `tshark -r '${pcap}' -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -30`
      );

      const scanners: Array<{ ip: string; syn_count: number }> = [];
      for (const line of parseLines(synBySrc.stdout)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          scanners.push({ ip: parts[1], syn_count: parseInt(parts[0], 10) });
        }
      }

      const result = {
        scanners,
        top_scanned_ports: parseLines(topPorts.stdout).slice(0, 30),
        hint: "IPs with >100 SYN packets are likely scanning. Check top ports for targeted services.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "pcap_follow_stream",
    "Follow a TCP/UDP/HTTP stream in a PCAP. Returns stream_content, stream_num, and protocol. Read-only file analysis.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
      stream_num: z.number().min(0).describe("TCP stream number to follow"),
      protocol: z
        .enum(["tcp", "udp", "http"])
        .describe("Stream protocol")
        .default("tcp"),
    },
    async ({ pcap_path, stream_num, protocol }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);

      const res = await runCmd("tshark", [
        "-r", pcap,
        "-z", `follow,${protocol},ascii,${stream_num}`,
        "-q",
      ]);

      const result = {
        stream_num,
        protocol,
        stream_content: res.stdout.slice(0, 5000),
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "pcap_tls_analysis",
    "Analyze TLS handshakes, SNI values, and certificate data in a PCAP. Returns sni_values, tls_versions, server_ephemeral_keys, and client_randoms. Read-only file analysis.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
    },
    async ({ pcap_path }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);

      const sni = await runShell(
        `tshark -r '${pcap}' -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u`
      );

      const versions = await runShell(
        `tshark -r '${pcap}' -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.version 2>/dev/null | sort | uniq -c | sort -rn`
      );

      const serverKeys = await runShell(
        `tshark -r '${pcap}' -Y 'tls.handshake.type == 12' -T fields -e tls.handshake.server_point 2>/dev/null | head -5`
      );

      const clientRandoms = await runShell(
        `tshark -r '${pcap}' -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.random 2>/dev/null | head -10`
      );

      const result = {
        sni_values: parseLines(sni.stdout),
        tls_versions: parseLines(versions.stdout),
        server_ephemeral_keys: parseLines(serverKeys.stdout),
        client_randoms: parseLines(clientRandoms.stdout),
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "pcap_llmnr_ntlm",
    "Detect LLMNR poisoning and extract NTLM credentials from SMB. Returns llmnr_queries, ntlm_auth_entries, counts, and poisoning_indicators. Read-only file analysis.",
    {
      pcap_path: z.string().describe("Path to the PCAP file"),
    },
    async ({ pcap_path }) => {
      requireTool("tshark");
      const pcap = validatePcap(pcap_path);

      const llmnr = await runCmd("tshark", [
        "-r", pcap,
        "-Y", "udp.port == 5355",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "llmnr.query_name",
      ]);

      const ntlm = await runCmd("tshark", [
        "-r", pcap,
        "-Y", "ntlmssp.auth",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ntlmssp.auth.username",
        "-e", "ntlmssp.auth.domain",
        "-e", "ntlmssp.auth.hostname",
      ]);

      const llmnrLines = parseLines(llmnr.stdout);
      const ntlmLines = parseLines(ntlm.stdout);

      // Detect poisoning: multiple responders for the same LLMNR query
      const poisoning = llmnrLines.length > 2;

      const result = {
        llmnr_queries: llmnrLines.slice(0, 50),
        ntlm_auth_entries: ntlmLines.slice(0, 50),
        llmnr_count: llmnrLines.length,
        ntlm_count: ntlmLines.length,
        poisoning_indicators: poisoning,
      };

      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );
}
