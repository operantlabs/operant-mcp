/**
 * GraphQL testing tools.
 *
 * Introspection queries and hidden field discovery for GraphQL APIs.
 * Based on PortSwigger GraphQL labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "graphql_introspect",
    "Run introspection query to enumerate all types, fields, and mutations. Sends the standard GraphQL introspection query (__schema) to discover the full API schema including hidden/undocumented fields, mutations, and types. Returns: {introspection_enabled, types: [{name, kind, fields: [str]}], mutations: [str], queries: [str]}. Side effects: Single POST request. Read-only.",
    {
      url: z
        .string()
        .describe(
          "GraphQL endpoint URL, e.g. https://target/graphql or https://target/api"
        ),
      auth_header: z
        .string()
        .optional()
        .describe(
          "Authorization header value, e.g. 'Bearer abc123'"
        ),
      auth_cookie: z
        .string()
        .optional()
        .describe("Session cookie for authenticated requests"),
    },
    async ({ url, auth_header, auth_cookie }) => {
      requireTool("curl");

      const introspectionQuery = {
        query: `
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types {
                            name
                            kind
                            fields {
                                name
                                type {
                                    name
                                    kind
                                    ofType { name kind }
                                }
                                args {
                                    name
                                    type { name kind }
                                }
                            }
                        }
                    }
                }
            `,
      };

      const curlArgs: string[] = [
        "-sk",
        "-o",
        "-",
        "-w",
        "\n__META__%{http_code}",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-d",
        JSON.stringify(introspectionQuery),
      ];

      if (auth_header) {
        curlArgs.push("-H", `Authorization: ${auth_header}`);
      }
      if (auth_cookie) {
        curlArgs.push("-b", auth_cookie);
      }
      curlArgs.push(url);

      const res = await runCmd("curl", curlArgs);
      let body = res.stdout;
      const metaMarker = body.lastIndexOf("__META__");
      let status = 0;
      if (metaMarker !== -1) {
        try {
          status = parseInt(body.slice(metaMarker + 8).trim(), 10) || 0;
        } catch {
          // ignore
        }
        body = body.slice(0, metaMarker);
      }

      // Parse the introspection result
      let data: Record<string, unknown>;
      try {
        data = JSON.parse(body);
      } catch {
        const result = {
          introspection_enabled: false,
          status,
          error: "Failed to parse response as JSON",
          response_snippet: body.slice(0, 1000),
          hint: "Introspection may be disabled. Try alternative endpoints: /graphql, /api/graphql, /v1/graphql",
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      const schema = (
        (data.data as Record<string, unknown> | undefined) ?? {}
      ).__schema as Record<string, unknown> | undefined;

      if (!schema) {
        // Check if there's an error message
        const errors = (data.errors as Array<Record<string, unknown>> | undefined) ?? [];
        const result = {
          introspection_enabled: false,
          status,
          errors: errors
            .slice(0, 5)
            .map((e) => (e.message as string) || ""),
          response_snippet: body.slice(0, 1000),
          hint: "Introspection may be disabled. Try field suggestion brute-force instead.",
        };
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // Extract types (filter out internal __ types)
      const typesList: Array<{
        name: string;
        kind: string;
        fields?: Array<{ name: string; type: string; args: string[] }>;
      }> = [];

      const rawTypes = (schema.types as Array<Record<string, unknown>>) ?? [];
      for (const t of rawTypes) {
        const typeName = t.name as string;
        if (typeName.startsWith("__")) continue;

        const typeInfo: {
          name: string;
          kind: string;
          fields?: Array<{ name: string; type: string; args: string[] }>;
        } = {
          name: typeName,
          kind: t.kind as string,
        };

        if (t.fields) {
          const rawFields = t.fields as Array<Record<string, unknown>>;
          typeInfo.fields = rawFields.map((f) => {
            const fType = f.type as Record<string, unknown> | undefined;
            const ofType = (fType?.ofType as Record<string, unknown> | undefined) ?? {};
            const typeName =
              (fType?.name as string | undefined) ||
              (ofType?.name as string | undefined) ||
              "";
            const rawArgs = (f.args as Array<Record<string, unknown>>) ?? [];
            return {
              name: f.name as string,
              type: typeName,
              args: rawArgs.map((a) => a.name as string),
            };
          });
        }

        typesList.push(typeInfo);
      }

      // Extract query and mutation names
      const queryTypeName =
        ((schema.queryType as Record<string, unknown> | undefined)?.name as string) ||
        "Query";
      const mutationTypeName =
        ((schema.mutationType as Record<string, unknown> | undefined)?.name as string) ||
        "Mutation";

      let queries: string[] = [];
      let mutations: string[] = [];
      for (const t of typesList) {
        if (t.name === queryTypeName && t.fields) {
          queries = t.fields.map((f) => f.name);
        } else if (t.name === mutationTypeName && t.fields) {
          mutations = t.fields.map((f) => f.name);
        }
      }

      const result = {
        introspection_enabled: true,
        status,
        type_count: typesList.length,
        types: typesList,
        queries,
        mutations,
        hint: `Found ${typesList.length} types, ${queries.length} queries, ${mutations.length} mutations. Look for sensitive fields (password, secret, token, admin, private).`,
      };

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  server.tool(
    "graphql_find_hidden",
    "Find hidden/undocumented fields on a GraphQL type using field suggestion errors. Sends queries with intentionally misspelled field names to trigger GraphQL's field suggestion feature, which reveals valid field names. Also tries common sensitive field names directly. Returns: {discovered_fields: [str], suggestion_results: [...], direct_probe_results: [...]}. Side effects: Read-only POST requests. Sends ~25 requests.",
    {
      url: z.string().describe("GraphQL endpoint URL"),
      type_name: z
        .string()
        .describe(
          "GraphQL type to probe for hidden fields, e.g. 'User', 'Post', 'BlogPost'"
        ),
      known_field: z
        .string()
        .describe(
          "A known field on this type to use in queries, e.g. 'id' or 'title'"
        )
        .default("id"),
      query_name: z
        .string()
        .optional()
        .describe(
          "Query name to use for fetching objects, e.g. 'getUser' or 'getBlogPost'"
        ),
      query_arg: z
        .string()
        .optional()
        .describe("Query argument, e.g. 'id: 1' or 'slug: \"test\"'"),
      auth_header: z
        .string()
        .optional()
        .describe("Authorization header value"),
      auth_cookie: z.string().optional().describe("Session cookie"),
    },
    async ({
      url,
      type_name,
      known_field,
      query_name,
      query_arg,
      auth_header,
      auth_cookie,
    }) => {
      requireTool("curl");

      const queryGraphql = async (
        graphqlQuery: string
      ): Promise<Record<string, unknown>> => {
        const curlArgs: string[] = [
          "-sk",
          "-o",
          "-",
          "-w",
          "\n__META__%{http_code}",
          "-X",
          "POST",
          "-H",
          "Content-Type: application/json",
          "-d",
          JSON.stringify({ query: graphqlQuery }),
        ];
        if (auth_header) {
          curlArgs.push("-H", `Authorization: ${auth_header}`);
        }
        if (auth_cookie) {
          curlArgs.push("-b", auth_cookie);
        }
        curlArgs.push(url);

        const res = await runCmd("curl", curlArgs);
        let body = res.stdout;
        const metaMarker = body.lastIndexOf("__META__");
        if (metaMarker !== -1) {
          body = body.slice(0, metaMarker);
        }
        try {
          return JSON.parse(body) as Record<string, unknown>;
        } catch {
          return { raw: body.slice(0, 500) };
        }
      };

      // Build the query prefix
      let queryPrefix: string;
      if (query_name && query_arg) {
        queryPrefix = `${query_name}(${query_arg})`;
      } else if (query_name) {
        queryPrefix = query_name;
      } else {
        // Guess common query patterns
        queryPrefix = type_name[0].toLowerCase() + type_name.slice(1);
      }

      // Phase 1: Try misspelled fields to trigger suggestions
      const probePrefixes = [
        "passwor",    // triggers: password
        "secre",      // triggers: secret
        "toke",       // triggers: token
        "admi",       // triggers: admin
        "emai",       // triggers: email
        "phon",       // triggers: phone
        "priva",      // triggers: private
        "hidde",      // triggers: hidden
        "intern",     // triggers: internal
        "creat",      // triggers: createdAt, createdBy
        "updat",      // triggers: updatedAt
        "delet",      // triggers: deleted, deletedAt
        "rol",        // triggers: role
        "permissio",  // triggers: permission
      ];

      const suggestionResults: Array<{
        probe: string;
        suggestions: string[];
      }> = [];
      const discoveredFromSuggestions = new Set<string>();

      for (const probe of probePrefixes) {
        const query = `{ ${queryPrefix} { ${known_field} ${probe} } }`;
        const result = await queryGraphql(query);

        const errors = (result.errors as Array<Record<string, unknown>> | undefined) ?? [];
        const suggestions: string[] = [];
        for (const error of errors) {
          const msg = (error.message as string) || "";
          // Parse suggestions like: Did you mean "password"?
          const found = msg.match(/"([^"]+)"/g) ?? [];
          for (const f of found) {
            const fieldName = f.replace(/"/g, "");
            if (fieldName !== probe && fieldName !== known_field) {
              suggestions.push(fieldName);
              discoveredFromSuggestions.add(fieldName);
            }
          }
        }

        if (suggestions.length > 0) {
          suggestionResults.push({ probe, suggestions });
        }
      }

      // Phase 2: Direct probe common sensitive field names
      const sensitiveFields = [
        "password", "passwordHash", "secret", "secretKey",
        "token", "apiKey", "apiToken", "accessToken", "refreshToken",
        "admin", "isAdmin", "role", "roles", "permissions",
        "email", "phone", "ssn", "creditCard",
        "privateKey", "privateField", "hidden", "internal",
        "deletedAt", "createdBy", "updatedBy",
        "postPassword", "hash", "salt",
      ];

      const directResults: Array<Record<string, unknown>> = [];
      const discoveredDirect = new Set<string>();

      for (const field of sensitiveFields) {
        const query = `{ ${queryPrefix} { ${known_field} ${field} } }`;
        const result = await queryGraphql(query);

        const errors = (result.errors as Array<Record<string, unknown>> | undefined) ?? [];
        const data = result.data;

        if (data && errors.length === 0) {
          // Field exists and returned data
          discoveredDirect.add(field);
          directResults.push({
            field,
            exists: true,
            data_returned: true,
            value_snippet: String(data).slice(0, 200),
          });
        } else if (errors.length > 0) {
          // Check if error is "cannot query field" (doesn't exist) vs auth error
          const errorMsg = ((errors[0].message as string) || "").toLowerCase();
          if (
            errorMsg.includes("cannot query field") ||
            errorMsg.includes("unknown field")
          ) {
            // Field doesn't exist — skip
          } else if (
            errorMsg.includes("not authorized") ||
            errorMsg.includes("forbidden")
          ) {
            discoveredDirect.add(field);
            directResults.push({
              field,
              exists: true,
              data_returned: false,
              note: "Field exists but access denied",
            });
          }
        }
      }

      const allDiscovered = Array.from(
        new Set([...discoveredFromSuggestions, ...discoveredDirect])
      ).sort();

      const result = {
        type_name,
        discovered_fields: allDiscovered,
        suggestion_results: suggestionResults,
        direct_probe_results: directResults,
        hint:
          allDiscovered.length > 0
            ? `Found ${allDiscovered.length} hidden/sensitive fields: ${JSON.stringify(allDiscovered)}`
            : "No hidden fields discovered. Type may have minimal fields or suggestions are disabled.",
      };

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
  );
}
