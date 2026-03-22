/**
 * Business Logic testing tools.
 *
 * Tests price manipulation, coupon abuse, and other logic flaws.
 * Based on PortSwigger Business Logic labs.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCmd, requireTool } from "../runner.js";

export function register(server: McpServer): void {
  server.tool(
    "price_manipulation_test",
    "Test client-side price manipulation by sending modified price values.\n\nSends price=0, price=1, price=-1, and negative quantity variants to check if the server validates prices server-side.\n\nReturns: {\"results\": [{\"test_case\": str, \"payload\": str, \"status\": int, \"length\": int, \"accepted\": bool, \"snippet\": str}]}.\n\nSide effects: May add items to cart or create orders at manipulated prices.",
    {
      url: z
        .string()
        .describe("URL that processes the purchase/cart action"),
      price_param: z
        .string()
        .describe(
          "Parameter name for the price, e.g. 'price', 'amount', 'total'"
        ),
      cart_endpoint: z
        .string()
        .optional()
        .describe(
          "Separate cart/checkout endpoint to verify final price after manipulation"
        ),
      extra_params: z
        .string()
        .optional()
        .describe(
          "Additional form parameters, e.g. 'productId=1&quantity=1'"
        ),
      auth_cookie: z
        .string()
        .optional()
        .describe("Session cookie for authenticated requests"),
      content_type: z
        .string()
        .describe("Request content type: 'form' or 'json'")
        .optional(),
    },
    async ({
      url,
      price_param,
      cart_endpoint,
      extra_params,
      auth_cookie,
      content_type = "form",
    }) => {
      requireTool("curl");

      const testCases: Array<[string, Record<string, string>]> = [
        ["zero_price", { [price_param]: "0" }],
        ["one_cent", { [price_param]: "0.01" }],
        ["one_unit", { [price_param]: "1" }],
        ["negative_price", { [price_param]: "-100" }],
        ["large_negative", { [price_param]: "-99999" }],
        ["string_value", { [price_param]: "free" }],
      ];

      // If there's a quantity parameter embedded in extra_params, also test negative quantity
      if (extra_params && extra_params.includes("quantity")) {
        testCases.push([
          "negative_quantity",
          { [price_param]: "100", quantity: "-16" },
        ]);
      }

      const results: Array<{
        test_case: string;
        payload: Record<string, string>;
        status: number;
        length: number;
        accepted: boolean;
        response_snippet: string;
      }> = [];

      for (const [testName, params] of testCases) {
        let curlArgs: string[];

        if (content_type === "json") {
          let baseParams: Record<string, string> = {};
          if (extra_params) {
            // Parse extra_params as key=value pairs
            for (const pair of extra_params.split("&")) {
              if (pair.includes("=")) {
                const eqIdx = pair.indexOf("=");
                const k = pair.slice(0, eqIdx);
                const v = pair.slice(eqIdx + 1);
                baseParams[k] = v;
              }
            }
          }
          Object.assign(baseParams, params);
          const data = JSON.stringify(baseParams);

          curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            data,
          ];
        } else {
          const formParts: string[] = [];
          if (extra_params) {
            formParts.push(extra_params);
          }
          for (const [k, v] of Object.entries(params)) {
            formParts.push(`${k}=${v}`);
          }
          const formData = formParts.join("&");

          curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-X",
            "POST",
            "-d",
            formData,
          ];
        }

        if (auth_cookie) {
          curlArgs.push("-b", auth_cookie);
        }
        curlArgs.push(url);

        const res = await runCmd("curl", curlArgs);
        let body = res.stdout;
        const metaMarker = body.lastIndexOf("__META__");
        let status = 0;
        let length = 0;
        if (metaMarker !== -1) {
          const meta = body.slice(metaMarker + 8).trim();
          const parts = meta.split(":");
          status = parts[0] ? parseInt(parts[0], 10) : 0;
          length = parts[1] ? parseInt(parts[1], 10) : 0;
          body = body.slice(0, metaMarker);
        }

        // Accepted if not an error status
        const accepted = [200, 201, 301, 302, 303].includes(status);
        results.push({
          test_case: testName,
          payload: params,
          status,
          length,
          accepted,
          response_snippet: body.slice(0, 500),
        });
      }

      // Optionally check the cart to see if manipulated prices stuck
      let cartResult: string | null = null;
      if (cart_endpoint) {
        const cartArgs = [
          "-sk",
          "-o",
          "-",
          "-w",
          "\n__META__%{http_code}:%{size_download}",
        ];
        if (auth_cookie) {
          cartArgs.push("-b", auth_cookie);
        }
        cartArgs.push(cart_endpoint);

        const cartRes = await runCmd("curl", cartArgs);
        let cartBody = cartRes.stdout;
        const metaMarker = cartBody.lastIndexOf("__META__");
        if (metaMarker !== -1) {
          cartBody = cartBody.slice(0, metaMarker);
        }
        cartResult = cartBody.slice(0, 1000);
      }

      const acceptedCount = results.filter((r) => r.accepted).length;
      const result = {
        results,
        accepted_count: acceptedCount,
        cart_contents: cartResult,
        hint:
          acceptedCount > 0
            ? `${acceptedCount} manipulated price(s) accepted. Check cart for final totals.`
            : "All manipulated prices rejected. Server-side validation appears intact.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );

  server.tool(
    "coupon_abuse_test",
    "Test coupon stacking and alternation bypass.\n\nTests each coupon individually, then alternates between coupons to see if discounts compound past the intended limit.\n\nReturns: {\"individual_results\": [...], \"stacking_results\": [...], \"stacking_possible\": bool}.\n\nSide effects: Applies coupons to the cart. May modify cart totals.",
    {
      url: z
        .string()
        .describe("Coupon application endpoint URL"),
      coupon_endpoint: z
        .string()
        .describe(
          "Full URL for applying coupons, e.g. https://target/cart/coupon"
        ),
      coupons: z
        .array(z.string())
        .min(1)
        .max(20)
        .describe(
          "Coupon codes to test, e.g. ['NEWCUST5', 'SIGNUP30', 'FREESHIP']"
        ),
      coupon_param: z
        .string()
        .describe("Form parameter name for the coupon code")
        .optional(),
      auth_cookie: z
        .string()
        .optional()
        .describe("Session cookie for authenticated requests"),
      stacking_rounds: z
        .number()
        .min(1)
        .max(20)
        .describe(
          "Number of alternation rounds to test for coupon stacking"
        )
        .optional(),
    },
    async ({
      url,
      coupon_endpoint,
      coupons,
      coupon_param = "coupon",
      auth_cookie,
      stacking_rounds = 5,
    }) => {
      requireTool("curl");

      // Phase 1: Test each coupon individually
      const individualResults: Array<{
        coupon: string;
        status: number;
        length: number;
        accepted: boolean;
        response_snippet: string;
      }> = [];

      for (const coupon of coupons) {
        const curlArgs = [
          "-sk",
          "-o",
          "-",
          "-w",
          "\n__META__%{http_code}:%{size_download}",
          "-X",
          "POST",
          "-d",
          `${coupon_param}=${coupon}`,
        ];
        if (auth_cookie) {
          curlArgs.push("-b", auth_cookie);
        }
        curlArgs.push(coupon_endpoint);

        const res = await runCmd("curl", curlArgs);
        let body = res.stdout;
        const metaMarker = body.lastIndexOf("__META__");
        let status = 0;
        let length = 0;
        if (metaMarker !== -1) {
          const meta = body.slice(metaMarker + 8).trim();
          const parts = meta.split(":");
          status = parts[0] ? parseInt(parts[0], 10) : 0;
          length = parts[1] ? parseInt(parts[1], 10) : 0;
          body = body.slice(0, metaMarker);
        }

        individualResults.push({
          coupon,
          status,
          length,
          accepted: [200, 201, 302].includes(status),
          response_snippet: body.slice(0, 300),
        });
      }

      const validCoupons = individualResults
        .filter((r) => r.accepted)
        .map((r) => r.coupon);

      // Phase 2: Test coupon alternation/stacking
      const stackingResults: Array<{
        round: number;
        coupon: string;
        status: number;
        accepted: boolean;
        response_snippet: string;
      }> = [];

      if (validCoupons.length >= 2) {
        for (let roundNum = 0; roundNum < stacking_rounds; roundNum++) {
          const coupon = validCoupons[roundNum % validCoupons.length];
          const curlArgs = [
            "-sk",
            "-o",
            "-",
            "-w",
            "\n__META__%{http_code}:%{size_download}",
            "-X",
            "POST",
            "-d",
            `${coupon_param}=${coupon}`,
          ];
          if (auth_cookie) {
            curlArgs.push("-b", auth_cookie);
          }
          curlArgs.push(coupon_endpoint);

          const res = await runCmd("curl", curlArgs);
          let body = res.stdout;
          const metaMarker = body.lastIndexOf("__META__");
          let status = 0;
          if (metaMarker !== -1) {
            const meta = body.slice(metaMarker + 8).trim();
            const parts = meta.split(":");
            status = parts[0] ? parseInt(parts[0], 10) : 0;
            body = body.slice(0, metaMarker);
          }

          stackingResults.push({
            round: roundNum + 1,
            coupon,
            status,
            accepted: [200, 201, 302].includes(status),
            response_snippet: body.slice(0, 300),
          });
        }
      }

      // Determine if stacking worked
      const stackingAccepted = stackingResults.filter((r) => r.accepted).length;
      const stackingPossible = stackingAccepted > validCoupons.length;

      // Check cart total after stacking
      let cartCheck: string | null = null;
      if (auth_cookie) {
        const cartArgs = [
          "-sk",
          "-o",
          "-",
          "-w",
          "\n__META__%{http_code}:%{size_download}",
          "-b",
          auth_cookie,
          url,
        ];
        const cartRes = await runCmd("curl", cartArgs);
        let cartBody = cartRes.stdout;
        const metaMarker = cartBody.lastIndexOf("__META__");
        if (metaMarker !== -1) {
          cartBody = cartBody.slice(0, metaMarker);
        }
        cartCheck = cartBody.slice(0, 1000);
      }

      const result = {
        individual_results: individualResults,
        valid_coupons: validCoupons,
        stacking_results: stackingResults,
        stacking_accepted_count: stackingAccepted,
        stacking_possible: stackingPossible,
        cart_after_stacking: cartCheck,
        hint: stackingPossible
          ? "Coupon stacking/alternation bypass detected! Discounts compounded beyond intended limit."
          : "Coupon stacking blocked. Server enforces single-use correctly.",
      };

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );
}
