import type { VercelResponse } from "@vercel/node";

/**
 * Sets Content Security Policy headers according to Privy's recommendations
 * @see https://docs.privy.io/security/implementation-guide/content-security-policy
 *
 * @param res - VercelResponse object
 * @param options - Optional configuration for additional domains
 */
export function setCSPHeaders(
  res: VercelResponse,
  options?: {
    /**
     * Additional domains to add to connect-src (e.g., your API domain)
     */
    additionalConnectSrc?: string[];
    /**
     * Additional domains to add to script-src
     */
    additionalScriptSrc?: string[];
    /**
     * Additional domains to add to style-src
     */
    additionalStyleSrc?: string[];
    /**
     * Additional domains to add to img-src
     */
    additionalImgSrc?: string[];
    /**
     * Additional domains to add to font-src
     */
    additionalFontSrc?: string[];
    /**
     * Use report-only mode (Content-Security-Policy-Report-Only)
     */
    reportOnly?: boolean;
    /**
     * Report URI for CSP violations
     */
    reportUri?: string;
  }
) {
  const {
    additionalConnectSrc = [],
    additionalScriptSrc = [],
    additionalStyleSrc = [],
    additionalImgSrc = [],
    additionalFontSrc = [],
    reportOnly = false,
    reportUri,
  } = options || {};

  // Base CSP configuration according to Privy documentation
  const directives: string[] = [
    "default-src 'self'",
    `script-src 'self' https://challenges.cloudflare.com${
      additionalScriptSrc.length ? " " + additionalScriptSrc.join(" ") : ""
    }`,
    `style-src 'self' 'unsafe-inline'${
      additionalStyleSrc.length ? " " + additionalStyleSrc.join(" ") : ""
    }`,
    `img-src 'self' data: blob:${
      additionalImgSrc.length ? " " + additionalImgSrc.join(" ") : ""
    }`,
    `font-src 'self'${
      additionalFontSrc.length ? " " + additionalFontSrc.join(" ") : ""
    }`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "child-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org",
    "frame-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org https://challenges.cloudflare.com",
    `connect-src 'self' https://auth.privy.io wss://relay.walletconnect.com wss://relay.walletconnect.org wss://www.walletlink.org https://*.rpc.privy.systems https://explorer-api.walletconnect.com${
      additionalConnectSrc.length ? " " + additionalConnectSrc.join(" ") : ""
    }`,
    "worker-src 'self'",
    "manifest-src 'self'",
  ];

  // Add report-uri if provided
  if (reportUri) {
    directives.push(`report-uri ${reportUri}`);
  }

  const cspHeader = directives.join("; ");

  // Set the appropriate CSP header
  const headerName = reportOnly
    ? "Content-Security-Policy-Report-Only"
    : "Content-Security-Policy";

  res.setHeader(headerName, cspHeader);
}
