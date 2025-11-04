import type { VercelRequest, VercelResponse } from "@vercel/node";
import { setCSPHeaders } from "../utils/csp";

// Whitelisted origins
const ALLOWED_ORIGINS = [
  "http://localhost:19006",
  "https://*.gems.xyz",
  "https://*.bsky-app.pages.dev",
  "https://thegems.app",
];

// Check if origin is allowed
function isOriginAllowed(origin: string): boolean {
  return ALLOWED_ORIGINS.some((allowedOrigin) => {
    if (allowedOrigin.includes("*")) {
      // Handle wildcard domains
      const pattern = allowedOrigin.replace("*", ".*");
      const regex = new RegExp(`^${pattern}$`);
      return regex.test(origin);
    }
    return allowedOrigin === origin;
  });
}

//

async function issueEs256Jwt(userDid: string) {
  const { SignJWT, importPKCS8 } = await import("jose");

  const privateKey = await importPKCS8(
    process.env.ES256_PRIVATE_KEY!.replace(/\\n/g, "\n"),
    "ES256"
  );

  return await new SignJWT({ sub: userDid })
    .setProtectedHeader({
      alg: "ES256",
      kid: process.env.ES256_KEY_ID || "default-key",
    })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // ✅ Set CSP headers according to Privy recommendations
  setCSPHeaders(res, {
    additionalConnectSrc: [ALLOWED_ORIGINS.join(" ")],
    additionalScriptSrc: [ALLOWED_ORIGINS.join(" ")],
    additionalStyleSrc: [ALLOWED_ORIGINS.join(" ")],
    additionalImgSrc: [ALLOWED_ORIGINS.join(" ")],
    additionalFontSrc: [ALLOWED_ORIGINS.join(" ")],
    // Add your API domain here if needed
    // additionalConnectSrc: ["https://your-api-domain.com"],
  });

  // ✅ Set CORS headers based on origin
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  // ✅ Handle preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // ✅ Safely parse only on POST
  try {
    // Unlike Next.js, Vercel serverless functions do *not* automatically parse JSON
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    const { did } = body || {};

    if (!did) {
      return res.status(400).json({ error: "Missing DID" });
    }

    const token = await issueEs256Jwt(did);
    return res.status(200).json({ token });
  } catch (err) {
    console.log("err", err);
    console.error("JWT issuing error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}
