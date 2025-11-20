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

// Token cache: maps DID -> { token, expiresAt, windowStart }
const tokenCache = new Map<
  string,
  { token: string; expiresAt: number; windowStart: number }
>();

// Use 1-hour time windows for deterministic token generation
// All requests within the same hour window get the same token
const TOKEN_WINDOW_SECONDS = 3600; // 1 hour

// Get the start of the current time window
function getCurrentWindowStart(): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.floor(now / TOKEN_WINDOW_SECONDS) * TOKEN_WINDOW_SECONDS;
}

// Check if a cached token is still valid for the current window
function isTokenValid(cached: {
  expiresAt: number;
  windowStart: number;
}): boolean {
  const currentWindow = getCurrentWindowStart();
  // Token is valid if it's from the current window and hasn't expired
  return (
    cached.windowStart === currentWindow && cached.expiresAt > Date.now() / 1000
  );
}

async function issueEs256Jwt(userDid: string) {
  const { SignJWT, importPKCS8 } = await import("jose");

  const currentWindow = getCurrentWindowStart();

  // Check cache first
  const cached = tokenCache.get(userDid);
  if (cached && isTokenValid(cached)) {
    return cached.token;
  }

  // Generate new token with deterministic iat based on current window
  const privateKey = await importPKCS8(
    process.env.ES256_PRIVATE_KEY!.replace(/\\n/g, "\n"),
    "ES256"
  );

  const token = await new SignJWT({ sub: userDid })
    .setProtectedHeader({
      alg: "ES256",
      kid: process.env.ES256_KEY_ID || "default-key",
    })
    .setIssuedAt(currentWindow) // Use window start as iat for determinism
    .setExpirationTime("1h")
    .sign(privateKey);

  const expiresAt = currentWindow + TOKEN_WINDOW_SECONDS;

  // Cache the token
  tokenCache.set(userDid, { token, expiresAt, windowStart: currentWindow });

  return token;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
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
