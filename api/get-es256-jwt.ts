import type { VercelRequest, VercelResponse } from "@vercel/node";
//import { SignJWT, importPKCS8 } from "jose";

async function issueEs256Jwt(userDid: string) {
  const { SignJWT, importPKCS8 } = await import("jose");

  const privateKey = await importPKCS8(
    process.env.ES256_PRIVATE_KEY!.replace(/\\n/g, "\n"),
    "ES256"
  );

  return await new SignJWT({ sub: userDid })
    .setProtectedHeader({ alg: "ES256" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // ✅ Always set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
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
    const { did } = body.did || {};

    if (!did) {
      return res.status(400).json({ error: "Missing DID" });
    }

    const token = await issueEs256Jwt(did);
    return res.status(200).json({ token });
  } catch (err) {
    console.error("JWT issuing error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}
