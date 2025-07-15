import type { VercelRequest, VercelResponse } from "@vercel/node";
import { SignJWT, importPKCS8 } from "jose";

async function issueEs256Jwt(userDid: string) {
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
  res.setHeader("Access-Control-Allow-Origin", "*"); // or specify 'http://localhost:19006'
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    // CORS preflight request
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { did } = req.body || {};
  if (!did) {
    return res.status(400).json({ error: "Missing DID" });
  }

  try {
    const token = await issueEs256Jwt(did);
    return res.status(200).json({ token });
  } catch (err) {
    console.error("JWT issuing error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}
