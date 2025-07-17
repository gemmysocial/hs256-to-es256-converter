import type { VercelRequest, VercelResponse } from "@vercel/node";

async function getJwks() {
  // Return the specific JWKS
  const jwks = {
    keys: [
      {
        kty: "EC",
        kid: process.env.ES256_KEY_ID || "default-key",
        d: "Aqrw7SeRNkaO8RywNJeMK58Tx7sOtdRhOwbVHapU8ms",
        crv: "P-256",
        x: "V703uuUvJ_RqSVPOoi0dJkirCJIej_OwMUDky2p7c2U",
        y: "vh04EoNSrbaGhZTFMBRn7KR_2W-E3peGz3AkIPpH5og",
      },
    ],
  };

  return jwks;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  // Handle preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const jwks = await getJwks();

    // Set appropriate headers for JWKS
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "public, max-age=3600"); // Cache for 1 hour

    return res.status(200).json(jwks);
  } catch (err) {
    console.error("JWKS error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}
