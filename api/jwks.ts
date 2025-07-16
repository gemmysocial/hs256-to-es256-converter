import type { VercelRequest, VercelResponse } from "@vercel/node";

async function getJwks() {
  const { importPKCS8, exportSPKI } = await import("jose");

  // Import the private key
  const privateKey = await importPKCS8(
    process.env.ES256_PRIVATE_KEY!.replace(/\\n/g, "\n"),
    "ES256"
  );

  // Export the public key in SPKI format first
  const spkiPublicKey = await exportSPKI(privateKey);

  // Import the SPKI public key to get an extractable key
  const { importSPKI, exportJWK } = await import("jose");
  const extractablePublicKey = await importSPKI(spkiPublicKey, "ES256");

  // Now export as JWK
  const publicKey = await exportJWK(extractablePublicKey);

  // Create the JWKS response
  const jwks = {
    keys: [
      {
        kty: publicKey.kty,
        use: "sig",
        crv: publicKey.crv,
        kid: process.env.ES256_KEY_ID || "default-key",
        x: publicKey.x,
        y: publicKey.y,
        alg: "ES256",
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
