import type { VercelRequest, VercelResponse } from "@vercel/node";

async function getJwks() {
  const crypto = await import("crypto");

  // Parse the private key PEM
  const privateKeyPem = process.env.ES256_PRIVATE_KEY!.replace(/\\n/g, "\n");

  // Create a key object from the private key
  const privateKeyObj = crypto.createPrivateKey({
    key: privateKeyPem,
    format: "pem",
  });

  // Extract the public key from the private key
  const publicKeyObj = crypto.createPublicKey(privateKeyObj);

  // Export the public key in DER format
  const publicKeyDer = publicKeyObj.export({ format: "der", type: "spki" });

  // For ES256 (P-256), the public key is 65 bytes: 1 byte prefix + 32 bytes x + 32 bytes y
  // The first byte is 0x04 (uncompressed point)
  const x = publicKeyDer.slice(27, 59); // x coordinate (32 bytes)
  const y = publicKeyDer.slice(59, 91); // y coordinate (32 bytes)

  // Convert to base64url encoding
  const xBase64Url = x.toString("base64url");
  const yBase64Url = y.toString("base64url");

  // Create the JWKS response
  const jwks = {
    keys: [
      {
        kty: "EC",
        use: "sig",
        crv: "P-256",
        kid: process.env.ES256_KEY_ID || "default-key",
        x: xBase64Url,
        y: yBase64Url,
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
