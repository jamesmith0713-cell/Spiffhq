// ══════════════════════════════════════════════════════════════
// SpiffHQ — Promo Code Validation Function (VULN-03)
// ══════════════════════════════════════════════════════════════
// Validates promo codes server-side so the codes never appear
// in the client bundle. The client sends the code + workspace slug;
// this function returns whether the code is valid without exposing
// the full code list to the browser.
//
// Deploy to: netlify/functions/validate-promo.js
// Client calls: POST /.netlify/functions/validate-promo
// ══════════════════════════════════════════════════════════════

// ── Promo codes ────────────────────────────────────────────────────
// These live ONLY here — not in app.html, not in GitHub commits.
// Add new codes here and redeploy. Rotate old ones by removing them.
//
// IMPORTANT: After deploying this function, remove PROMO_CODES from
// app.html entirely and rotate these three codes to new values since
// the old ones were exposed in the client source.
const PROMO_CODES = {
  // Format: "CODE": { label, bypass, expiresAt (optional ISO string) }
  "SAPENTER100":  { label: "Sapenter Internal",  bypass: true  },
  "FOUNDER2026":  { label: "Founder Access",      bypass: true  },
  "SPIFFLAUNCH":  { label: "Launch Promo",         bypass: true  },
  // Add new codes below — deploy to activate, remove to deactivate
};

// ── CORS helper ────────────────────────────────────────────────────
const CORS_HEADERS = {
  "Access-Control-Allow-Origin":  "https://spiffhq.com",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

exports.handler = async (event) => {
  // Handle CORS preflight
  if(event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS_HEADERS, body: "" };
  }

  if(event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: "Method not allowed" })
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return {
      statusCode: 400,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: "Invalid request body" })
    };
  }

  const code = (body.code || "").trim().toUpperCase();
  const slug = (body.slug || "").trim();

  // Basic input validation
  if(!code || code.length > 30) {
    return {
      statusCode: 400,
      headers: CORS_HEADERS,
      body: JSON.stringify({ valid: false, error: "Invalid code format" })
    };
  }

  const match = PROMO_CODES[code];

  if(!match) {
    // Don't reveal which specific codes exist — just say invalid
    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: JSON.stringify({ valid: false })
    };
  }

  // Check expiry if set
  if(match.expiresAt && new Date(match.expiresAt) < new Date()) {
    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: JSON.stringify({ valid: false, expired: true })
    };
  }

  // Valid code — return grant without exposing the full code list
  return {
    statusCode: 200,
    headers: CORS_HEADERS,
    body: JSON.stringify({
      valid:   true,
      bypass:  match.bypass || false,
      label:   match.label,
    })
  };
};
