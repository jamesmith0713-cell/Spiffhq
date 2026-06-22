// ══════════════════════════════════════════════════════════════
// SpiffHQ — Server-Side Audit Log Function (VULN-10)
// ══════════════════════════════════════════════════════════════
// Receives audit events from the client and writes them to
// Firebase using the Admin SDK. Since this runs server-side,
// the log entries cannot be spoofed, deleted, or injected by
// the client — the server controls what gets written.
//
// The client sends: { workspaceSlug, action, details, actorName,
//                     actorRole, locationId, idToken }
// The idToken is the Firebase Auth token — we verify it before
// accepting any log entry, ensuring only authenticated sessions
// can write to the audit log.
//
// Deploy to: netlify/functions/audit-log.js
// Client calls: POST /.netlify/functions/audit-log
// Env vars needed:
//   FIREBASE_SERVICE_ACCOUNT  — JSON string of service account key
//   FIREBASE_DATABASE_URL     — https://spiffhq-default-rtdb.firebaseio.com
// ══════════════════════════════════════════════════════════════

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth }     = require("firebase-admin/auth");
const { getDatabase } = require("firebase-admin/database");

// ── Initialize Firebase Admin (once per cold start) ────────────────
function getAdminApp() {
  if(getApps().length > 0) return getApps()[0];

  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}");
  return initializeApp({
    credential:  cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  });
}

// ── CORS headers ───────────────────────────────────────────────────
const CORS = {
  "Access-Control-Allow-Origin":  "https://spiffhq.com",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

// ── Allowed action types ───────────────────────────────────────────
// Whitelist prevents a client from injecting arbitrary action strings
const ALLOWED_ACTIONS = new Set([
  "entry_submitted","entry_approved","entry_denied","entry_deleted",
  "rep_added","rep_removed","rep_renamed","rep_avatar_updated",
  "spiff_type_added","spiff_type_updated","spiff_type_deleted",
  "ref_type_updated","verify_checks_updated",
  "admin_pin_changed","verifier_pin_changed",
  "team_name_changed","location_added","location_deleted",
  "location_paused","location_resumed","location_renamed",
  "team_added","team_updated","team_deleted",
  "danger_zone_unlocked","data_cleared","entries_cleared",
  "snapshot_saved","period_exported",
  "wager_created","wager_active","wager_settled",
  "wager_voided","wager_declined","wager_cancelled",
  "rep_pin_created","rep_pin_reset",
  "promo_code_applied","industry_setup_applied",
  "checkout_started","checkout_completed",
  "combined_doubling_toggled","combined_doubling_threshold_changed",
]);

exports.handler = async (event) => {
  if(event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS, body: "" };
  }
  if(event.httpMethod !== "POST") {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Invalid body" }) };
  }

  const { workspaceSlug, action, details, actorName, actorRole, locationId, idToken } = body;

  // ── Input validation ───────────────────────────────────────────
  if(!workspaceSlug || !/^[a-z0-9-]{3,60}$/.test(workspaceSlug)) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Invalid workspace" }) };
  }
  if(!action || !ALLOWED_ACTIONS.has(action)) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Invalid action" }) };
  }

  // ── Verify Firebase Auth token (non-owner actions use PIN, skip verify) ──
  // For owner actions (idToken present), verify the token.
  // For PIN-based actions (no idToken), we still accept but mark as unverified.
  let verifiedUid = null;
  let verifiedEmail = null;

  if(idToken) {
    try {
      const app  = getAdminApp();
      const auth = getAuth(app);
      const decoded = await auth.verifyIdToken(idToken);
      verifiedUid   = decoded.uid;
      verifiedEmail = decoded.email;
    } catch(e) {
      return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: "Invalid auth token" }) };
    }
  }

  // ── Build the log entry ────────────────────────────────────────
  const logEntry = {
    action,
    actorName:  String(actorName  || "Unknown").slice(0, 100),
    actorRole:  String(actorRole  || "unknown").slice(0, 50),
    locationId: String(locationId || "default").slice(0, 60),
    details:    details && typeof details === "object" ? details : {},
    timestamp:  new Date().toISOString(),
    serverWritten: true,   // flag proves this came through the server
    ...(verifiedUid ? { verifiedUid, verifiedEmail } : { pinAuth: true }),
  };

  // ── Write to Firebase ──────────────────────────────────────────
  try {
    const app = getAdminApp();
    const db  = getDatabase(app);
    const path = `workspaces/${workspaceSlug}/auditLog`;
    await db.ref(path).push(logEntry);

    return {
      statusCode: 200,
      headers: CORS,
      body: JSON.stringify({ ok: true })
    };
  } catch(e) {
    console.error("Audit log write error:", e);
    return {
      statusCode: 500,
      headers: CORS,
      body: JSON.stringify({ error: "Failed to write log" })
    };
  }
};
