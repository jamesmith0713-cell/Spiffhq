// ══════════════════════════════════════════════════════════════
// SpiffHQ — Stripe Webhook Handler
// ══════════════════════════════════════════════════════════════
// Receives checkout.session.completed events from Stripe after
// a successful payment. Verifies the Stripe signature, reads the
// workspace slug from client_reference_id, and writes the plan
// to Firebase via Admin SDK.
//
// This is the SECURE path for plan activation — the client-side
// checkStripeReturn() is a convenience fallback only.
//
// Deploy to: netlify/functions/stripe-webhook.js
//
// Env vars needed:
//   STRIPE_SECRET_KEY        — sk_test_... or sk_live_...
//   STRIPE_WEBHOOK_SECRET    — whsec_... (from Stripe Dashboard → Webhooks)
//   FIREBASE_SERVICE_ACCOUNT — Firebase Admin SDK JSON
//   FIREBASE_DATABASE_URL    — https://spiffhq-default-rtdb.firebaseio.com
//
// Stripe webhook setup:
//   Dashboard → Developers → Webhooks → Add endpoint
//   URL: https://spiffhq.com/.netlify/functions/stripe-webhook
//   Events: checkout.session.completed, customer.subscription.deleted
// ══════════════════════════════════════════════════════════════

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");

// ── Initialize Firebase Admin (once per cold start) ────────────
function getAdminApp() {
  if(getApps().length > 0) return getApps()[0];
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}");
  return initializeApp({
    credential:  cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  });
}

// ── Map Stripe price IDs to SpiffHQ plan keys ──────────────────
// Add your actual Stripe Price IDs here after creating products.
// Find them in Stripe Dashboard → Products → [product] → Pricing.
// Format: "price_xxx": "starter" or "price_xxx": "pro"
const PRICE_TO_PLAN = {
  // Test mode price IDs — replace with live IDs before going live
  // "price_test_xxx": "starter",
  // "price_test_yyy": "pro",
};

// ── CORS / response helpers ────────────────────────────────────
const ok  = (body = "ok") => ({ statusCode: 200, body: JSON.stringify({ ok: true, body }) });
const err = (msg, code = 400) => ({ statusCode: code, body: JSON.stringify({ error: msg }) });

exports.handler = async (event) => {
  // Stripe sends raw body — must read it as-is for signature verification
  const sig     = event.headers["stripe-signature"];
  const secret  = process.env.STRIPE_WEBHOOK_SECRET;
  const rawBody = event.body;

  if(!sig || !secret) {
    console.error("Missing stripe-signature header or STRIPE_WEBHOOK_SECRET env var");
    return err("Webhook not configured", 500);
  }

  // ── Verify Stripe signature ────────────────────────────────────
  let stripeEvent;
  try {
    stripeEvent = stripe.webhooks.constructEvent(rawBody, sig, secret);
  } catch(e) {
    console.error("Webhook signature verification failed:", e.message);
    return err(`Webhook signature verification failed: ${e.message}`, 400);
  }

  console.log(`Stripe event: ${stripeEvent.type}`);

  // ── Handle checkout.session.completed ─────────────────────────
  if(stripeEvent.type === "checkout.session.completed") {
    const session = stripeEvent.data.object;

    // client_reference_id is set by startCheckout() in the app:
    // link.searchParams.set("client_reference_id", workspaceSlug)
    const workspaceSlug = session.client_reference_id;
    const customerEmail = session.customer_details?.email || session.customer_email;

    if(!workspaceSlug) {
      console.error("No client_reference_id on session — can't map to workspace");
      // Return 200 so Stripe doesn't retry — this is a data issue, not a server error
      return ok("No workspace slug — skipped");
    }

    // Determine plan from line items or amount
    // First try to match via price ID from subscription
    let planKey = null;

    if(session.subscription) {
      // Subscription checkout — retrieve line items to get price ID
      try {
        const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
        const priceId = lineItems.data[0]?.price?.id;
        if(priceId && PRICE_TO_PLAN[priceId]) {
          planKey = PRICE_TO_PLAN[priceId];
        }
      } catch(e) {
        console.error("Failed to retrieve line items:", e.message);
      }
    }

    // Fallback: determine plan from amount if price ID map isn't set up yet
    if(!planKey) {
      const amount = session.amount_total; // in cents
      if(amount <= 1900)       planKey = "starter"; // $19 or less
      else if(amount <= 4900)  planKey = "pro";     // $49 or less
      else                     planKey = "pro";     // anything higher → pro
    }

    // ── Write plan to Firebase ───────────────────────────────────
    try {
      const app = getAdminApp();
      const db  = getDatabase(app);
      const metaRef = db.ref(`workspaces/${workspaceSlug}/meta`);

      await metaRef.update({
        plan:               planKey,
        stripeCustomerId:   session.customer || null,
        stripeSessionId:    session.id,
        planActivatedAt:    new Date().toISOString(),
        planActivatedEmail: customerEmail || null,
      });

      console.log(`✅ Plan ${planKey} activated for workspace: ${workspaceSlug}`);
      return ok(`Plan ${planKey} activated for ${workspaceSlug}`);

    } catch(e) {
      console.error("Firebase write failed:", e.message);
      return err("Firebase write failed", 500);
    }
  }

  // ── Handle subscription cancellation ──────────────────────────
  if(stripeEvent.type === "customer.subscription.deleted") {
    const subscription = stripeEvent.data.object;
    const customerId = subscription.customer;

    // Find the workspace with this Stripe customer ID and downgrade to free
    try {
      const app = getAdminApp();
      const db  = getDatabase(app);

      // Search for workspace with this customer ID
      const workspacesRef = db.ref("workspaces");
      const snapshot = await workspacesRef
        .orderByChild("meta/stripeCustomerId")
        .equalTo(customerId)
        .once("value");

      if(snapshot.exists()) {
        const updates = {};
        snapshot.forEach(child => {
          updates[`${child.key}/meta/plan`] = "free";
          updates[`${child.key}/meta/planCancelledAt`] = new Date().toISOString();
        });
        await workspacesRef.update(updates);
        console.log(`✅ Subscription cancelled — downgraded workspace for customer: ${customerId}`);
      } else {
        console.log(`No workspace found for Stripe customer: ${customerId}`);
      }

      return ok("Subscription cancellation handled");
    } catch(e) {
      console.error("Cancellation handling failed:", e.message);
      return err("Cancellation handling failed", 500);
    }
  }

  // All other events — acknowledge receipt, no action needed
  return ok(`Event ${stripeEvent.type} received — no action needed`);
};
