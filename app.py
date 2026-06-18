"""
XA Tweaker — Stripe Webhook Server
Runs on Railway. Handles:
  - POST /webhook        Stripe sends payment events here
  - GET  /check/<discord_id>   App polls this to check subscription status
  - GET  /health         Railway health check
"""

import os
import json
import hmac
import hashlib
import sqlite3
import datetime
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# ── Config (set these as Railway environment variables) ────────────────────────
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")   # whsec_...
API_SECRET_KEY        = os.environ.get("API_SECRET_KEY", "changeme")  # any strong random string
DATABASE_PATH         = os.environ.get("DATABASE_PATH", "subscriptions.db")

# ── Database setup ─────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                discord_id      TEXT PRIMARY KEY,
                discord_username TEXT,
                stripe_customer TEXT,
                stripe_sub_id   TEXT,
                status          TEXT DEFAULT 'active',
                current_period_end INTEGER,
                created_at      TEXT,
                updated_at      TEXT
            )
        """)
        conn.commit()

init_db()

# ── Stripe signature verification ──────────────────────────────────────────────
def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Verify the request actually came from Stripe."""
    try:
        parts = {k: v for k, v in (p.split("=", 1) for p in sig_header.split(","))}
        timestamp = parts.get("t", "")
        signatures = [v for k, v in parts.items() if k == "v1"]

        signed_payload = f"{timestamp}.".encode() + payload
        expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()

        return any(hmac.compare_digest(expected, sig) for sig in signatures)
    except Exception:
        return False

# ── Helper ─────────────────────────────────────────────────────────────────────
def upsert_subscription(discord_id, discord_username, stripe_customer,
                         stripe_sub_id, status, period_end):
    now = datetime.datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute("""
            INSERT INTO subscriptions
                (discord_id, discord_username, stripe_customer, stripe_sub_id,
                 status, current_period_end, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(discord_id) DO UPDATE SET
                discord_username   = excluded.discord_username,
                stripe_customer    = excluded.stripe_customer,
                stripe_sub_id      = excluded.stripe_sub_id,
                status             = excluded.status,
                current_period_end = excluded.current_period_end,
                updated_at         = excluded.updated_at
        """, (discord_id, discord_username, stripe_customer,
              stripe_sub_id, status, period_end, now, now))
        conn.commit()

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/check/<discord_id>")
def check_subscription(discord_id):
    """
    The desktop app calls this on startup to verify subscription.
    Requires X-API-Key header matching API_SECRET_KEY.
    Returns: { subscribed: bool, status: str, expires: str|null }
    """
    key = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(key, API_SECRET_KEY):
        abort(401)

    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM subscriptions WHERE discord_id = ?", (discord_id,)
        ).fetchone()

    if not row:
        return jsonify({"subscribed": False, "status": "not_found", "expires": None})

    # Check if period has lapsed (grace period: 2 days)
    now_ts = int(datetime.datetime.utcnow().timestamp())
    grace  = 2 * 24 * 60 * 60
    active = (
        row["status"] in ("active", "trialing")
        and (row["current_period_end"] is None or row["current_period_end"] + grace > now_ts)
    )

    expires = None
    if row["current_period_end"]:
        expires = datetime.datetime.utcfromtimestamp(row["current_period_end"]).isoformat()

    return jsonify({
        "subscribed": active,
        "status":     row["status"],
        "expires":    expires,
        "username":   row["discord_username"],
    })


@app.post("/webhook")
def stripe_webhook():
    """
    Stripe posts events here.
    Set this URL in Stripe Dashboard → Developers → Webhooks.
    """
    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    if STRIPE_WEBHOOK_SECRET and not verify_stripe_signature(payload, sig_header, STRIPE_WEBHOOK_SECRET):
        print("[webhook] Invalid Stripe signature — rejected")
        abort(400)

    try:
        event = json.loads(payload)
    except Exception:
        abort(400)

    event_type = event.get("type", "")
    data_obj   = event.get("data", {}).get("object", {})

    print(f"[webhook] Received: {event_type}")

    # ── Payment succeeded (new sub or renewal) ────────────────────────────────
    if event_type in ("checkout.session.completed", "invoice.payment_succeeded"):
        _handle_payment_succeeded(data_obj, event_type)

    # ── Subscription cancelled or unpaid ──────────────────────────────────────
    elif event_type in ("customer.subscription.deleted",
                        "customer.subscription.updated",
                        "invoice.payment_failed"):
        _handle_subscription_changed(data_obj, event_type)

    return jsonify({"received": True})


# ── Event handlers ─────────────────────────────────────────────────────────────

def _handle_payment_succeeded(obj, event_type):
    """
    Extract discord_id from Stripe metadata and mark subscription active.

    In your Stripe Payment Link: add a custom field called 'discord_id'
    so the customer types their Discord user ID at checkout.
    Stripe puts it in metadata automatically.
    """
    discord_id       = None
    discord_username = ""
    stripe_customer  = obj.get("customer", "")
    stripe_sub_id    = ""
    period_end       = None

    if event_type == "checkout.session.completed":
        meta             = obj.get("metadata", {}) or obj.get("custom_fields", {}) or {}
        discord_id       = (meta.get("discord_id") or
                            _find_custom_field(obj, "discord_id"))
        discord_username = meta.get("discord_username", "")
        stripe_sub_id    = obj.get("subscription", "")

    elif event_type == "invoice.payment_succeeded":
        sub_data         = obj.get("subscription_details") or {}
        meta             = sub_data.get("metadata", {}) or {}
        discord_id       = meta.get("discord_id")
        stripe_sub_id    = obj.get("subscription", "")
        period_end       = obj.get("lines", {}).get("data", [{}])[0].get("period", {}).get("end")

    if not discord_id:
        print(f"[webhook] No discord_id in metadata — skipping. Object: {obj.get('id')}")
        return

    upsert_subscription(
        discord_id=discord_id,
        discord_username=discord_username,
        stripe_customer=stripe_customer,
        stripe_sub_id=stripe_sub_id,
        status="active",
        period_end=period_end,
    )
    print(f"[webhook] ✔ Subscription activated for discord_id={discord_id}")


def _handle_subscription_changed(obj, event_type):
    """Handle cancellations, failures, and status changes."""
    # For subscription objects
    if "current_period_end" in obj:
        stripe_sub_id = obj.get("id", "")
        new_status    = obj.get("status", "canceled")
        period_end    = obj.get("current_period_end")
        meta          = obj.get("metadata", {}) or {}
        discord_id    = meta.get("discord_id")

        if not discord_id:
            # Look up by stripe sub id
            with get_db() as conn:
                row = conn.execute(
                    "SELECT discord_id FROM subscriptions WHERE stripe_sub_id = ?",
                    (stripe_sub_id,)
                ).fetchone()
            if row:
                discord_id = row["discord_id"]

        if discord_id:
            now = datetime.datetime.utcnow().isoformat()
            with get_db() as conn:
                conn.execute(
                    "UPDATE subscriptions SET status=?, current_period_end=?, updated_at=? WHERE discord_id=?",
                    (new_status, period_end, now, discord_id)
                )
                conn.commit()
            print(f"[webhook] ↩ Subscription {new_status} for discord_id={discord_id}")


def _find_custom_field(obj, field_key):
    """Stripe Payment Links store custom fields in custom_fields list."""
    for field in obj.get("custom_fields", []):
        if field.get("key") == field_key:
            return (field.get("text", {}) or {}).get("value")
    return None


# ── Admin endpoints (optional) ─────────────────────────────────────────────────

@app.post("/admin/grant")
def admin_grant():
    """Manually grant access. POST JSON: { discord_id, discord_username, api_key }"""
    key = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(key, API_SECRET_KEY):
        abort(401)
    body = request.get_json() or {}
    discord_id       = body.get("discord_id")
    discord_username = body.get("discord_username", "")
    if not discord_id:
        return jsonify({"error": "discord_id required"}), 400
    upsert_subscription(discord_id, discord_username, "", "", "active", None)
    return jsonify({"ok": True, "discord_id": discord_id})


@app.post("/admin/revoke")
def admin_revoke():
    """Manually revoke access."""
    key = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(key, API_SECRET_KEY):
        abort(401)
    body = request.get_json() or {}
    discord_id = body.get("discord_id")
    if not discord_id:
        return jsonify({"error": "discord_id required"}), 400
    now = datetime.datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE subscriptions SET status='canceled', updated_at=? WHERE discord_id=?",
            (now, discord_id)
        )
        conn.commit()
    return jsonify({"ok": True})


@app.get("/admin/list")
def admin_list():
    """List all subscribers."""
    key = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(key, API_SECRET_KEY):
        abort(401)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM subscriptions ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
