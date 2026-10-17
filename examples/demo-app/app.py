#!/usr/bin/env python3
"""Aurora Nights Live: a real three-tier demo of Kavach in production shape.

    browser -> this app (Flask) -> Kavach engine (HTTP + HMAC)

The app is written the way a third-party developer would integrate the
engine: it talks to Kavach only through the Python SDK (sdk/python),
holds seats with reserve() while the customer "pays", confirms on
success, releases on failure, and falls back to the waitlist when the
show sells out. Pricing and the (simulated) payment live in THIS layer
on purpose: the engine never sees money.

Run it:
    cd engine && ./kavach -seats 200 -ip-rate 0 \
        -api-keys appkey:aurora-app -hmac-secret appsecret -hold-ttl 60 &
    cd examples/demo-app && python3 app.py &   # http://127.0.0.1:9000
    python3 loadtest_app.py                     # end-to-end load test
"""
import os, sys, uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "sdk", "python"))
from flask import Flask, jsonify, request, send_from_directory
from kavach import Kavach, KavachError

KAVACH_URL = os.environ.get("KAVACH_URL", "http://127.0.0.1:8080")
KAVACH_KEY = os.environ.get("KAVACH_KEY", "appkey")
KAVACH_SECRET = os.environ.get("KAVACH_SECRET", "appsecret")

app = Flask(__name__, static_folder="static", static_url_path="")
kv = Kavach(KAVACH_URL, api_key=KAVACH_KEY, hmac_secret=KAVACH_SECRET)

@app.get("/")
def home():
    return send_from_directory("static", "index.html")

@app.get("/api/seats")
def seats():
    return jsonify(kv.seats())

@app.post("/api/hold")
def hold():
    """Reserve seats through Kavach; the app keeps its own order record."""
    b = request.get_json(silent=True) or {}
    user, n = b.get("user_id"), int(b.get("seats", 1))
    key = b.get("key") or uuid.uuid4().hex
    try:
        r = kv.reserve(user, key, seats=n)
    except KavachError as e:
        return jsonify({"ok": False, "status": e.body.get("status", "error")}), e.status
    if r.get("status") != "held":
        return jsonify({"ok": False, **r}), 200
    return jsonify({"ok": True, "reservation_id": r["reservation_id"], "seats": r["seats"],
                    "hold_expires_at": r["hold_expires_at"], "amount": 499.0 * n, "key": key})

@app.post("/api/pay")
def pay():
    """Simulated payment gateway. Success -> confirm the hold in Kavach.
    Failure or the customer walking away -> release the seats back."""
    b = request.get_json(silent=True) or {}
    rid = b.get("reservation_id")
    if b.get("outcome", "success") != "success":
        try:
            kv.release(rid)
        except KavachError:
            pass  # hold already expired: the engine freed the seats itself
        return jsonify({"ok": False, "status": "payment_failed"}), 200
    try:
        c = kv.confirm(rid, b.get("user_id"))
    except KavachError as e:
        return jsonify({"ok": False, "status": e.body.get("status", "error")}), e.status
    return jsonify({"ok": True, "booking_id": c["booking_id"], "seats": c["seats"]})

@app.post("/api/waitlist")
def waitlist():
    b = request.get_json(silent=True) or {}
    try:
        w = kv.waitlist_join(b.get("user_id"), b.get("key") or uuid.uuid4().hex,
                             seats=int(b.get("seats", 1)))
    except KavachError as e:
        return jsonify({"ok": False, "status": e.body.get("status", "error")}), e.status
    return jsonify({"ok": True, "waitlist_id": w.get("waitlist_id"), "position": w.get("position")})

@app.get("/api/metrics")
def metrics():
    return jsonify(kv.metrics())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9000")), threaded=True)
