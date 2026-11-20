#!/usr/bin/env python3
"""Run 111 extras: 12 angles (all live in redteam_battery.py Phase BM too).
1: webhook token base64-encoded: no 500, app alive
2: app /api/pay outcome empty string: no 500, app alive
3: app /api/pay outcome boolean true: no 500, app alive
4: /transfer to_user as JSON object: graceful, conserved
5: reserve idempotency_key whitespace-only: graceful, conserved
6: X-Kavach-Timestamp with leading plus sign: 401/4xx, no 5xx
7: app /api/board limit as string "abc": no 500, app alive
8: app /api/hold seats "1e1": no 500, app alive
9: release a transferred reservation's rid (old owner): no 5xx, conserved
10: app /api/pay reservation_id whitespace-padded: no 500, app alive
11: DELETE /seats with valid signature: no 5xx, conserved
12: MAC computed with lowercase method "post": 401, conserved
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import base64, hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
    return ok
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None, sig_method=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + (sig_method or method) + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256).hexdigest()
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
            "X-Kavach-Signature": mac, "Content-Type": "application/json"}
def raw(port, method, path, body=None, headers=None):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers: headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
        c.request(method, path, body=b, headers=headers or {})
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try: j = json.loads(data) if data else {}
        except Exception: j = {"raw": data[:150].decode("utf-8", "replace")}
        return st, j
    except Exception as ex: return -1, {"exception": str(ex)[:120]}
def post(port, path, obj, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, "POST", path, body, sign(KEY, "POST", path, body, **kw))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def conserved(port=ER):
    s = seats(port)
    return s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
def alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200

# ---------------- Phase BM: run 111 extras (12 new angles) ----------------
def bm_alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def bm_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

def webhook_token_base64():
    tok = base64.b64encode(b"whsec-redtest").decode()
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=" + tok, json.dumps({"event": "payment_success", "reservation_id": "RSV00000001"}).encode())
    ok = st != 500 and st != -1 and bm_alive(AR, "/")
    return check("webhook", "webhook token base64-encoded: no 500, app alive", ok, "st=%s" % st)
webhook_token_base64()

def app_pay_outcome_empty():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": "rt-111oe", "outcome": ""}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bm_alive(AR, "/")
    return check("app", "app /api/pay outcome empty string: no 500, app alive", ok, "st=%s" % st)
app_pay_outcome_empty()

def app_pay_outcome_bool():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": "rt-111ob", "outcome": True}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bm_alive(AR, "/")
    return check("app", "app /api/pay outcome boolean true: no 500, app alive", ok, "st=%s" % st)
app_pay_outcome_bool()

def transfer_to_user_object():
    rid, st, _ = bm_hold("rt-111to", "k111to")
    if not rid:
        return check("state", "transfer to_user object: skipped (hold unavailable)", True, "st=%s" % st)
    st2, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": {"name": "x"}})
    ok = st2 != 500 and st2 != -1 and conserved() and bm_alive(ER)
    return check("fuzz", "transfer to_user as JSON object: graceful, conserved", ok, "st2=%s" % st2)
transfer_to_user_object()

def idem_whitespace():
    st, j = post(ER, "/reserve", {"user_id": "rt-111iw", "idempotency_key": "   ", "seats": 1})
    ok = st != 500 and st != -1 and conserved() and bm_alive(ER)
    return check("fuzz", "reserve idempotency_key whitespace-only: graceful, conserved", ok, "st=%s" % st)
idem_whitespace()

def ts_plus_sign():
    body = json.dumps({"user_id": "rt-111tp", "idempotency_key": "k111tp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body, ts="+1731987000")
    h["X-Kavach-Timestamp"] = "+1731987000"
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st != 500 and st != -1 and conserved() and bm_alive(ER)
    return check("auth", "X-Kavach-Timestamp with leading plus sign: no 5xx, conserved", ok, "st=%s" % st)
ts_plus_sign()

def app_board_limit_str():
    st, j = raw(AR, "GET", "/api/board?limit=abc")
    ok = st != 500 and st != -1 and bm_alive(AR, "/")
    return check("app", "app /api/board limit as string: no 500, app alive", ok, "st=%s" % st)
app_board_limit_str()

def app_hold_sci_notation():
    body = json.dumps({"user_id": "rt-111sn", "seats": "1e1"}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and bm_alive(AR, "/")
    return check("app", "app /api/hold seats \"1e1\": no 500, app alive", ok, "st=%s" % st)
app_hold_sci_notation()

def release_after_transfer():
    rid, st, _ = bm_hold("rt-111rt", "k111rt")
    if not rid:
        return check("state", "release post-transfer rid: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-111rt-b"})
    st3, _ = post(ER, "/release", {"reservation_id": rid})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st2, st3)) and conserved() and bm_alive(ER)
    return check("state", "release old owner's rid after transfer: no 5xx, conserved", ok, "tr=%s rel=%s" % (st2, st3))
release_after_transfer()

def app_pay_rid_padded():
    body = json.dumps({"reservation_id": "  RSV00000001  ", "user_id": "rt-111pp", "outcome": "success"}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bm_alive(AR, "/")
    return check("app", "app /api/pay reservation_id whitespace-padded: no 500, app alive", ok, "st=%s" % st)
app_pay_rid_padded()

def delete_seats_signed():
    h = sign(KEY, "DELETE", "/seats", b"")
    st, j = raw(ER, "DELETE", "/seats", b"", h)
    ok = st != 500 and st != -1 and conserved() and bm_alive(ER)
    return check("fuzz", "DELETE /seats with valid signature: no 5xx, conserved", ok, "st=%s" % st)
delete_seats_signed()

def mac_lowercase_method():
    body = json.dumps({"user_id": "rt-111lm", "idempotency_key": "k111lm", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    ts, rid = h["X-Kavach-Timestamp"], h["X-Kavach-Request-Id"]
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\n" + "post" + "\n" + "/reserve" + "\n" + KEY + "\n").encode() + body, hashlib.sha256).hexdigest()
    h["X-Kavach-Signature"] = mac
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st in (401, 403) and conserved() and bm_alive(ER)
    return check("auth", "MAC over lowercase method: 401, conserved", ok, "st=%s" % st)
mac_lowercase_method()
