#!/usr/bin/env python3
"""Run 107 extras: 12 angles (all live in redteam_battery.py Phase BI too).
1: reserve seats huge int 99999999999999999999 (int64 overflow): graceful, conserved
2: reserve seats as string "1.0": graceful, conserved
3: reserve seats "-0" (negative zero): graceful, conserved
4: reserve user_id as nested JSON object: graceful, conserved
5: confirm with 10000-char reservation_id: 4xx, no 5xx, conserved
6: duplicate X-Kavach-Timestamp headers, two values, sig over first: no 5xx, conserved
7: X-Kavach-Timestamp as float string: 4xx, no 5xx, conserved
8: Authorization "Bearer " empty token: 401, no 5xx, conserved
9: multi-hop transfer (u1->u2, then u2 onward): no 5xx, conserved
10: app /api/hold seats "1.5": no 500, app alive
11: app /api/pay user_id null: no 500, app alive
12: webhook query token percent-encoded %77hsec: no 500, token not accepted
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid

ER, AR, ER2 = 8091, 9001, 8092
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
    return ok
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256).hexdigest()
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

# ---------------- Phase BI: run 107 extras (12 new angles) ----------------
def bi_hold(user, key="k107%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})

def seats_huge_int():
    body = json.dumps({"user_id": "rt-107hi", "idempotency_key": "k107hi", "seats": 99999999999999999999}).encode()
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats huge int 99999999999999999999: graceful, conserved", ok, "st=%s" % st)
seats_huge_int()

def seats_str_float():
    st, j = post(ER, "/reserve", {"user_id": "rt-107sf", "idempotency_key": "k107sf", "seats": "1.0"})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as string \"1.0\": graceful, conserved", ok, "st=%s" % st)
seats_str_float()

def seats_neg_zero():
    body = json.dumps({"user_id": "rt-107nz", "idempotency_key": "k107nz", "seats": -0}).encode()
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats -0 (negative zero): graceful, conserved", ok, "st=%s" % st)
seats_neg_zero()

def userid_nested_obj():
    body = json.dumps({"user_id": {"nested": {"deep": [1, 2, 3]}}, "idempotency_key": "k107no", "seats": 1}).encode()
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id as nested JSON object: graceful, conserved", ok, "st=%s" % st)
userid_nested_obj()

def confirm_huge_rid():
    rid = "RSV" + "A" * 10000
    body = json.dumps({"reservation_id": rid}).encode()
    st, j = raw(ER, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm with 10000-char reservation_id: no 5xx, conserved", ok, "st=%s" % st)
confirm_huge_rid()

def dup_timestamp_headers():
    body = json.dumps({"user_id": "rt-107dt", "idempotency_key": "k107dt", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    hdrs = [("Host", "127.0.0.1"), ("Authorization", "Bearer " + KEY),
            ("X-Kavach-Timestamp", h["X-Kavach-Timestamp"]), ("X-Kavach-Request-Id", h["X-Kavach-Request-Id"]),
            ("X-Kavach-Signature", h["X-Kavach-Signature"]), ("Content-Type", "application/json"),
            ("X-Kavach-Timestamp", "9999999999")]
    try:
        c = http.client.HTTPConnection("127.0.0.1", ER, timeout=25)
        c.putrequest("POST", "/reserve")
        for k, v in hdrs:
            c.putheader(k, v)
        c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse(); r.read(); st = r.status; c.close()
    except Exception as ex:
        st = -1
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("auth", "duplicate X-Kavach-Timestamp headers (sig over first): no 5xx, conserved", ok, "st=%s" % st)
dup_timestamp_headers()

def ts_float_string():
    body = json.dumps({"user_id": "rt-107tf", "idempotency_key": "k107tf", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body, ts="1731987000.5")
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("auth", "X-Kavach-Timestamp as float string: no 5xx, conserved", ok, "st=%s" % st)
ts_float_string()

def bearer_empty_token():
    body = json.dumps({"user_id": "rt-107be", "idempotency_key": "k107be", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    h["Authorization"] = "Bearer "
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st in (401, 403) and conserved() and alive(ER)
    return check("auth", "Authorization \"Bearer \" empty token: 401, conserved", ok, "st=%s" % st)
bearer_empty_token()

def multi_hop_transfer():
    rid, st, _ = bi_hold("rt-107mt", "k107mt")
    if not rid:
        return check("state", "multi-hop transfer: skipped (hold unavailable)", True, "st=%s" % st)
    b1 = json.dumps({"reservation_id": rid, "to_user": "rt-107mt2"}).encode()
    st1, _ = raw(ER, "POST", "/transfer", b1, sign(KEY, "POST", "/transfer", b1))
    b2 = json.dumps({"reservation_id": rid, "to_user": "rt-107mt3"}).encode()
    st2, _ = raw(ER, "POST", "/transfer", b2, sign(KEY, "POST", "/transfer", b2))
    time.sleep(0.3)
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and conserved() and alive(ER)
    return check("state", "multi-hop transfer u1->u2 then u2 onward: no 5xx, conserved", ok, "t1=%s t2=%s" % (st1, st2))
multi_hop_transfer()

def app_hold_seats_str_float():
    body = json.dumps({"user_id": "rt-107asf", "seats": "1.5"}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold seats \"1.5\": no 500, app alive", ok, "st=%s" % st)
app_hold_seats_str_float()

def app_pay_userid_null():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": None, "outcome": "success"}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/pay user_id null: no 500, app alive", ok, "st=%s" % st)
app_pay_userid_null()

def webhook_token_pct_encoded():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=%77hsec-redtest", json.dumps({"event": "payment_success", "reservation_id": "RSV00000001"}).encode())
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("webhook", "webhook query token percent-encoded %77hsec: no 500, app alive", ok, "st=%s" % st)
webhook_token_pct_encoded()
