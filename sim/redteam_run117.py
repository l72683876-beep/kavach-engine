#!/usr/bin/env python3
"""Run 117 extras: 12 angles (Phase BS), all new vs run 115/116.
1: /reserve seats as negative int -1: graceful 4xx, conserved
2: /reserve seats as real JSON float 1.5: graceful, conserved
3: /release with reservation_id as JSON integer (type confusion): no 5xx
4: /transfer where to_user == from_user (self-transfer): no 5xx, conserved
5: /confirm with idempotency_key as nested JSON object {}: no 5xx, conserved
6: /reserve with X-Kavach-Timestamp one year in the future (skew): no 5xx
7: /waitlist with seats field missing entirely: graceful, app alive
8: app /api/kavach-webhook with oversized rid (10KB): no 500, app alive
9: app /api/hold seats as float 2.5: no 500, app alive
10: app /api/waitlist with seats as negative -3: graceful, app alive
11: app /api/pay with reservation_id as JSON integer: no 500, app alive
12: /reserve with user_id 10KB long string: no 5xx, conserved
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, re, sys, time, uuid

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
def bs_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

# ---------------- Phase BS: run 117 extras (12 new angles) ----------------
def bs_reserve_seats_negative():
    st, j = post(ER, "/reserve", {"user_id": "rt-117sn", "idempotency_key": "k117sn", "seats": -1})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as negative int -1: graceful, conserved", ok, "st=%s" % st)
bs_reserve_seats_negative()

def bs_reserve_seats_float():
    st, j = post(ER, "/reserve", {"user_id": "rt-117sf", "idempotency_key": "k117sf", "seats": 1.5})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as real JSON float 1.5: graceful, conserved", ok, "st=%s" % st)
bs_reserve_seats_float()

def bs_release_rid_int():
    rid, st, _ = bs_hold("rt-117ri", "k117ri")
    if not rid:
        return check("state", "release rid as int: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": int(re.sub(r"\D", "", str(rid))[:8] or 12345)}).encode()
    st2, _ = raw(ER, "POST", "/release", body, sign(KEY, "POST", "/release", body))
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("fuzz", "release with reservation_id as JSON integer: no 5xx, conserved", ok, "st2=%s" % st2)
bs_release_rid_int()

def bs_transfer_self():
    rid, st, _ = bs_hold("rt-117ts", "k117ts", seats_n=2)
    if not rid:
        return check("state", "self-transfer: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "from_user": "rt-117ts", "to_user": "rt-117ts"})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("authz", "transfer with to_user == from_user (self-transfer): no 5xx, conserved", ok, "st2=%s" % st2)
bs_transfer_self()

def bs_confirm_idem_object():
    rid, st, _ = bs_hold("rt-117co", "k117co")
    if not rid:
        return check("state", "confirm idem object: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-117co", "idempotency_key": {"a": 1}})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm with idempotency_key as nested JSON object: no 5xx, conserved", ok, "st2=%s" % st2)
bs_confirm_idem_object()

def bs_timestamp_future_skew():
    body = json.dumps({"user_id": "rt-117tk", "idempotency_key": "k117tk", "seats": 1}).encode()
    headers = sign(KEY, "POST", "/reserve", body, ts=str(int(time.time()) + 365 * 86400))
    st, _ = raw(ER, "POST", "/reserve", body, headers)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("auth", "reserve with X-Kavach-Timestamp one year in future: no 5xx (reject or accept cleanly), conserved", ok, "st=%s" % st)
bs_timestamp_future_skew()

def bs_waitlist_no_seats():
    st, j = post(ER, "/waitlist", {"user_id": "rt-117wn", "idempotency_key": "k117wn"})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist with seats field missing entirely: graceful", ok, "st=%s" % st)
bs_waitlist_no_seats()

def bs_webhook_oversized_rid():
    body = json.dumps({"event": "waitlist_fulfilled", "rid": "x" * 10240, "seats": 1}).encode()
    st, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app webhook with oversized rid (10KB): no 500, app alive", ok, "st=%s" % st)
bs_webhook_oversized_rid()

def bs_app_hold_float():
    body = json.dumps({"user_id": "rt-117hf", "seats": 2.5}).encode()
    st, _ = raw(AR, "POST", "/api/hold", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold with seats as float 2.5: no 500, app alive", ok, "st=%s" % st)
bs_app_hold_float()

def bs_app_waitlist_negative():
    body = json.dumps({"user_id": "rt-117wng", "seats": -3}).encode()
    st, _ = raw(AR, "POST", "/api/waitlist", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/waitlist with seats as negative -3: graceful, app alive", ok, "st=%s" % st)
bs_app_waitlist_negative()

def bs_app_pay_int_rid():
    body = json.dumps({"reservation_id": 12345, "user_id": "rt-117pr", "outcome": "success"}).encode()
    st, _ = raw(AR, "POST", "/api/pay", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/pay with reservation_id as JSON integer: no 500, app alive", ok, "st=%s" % st)
bs_app_pay_int_rid()

def bs_reserve_long_user():
    body = json.dumps({"user_id": "u" * 10240, "idempotency_key": "k117lu", "seats": 1}).encode()
    st, _ = post(ER, "/reserve", None) if False else (None, None)
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve with user_id 10KB long string: no 5xx, conserved", ok, "st=%s" % st)
bs_reserve_long_user()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("BS TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in results:
    print("OK " if r[2] else "FAIL", "[%s] %s :: %s" % (r[0], r[1], r[3]))
sys.exit(1 if fails else 0)
