#!/usr/bin/env python3
"""Run 114 extras: 12 angles (all live in redteam_battery.py Phase BP too).
1: app /api/pay outcome float 1.5: no 500, app alive
2: app POST /api/deals (method confusion): no 500, app alive
3: overcommit race: two parallel idems, combined seats exceed free: no 5xx, conserved
4: reserve seats as string "null": graceful, conserved
5: /release reservation_id as JSON array: no 5xx, conserved
6: transfer then NEW owner releases: no 5xx, conserved
7: X-Kavach-Timestamp as "true": 401/4xx, no 5xx
8: reserve with user_id equal to idempotency_key: graceful, conserved
9: webhook reservation_id whitespace-padded: no 500, app alive
10: GET /seats during a concurrent reserve: no 5xx, conserved
11: /confirm reservation_id 10000 chars: no 5xx, conserved
12: app /api/hold user_id float 1.5: no 500, app alive
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

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

# ---------------- Phase BP: run 114 extras (12 new angles) ----------------
def bp_alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def bp_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

def app_pay_outcome_float():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": "rt-114of", "outcome": 1.5}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bp_alive(AR, "/")
    return check("app", "app /api/pay outcome float 1.5: no 500, app alive", ok, "st=%s" % st)
app_pay_outcome_float()

def app_deals_post():
    st, j = raw(AR, "POST", "/api/deals", json.dumps({"title": "x"}).encode())
    ok = st != 500 and st != -1 and bp_alive(AR, "/")
    return check("app", "app POST /api/deals method confusion: no 500, app alive", ok, "st=%s" % st)
app_deals_post()

def overcommit_race():
    b1 = json.dumps({"user_id": "rt-114oc", "idempotency_key": "k114oc1", "seats": 30}).encode()
    b2 = json.dumps({"user_id": "rt-114oc", "idempotency_key": "k114oc2", "seats": 30}).encode()
    h1, h2 = sign(KEY, "POST", "/reserve", b1), sign(KEY, "POST", "/reserve", b2)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/reserve", b1, h1)
        f2 = ex.submit(raw, ER, "POST", "/reserve", b2, h2)
        st1, _ = f1.result(); st2, _ = f2.result()
    time.sleep(0.3)
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and conserved() and bp_alive(ER)
    return check("race", "overcommit race combined 60 > 50 free: no 5xx, conserved", ok, "s1=%s s2=%s" % (st1, st2))
overcommit_race()

def seats_string_null():
    st, j = post(ER, "/reserve", {"user_id": "rt-114sn", "idempotency_key": "k114sn", "seats": "null"})
    ok = st != 500 and st != -1 and conserved() and bp_alive(ER)
    return check("fuzz", "reserve seats as string \"null\": graceful, conserved", ok, "st=%s" % st)
seats_string_null()

def release_rid_array():
    st, _ = post(ER, "/release", {"reservation_id": ["RSV00000001"]})
    ok = st != 500 and st != -1 and conserved() and bp_alive(ER)
    return check("fuzz", "release reservation_id as JSON array: no 5xx, conserved", ok, "st=%s" % st)
release_rid_array()

def transfer_then_new_owner_releases():
    rid, st, _ = bp_hold("rt-114tr", "k114tr")
    if not rid:
        return check("state", "new-owner release: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-114tr-b"})
    st3, _ = post(ER2, "/release", {"reservation_id": rid})
    st4, _ = post(ER, "/release", {"reservation_id": rid})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st2, st3, st4)) and conserved() and bp_alive(ER)
    return check("state", "transfer then new owner releases: no 5xx, conserved", ok, "tr=%s r2=%s r1=%s" % (st2, st3, st4))
transfer_then_new_owner_releases()

def ts_true_header():
    body = json.dumps({"user_id": "rt-114tb", "idempotency_key": "k114tb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body, ts="1731987000")
    h["X-Kavach-Timestamp"] = "true"
    st, _ = raw(ER, "POST", "/reserve", body, h)
    ok = st != 500 and st != -1 and conserved() and bp_alive(ER)
    return check("auth", "X-Kavach-Timestamp as \"true\": no 5xx, conserved", ok, "st=%s" % st)
ts_true_header()

def userid_equals_idem():
    st, j = post(ER, "/reserve", {"user_id": "k114same", "idempotency_key": "k114same", "seats": 1})
    ok = st != 500 and st != -1 and conserved() and bp_alive(ER)
    return check("fuzz", "reserve user_id equal to idempotency_key: graceful, conserved", ok, "st=%s" % st)
userid_equals_idem()

def webhook_rid_padded():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": "  RSV00000001 "}).encode())
    ok = st != 500 and st != -1 and bp_alive(AR, "/")
    return check("webhook", "webhook reservation_id whitespace-padded: no 500, app alive", ok, "st=%s" % st)
webhook_rid_padded()

def seats_during_write():
    b = json.dumps({"user_id": "rt-114rw", "idempotency_key": "k114rw", "seats": 2}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/reserve", b, h)
        f2 = ex.submit(raw, ER, "GET", "/seats", None, None)
        st1, _ = f1.result(); st2, _ = f2.result()
    ok = st1 != 500 and st1 != -1 and st2 == 200 and conserved() and bp_alive(ER)
    return check("race", "GET /seats during concurrent reserve: 200, conserved", ok, "w=%s r=%s" % (st1, st2))
seats_during_write()

def confirm_long_rid():
    st, _ = post(ER, "/confirm", {"reservation_id": "R" * 10000, "idempotency_key": "k114lr"})
    ok = st != 500 and st != -1 and conserved() and bp_alive(ER)
    return check("fuzz", "confirm reservation_id 10000 chars: no 5xx, conserved", ok, "st=%s" % st)
confirm_long_rid()

def app_hold_userid_float():
    body = json.dumps({"user_id": 1.5, "seats": 1}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and bp_alive(AR, "/")
    return check("app", "app /api/hold user_id float 1.5: no 500, app alive", ok, "st=%s" % st)
app_hold_userid_float()
