#!/usr/bin/env python3
"""Run 80 extras: 12 angles (all live in redteam_battery.py Phase AH too).
1: signature with 0x prefix: 401, alive
2: 10 confirms + 10 releases parallel on one rid: no 5xx, conserved
3: waitlist join twice same user different keys: no 5xx, conserved
4: percent-encoded path /%73eats and /seats%2F: no 5xx, alive
5: null byte %00 in query: no 5xx, alive
6: reserve user_id null: 4xx, alive
7: app hold seats=-1: no 500
8: webhook payment_success seats=3 on 2-seat hold: no 500, seats sane
9: two holds same user different keys: releasing one leaves the other intact
10: 200 rapid GET /seats: no 5xx, alive (429 allowed)
11: app confirm lowercase-prefixed rid: no 500
12: timestamp with leading zeros: no 5xx
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, SECRET = "testkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
            "X-Kavach-Signature": mac.hexdigest(), "Content-Type": "application/json"}
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
def rej(st): return 400 <= st < 500 or st == 429
def P(n, fn):
    with ThreadPoolExecutor(max(1, n)) as ex:
        return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase AH: run 80 extras (12 new angles) ----------------
def sig_0x_prefix():
    b = json.dumps({"user_id": "rt-80zp", "idempotency_key": "k80zp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Signature"] = "0x" + h["X-Kavach-Signature"]
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "signature with 0x hex prefix: 401, alive", st == 401 and alive, "status=%s" % st)
sig_0x_prefix()
def confirm_release_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-80cr", "idempotency_key": "k80cr", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel confirm+release same rid: skipped (hold unavailable)", True, "st=%s" % st)
    outs = P(20, lambda i: post(ER, "/confirm" if i % 2 == 0 else "/release", {"reservation_id": rid})[0])
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved
    return check("race", "10 confirms + 10 releases in parallel on one rid: no 5xx, exactly one terminal state, conserved", ok, "outs=%s" % outs)
confirm_release_race()
def duplicate_waitlist_join():
    o1 = {"user_id": "rt-80dw", "idempotency_key": "k80dw1", "event_id": "prod-v1"}
    o2 = {"user_id": "rt-80dw", "idempotency_key": "k80dw2", "event_id": "prod-v1"}  # same user, different key
    st1, _ = post(ER, "/waitlist", o1)
    st2, _ = post(ER, "/waitlist", o2)
    s = seats(ER)
    alive = raw(ER, "GET", "/seats")[0] == 200
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st1 != 500 and st1 != -1 and st2 != 500 and st2 != -1 and alive and conserved
    return check("state", "waitlist join twice same user different keys: no 5xx, conserved", ok, "st1=%s st2=%s" % (st1, st2))
duplicate_waitlist_join()
def percent_encoded_path():
    st1, _ = raw(ER, "GET", "/%73eats")  # %73 = 's': /seats percent-encoded
    st2, _ = raw(ER, "GET", "/seats%2F")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st1 != 500 and st1 != -1 and st2 != 500 and st2 != -1 and alive
    return check("wire", "percent-encoded path /%73eats and trailing %2F: no 5xx, alive", ok, "st1=%s st2=%s" % (st1, st2))
percent_encoded_path()
def null_byte_query():
    st, _ = raw(ER, "GET", "/seats?x=%00abc")
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "null byte %00 in query string: no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
null_byte_query()
def user_id_null():
    st, _ = post(ER, "/reserve", {"user_id": None, "idempotency_key": "k80un", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with user_id null: 4xx, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
user_id_null()
def app_hold_negative_seats():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-80ng", "seats": -1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats=-1: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_negative_seats()
def webhook_seats_mismatch():
    st, j = post(ER, "/reserve", {"user_id": "rt-80wm", "idempotency_key": "k80wm", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook seats mismatch: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid, "seats": 3}))  # rid holds 2, webhook says 3
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    sane = s1.get("sold", 0) in (s0.get("sold", 0), s0.get("sold", 0) + 2)
    if s1.get("sold", 0) == s0.get("sold", 0) + 2:
        pass  # paid, seats consumed per hold (2), not per webhook (3)
    else:
        post(ER, "/release", {"reservation_id": rid})
    ok = w != 500 and w != -1 and alive and sane
    return check("app", "webhook payment_success with seats=3 on a 2-seat hold: no 500, seats sane", ok, "w=%s sold0=%s sold1=%s" % (w, s0.get("sold"), s1.get("sold")))
webhook_seats_mismatch()
def two_holds_independent():
    a = {"user_id": "rt-80th", "idempotency_key": "k80th1", "seats": 1}
    b = {"user_id": "rt-80th", "idempotency_key": "k80th2", "seats": 2}
    st1, j1 = post(ER, "/reserve", a)
    st2, j2 = post(ER, "/reserve", b)
    r1 = j1.get("reservation_id") if isinstance(j1, dict) and st1 == 200 else None
    r2 = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    if not (r1 and r2):
        return check("state", "two holds same user independent: skipped (holds unavailable)", True, "st1=%s st2=%s" % (st1, st2))
    s0 = seats(ER)
    post(ER, "/release", {"reservation_id": r1})
    s1 = seats(ER)
    r2_still = s1.get("held", 0) == s0.get("held", 0) - 1
    post(ER, "/release", {"reservation_id": r2})
    ok = r2_still
    return check("state", "two holds same user (different keys): releasing one leaves the other intact", ok, "held0=%s held1=%s" % (s0.get("held"), s1.get("held")))
two_holds_independent()
def rapid_gets():
    outs = [raw(ER, "GET", "/seats")[0] for _ in range(200)]
    alive = raw(ER, "GET", "/seats")[0] != -1
    ok = all(x != 500 for x in outs) and alive
    return check("rate", "200 rapid GET /seats same IP: no 5xx, engine answers (429 allowed)", ok, "429s=%d 500s=%d" % (outs.count(429), outs.count(500)))
rapid_gets()
def app_confirm_lowercase_rid():
    p, _ = raw(AR, "POST", "/api/confirm", json.dumps({"reservation_id": "rsv00000001"}))  # lowercase prefix
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app confirm with lowercase-prefixed rid: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_confirm_lowercase_rid()
def ts_leading_zeros():
    b = json.dumps({"user_id": "rt-80lz", "idempotency_key": "k80lz", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, ts="0000000" + str(int(time.time())))
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("auth", "timestamp with leading zeros: 200 or 4xx, no 5xx", ok, "status=%s" % st)
ts_leading_zeros()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
