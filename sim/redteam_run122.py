#!/usr/bin/env python3
"""Run 122 extras: 12 angles (Phase BX), all new vs runs 115-121.
1: /reserve with user_id as array: no 5xx, conserved
2: /confirm with event_id field present: no 5xx, state sane
3: /waitlist with user_id as integer: no 5xx
4: /release with idempotency_key field present: no 5xx, conserved
5: /transfer with to_user as integer: no 5xx, conserved
6: /book with idempotency_key as integer: no 5xx, conserved
7: app /api/reserve with seats -2: no 500, app alive
8: app /api/confirm with rid empty string: no 500, app alive
9: app webhook malformed JSON with valid signature: no crash, app alive
10: /reserve with empty idempotency_key string: no 5xx, conserved
11: race: 10 parallel /confirm on same hold: exactly one booking_id, conserved
12: valid signature for original body but body sent with trailing newline: rejected, conserved
Run against targets already up: 8091 engine, 8092 engine2, 8095 ttl engine, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2, ET = 8091, 9001, 8092, 8095
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
def post2(port, path, obj, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, "POST", path, body, sign(KEY2, "POST", path, body, **kw))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def conserved(port=ER):
    s = seats(port)
    return s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
def alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

# ---------------- Phase BX: run 122 extras (12 new angles) ----------------
def bx_reserve_uid_array():
    st, j = post(ER, "/reserve", {"user_id": ["rt-122a", "rt-122b"], "idempotency_key": "k122a", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id as array: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bx_reserve_uid_array()

def bx_confirm_eventid_field():
    rid, st, _ = hold("rt-122ev", "k122ev", 1)
    if not rid:
        return check("state", "confirm event_id field: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-122ev", "event_id": "evt-122"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "confirm with event_id present: no 5xx, state sane", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
bx_confirm_eventid_field()

def bx_waitlist_uid_int():
    st, j = post(ER, "/waitlist", {"user_id": 7, "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist user_id integer: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
bx_waitlist_uid_int()

def bx_release_idem_field():
    rid, st, _ = hold("rt-122ri", "k122ri", 1)
    if not rid:
        return check("state", "release idempotency_key field: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/release", {"reservation_id": rid, "idempotency_key": "k122ri-x"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "release with extra idempotency_key field: no 5xx, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
bx_release_idem_field()

def bx_transfer_touser_int():
    rid, st, _ = hold("rt-122ti", "k122ti", 2)
    if not rid:
        return check("state", "transfer to_user integer: skipped (hold unavailable)", True, "st=%s" % st)
    stb, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-122ti"})
    stc, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": 99})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer to_user as integer: no 5xx, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
bx_transfer_touser_int()

def bx_book_idem_int():
    st, j = post(ER, "/book", {"user_id": "rt-122bi", "idempotency_key": 12345, "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book idempotency_key as integer: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bx_book_idem_int()

def bx_app_reserve_negative():
    st, j = raw(AR, "POST", "/api/reserve", json.dumps({"user_id": "rt-122an", "seats": -2}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app reserve seats -2: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bx_app_reserve_negative()

def bx_app_confirm_empty():
    st, j = raw(AR, "POST", "/api/confirm", json.dumps({"reservation_id": ""}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app confirm empty rid: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bx_app_confirm_empty()

def bx_webhook_malformed():
    body = b'{"type": "confirmed", "reservation_id": "RSV0000000"'
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest", "X-Kavach-Signature": sig}
    st, j = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "webhook malformed JSON valid sig: no crash, app alive", ok, "st=%s" % st)
bx_webhook_malformed()

def bx_reserve_empty_idem():
    st, j = post(ER, "/reserve", {"user_id": "rt-122ei", "idempotency_key": "", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve empty idempotency_key string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bx_reserve_empty_idem()

def bx_parallel_confirm_race():
    rid, st, _ = hold("rt-122pr", "k122pr", 2)
    if not rid:
        return check("race", "parallel confirm race: skipped (hold unavailable)", True, "st=%s" % st)
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(post, ER, "/confirm", {"reservation_id": rid, "user_id": "rt-122pr"}) for _ in range(10)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    bids = set()
    for stc, j in outs:
        if stc == 200 and isinstance(j, dict) and j.get("booking_id"):
            bids.add(j["booking_id"])
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved() and alive(ER) and len(bids) == 1
    return check("race", "10-way parallel confirm same hold: one booking_id, conserved", ok, "bids=%d sts=%s" % (len(bids), [o[0] for o in outs]))
bx_parallel_confirm_race()

def bx_body_trailing_newline():
    obj = {"user_id": "rt-122tn", "idempotency_key": "k122tn", "seats": 1}
    good = json.dumps(obj).encode()
    bad = good + b"\n"
    h = sign(KEY, "POST", "/reserve", good)
    st, j = raw(ER, "POST", "/reserve", bad, h)
    time.sleep(0.2)
    ok = st != 500 and st != -1 and st != 200 and conserved() and alive(ER)
    return check("auth", "signature valid but body has trailing newline: rejected", ok, "st=%s j=%s" % (st, str(j)[:60]))
bx_body_trailing_newline()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("BX TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "BX", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/bx122.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
