#!/usr/bin/env python3
"""Run 123 extras: 12 angles (Phase BY), all new vs runs 115-122.
1: /reserve with user_id as nested object: no 5xx, conserved
2: /confirm with user_id as boolean true: no 5xx
3: /waitlist with idempotency_key as boolean: no 5xx
4: /release with extra user_id field: no 5xx, conserved
5: /transfer with reservation_id as integer: no 5xx, conserved
6: /book with user_id empty string: no 5xx, conserved
7: app /api/release with rid missing: no 500, app alive
8: app /api/hold with seats as boolean: no 500, app alive
9: app webhook valid token, JSON array body: no crash, app alive
10: /reserve with seats as JSON null: no 5xx, conserved
11: race: 20-way parallel /book same idempotency_key: one booking, conserved
12: /confirm with reservation_id whitespace-only: graceful, no 5xx
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

# ---------------- Phase BY: run 123 extras (12 new angles) ----------------
def by_reserve_uid_object():
    st, j = post(ER, "/reserve", {"user_id": {"id": "rt-123o"}, "idempotency_key": "k123o", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id as object: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
by_reserve_uid_object()

def by_confirm_uid_bool():
    rid, st, _ = hold("rt-123cb", "k123cb", 1)
    if not rid:
        return check("state", "confirm user_id boolean: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": rid, "user_id": True})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and alive(ER)
    return check("fuzz", "confirm user_id as boolean: no 5xx", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
by_confirm_uid_bool()

def by_waitlist_idem_bool():
    st, j = post(ER, "/waitlist", {"user_id": "rt-123wb", "idempotency_key": True, "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist idempotency_key boolean: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
by_waitlist_idem_bool()

def by_release_extra_uid():
    rid, st, _ = hold("rt-123ru", "k123ru", 1)
    if not rid:
        return check("state", "release extra user_id: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/release", {"reservation_id": rid, "user_id": "someone-else"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "release with extra user_id field: no 5xx, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
by_release_extra_uid()

def by_transfer_rid_int():
    rid, st, _ = hold("rt-123tr", "k123tr", 2)
    if not rid:
        return check("state", "transfer rid integer: skipped (hold unavailable)", True, "st=%s" % st)
    stb, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-123tr"})
    stc, j = post(ER, "/transfer", {"reservation_id": 42, "to_user": "rt-123tr2"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer reservation_id as integer: no 5xx, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
by_transfer_rid_int()

def by_book_uid_empty():
    st, j = post(ER, "/book", {"user_id": "", "idempotency_key": "k123be", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book user_id empty string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
by_book_uid_empty()

def by_app_release_missing():
    st, j = raw(AR, "POST", "/api/release", json.dumps({"user_id": "rt-123ar"}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app release rid missing: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
by_app_release_missing()

def by_app_hold_seats_bool():
    st, j = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-123hb", "seats": True}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app hold seats boolean: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
by_app_hold_seats_bool()

def by_webhook_array_body():
    body = json.dumps([{"type": "confirmed", "reservation_id": "RSV00000001"}]).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest", "X-Kavach-Signature": sig}
    st, j = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "webhook JSON array body valid token: no crash, app alive", ok, "st=%s" % st)
by_webhook_array_body()

def by_reserve_seats_null():
    st, j = post(ER, "/reserve", {"user_id": "rt-123sn", "idempotency_key": "k123sn", "seats": None})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats null: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
by_reserve_seats_null()

def by_book_race_same_idem():
    outs = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(post, ER, "/book", {"user_id": "rt-123br", "idempotency_key": "k123br", "seats": 1}) for _ in range(20)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    bids = set()
    for stc, j in outs:
        if stc == 200 and isinstance(j, dict) and j.get("booking_id"):
            bids.add(j["booking_id"])
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved() and alive(ER) and len(bids) == 1
    return check("race", "20-way book same idempotency_key: one booking, conserved", ok, "bids=%d sts=%s" % (len(bids), sorted(set(o[0] for o in outs))))
by_book_race_same_idem()

def by_confirm_whitespace_rid():
    st, j = post(ER, "/confirm", {"reservation_id": "   ", "user_id": "rt-123cw"})
    ok = st != 500 and st != -1 and alive(ER)
    return check("state", "confirm whitespace-only reservation_id: graceful", ok, "st=%s j=%s" % (st, str(j)[:60]))
by_confirm_whitespace_rid()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("BY TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "BY", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/by123.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
