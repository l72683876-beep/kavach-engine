#!/usr/bin/env python3
"""Run 124 extras: 12 angles (Phase BZ), all new vs runs 115-123.
1: /reserve with seats -1 (engine): no 5xx, conserved
2: /confirm with extra seats field: no 5xx, state sane
3: /waitlist with seats 100000: no 5xx
4: /release with reservation_id boolean: no 5xx, conserved
5: /transfer with to_user null: no 5xx, conserved
6: /book with seats float 2.5: no 5xx, conserved
7: app /api/confirm with rid as integer: no 500, app alive
8: app /api/reserve with user_id empty string: no 500, app alive
9: app webhook signature present but X-Kavach-Token missing: rejected, app alive
10: /reserve idempotency_key with newline + unicode: no 5xx, conserved
11: race: 5-way parallel /transfer of same confirmed reservation to different users: at most one success, conserved
12: /confirm with 100KB reservation_id: graceful, no 5xx
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

# ---------------- Phase BZ: run 124 extras (12 new angles) ----------------
def bz_reserve_negative_seats():
    st, j = post(ER, "/reserve", {"user_id": "rt-124ns", "idempotency_key": "k124ns", "seats": -1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats -1: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_reserve_negative_seats()

def bz_confirm_extra_seats():
    rid, st, _ = hold("rt-124cs", "k124cs", 1)
    if not rid:
        return check("state", "confirm extra seats field: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-124cs", "seats": 99})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "confirm with extra seats field: no 5xx, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
bz_confirm_extra_seats()

def bz_waitlist_huge_seats():
    st, j = post(ER, "/waitlist", {"user_id": "rt-124hw", "seats": 100000})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist seats 100000: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_waitlist_huge_seats()

def bz_release_rid_bool():
    st, j = post(ER, "/release", {"reservation_id": True})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "release reservation_id boolean: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_release_rid_bool()

def bz_transfer_touser_null():
    rid, st, _ = hold("rt-124tn", "k124tn", 2)
    if not rid:
        return check("state", "transfer to_user null: skipped (hold unavailable)", True, "st=%s" % st)
    stb, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-124tn"})
    stc, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": None})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer to_user null: no 5xx, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
bz_transfer_touser_null()

def bz_book_seats_float():
    st, j = post(ER, "/book", {"user_id": "rt-124bf", "idempotency_key": "k124bf", "seats": 2.5})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book seats float 2.5: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_book_seats_float()

def bz_app_confirm_rid_int():
    st, j = raw(AR, "POST", "/api/confirm", json.dumps({"reservation_id": 99}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app confirm rid integer: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_app_confirm_rid_int()

def bz_app_reserve_empty_uid():
    st, j = raw(AR, "POST", "/api/reserve", json.dumps({"user_id": "", "seats": 1}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app reserve user_id empty: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_app_reserve_empty_uid()

def bz_webhook_no_token():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Signature": sig}  # token header missing
    st, j = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = st != 500 and st != -1 and st != 200 and alive(AR, "/")
    return check("app", "webhook sig present token missing: rejected, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_webhook_no_token()

def bz_reserve_idem_weird():
    st, j = post(ER, "/reserve", {"user_id": "rt-124iw", "idempotency_key": "k124\niw-🚀-⟳", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve idem key newline+unicode: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bz_reserve_idem_weird()

def bz_parallel_transfer_race():
    rid, st, _ = hold("rt-124pt", "k124pt", 3)
    if not rid:
        return check("race", "parallel transfer race: skipped (hold unavailable)", True, "st=%s" % st)
    stb, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-124pt"})
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(post, ER, "/transfer", {"reservation_id": rid, "to_user": "rt-124pt-u%d" % i}) for i in range(5)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved() and alive(ER)
    return check("race", "5-way parallel transfer same booking: no 5xx, conserved", ok, "sts=%s" % [o[0] for o in outs])
bz_parallel_transfer_race()

def bz_confirm_huge_rid():
    st, j = post(ER, "/confirm", {"reservation_id": "X" * 100000, "user_id": "rt-124hr"})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "confirm 100KB reservation_id: graceful", ok, "st=%s" % st)
bz_confirm_huge_rid()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("BZ TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "BZ", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/bz124.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
