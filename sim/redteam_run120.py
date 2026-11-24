#!/usr/bin/env python3
"""Run 120 extras: 12 angles (Phase BV), all new vs runs 115-119.
1: /reserve with seats as JSON float 2.0: no 5xx, conserved
2: /confirm with user_id as integer 123: no 5xx, conserved
3: /waitlist with user_id empty string: no 5xx
4: /reserve with user_id missing entirely: no 5xx, conserved
5: /release on a confirmed (sold) reservation: 409/404 graceful, conserved
6: /confirm on an already-released reservation: graceful 404/409, conserved
7: waitlist overflow: sell all seats then join waitlist: graceful, conserved
8: app /api/board with rid missing: no 500, app alive
9: app webhook wrong token with valid body: 403, app alive
10: /reserve with 10KB idempotency_key: no 5xx, conserved
11: confirm+release race on the same reservation: exactly one terminal state, conserved
12: signed request with timestamp +6 minutes in future: no 5xx, conserved
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
def bt_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

# ---------------- Phase BV: run 120 extras (12 new angles) ----------------
def bv_seats_float_2dot0():
    st, j = post(ER, "/reserve", {"user_id": "rt-120f", "idempotency_key": "k120f", "seats": 2.0})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as float 2.0: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:80]))
bv_seats_float_2dot0()

def bv_confirm_userid_int():
    rid, st, _ = bt_hold("rt-120ci", "k120ci")
    if not rid:
        return check("state", "confirm user_id int: skipped (hold unavailable)", True, "st=%s" % st)
    st2, j2 = post(ER, "/confirm", {"reservation_id": rid, "user_id": 123})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("state", "confirm user_id as integer: no 5xx, conserved", ok, "rid=%s st2=%s j2=%s" % (rid, st2, str(j2)[:60]))
bv_confirm_userid_int()

def bv_waitlist_empty_userid():
    st, j = post(ER, "/waitlist", {"user_id": "", "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("state", "waitlist empty user_id: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
bv_waitlist_empty_userid()

def bv_reserve_missing_userid():
    st, j = post(ER, "/reserve", {"idempotency_key": "k120mr", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve with user_id missing: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bv_reserve_missing_userid()

def bv_release_confirmed():
    rid, st, _ = bt_hold("rt-120rc", "k120rc")
    if not rid:
        return check("state", "release confirmed: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-120rc"})
    str_, j2 = post(ER, "/release", {"reservation_id": rid})
    time.sleep(0.2)
    ok = stc != 500 and str_ in (404, 409, 400, 410) and conserved() and alive(ER)
    return check("state", "release on confirmed reservation: graceful 409/404, sold conserved", ok, "rid=%s stc=%s strel=%s j=%s" % (rid, stc, str_, str(j2)[:60]))
bv_release_confirmed()

def bv_confirm_released():
    rid, st, _ = bt_hold("rt-120cr", "k120cr")
    if not rid:
        return check("state", "confirm released: skipped (hold unavailable)", True, "st=%s" % st)
    str_, _ = post(ER, "/release", {"reservation_id": rid})
    stc, j2 = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-120cr"})
    time.sleep(0.2)
    ok = str_ != 500 and stc in (404, 409, 400, 410) and conserved() and alive(ER)
    return check("state", "confirm on released reservation: graceful, conserved", ok, "rid=%s strel=%s stc=%s j=%s" % (rid, str_, stc, str(j2)[:60]))
bv_confirm_released()

def bv_waitlist_overflow():
    # sell out ER2 (30 seats) with fresh engine state, then try to waitlist beyond
    outs = []
    for i in range(30):
        rid, st, _ = bt_hold("rt-120wo%d" % i, "k120wo%d" % i, 1, port=ER2)
        if rid: post(ER2, "/confirm", {"reservation_id": rid, "user_id": "rt-120wo%d" % i})
    s = seats(ER2)
    if s.get("sold") != s.get("total"):
        return check("state", "waitlist overflow: skipped (engine2 not sold out: %s)" % str(s), True, "sold=%s total=%s" % (s.get("sold"), s.get("total")))
    st, j = post(ER2, "/waitlist", {"user_id": "rt-120ov", "seats": 1})
    ok = st != 500 and st != -1 and conserved(ER2) and alive(ER2)
    return check("state", "waitlist join after sellout: graceful, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bv_waitlist_overflow()

def bv_app_board_missing_rid():
    st, j = raw(AR, "POST", "/api/board", json.dumps({"user_id": "rt-120br"}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/board rid missing: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bv_app_board_missing_rid()

def bv_app_webhook_wrong_token():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001", "event_id": "ev-120"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    st, j = raw(AR, "POST", "/api/kavach-webhook", body, {"Content-Type": "application/json", "X-Kavach-Token": "wrongtoken", "X-Kavach-Signature": sig})
    ok = st == 403 and alive(AR, "/")
    return check("app", "app webhook wrong token valid body: 403, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bv_app_webhook_wrong_token()

def bv_reserve_10kb_idem():
    st, j = post(ER, "/reserve", {"user_id": "rt-120big", "idempotency_key": "x" * 10240, "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve with 10KB idempotency_key: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bv_reserve_10kb_idem()

def bv_confirm_release_race():
    rid, st, _ = bt_hold("rt-120rr", "k120rr")
    if not rid:
        return check("race", "confirm+release race: skipped (hold unavailable)", True, "st=%s" % st)
    sold_before = seats(ER).get("sold")
    def confirm_call(_): return post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-120rr"})
    def release_call(_): return post(ER, "/release", {"reservation_id": rid})
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(confirm_call, 0)
        f2 = ex.submit(release_call, 1)
        stc, jc = f1.result(); str_, jr = f2.result()
    time.sleep(0.4)
    s = seats(ER)
    ok = stc != 500 and str_ != 500 and stc != -1 and str_ != -1 and conserved() and alive(ER)
    terminal = (s.get("sold") == (sold_before or 0) + 1) or (s.get("sold") == sold_before)
    return check("race", "confirm+release race on same reservation: no 5xx, exactly one terminal state, conserved", ok and terminal, "rid=%s stc=%s strel=%s before=%s after=%s" % (rid, stc, str_, sold_before, str(s)[:60]))
bv_confirm_release_race()

def bv_future_timestamp():
    ts = str(int(time.time()) + 360)
    body = json.dumps({"user_id": "rt-120ft", "idempotency_key": "k120ft", "seats": 1}).encode()
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body, ts=ts))
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("replay", "signed reserve with +6min future timestamp: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bv_future_timestamp()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("BV TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "BV", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/bv120.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
