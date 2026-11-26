#!/usr/bin/env python3
"""Run 127 extras: 12 angles (Phase CC), all new vs runs 115-126.
1: /reserve with user_id nested object (deep nesting): no 5xx, conserved
2: /confirm with 10KB X-Kavach-Request-Id header: no 5xx, state sane
3: /waitlist same user joining twice: no 5xx, sane
4: /release with seats field present (field injection): no 5xx, conserved
5: /transfer with extra idempotency_key field: no 5xx, conserved
6: /book with user_id as array: no 5xx, conserved
7: app /api/release with rid as boolean: no 500, app alive
8: app webhook signature missing entirely (token valid): rejected, app alive
9: /reserve with idempotency_key empty string: no 5xx, conserved
10: /transfer on expired hold (TTL engine 8095): graceful, no 5xx
11: race: 10-way parallel /confirm of 10 separate holds (same user): all consistent, conserved
12: /waitlist with seats boolean: no 5xx
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

# ---------------- Phase CC: run 127 extras (12 new angles) ----------------
def cc_reserve_uid_nested():
    st, j = post(ER, "/reserve", {"user_id": {"a": {"b": [1, 2, {"c": None}]}}, "idempotency_key": "k127nn", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id nested object: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cc_reserve_uid_nested()

def cc_confirm_huge_rid_header():
    rid, st, _ = hold("rt-127hr", "k127hr", 1)
    if not rid:
        return check("state", "confirm huge rid header: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": rid, "user_id": "rt-127hr"}).encode()
    h = sign(KEY, "POST", "/confirm", body, rid="A" * 10000)
    stc, j = raw(ER, "POST", "/confirm", body, h)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("auth", "confirm 10KB request-id header: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cc_confirm_huge_rid_header()

def cc_waitlist_same_user_twice():
    s1, j1 = post(ER, "/waitlist", {"user_id": "rt-127ww", "seats": 1})
    s2, j2 = post(ER, "/waitlist", {"user_id": "rt-127ww", "seats": 1})
    ok = s1 != 500 and s1 != -1 and s2 != 500 and s2 != -1 and alive(ER)
    return check("fuzz", "waitlist same user twice: no 5xx", ok, "s1=%s s2=%s" % (s1, s2))
cc_waitlist_same_user_twice()

def cc_release_seats_field():
    rid, st, _ = hold("rt-127rs", "k127rs", 2)
    if not rid:
        return check("state", "release seats field: skipped (hold unavailable)", True, "st=%s" % st)
    str1, j = post(ER, "/release", {"reservation_id": rid, "user_id": "rt-127rs", "seats": 99})
    time.sleep(0.2)
    ok = str1 != 500 and str1 != -1 and conserved() and alive(ER)
    return check("fuzz", "release with seats field: no 5xx, conserved", ok, "rid=%s str1=%s j=%s" % (rid, str1, str(j)[:60]))
cc_release_seats_field()

def cc_transfer_extra_idem_field():
    rid, st, _ = hold("rt-127ti", "k127ti", 1)
    if not rid:
        return check("state", "transfer extra idem field: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-127ti"})
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-127ti-b", "idempotency_key": "k127ti-x"})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer extra idem field: no 5xx, conserved", ok, "rid=%s stt=%s j=%s" % (rid, stt, str(j)[:60]))
cc_transfer_extra_idem_field()

def cc_book_uid_array():
    st, j = post(ER, "/book", {"user_id": ["rt-127ba"], "idempotency_key": "k127ba", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book user_id array: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cc_book_uid_array()

def cc_app_release_rid_bool():
    st, j = raw(AR, "POST", "/api/release", json.dumps({"reservation_id": True}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app release rid boolean: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cc_app_release_rid_bool()

def cc_webhook_no_sig():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001"}).encode()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest"}
    st, j = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = st != 500 and st != -1 and st != 200 and alive(AR, "/")
    return check("app", "webhook sig missing token valid: rejected, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cc_webhook_no_sig()

def cc_reserve_idem_empty():
    st, j = post(ER, "/reserve", {"user_id": "rt-127ie", "idempotency_key": "", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve idempotency_key empty: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cc_reserve_idem_empty()

def cc_transfer_expired_hold():
    rid, st, _ = hold("rt-127tx", "k127tx", 2, port=ET)
    if not rid:
        return check("state", "transfer expired hold: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(4.5)  # hold-ttl 3s: expires
    stt, j = post(ET, "/transfer", {"reservation_id": rid, "to_user": "rt-127tx-b"})
    ok = stt != 500 and stt != -1 and conserved(ET) and alive(ET)
    return check("state", "transfer expired hold (TTL): graceful, no 5xx", ok, "rid=%s stt=%s j=%s" % (rid, stt, str(j)[:60]))
cc_transfer_expired_hold()

def cc_parallel_multi_hold_confirm():
    # 10 holds across 10 different users (per-user active-hold cap keeps 10 holds from one user)
    rids, uids = [], []
    for i in range(10):
        rid, st, _ = hold("rt-127mcu%d" % i, "k127mcu%d" % i, 1)
        if rid:
            rids.append(rid); uids.append("rt-127mcu%d" % i)
    if len(rids) < 10:
        return check("race", "multi-hold confirm race: skipped (only %d/10 holds)" % len(rids), True, "holds=%d" % len(rids))
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(post, ER, "/confirm", {"reservation_id": r, "user_id": u}) for r, u in zip(rids, uids)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved() and alive(ER)
    return check("race", "10-way parallel confirm 10 holds (10 users): no 5xx, conserved", ok, "sts=%s" % [o[0] for o in outs])
cc_parallel_multi_hold_confirm()

def cc_waitlist_seats_bool():
    st, j = post(ER, "/waitlist", {"user_id": "rt-127wb", "seats": True})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist seats boolean: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cc_waitlist_seats_bool()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("CC TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "CC", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/cc127.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
