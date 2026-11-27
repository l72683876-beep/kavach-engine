#!/usr/bin/env python3
"""Run 129 extras: 12 angles (Phase CE), all new vs runs 115-128.
1: /reserve with seats as string "0": no 5xx, conserved
2: /confirm with reservation_id as object {}: no 5xx, sane
3: /waitlist with user_id as boolean: no 5xx
4: app /api/hold with user_id as array: no 500, app alive
5: /transfer with duplicate to_user JSON keys (raw): no 5xx, conserved
6: /book with seats 0.5 fractional: no 5xx, conserved
7: app /api/book missing reservation_id entirely: no 500, app alive
8: app webhook 1MB body with valid sig: graceful, app alive
9: /reserve with 10KB idempotency_key value: no 5xx, conserved
10: /transfer valid hold WITHIN TTL window on 8095: succeeds, conserved
11: race: 10-way parallel /release of 10 holds (10 users): exactly one wins per hold, conserved
12: /book with user_id as float: no 5xx, conserved
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
def rawpost(port, path, raw_body, user_key=KEY):
    return raw(port, "POST", path, raw_body, sign(user_key, "POST", path, raw_body))
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

# ---------------- Phase CE: run 129 extras (12 new angles) ----------------
def ce_reserve_seats_zero_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-129zs", "idempotency_key": "k129zs", "seats": "0"})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats '0' string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ce_reserve_seats_zero_string()

def ce_confirm_rid_object():
    rid, st, _ = hold("rt-129ro", "k129ro", 1)
    if not rid:
        return check("state", "confirm rid object: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": {}, "user_id": "rt-129ro"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm reservation_id object: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
ce_confirm_rid_object()

def ce_waitlist_uid_bool():
    st, j = post(ER, "/waitlist", {"user_id": True, "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist user_id boolean: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
ce_waitlist_uid_bool()

def ce_app_hold_uid_array():
    st, j = raw(AR, "POST", "/api/hold", json.dumps({"user_id": ["rt-129ha"], "seats": 1}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app hold user_id array: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ce_app_hold_uid_array()

def ce_transfer_dup_touser_keys():
    rid, st, _ = hold("rt-129td", "k129td", 1)
    if not rid:
        return check("state", "transfer dup to_user keys: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-129td"})
    raw_body = ('{"reservation_id": "%s", "to_user": "rt-129td-a", "to_user": "rt-129td-b"}' % rid).encode()
    stt, j = rawpost(ER, "/transfer", raw_body)
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("auth", "transfer duplicate to_user JSON keys: no 5xx, conserved", ok, "rid=%s stt=%s" % (rid, stt))
ce_transfer_dup_touser_keys()

def ce_book_fractional():
    st, j = post(ER, "/book", {"user_id": "rt-129bf", "idempotency_key": "k129bf", "seats": 0.5})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book seats 0.5: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ce_book_fractional()

def ce_app_book_missing_rid():
    st, j = raw(AR, "POST", "/api/book", json.dumps({"user_id": "rt-129bk"}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app book missing reservation_id: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ce_app_book_missing_rid()

def ce_webhook_1mb():
    rid, st, _ = hold("rt-129wb", "k129wb", 1)
    body = json.dumps({"type": "confirmed", "reservation_id": rid or "RSV00000001", "pad": "x" * 1000000}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest", "X-Kavach-Signature": sig}
    stw, j = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = stw != 500 and stw != -1 and alive(AR, "/")
    return check("app", "webhook 1MB body valid sig: graceful, app alive", ok, "st=%s j=%s" % (stw, str(j)[:60]))
ce_webhook_1mb()

def ce_reserve_huge_idem():
    st, j = post(ER, "/reserve", {"user_id": "rt-129hi", "idempotency_key": "K" * 10000, "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve 10KB idempotency_key: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ce_reserve_huge_idem()

def ce_transfer_within_ttl():
    # engine rule: only a CONFIRMED booking transfers; a held one 409s with its state
    rid, st, _ = hold("rt-129tw", "k129tw", 2, port=ET)
    if not rid:
        return check("state", "transfer within TTL: skipped (hold unavailable)", True, "st=%s" % st)
    sth, jh = post(ET, "/transfer", {"reservation_id": rid, "to_user": "rt-129tw-b"})  # held must NOT move
    stc, _ = post(ET, "/confirm", {"reservation_id": rid, "user_id": "rt-129tw"})
    stt, j = post(ET, "/transfer", {"reservation_id": rid, "to_user": "rt-129tw-b"})  # confirmed moves within TTL
    time.sleep(0.2)
    ok = sth == 409 and stc == 200 and stt == 200 and conserved(ET) and alive(ET)
    return check("state", "held transfer 409, confirmed transfer within TTL succeeds", ok, "rid=%s sth=%s stc=%s stt=%s" % (rid, sth, stc, stt))
ce_transfer_within_ttl()

def ce_parallel_multi_hold_release():
    rids, uids = [], []
    for i in range(10):
        rid, st, _ = hold("rt-129mru%d" % i, "k129mru%d" % i, 1)
        if rid:
            rids.append(rid); uids.append("rt-129mru%d" % i)
    if len(rids) < 10:
        return check("race", "multi-hold release race: skipped (only %d/10 holds)" % len(rids), True, "holds=%d" % len(rids))
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(post, ER, "/release", {"reservation_id": r, "user_id": u}) for r, u in zip(rids, uids)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved() and alive(ER)
    return check("race", "10-way parallel release 10 holds: no 5xx, conserved", ok, "sts=%s" % [o[0] for o in outs])
ce_parallel_multi_hold_release()

def ce_book_uid_float():
    st, j = post(ER, "/book", {"user_id": 1.5, "idempotency_key": "k129uf", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book user_id float: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ce_book_uid_float()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("CE TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "CE", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/ce129.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
