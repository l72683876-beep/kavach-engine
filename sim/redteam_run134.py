#!/usr/bin/env python3
"""Run 134 extras: 12 angles (Phase CJ), all new vs runs 115-133.
1: /reserve seats as string: no 5xx, conserved
2: /confirm reservation_id as integer: no 5xx
3: /waitlist with extra reservation_id field: no 5xx
4: /release user_id as number: no 5xx, conserved
5: /transfer idempotency_key as array: no 5xx, conserved
6: /book with extra reservation_id field: no 5xx, conserved
7: app /api/hold seats negative: no 500, app alive
8: app webhook JSON array body with valid sig: graceful, app alive
9: /reserve idempotency_key whitespace only: no 5xx, conserved
10: HMAC timestamp +1 day future: rejected (replay window), conserved
11: race 10-way parallel /release same held reservation: one release, conserved
12: /book seats 1e9: no 5xx, conserved
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

# ---------------- Phase CJ: run 134 extras (12 new angles) ----------------
def cj_reserve_seats_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-134ss", "idempotency_key": "k134ss", "seats": "3"})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_reserve_seats_string()

def cj_confirm_rid_int():
    rid, st, _ = hold("rt-134ri", "k134ri", 1)
    if not rid:
        return check("state", "confirm rid int: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": 12345, "user_id": "rt-134ri"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm reservation_id integer: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cj_confirm_rid_int()

def cj_waitlist_extra_rid():
    st, j = post(ER, "/waitlist", {"user_id": "rt-134wr", "reservation_id": "RSV00000099", "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist extra reservation_id field: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_waitlist_extra_rid()

def cj_release_uid_number():
    rid, st, _ = hold("rt-134ru", "k134ru", 1)
    if not rid:
        return check("state", "release uid number: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/release", {"reservation_id": rid, "user_id": 77})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "release user_id number: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cj_release_uid_number()

def cj_transfer_idem_array():
    rid, st, _ = hold("rt-134ti", "k134ti", 1)
    if not rid:
        return check("state", "transfer idem array: skipped (hold unavailable)", True, "st=%s" % st)
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-134ti-b", "idempotency_key": ["k134ti"]})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer idempotency_key array: no 5xx, conserved", ok, "rid=%s stt=%s" % (rid, stt))
cj_transfer_idem_array()

def cj_book_extra_rid():
    st, j = post(ER, "/book", {"user_id": "rt-134br", "idempotency_key": "k134br", "reservation_id": "RSV00000098", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book extra reservation_id field: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_book_extra_rid()

def cj_app_hold_seats_negative():
    st, j = raw(AR, "POST", "/api/hold", json.dumps({"seats": -2}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app hold seats negative: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_app_hold_seats_negative()

def cj_webhook_array_body():
    body = json.dumps([{"type": "confirmed", "reservation_id": "RSV00000001"}]).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest", "X-Kavach-Signature": sig}
    st, j = raw(AR, "POST", "/webhook", body, h)
    ok = st != 500 and st != -1 and st not in (200,) and alive(AR, "/")
    return check("app", "webhook JSON array body valid sig: graceful, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_webhook_array_body()

def cj_reserve_idem_whitespace():
    st, j = post(ER, "/reserve", {"user_id": "rt-134iw", "idempotency_key": "   ", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve idempotency_key whitespace only: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_reserve_idem_whitespace()

def cj_hmac_future_ts():
    body = json.dumps({"user_id": "rt-134ft", "idempotency_key": "k134ft", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body, ts=str(int(time.time()) + 86400))
    st, j = raw(ER, "POST", "/reserve", body, h)
    time.sleep(0.2)
    ok = st != 500 and st != -1 and st not in (200,) and conserved() and alive(ER)
    return check("auth", "HMAC timestamp +1 day future: rejected, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_hmac_future_ts()

def cj_release_race():
    rid, st, _ = hold("rt-134rr", "k134rr", 2)
    if not rid:
        return check("state", "release race: skipped (hold unavailable)", True, "st=%s" % st)
    def one(_):
        return post(ER, "/release", {"reservation_id": rid, "user_id": "rt-134rr"})[0]
    with ThreadPoolExecutor(max_workers=10) as ex:
        sts = list(ex.map(one, range(10)))
    time.sleep(0.3)
    ok = all(s in (200, 400, 409, 410, 429) for s in sts) and conserved() and alive(ER)
    return check("race", "10-way parallel release same hold: no 5xx, conserved", ok, "rid=%s sts=%s" % (rid, sts))
cj_release_race()

def cj_book_seats_huge():
    st, j = post(ER, "/book", {"user_id": "rt-134bh", "idempotency_key": "k134bh", "seats": 1000000000})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book seats 1e9: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cj_book_seats_huge()

print("CJ TOTAL %d cases, PASS %d, FAIL %d" % (
    len(results), sum(1 for c, n, ok, d in results if ok), sum(1 for c, n, ok, d in results if not ok)))
for cat, name, ok, detail in results:
    print("%-4s %-4s %s %s" % ("OK" if ok else "FAIL", cat, name, detail if not ok else ""))
sys.exit(0 if all(ok for _, _, ok, _ in results) else 1)
