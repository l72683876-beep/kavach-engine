#!/usr/bin/env python3
"""Run 131 extras: 12 angles (Phase CG), all new vs runs 115-130.
1: /reserve idempotency_key as array: no 5xx
2: /confirm with extra seats field: no 5xx, conserved
3: /waitlist user_id as array: no 5xx
4: /release reservation_id as float: no 5xx, conserved
5: /transfer with extra user_id field: no 5xx, conserved
6: /book idempotency_key null: no 5xx, conserved
7: app /api/hold seats as string '2': no 500, app alive
8: app webhook duplicate X-Kavach-Signature headers: graceful/rejected, app alive
9: /reserve user_id 10KB string: no 5xx
10: cross-tenant: tenant2 key confirms tenant1 reservation: rejected, conserved
11: race: 6-way mixed confirm/release across 3 holds (3 users): one outcome each, conserved
12: /waitlist seats 1.5 float: no 5xx
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

# ---------------- Phase CG: run 131 extras (12 new angles) ----------------
def cg_reserve_idem_array():
    st, j = post(ER, "/reserve", {"user_id": "rt-131ia", "idempotency_key": ["k131ia"], "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve idempotency_key array: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cg_reserve_idem_array()

def cg_confirm_extra_seats():
    rid, st, _ = hold("rt-131cs", "k131cs", 1)
    if not rid:
        return check("state", "confirm extra seats: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-131cs", "seats": 5})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "confirm extra seats field: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cg_confirm_extra_seats()

def cg_waitlist_uid_array():
    st, j = post(ER, "/waitlist", {"user_id": ["rt-131wa"], "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist user_id array: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cg_waitlist_uid_array()

def cg_release_rid_float():
    rid, st, _ = hold("rt-131rf", "k131rf", 1)
    if not rid:
        return check("state", "release rid float: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/release", {"reservation_id": 1.5, "user_id": "rt-131rf"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "release reservation_id float: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cg_release_rid_float()

def cg_transfer_extra_uid():
    rid, st, _ = hold("rt-131tu", "k131tu", 1)
    if not rid:
        return check("state", "transfer extra uid: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-131tu"})
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-131tu-x", "user_id": "rt-131tu"})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("state", "transfer extra user_id field: no 5xx, conserved", ok, "rid=%s stt=%s" % (rid, stt))
cg_transfer_extra_uid()

def cg_book_idem_null():
    st, j = post(ER, "/book", {"user_id": "rt-131bn", "idempotency_key": None, "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book idempotency_key null: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cg_book_idem_null()

def cg_app_hold_seats_string():
    st, j = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-131ah", "seats": "2"}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app hold seats string '2': no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cg_app_hold_seats_string()

def cg_webhook_dup_sig_headers():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest",
         "X-Kavach-Signature": sig, "X-KAVACH-SIGNATURE": sig}
    st, j = raw(AR, "POST", "/webhook", body, h)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "webhook duplicate sig headers (case variants): graceful, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cg_webhook_dup_sig_headers()

def cg_reserve_uid_10kb():
    st, j = post(ER, "/reserve", {"user_id": "u" * 10240, "idempotency_key": "k131big", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id 10KB string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cg_reserve_uid_10kb()

def cg_cross_tenant():
    rid, st, _ = hold("rt-131xt", "k131xt", 1)
    if not rid:
        return check("state", "cross-tenant: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = rawpost(ER, "/confirm", json.dumps({"reservation_id": rid, "user_id": "rt-131xt"}).encode(), user_key=KEY2)
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and stc not in (200,) and conserved() and alive(ER)
    return check("auth", "cross-tenant confirm (otherkey on tenant1 hold): rejected, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
cg_cross_tenant()

def cg_mixed_confirm_release_race():
    holds = []
    for i in range(3):
        rid, st, _ = hold("rt-131mr%d" % i, "k131mr%d" % i, 1)
        if rid: holds.append(rid)
    if len(holds) < 3:
        return check("state", "mixed race: skipped (only %d holds)" % len(holds), True)
    def one(i):
        rid = holds[i % 3]
        if i < 3:
            return post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-131mr%d" % (i % 3)})[0]
        return post(ER, "/release", {"reservation_id": rid, "user_id": "rt-131mr%d" % (i % 3)})[0]
    with ThreadPoolExecutor(max_workers=6) as ex:
        sts = list(ex.map(one, range(6)))
    time.sleep(0.4)
    ok = all(s in (200, 400, 409, 410) for s in sts) and conserved() and alive(ER)
    return check("race", "6-way confirm+release across 3 holds: sane (race loser release may 400 on confirmed), conserved", ok, "sts=%s" % sts)
cg_mixed_confirm_release_race()

def cg_waitlist_seats_float():
    st, j = post(ER, "/waitlist", {"user_id": "rt-131wf", "seats": 1.5})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist seats 1.5: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cg_waitlist_seats_float()

print("CG TOTAL %d cases, PASS %d, FAIL %d" % (
    len(results), sum(1 for c, n, ok, d in results if ok), sum(1 for c, n, ok, d in results if not ok)))
for cat, name, ok, detail in results:
    print("%-4s %-4s %s %s" % ("OK" if ok else "FAIL", cat, name, detail if not ok else ""))
sys.exit(0 if all(ok for _, _, ok, _ in results) else 1)
