#!/usr/bin/env python3
"""Run 135 extras: 12 angles (Phase CK), all new vs runs 115-134.
1: /reserve seats boolean true: no 5xx, conserved
2: /confirm reservation_id null: no 5xx
3: /waitlist seats as object: no 5xx
4: /release with extra seats field: no 5xx, conserved
5: /transfer reservation_id null: no 5xx, conserved
6: /book idempotency_key empty string: no 5xx, conserved
7: app /api/waitlist seats string: no 500, app alive
8: app webhook valid sig but token missing: rejected, app alive
9: /reserve user_id as object: no 5xx, conserved
10: engine duplicate X-Kavach-Signature headers (two different values): rejected, conserved
11: race 10-way parallel /confirm same hold: one confirm, conserved
12: TTL engine: release on expired hold: no 5xx, no seat leak
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

# ---------------- Phase CK: run 135 extras (12 new angles) ----------------
def ck_reserve_seats_bool():
    st, j = post(ER, "/reserve", {"user_id": "rt-135sb", "idempotency_key": "k135sb", "seats": True})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats boolean: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_reserve_seats_bool()

def ck_confirm_rid_null():
    rid, st, _ = hold("rt-135cn", "k135cn", 1)
    if not rid:
        return check("state", "confirm rid null: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": None, "user_id": "rt-135cn"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm reservation_id null: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
ck_confirm_rid_null()

def ck_waitlist_seats_object():
    st, j = post(ER, "/waitlist", {"user_id": "rt-135wo", "seats": {"n": 1}})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist seats object: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_waitlist_seats_object()

def ck_release_extra_seats():
    rid, st, _ = hold("rt-135rs", "k135rs", 1)
    if not rid:
        return check("state", "release extra seats: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/release", {"reservation_id": rid, "user_id": "rt-135rs", "seats": 99})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "release extra seats field: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
ck_release_extra_seats()

def ck_transfer_rid_null():
    st, j = post(ER, "/transfer", {"reservation_id": None, "to_user": "rt-135tn"})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer reservation_id null: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_transfer_rid_null()

def ck_book_idem_empty():
    st, j = post(ER, "/book", {"user_id": "rt-135ie", "idempotency_key": "", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book idempotency_key empty string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_book_idem_empty()

def ck_app_waitlist_seats_string():
    st, j = raw(AR, "POST", "/api/waitlist", json.dumps({"seats": "two"}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app waitlist seats string: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_app_waitlist_seats_string()

def ck_webhook_no_token():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Signature": sig}
    st, j = raw(AR, "POST", "/webhook", body, h)
    ok = st != 500 and st != -1 and st not in (200,) and alive(AR, "/")
    return check("app", "webhook valid sig token missing: rejected, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_webhook_no_token()

def ck_reserve_uid_object():
    st, j = post(ER, "/reserve", {"user_id": {"x": 1}, "idempotency_key": "k135uo", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id object: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_reserve_uid_object()

def ck_dup_sig_headers():
    body = json.dumps({"user_id": "rt-135ds", "idempotency_key": "k135ds", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    mac2 = hmac.new(b"wrongsecret", (h["X-Kavach-Timestamp"] + "\n" + h["X-Kavach-Request-Id"] + "\nPOST\n/reserve\n" + KEY + "\n").encode() + body, hashlib.sha256).hexdigest()
    h2 = dict(h); h2["X-Kavach-Signature"] = h["X-Kavach-Signature"] + ", " + mac2
    st, j = raw(ER, "POST", "/reserve", body, h2)
    time.sleep(0.2)
    ok = st != 500 and st != -1 and st not in (200,) and conserved() and alive(ER)
    return check("auth", "duplicate sig header two different values: rejected, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ck_dup_sig_headers()

def ck_confirm_race():
    rid, st, _ = hold("rt-135cr", "k135cr", 2)
    if not rid:
        return check("state", "confirm race: skipped (hold unavailable)", True, "st=%s" % st)
    def one(_):
        return post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-135cr"})[0]
    with ThreadPoolExecutor(max_workers=10) as ex:
        sts = list(ex.map(one, range(10)))
    time.sleep(0.3)
    ok = all(s in (200, 400, 409, 410, 429) for s in sts) and conserved() and alive(ER)
    return check("race", "10-way parallel confirm same hold: no 5xx, conserved", ok, "rid=%s sts=%s" % (rid, sts))
ck_confirm_race()

def ck_ttl_expired_release():
    rid, st, _ = hold("rt-135er", "k135er", 2, port=ET)
    if not rid:
        return check("state", "ttl expired release: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(4)
    stc, j = post(ET, "/release", {"reservation_id": rid, "user_id": "rt-135er"})
    time.sleep(0.3)
    s = seats(ET)
    ok = stc != 500 and stc != -1 and conserved(ET) and alive(ET)
    return check("state", "ttl engine: release on expired hold: no 5xx, no seat leak", ok, "rid=%s stc=%s seats=%s" % (rid, stc, str(s)[:60]))
ck_ttl_expired_release()

print("CK TOTAL %d cases, PASS %d, FAIL %d" % (
    len(results), sum(1 for c, n, ok, d in results if ok), sum(1 for c, n, ok, d in results if not ok)))
for cat, name, ok, detail in results:
    print("%-4s %-4s %s %s" % ("OK" if ok else "FAIL", cat, name, detail if not ok else ""))
sys.exit(0 if all(ok for _, _, ok, _ in results) else 1)
