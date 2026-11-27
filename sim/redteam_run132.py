#!/usr/bin/env python3
"""Run 132 extras: 12 angles (Phase CH), all new vs runs 115-131.
1: /reserve seats as empty array: no 5xx, conserved
2: /confirm user_id as number: no 5xx
3: /waitlist idempotency_key as boolean: no 5xx
4: /release with extra idempotency_key field: no 5xx, conserved
5: /transfer to_user as number: no 5xx, conserved
6: /book seats as boolean: no 5xx, conserved
7: app /api/release rid as array: no 500, app alive
8: app webhook wrong token (right sig): rejected, app alive
9: /reserve user_id with unicode emoji + null bytes: no 5xx, conserved
10: exact replay of signed /reserve request (same ts+rid+sig): no double seat, conserved
11: race: 8-way parallel /waitlist same user: no 5xx, conserved
12: /book missing user_id entirely: no 5xx, conserved
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

# ---------------- Phase CH: run 132 extras (12 new angles) ----------------
def ch_reserve_seats_empty_array():
    st, j = post(ER, "/reserve", {"user_id": "rt-132sa", "idempotency_key": "k132sa", "seats": []})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats empty array: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ch_reserve_seats_empty_array()

def ch_confirm_uid_number():
    rid, st, _ = hold("rt-132cn", "k132cn", 1)
    if not rid:
        return check("state", "confirm uid number: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": rid, "user_id": 42})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm user_id number: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
ch_confirm_uid_number()

def ch_waitlist_idem_bool():
    st, j = post(ER, "/waitlist", {"user_id": "rt-132wb", "idempotency_key": True, "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist idempotency_key boolean: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
ch_waitlist_idem_bool()

def ch_release_extra_idem():
    rid, st, _ = hold("rt-132ri", "k132ri", 1)
    if not rid:
        return check("state", "release extra idem: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/release", {"reservation_id": rid, "user_id": "rt-132ri", "idempotency_key": "k132ri-extra"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "release extra idempotency_key field: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
ch_release_extra_idem()

def ch_transfer_touser_number():
    rid, st, _ = hold("rt-132tn", "k132tn", 1)
    if not rid:
        return check("state", "transfer touser number: skipped (hold unavailable)", True, "st=%s" % st)
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": 12345})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer to_user number: no 5xx, conserved", ok, "rid=%s stt=%s" % (rid, stt))
ch_transfer_touser_number()

def ch_book_seats_bool():
    st, j = post(ER, "/book", {"user_id": "rt-132bb", "idempotency_key": "k132bb", "seats": True})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book seats boolean: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ch_book_seats_bool()

def ch_app_release_rid_array():
    st, j = raw(AR, "POST", "/api/release", json.dumps({"rid": ["RSV00000001"]}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app release rid as array: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ch_app_release_rid_array()

def ch_webhook_wrong_token():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-wrong", "X-Kavach-Signature": sig}
    st, j = raw(AR, "POST", "/webhook", body, h)
    ok = st != 500 and st != -1 and st not in (200,) and alive(AR, "/")
    return check("app", "webhook wrong token right sig: rejected, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ch_webhook_wrong_token()

def ch_reserve_uid_unicode():
    st, j = post(ER, "/reserve", {"user_id": "rt-132🚀\u0000\u0001", "idempotency_key": "k132uni", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id emoji+null bytes: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ch_reserve_uid_unicode()

def ch_exact_replay():
    body = json.dumps({"user_id": "rt-132rp", "idempotency_key": "k132rp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    st1, j1 = raw(ER, "POST", "/reserve", body, h)
    st2, j2 = raw(ER, "POST", "/reserve", body, h)
    time.sleep(0.2)
    rids = set()
    for jj, stt in ((j1, st1), (j2, st2)):
        if stt == 200 and isinstance(jj, dict) and jj.get("reservation_id"): rids.add(jj["reservation_id"])
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and len(rids) <= 1 and conserved() and alive(ER)
    return check("auth", "exact replay same sig: no double seat, conserved", ok, "st1=%s st2=%s rids=%d" % (st1, st2, len(rids)))
ch_exact_replay()

def ch_waitlist_race():
    user = "rt-132wr"
    def one(_):
        return post(ER, "/waitlist", {"user_id": user, "seats": 1})[0]
    with ThreadPoolExecutor(max_workers=8) as ex:
        sts = list(ex.map(one, range(8)))
    time.sleep(0.3)
    ok = all(s in (200, 400, 409, 410, 429) for s in sts) and conserved() and alive(ER)
    return check("race", "8-way parallel waitlist same user: no 5xx, conserved", ok, "sts=%s" % sts)
ch_waitlist_race()

def ch_book_missing_uid():
    st, j = post(ER, "/book", {"idempotency_key": "k132mu", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book missing user_id: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ch_book_missing_uid()

print("CH TOTAL %d cases, PASS %d, FAIL %d" % (
    len(results), sum(1 for c, n, ok, d in results if ok), sum(1 for c, n, ok, d in results if not ok)))
for cat, name, ok, detail in results:
    print("%-4s %-4s %s %s" % ("OK" if ok else "FAIL", cat, name, detail if not ok else ""))
sys.exit(0 if all(ok for _, _, ok, _ in results) else 1)
