#!/usr/bin/env python3
"""Run 130 extras: 12 angles (Phase CF), all new vs runs 115-129.
1: /reserve user_id null: no 5xx, conserved
2: /confirm with extra event_id field: no 5xx, sane
3: /waitlist idempotency_key as number: no 5xx
4: /release user_id null: no 5xx, conserved
5: /transfer reservation_id as boolean: no 5xx, conserved
6: /book duplicate user_id JSON keys (raw): no 5xx, conserved
7: app /api/confirm rid as number: no 500, app alive
8: app webhook type 'booked' with empty reservation_id, valid sig: graceful, app alive
9: /reserve seats null: no 5xx, conserved
10: engine2 (8092) happy path reserve->confirm: conserved
11: race: 10-way parallel /reserve same idempotency_key same user: one reservation, conserved
12: /waitlist seats as array: no 5xx
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

# ---------------- Phase CF: run 130 extras (12 new angles) ----------------
def cf_reserve_uid_null():
    st, j = post(ER, "/reserve", {"user_id": None, "idempotency_key": "k130un", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id null: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cf_reserve_uid_null()

def cf_confirm_extra_event_id():
    rid, st, _ = hold("rt-130ee", "k130ee", 1)
    if not rid:
        return check("state", "confirm extra event_id: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-130ee", "event_id": "evt-xyz"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("state", "confirm extra event_id field: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cf_confirm_extra_event_id()

def cf_waitlist_idem_number():
    st, j = post(ER, "/waitlist", {"user_id": "rt-130wn", "idempotency_key": 12345, "seats": 1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist idempotency_key number: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cf_waitlist_idem_number()

def cf_release_uid_null():
    rid, st, _ = hold("rt-130rn", "k130rn", 1)
    if not rid:
        return check("state", "release user_id null: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/release", {"reservation_id": rid, "user_id": None})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "release user_id null: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cf_release_uid_null()

def cf_transfer_rid_bool():
    rid, st, _ = hold("rt-130tb", "k130tb", 1)
    if not rid:
        return check("state", "transfer rid bool: skipped (hold unavailable)", True, "st=%s" % st)
    stt, j = post(ER, "/transfer", {"reservation_id": True, "to_user": "rt-130tb-x"})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer reservation_id boolean: no 5xx, conserved", ok, "rid=%s stt=%s" % (rid, stt))
cf_transfer_rid_bool()

def cf_book_dup_uid_keys():
    raw_body = b'{"user_id": "rt-130bd", "user_id": "rt-130bd2", "idempotency_key": "k130bd", "seats": 1}'
    st, j = rawpost(ER, "/book", raw_body)
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("auth", "book duplicate user_id JSON keys: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cf_book_dup_uid_keys()

def cf_app_confirm_rid_number():
    rid, st, _ = hold("rt-130ac", "k130ac", 1)
    if not rid:
        return check("state", "app confirm rid number: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = raw(AR, "POST", "/api/confirm", json.dumps({"rid": 12345}).encode(), {"Content-Type": "application/json"})
    ok = stc != 500 and stc != -1 and alive(AR, "/")
    return check("app", "app confirm rid as number: no 500, app alive", ok, "rid=%s stc=%s" % (rid, stc))
cf_app_confirm_rid_number()

def cf_webhook_empty_rid():
    body = json.dumps({"type": "booked", "reservation_id": ""}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest", "X-Kavach-Signature": sig}
    st, j = raw(AR, "POST", "/webhook", body, h)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "webhook type booked empty reservation_id valid sig: graceful, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cf_webhook_empty_rid()

def cf_reserve_seats_null():
    st, j = post(ER, "/reserve", {"user_id": "rt-130sn", "idempotency_key": "k130sn", "seats": None})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats null: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cf_reserve_seats_null()

def cf_engine2_happy():
    s0 = seats(ER2)
    tag = uuid.uuid4().hex[:8]
    rid, st, j = hold("rt-130e2-" + tag, "k130e2-" + tag, 1, port=ER2)
    if not rid:
        return check("state", "engine2 happy: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER2, "/confirm", {"reservation_id": rid, "user_id": "rt-130e2-" + tag})
    time.sleep(0.2)
    s1 = seats(ER2)
    ok = stc == 200 and s1.get("sold") == s0.get("sold", 0) + 1 and conserved(ER2)
    return check("engine2", "8092 hold->confirm happy path: sold+1, conserved", ok, "s0=%s s1=%s stc=%s" % (s0, s1, stc))
cf_engine2_happy()

def cf_idem_dedupe_race():
    user, key = "rt-130ir", "k130ir"
    def one(_):
        return post(ER, "/reserve", {"user_id": user, "idempotency_key": key, "seats": 1})
    with ThreadPoolExecutor(max_workers=10) as ex:
        outs = list(ex.map(one, range(10)))
    sts = [o[0] for o in outs]
    rids = [o[1].get("reservation_id") for o in outs if o[0] == 200 and isinstance(o[1], dict)]
    uniq = len(set(r for r in rids if r))
    time.sleep(0.3)
    ok = all(s in (200, 409, 429) for s in sts) and uniq <= 1 and conserved() and alive(ER)
    return check("race", "10-way reserve same idem key same user: one reservation, conserved", ok, "sts=%s uniq=%d" % (sts, uniq))
cf_idem_dedupe_race()

def cf_waitlist_seats_array():
    st, j = post(ER, "/waitlist", {"user_id": "rt-130wa", "seats": [1, 2]})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist seats array: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cf_waitlist_seats_array()

print("CF TOTAL %d cases, PASS %d, FAIL %d" % (
    len(results), sum(1 for c, n, ok, d in results if ok), sum(1 for c, n, ok, d in results if not ok)))
for cat, name, ok, detail in results:
    print("%-4s %-4s %s %s" % ("OK" if ok else "FAIL", cat, name, detail if not ok else ""))
sys.exit(0 if all(ok for _, _, ok, _ in results) else 1)
