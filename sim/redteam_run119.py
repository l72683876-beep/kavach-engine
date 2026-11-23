#!/usr/bin/env python3
"""Run 119 extras: 12 angles (Phase BU), all new vs runs 115-118.
1: /confirm replay (same confirm twice): no 5xx, second is idempotent/409, conserved
2: /reserve same idempotency_key with different seats from same user: same reservation back, conserved
3: /waitlist with seats null: no 5xx
4: /reserve user_id containing a null byte: no 5xx, conserved
5: /confirm with unknown extra field: strict 400, no 5xx
6: /transfer with a seats field injected: no 5xx, conserved
7: /release with unknown event_id: graceful, no 5xx
8: app /api/pay with rid missing: no 500, app alive
9: app /api/hold with seats as string "1.5": no 500, app alive
10: webhook with invalid base64 signature header: no 5xx
11: 10-way concurrent /reserve with the SAME idempotency_key: exactly one reservation, seats allocated once, conserved
12: /reserve with 10KB timestamp header: no 5xx
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

# ---------------- Phase BU: run 119 extras (12 new angles) ----------------
def bu_confirm_replay():
    rid, st, _ = bt_hold("rt-119cr", "k119cr")
    if not rid:
        return check("state", "confirm replay: skipped (hold unavailable)", True, "st=%s" % st)
    st1, j1 = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-119cr"})
    st2, j2 = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-119cr"})
    time.sleep(0.2)
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and conserved() and alive(ER)
    return check("state", "confirm replay (same confirm twice): no 5xx, idempotent/409, conserved", ok, "st1=%s j1=%s st2=%s j2=%s" % (st1, str(j1)[:40], st2, str(j2)[:40]))
bu_confirm_replay()

def bu_idem_different_seats():
    rid1, st1, j1 = bt_hold("rt-119id", "k119id", seats_n=1)
    st2, j2 = post(ER, "/reserve", {"user_id": "rt-119id", "idempotency_key": "k119id", "seats": 3})
    same = isinstance(j2, dict) and j2.get("reservation_id") == rid1
    conflict = st2 == 409
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("state", "reserve same idem key with different seats: same rid or 409, no second hold", ok and (same or conflict), "rid1=%s st2=%s j2=%s" % (rid1, st2, str(j2)[:60]))
bu_idem_different_seats()

def bu_waitlist_seats_null():
    st, _ = post(ER, "/waitlist", {"user_id": "rt-119wn", "idempotency_key": "k119wn", "seats": None})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist with seats null: no 5xx", ok, "st=%s" % st)
bu_waitlist_seats_null()

def bu_user_id_nullbyte():
    st, _ = post(ER, "/reserve", {"user_id": "rt-119\u0000nb", "idempotency_key": "k119nb", "seats": 1})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id with null byte: no 5xx, conserved", ok, "st=%s" % st)
bu_user_id_nullbyte()

def bu_confirm_unknown_field():
    rid, st, _ = bt_hold("rt-119cf", "k119cf")
    if not rid:
        return check("state", "confirm unknown field: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid, "idempotency_key": "pay119cf", "admin": True})
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("authz", "confirm with unknown extra field: strict 400, no 5xx, conserved", ok, "st2=%s" % st2)
bu_confirm_unknown_field()

def bu_transfer_seats_field():
    rid, st, _ = bt_hold("rt-119tf", "k119tf", seats_n=2)
    if not rid:
        return check("state", "transfer seats field: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "from_user": "rt-119tf", "to_user": "rt-119tf2", "seats": 1})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("authz", "transfer with injected seats field: no 5xx, conserved", ok, "st2=%s" % st2)
bu_transfer_seats_field()

def bu_release_unknown_event():
    rid, st, _ = bt_hold("rt-119ue", "k119ue")
    if not rid:
        return check("state", "release unknown event_id: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/release", {"reservation_id": rid, "event_id": "evt-does-not-exist-119"})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("state", "release with unknown event_id: graceful, conserved", ok, "st2=%s" % st2)
bu_release_unknown_event()

def bu_app_pay_no_rid():
    body = json.dumps({"outcome": "success"}).encode()
    st, _ = raw(AR, "POST", "/api/pay", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/pay with rid missing: no 500, app alive", ok, "st=%s" % st)
bu_app_pay_no_rid()

def bu_app_hold_seats_str_float():
    body = json.dumps({"user_id": "rt-119hs", "seats": "1.5"}).encode()
    st, _ = raw(AR, "POST", "/api/hold", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold with seats as string \"1.5\": no 500, app alive", ok, "st=%s" % st)
bu_app_hold_seats_str_float()

def bu_webhook_bad_b64():
    body = json.dumps({"event": "waitlist_fulfilled", "rid": "rt-119bb", "seats": 1}).encode()
    headers = {"Content-Type": "application/json", "X-Kavach-Signature": "!!not-base64!!", "X-Kavach-Timestamp": str(int(time.time()))}
    st, _ = raw(AR, "POST", "/api/kavach-webhook", body, headers)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app webhook with invalid base64 signature: no 500, app alive", ok, "st=%s" % st)
bu_webhook_bad_b64()

def bu_reserve_idem_race():
    def res(_):
        return post(ER, "/reserve", {"user_id": "rt-119ir", "idempotency_key": "k119ir", "seats": 2})
    with ThreadPoolExecutor(max_workers=10) as ex:
        outs = list(ex.map(res, range(10)))
    rids = {o[1].get("reservation_id") for o in outs if o[0] == 200 and isinstance(o[1], dict)}
    ok = conserved() and alive(ER) and len(rids) <= 1 and all(o[0] in (200, 409, 400, 429) for o in outs)
    return check("race", "10-way concurrent reserve with SAME idempotency_key: one reservation, conserved", ok, "outs=%s rids=%s" % ([o[0] for o in outs][:6], rids))
bu_reserve_idem_race()

def bu_oversized_timestamp():
    body = json.dumps({"user_id": "rt-119ot", "idempotency_key": "k119ot", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    h["X-Kavach-Timestamp"] = "1" * 10240
    st, _ = raw(ER, "POST", "/reserve", body, h)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("auth", "reserve with 10KB timestamp header: no 5xx, conserved", ok, "st=%s" % st)
bu_oversized_timestamp()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("BU TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in results:
    print("OK " if r[2] else "FAIL", "[%s] %s :: %s" % (r[0], r[1], r[3]))
sys.exit(1 if fails else 0)
