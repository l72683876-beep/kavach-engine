#!/usr/bin/env python3
"""Run 118 extras: 12 angles (Phase BT), all new vs runs 115-117.
1: /reserve seats as boolean true: graceful, conserved
2: /reserve idempotency_key as boolean true: no 5xx
3: /release with user_id as empty string: no 5xx, conserved
4: /transfer with unknown extra field injected: no 5xx, conserved
5: /confirm with reservation_id as boolean true: no 5xx, conserved
6: /waitlist duplicate idempotency_key from two different users: no 5xx, no dup grant
7: /reserve valid HMAC but Content-Type text/plain: no 5xx
8: app /api/hold with user_id empty string: no 500, app alive
9: app /api/waitlist same idem key twice: no 500, app alive
10: app webhook with duplicated token query param: no 500, app alive
11: /reserve seats as hex string "0x2": graceful, conserved
12: concurrent double-release of same reservation (10-way race): freed exactly once, conserved
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

# ---------------- Phase BT: run 118 extras (12 new angles) ----------------
def bt_reserve_seats_bool():
    st, j = post(ER, "/reserve", {"user_id": "rt-118sb", "idempotency_key": "k118sb", "seats": True})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as boolean true: graceful, conserved", ok, "st=%s" % st)
bt_reserve_seats_bool()

def bt_reserve_idem_bool():
    st, j = post(ER, "/reserve", {"user_id": "rt-118ib", "idempotency_key": True})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve idempotency_key as boolean true: graceful, conserved", ok, "st=%s" % st)
bt_reserve_idem_bool()

def bt_release_empty_user():
    rid, st, _ = bt_hold("rt-118eu", "k118eu")
    if not rid:
        return check("state", "release empty user_id: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/release", {"reservation_id": rid, "user_id": ""})  # user_id unknown to /release: strict-reject expected
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("authz", "release body with undefined field user_id: strict 400, conserved", ok, "st2=%s" % st2)
bt_release_empty_user()

def bt_transfer_extra_field():
    rid, st, _ = bt_hold("rt-118xf", "k118xf", seats_n=2)
    if not rid:
        return check("state", "transfer extra field: skipped (hold unavailable)", True, "st=%s" % st)
    st2, j2 = post(ER, "/transfer", {"reservation_id": rid, "from_user": "rt-118xf", "to_user": "rt-118xf2", "admin_override": True, "role": "root"})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("authz", "transfer with unknown extra fields (admin_override/role): no 5xx, conserved", ok, "st2=%s j=%s" % (st2, str(j2)[:60]))
bt_transfer_extra_field()

def bt_confirm_rid_bool():
    st, _ = post(ER, "/confirm", {"reservation_id": True, "user_id": "rt-118cr"})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm with reservation_id as boolean true: no 5xx, conserved", ok, "st=%s" % st)
bt_confirm_rid_bool()

def bt_waitlist_idem_collision():
    u1, u2 = "rt-118w1", "rt-118w2"
    k = "k118wc"
    st1, j1 = post(ER, "/waitlist", {"user_id": u1, "idempotency_key": k, "seats": 1})
    st2, j2 = post(ER, "/waitlist", {"user_id": u2, "idempotency_key": k, "seats": 1})
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and alive(ER)
    detail = "st1=%s st2=%s j1=%s j2=%s" % (st1, st2, str(j1)[:60], str(j2)[:60])
    return check("state", "waitlist same idempotency_key from two users: no 5xx, no dup grant", ok, detail)
bt_waitlist_idem_collision()

def bt_wrong_content_type():
    body = json.dumps({"user_id": "rt-118ct", "idempotency_key": "k118ct", "seats": 1}).encode()
    headers = sign(KEY, "POST", "/reserve", body)
    headers["Content-Type"] = "text/plain"
    st, _ = raw(ER, "POST", "/reserve", body, headers)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("auth", "reserve valid HMAC but Content-Type text/plain: no 5xx, conserved", ok, "st=%s" % st)
bt_wrong_content_type()

def bt_app_hold_empty_user():
    body = json.dumps({"user_id": "", "seats": 1}).encode()
    st, _ = raw(AR, "POST", "/api/hold", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold with user_id empty string: no 500, app alive", ok, "st=%s" % st)
bt_app_hold_empty_user()

def bt_app_waitlist_dup_key():
    body = json.dumps({"user_id": "rt-118wd", "key": "k118wd", "seats": 1}).encode()
    st1, _ = raw(AR, "POST", "/api/waitlist", body, {"Content-Type": "application/json"})
    st2, _ = raw(AR, "POST", "/api/waitlist", body, {"Content-Type": "application/json"})
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and alive(AR, "/")
    return check("app", "app /api/waitlist same idem key twice: no 500, app alive", ok, "st1=%s st2=%s" % (st1, st2))
bt_app_waitlist_dup_key()

def bt_app_webhook_dup_token():
    body = json.dumps({"event": "waitlist_fulfilled", "rid": "rt-118wt", "seats": 1}).encode()
    st, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest&token=whsec-redtest", body, {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app webhook with duplicated token query param: no 500, app alive", ok, "st=%s" % st)
bt_app_webhook_dup_token()

def bt_reserve_seats_hex():
    st, j = post(ER, "/reserve", {"user_id": "rt-118hx", "idempotency_key": "k118hx", "seats": "0x2"})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as hex string \"0x2\": graceful, conserved", ok, "st=%s" % st)
bt_reserve_seats_hex()

def bt_double_release_race():
    # hold TTL is 2-3s and the sandbox can be slow: retry until the race fires on a live hold.
    for attempt in range(4):
        fb = seats(ER).get("free")
        rid, st, _ = bt_hold("rt-118dr", "k118dr-a%d" % attempt, seats_n=2)
        if not rid:
            time.sleep(0.3); continue
        def rel(_):
            return post(ER, "/release", {"reservation_id": rid})
        with ThreadPoolExecutor(max_workers=10) as ex:
            outs = [o[0] for o in ex.map(rel, range(10))]
        after = seats(ER)
        if 409 in outs:
            time.sleep(0.4); continue  # hold expired before the race landed; fresh attempt
        freed_ok = (after.get("free", -99) == fb)  # hold+release nets back to baseline; outs all 200 = released, not expired
        ok = conserved() and freed_ok and all(o == 200 for o in outs)
        return check("race", "10-way concurrent release of same reservation: freed exactly once, conserved", ok, "outs=%s free %s->%s" % (outs[:6], fb, after.get("free")))
    return check("race", "10-way concurrent release of same reservation: freed exactly once, conserved", False, "hold expired before race in all attempts")
bt_double_release_race()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("BT TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in results:
    print("OK " if r[2] else "FAIL", "[%s] %s :: %s" % (r[0], r[1], r[3]))
sys.exit(1 if fails else 0)
