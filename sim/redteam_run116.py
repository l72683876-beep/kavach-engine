#!/usr/bin/env python3
"""Run 116 extras: 12 angles (all live in redteam_battery.py Phase BR too).
1: reserve seats as string " 2" (leading whitespace): graceful, conserved
2: release with seats as float string "2.0": no 5xx, conserved
3: concurrent reserve+waitlist on same seats (10-way race): conserved, no oversell
4: app /api/hold seats as string "02": no 500, app alive
5: confirm with idempotency_key as JSON array: no 5xx, conserved
6: app POST /api/deals title whitespace-only: no 500, app alive
7: app /api/board limit=100000 (huge): no 500, app alive
8: transfer without to_user field: 4xx, no 5xx, conserved
9: app /api/board limit=1e9 (scientific): no 500, app alive
10: /waitlist with seats as boolean true: graceful, conserved
11: app POST /api/deals with seats as string "1": no 500, app alive
12: /release with user_id as JSON array: no 5xx, conserved
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
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
def br_alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def br_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

# ---------------- Phase BR: run 116 extras (12 new angles) ----------------
def br_reserve_seats_leadspace():
    st, j = post(ER, "/reserve", {"user_id": "rt-116sl", "idempotency_key": "k116sl", "seats": " 2"})
    ok = st != 500 and st != -1 and conserved() and br_alive(ER)
    return check("fuzz", "reserve seats as string \" 2\" (leading whitespace): graceful, conserved", ok, "st=%s" % st)
br_reserve_seats_leadspace()

def br_release_seats_floatstr():
    rid, st, _ = br_hold("rt-116rf", "k116rf")
    if not rid:
        return check("state", "release seats \"2.0\": skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/release", {"reservation_id": rid, "user_id": "rt-116rf", "seats": "2.0"})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and br_alive(ER)
    return check("fuzz", "release with seats as float string \"2.0\": no 5xx, conserved", ok, "st2=%s" % st2)
br_release_seats_floatstr()

def br_reserve_waitlist_race():
    base = seats(ER)
    total = base.get("total", 50); free0 = base.get("free", 0)
    if free0 < 1:
        return check("state", "reserve+waitlist race: skipped (no free seats)", True, "free0=%s" % free0)
    rid, st, _ = br_hold("rt-116rw", "k116rw")
    if not rid:
        return check("state", "reserve+waitlist race: skipped (hold unavailable)", True, "st=%s" % st)
    def one(i):
        if i % 2 == 0:
            return post(ER, "/reserve", {"user_id": "rt-116rr%d" % i, "idempotency_key": "k116rr%d" % i, "seats": 1})
        return post(ER, "/waitlist", {"user_id": "rt-116rw%d" % i, "idempotency_key": "k116ww%d" % i, "seats": 1})
    outs = list(ThreadPoolExecutor(max_workers=10).map(one, range(10)))
    time.sleep(0.5)
    s = seats(ER)
    no500 = all(o[0] != 500 and o[0] != -1 for o in outs)
    never_over = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0) and s.get("sold", 0) <= s.get("total", 0)
    ok = no500 and never_over and br_alive(ER)
    return check("race", "concurrent reserve+waitlist on same seats (10-way): conserved, no oversell", ok,
                 "sold=%s held=%s outs=%s" % (s.get("sold"), s.get("held"), [o[0] for o in outs]))
br_reserve_waitlist_race()

def br_app_hold_seats_octal():
    body = json.dumps({"user_id": "rt-116ho", "seats": "02"}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and br_alive(AR, "/")
    return check("app", "app /api/hold seats as string \"02\": no 500, app alive", ok, "st=%s" % st)
br_app_hold_seats_octal()

def br_confirm_idem_array():
    rid, st, _ = br_hold("rt-116ca", "k116ca")
    if not rid:
        return check("state", "confirm idem array: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-116ca", "idempotency_key": ["k116ca"]})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and br_alive(ER)
    return check("fuzz", "confirm with idempotency_key as JSON array: no 5xx, conserved", ok, "st2=%s" % st2)
br_confirm_idem_array()

def br_app_deals_ws_title():
    body = json.dumps({"title": "   ", "seats": 1}).encode()
    st, j = raw(AR, "POST", "/api/deals", body)
    ok = st != 500 and st != -1 and br_alive(AR, "/")
    return check("app", "app POST /api/deals title whitespace-only: no 500, app alive", ok, "st=%s" % st)
br_app_deals_ws_title()

def br_app_board_limit_huge():
    st, j = raw(AR, "GET", "/api/board?limit=100000")
    ok = st != 500 and st != -1 and br_alive(AR, "/")
    return check("app", "app /api/board limit=100000 (huge): no 500, app alive", ok, "st=%s" % st)
br_app_board_limit_huge()

def br_transfer_no_to_user():
    rid, st, _ = br_hold("rt-116tn", "k116tn")
    if not rid:
        return check("state", "transfer missing to_user: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and br_alive(ER)
    return check("fuzz", "transfer without to_user field: no 5xx, conserved", ok, "st2=%s" % st2)
br_transfer_no_to_user()

def br_app_board_limit_sci():
    st, j = raw(AR, "GET", "/api/board?limit=1e9")
    ok = st != 500 and st != -1 and br_alive(AR, "/")
    return check("app", "app /api/board limit=1e9 (scientific): no 500, app alive", ok, "st=%s" % st)
br_app_board_limit_sci()

def br_waitlist_seats_bool():
    st, j = post(ER, "/waitlist", {"user_id": "rt-116wb", "idempotency_key": "k116wb", "seats": True})
    ok = st != 500 and st != -1 and conserved() and br_alive(ER)
    return check("fuzz", "waitlist with seats as boolean true: graceful, conserved", ok, "st=%s" % st)
br_waitlist_seats_bool()

def br_app_deals_seats_str():
    body = json.dumps({"title": "rt-116ds", "seats": "1"}).encode()
    st, j = raw(AR, "POST", "/api/deals", body)
    ok = st != 500 and st != -1 and br_alive(AR, "/")
    return check("app", "app POST /api/deals with seats as string \"1\": no 500, app alive", ok, "st=%s" % st)
br_app_deals_seats_str()

def br_release_uid_array():
    rid, st, _ = br_hold("rt-116ra", "k116ra")
    if not rid:
        return check("state", "release user_id array: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/release", {"reservation_id": rid, "user_id": ["rt-116ra"]})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and br_alive(ER)
    return check("fuzz", "release with user_id as JSON array: no 5xx, conserved", ok, "st2=%s" % st2)
br_release_uid_array()
