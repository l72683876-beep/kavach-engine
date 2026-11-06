#!/usr/bin/env python3
"""Run 64 extras: 12 angles (all live in redteam_battery.py Phase R too).
1: timestamp +5s future (inside window): accepted
2: timestamp +2h future: 401
3: sig over /reserve?x=1, request to /reserve: 401 (query MAC-bound)
4: lowercase bearer scheme: 401
5: top-level JSON array body: 4xx, alive
6: engine seats as string "1": 4xx
7: idempotency_key single space: 4xx
8: confirm another user's hold: 4xx, hold intact
9: waitlisted user reserves directly: no 5xx, conserved
10: app hold seats=1.5: no 500
11: app two identical holds: no 500, alive
12: bare-LF request: handled or 400, alive
13: percent-encoded path /%72eserve: 4xx, alive
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, SECRET = "testkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
            "X-Kavach-Signature": mac.hexdigest(), "Content-Type": "application/json"}
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
def rej(st): return 400 <= st < 500 or st == 429
def P(n, fn):
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase R: run 64 extras (12 new angles) ----------------
def ts_slight_future_ok():
    b = json.dumps({"user_id": "rt-64f5", "idempotency_key": "k64f5", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, ts=str(int(time.time()) + 5))
    st, j = raw(ER, "POST", "/reserve", b, h)
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    return check("auth", "timestamp +5s in future (inside window): accepted, no 5xx", st in (200, 429), "status=%s" % st)
ts_slight_future_ok()
def ts_two_hours_future():
    b = json.dumps({"user_id": "rt-64f2", "idempotency_key": "k64f2", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, ts=str(int(time.time()) + 7200))
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "timestamp +2h in future (outside window): 401", st == 401, "status=%s" % st)
ts_two_hours_future()
def sig_query_binding():
    b = json.dumps({"user_id": "rt-64qb", "idempotency_key": "k64qb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve?x=1", b)  # MAC over path WITH query
    st, _ = raw(ER, "POST", "/reserve", b, h)  # request without query
    return check("auth", "sig over /reserve?x=1 but request to /reserve: 401 (query is MAC-bound)", st == 401, "status=%s" % st)
sig_query_binding()
def lowercase_bearer():
    b = json.dumps({"user_id": "rt-64lb", "idempotency_key": "k64lb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["Authorization"] = "bearer testkey"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "lowercase 'bearer testkey' scheme: 401", st == 401, "status=%s" % st)
lowercase_bearer()
def top_level_array_body():
    b = b'[1,2,3]'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "top-level JSON array body on /reserve: 4xx, no 5xx, engine alive", rej(st) and alive, "status=%s" % st)
top_level_array_body()
def seats_string_engine():
    b = b'{"user_id":"rt-64ss","idempotency_key":"k64ss","seats":"1"}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "engine seats as string \"1\": 4xx, no 5xx", rej(st) and st != -1, "status=%s" % st)
seats_string_engine()
def idem_whitespace_only():
    b = b'{"user_id":"rt-64ws","idempotency_key":" ","seats":1}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "idempotency_key of a single space: 4xx, no 5xx", rej(st) and st != -1, "status=%s" % st)
idem_whitespace_only()
def confirm_wrong_user():
    st, j = post(ER, "/reserve", {"user_id": "rt-64o1", "idempotency_key": "k64o1", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "confirm with wrong user: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    b = json.dumps({"reservation_id": rid, "user_id": "rt-64o2"}).encode()
    st2 = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    s1 = seats(ER)
    post(ER, "/release", {"reservation_id": rid})
    intact = (s1.get("held", 0) == s0.get("held", 0)) and (s1.get("sold", 0) == s0.get("sold", 0))
    ok = rej(st2) and intact and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("state", "confirm another user's hold: 4xx, hold intact, conserved", ok, "st=%s" % st2)
confirm_wrong_user()
def waitlisted_user_reserves_directly():
    st1, j1 = post(ER2, "/waitlist", {"user_id": "rt-64wl", "idempotency_key": "k64wl", "seats": 1})
    wid = j1.get("waitlist_id") if isinstance(j1, dict) else None
    if not wid:
        return check("state", "waitlisted user reserves directly: skipped (join unavailable)", True, "st=%s" % st1)
    st2, j2 = post(ER2, "/reserve", {"user_id": "rt-64wl", "idempotency_key": "k64wl2", "seats": 1})
    rid = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    if rid: post(ER2, "/release", {"reservation_id": rid})
    st3, _ = post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    s = seats(ER2)
    ok = st2 != 500 and st2 != -1 and st3 in (200, 404) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "waitlisted user reserves directly: no 5xx, cleanup clean, conserved", ok, "join=%s res=%s" % (st1, st2))
waitlisted_user_reserves_directly()
def app_hold_float_seats():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"rt-64af","seats":1.5}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold seats=1.5: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_float_seats()
def app_identical_holds_x2():
    body = '{"user_id":"rt-64ix","seats":1}'
    st1, j1 = raw(AR, "POST", "/api/hold", body)
    st2, j2 = raw(AR, "POST", "/api/hold", body)
    for r in (j1, j2):
        if isinstance(r, dict) and r.get("reservation_id"):
            raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": r["reservation_id"], "outcome": "payment_failed"}))
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and alive
    return check("app", "app: two identical hold requests back to back: no 500, app alive, both cleaned", ok, "h1=%s h2=%s" % (st1, st2))
app_identical_holds_x2()
def bare_lf_request():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\nHost: x\n\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc in (200, 400) and alive
    return check("wire", "bare-LF line endings (no CR): handled or 400, engine alive", ok, "st=%s" % stc)
bare_lf_request()
def percent_encoded_path():
    b = json.dumps({"user_id": "rt-64pe", "idempotency_key": "k64pe", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    st, _ = raw(ER, "POST", "/%72eserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "percent-encoded path /%72eserve: 4xx (no route confusion), engine alive", rej(st) and alive, "status=%s" % st)
percent_encoded_path()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
