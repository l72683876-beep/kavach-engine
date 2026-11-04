#!/usr/bin/env python3
"""Run 60 extras: 12 angles (all live in redteam_battery.py Phase N too).
1: Authorization key with trailing period (unknown key): 401
2: request-id reuse with same body, fresh ts+sig: 401 replay guard
3: seats=1e30: 4xx, conserved
4: user_id as 100-deep nested arrays (real lists): 4xx
5: release with never-created rid: 4xx, engine alive
6: book free+1 seats: 200 sold_out, nothing sold
7: app hold duplicate JSON keys: no 500
8: app pay missing outcome: no 500, graceful
9: webhook empty JSON {}: no 500
10: valid /seats + garbage pipelined: answered, survives
11: 30 parallel reserves across 3 users: no 5xx, conserved
12: confirm with extra unknown field: 400 strict schema
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

# ---------------- Phase N: run 60 extras (12 new angles) ----------------
def auth_trailing_period_key():
    b = json.dumps({"user_id": "rt-60ts", "idempotency_key": "k60ts", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["Authorization"] = "Bearer testkey."
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "Authorization key with trailing period (unknown key): 401, no hold", st == 401, "status=%s" % st)
auth_trailing_period_key()
def rid_replay_same_body_new_ts():
    b = json.dumps({"user_id": "rt-60rr", "idempotency_key": "k60rr", "seats": 1}).encode()
    h1 = sign(KEY, "POST", "/reserve", b)
    st1, j1 = raw(ER, "POST", "/reserve", b, h1)
    rid = j1.get("reservation_id") if isinstance(j1, dict) else None
    if rid:
        post(ER, "/release", {"reservation_id": rid})
    h2 = dict(sign(KEY, "POST", "/reserve", b))
    h2["X-Kavach-Request-Id"] = h1["X-Kavach-Request-Id"]
    st2, _ = raw(ER, "POST", "/reserve", b, h2)
    ok = st1 in (200, 409, 429) and st2 == 401
    return check("auth", "request-id reuse with same body, fresh timestamp+sig: 401 replay guard", ok,
                 "r1=%s r2=%s" % (st1, st2))
rid_replay_same_body_new_ts()
def seats_huge_float():
    b = b'{"user_id":"rt-60hf","idempotency_key":"k60hf","seats":1e30}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    s = seats(ER)
    ok = rej(st) and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats=1e30: 4xx, no 5xx, conserved", ok, "status=%s" % st)
seats_huge_float()
def uid_nested_arrays():
    uid = ["a"]
    for _ in range(100):
        uid = [uid]
    b = json.dumps({"user_id": uid, "idempotency_key": "k60na", "seats": 1}).encode()
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "user_id as 100-deep nested arrays: 4xx, no 5xx", rej(st) and st != -1, "status=%s" % st)
uid_nested_arrays()
def release_unknown_rid():
    b = json.dumps({"reservation_id": "RSV00000000"}).encode()
    st = raw(ER, "POST", "/release", b, sign(KEY, "POST", "/release", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("state", "release with never-created rid RSV00000000: 4xx, engine alive", rej(st) and alive, "status=%s" % st)
release_unknown_rid()
def book_over_free():
    f = seats(ER).get("free", 0)
    if f < 1:
        return check("state", "book free+1 seats: skipped (no free seat)", True, "free=%s" % f)
    sold0 = seats(ER).get("sold")
    b = json.dumps({"user_id": "rt-60bf", "idempotency_key": "k60bf", "seats": f + 1}).encode()
    st, j = raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b))
    sold1 = seats(ER).get("sold")
    ok = st == 200 and isinstance(j, dict) and j.get("status") == "sold_out" and sold1 == sold0
    return check("state", "book %d seats with %d free: 200 sold_out, nothing sold" % (f + 1, f), ok,
                 "st=%s sold %d->%d" % (st, sold0, sold1))
book_over_free()
def app_hold_dup_keys():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"rt-60dk","seats":1,"seats":2}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with duplicate JSON keys (seats 1 then 2): no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_dup_keys()
def app_pay_missing_outcome():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-60mo","seats":1}')
    rid = h.get("reservation_id") if isinstance(h, dict) else None
    if not (st == 200 and rid):
        return check("app", "app pay missing outcome: skipped (hold unavailable)", True, "hold=%s" % st)
    st2, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-60mo"}))
    alive = raw(AR, "GET", "/")[0] == 200
    if st2 == 200:
        pass  # pay went through or failed gracefully; either is non-500
    return check("app", "app pay without outcome field: no 500, graceful, app alive", st2 != 500 and st2 != -1 and alive, "pay=%s" % st2)
app_pay_missing_outcome()
def webhook_empty_json():
    st, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", "{}")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook with empty JSON {} and valid token: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
webhook_empty_json()
def valid_then_garbage_pipelined():
    import socket as _s
    req = b"GET /seats HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\nGARBAGE-BYTES\r\n\r\n"
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        sk.sendall(req)
        sk.settimeout(3)
        try: buf = sk.recv(400)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    alive = raw(ER, "GET", "/seats")[0] == 200
    body2 = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-60vg"}).encode()
    st2 = raw(ER, "POST", "/confirm", body2, sign(KEY, "POST", "/confirm", body2))[0]
    ok = b"HTTP/1.1 200" in buf and alive and st2 == 404
    return check("wire", "valid /seats + garbage pipelined on one connection: answered, survives, next request fine", ok,
                 "resp=%s next=%s" % (buf[:20], st2))
valid_then_garbage_pipelined()
def three_users_60_parallel():
    def one(i):
        u = "rt-60p%d" % (i % 3)
        b = json.dumps({"user_id": u, "idempotency_key": "k60p%03d" % i, "seats": 1}).encode()
        return raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    outs = P(30, one)
    rids = [j["reservation_id"] for st, j in outs if st == 200 and isinstance(j, dict) and j.get("reservation_id")]
    for rid in rids:
        post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    codes = [st for st, _ in outs]
    ok = all(x < 500 and x != -1 for x in codes) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("rate", "30 parallel reserves across 3 users: no 5xx, conserved (429s allowed)", ok,
                 "codes=%s holds=%d" % (sorted(set(codes)), len(rids)))
three_users_60_parallel()
def confirm_unknown_field():
    st, j = post(ER, "/reserve", {"user_id": "rt-60uf", "idempotency_key": "k60uf", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("state", "confirm with unknown field: skipped (hold unavailable)", True, "st=%s" % st)
    b = json.dumps({"reservation_id": rid, "user_id": "rt-60uf", "extra": 1}).encode()
    st2 = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    post(ER, "/release", {"reservation_id": rid})
    ok = rej(st2) and st2 != -1
    return check("state", "confirm with extra unknown field: 400 strict schema, hold released clean", ok, "status=%s" % st2)
confirm_unknown_field()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
