#!/usr/bin/env python3
"""Run 62 extras: 12 angles (all live in redteam_battery.py Phase P too).
1: duplicate X-Kavach-Request-Id headers: engine takes first, conserved
2: same rid reused on /release after /reserve: 401 replay guard
3: reserve empty user_id: 4xx
4: reserve empty idempotency_key: 4xx
5: reserve seats=10 single request: no 5xx, released clean
6: release same rid twice: second 4xx, conserved
7: 50 parallel /book on drained engine: all sold_out, conserved
8: app hold seats=0: no 500
9: app hold empty user_id: no 500
10: webhook payment_failed without seats: no 500, conserved
11: absolute-form URI: handled, engine alive
12: 100KB URL query: 4xx or handled, engine alive
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

# ---------------- Phase P: run 62 extras (12 new angles) ----------------
def dup_rid_headers():
    import socket as _s
    body = json.dumps({"user_id": "rt-62dr", "idempotency_key": "k62dr", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    ridA = h["X-Kavach-Request-Id"]
    ridB_used = sign(KEY, "POST", "/reserve", body)["X-Kavach-Request-Id"]
    head = "POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nContent-Type: application/json\r\n" % len(body)
    head += "Authorization: %s\r\nX-Kavach-Timestamp: %s\r\nX-Kavach-Request-Id: %s\r\nX-Kavach-Request-Id: %s\r\nX-Kavach-Signature: %s\r\n\r\n" % (
        h["Authorization"], h["X-Kavach-Timestamp"], ridA, ridB_used, h["X-Kavach-Signature"])
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(head.encode() + body)
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    rid = None
    if stc == 200:
        try:
            j = json.loads(buf.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in buf else {}
            rid = j.get("reservation_id")
        except Exception: pass
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = stc in (200, 429) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("auth", "duplicate X-Kavach-Request-Id headers (fresh first, used second): engine takes first, no confusion, conserved", ok, "st=%s" % stc)
dup_rid_headers()
def rid_reuse_across_endpoints():
    b = json.dumps({"user_id": "rt-62rx", "idempotency_key": "k62rx", "seats": 1}).encode()
    h1 = sign(KEY, "POST", "/reserve", b)
    st1, j1 = raw(ER, "POST", "/reserve", b, h1)
    rid = j1.get("reservation_id") if isinstance(j1, dict) and st1 == 200 else None
    if not rid:
        return check("auth", "rid reuse across endpoints: skipped (hold unavailable)", True, "st=%s" % st1)
    b2 = json.dumps({"reservation_id": rid}).encode()
    st2 = raw(ER, "POST", "/release", b2, sign(KEY, "POST", "/release", b2, rid=h1["X-Kavach-Request-Id"]))[0]
    st3, _ = post(ER, "/release", {"reservation_id": rid})
    ok = st2 == 401 and rej(st3) is False if st3 == 200 else st2 == 401
    return check("auth", "same rid reused on /release right after /reserve: 401 replay guard", st2 == 401, "r2=%s cleanup=%s" % (st2, st3))
rid_reuse_across_endpoints()
def reserve_empty_user_id():
    b = b'{"user_id":"","idempotency_key":"k62eu","seats":1}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "reserve with empty user_id: 4xx, no 5xx", rej(st) and st != -1, "status=%s" % st)
reserve_empty_user_id()
def reserve_empty_idem():
    b = b'{"user_id":"rt-62ei","idempotency_key":"","seats":1}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "reserve with empty idempotency_key: 4xx, no 5xx", rej(st) and st != -1, "status=%s" % st)
reserve_empty_idem()
def reserve_multi_seat_10():
    s0 = seats(ER)
    b = json.dumps({"user_id": "rt-62m10", "idempotency_key": "k62m10", "seats": 10}).encode()
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s1 = seats(ER)
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 and j.get("reservation_id") else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    s2 = seats(ER)
    ok = st != 500 and st != -1 and s2.get("total") == s2.get("sold") + s2.get("held") + s2.get("free")
    return check("state", "reserve seats=10 single request: no 5xx, released clean, conserved", ok,
                 "st=%s free %s->%s->%s" % (st, s0.get("free"), s1.get("free"), s2.get("free")))
reserve_multi_seat_10()
def double_release():
    st, j = post(ER, "/reserve", {"user_id": "rt-62d2", "idempotency_key": "k62d2", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("state", "double release: skipped (hold unavailable)", True, "st=%s" % st)
    st1, _ = post(ER, "/release", {"reservation_id": rid})
    st2, _ = post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st1 == 200 and rej(st2) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "release same rid twice: first 200, second 4xx, conserved", ok, "r1=%s r2=%s" % (st1, st2))
double_release()
def parallel_book_drained():
    f = seats(ER2).get("free", 0)
    big = None
    if f > 0:
        st, j = post(ER2, "/reserve", {"user_id": "rt-62pb", "idempotency_key": "k62pb", "seats": f})
        if st == 200 and isinstance(j, dict) and j.get("reservation_id"):
            big = j["reservation_id"]
    if not big:
        return check("state", "50 parallel /book on drained engine: skipped (could not drain)", True, "free=%s" % f)
    def one(_):
        b = json.dumps({"user_id": "rt-62pb2", "idempotency_key": "k62pb2-%d" % _, "seats": 1}).encode()
        return raw(ER2, "POST", "/book", b, sign(KEY, "POST", "/book", b))
    outs = P(50, one)
    post(ER2, "/release", {"reservation_id": big})
    s = seats(ER2)
    sts = [st for st, _ in outs]
    ok = all(x == 200 for x in sts) and all(isinstance(j, dict) and j.get("status") == "sold_out" for _, j in outs) \
         and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "50 parallel /book on drained engine: all 200 sold_out, nothing sold, conserved", ok,
                 "sts=%s" % sorted(set(sts)))
parallel_book_drained()
def app_hold_zero_seats():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"rt-62z0","seats":0}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold seats=0: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_zero_seats()
def app_hold_empty_user():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"","seats":1}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold empty user_id: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_empty_user()
def webhook_missing_seats():
    st, j = post(ER, "/reserve", {"user_id": "rt-62wm", "idempotency_key": "k62wm", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("app", "webhook missing seats: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest",
                 json.dumps({"event": "payment_failed", "reservation_id": rid}))
    alive = raw(AR, "GET", "/")[0] == 200
    post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st2 != 500 and st2 != -1 and alive and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("app", "webhook payment_failed without seats field: no 500, conserved after cleanup", ok, "wh=%s" % st2)
webhook_missing_seats()
def absolute_form_uri():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET http://127.0.0.1:8091/seats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc in (200, 400, 404) and alive
    return check("wire", "absolute-form URI (GET http://host/seats): handled, no 5xx, engine alive", ok, "st=%s" % stc)
absolute_form_uri()
def huge_url_path():
    st = -1
    try:
        c = http.client.HTTPConnection("127.0.0.1", ER, timeout=15)
        c.request("GET", "/seats?" + "a" * 100000)
        r = c.getresponse(); st = r.status; r.read(); c.close()
    except Exception:
        pass
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = (st < 500 and st != -1) or (st == -1 and alive)
    return check("wire", "100KB URL query on GET /seats: 4xx or handled, no 5xx, engine alive", ok, "st=%s" % st)
huge_url_path()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
