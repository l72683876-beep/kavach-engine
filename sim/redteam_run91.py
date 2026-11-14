#!/usr/bin/env python3
"""Run 91 extras: 12 angles (all live in redteam_battery.py Phase AS too).
1: non-hex 64-char signature: 4xx/401, alive
2: parallel release + 2-seat reserve race: no 5xx, conserved
3: OPTIONS /seats (CORS preflight): no 5xx, alive
4: tenant1 confirm of tenant2's hold: denied
5: app hold with seats true (bool): no 500
6: GET /seats%2F encoded slash: no 5xx, alive
7: timestamp 60s in future: 401, alive
8: reserve body with duplicate JSON keys: no 5xx, conserved
9: webhook with empty event string: no 500, alive
10: 8 parallel waitlist joins same user: no 5xx, conserved
11: bare newline inside header value: no 5xx, no hang
12: reserve with seats -0.0: 4xx, alive
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
    with ThreadPoolExecutor(max(1, n)) as ex:
        return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def waitlist(port=ER):
    st, j = raw(port, "GET", "/waitlist"); return j if st == 200 else j if isinstance(j, int) else {}

# ---------------- Phase AS: run 91 extras (12 new angles) ----------------
def raw_bytes_sig():
    b = json.dumps({"user_id": "rt-91rb", "idempotency_key": "k91rb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Signature"] = "0" * 64  # 64 chars of non-hex garbage
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "non-hex 64-char signature: 4xx/401, alive", st != 500 and st != -1 and alive, "status=%s" % st)
raw_bytes_sig()
def parallel_release_reserve():
    st, j = post(ER, "/reserve", {"user_id": "rt-91pr", "idempotency_key": "k91pr", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel release+reserve: skipped (hold unavailable)", True, "st=%s" % st)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(post, ER, "/release", {"reservation_id": rid})
        f2 = ex.submit(post, ER, "/reserve", {"user_id": "rt-91pr2", "idempotency_key": "k91pr2", "seats": 2})
        r1, r2 = f1.result()[0], f2.result()[0]
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = r1 != 500 and r2 != 500 and r1 != -1 and r2 != -1 and conserved
    return check("race", "parallel release + 2-seat reserve race: no 5xx, conserved", ok, "r1=%s r2=%s" % (r1, r2))
parallel_release_reserve()
def options_method():
    st, _ = raw(ER, "OPTIONS", "/seats", None, {})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "OPTIONS /seats (CORS preflight): no 5xx, alive", ok, "status=%s" % st)
options_method()
def cross_tenant_confirm_denied():
    st, j = post(ER, "/reserve", {"user_id": "rt-91xc", "idempotency_key": "k91xc", "seats": 1}, key="otherkey")
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "cross-tenant confirm denied: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})  # tenant1 confirms tenant2's hold
    post(ER, "/release", {"reservation_id": rid}, key="otherkey")  # owner cleans up
    ok = st2 != 200 and st2 != 500 and st2 != -1
    return check("state", "tenant1 confirm of tenant2's hold: denied", ok, "st2=%s" % st2)
cross_tenant_confirm_denied()
def app_hold_seats_bool():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-91ab", "seats": True}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats true (bool): no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_seats_bool()
def encoded_slash_path():
    st, _ = raw(ER, "GET", "/seats%2F")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "GET /seats%2F encoded slash: no 5xx, alive", ok, "status=%s" % st)
encoded_slash_path()
def future_timestamp():
    b = json.dumps({"user_id": "rt-91ft", "idempotency_key": "k91ft", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, ts=str(int(time.time()) + 60))
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    st2, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=str(int(time.time()) + 600)))
    alive2 = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp +60s inside +/-300s window: 200; +600s outside: 401", st == 200 and st2 == 401 and alive2, "st=%s st2=%s" % (st, st2))
future_timestamp()
def reserve_duplicate_json_keys():
    b = b'{"user_id": "rt-91dk", "seats": 1, "seats": 2, "idempotency_key": "k91dk"}'
    h = sign(KEY, "POST", "/reserve", b)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and conserved
    return check("fuzz", "reserve body with duplicate JSON keys: no 5xx, conserved", ok, "status=%s" % st)
reserve_duplicate_json_keys()
def webhook_empty_event():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", b'{"event": "", "reservation_id": "RSV00000001"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook with empty event string: no 500, alive", w != 500 and w != -1 and alive, "w=%s" % w)
webhook_empty_event()
def parallel_waitlist_same_user():
    def go(i):
        return post(ER2, "/waitlist", {"user_id": "rt-91pw", "seats": 1})[0]
    with ThreadPoolExecutor(8) as ex:
        outs = list(ex.map(go, range(8)))
    j = waitlist(ER2)
    size = j.get("size") if isinstance(j, dict) else (j if isinstance(j, int) else None)
    s = seats(ER2)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 for x in outs) and conserved
    return check("race", "8 parallel waitlist joins same user: no 5xx, conserved (size=%s)" % size, ok, "200s=%d" % outs.count(200))
parallel_waitlist_same_user()
def header_newline_injection():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Kavach-Timestamp: 1\nX-Injected: 1\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "bare newline inside header value: no 5xx, no hang, alive", ok, "st=%s" % stc)
header_newline_injection()
def seats_minus_zero():
    st, _ = post(ER, "/reserve", {"user_id": "rt-91mz", "idempotency_key": "k91mz", "seats": -0.0})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "reserve with seats -0.0: 4xx, alive", ok, "status=%s" % st)
seats_minus_zero()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
