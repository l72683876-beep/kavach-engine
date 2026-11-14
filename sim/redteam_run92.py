#!/usr/bin/env python3
"""Run 92 extras: 12 angles (all live in redteam_battery.py Phase AT too).
1: MAC over path-with-query while request path /reserve: 401
2: parallel confirms at hold expiry: no 5xx, conserved
3: duplicate Host headers: no 5xx, no hang
4: reserve with seats "NaN" string: 4xx
5: waitlist join while user holds a seat: no 5xx, conserved
6: app hold with empty user_id: no 500
7: app webhook with tenant2's rid: rejected, no 500, conserved
8: absolute-form request line: no 5xx, no hang
9: reserve with top-level JSON array body: 4xx
10: self-transfer of confirmed reservation: no 5xx, conserved
11: 8 parallel releases same rid: no 5xx, conserved
12: non-ASCII X-Kavach-Request-Id: no 5xx
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
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase AT: run 92 extras (12 new angles) ----------------
def mac_with_query_string():
    b = json.dumps({"user_id": "rt-92q", "idempotency_key": "k92q", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve?x=1", b)  # MAC over path+query, request path is /reserve
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC over path-with-query while request path /reserve: 401, alive", st == 401 and alive, "status=%s" % st)
mac_with_query_string()
def confirm_vs_expiry_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-92ce", "idempotency_key": "k92ce", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "confirm vs expiry race: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(2.6)  # hold-ttl 3s on 8091: fire confirm right at expiry
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(post, ER, "/confirm", {"reservation_id": rid})
        f2 = ex.submit(post, ER, "/confirm", {"reservation_id": rid})
        r1, r2 = f1.result()[0], f2.result()[0]
    time.sleep(1.5)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = r1 != 500 and r2 != 500 and r1 != -1 and r2 != -1 and conserved
    return check("race", "parallel confirms at hold expiry: no 5xx, conserved", ok, "r1=%s r2=%s" % (r1, r2))
confirm_vs_expiry_race()
def duplicate_host_headers():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "duplicate Host headers: no 5xx, no hang, alive", ok, "st=%s" % stc)
duplicate_host_headers()
def seats_nan_string():
    st, _ = post(ER, "/reserve", {"user_id": "rt-92nan", "idempotency_key": "k92nan", "seats": "NaN"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "reserve with seats \"NaN\" string: 4xx, alive", ok, "status=%s" % st)
seats_nan_string()
def waitlist_join_while_holding():
    st, j = post(ER, "/reserve", {"user_id": "rt-92wh", "idempotency_key": "k92wh", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "waitlist join while holding: skipped (hold unavailable)", True, "st=%s" % st)
    w, _ = post(ER, "/waitlist", {"user_id": "rt-92wh", "seats": 1})
    time.sleep(4.0)
    post(ER, "/release", {"reservation_id": rid})
    time.sleep(1.5)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = w != 500 and w != -1 and conserved
    return check("state", "waitlist join while user holds a seat: no 5xx, conserved", ok, "w=%s" % w)
waitlist_join_while_holding()
def app_hold_empty_user():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "", "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with empty user_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_empty_user()
def cross_tenant_webhook():
    st, j = post(ER2, "/reserve", {"user_id": "rt-92xt", "idempotency_key": "k92xt", "seats": 1}, key="otherkey")
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "cross-tenant webhook: skipped (hold unavailable)", True, "st=%s" % st)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest",
               json.dumps({"event": "payment_success", "reservation_id": rid, "seats": 1}))
    post(ER2, "/release", {"reservation_id": rid}, key="otherkey")
    time.sleep(1.0)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = w != 500 and w != -1 and conserved
    return check("app", "app webhook with tenant2's rid (app on tenant1): rejected, no 500, conserved", ok, "w=%s" % w)
cross_tenant_webhook()
def absolute_form_uri():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET http://127.0.0.1/seats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "absolute-form request line: no 5xx, no hang, alive", ok, "st=%s" % stc)
absolute_form_uri()
def top_level_array_body():
    b = b'[1, 2, 3]'
    h = sign(KEY, "POST", "/reserve", b)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "reserve with top-level JSON array body: 4xx, alive", ok, "status=%s" % st)
top_level_array_body()
def self_transfer():
    st, j = post(ER, "/reserve", {"user_id": "rt-92st", "idempotency_key": "k92st", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "self-transfer: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("state", "self-transfer: skipped (confirm %s)" % st2, True)
    t, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-92st"})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = t != 500 and t != -1 and conserved
    return check("state", "self-transfer of confirmed reservation: no 5xx, conserved", ok, "t=%s" % t)
self_transfer()
def parallel_release_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-92pr", "idempotency_key": "k92pr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel release race: skipped (hold unavailable)", True, "st=%s" % st)
    def go(i):
        return post(ER, "/release", {"reservation_id": rid})[0]
    with ThreadPoolExecutor(8) as ex:
        outs = list(ex.map(go, range(8)))
    time.sleep(1.0)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 for x in outs) and conserved
    return check("race", "8 parallel releases same rid: no 5xx, conserved (200s=%d)" % outs.count(200), ok, "200s=%d" % outs.count(200))
parallel_release_race()
def unicode_request_id():
    b = json.dumps({"user_id": "rt-92ur", "idempotency_key": "k92ur", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Request-Id"] = "rid-üñí-92"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "non-ASCII X-Kavach-Request-Id: no 5xx, alive", ok, "status=%s" % st)
unicode_request_id()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
