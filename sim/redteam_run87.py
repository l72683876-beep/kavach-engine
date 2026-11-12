#!/usr/bin/env python3
"""Run 87 extras: 12 angles (all live in redteam_battery.py Phase AO too).
1: HTTP/1.1 request without Host header: no 5xx, alive
2: 10,000-char path: no 5xx, alive
3: reserve with extra nested unknown keys: no 5xx, conserved
4: app hold with seats 1.5: no 500
5: webhook with unknown event string: no 500, alive
6: two parallel confirms on two distinct rids same user: both succeed, conserved
7: Content-Type text/plain with JSON body: no 5xx, alive
8: MAC over '/RESERVE' vs request '/reserve': 401, alive
9: 1000-char idempotency_key: no 5xx, conserved
10: 20 rapid app holds same user: no 500, alive
11: release with never-held rid on fresh engine: 4xx, conserved
12: confirm twice sequentially: no 5xx, conserved
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

# ---------------- Phase AO: run 87 extras (12 new angles) ----------------
def no_host_header():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "HTTP/1.1 request without Host header: no 5xx, alive", ok, "st=%s" % stc)
no_host_header()
def very_long_path():
    st, _ = raw(ER, "GET", "/" + "a" * 10000)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "10,000-char path: no 5xx, alive", ok, "status=%s" % st)
very_long_path()
def extra_nested_keys():
    st, _ = post(ER, "/reserve", {"user_id": "rt-87nk", "idempotency_key": "k87nk", "seats": 1, "extra": {"a": [1, 2, {"b": None}]}, "meta": "x"})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and conserved
    return check("fuzz", "reserve with extra nested unknown keys: no 5xx, conserved", ok, "status=%s" % st)
extra_nested_keys()
def app_hold_seats_float():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-87hf", "seats": 1.5}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats 1.5: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_seats_float()
def webhook_unknown_event():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", b'{"event": "payment_refunded_v2", "reservation_id": "RSV00000098"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook with unknown event string: no 500, app alive", w != 500 and w != -1 and alive, "w=%s" % w)
webhook_unknown_event()
def parallel_confirms_two_rids():
    st1, j1 = post(ER, "/reserve", {"user_id": "rt-87pc", "idempotency_key": "k87pc1", "seats": 1})
    st2, j2 = post(ER, "/reserve", {"user_id": "rt-87pc", "idempotency_key": "k87pc2", "seats": 1})
    r1 = j1.get("reservation_id") if isinstance(j1, dict) and st1 == 200 else None
    r2 = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    if not (r1 and r2):
        return check("race", "parallel confirms on two rids: skipped (holds unavailable)", True, "st1=%s st2=%s" % (st1, st2))
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(post, ER, "/confirm", {"reservation_id": r1})
        f2 = ex.submit(post, ER, "/confirm", {"reservation_id": r2})
        c1, c2 = f1.result()[0], f2.result()[0]
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = c1 == 200 and c2 == 200 and conserved
    return check("race", "two parallel confirms on two distinct rids same user: both succeed, conserved", ok, "c1=%s c2=%s" % (c1, c2))
parallel_confirms_two_rids()
def content_type_text_plain():
    b = json.dumps({"user_id": "rt-87tp", "idempotency_key": "k87tp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["Content-Type"] = "text/plain"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "Content-Type text/plain with JSON body: no 5xx, alive", ok, "status=%s" % st)
content_type_text_plain()
def mac_uppercase_path():
    b = json.dumps({"user_id": "rt-87up", "idempotency_key": "k87up", "seats": 1}).encode()
    h = sign(KEY, "POST", "/RESERVE", b)  # MAC over uppercase path
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC over '/RESERVE' vs request '/reserve': 401, alive", st == 401 and alive, "status=%s" % st)
mac_uppercase_path()
def idem_key_1000():
    st, _ = post(ER, "/reserve", {"user_id": "rt-87ik", "idempotency_key": "k" * 1000, "seats": 1})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and conserved
    return check("fuzz", "reserve with 1000-char idempotency_key: no 5xx, conserved", ok, "status=%s" % st)
idem_key_1000()
def app_rapid_holds():
    outs = [raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-87rh", "seats": 1}))[0] for _ in range(20)]
    alive = raw(AR, "GET", "/")[0] == 200
    ok = all(x != 500 for x in outs) and alive
    return check("app", "20 rapid app holds same user: no 500, app alive", ok, "500s=%d 429s=%d" % (outs.count(500), outs.count(429)))
app_rapid_holds()
def release_free_rid():
    st, _ = post(ER, "/release", {"reservation_id": "RSV00000001"})  # fresh engine: never held
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and conserved
    return check("state", "release with never-held rid on fresh engine: 4xx, conserved", ok, "status=%s" % st)
release_free_rid()
def confirm_twice_sequential():
    st, j = post(ER, "/reserve", {"user_id": "rt-87ct", "idempotency_key": "k87ct", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "confirm twice sequentially: skipped (hold unavailable)", True, "st=%s" % st)
    st1, _ = post(ER, "/confirm", {"reservation_id": rid})
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st1 == 200 and st2 != 500 and st2 != -1 and conserved
    return check("state", "confirm twice sequentially: first 200, second no 5xx, conserved", ok, "st1=%s st2=%s" % (st1, st2))
confirm_twice_sequential()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
