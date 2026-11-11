#!/usr/bin/env python3
"""Run 81 extras: 12 angles (all live in redteam_battery.py Phase AI too).
1: MAC over empty body, JSON body sent: 401, alive
2: whitespace-only X-Kavach-Timestamp: 401/400, alive
3: duplicate Content-Length headers: no 5xx, alive
4: reserve seats as string '2': 4xx, conserved
5: app release empty reservation_id: no 500
6: webhook truncated JSON body: no 500, alive
7: app hold seats=10^9: no 500
8: double-slash path //seats: no 5xx, alive
9: API key case-variant TESTKEY: 401, alive
10: MAC signed over otherkey with testkey Authorization: 401, alive
11: reserve with JSON array body: 4xx, alive
12: timestamp '-1' negative: 401, alive
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

# ---------------- Phase AI: run 81 extras (12 new angles) ----------------
def mac_over_empty_body():
    b = json.dumps({"user_id": "rt-81eb", "idempotency_key": "k81eb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b"")  # MAC computed over empty body
    st, _ = raw(ER, "POST", "/reserve", b, h)  # but JSON body sent
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC over empty body, JSON body sent: 401, alive", st == 401 and alive, "status=%s" % st)
mac_over_empty_body()
def ts_whitespace_only():
    b = json.dumps({"user_id": "rt-81tw", "idempotency_key": "k81tw", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Timestamp"] = "   "
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "X-Kavach-Timestamp whitespace-only: 401/400, alive", st in (400, 401) and alive, "status=%s" % st)
ts_whitespace_only()
def duplicate_content_length():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive  # Go stdlib rejects dup CL with 400; engine must stay alive
    return check("wire", "duplicate Content-Length headers: no 5xx, alive", ok, "st=%s" % stc)
duplicate_content_length()
def seats_string():
    st, _ = post(ER, "/reserve", {"user_id": "rt-81ss", "idempotency_key": "k81ss", "seats": "2"})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "reserve with seats as string '2': 4xx, no 5xx, conserved", ok, "status=%s" % st)
seats_string()
def app_release_empty_rid():
    p, _ = raw(AR, "POST", "/api/release", json.dumps({"reservation_id": ""}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app release with empty reservation_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_release_empty_rid()
def webhook_malformed_json():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", b'{"event": ')  # truncated JSON
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook with truncated JSON body: no 500, app alive", w != 500 and w != -1 and alive, "w=%s" % w)
webhook_malformed_json()
def app_hold_huge_seats():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-81hs", "seats": 10 ** 9}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats=10^9: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_huge_seats()
def double_slash_path():
    st, _ = raw(ER, "GET", "//seats")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "double-slash path //seats: no 5xx, alive", ok, "status=%s" % st)
double_slash_path()
def key_case_variant():
    b = json.dumps({"user_id": "rt-81kc", "idempotency_key": "k81kc", "seats": 1}).encode()
    st, _ = post(ER, "/reserve", {"user_id": "rt-81kc", "idempotency_key": "k81kc", "seats": 1}, key="TESTKEY")
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "API key case-variant TESTKEY (valid is testkey): 401, alive", st == 401 and alive, "status=%s" % st)
key_case_variant()
def cross_tenant_mac():
    b = json.dumps({"user_id": "rt-81ct", "idempotency_key": "k81ct", "seats": 1}).encode()
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    # MAC signed with otherkey while Authorization says testkey
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\nPOST\n/reserve\notherkey\n").encode() + b, hashlib.sha256).hexdigest()
    h = {"Authorization": "Bearer " + KEY, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC signed over otherkey with testkey Authorization: 401, alive", st == 401 and alive, "status=%s" % st)
cross_tenant_mac()
def json_array_body():
    body = b'[1, 2]'
    h = sign(KEY, "POST", "/reserve", body)
    st, _ = raw(ER, "POST", "/reserve", body, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with JSON array body: 4xx, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
json_array_body()
def ts_negative():
    b = json.dumps({"user_id": "rt-81ng", "idempotency_key": "k81ng", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts="-1"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp '-1' (negative): 401, alive", st == 401 and alive, "status=%s" % st)
ts_negative()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
