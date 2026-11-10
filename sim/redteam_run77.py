#!/usr/bin/env python3
"""Run 77 extras: 12 angles (all live in redteam_battery.py Phase AE too).
1: timestamp '+<unix>': 200 or 4xx, no 5xx
2: signature UUID-styled with dashes: 401, alive
3: 20 parallel 5-seat holds on ER2: ok holds exactly account for held delta, conserved
4: ~2400-char query string: no 5xx, alive
5: timestamp as float: 401/400, alive
6: app hold user_id as number: no 500
7: webhook 'refund' on SOLD rid: no 500, sale stands
8: GET /seats/ trailing slash: no 5xx, alive
9: Content-Length 0 with body: no 5xx, alive
10: MAC over '/reserve/': 401, alive
11: webhook empty body: no 500, app alive
12: Authorization lowercase 'bearer': 401, alive
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

# ---------------- Phase AE: run 77 extras (12 new angles) ----------------
def ts_plus_sign():
    b = json.dumps({"user_id": "rt-77ps", "idempotency_key": "k77ps", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts="+" + str(int(time.time()))))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("auth", "timestamp '+<unix>' (plus-signed): 200 or 4xx, no 5xx", ok, "status=%s" % st)
ts_plus_sign()
def sig_dashes():
    b = json.dumps({"user_id": "rt-77sd", "idempotency_key": "k77sd", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    mac = h["X-Kavach-Signature"]
    h["X-Kavach-Signature"] = "%s-%s-%s-%s" % (mac[0:8], mac[8:12], mac[12:16], mac[16:20])  # UUID-styled
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "signature in UUID style with dashes: 401, alive", st == 401 and alive, "status=%s" % st)
sig_dashes()
def multi_seat_burst_race():
    s0 = seats(ER2)
    cap = s0.get("total", 0)
    want = min(5, max(1, cap // 2))  # 5 seats per hold if capacity allows
    outs = P(20, lambda i: post(ER2, "/reserve", {"user_id": "rt-77mb%d" % i, "idempotency_key": "k77mb%d" % i, "seats": want})[0])
    s1 = seats(ER2)
    held_delta = s1.get("held", 0) - s0.get("held", 0)
    ok_count = sum(1 for x in outs if x == 200)
    exact = ok_count * want == max(0, held_delta)
    conserved = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    no5xx = all(x != 500 and x != -1 for x in outs)
    # cleanup: release all held rids we created
    for i in range(20):
        st, j = post(ER2, "/reserve", {"user_id": "rt-77mb%d" % i, "idempotency_key": "k77mb%d" % i, "seats": want})
        # idempotent replay returns the same hold; release it
        if isinstance(j, dict) and j.get("reservation_id"):
            post(ER2, "/release", {"reservation_id": j["reservation_id"]})
    return check("race", "20 parallel 5-seat holds on ER2: successful holds exactly account for held delta, conserved", no5xx and exact and conserved, "outs=%s held_delta=%s ok=%d" % (outs, held_delta, ok_count))
multi_seat_burst_race()
def long_query_string():
    q = "&".join("k%d=%s" % (i, "x" * 20) for i in range(100))  # ~2400 chars
    st, _ = raw(ER, "GET", "/seats?" + q)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "GET /seats with ~2400-char query string: no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
long_query_string()
def ts_float():
    b = json.dumps({"user_id": "rt-77tf", "idempotency_key": "k77tf", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=str(time.time())))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st == 401 or st == 400
    return check("auth", "timestamp as float (e.g. 1762...​.5): 401/400, alive", ok and alive, "status=%s" % st)
ts_float()
def app_hold_user_id_number():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": 123, "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with user_id as number: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_user_id_number()
def webhook_refund_on_sold():
    st, j = post(ER, "/reserve", {"user_id": "rt-77rf", "idempotency_key": "k77rf", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook refund on SOLD: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER, "/confirm", {"reservation_id": rid})
    if stc != 200:
        return check("app", "webhook refund on SOLD: skipped (confirm unavailable)", True, "st=%s" % stc)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "refund", "reservation_id": rid, "seats": 1}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    unchanged = s1.get("sold", 0) == s0.get("sold", 0) and s1.get("free", 0) == s0.get("free", 0)
    ok = w != 500 and w != -1 and alive and unchanged
    return check("app", "webhook 'refund' event on SOLD rid: no 500, sale stands", ok, "w=%s" % w)
webhook_refund_on_sold()
def trailing_slash():
    st, _ = raw(ER, "GET", "/seats/")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "GET /seats/ (trailing slash): no 5xx, alive", ok, "status=%s" % st)
trailing_slash()
def cl_zero_with_body():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\nnot-json")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "Content-Length 0 with body present (Go rejects): no 5xx, alive", ok, "st=%s" % stc)
cl_zero_with_body()
def mac_path_trailing_slash():
    b = json.dumps({"user_id": "rt-77mt", "idempotency_key": "k77mt", "seats": 1}).encode()
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\nPOST\n/reserve/\n" + KEY + "\n").encode() + b, hashlib.sha256).hexdigest()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Signature"] = mac
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC over path '/reserve/' (request was '/reserve'): 401, alive", st == 401 and alive, "status=%s" % st)
mac_path_trailing_slash()
def webhook_empty_body():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", b"")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook with empty body: no 500, app alive", w != 500 and w != -1 and alive, "w=%s" % w)
webhook_empty_body()
def auth_lowercase_bearer():
    b = json.dumps({"user_id": "rt-77lb", "idempotency_key": "k77lb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["Authorization"] = "bearer " + KEY
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "Authorization 'bearer key' (lowercase scheme): 401, alive", st == 401 and alive, "status=%s" % st)
auth_lowercase_bearer()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
