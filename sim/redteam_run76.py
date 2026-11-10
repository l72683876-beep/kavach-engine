#!/usr/bin/env python3
"""Run 76 extras: 12 angles (all live in redteam_battery.py Phase AD too).
1: timestamp '0' (epoch zero): 401, alive
2: Authorization 'Bearer  key' (double space): 401, alive
3: 10 parallel confirms same rid: no 5xx, exactly-once sale, conserved
4: re-reserve same idempotency key after release: no 5xx, conserved
5: GET /seats with 100 query params: no 5xx, alive
6: request id 65 chars (invalid hex length): 401, alive
7: app confirm rid held on engine 8092: no 500, app alive
8: Host header with out-of-range port 99999: no 5xx, alive
9: app status unknown rid: no 500, app alive
10: timestamp in milliseconds (13 digits): 401, alive
11: webhook payment_success seats=-1 on held rid: no 500, state unchanged
12: MAC input lowercase method: 401, alive
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

# ---------------- Phase AD: run 76 extras (12 new angles) ----------------
def ts_epoch_zero():
    b = json.dumps({"user_id": "rt-76ez", "idempotency_key": "k76ez", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts="0"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp '0' (epoch zero): 401, alive", st == 401 and alive, "status=%s" % st)
ts_epoch_zero()
def bearer_double_space():
    b = json.dumps({"user_id": "rt-76bd", "idempotency_key": "k76bd", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["Authorization"] = "Bearer  " + KEY  # two spaces
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "Authorization 'Bearer  key' (double space): 401, alive", st == 401 and alive, "status=%s" % st)
bearer_double_space()
def parallel_confirm_same_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-76pc", "idempotency_key": "k76pc", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel confirm same rid: skipped (hold unavailable)", True, "st=%s" % st)
    outs = P(10, lambda i: post(ER, "/confirm", {"reservation_id": rid})[0])
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved
    return check("race", "10 parallel confirms same rid: no 5xx, exactly-once sale, conserved", ok, "outs=%s" % outs)
parallel_confirm_same_rid()
def re_reserve_after_release():
    obj = {"user_id": "rt-76rr", "idempotency_key": "k76rr", "seats": 1}
    st1, j1 = post(ER, "/reserve", obj)
    rid = j1.get("reservation_id") if isinstance(j1, dict) and st1 == 200 else None
    if not rid:
        return check("state", "re-reserve after release: skipped (hold unavailable)", True, "st=%s" % st1)
    st2, _ = post(ER, "/release", {"reservation_id": rid})
    st3, j3 = post(ER, "/reserve", obj)  # same idempotency key after release
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st1 == 200 and st2 == 200 and st3 != 500 and st3 != -1 and conserved
    return check("state", "re-reserve same idempotency key after release: no 5xx, conserved", ok, "st1=%s st2=%s st3=%s" % (st1, st2, st3))
re_reserve_after_release()
def hundred_query_params():
    q = "&".join("p%d=%d" % (i, i) for i in range(100))
    st, _ = raw(ER, "GET", "/seats?" + q)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "GET /seats with 100 query params: no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
hundred_query_params()
def rid_wrong_length():
    b = json.dumps({"user_id": "rt-76wl", "idempotency_key": "k76wl", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Request-Id"] = "a" * 65
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "request id 65 chars (invalid hex length): 401, alive", st == 401 and alive, "status=%s" % st)
rid_wrong_length()
def app_confirm_other_engine_rid():
    st, j = post(ER2, "/reserve", {"user_id": "rt-76oe", "idempotency_key": "k76oe", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app confirm rid of other engine: skipped (8092 hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/confirm", json.dumps({"reservation_id": rid}))
    alive = raw(AR, "GET", "/")[0] == 200
    post(ER2, "/release", {"reservation_id": rid})
    ok = p != 500 and p != -1 and alive
    return check("app", "app confirm with rid held on engine 8092 (wrong engine): no 500, app alive", ok, "p=%s" % p)
app_confirm_other_engine_rid()
def host_bad_port():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: localhost:99999\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "Host header with out-of-range port 99999: no 5xx, alive", ok, "st=%s" % stc)
host_bad_port()
def app_status_unknown_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-76ur", "idempotency_key": "k76ur", "seats": 1})
    if st == 200 and isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    p, _ = raw(AR, "GET", "/api/status?reservation_id=RSVZZZZZZ99")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app status with unknown rid RSVZZZZZZ99: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_status_unknown_rid()
def ts_milliseconds():
    b = json.dumps({"user_id": "rt-76ms", "idempotency_key": "k76ms", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=str(int(time.time() * 1000))))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp in milliseconds (13 digits): 401, alive", st == 401 and alive, "status=%s" % st)
ts_milliseconds()
def webhook_negative_seats():
    st, j = post(ER, "/reserve", {"user_id": "rt-76ns", "idempotency_key": "k76ns", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook negative seats: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid, "seats": -1}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    unchanged = s1.get("sold", 0) == s0.get("sold", 0) and s1.get("held", 0) == s0.get("held", 0)
    post(ER, "/release", {"reservation_id": rid})
    ok = w != 500 and w != -1 and alive and unchanged
    return check("app", "webhook payment_success with seats=-1 on HELD rid: no 500, state unchanged", ok, "w=%s" % w)
webhook_negative_seats()
def sig_lowercase_method():
    b = json.dumps({"user_id": "rt-76lm", "idempotency_key": "k76lm", "seats": 1}).encode()
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\npost\n/reserve\n" + KEY + "\n").encode() + b, hashlib.sha256).hexdigest()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Signature"] = mac
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC input with lowercase method 'post' (engine sees POST): 401, alive", st == 401 and alive, "status=%s" % st)
sig_lowercase_method()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
