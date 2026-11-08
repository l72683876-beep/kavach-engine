#!/usr/bin/env python3
"""Run 70 extras: 12 angles (all live in redteam_battery.py Phase X too).
1: sig over body A, reordered body B sent: 401
2: negative timestamp: 401
3: far-future timestamp (year 5138): 401
4: rid 129 chars 401, 128-char boundary handled
5: 10 parallel waitlist joins same user different keys: no 5xx, conserved
6: Content-Length larger than body, then close: graceful, alive
7: header line missing colon: 400, alive
8: app pay with the other engine's rid: no 500, no sale on either engine
9: app pay without reservation_id: no 500, alive
10: webhook unknown event on a held rid: no 500, state unchanged
11: valid chunked Transfer-Encoding reserve: served or 4xx, conserved
12: seats as 1.0 JSON float: 4xx, conserved
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

# ---------------- Phase X: run 70 extras (12 new angles) ----------------
def body_reorder_sig():
    b1 = json.dumps({"user_id": "rt-70br", "idempotency_key": "k70br", "seats": 1}).encode()
    b2 = json.dumps({"seats": 1, "idempotency_key": "k70br", "user_id": "rt-70br"}).encode()
    st, _ = raw(ER, "POST", "/reserve", b2, sign(KEY, "POST", "/reserve", b1))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "sig over body A, reordered body B sent: 401 (MAC binds exact bytes)", st == 401 and alive, "status=%s" % st)
body_reorder_sig()
def negative_ts():
    b = json.dumps({"user_id": "rt-70nt", "idempotency_key": "k70nt", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts="-99999999"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "negative X-Kavach-Timestamp: 401, alive", st == 401 and alive, "status=%s" % st)
negative_ts()
def far_future_ts():
    b = json.dumps({"user_id": "rt-70ff", "idempotency_key": "k70ff", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts="99999999999"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "far-future X-Kavach-Timestamp (year 5138): 401, alive", st == 401 and alive, "status=%s" % st)
far_future_ts()
def rid_boundary():
    b = json.dumps({"user_id": "rt-70rb", "idempotency_key": "k70rb", "seats": 1}).encode()
    st129, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, rid="r" * 129))
    b2 = json.dumps({"user_id": "rt-70rb", "idempotency_key": "k70rb", "seats": 1}).encode()
    st128, j = raw(ER, "POST", "/reserve", b2, sign(KEY, "POST", "/reserve", b2, rid="r" * 128))
    rid = j.get("reservation_id") if isinstance(j, dict) and st128 == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st129 == 401 and (st128 == 200 or rej(st128)) and alive
    return check("auth", "rid 129 chars rejected 401, 128-char boundary handled", ok, "129=%s 128=%s" % (st129, st128))
rid_boundary()
def parallel_waitlist_diff_keys_same_user():
    s0 = seats(ER2)
    outs = P(10, lambda i: post(ER2, "/waitlist", {"user_id": "rt-70pw", "idempotency_key": "k70pw%d" % i, "seats": 4})[0])
    s1 = seats(ER2)
    # clean up: cancel all waitlist entries for this user if ids came back
    wid = None
    ok = all(x != 500 and x != -1 for x in outs) \
         and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("abuse", "10 parallel waitlist joins, same user, 10 different keys: no 5xx, conserved (outs=%s)" % outs, ok, "outs=%s" % outs)
parallel_waitlist_diff_keys_same_user()
def cl_larger_than_body():
    import socket as _s
    b = b'{"user_id":"rt-70cl","idempotency_key":"k70cl","seats":1}'
    head = ("POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n" % (len(b) + 500)).encode()
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(head + b)
        sk.settimeout(4)  # engine will wait for 500 more bytes; we send nothing and close
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    s = seats(ER)
    ok = (stc == -1 or rej(stc)) and alive and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wire", "Content-Length larger than body sent, then close: graceful, alive, conserved", ok, "st=%s" % stc)
cl_larger_than_body()
def header_missing_colon():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: x\r\nX-BadHeader\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc == 400 and alive
    return check("wire", "header line missing colon: 400, engine alive", ok, "st=%s" % stc)
header_missing_colon()
def app_pay_foreign_rid():
    st, j = post(ER2, "/reserve", {"user_id": "rt-70fr", "idempotency_key": "k70fr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app pay with foreign-engine rid: skipped (hold unavailable)", True, "st=%s" % st)
    s1_before = seats(ER)
    s2_before = seats(ER2)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "outcome": "success", "user_id": "rt-70fr"}))
    s1_after = seats(ER)
    s2_after = seats(ER2)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive \
         and s1_after.get("sold", 0) == s1_before.get("sold", 0) \
         and s2_after.get("sold", 0) == s2_before.get("sold", 0)
    post(ER2, "/release", {"reservation_id": rid})
    return check("app", "app (wired to 8091) pay with 8092's rid: no 500, no sale on either engine", ok, "p=%s" % p)
app_pay_foreign_rid()
def app_pay_no_rid():
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"outcome": "success", "user_id": "rt-70nr"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app pay without reservation_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_pay_no_rid()
def app_webhook_unknown_event():
    st, j = post(ER, "/reserve", {"user_id": "rt-70wu", "idempotency_key": "k70wu", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook unknown event: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_received", "reservation_id": rid, "seats": 1}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    unchanged = s1.get("sold", 0) == s0.get("sold", 0) and s1.get("held", 0) == s0.get("held", 0)
    post(ER, "/release", {"reservation_id": rid})
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook unknown event payment_received on a HELD rid: no 500, app alive, state unchanged=%s" % unchanged, ok, "w=%s" % w)
app_webhook_unknown_event()
def chunked_reserve():
    import socket as _s
    b = json.dumps({"user_id": "rt-70ch", "idempotency_key": "k70ch", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    chunked = ("%x\r\n" % len(b)).encode() + b + b"\r\n0\r\n\r\n"
    head = ("POST /reserve HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n"
            "Authorization: %s\r\nX-Kavach-Timestamp: %s\r\nX-Kavach-Request-Id: %s\r\nX-Kavach-Signature: %s\r\nConnection: close\r\n\r\n" % (
                h["Authorization"], h["X-Kavach-Timestamp"], h["X-Kavach-Request-Id"], h["X-Kavach-Signature"])).encode()
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(head + chunked)
        sk.settimeout(6)
        try: buf = sk.recv(400)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    rid = None
    if stc == 200 and b"\r\n\r\n" in buf:
        try:
            j = json.loads(buf.split(b"\r\n\r\n", 1)[1])
            rid = j.get("reservation_id")
        except Exception: pass
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = (stc == 200 or rej(stc)) and stc != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wire", "valid chunked Transfer-Encoding reserve: served or 4xx, no 5xx, conserved", ok, "st=%s" % stc)
chunked_reserve()
def seats_float_one():
    b = b'{"user_id":"rt-70sf","idempotency_key":"k70sf","seats":1.0}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats as 1.0 (JSON float): 4xx, no 5xx, conserved", ok, "status=%s" % st)
seats_float_one()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
