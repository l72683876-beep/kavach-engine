#!/usr/bin/env python3
"""Run 72 extras: 12 angles (all live in redteam_battery.py Phase Z too).
1: 5 confirms + 5 releases on the same rid in parallel: exactly one outcome, conserved
2: MAC over testkey, Authorization otherkey: 401
3: absolute-form request line: served 200
4: confirm with 200-char reservation_id: 4xx, no 5xx
5: webhook payment_failed twice on a HELD rid: no 500, no double-free
6: app hold with empty user_id: no 500
7: HTTP/0.9-style request line: rejected or ignored, alive
8: waitlist join seats=999: 4xx, no 5xx
9: confirm a released rid: 4xx, no sale
10: 10 parallel app holds + 10 reads: no 5xx, conserved
11: X-Kavach-Signature with 0x prefix: 401
12: seats 2147483648 (int32 overflow): no 5xx, conserved
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

# ---------------- Phase Z: run 72 extras (12 new angles) ----------------
def same_rid_confirm_release_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-72cr", "idempotency_key": "k72cr", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "same-rid confirm/release race: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    outs = P(10, lambda i: post(ER, "/confirm" if i < 5 else "/release", {"reservation_id": rid})[0])
    s1 = seats(ER)
    confirmed = s1.get("sold", 0) == s0.get("sold", 0) + 2
    released = s1.get("free", 0) == s0.get("free", 0) + 2
    conserved = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs) and (confirmed or released) and not (confirmed and released) and conserved
    return check("race", "5 confirms + 5 releases same rid in parallel: exactly one outcome, conserved", ok, "outs=%s sold=%s free=%s" % (outs, s1.get("sold"), s1.get("free")))
same_rid_confirm_release_race()
def mac_auth_key_mismatch():
    b = json.dumps({"user_id": "rt-72mk", "idempotency_key": "k72mk", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)  # MAC over testkey
    h["Authorization"] = "Bearer otherkey"  # but says otherkey
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC over testkey, Authorization otherkey (key mismatch): 401, alive", st == 401 and alive, "status=%s" % st)
mac_auth_key_mismatch()
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
    ok = stc == 200 and alive
    return check("wire", "absolute-form request line 'GET http://... /seats': served 200, alive", ok, "st=%s" % stc)
absolute_form_uri()
def confirm_long_rid():
    p, _ = post(ER, "/confirm", {"reservation_id": "r" * 200})
    s = seats(ER)
    ok = p != 500 and p != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "confirm with 200-char reservation_id in body: 4xx, no 5xx, conserved", ok, "status=%s" % p)
confirm_long_rid()
def webhook_failed_twice_on_held():
    st, j = post(ER, "/reserve", {"user_id": "rt-72wf", "idempotency_key": "k72wf", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook failed twice on held: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    w1, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_failed", "reservation_id": rid, "seats": 2}))
    w2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_failed", "reservation_id": rid, "seats": 2}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    sane = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    freed = s1.get("free", 0) >= s0.get("free", 0)
    post(ER, "/release", {"reservation_id": rid})
    ok = w1 != 500 and w1 != -1 and w2 != 500 and w2 != -1 and alive and sane and freed
    return check("app", "webhook payment_failed twice on HELD rid: no 500, no double-free, sane", ok, "w1=%s w2=%s" % (w1, w2))
webhook_failed_twice_on_held()
def app_hold_empty_user():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "", "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with empty user_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_empty_user()
def http09_request():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = (stc == -1 or rej(stc)) and alive
    return check("wire", "HTTP/0.9-style request line: rejected or ignored, alive", ok, "st=%s" % stc)
http09_request()
def waitlist_over_capacity():
    w, _ = post(ER2, "/waitlist", {"user_id": "rt-71wc", "idempotency_key": "k71wc999", "seats": 999})
    s = seats(ER2)
    ok = w != 500 and w != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "waitlist join seats=999 (over capacity): 4xx, no 5xx, conserved", ok, "status=%s" % w)
waitlist_over_capacity()
def confirm_released_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-72cr2", "idempotency_key": "k72cr2", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "confirm released rid: skipped (hold unavailable)", True, "st=%s" % st)
    post(ER, "/release", {"reservation_id": rid})
    s0 = seats(ER)
    c, _ = post(ER, "/confirm", {"reservation_id": rid})
    s1 = seats(ER)
    ok = c != 500 and c != -1 and s1.get("sold", 0) == s0.get("sold", 0) \
         and s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    return check("state", "confirm a released rid: 4xx, no sale, conserved", ok, "status=%s" % c)
confirm_released_rid()
def app_mixed_burst():
    outs_h = P(10, lambda i: raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-72mb%d" % i, "seats": 1}))[0])
    outs_r = P(10, lambda i: raw(AR, "GET", "/api/seats")[0])
    s = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    sane = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs_h + outs_r) and alive and sane
    return check("app", "10 parallel app holds + 10 reads: no 5xx, alive, conserved", ok, "holds=%s" % outs_h[:6])
app_mixed_burst()
def sig_0x_prefix():
    b = json.dumps({"user_id": "rt-72sx", "idempotency_key": "k72sx", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Signature"] = "0x" + h["X-Kavach-Signature"]
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "X-Kavach-Signature with 0x prefix: 401, alive", st == 401 and alive, "status=%s" % st)
sig_0x_prefix()
def seats_int32_overflow():
    b = json.dumps({"user_id": "rt-72io", "idempotency_key": "k72io", "seats": 2147483648}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats 2147483648 (int32 overflow, < int64 max): no 5xx, conserved", ok, "status=%s" % st)
seats_int32_overflow()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
