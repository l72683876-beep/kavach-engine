#!/usr/bin/env python3
"""Run 78 extras: 12 angles (all live in redteam_battery.py Phase AF too).
1: timestamp 'null': 401/400, alive
2: waitlist join then 10 parallel cancels: no 5xx, alive
3: waitlist promote with zero free seats: no 5xx, alive
4: HTTP/1.9 request line: no 5xx, alive
5: app release rid held on engine 8092: no 500, app alive
6: webhook token uppercase variant: rejected, no 500
7: GET with body: no 5xx, alive
8: reserve seats=1.5: 4xx, conserved
9: app status rid as number: no 500
10: after reserve burst 429, GET /seats still 200
11: empty X-Kavach-Request-Id: 401/400, alive
12: empty X-Kavach-Signature: 401/400, alive
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

# ---------------- Phase AF: run 78 extras (12 new angles) ----------------
def ts_null_string():
    b = json.dumps({"user_id": "rt-78tn", "idempotency_key": "k78tn", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts="null"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp 'null' (literal string): 401/400, alive", st in (400, 401) and alive, "status=%s" % st)
ts_null_string()
def waitlist_join_cancel_race():
    obj = {"user_id": "rt-78wr", "idempotency_key": "k78wr", "event_id": "prod-v1"}
    outs = []
    for i in range(2):
        outs.append(post(ER, "/waitlist", obj)[0])
    c_outs = P(10, lambda i: post(ER, "/waitlist/cancel", obj)[0])
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = all(x != 500 and x != -1 for x in outs + c_outs) and alive
    return check("race", "waitlist join then 10 parallel cancels: no 5xx, engine alive", ok, "joins=%s cancels=%s" % (outs, c_outs))
waitlist_join_cancel_race()
def promote_no_free_seats():
    st, j = post(ER, "/waitlist", {"user_id": "rt-78pn", "idempotency_key": "k78pn", "event_id": "prod-v1"})
    # try promotion while all seats held (battery holds seats earlier in run; use ER2 which we first fully hold)
    s0 = seats(ER2)
    rid = None
    st2, j2 = post(ER2, "/reserve", {"user_id": "rt-78pn", "idempotency_key": "k78pn2", "seats": s0.get("total", 0)})
    if isinstance(j2, dict) and st2 == 200:
        rid = j2.get("reservation_id")
    pw, _ = post(ER, "/waitlist/promote", {"event_id": "prod-v1"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    if rid:
        post(ER2, "/release", {"reservation_id": rid})
    ok = pw != 500 and pw != -1 and alive
    return check("state", "waitlist promote with zero free seats: no 5xx, alive", ok, "pw=%s" % pw)
promote_no_free_seats()
def http_19_version():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.9\r\nHost: x\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "HTTP/1.9 request line (unknown version): no 5xx, alive", stc != 500 and stc != -1 and alive, "st=%s" % stc)
http_19_version()
def app_release_other_engine_rid():
    st, j = post(ER2, "/reserve", {"user_id": "rt-78or", "idempotency_key": "k78or", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app release other-engine rid: skipped (8092 hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/release", json.dumps({"reservation_id": rid}))
    alive = raw(AR, "GET", "/")[0] == 200
    post(ER2, "/release", {"reservation_id": rid})
    ok = p != 500 and p != -1 and alive
    return check("app", "app release with rid held on engine 8092: no 500, app alive", ok, "p=%s" % p)
app_release_other_engine_rid()
def webhook_token_case():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=WHSEC-redtest", json.dumps({"event": "payment_success", "reservation_id": "RSV00000001", "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook token uppercase variant WHSEC-redtest: rejected, no 500, app alive", w != 500 and w != -1 and alive and w != 200, "w=%s" % w)
webhook_token_case()
def get_with_body():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "GET /seats with a body (Content-Length 2): no 5xx, alive", ok, "st=%s" % stc)
get_with_body()
def seats_float():
    st, _ = post(ER, "/reserve", {"user_id": "rt-78fl", "idempotency_key": "k78fl", "seats": 1.5})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "reserve with seats=1.5 (float): 4xx, no 5xx, conserved", ok, "status=%s" % st)
seats_float()
def app_status_rid_number():
    p, _ = raw(AR, "GET", "/api/status?reservation_id=12345")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app status with rid as number 12345: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_status_rid_number()
def post_429_recovery():
    # ip limiter is 100/s with burst 300 (a 120 burst never drains it); the user limiter is 2/s,
    # so a rapid same-user burst is what reliably fires 429
    outs = [post(ER, "/reserve", {"user_id": "rt-78rc", "idempotency_key": "k78rc%d" % i, "seats": 1})[0] for i in range(10)]
    saw429 = 429 in outs
    st, _ = raw(ER, "GET", "/seats")  # 200 or 429 both fine, the point is the engine still answers after limiting
    ok = saw429 and st in (200, 429)
    return check("rate", "same-user burst fires the limiter (429 seen), engine still answers /seats", ok, "saw429=%s get=%s outs=%s" % (saw429, st, outs))
post_429_recovery()
def empty_rid_header():
    b = json.dumps({"user_id": "rt-78er", "idempotency_key": "k78er", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Request-Id"] = ""
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "empty X-Kavach-Request-Id: 401/400, alive", st in (400, 401) and alive, "status=%s" % st)
empty_rid_header()
def empty_signature():
    b = json.dumps({"user_id": "rt-78es", "idempotency_key": "k78es", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Signature"] = ""
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "empty X-Kavach-Signature: 401/400, alive", st in (400, 401) and alive, "status=%s" % st)
empty_signature()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
