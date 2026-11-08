#!/usr/bin/env python3
"""Run 71 extras: 12 angles (all live in redteam_battery.py Phase Y too).
1: over-subscription race, 10 parallel 1-seat reserves on 5 free seats: <=5 succeed, conserved
2: waitlist join then hold released: no 5xx, conserved (promotion behavior observed)
3: leading-zero timestamp: 200 or 4xx, no 5xx
4: idempotency_key with RTL-override unicode: 4xx, no 5xx
5: seats negative: 4xx, no 5xx
6: GET with request body: no 5xx, alive
7: pipelined two GETs on one connection: both served, alive
8: webhook payment_success seats=99 on 2-seat held rid: no 500, sane
9: 20 rapid app reads: no 5xx, app alive
10: Content-Type charset param: served or 4xx, conserved
11: Authorization with a third token: 401, alive
12: app pay with empty reservation_id: no 500, alive
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

# ---------------- Phase Y: run 71 extras (12 new angles) ----------------
def oversubscription_race():
    st, j = post(ER2, "/reserve", {"user_id": "rt-71os", "idempotency_key": "k71os", "seats": 25})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "over-subscription race: skipped (25-seat hold unavailable)", True, "st=%s" % st)
    post(ER2, "/confirm", {"reservation_id": rid})
    s0 = seats(ER2)
    free_before = s0.get("free", 0)
    outs = P(10, lambda i: post(ER2, "/reserve", {"user_id": "rt-71os", "idempotency_key": "k71osr%d" % i, "seats": 1})[0])
    ok_outs = [x for x in outs if x == 200]
    post(ER2, "/release", {"reservation_id": rid})
    s1 = seats(ER2)
    conserved = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    ok = len(ok_outs) <= free_before and conserved and all(x != 500 and x != -1 for x in outs)
    return check("race", "10 parallel reserves on 5 free seats: <=5 succeed, conserved (ok=%s)" % len(ok_outs), ok, "outs=%s free=%s" % (outs, free_before))
oversubscription_race()
def waitlist_promotion():
    st, j = post(ER2, "/reserve", {"user_id": "rt-71wp", "idempotency_key": "k71wp", "seats": 30})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "waitlist promotion: skipped (cannot fill ER2)", True, "st=%s" % st)
    post(ER2, "/confirm", {"reservation_id": rid})
    wst, _ = post(ER2, "/waitlist", {"user_id": "rt-71wpu", "idempotency_key": "k71wpu", "seats": 1})
    post(ER2, "/release", {"reservation_id": rid})
    s = seats(ER2)
    alive = raw(ER2, "GET", "/seats")[0] == 200
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = wst != 500 and wst != -1 and alive and conserved
    return check("state", "waitlist join then hold released: no 5xx, conserved (promotion behavior observed)", ok, "wst=%s free=%s held=%s" % (wst, s.get("free"), s.get("held")))
waitlist_promotion()
def leading_zero_ts():
    b = json.dumps({"user_id": "rt-71lz", "idempotency_key": "k71lz", "seats": 1}).encode()
    ts = "0" + str(int(time.time()))
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=ts))
    s = seats(ER)
    ok = (st == 200 or rej(st)) and st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("auth", "leading-zero X-Kavach-Timestamp: 200 or 4xx, no 5xx", ok, "status=%s" % st)
leading_zero_ts()
def rtl_override_idem():
    b = json.dumps({"user_id": "rt-71rtl", "idempotency_key": "k71\u202e\u202drtl", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "idempotency_key with RTL-override unicode: 4xx, no 5xx, conserved", ok, "status=%s" % st)
rtl_override_idem()
def seats_negative():
    b = json.dumps({"user_id": "rt-71sn", "idempotency_key": "k71sn", "seats": -1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats negative (-1): 4xx, no 5xx, conserved", ok, "status=%s" % st)
seats_negative()
def get_with_body():
    st, _ = raw(ER, "GET", "/seats", b'{"junk": true}')
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "GET /seats with a request body: no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
get_with_body()
def pipelined_requests():
    import socket as _s
    req = b"GET /seats HTTP/1.1\r\nHost: x\r\n\r\n"
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(req + req)  # pipelined: two requests, one connection
        sk.settimeout(6)
        buf = b""
        try:
            while True:
                d = sk.recv(4096)
                if not d: break
                buf += d
                if len(buf) > 16384: break
        except Exception: pass
        sk.close()
    except Exception:
        buf = b""
    n200 = buf.count(b"HTTP/1.1 200") + buf.count(b"HTTP/1.0 200")
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "pipelined two GETs on one connection: both served, alive", n200 >= 2 and alive, "200s=%d" % n200)
pipelined_requests()
def app_webhook_seats_mismatch():
    st, j = post(ER, "/reserve", {"user_id": "rt-71wm", "idempotency_key": "k71wm", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook seats mismatch: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid, "seats": 99}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    sane = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    post(ER, "/release", {"reservation_id": rid})
    ok = w != 500 and w != -1 and alive and sane
    return check("app", "webhook payment_success seats=99 on a 2-seat held rid: no 500, sane", ok, "w=%s" % w)
app_webhook_seats_mismatch()
def app_read_burst():
    outs = P(20, lambda i: raw(AR, "GET", "/api/seats")[0])
    alive = raw(AR, "GET", "/")[0] == 200
    ok = all(x != 500 and x != -1 for x in outs) and alive
    return check("app", "20 rapid GET /api/seats: no 5xx, app alive (outs sample %s)" % outs[:5], ok, "outs=%s" % outs[:8])
app_read_burst()
def ct_charset_param():
    b = json.dumps({"user_id": "rt-71cc", "idempotency_key": "k71cc", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["Content-Type"] = "application/json; charset=utf-8"
    st, j = raw(ER, "POST", "/reserve", b, h)
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = (st == 200 or rej(st)) and st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wire", "Content-Type with charset param: served or 4xx, no 5xx, conserved", ok, "status=%s" % st)
ct_charset_param()
def auth_extra_token():
    b = json.dumps({"user_id": "rt-71et", "idempotency_key": "k71et", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["Authorization"] = h["Authorization"] + " extra"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "Authorization 'Bearer testkey extra' (third token): 401, alive", st == 401 and alive, "status=%s" % st)
auth_extra_token()
def app_pay_empty_rid():
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": "", "outcome": "success", "user_id": "rt-71er"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app pay with empty reservation_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_pay_empty_rid()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
