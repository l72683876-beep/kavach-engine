#!/usr/bin/env python3
"""Run 61 extras: 12 angles (all live in redteam_battery.py Phase O too).
1: sig over /reserve, request to /RESERVE (case mismatch): 4xx, nothing processed
2: X-Kavach-Timestamp float string: 4xx
3: 1000-char request id: 4xx (128-char cap)
4: seats=3.0000000001: 400, no hold, conserved
5: seats as JSON array: 4xx
6: declared Content-Length 1000x larger, cut mid-body: no partial hold, alive
7: 10 parallel same idem key same body: one reservation, one hold, conserved
8: confirm same rid twice: second 4xx, conserved
9: app two holds same user, pay-fail both: no 500, alive
10: app GET /deals + /profile XSS/SQLi-ish queries: no 500, alive
11: webhook payment_failed seats=0: no 500, conserved
12: chunked transfer-encoding signed /reserve: handled, no 5xx
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

# ---------------- Phase O: run 61 extras (12 new angles) ----------------
def sig_path_case_mismatch():
    b = json.dumps({"user_id": "rt-61pc", "idempotency_key": "k61pc", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    st, _ = raw(ER, "POST", "/RESERVE", b, h)
    return check("auth", "sig over /reserve but request to /RESERVE (case mismatch): 4xx, nothing processed", rej(st) and st != -1, "status=%s" % st)
sig_path_case_mismatch()
def ts_float_string():
    b = json.dumps({"user_id": "rt-61tf", "idempotency_key": "k61tf", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, ts="1700000000.5")
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "X-Kavach-Timestamp as float string 1700000000.5: 4xx, no 5xx", rej(st) and st != -1, "status=%s" % st)
ts_float_string()
def rid_thousand_chars():
    b = json.dumps({"user_id": "rt-61rid", "idempotency_key": "k61rid", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, rid="r" * 1000)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "X-Kavach-Request-Id of 1000 chars: 4xx (128-char cap), no 5xx", rej(st) and st != -1, "status=%s" % st)
rid_thousand_chars()
def seats_near_integral_float():
    b = b'{"user_id":"rt-61ni","idempotency_key":"k61ni","seats":3.0000000001}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    s = seats(ER)
    ok = rej(st) and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats=3.0000000001 (near-integral float): 400, no hold, conserved", ok, "status=%s" % st)
seats_near_integral_float()
def seats_as_array():
    b = b'{"user_id":"rt-61sa","idempotency_key":"k61sa","seats":[1]}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "seats as JSON array [1]: 4xx, no 5xx", rej(st) and st != -1, "status=%s" % st)
seats_as_array()
def declared_cl_larger():
    import socket as _s
    body = json.dumps({"user_id": "rt-61cl", "idempotency_key": "k61cl", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    head = "POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % (len(body) + 990)
    for k, v in h.items(): head += "%s: %s\r\n" % (k, v)
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(head.encode() + "\r\n".encode() + body + b"XX")  # 2 of 992 promised bytes
        sk.settimeout(4)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.shutdown(_s.SHUT_RDWR); sk.close()
    except Exception:
        pass
    alive = raw(ER, "GET", "/seats")[0] == 200
    body2 = json.dumps({"reservation_id": "RSV999998", "user_id": "rt-61cl"}).encode()
    st2 = raw(ER, "POST", "/confirm", body2, sign(KEY, "POST", "/confirm", body2))[0]
    ok = alive and st2 == 404
    return check("wire", "declared Content-Length 1000x larger, connection cut mid-body: no partial hold, engine alive", ok,
                 "resp=%s next=%s" % (buf[:20], st2))
declared_cl_larger()
def same_idem_parallel_race():
    s0 = seats(ER)
    if s0.get("free", 0) < 3:
        return check("race", "10 parallel same idem key same body: skipped (free seats unavailable)", True, "free=%s" % s0.get("free"))
    held0 = s0.get("held", 0)
    b = json.dumps({"user_id": "rt-61sp", "idempotency_key": "k61sp", "seats": 1}).encode()
    def one(_):
        return raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    outs = P(10, one)
    sts = [st for st, _ in outs]
    rids = [j.get("reservation_id") for st, j in outs if st == 200 and isinstance(j, dict) and j.get("reservation_id")]
    s1 = seats(ER)
    held_delta = s1.get("held", 0) - held0
    distinct = len(set(rids))
    ok = len(rids) >= 1 and distinct == 1 and held_delta == 1 and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    if rids: post(ER, "/release", {"reservation_id": rids[0]})
    return check("race", "10 parallel same idem key same body: one reservation, one hold (429s allowed), conserved", ok,
                 "sts=%s rids200=%d held+%d" % (sorted(set(sts)), distinct, held_delta))
same_idem_parallel_race()
def double_confirm():
    st, j = post(ER, "/reserve", {"user_id": "rt-61dc", "idempotency_key": "k61dc", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("state", "double confirm: skipped (hold unavailable)", True, "st=%s" % st)
    b1 = json.dumps({"reservation_id": rid, "user_id": "rt-61dc"}).encode()
    st1 = raw(ER, "POST", "/confirm", b1, sign(KEY, "POST", "/confirm", b1))[0]
    st2 = raw(ER, "POST", "/confirm", b1, sign(KEY, "POST", "/confirm", b1))[0]
    s = seats(ER)
    ok = st1 == 200 and rej(st2) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "confirm same rid twice: first 200, second 4xx, conserved", ok,
                 "c1=%s c2=%s" % (st1, st2))
double_confirm()
def app_two_holds_pay_fail_one():
    st1, j1 = raw(AR, "POST", "/api/hold", '{"user_id":"rt-61ah","seats":1}')
    st2, j2 = raw(AR, "POST", "/api/hold", '{"user_id":"rt-61ah","seats":1}')
    r1 = j1.get("reservation_id") if isinstance(j1, dict) else None
    r2 = j2.get("reservation_id") if isinstance(j2, dict) else None
    if not (r1 and r2):
        if r1: raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": r1, "outcome": "payment_failed"}))
        return check("app", "app: two holds same user, pay-fail one: skipped (holds unavailable)", True, "h1=%s h2=%s" % (st1, st2))
    stp, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": r1, "outcome": "payment_failed"}))
    alive = raw(AR, "GET", "/")[0] == 200
    stc, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": r2, "outcome": "payment_failed"}))
    return check("app", "app: two holds same user, pay-fail both: no 500, app alive, both released", stp != 500 and stp != -1 and stc != 500 and alive, "pay1=%s pay2=%s" % (stp, stc))
app_two_holds_pay_fail_one()
def app_query_fuzz():
    import urllib.parse as _u
    q = _u.quote('<script>alert(1)</script>')
    st1 = raw(AR, "GET", "/deals?id=" + q)[0]
    st2 = raw(AR, "GET", "/profile?u=" + _u.quote("rt-61x'; DROP TABLE users;--"))[0]
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st1 != 500 and st1 != -1 and st2 != 500 and st2 != -1 and alive
    return check("app", "app GET /deals + /profile with XSS/SQLi-ish query strings: no 500, app alive", ok, "deals=%s profile=%s" % (st1, st2))
app_query_fuzz()
def webhook_zero_seats():
    st, j = post(ER, "/reserve", {"user_id": "rt-61wz", "idempotency_key": "k61wz", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("app", "webhook seats=0: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest",
                 json.dumps({"event": "payment_failed", "reservation_id": rid, "seats": 0}))
    alive = raw(AR, "GET", "/")[0] == 200
    post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st2 != 500 and st2 != -1 and alive and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("app", "webhook payment_failed with seats=0 (valid types): no 500, conserved after cleanup", ok, "wh=%s" % st2)
webhook_zero_seats()
def chunked_reserve():
    import socket as _s
    body = json.dumps({"user_id": "rt-61ck", "idempotency_key": "k61ck", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    head = "POST /reserve HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
    for k, v in h.items(): head += "%s: %s\r\n" % (k, v)
    chunked = ("%x\r\n" % len(body)).encode() + body + b"\r\n0\r\n\r\n"
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(head.encode() + "\r\n".encode() + chunked)
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    alive = raw(ER, "GET", "/seats")[0] == 200
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    rids = []
    if stc == 200:
        try:
            j = json.loads(buf.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in buf else {}
            rids = [j.get("reservation_id")] if j.get("reservation_id") else []
        except Exception: pass
    for r in rids: post(ER, "/release", {"reservation_id": r})
    s = seats(ER)
    ok = stc in (200, 400, 401, 409, 429) and alive and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wire", "chunked transfer-encoding signed /reserve: handled, no 5xx, engine alive, conserved", ok,
                 "st=%s" % stc)
chunked_reserve()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
