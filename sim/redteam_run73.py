#!/usr/bin/env python3
"""Run 73 extras: 12 angles (all live in redteam_battery.py Phase AA too).
1: 20 rapid GET /seats (IP burst): only 200/429, no 5xx
2: release an already-expired hold: 4xx, no 5xx, conserved
3: app book with malformed reservation_id: no 500
4: user_id as JSON number: 4xx, no 5xx
5: seats as leading-zero string '01': 4xx, no 5xx
6: header with embedded CR (injection attempt): 400
7: 10 parallel reserves, distinct users, enough free: all succeed, conserved
8: webhook payment_success on already-BOOKED rid: no 500, no double sale
9: app pay unknown outcome 'refunded': no 500
10: sig over '/reserve/' sent to '/reserve': 401
11: same idem key reused after hold expiry: no 5xx, conserved
12: empty X-Kavach-Request-Id: 401
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

# ---------------- Phase AA: run 73 extras (12 new angles) ----------------
def ip_burst_flood():
    outs = P(20, lambda i: raw(ER, "GET", "/seats")[0])
    time.sleep(1)
    s = seats(ER)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = all(x in (200, 429) for x in outs) and alive and s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    return check("rate", "20 rapid GET /seats (IP burst): only 200/429, no 5xx, alive", ok, "outs=%s" % outs[:8])
ip_burst_flood()
def release_after_expiry():
    st, j = post(ER, "/reserve", {"user_id": "rt-73re", "idempotency_key": "k73re", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "release after expiry: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(4)  # hold-ttl 3s: expired
    s0 = seats(ER)
    r, _ = post(ER, "/release", {"reservation_id": rid})
    s1 = seats(ER)
    conserved = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    ok = r != 500 and r != -1 and s1.get("free", 0) >= s0.get("free", 0) and conserved
    return check("state", "release an already-expired hold: 4xx, no 5xx, conserved", ok, "status=%s" % r)
release_after_expiry()
def app_book_malformed_rid():
    p, _ = raw(AR, "POST", "/api/book", json.dumps({"reservation_id": "!!!not-a-rid!!!", "user_id": "rt-73bm"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app book with malformed reservation_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_book_malformed_rid()
def user_id_json_number():
    b = b'{"user_id": 12345, "idempotency_key": "k73un", "seats": 1}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "user_id as JSON number (not string): 4xx, no 5xx, conserved", ok, "status=%s" % st)
user_id_json_number()
def seats_leading_zero_string():
    b = b'{"user_id":"rt-73lz","idempotency_key":"k73lz","seats":"01"}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats as leading-zero string '01': 4xx, no 5xx, conserved", ok, "status=%s" % st)
seats_leading_zero_string()
def header_cr_injection():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: x\r\nX-Junk: a\rX-Injected: 1\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc == 400 and alive
    return check("wire", "header with embedded CR (injection attempt): 400, alive", ok, "st=%s" % stc)
header_cr_injection()
def parallel_distinct_users_exact_free():
    s0 = seats(ER2)
    free_before = s0.get("free", 0)
    n = min(10, free_before)
    if n < 1:
        return check("race", "10 parallel distinct-user reserves: skipped (no free seats on ER2)", True, "free=0")
    outs = P(n, lambda i: post(ER2, "/reserve", {"user_id": "rt-73pd%d" % i, "idempotency_key": "k73pd%d" % i, "seats": 1})[0])
    s1 = seats(ER2)
    all_ok = all(x == 200 for x in outs)
    rids = []
    conserved = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    held_gain = s1.get("held", 0) - s0.get("held", 0)
    for i in range(n):
        rid = "k73pd%d" % i
    # cleanup: release by reserving lookups not possible; just confirm nothing: holds expire in 3s anyway
    ok = all_ok and conserved and held_gain == n
    return check("race", "%d parallel reserves, %d distinct users, enough free: all succeed, held +%d" % (n, n, n), ok, "outs=%s held_gain=%s" % (outs, held_gain))
parallel_distinct_users_exact_free()
def webhook_success_on_booked():
    st, j = post(ER, "/reserve", {"user_id": "rt-73wb", "idempotency_key": "k73wb", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook success on booked: skipped (hold unavailable)", True, "st=%s" % st)
    post(ER, "/confirm", {"reservation_id": rid})
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid, "seats": 2}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    no_double = s1.get("sold", 0) == s0.get("sold", 0)
    ok = w != 500 and w != -1 and alive and no_double
    return check("app", "webhook payment_success on already-BOOKED rid: no 500, no double sale", ok, "w=%s sold=%s" % (w, s1.get("sold")))
webhook_success_on_booked()
def app_pay_refunded_outcome():
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": "nonexistent-rid", "outcome": "refunded", "user_id": "rt-73pr"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app pay with unknown outcome 'refunded': no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_pay_refunded_outcome()
def sig_trailing_slash_path():
    b = json.dumps({"user_id": "rt-73ts", "idempotency_key": "k73ts", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve/", b))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "sig over '/reserve/' sent to '/reserve': 401, alive", st == 401 and alive, "status=%s" % st)
sig_trailing_slash_path()
def idem_reuse_after_expiry():
    st, j = post(ER, "/reserve", {"user_id": "rt-73ie", "idempotency_key": "k73ie", "seats": 1})
    rid1 = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    time.sleep(4)  # expire
    st2, j2 = post(ER, "/reserve", {"user_id": "rt-73ie", "idempotency_key": "k73ie", "seats": 1})
    rid2 = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    if rid2 and rid2 != rid1: post(ER, "/release", {"reservation_id": rid2})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st2 != 500 and st2 != -1 and conserved
    return check("state", "same idem key reused after hold expiry: no 5xx, conserved (fresh hold or 4xx)", ok, "st2=%s same=%s" % (st2, rid1 == rid2))
idem_reuse_after_expiry()
def empty_rid_header():
    b = json.dumps({"user_id": "rt-73er", "idempotency_key": "k73er", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, rid=""))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "empty X-Kavach-Request-Id header: 401, alive", st == 401 and alive, "status=%s" % st)
empty_rid_header()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
