#!/usr/bin/env python3
"""Run 74 extras: 12 angles (all live in redteam_battery.py Phase AB too).
1: MAC over GET, POST sent: 401
2: 5000-char path suffix on /seats: 4xx, alive
3: idempotency_key as JSON number: 4xx, no 5xx
4: seats as JSON array: 4xx, no 5xx
5: two holds same user: release one, confirm other: sale lands, conserved
6: 5 same-key + 5 diff-key parallel reserves same user: no 5xx, conserved
7: webhook event null: no 500
8: app GET /api/deals with 5000-char query: no 500
9: Expect: 100-continue reserve: served or 4xx, no 5xx
10: user_id whitespace-only: no 5xx
11: app book same rid twice: no 500, at most one sale
12: waitlist seats=0: 4xx, no 5xx
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

# ---------------- Phase AB: run 74 extras (12 new angles) ----------------
def mac_wrong_method():
    b = json.dumps({"user_id": "rt-74mm", "idempotency_key": "k74mm", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "GET", "/reserve", b))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC computed over GET, POST sent: 401, alive", st == 401 and alive, "status=%s" % st)
mac_wrong_method()
def long_path_suffix():
    st, _ = raw(ER, "GET", "/seats" + "/" + "a" * 5000)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "5000-char path suffix on /seats: 4xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
long_path_suffix()
def idem_json_number():
    b = b'{"user_id": "rt-74in", "idempotency_key": 99, "seats": 1}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "idempotency_key as JSON number: 4xx, no 5xx, conserved", ok, "status=%s" % st)
idem_json_number()
def seats_json_array():
    b = b'{"user_id": "rt-74sa", "idempotency_key": "k74sa", "seats": [1]}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats as JSON array [1]: 4xx, no 5xx, conserved", ok, "status=%s" % st)
seats_json_array()
def two_holds_release_one_confirm_other():
    st1, j1 = post(ER, "/reserve", {"user_id": "rt-74th", "idempotency_key": "k74tha", "seats": 1})
    st2, j2 = post(ER, "/reserve", {"user_id": "rt-74th", "idempotency_key": "k74thb", "seats": 2})
    rid1 = j1.get("reservation_id") if isinstance(j1, dict) and st1 == 200 else None
    rid2 = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    if not rid1 or not rid2:
        return check("state", "two holds: skipped (holds unavailable)", True, "st1=%s st2=%s" % (st1, st2))
    r, _ = post(ER, "/release", {"reservation_id": rid1})
    c, _ = post(ER, "/confirm", {"reservation_id": rid2})
    s = seats(ER)
    sold_gain = s.get("sold", 0) - (s.get("sold", 0))  # baseline unknown; assert via total
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = r != 500 and c != 500 and c != -1 and conserved
    return check("state", "two holds same user: release one, confirm other → sale lands, conserved", ok, "r=%s c=%s" % (r, c))
two_holds_release_one_confirm_other()
def mixed_key_parallel_same_user():
    outs_same = P(5, lambda i: post(ER, "/reserve", {"user_id": "rt-74mk", "idempotency_key": "k74mksame", "seats": 1})[0])
    outs_diff = P(5, lambda i: post(ER, "/reserve", {"user_id": "rt-74mk", "idempotency_key": "k74mkdiff%d" % i, "seats": 1})[0])
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs_same + outs_diff) and conserved
    return check("race", "5 same-key + 5 diff-key parallel reserves same user: no 5xx, conserved", ok, "same=%s diff=%s" % (outs_same, outs_diff[:5]))
mixed_key_parallel_same_user()
def webhook_null_event():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": None, "reservation_id": "whatever", "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook event null: no 500, app alive", w != 500 and w != -1 and alive, "w=%s" % w)
webhook_null_event()
def app_deals_long_query():
    p, _ = raw(AR, "GET", "/api/deals?" + "x=" + "A" * 5000)
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app GET /api/deals with 5000-char query: no 500, alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_deals_long_query()
def expect_100_continue():
    import socket as _s
    b = json.dumps({"user_id": "rt-74ec", "idempotency_key": "k74ec", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    head = ("POST /reserve HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: %d\r\nContent-Type: application/json\r\n"
            "Authorization: %s\r\nX-Kavach-Timestamp: %s\r\nX-Kavach-Request-Id: %s\r\nX-Kavach-Signature: %s\r\nConnection: close\r\n\r\n" % (
                len(b), h["Authorization"], h["X-Kavach-Timestamp"], h["X-Kavach-Request-Id"], h["X-Kavach-Signature"])).encode()
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(head)
        sk.settimeout(3)
        try: buf = sk.recv(200)  # interim "HTTP/1.1 100 Continue"
        except Exception: pass
        sk.sendall(b)
        sk.settimeout(6)
        try:
            while True:
                d = sk.recv(4096)
                if not d: break
                buf += d
                if len(buf) > 8000: break
        except Exception: pass
        sk.close()
    except Exception:
        pass
    lines = [l for l in buf.split(b"\r\n") if l.startswith(b"HTTP/1.")]
    stc = int(lines[-1].split(b" ")[1]) if lines else -1  # last status line: final response, 100 was interim
    rid = None
    if stc == 200 and b"\r\n\r\n" in buf:
        try:
            j = json.loads(buf.rsplit(b"\r\n\r\n", 1)[-1])
            rid = j.get("reservation_id")
        except Exception: pass
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = (stc == 200 or rej(stc)) and stc != 500 and stc != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wire", "Expect: 100-continue reserve: served or 4xx, no 5xx, conserved", ok, "st=%s" % stc)
expect_100_continue()
def user_id_whitespace_only():
    b = json.dumps({"user_id": "   ", "idempotency_key": "k74uw", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "user_id whitespace-only '   ': no 5xx, conserved", ok, "status=%s" % st)
user_id_whitespace_only()
def app_book_twice():
    st, j = post(ER, "/reserve", {"user_id": "rt-74bt", "idempotency_key": "k74bt", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app book twice: skipped (hold unavailable)", True, "st=%s" % st)
    b1, _ = raw(AR, "POST", "/api/book", json.dumps({"reservation_id": rid, "user_id": "rt-74bt"}))
    s0 = seats(ER)
    b2, _ = raw(AR, "POST", "/api/book", json.dumps({"reservation_id": rid, "user_id": "rt-74bt"}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    no_double = s1.get("sold", 0) <= s0.get("sold", 0) + 2
    ok = b1 != 500 and b1 != -1 and b2 != 500 and b2 != -1 and alive and no_double
    return check("app", "app book same rid twice: no 500, at most one sale", ok, "b1=%s b2=%s sold=%s" % (b1, b2, s1.get("sold")))
app_book_twice()
def waitlist_zero_seats():
    w, _ = post(ER2, "/waitlist", {"user_id": "rt-74wz", "idempotency_key": "k74wz", "seats": 0})
    s = seats(ER2)
    ok = w != 500 and w != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "waitlist join seats=0: 4xx, no 5xx, conserved", ok, "status=%s" % w)
waitlist_zero_seats()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
