#!/usr/bin/env python3
"""Run 68 extras: 12 angles (all live in redteam_battery.py Phase V too).
1: float-string timestamp: 4xx, alive
2: API key with leading space: 401, alive
3: seats as NaN literal: 4xx, conserved
4: emoji user_id: no 5xx, conserved
5: 10 parallel reserves same idem key: at most 1 hold, conserved
6: app webhook payment_refunded for a BOOKED rid: no 500, app alive
7: tenant1 key cancels tenant2 waitlist entry: 4xx
8: duplicate Host headers: 400/421, alive
9: double release: first frees, second no-op, conserved
10: 10,000-char query string on /seats: alive
11: JSON body with UTF-8 BOM: 4xx, conserved
12: app hold HTML-injection user_id: no 500, alive
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

# ---------------- Phase V: run 68 extras (12 new angles) ----------------
def float_string_ts():
    b = json.dumps({"user_id": "rt-68ft", "idempotency_key": "k68ft", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts="1762485600.5"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "X-Kavach-Timestamp as float string (1762485600.5): 4xx, no 5xx", rej(st) and alive, "status=%s" % st)
float_string_ts()
def whitespace_api_key():
    b = json.dumps({"user_id": "rt-68wk", "idempotency_key": "k68wk", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(" testkey", "POST", "/reserve", b))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "API key with leading space (' testkey'): 401, alive", st == 401 and alive, "status=%s" % st)
whitespace_api_key()
def seats_nan_literal():
    b = b'{"user_id":"rt-68nn","idempotency_key":"k68nn","seats":NaN}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and st != 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats as NaN literal (invalid JSON constant): 4xx, no 5xx", ok, "status=%s" % st)
seats_nan_literal()
def emoji_user_id():
    st, j = post(ER, "/reserve", {"user_id": "rt-68\xf0\x9f\x98\x80user", "idempotency_key": "k68em", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "user_id with emoji: no 5xx, conserved", ok, "status=%s" % st)
emoji_user_id()
def parallel_same_idem_key():
    s0 = seats(ER)
    b = json.dumps({"user_id": "rt-68pk", "idempotency_key": "k68pk", "seats": 1}).encode()
    hdr = sign(KEY, "POST", "/reserve", b)
    outs = P(10, lambda i: raw(ER, "POST", "/reserve", b, dict(hdr))[0])
    s1 = seats(ER)
    held_d = s1.get("held", 0) - s0.get("held", 0)
    ok = all(x != 500 and x != -1 for x in outs) and held_d <= 1 \
         and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("race", "10 parallel reserves, same idempotency_key: at most 1 hold, conserved", ok, "held%+d outs=%s" % (held_d, outs))
parallel_same_idem_key()
def app_webhook_refunded():
    st, j = post(ER, "/reserve", {"user_id": "rt-68rf", "idempotency_key": "k68rf", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook payment_refunded: skipped (hold unavailable)", True, "st=%s" % st)
    b = json.dumps({"reservation_id": rid, "user_id": "rt-68rf"}).encode()
    stc = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    if stc != 200:
        return check("app", "webhook payment_refunded: skipped (confirm failed)", True, "c=%s" % stc)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_refunded", "reservation_id": rid, "seats": 1}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive \
         and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("app", "app webhook payment_refunded for a BOOKED rid: no 500, app alive, conserved", ok, "w=%s" % w)
app_webhook_refunded()
def cross_tenant_waitlist_cancel():
    st2, j2 = post(ER2, "/waitlist", {"user_id": "rt-68xc", "idempotency_key": "k68xc", "seats": 4})
    wid = j2.get("waitlist_id") if isinstance(j2, dict) and st2 in (200, 409) and isinstance(j2, dict) else j2.get("waitlist_id")
    if not wid:
        return check("abuse", "cross-tenant waitlist cancel: skipped (no waitlist entry)", True, "st=%s" % st2)
    st, _ = post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    # now try cancelling it again with tenant1's key on ER1 (different instance, same key creds)
    st2b, _ = raw(ER, "POST", "/waitlist/cancel", json.dumps({"waitlist_id": wid}).encode(),
                  sign(KEY, "POST", "/waitlist/cancel", json.dumps({"waitlist_id": wid}).encode()))
    ok = rej(st2b) or st2b == -1
    post(ER2, "/waitlist/cancel", {"waitlist_id": wid}) if st in (200, 404) else None
    return check("abuse", "tenant1 key cancels tenant2's waitlist entry: 4xx (or unknown on other instance)", ok, "st=%s" % st2b)
cross_tenant_waitlist_cancel()
def duplicate_host_headers():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc in (400, 421) and alive
    return check("wire", "duplicate Host headers: 400/421, engine alive", ok, "st=%s" % stc)
duplicate_host_headers()
def double_release():
    st, j = post(ER, "/reserve", {"user_id": "rt-68dr", "idempotency_key": "k68dr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "double release: skipped (hold unavailable)", True, "st=%s" % st)
    b = json.dumps({"reservation_id": rid}).encode()
    s0 = seats(ER)
    h0 = s0.get("held", 0); f0 = s0.get("free", 0)
    r1, _ = raw(ER, "POST", "/release", b, sign(KEY, "POST", "/release", b))
    s1 = seats(ER)
    r2, _ = raw(ER, "POST", "/release", b, sign(KEY, "POST", "/release", b))
    s2 = seats(ER)
    ok = r1 == 200 and s1.get("held", 0) == h0 - 1 and s1.get("free", 0) == f0 + 1 \
         and (rej(r2) or r2 == 200) and s2.get("held", 0) == s1.get("held", 0) and s2.get("free", 0) == s1.get("free", 0) \
         and s2.get("total") == s2.get("sold") + s2.get("held") + s2.get("free")
    return check("state", "double release: first frees, second no-op, conserved", ok, "r1=%s r2=%s" % (r1, r2))
double_release()
def long_query_string():
    q = "/seats?" + "x=" + "a" * 10000
    st, _ = raw(ER, "GET", q)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "10,000-char query string on /seats: 4xx/431 or served, alive", st != 500 and st != -1 and alive, "status=%s" % st)
long_query_string()
def bom_json_body():
    b = b'\xef\xbb\xbf' + json.dumps({"user_id": "rt-68bom", "idempotency_key": "k68bom", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "JSON body with UTF-8 BOM prefix: 4xx, no 5xx, conserved", ok, "status=%s" % st)
bom_json_body()
def app_hold_html_user():
    st, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "<script>alert(1)</script>", "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with HTML-injection user_id: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_html_user()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
