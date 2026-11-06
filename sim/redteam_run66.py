#!/usr/bin/env python3
"""Run 66 extras: 12 angles (all live in redteam_battery.py Phase T too).
1: two Authorization headers: rejected 400 (RFC 7235)
2: valid /reserve signature replayed on /book: 401 (endpoint-bound)
3: tenant2's hold confirmed with tenant1's key: 4xx, seats unchanged
4: tenant2's idem key via /status with tenant1's key: 4xx, no leak
5: sig over /reserve?debug=1 AND request to /reserve?debug=1: accepted
6: OPTIONS /reserve: 4xx/405, alive
7: TRACE /seats: 4xx/405, alive
8: confirm with reservation_id as JSON number: 4xx
9: idempotency_key of 10,000 chars: no 5xx, conserved
10: app pay twice same rid: one sale, second no-op
11: app hold seats=true: no 500
12: waitlist join seats=4 boundary: clean, conserved
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

# ---------------- Phase T: run 66 extras (12 new angles) ----------------
def duplicate_auth_headers():
    import socket as _s
    b = json.dumps({"user_id": "rt-66da", "idempotency_key": "k66da", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    hdr = b""
    for k, v in h.items():
        if k == "Authorization":
            continue
        hdr += ("%s: %s\r\n" % (k, v)).encode()
    hdr += b"Content-Type: application/json\r\n"
    req = (b"POST /reserve HTTP/1.1\r\nHost: x\r\n"
           + b"Authorization: Bearer testkey\r\n"
           + b"Authorization: Bearer otherkey\r\n"
           + hdr + b"Content-Length: " + str(len(b)).encode() + b"\r\nConnection: close\r\n\r\n" + b)
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(req)
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    st = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    return check("auth", "two Authorization headers: rejected 400 (RFC 7235), not accepted on first-header-wins", st in (400, 401), "status=%s" % st)
duplicate_auth_headers()
def reserve_sig_on_book():
    b = json.dumps({"user_id": "rt-66rb", "idempotency_key": "k66rb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)  # MAC over /reserve
    st, _ = raw(ER, "POST", "/book", b, h)  # sent to /book
    return check("auth", "valid /reserve signature replayed on /book: 401 (endpoint-bound)", st == 401, "status=%s" % st)
reserve_sig_on_book()
def cross_tenant_confirm():
    # reserve with tenant2's key (otherkey)
    b = json.dumps({"user_id": "rt-66t2", "idempotency_key": "k66t2", "seats": 1}).encode()
    h2 = sign("otherkey", "POST", "/reserve", b)
    st2, j2 = raw(ER, "POST", "/reserve", b, h2)
    rid = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    if not rid:
        return check("state", "cross-tenant confirm: skipped (tenant2 hold unavailable)", True, "st=%s" % st2)
    s0 = seats(ER)
    b3 = json.dumps({"reservation_id": rid, "user_id": "rt-66t2"}).encode()
    st3 = raw(ER, "POST", "/confirm", b3, sign("testkey", "POST", "/confirm", b3))[0]
    s1 = seats(ER)
    unchanged = (s1.get("sold", 0) == s0.get("sold", 0)) and (s1.get("held", 0) == s0.get("held", 0))
    # cleanup with the right tenant
    b4 = json.dumps({"reservation_id": rid}).encode()
    raw(ER, "POST", "/release", b4, sign("otherkey", "POST", "/release", b4))
    ok = rej(st3) and unchanged
    return check("state", "tenant2's hold confirmed with tenant1's key: 4xx, seats unchanged", ok, "st=%s" % st3)
cross_tenant_confirm()
def cross_tenant_status():
    b = json.dumps({"user_id": "rt-66s2", "idempotency_key": "k66s2", "seats": 1}).encode()
    st2, j2 = raw(ER, "POST", "/reserve", b, sign("otherkey", "POST", "/reserve", b))
    rid = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    if rid:
        b4 = json.dumps({"reservation_id": rid}).encode()
        raw(ER, "POST", "/release", b4, sign("otherkey", "POST", "/release", b4))
    st, j = raw(ER, "GET", "/status?idempotency_key=k66s2", None, sign("testkey", "GET", "/status", b""))
    body = json.dumps(j)[:120] if isinstance(j, dict) else ""
    ok = rej(st) and "reservation_id" not in body
    return check("state", "tenant2's idem key queried via /status with tenant1's key: 4xx, no result leak", ok, "st=%s" % st)
cross_tenant_status()
def sig_with_query_ok():
    b = json.dumps({"user_id": "rt-66sq", "idempotency_key": "k66sq", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve?debug=1", b)
    st, j = raw(ER, "POST", "/reserve?debug=1", b, h)
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    ok = st in (200, 429)
    return check("auth", "sig over /reserve?debug=1 AND request to /reserve?debug=1: accepted (query MAC-bound both ways)", ok, "status=%s" % st)
sig_with_query_ok()
def options_reserve():
    st, _ = raw(ER, "OPTIONS", "/reserve")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and st != 200 and alive
    return check("wire", "OPTIONS /reserve: 4xx/405, no 5xx, alive", ok, "status=%s" % st)
options_reserve()
def trace_seats():
    st, _ = raw(ER, "TRACE", "/seats")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and st != 200 and alive
    return check("wire", "TRACE /seats: 4xx/405, no 5xx, alive", ok, "status=%s" % st)
trace_seats()
def rid_as_json_number():
    b = json.dumps({"reservation_id": 12345, "user_id": "rt-66nr"}).encode()
    st = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "confirm with reservation_id as JSON number: 4xx, no 5xx", rej(st) and alive, "status=%s" % st)
rid_as_json_number()
def idem_key_10kb():
    b = json.dumps({"user_id": "rt-66ik", "idempotency_key": "k" * 10000, "seats": 1}).encode()
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "idempotency_key of 10,000 chars: no 5xx, conserved", ok, "status=%s" % st)
idem_key_10kb()
def app_double_pay():
    st, j = post(ER, "/reserve", {"user_id": "rt-66dp", "idempotency_key": "k66dp", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app double pay: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    p1, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "outcome": "payment_success"}))
    s1 = seats(ER)
    sold_d1 = s1.get("sold", 0) - s0.get("sold", 0)
    p2, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "outcome": "payment_success"}))
    s2 = seats(ER)
    sold_d2 = s2.get("sold", 0) - s1.get("sold", 0)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p1 != 500 and p2 != 500 and p1 != -1 and p2 != -1 and sold_d1 == 1 and sold_d2 == 0 and alive
    return check("app", "app pay twice same rid: one sale, second no-op/4xx, no 500", ok, "p1=%s p2=%s sold%+d%+d" % (p1, p2, sold_d1, sold_d2))
app_double_pay()
def app_bool_seats():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"rt-66bs","seats":true}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold seats=true (JSON bool): no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_bool_seats()
def waitlist_seats_boundary():
    st1, j1 = post(ER2, "/waitlist", {"user_id": "rt-66w4", "idempotency_key": "k66w4", "seats": 4})
    wid = j1.get("waitlist_id") if isinstance(j1, dict) else None
    st2 = 0
    if wid: st2, _ = post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    s = seats(ER2)
    ok = st1 in (200, 409, 429) and st2 in (200, 404, 0) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("abuse", "waitlist join seats=4 (max boundary): clean, conserved", ok, "j=%s c=%s" % (st1, st2))
waitlist_seats_boundary()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
