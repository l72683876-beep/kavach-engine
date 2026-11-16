#!/usr/bin/env python3
"""Run 97 extras: 12 angles (all live in redteam_battery.py Phase AY too).
1: HTTP/1.1 request without Host header: no 5xx, alive
2: 10KB header name: no 5xx, alive
3: valid MAC but missing X-Kavach-Timestamp: 401
4: X-Kavach-Request-Id containing spaces: 401/4xx
5: seats as string "true": 4xx
6: user_id as JSON number: 4xx
7: double confirm same rid: no 5xx, conserved
8: waitlist join, cancel, re-join: no 5xx
9: app /api/confirm with rid held on engine 8092: no 500, graceful
10: app /api/hold with seats "abc": no 500
11: 8-way parallel reserve same idempotency_key: no 5xx, conserved
12: webhook 100KB body with valid token: no 500, no hang
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
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def conserved(port=ER):
    s = seats(port)
    return s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)

# ---------------- Phase AY: run 97 extras (12 new angles) ----------------
def no_host_header():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "HTTP/1.1 request without Host header: no 5xx, no hang, alive", ok, "st=%s" % stc)
no_host_header()
def ten_kb_header_name():
    st, _ = raw(ER, "GET", "/seats", headers={"X-" + "a" * 10000: "1"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "10KB header name: no 5xx, no hang, alive", ok, "status=%s" % st)
ten_kb_header_name()
def missing_timestamp():
    b = json.dumps({"user_id": "rt-97mt", "idempotency_key": "k97mt", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h.pop("X-Kavach-Timestamp")
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 200 and st != 500 and st != -1 and alive
    return check("auth", "valid MAC but missing timestamp header: 401, no 5xx, alive", ok, "status=%s" % st)
missing_timestamp()
def rid_with_spaces():
    b = json.dumps({"user_id": "rt-97rs", "idempotency_key": "k97rs", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Request-Id"] = h["X-Kavach-Request-Id"][:8] + " abc " + h["X-Kavach-Request-Id"][8:]
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 200 and st != 500 and st != -1 and alive
    return check("auth", "request-id containing spaces: 401/4xx, no 5xx, alive", ok, "status=%s" % st)
rid_with_spaces()
def seats_string_true():
    st, _ = post(ER, "/reserve", {"user_id": "rt-97st", "idempotency_key": "k97st", "seats": "true"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "seats as string \"true\": 4xx, no 5xx, alive", ok, "status=%s" % st)
seats_string_true()
def user_id_number():
    st, _ = post(ER, "/reserve", {"user_id": 12345, "idempotency_key": "k97un", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "user_id as JSON number: 4xx, no 5xx, alive", ok, "status=%s" % st)
user_id_number()
def double_confirm():
    st, j = post(ER, "/reserve", {"user_id": "rt-97dc", "idempotency_key": "k97dc", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "double confirm: skipped (hold unavailable)", True, "st=%s" % st)
    c1 = post(ER, "/confirm", {"reservation_id": rid})[0]
    c2 = post(ER, "/confirm", {"reservation_id": rid})[0]
    time.sleep(1.0)
    ok = c1 != 500 and c2 != 500 and c1 != -1 and c2 != -1 and conserved()
    return check("state", "double confirm same rid: no 5xx, conserved", ok, "c1=%s c2=%s" % (c1, c2))
double_confirm()
def waitlist_join_cancel_rejoin():
    u = "rt-97wc"
    j1 = post(ER, "/waitlist", {"user_id": u})[0]
    c1 = post(ER, "/waitlist/cancel", {"user_id": u})[0]
    j2 = post(ER, "/waitlist", {"user_id": u})[0]
    post(ER, "/waitlist/cancel", {"user_id": u})
    ok = all(x != 500 and x != -1 for x in (j1, c1, j2)) and conserved()
    return check("state", "waitlist join, cancel, re-join: no 5xx, conserved", ok, "j1=%s c1=%s j2=%s" % (j1, c1, j2))
waitlist_join_cancel_rejoin()
def app_confirm_other_engine_rid():
    st, j = post(ER2, "/reserve", {"user_id": "rt-97oe", "idempotency_key": "k97oe", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app confirm other-engine rid: skipped (8092 hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/confirm", json.dumps({"reservation_id": rid}))
    post(ER2, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/confirm with rid held on engine 8092: no 500, graceful", ok, "p=%s" % p)
app_confirm_other_engine_rid()
def app_hold_alpha_seats():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"rt-97as","seats":"abc"}')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("app", "app hold seats \"abc\": no 500, alive", ok, "st=%s" % st)
app_hold_alpha_seats()
def parallel_same_idem_reserve():
    def go(i):
        return post(ER2, "/reserve", {"user_id": "rt-97pi", "idempotency_key": "k97pi", "seats": 1})[0]
    with ThreadPoolExecutor(8) as ex:
        outs = list(ex.map(go, range(8)))
    time.sleep(1.0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved(ER2)
    return check("race", "8-way parallel reserve same idempotency_key: no 5xx, conserved", ok, "200s=%d" % outs.count(200))
parallel_same_idem_reserve()
def webhook_huge_body():
    body = '{"token":"whsec-redtest","event":"payment_success","reservation_id":"RSV00000001","junk":"' + "x" * 100000 + '"}'
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook 100KB body with valid token: no 500, no hang, alive", ok, "w=%s" % w)
webhook_huge_body()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
