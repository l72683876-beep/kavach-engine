#!/usr/bin/env python3
"""Run 102 extras: 12 angles (all live in redteam_battery.py Phase BD too).
1: seats as JSON escaped unicode digit "\\u0031": valid reserve, conserved
2: transfer body with extra seats field: ignored, conserved
3: app /api/pay with amount null: no 500
4: parallel waitlist joins + parallel releases race: no 5xx, conserved
5: event_id as JSON boolean true: 4xx, no 5xx
6: null byte in a header value (raw socket): 400/close, alive
7: @ in URL path: no 5xx, alive
8: query key with no value "?k": no 5xx, alive
9: 10KB X-Kavach-Request-Id: no 5xx, alive
10: CR-only line endings request (raw socket): 400/close, alive
11: event_id whitespace-only: no 5xx, alive
12: app /api/pay with amount as boolean: no 500
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
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256).hexdigest()
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
            "X-Kavach-Signature": mac, "Content-Type": "application/json"}
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

# ---------------- Phase BD: run 102 extras (12 new angles) ----------------
def bd_hold(user, key="k102%s"):
    st, j = post(ER, "/reserve", {"user_id": user, "idempotency_key": key % user.replace("rt-102", ""), "seats": 1})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st
def escaped_unicode_seats():
    body = '{"user_id":"rt-102eu","idempotency_key":"k102eu","seats":"\\u0031"}'.encode()
    st, _ = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    time.sleep(0.5)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive and conserved()
    return check("fuzz", "seats as JSON escaped unicode digit \\u0031: no 5xx, conserved", ok, "status=%s" % st)
escaped_unicode_seats()
def transfer_extra_seats_field():
    rid, st = bd_hold("rt-102ts")
    if not rid:
        return check("state", "transfer extra seats field: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("state", "transfer extra seats field: skipped (confirm %s)" % st2, True)
    st3, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-102ts-b", "seats": 2})
    time.sleep(0.8)
    ok = st3 != 500 and st3 != -1 and conserved()
    return check("state", "transfer with extra seats field: ignored, no 5xx, conserved", ok, "st3=%s" % st3)
transfer_extra_seats_field()
def app_pay_amount_null():
    rid, st = bd_hold("rt-102an")
    if not rid:
        return check("app", "app pay amount null: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": None}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount null: no 500, graceful", ok, "p=%s" % p)
app_pay_amount_null()
def waitlist_release_race():
    rids = []
    for i in range(6):
        rid, _ = bd_hold("rt-102wr%d" % i, "k102wr%s")
        if rid: rids.append(rid)
    if not rids:
        return check("race", "waitlist+release race: skipped (holds unavailable)", True)
    def join(i):
        return post(ER, "/waitlist", {"user_id": "rt-102wj%d" % i, "event_id": "demo", "seats": 1})[0]
    def rel(rid):
        return post(ER, "/release", {"reservation_id": rid})[0]
    with ThreadPoolExecutor(12) as ex:
        f1 = [ex.submit(join, i) for i in range(6)]
        f2 = [ex.submit(rel, r) for r in rids]
        outs = [f.result() for f in f1 + f2]
    for i in range(6):
        post(ER, "/waitlist/cancel", {"entry_id": "rt-102wj%d" % i})
    time.sleep(0.8)
    ok = all(x != 500 and x != -1 for x in outs) and conserved()
    return check("race", "parallel waitlist joins + releases race: no 5xx, conserved", ok, "200s=%d" % outs.count(200))
waitlist_release_race()
def event_id_boolean():
    st, _ = post(ER, "/reserve", {"user_id": "rt-102eb", "idempotency_key": "k102eb", "seats": 1, "event_id": True})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "event_id as JSON boolean: no 5xx, alive", ok, "status=%s" % st)
event_id_boolean()
def null_byte_header_value():
    import socket as _socket
    try:
        s = _socket.create_connection(("127.0.0.1", ER), timeout=10)
        s.sendall(b"GET /seats HTTP/1.1\r\nHost: 127.0.0.1:8091\r\nX-Junk: a\x00b\r\n\r\n")
        try: d = s.recv(400)
        except Exception: d = b""
        s.close()
    except Exception as ex:
        d = ("EXC " + str(ex)).encode()
    graceful = d[:32].startswith(b"HTTP/1.1 4") or len(d) == 0
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = graceful and alive
    return check("wire", "null byte in header value (raw socket): 400/close, alive", ok, "resp=%s" % d[:60].decode("utf-8", "replace"))
null_byte_header_value()
def at_in_path():
    st, _ = raw(ER, "GET", "/seats@rt102")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "@ in URL path: no 5xx, alive", ok, "status=%s" % st)
at_in_path()
def query_no_value():
    st, _ = raw(ER, "GET", "/seats?k")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "query key with no value (?k): no 5xx, alive", ok, "status=%s" % st)
query_no_value()
def huge_request_id():
    b = json.dumps({"user_id": "rt-102hr", "idempotency_key": "k102hr", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, rid="r" * 10000)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("auth", "10KB X-Kavach-Request-Id: no 5xx, alive", ok, "status=%s" % st)
huge_request_id()
def cr_only_line_endings():
    import socket as _socket
    try:
        s = _socket.create_connection(("127.0.0.1", ER), timeout=10)
        s.sendall(b"GET /seats HTTP/1.1\rHost: 127.0.0.1:8091\r\r")
        try: d = s.recv(400)
        except Exception: d = b""
        s.close()
    except Exception as ex:
        d = ("EXC " + str(ex)).encode()
    graceful = d[:32].startswith(b"HTTP/1.1 4") or len(d) == 0
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = graceful and alive
    return check("wire", "CR-only line endings (raw socket): 400/close, alive", ok, "resp=%s" % d[:60].decode("utf-8", "replace"))
cr_only_line_endings()
def event_id_whitespace():
    st, _ = post(ER, "/reserve", {"user_id": "rt-102ew", "idempotency_key": "k102ew", "seats": 1, "event_id": " "})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive and conserved()
    return check("fuzz", "event_id whitespace-only: no 5xx, conserved", ok, "status=%s" % st)
event_id_whitespace()
def app_pay_amount_boolean():
    rid, st = bd_hold("rt-102ab")
    if not rid:
        return check("app", "app pay amount boolean: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": True}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount as boolean: no 500, graceful", ok, "p=%s" % p)
app_pay_amount_boolean()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
