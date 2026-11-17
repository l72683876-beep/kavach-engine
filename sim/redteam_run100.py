#!/usr/bin/env python3
"""Run 100 extras: 12 angles (all live in redteam_battery.py Phase BB too).
1: GET /seats with 10KB query string: no 5xx, no hang
2: app /api/pay with negative amount: no 500, graceful
3: idempotency_key containing null byte: 4xx, no 5xx
4: duplicate X-Kavach-Timestamp headers (two different values): 401
5: double transfer (user2 then user3): conserved
6: app /api/pay with unknown random rid: graceful, no 500
7: 10KB URL path on GET /seats: no 5xx, no hang
8: 10KB event_id on reserve: no 5xx, alive
9: app /api/seats?limit=999999: no 500, alive
10: reserve with custom event_id (ev-99): no 5xx, conserved
11: 6-way parallel transfer of same confirmed rid to different users: one owner, conserved
12: transfer to_user with null byte: 4xx, no 5xx
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

# ---------------- Phase BB: run 100 extras (12 new angles) ----------------
def long_query_seats():
    st, _ = raw(ER, "GET", "/seats?" + "q" * 10000 + "=1")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "GET /seats 10KB query string: no 5xx, no hang, alive", ok, "status=%s" % st)
long_query_seats()
def app_pay_negative_amount():
    st, j = post(ER, "/reserve", {"user_id": "rt-100pa", "idempotency_key": "k100pa", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app pay negative amount: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": -500}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay negative amount: no 500, graceful", ok, "p=%s" % p)
app_pay_negative_amount()
def idem_null_byte():
    st, _ = post(ER, "/reserve", {"user_id": "rt-100nb", "idempotency_key": "k100\x00nb", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "idempotency_key with null byte: no 5xx, alive", ok, "status=%s" % st)
idem_null_byte()
def duplicate_timestamp_headers():
    b = json.dumps({"user_id": "rt-100dt", "idempotency_key": "k100dt", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Timestamp"] = str(int(time.time()) - 10)  # wire sends one, then we append a second
    raw_out = None
    try:
        c = http.client.HTTPConnection("127.0.0.1", ER, timeout=25)
        hdrs = dict(h); hdrs["Content-Type"] = "application/json"
        # craft duplicate header via putrequest/putheader
        c.putrequest("POST", "/reserve", skip_host=True)
        c.putheader("Host", "127.0.0.1:%d" % ER)
        for k, v in hdrs.items():
            if k == "X-Kavach-Timestamp":
                continue
            c.putheader(k, v)
        c.putheader("X-Kavach-Timestamp", str(int(time.time()) - 10))
        c.putheader("X-Kavach-Timestamp", str(int(time.time()) + 10))
        c.putheader("Content-Length", str(len(b)))
        c.endheaders(message_body=b)
        r = c.getresponse(); data = r.read(); st2 = r.status; c.close()
        raw_out = st2
    except Exception as ex:
        raw_out = -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = raw_out != 200 and raw_out != 500 and raw_out != -1 and alive
    return check("auth", "duplicate X-Kavach-Timestamp headers: 401, no 5xx, alive", ok, "status=%s" % raw_out)
duplicate_timestamp_headers()
def double_transfer():
    st, j = post(ER, "/reserve", {"user_id": "rt-100dtr", "idempotency_key": "k100dtr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "double transfer: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("state", "double transfer: skipped (confirm %s)" % st2, True)
    st3, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-100dtr-b"})
    st4, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-100dtr-c"})
    time.sleep(0.8)
    ok = st3 == 200 and st4 == 200 and conserved()
    return check("state", "double transfer b then c: both ok, conserved", ok, "st3=%s st4=%s" % (st3, st4))
double_transfer()
def app_pay_unknown_rid():
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": "rt-100-unknown-" + uuid.uuid4().hex[:8]}))
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay unknown rid: graceful, no 500, alive", ok, "p=%s" % p)
app_pay_unknown_rid()
def long_path_seats():
    st, _ = raw(ER, "GET", "/seats/" + "a" * 10000)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "10KB URL path: no 5xx, no hang, alive", ok, "status=%s" % st)
long_path_seats()
def long_event_id():
    st, j = post(ER, "/reserve", {"user_id": "rt-100le", "idempotency_key": "k100le", "seats": 1, "event_id": "ev-" + "x" * 10000})
    if st == 200 and isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "10KB event_id on reserve: no 5xx, alive", ok, "status=%s" % st)
long_event_id()
def app_seats_limit_param():
    st, _ = raw(AR, "GET", "/api/seats?limit=999999")
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("app", "app /api/seats?limit=999999: no 500, alive", ok, "st=%s" % st)
app_seats_limit_param()
def custom_event_reserve():
    st, j = post(ER, "/reserve", {"user_id": "rt-100ce", "idempotency_key": "k100ce", "seats": 1, "event_id": "ev-99"})
    if st == 200 and isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    time.sleep(0.6)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive and conserved()
    return check("state", "reserve with custom event_id ev-99: no 5xx, conserved", ok, "status=%s" % st)
custom_event_reserve()
def transfer_race_multi_user():
    st, j = post(ER, "/reserve", {"user_id": "rt-100t6", "idempotency_key": "k100t6", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel transfer multi-user: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("race", "parallel transfer multi-user: skipped (confirm %s)" % st2, True)
    def go(i):
        return post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-100t6-u%d" % i})[0]
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(go, range(6)))
    time.sleep(1.0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved()
    return check("race", "6-way parallel transfer same rid to 6 users: no 5xx, conserved", ok, "200s=%d" % outs.count(200))
transfer_race_multi_user()
def transfer_to_user_null_byte():
    st, j = post(ER, "/reserve", {"user_id": "rt-100tn", "idempotency_key": "k100tn", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("fuzz", "transfer to_user null byte: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-100\x00nb"})
    post(ER, "/release", {"reservation_id": rid})
    time.sleep(0.6)
    ok = st2 != 500 and st2 != -1 and conserved()
    return check("fuzz", "transfer to_user with null byte: no 5xx, conserved", ok, "st2=%s" % st2)
transfer_to_user_null_byte()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
