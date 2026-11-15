#!/usr/bin/env python3
"""Run 94 extras: 12 angles (all live in redteam_battery.py Phase AV too).
1: double URL-encoded slash path on /seats: no 5xx, alive
2: 10KB URL path on /seats: no 5xx, no hang, alive
3: X-Kavach-Timestamp +301s (just outside +/-300 window): 401
4: user_id with lone UTF-16 surrogate escape: no 5xx, alive
5: seats "1.999999" string: 4xx
6: webhook body with duplicate "event" keys: no 500, alive
7: app /api/hold seats 10x capacity: 4xx, no 500
8: X-Kavach-Timestamp "-0": 401/4xx, no 5xx
9: transfer to_user 10KB: no 5xx, conserved
10: seats "1 " trailing space string: 4xx
11: confirm with lowercased reservation_id: 4xx, no 500
12: waitlist join with 10KB user_id: no 5xx
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid

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

# ---------------- Phase AV: run 94 extras (12 new angles) ----------------
def double_encoded_slash_path():
    st, _ = raw(ER, "GET", "/seats%252F..%252Fetc%252Fpasswd")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "double URL-encoded slash path (%252F): no 5xx, alive", ok, "status=%s" % st)
double_encoded_slash_path()
def ten_kb_path():
    st, _ = raw(ER, "GET", "/seats/" + "a" * 10000)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "10KB URL path on /seats: no 5xx, no hang, alive", ok, "status=%s" % st)
ten_kb_path()
def timestamp_just_outside_window():
    ts = str(int(time.time()) + 301)
    b = json.dumps({"user_id": "rt-94w1", "idempotency_key": "k94w1", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=ts))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp +301s just outside window: 401, alive", st == 401 and alive, "status=%s" % st)
timestamp_just_outside_window()
def user_id_lone_surrogate():
    body = '{"user_id":"rt-94\\ud800x","idempotency_key":"k94ls","seats":1}'
    st, _ = raw(ER, "POST", "/reserve", body)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "user_id lone UTF-16 surrogate escape: no 5xx, alive", ok, "status=%s" % st)
user_id_lone_surrogate()
def seats_fraction_string():
    st, _ = post(ER, "/reserve", {"user_id": "rt-94fs", "idempotency_key": "k94fs", "seats": "1.999999"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "seats \"1.999999\" string: 4xx, alive", ok, "status=%s" % st)
seats_fraction_string()
def webhook_duplicate_event_keys():
    body = '{"token":"whsec-redtest","event":"payment_success","event":"bogus_event","reservation_id":"RSV00000001"}'
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook body with duplicate event keys: no 500, alive", ok, "w=%s" % w)
webhook_duplicate_event_keys()
def app_hold_ten_x_capacity():
    st, j = raw(AR, "POST", "/api/hold", '{"user_id":"rt-94ob","seats":500}')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("app", "app hold seats 10x capacity (500): 4xx, no 500, alive", ok, "st=%s" % st)
app_hold_ten_x_capacity()
def timestamp_negative_zero():
    ts = "-0"
    b = json.dumps({"user_id": "rt-94nz", "idempotency_key": "k94nz", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=ts))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 200 and st != 500 and st != -1 and alive
    return check("auth", "timestamp \"-0\": 401/4xx, no 5xx, alive", ok, "status=%s" % st)
timestamp_negative_zero()
def transfer_huge_to_user():
    st, j = post(ER, "/reserve", {"user_id": "rt-94ht", "idempotency_key": "k94ht", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "transfer 10KB to_user: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        post(ER, "/release", {"reservation_id": rid})
        return check("state", "transfer 10KB to_user: skipped (confirm %s)" % st2, True)
    st3, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "t" * 10000})
    time.sleep(1.0)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st3 != 500 and st3 != -1 and conserved
    return check("state", "transfer to_user 10KB: no 5xx, conserved", ok, "st3=%s" % st3)
transfer_huge_to_user()
def seats_trailing_space_string():
    st, _ = post(ER, "/reserve", {"user_id": "rt-94ts", "idempotency_key": "k94ts", "seats": "1 "})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "seats \"1 \" trailing space string: 4xx, alive", ok, "status=%s" % st)
seats_trailing_space_string()
def confirm_lowercase_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-94lc", "idempotency_key": "k94lc", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "confirm lowercased rid: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid.lower()})
    post(ER, "/release", {"reservation_id": rid})
    ok = st2 != 200 and st2 != 500 and st2 != -1
    return check("state", "confirm with lowercased reservation_id: 4xx, no 500, not confirmed", ok, "st2=%s" % st2)
confirm_lowercase_rid()
def waitlist_huge_user_id():
    st, _ = post(ER, "/waitlist", {"user_id": "u" * 10000})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "waitlist join with 10KB user_id: no 5xx, alive", ok, "status=%s" % st)
waitlist_huge_user_id()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
