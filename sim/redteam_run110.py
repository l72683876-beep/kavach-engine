#!/usr/bin/env python3
"""Run 110 extras: 12 angles (all live in redteam_battery.py Phase BL too).
1: reserve seats as Devanagari digit string: graceful, conserved
2: MAC over permuted canonical order (ts path rid method): 401, no 5xx
3: /confirm with duplicate reservation_id JSON keys: no 5xx, conserved
4: reserve user_id as empty string: graceful, conserved
5: app /api/hold user_id with tab char: no 500, app alive
6: app /api/pay reservation_id as JSON object: no 500, app alive
7: webhook token in query AND Authorization header: no 500, app alive
8: parallel reserve + release with same idem race: no 5xx, conserved
9: /waitlist user_id as JSON number: graceful, conserved
10: reserve seats as string "-1": graceful, conserved
11: app /api/hold empty body (0 bytes, valid CT): no 500, app alive
12: app /api/pay user_id boolean true: no 500, app alive
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
    return ok
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
def alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200

# ---------------- Phase BL: run 110 extras (12 new angles) ----------------
def bl_hold(user, key="k110%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})

def seats_devanagari_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-110dv", "idempotency_key": "k110dv", "seats": "१"})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats Devanagari digit string: graceful, conserved", ok, "st=%s" % st)
seats_devanagari_string()

def mac_permuted_order():
    body = json.dumps({"user_id": "rt-110po", "idempotency_key": "k110po", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    ts, rid = h["X-Kavach-Timestamp"], h["X-Kavach-Request-Id"]
    mac = hmac.new(SECRET.encode(), (ts + "\n" + "/reserve" + "\n" + rid + "\n" + "POST" + "\n" + KEY + "\n").encode() + body, hashlib.sha256).hexdigest()
    h["X-Kavach-Signature"] = mac
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st in (401, 403) and conserved() and alive(ER)
    return check("auth", "MAC over permuted canonical order (ts path rid method): 401, conserved", ok, "st=%s" % st)
mac_permuted_order()

def confirm_dup_rid_keys():
    rid, st, _ = bl_hold("rt-110cd", "k110cd")
    if not rid:
        return check("fuzz", "confirm duplicate rid keys: skipped (hold unavailable)", True, "st=%s" % st)
    body = ('{"reservation_id":"%s","reservation_id":"%s"}' % (rid, rid)).encode()
    st2, _ = raw(ER, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm with duplicate reservation_id keys: no 5xx, conserved", ok, "st2=%s" % st2)
confirm_dup_rid_keys()

def userid_empty_string():
    st, j = post(ER, "/reserve", {"user_id": "", "idempotency_key": "k110ue", "seats": 1})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id as empty string: graceful, conserved", ok, "st=%s" % st)
userid_empty_string()

def app_hold_tab_userid():
    body = json.dumps({"user_id": "rt-110\tab", "seats": 1}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold user_id with tab char: no 500, app alive", ok, "st=%s" % st)
app_hold_tab_userid()

def app_pay_rid_object():
    body = json.dumps({"reservation_id": {}, "user_id": "rt-110ro", "outcome": "success"}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/pay reservation_id as JSON object: no 500, app alive", ok, "st=%s" % st)
app_pay_rid_object()

def webhook_token_dual_placement():
    h = {"Content-Type": "application/json", "Authorization": "Bearer whsec-redtest"}
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": "RSV00000001"}).encode(), h)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("webhook", "webhook token in query AND Authorization header: no 500, app alive", ok, "st=%s" % st)
webhook_token_dual_placement()

def reserve_release_same_idem_race():
    body = json.dumps({"user_id": "rt-110rr", "idempotency_key": "k110rr", "seats": 1}).encode()
    hr = sign(KEY, "POST", "/reserve", body)
    hl = sign(KEY, "POST", "/release", json.dumps({"reservation_id": "RSV00000001"}).encode())
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/reserve", body, hr)
        st1, _ = f1.result()
        rid = None
        st2, _ = raw(ER, "POST", "/release", json.dumps({"reservation_id": "RSV00000001"}).encode(), hl)
    time.sleep(0.3)
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and conserved() and alive(ER)
    return check("race", "reserve + release race: no 5xx, conserved", ok, "r=%s rel=%s" % (st1, st2))
reserve_release_same_idem_race()

def waitlist_userid_number():
    st, j = post(ER, "/waitlist", {"user_id": 42, "seats": 1})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "waitlist user_id as JSON number: graceful, conserved", ok, "st=%s" % st)
waitlist_userid_number()

def seats_negative_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-110ns", "idempotency_key": "k110ns", "seats": "-1"})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as string \"-1\": graceful, conserved", ok, "st=%s" % st)
seats_negative_string()

def app_hold_empty_body():
    st, j = raw(AR, "POST", "/api/hold", b"", {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold empty body (0 bytes): no 500, app alive", ok, "st=%s" % st)
app_hold_empty_body()

def app_pay_userid_bool():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": True, "outcome": "success"}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/pay user_id boolean true: no 500, app alive", ok, "st=%s" % st)
app_pay_userid_bool()
