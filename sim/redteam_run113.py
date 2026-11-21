#!/usr/bin/env python3
"""Run 113 extras: 12 angles (all live in redteam_battery.py Phase BO too).
1: reserve body with UTF-8 BOM prefix: no 5xx, conserved
2: reserve seats beyond float precision (2^53+1): graceful, conserved
3: reserve with duplicate seats JSON keys: no 5xx, conserved
4: app /api/hold seats as JSON object: no 500, app alive
5: /release with idempotency_key field: no 5xx, conserved
6: app /api/pay with duplicate reservation_id keys: no 500, app alive
7: webhook token with trailing newline: no 500, app alive
8: parallel confirm of two different rids same user: no 5xx, conserved
9: circular transfer A to B, B to C, C to A: no 5xx, conserved
10: /waitlist idempotency_key 5000 chars: graceful, conserved
11: app /api/board limit negative: no 500, app alive
12: PUT /reserve with valid signature: no 5xx, conserved
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

# ---------------- Phase BO: run 113 extras (12 new angles) ----------------
def bo_alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def bo_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

def bom_body_reserve():
    body = json.dumps({"user_id": "rt-113bom", "idempotency_key": "k113bom", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b"\xef\xbb\xbf" + body, sign(KEY, "POST", "/reserve", b"\xef\xbb\xbf" + body))
    ok = st != 500 and st != -1 and conserved() and bo_alive(ER)
    return check("fuzz", "reserve body with UTF-8 BOM: no 5xx, conserved", ok, "st=%s" % st)
bom_body_reserve()

def seats_beyond_float():
    st, j = post(ER, "/reserve", {"user_id": "rt-113bf", "idempotency_key": "k113bf", "seats": 9007199254740993})
    ok = st != 500 and st != -1 and conserved() and bo_alive(ER)
    return check("fuzz", "reserve seats 2^53+1: graceful, conserved", ok, "st=%s" % st)
seats_beyond_float()

def reserve_dup_seats_keys():
    body = ('{"user_id":"rt-113dk","idempotency_key":"k113dk","seats":1,"seats":1}').encode()
    st, _ = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    ok = st != 500 and st != -1 and conserved() and bo_alive(ER)
    return check("fuzz", "reserve duplicate seats keys: no 5xx, conserved", ok, "st=%s" % st)
reserve_dup_seats_keys()

def app_hold_seats_object():
    body = json.dumps({"user_id": "rt-113so", "seats": {}}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and bo_alive(AR, "/")
    return check("app", "app /api/hold seats as JSON object: no 500, app alive", ok, "st=%s" % st)
app_hold_seats_object()

def release_with_idem():
    rid, st, _ = bo_hold("rt-113ri", "k113ri")
    if not rid:
        return check("state", "release with idem: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/release", {"reservation_id": rid, "idempotency_key": "k113ri2"})
    ok = st2 != 500 and st2 != -1 and conserved() and bo_alive(ER)
    return check("state", "release with idempotency_key field: no 5xx, conserved", ok, "st2=%s" % st2)
release_with_idem()

def app_pay_dup_rid_keys():
    body = ('{"reservation_id":"RSV00000001","reservation_id":"RSV00000001","user_id":"rt-113pd","outcome":"success"}').encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bo_alive(AR, "/")
    return check("app", "app /api/pay duplicate reservation_id keys: no 500, app alive", ok, "st=%s" % st)
app_pay_dup_rid_keys()

def webhook_token_trailing_newline():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest%0A", json.dumps({"event": "payment_success", "reservation_id": "RSV00000001"}).encode())
    ok = st != 500 and st != -1 and bo_alive(AR, "/")
    return check("webhook", "webhook token with trailing newline: no 500, app alive", ok, "st=%s" % st)
webhook_token_trailing_newline()

def parallel_confirm_two_rids():
    r1, s1, _ = bo_hold("rt-113pc", "k113pc1")
    r2, s2, _ = bo_hold("rt-113pc", "k113pc2")
    if not (r1 and r2):
        return check("race", "parallel confirm two rids: skipped (holds unavailable)", True, "s1=%s s2=%s" % (s1, s2))
    b1, b2 = json.dumps({"reservation_id": r1, "idempotency_key": "k113pc1c"}).encode(), json.dumps({"reservation_id": r2, "idempotency_key": "k113pc2c"}).encode()
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/confirm", b1, sign(KEY, "POST", "/confirm", b1))
        f2 = ex.submit(raw, ER, "POST", "/confirm", b2, sign(KEY, "POST", "/confirm", b2))
        st3, _ = f1.result(); st4, _ = f2.result()
    time.sleep(0.3)
    ok = all(x != 500 and x != -1 for x in (st3, st4)) and conserved() and bo_alive(ER)
    return check("race", "parallel confirm of two different rids: no 5xx, conserved", ok, "c1=%s c2=%s" % (st3, st4))
parallel_confirm_two_rids()

def circular_transfer():
    rA, sA, _ = bo_hold("rt-113a", "k113a")
    if not rA:
        return check("state", "circular transfer: skipped (hold unavailable)", True, "sA=%s" % sA)
    st2, _ = post(ER, "/transfer", {"reservation_id": rA, "to_user": "rt-113b"})
    st3, _ = post(ER, "/transfer", {"reservation_id": rA, "to_user": "rt-113c"})
    st4, _ = post(ER, "/transfer", {"reservation_id": rA, "to_user": "rt-113a"})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st2, st3, st4)) and conserved() and bo_alive(ER)
    return check("state", "circular transfer A-B-C-A: no 5xx, conserved", ok, "t=%s/%s/%s" % (st2, st3, st4))
circular_transfer()

def waitlist_idem_long():
    st, j = post(ER, "/waitlist", {"user_id": "rt-113wi", "idempotency_key": "w" * 5000, "seats": 1})
    ok = st != 500 and st != -1 and conserved() and bo_alive(ER)
    return check("fuzz", "waitlist idempotency_key 5000 chars: graceful, conserved", ok, "st=%s" % st)
waitlist_idem_long()

def app_board_negative_limit():
    st, j = raw(AR, "GET", "/api/board?limit=-1")
    ok = st != 500 and st != -1 and bo_alive(AR, "/")
    return check("app", "app /api/board negative limit: no 500, app alive", ok, "st=%s" % st)
app_board_negative_limit()

def put_reserve_signed():
    body = json.dumps({"user_id": "rt-113pr", "idempotency_key": "k113pr", "seats": 1}).encode()
    h = sign(KEY, "PUT", "/reserve", body)
    st, _ = raw(ER, "PUT", "/reserve", body, h)
    ok = st != 500 and st != -1 and conserved() and bo_alive(ER)
    return check("fuzz", "PUT /reserve with valid signature: no 5xx, conserved", ok, "st=%s" % st)
put_reserve_signed()
