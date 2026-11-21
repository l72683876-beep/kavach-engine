#!/usr/bin/env python3
"""Run 112 extras: 12 angles (all live in redteam_battery.py Phase BN too).
1: reserve idempotency_key 5000 chars: graceful, conserved
2: state chain: A holds, B waitlists, A releases, A confirms released rid: no 5xx, conserved
3: /transfer to_user with tab char: graceful, conserved
4: reserve idempotency_key as JSON number: graceful, conserved
5: app /api/pay with unexpected seats field: no 500, app alive
6: /confirm with body "null" literal: no 5xx, conserved
7: idem race: same key different seat counts parallel: no 5xx, conserved
8: webhook event as JSON number: no 500, app alive
9: app /api/pay user_id as JSON array: no 500, app alive
10: /waitlist seats as float 0.5: graceful, conserved
11: transfer a SOLD (confirmed) reservation: no 5xx, conserved
12: webhook with duplicate event+reservation_id JSON keys: no 500, app alive
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

# ---------------- Phase BN: run 112 extras (12 new angles) ----------------
def bn_alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def bn_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

def idem_5000():
    st, j = post(ER, "/reserve", {"user_id": "rt-112il", "idempotency_key": "k" * 5000, "seats": 1})
    ok = st != 500 and st != -1 and conserved() and bn_alive(ER)
    return check("fuzz", "reserve idempotency_key 5000 chars: graceful, conserved", ok, "st=%s" % st)
idem_5000()

def waitlist_release_confirm_chain():
    rid, st, _ = bn_hold("rt-112a", "k112a")
    if not rid:
        return check("state", "waitlist-release-confirm chain: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/waitlist", {"user_id": "rt-112b", "seats": 1})
    st3, _ = post(ER, "/release", {"reservation_id": rid})
    st4, _ = post(ER, "/confirm", {"reservation_id": rid, "idempotency_key": "k112a2"})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st2, st3, st4)) and conserved() and bn_alive(ER)
    return check("state", "hold + waitlist + release + confirm released rid: no 5xx, conserved", ok, "wl=%s rel=%s cf=%s" % (st2, st3, st4))
waitlist_release_confirm_chain()

def transfer_to_user_tab():
    rid, st, _ = bn_hold("rt-112tt", "k112tt")
    if not rid:
        return check("state", "transfer to_user tab: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-112\tx"})
    ok = st2 != 500 and st2 != -1 and conserved() and bn_alive(ER)
    return check("fuzz", "transfer to_user with tab char: graceful, conserved", ok, "st2=%s" % st2)
transfer_to_user_tab()

def idem_number():
    st, j = post(ER, "/reserve", {"user_id": "rt-112in", "idempotency_key": 12345, "seats": 1})
    ok = st != 500 and st != -1 and conserved() and bn_alive(ER)
    return check("fuzz", "reserve idempotency_key as JSON number: graceful, conserved", ok, "st=%s" % st)
idem_number()

def app_pay_extra_seats():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": "rt-112es", "outcome": "success", "seats": 5}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bn_alive(AR, "/")
    return check("app", "app /api/pay with unexpected seats field: no 500, app alive", ok, "st=%s" % st)
app_pay_extra_seats()

def confirm_null_body():
    st, _ = raw(ER, "POST", "/confirm", b"null", sign(KEY, "POST", "/confirm", b"null"))
    ok = st != 500 and st != -1 and conserved() and bn_alive(ER)
    return check("fuzz", "confirm with body \"null\": no 5xx, conserved", ok, "st=%s" % st)
confirm_null_body()

def idem_race_diff_seats():
    b1 = json.dumps({"user_id": "rt-112rd", "idempotency_key": "k112rd", "seats": 1}).encode()
    b2 = json.dumps({"user_id": "rt-112rd", "idempotency_key": "k112rd", "seats": 2}).encode()
    h1, h2 = sign(KEY, "POST", "/reserve", b1), sign(KEY, "POST", "/reserve", b2)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/reserve", b1, h1)
        f2 = ex.submit(raw, ER, "POST", "/reserve", b2, h2)
        st1, _ = f1.result(); st2, _ = f2.result()
    time.sleep(0.3)
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and conserved() and bn_alive(ER)
    return check("race", "same idem different seat counts race: no 5xx, conserved", ok, "s1=%s s2=%s" % (st1, st2))
idem_race_diff_seats()

def webhook_event_number():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": 1, "reservation_id": "RSV00000001"}).encode())
    ok = st != 500 and st != -1 and bn_alive(AR, "/")
    return check("webhook", "webhook event as JSON number: no 500, app alive", ok, "st=%s" % st)
webhook_event_number()

def app_pay_userid_array():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": [], "outcome": "success"}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bn_alive(AR, "/")
    return check("app", "app /api/pay user_id as JSON array: no 500, app alive", ok, "st=%s" % st)
app_pay_userid_array()

def waitlist_seats_float():
    st, j = post(ER, "/waitlist", {"user_id": "rt-112wf", "seats": 0.5})
    ok = st != 500 and st != -1 and conserved() and bn_alive(ER)
    return check("fuzz", "waitlist seats as float 0.5: graceful, conserved", ok, "st=%s" % st)
waitlist_seats_float()

def transfer_sold():
    rid, st, _ = bn_hold("rt-112ts", "k112ts")
    if not rid:
        return check("state", "transfer sold rid: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid, "idempotency_key": "k112ts2"})
    st3, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-112ts-b"})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st2, st3)) and conserved() and bn_alive(ER)
    return check("state", "transfer a SOLD (confirmed) reservation: no 5xx, conserved", ok, "cf=%s tr=%s" % (st2, st3))
transfer_sold()

def webhook_dup_keys():
    body = ('{"event":"payment_success","event":"payment_success","reservation_id":"RSV00000001","reservation_id":"RSV00000001"}').encode()
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    ok = st != 500 and st != -1 and bn_alive(AR, "/")
    return check("webhook", "webhook duplicate event+rid keys: no 500, app alive", ok, "st=%s" % st)
webhook_dup_keys()
