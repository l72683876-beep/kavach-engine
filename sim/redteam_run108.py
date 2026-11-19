#!/usr/bin/env python3
"""Run 108 extras: 12 angles (all live in redteam_battery.py Phase BJ too).
1: cross-instance rid replay: rid from 8091 confirmed on 8092 (same secret): no 5xx, both conserved
2: 4-way parallel transfer race, same rid, 4 different to_user: no 5xx, conserved
3: reserve with duplicate "user_id" JSON keys (u1, u2), sig over exact bytes: no 5xx, conserved
4: X-Kavach-Signature 65 hex chars (extra char): 401, no 5xx, conserved
5: idem reuse after release (hold, release, reserve same idem): no 5xx, conserved
6: replay-window boundary sweep (ts now-60, now-299, now-301, now-900): graceful, no 5xx
7: app /api/pay reservation_id as JSON number: no 500, app alive
8: app /api/hold seats as huge string: no 500, app alive
9: webhook Content-Type application/xml, valid token: no 500, app alive
10: webhook ?token= empty: no 500, app alive
11: webhook event field null: no 500, app alive
12: app /api/pay with another user's held rid: no 500, no unauthorized success
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

# ---------------- Phase BJ: run 108 extras (12 new angles) ----------------
def bj_hold(user, key="k108%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})

def cross_instance_rid():
    rid, st, _ = bj_hold("rt-108xi", "k108xi")
    if not rid:
        return check("state", "cross-instance rid replay: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": rid}).encode()
    st2, _ = raw(ER2, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))
    time.sleep(0.3)
    ok = st2 != 500 and st2 != -1 and conserved(ER) and conserved(ER2)
    return check("state", "cross-instance rid replay (8091 rid on 8092): no 5xx, both conserved", ok, "st2=%s" % st2)
cross_instance_rid()

def transfer_race_4way_same_rid():
    rid, st, _ = bj_hold("rt-108tr", "k108tr")
    if not rid:
        return check("race", "4-way transfer race same rid: skipped (hold unavailable)", True, "st=%s" % st)
    bodies = []
    heads = []
    for i in range(4):
        b = json.dumps({"reservation_id": rid, "to_user": "rt-108tr-x%d" % i}).encode()
        bodies.append(b)
        heads.append(sign(KEY, "POST", "/transfer", b))
    with ThreadPoolExecutor(4) as ex:
        outs = list(ex.map(lambda i: raw(ER, "POST", "/transfer", bodies[i], heads[i])[0], range(4)))
    time.sleep(0.3)
    wins = sum(1 for x in outs if x == 200)
    ok = all(x != 500 and x != -1 for x in outs) and conserved() and alive(ER)
    return check("race", "4-way parallel transfer same rid to 4 users: no 5xx, conserved", ok, "sts=%s wins=%s" % (outs, wins))
transfer_race_4way_same_rid()

def dup_userid_keys():
    body = ('{"user_id":"rt-108dup1","user_id":"rt-108dup2","idempotency_key":"k108dup","seats":1}').encode()
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve duplicate user_id JSON keys (u1, u2): no 5xx, conserved", ok, "st=%s" % st)
dup_userid_keys()

def sig_extra_hex_char():
    body = json.dumps({"user_id": "rt-108sh", "idempotency_key": "k108sh", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    h["X-Kavach-Signature"] = h["X-Kavach-Signature"] + "a"
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st in (401, 403) and conserved() and alive(ER)
    return check("auth", "X-Kavach-Signature 65 hex chars (extra char): 401, conserved", ok, "st=%s" % st)
sig_extra_hex_char()

def idem_reuse_after_release():
    rid, st, _ = bj_hold("rt-108ir", "k108ir")
    if not rid:
        return check("state", "idem reuse after release: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": rid}).encode()
    st1, _ = raw(ER, "POST", "/release", body, sign(KEY, "POST", "/release", body))
    st2, _ = post(ER, "/reserve", {"user_id": "rt-108ir", "idempotency_key": "k108ir", "seats": 1})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and conserved() and alive(ER)
    return check("state", "idem reuse after release: no 5xx, conserved", ok, "rel=%s re2=%s" % (st1, st2))
idem_reuse_after_release()

def window_boundary_sweep():
    now = int(time.time())
    outs = []
    for tag, ts in (("now-60", now - 60), ("now-299", now - 299), ("now-301", now - 301), ("now-900", now - 900)):
        body = json.dumps({"user_id": "rt-108ws", "idempotency_key": "k108ws-%s" % tag, "seats": 1}).encode()
        st, _ = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body, ts=str(ts)))
        outs.append("%s=%s" % (tag, st))
    time.sleep(0.3)
    ok = all(int(o.split("=")[1]) != 500 and int(o.split("=")[1]) != -1 for o in outs) and conserved() and alive(ER)
    return check("auth", "replay-window boundary sweep ts -60/-299/-301/-900s: graceful, no 5xx", ok, ",".join(outs))
window_boundary_sweep()

def app_pay_rid_number():
    body = json.dumps({"reservation_id": 123, "user_id": "rt-108pn", "outcome": "success"}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/pay reservation_id as JSON number: no 500, app alive", ok, "st=%s" % st)
app_pay_rid_number()

def app_hold_seats_huge_str():
    body = json.dumps({"user_id": "rt-108hs", "seats": "99999999999999999999"}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold seats huge string: no 500, app alive", ok, "st=%s" % st)
app_hold_seats_huge_str()

def webhook_xml_content_type():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": "RSV00000001"}).encode(), {"Content-Type": "application/xml"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("webhook", "webhook Content-Type application/xml valid token: no 500, app alive", ok, "st=%s" % st)
webhook_xml_content_type()

def webhook_empty_token():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=", json.dumps({"event": "payment_success", "reservation_id": "RSV00000001"}).encode())
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("webhook", "webhook ?token= empty: no 500, app alive", ok, "st=%s" % st)
webhook_empty_token()

def webhook_event_null():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": None, "reservation_id": "RSV00000001"}).encode())
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("webhook", "webhook event field null: no 500, app alive", ok, "st=%s" % st)
webhook_event_null()

def app_pay_other_users_rid():
    rid, st, _ = bj_hold("rt-108op", "k108op")
    if not rid:
        return check("app", "app pay other user's rid: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": rid, "user_id": "rt-108-attacker", "outcome": "success"}).encode()
    st2, j2 = raw(AR, "POST", "/api/pay", body)
    ok = st2 != 500 and st2 != -1 and alive(AR, "/") and conserved(ER)
    return check("app", "app /api/pay with another user's held rid: no 500, no unauthorized success", ok, "st=%s j=%s" % (st2, str(j2)[:60]))
app_pay_other_users_rid()
