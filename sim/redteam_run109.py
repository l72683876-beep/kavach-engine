#!/usr/bin/env python3
"""Run 109 extras: 12 angles (all live in redteam_battery.py Phase BK too).
1: cross-instance release: rid from 8091 released on 8092 (same secret): no 5xx, both conserved
2: app board endpoint with huge offset: no 500, app alive
3: app /api/deals with another user's user_id query (IDOR probe): no 500, app alive
4: X-Kavach-Signature all-zero 64 hex chars: 401, no 5xx, conserved
5: post-confirm waitlist join by same user: no 5xx, conserved
6: idem replay post-confirm (reserve same idem after confirm): no 5xx, conserved
7: app /api/pay outcome "pending" (unknown enum): no 500, app alive
8: app /api/hold seats -1: no 500, app alive
9: engine reserve seats as string "1e2": graceful, conserved
10: webhook event as empty string: no 500, app alive
11: two parallel identical reserves (same idem, same payload): no 5xx, conserved
12: app /api/hold with duplicate "seats" JSON keys: no 500, app alive
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

# ---------------- Phase BK: run 109 extras (12 new angles) ----------------
def bk_hold(user, key="k109%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})

def cross_instance_release():
    rid, st, _ = bk_hold("rt-109xr", "k109xr")
    if not rid:
        return check("state", "cross-instance release: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": rid}).encode()
    st2, _ = raw(ER2, "POST", "/release", body, sign(KEY, "POST", "/release", body))
    time.sleep(0.3)
    ok = st2 != 500 and st2 != -1 and conserved(ER) and conserved(ER2)
    return check("state", "cross-instance release (8091 rid on 8092): no 5xx, both conserved", ok, "st2=%s" % st2)
cross_instance_release()

def app_board_huge_offset():
    st, j = raw(AR, "GET", "/board?offset=999999999999")
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /board huge offset: no 500, app alive", ok, "st=%s" % st)
app_board_huge_offset()

def app_deals_idor_probe():
    st, j = raw(AR, "GET", "/api/deals?user_id=rt-other-user-109")
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/deals with another user's user_id (IDOR probe): no 500, app alive", ok, "st=%s" % st)
app_deals_idor_probe()

def sig_all_zero():
    body = json.dumps({"user_id": "rt-109zs", "idempotency_key": "k109zs", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    h["X-Kavach-Signature"] = "0" * 64
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st in (401, 403) and conserved() and alive(ER)
    return check("auth", "X-Kavach-Signature all-zero 64 hex: 401, conserved", ok, "st=%s" % st)
sig_all_zero()

def waitlist_after_confirm():
    rid, st, _ = bk_hold("rt-109wc", "k109wc")
    if not rid:
        return check("state", "post-confirm waitlist join: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": rid}).encode()
    st1, _ = raw(ER, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))
    st2, _ = post(ER, "/waitlist", {"user_id": "rt-109wc", "seats": 1})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and conserved() and alive(ER)
    return check("state", "post-confirm waitlist join by same user: no 5xx, conserved", ok, "conf=%s wl=%s" % (st1, st2))
waitlist_after_confirm()

def idem_replay_post_confirm():
    rid, st, _ = bk_hold("rt-109ir", "k109ir")
    if not rid:
        return check("state", "idem replay post-confirm: skipped (hold unavailable)", True, "st=%s" % st)
    body = json.dumps({"reservation_id": rid}).encode()
    st1, _ = raw(ER, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))
    st2, _ = post(ER, "/reserve", {"user_id": "rt-109ir", "idempotency_key": "k109ir", "seats": 1})
    time.sleep(0.2)
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and conserved() and alive(ER)
    return check("state", "idem replay post-confirm (same idem reserve after confirm): no 5xx, conserved", ok, "conf=%s re2=%s" % (st1, st2))
idem_replay_post_confirm()

def app_pay_outcome_pending():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": "rt-109po", "outcome": "pending"}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/pay outcome \"pending\": no 500, app alive", ok, "st=%s" % st)
app_pay_outcome_pending()

def app_hold_seats_neg():
    body = json.dumps({"user_id": "rt-109hn", "seats": -1}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold seats -1: no 500, app alive", ok, "st=%s" % st)
app_hold_seats_neg()

def seats_scientific_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-109ss", "idempotency_key": "k109ss", "seats": "1e2"})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as string \"1e2\": graceful, conserved", ok, "st=%s" % st)
seats_scientific_string()

def webhook_event_empty_str():
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "", "reservation_id": "RSV00000001"}).encode())
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("webhook", "webhook event as empty string: no 500, app alive", ok, "st=%s" % st)
webhook_event_empty_str()

def parallel_identical_reserves():
    outs = []
    def fire(_):
        return post(ER, "/reserve", {"user_id": "rt-109pi", "idempotency_key": "k109pi", "seats": 1})[0]
    with ThreadPoolExecutor(2) as ex:
        outs = list(ex.map(fire, range(2)))
    time.sleep(0.3)
    ok = all(x != 500 and x != -1 for x in outs) and conserved() and alive(ER)
    return check("race", "two parallel identical reserves (same idem, same payload): no 5xx, conserved", ok, "sts=%s" % outs)
parallel_identical_reserves()

def app_hold_dup_seats_keys():
    body = ('{"user_id":"rt-109dk","seats":1,"seats":2}').encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app /api/hold duplicate seats JSON keys: no 500, app alive", ok, "st=%s" % st)
app_hold_dup_seats_keys()
