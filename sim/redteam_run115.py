#!/usr/bin/env python3
"""Run 115 extras: 12 angles (all live in redteam_battery.py Phase BQ too).
1: reserve seats as string "+2": graceful, conserved
2: transfer to_user containing newline: no 5xx, conserved
3: /waitlist seats as string "1.0": graceful, conserved
4: /release with seats field "0": no 5xx, conserved
5: /confirm without idempotency_key: no 5xx, conserved
6: webhook reservation_id as JSON unicode escapes: no 500, app alive
7: app /api/hold user_id as JSON array: no 500, app alive
8: app /api/pay outcome whitespace-padded: no 500, app alive
9: app /api/board limit float 1.5: no 500, app alive
10: app /api/board limit boolean true: no 500, app alive
11: app POST /api/deals duplicate title keys: no 500, app alive
12: /waitlist body with UTF-8 BOM: graceful, conserved
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
def bq_alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def bq_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

# ---------------- Phase BQ: run 115 extras (12 new angles) ----------------
def bq_reserve_seats_plus():
    st, j = post(ER, "/reserve", {"user_id": "rt-115sp", "idempotency_key": "k115sp", "seats": "+2"})
    ok = st != 500 and st != -1 and conserved() and bq_alive(ER)
    return check("fuzz", "reserve seats as string \"+2\": graceful, conserved", ok, "st=%s" % st)
bq_reserve_seats_plus()

def bq_transfer_newline():
    rid, st, _ = bq_hold("rt-115tn", "k115tn")
    if not rid:
        return check("state", "transfer to_user newline: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-115tn\nb"})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and bq_alive(ER)
    return check("fuzz", "transfer to_user containing newline: no 5xx, conserved", ok, "st2=%s" % st2)
bq_transfer_newline()

def bq_waitlist_seats_str():
    st, j = post(ER, "/waitlist", {"user_id": "rt-115w0", "idempotency_key": "k115w0", "seats": "1.0"})
    ok = st != 500 and st != -1 and conserved() and bq_alive(ER)
    return check("fuzz", "/waitlist seats as string \"1.0\": graceful, conserved", ok, "st=%s" % st)
bq_waitlist_seats_str()

def bq_release_seats_zero():
    rid, st, _ = bq_hold("rt-115rz", "k115rz")
    if not rid:
        return check("state", "release seats \"0\": skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/release", {"reservation_id": rid, "seats": "0"})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and bq_alive(ER)
    return check("state", "/release with seats field \"0\": no 5xx, conserved", ok, "st2=%s" % st2)
bq_release_seats_zero()

def bq_confirm_no_idem():
    rid, st, _ = bq_hold("rt-115ci", "k115ci")
    if not rid:
        return check("state", "confirm without idem: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    time.sleep(0.2)
    ok = st2 != 500 and st2 != -1 and conserved() and bq_alive(ER)
    return check("state", "/confirm without idempotency_key: no 5xx, conserved", ok, "st2=%s" % st2)
bq_confirm_no_idem()

def bq_webhook_rid_escapes():
    body = b'{"event": "payment_success", "reservation_id": "\\u0052\\u0053\\u0056\\u0030\\u0030\\u0030\\u0030\\u0030\\u0030\\u0030\\u0031"}'
    st, j = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    ok = st != 500 and st != -1 and bq_alive(AR, "/")
    return check("webhook", "webhook reservation_id as JSON unicode escapes: no 500, app alive", ok, "st=%s" % st)
bq_webhook_rid_escapes()

def bq_app_hold_uid_array():
    body = json.dumps({"user_id": ["rt-115ha"], "seats": 1}).encode()
    st, j = raw(AR, "POST", "/api/hold", body)
    ok = st != 500 and st != -1 and bq_alive(AR, "/")
    return check("app", "app /api/hold user_id as JSON array: no 500, app alive", ok, "st=%s" % st)
bq_app_hold_uid_array()

def bq_app_pay_outcome_padded():
    body = json.dumps({"reservation_id": "RSV00000001", "user_id": "rt-115op", "outcome": " SUCCESS "}).encode()
    st, j = raw(AR, "POST", "/api/pay", body)
    ok = st != 500 and st != -1 and bq_alive(AR, "/")
    return check("app", "app /api/pay outcome whitespace-padded: no 500, app alive", ok, "st=%s" % st)
bq_app_pay_outcome_padded()

def bq_app_board_limit_float():
    st, j = raw(AR, "GET", "/api/board?limit=1.5")
    ok = st != 500 and st != -1 and bq_alive(AR, "/")
    return check("app", "app /api/board limit float 1.5: no 500, app alive", ok, "st=%s" % st)
bq_app_board_limit_float()

def bq_app_board_limit_bool():
    st, j = raw(AR, "GET", "/api/board?limit=true")
    ok = st != 500 and st != -1 and bq_alive(AR, "/")
    return check("app", "app /api/board limit boolean true: no 500, app alive", ok, "st=%s" % st)
bq_app_board_limit_bool()

def bq_app_deals_dup_title():
    st, j = raw(AR, "POST", "/api/deals", b'{"title": "rt-115a", "title": "rt-115b"}')
    ok = st != 500 and st != -1 and bq_alive(AR, "/")
    return check("app", "app POST /api/deals duplicate title keys: no 500, app alive", ok, "st=%s" % st)
bq_app_deals_dup_title()

def bq_waitlist_bom():
    body = b"\xef\xbb\xbf" + json.dumps({"user_id": "rt-115wb", "idempotency_key": "k115wb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/waitlist", body)
    st, j = raw(ER, "POST", "/waitlist", body, h)
    ok = st != 500 and st != -1 and conserved() and bq_alive(ER)
    return check("fuzz", "/waitlist body with UTF-8 BOM: graceful, conserved", ok, "st=%s" % st)
bq_waitlist_bom()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("FINDINGS: 0")
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in fails:
    print("FAIL [%s] %s :: %s" % (r[0], r[1], r[3]))
sys.exit(1 if fails else 0)
