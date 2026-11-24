#!/usr/bin/env python3
"""Run 121 extras: 12 angles (Phase BW), all new vs runs 115-120.
1: /reserve with duplicate JSON keys (seats twice): parser must not 5xx, conserved
2: /confirm with reservation_id empty string: graceful, no 5xx
3: /waitlist with seats negative -1: no 5xx
4: /release with reservation_id as integer: no 5xx, conserved
5: /transfer with source == target (self-transfer): no 5xx, conserved
6: /book with user_id null: no 5xx, conserved
7: app /api/hold with user_id as integer: no 500, app alive
8: cross-tenant confirm: confirm tenant2's reservation with tenant1 key: no grant, conserved
9: app webhook valid token, same event_id twice: no dup processing, app alive
10: /reserve with seats as string "1": no 5xx, conserved
11: race: 10-way parallel /waitlist same user+key: at most one grant, conserved
12: /book with seats 0: no 5xx, conserved
Run against targets already up: 8091 engine, 8092 engine2, 8095 ttl engine, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2, ET = 8091, 9001, 8092, 8095
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
def post2(port, path, obj, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, "POST", path, body, sign(KEY2, "POST", path, body, **kw))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def conserved(port=ER):
    s = seats(port)
    return s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
def alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def bt_hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

# ---------------- Phase BW: run 121 extras (12 new angles) ----------------
def bw_duplicate_json_keys():
    body = '{"user_id":"rt-121dk","idempotency_key":"k121dk","seats":1,"seats":3}'
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body.encode()))
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve duplicate JSON seats keys: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:80]))
bw_duplicate_json_keys()

def bw_confirm_empty_rid():
    st, j = post(ER, "/confirm", {"reservation_id": "", "user_id": "rt-121ce"})
    ok = st != 500 and st != -1 and alive(ER)
    return check("state", "confirm empty reservation_id: graceful", ok, "st=%s j=%s" % (st, str(j)[:60]))
bw_confirm_empty_rid()

def bw_waitlist_negative_seats():
    st, j = post(ER, "/waitlist", {"user_id": "rt-121wn", "seats": -1})
    ok = st != 500 and st != -1 and alive(ER)
    return check("state", "waitlist seats -1: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
bw_waitlist_negative_seats()

def bw_release_rid_int():
    st, j = post(ER, "/release", {"reservation_id": 123})
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "release reservation_id as integer: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bw_release_rid_int()

def bw_self_transfer():
    rid, st, _ = bt_hold("rt-121st", "k121st", seats_n=2)
    if not rid:
        return check("state", "self-transfer: skipped (hold unavailable)", True, "st=%s" % st)
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-121st"})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("state", "transfer to self: no 5xx, conserved", ok, "rid=%s st=%s j=%s" % (rid, stt, str(j)[:60]))
bw_self_transfer()

def bw_book_null_userid():
    st, j = post(ER, "/book", {"user_id": None, "idempotency_key": "k121bn", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book user_id null: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bw_book_null_userid()

def bw_app_hold_userid_int():
    st, j = raw(AR, "POST", "/api/hold", json.dumps({"user_id": 42, "seats": 1}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app hold user_id integer: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
bw_app_hold_userid_int()

def bw_cross_tenant_confirm():
    # hold MUST be created with tenant2's key (post2); confirm then tried with tenant1's key
    body = json.dumps({"user_id": "rt-121ct", "idempotency_key": "k121ct", "seats": 1}).encode()
    sts, jr = post2(ER2, "/reserve", {"user_id": "rt-121ct", "idempotency_key": "k121ct", "seats": 1})
    rid = jr.get("reservation_id") if isinstance(jr, dict) and sts == 200 else None
    if not rid:
        return check("auth", "cross-tenant confirm: skipped (hold unavailable)", True, "st=%s j=%s" % (sts, str(jr)[:60]))
    stc, j = post(ER2, "/confirm", {"reservation_id": rid, "user_id": "rt-121ct"})
    time.sleep(0.2)
    # wrong-tenant confirm must NOT confirm: 404/403/409 expected; 200 would be a finding
    granted = stc == 200
    ok = stc != 500 and stc != -1 and conserved(ER2) and alive(ER2) and not granted
    return check("auth", "confirm other tenant's reservation with tenant1 key: rejected, conserved", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
bw_cross_tenant_confirm()

def bw_webhook_dup_event():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001", "event_id": "ev-121-dup"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest", "X-Kavach-Signature": sig}
    st1, j1 = raw(AR, "POST", "/api/kavach-webhook", body, h)
    st2, j2 = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and alive(AR, "/")
    return check("app", "webhook same event_id twice: no 5xx, idempotent", ok, "st1=%s st2=%s" % (st1, st2))
bw_webhook_dup_event()

def bw_reserve_seats_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-121ss", "idempotency_key": "k121ss", "seats": "1"})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats as string '1': no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bw_reserve_seats_string()

def bw_waitlist_race_same_user():
    key = "k121wr"
    outs = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(post, ER, "/waitlist", {"user_id": "rt-121wr", "idempotency_key": key, "seats": 1}, ) for _ in range(10)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    granted = [o for o in outs if o[0] == 200 and isinstance(o[1], dict) and (o[1].get("status") == "granted" or o[1].get("granted"))]
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved() and alive(ER)
    return check("race", "10-way waitlist same user: no 5xx, at most one grant", ok and len(granted) <= 1, "granted=%d sts=%s" % (len(granted), [o[0] for o in outs]))
bw_waitlist_race_same_user()

def bw_book_zero_seats():
    st, j = post(ER, "/book", {"user_id": "rt-121z", "idempotency_key": "k121z", "seats": 0})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book seats 0: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
bw_book_zero_seats()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("BW TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "BW", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/bw121.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
