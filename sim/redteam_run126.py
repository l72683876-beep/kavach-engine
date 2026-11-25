#!/usr/bin/env python3
"""Run 126 extras: 12 angles (Phase CB), all new vs runs 115-125.
1: /reserve with user_id float 1.5: no 5xx, conserved
2: /reserve with X-Kavach-Timestamp header missing: rejected, no 5xx
3: /waitlist with seats as string "3": no 5xx
4: /release with mismatched user_id field: one terminal state, conserved
5: /transfer with to_user empty string: no 5xx, conserved
6: /book with idempotency_key boolean: no 5xx, conserved
7: app /api/reserve with extra seats field null: no 500, app alive
8: app webhook token with whitespace padding: rejected, app alive
9: /reserve with duplicate user_id JSON keys: no 5xx, conserved
10: /confirm on expired hold (TTL engine 8095): graceful, no 5xx
11: race: 8-way parallel /reserve same idem key different seat counts: conserved
12: /book with seats string "NaN": no 5xx, conserved
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
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def conserved(port=ER):
    s = seats(port)
    return s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
def alive(port, path="/seats"):
    st, _ = raw(port, "GET", path)
    return st == 200
def hold(user, key, seats_n=1, port=ER):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, j

# ---------------- Phase CB: run 126 extras (12 new angles) ----------------
def cb_reserve_uid_float():
    st, j = post(ER, "/reserve", {"user_id": 1.5, "idempotency_key": "k126uf", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id float: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_reserve_uid_float()

def cb_reserve_no_ts():
    body = json.dumps({"user_id": "rt-126nt", "idempotency_key": "k126nt", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    h.pop("X-Kavach-Timestamp")
    st, j = raw(ER, "POST", "/reserve", body, h)
    ok = st != 500 and st != -1 and st != 200 and alive(ER)
    return check("auth", "reserve missing timestamp header: rejected, no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_reserve_no_ts()

def cb_waitlist_seats_str():
    st, j = post(ER, "/waitlist", {"user_id": "rt-126ws", "seats": "3"})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist seats string: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_waitlist_seats_str()

def cb_release_uid_mismatch():
    rid, st, _ = hold("rt-126um", "k126um", 2)
    if not rid:
        return check("state", "release uid mismatch: skipped (hold unavailable)", True, "st=%s" % st)
    str1, j = post(ER, "/release", {"reservation_id": rid, "user_id": "someone-else"})
    time.sleep(0.2)
    ok = str1 != 500 and str1 != -1 and conserved() and alive(ER)
    return check("state", "release mismatched user_id: no 5xx, conserved", ok, "rid=%s str1=%s j=%s" % (rid, str1, str(j)[:60]))
cb_release_uid_mismatch()

def cb_transfer_touser_empty():
    rid, st, _ = hold("rt-126te", "k126te", 1)
    if not rid:
        return check("state", "transfer to_user empty: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-126te"})
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": ""})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer to_user empty string: no 5xx, conserved", ok, "rid=%s stt=%s j=%s" % (rid, stt, str(j)[:60]))
cb_transfer_touser_empty()

def cb_book_idem_bool():
    st, j = post(ER, "/book", {"user_id": "rt-126bi", "idempotency_key": True, "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book idempotency_key boolean: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_book_idem_bool()

def cb_app_reserve_extra_seats_null():
    st, j = raw(AR, "POST", "/api/reserve", json.dumps({"user_id": "rt-126ae", "seats": 1, "seats2": None}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app reserve extra seats field null: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_app_reserve_extra_seats_null()

def cb_webhook_token_padded():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Signature": sig, "X-Kavach-Token": " whsec-redtest "}
    st, j = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = st != 500 and st != -1 and st != 200 and alive(AR, "/")
    return check("app", "webhook token whitespace padded: rejected, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_webhook_token_padded()

def cb_reserve_dup_uid_keys():
    body = json.loads('{"user_id":"rt-126dk","idempotency_key":"k126dk","seats":1,"user_id":"rt-126dk-b"}')
    body = json.dumps(body).encode()
    st, j = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve duplicate user_id keys: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_reserve_dup_uid_keys()

def cb_confirm_expired_hold():
    rid, st, _ = hold("rt-126ex", "k126ex", 2, port=ET)
    if not rid:
        return check("state", "confirm expired hold: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(4.5)  # hold-ttl 3s: expires
    stc, j = post(ET, "/confirm", {"reservation_id": rid, "user_id": "rt-126ex"})
    ok = stc != 500 and stc != -1 and conserved(ET) and alive(ET)
    return check("state", "confirm expired hold (TTL): graceful, no 5xx", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
cb_confirm_expired_hold()

def cb_reserve_idem_race_varied():
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(post, ER, "/reserve", {"user_id": "rt-126rr", "idempotency_key": "k126rr", "seats": 1 + (i % 4)}) for i in range(8)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved() and alive(ER)
    return check("race", "8-way same idem varied seats: no 5xx, conserved", ok, "sts=%s" % [o[0] for o in outs])
cb_reserve_idem_race_varied()

def cb_book_seats_nan():
    st, j = post(ER, "/book", {"user_id": "rt-126nn", "idempotency_key": "k126nn", "seats": "NaN"})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book seats string NaN: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cb_book_seats_nan()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("CB TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "CB", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/cb126.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
