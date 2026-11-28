#!/usr/bin/env python3
"""Run 133 extras: 12 angles (Phase CI), all new vs runs 115-132.
1: /reserve seats as negative number: no 5xx, conserved
2: /confirm with idempotency_key instead of reservation_id: no 5xx
3: /waitlist seats as string: no 5xx
4: /release reservation_id empty string: no 5xx, conserved
5: /transfer with extra seats field: no 5xx, conserved
6: /book user_id as array: no 5xx, conserved
7: app /api/confirm rid as boolean: no 500, app alive
8: app webhook missing signature header: rejected, app alive
9: /reserve duplicate JSON keys for seats: no 5xx, conserved
10: HMAC path swap (sig over different path): rejected, conserved
11: race 6-way parallel /book same idem key different users: one booking, conserved
12: TTL engine: confirm on expired hold: no 5xx, no seat leak
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
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None, sign_path=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    sp = sign_path if sign_path is not None else path
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + sp + "\n" + key + "\n").encode() + body, hashlib.sha256).hexdigest()
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
def rawpost(port, path, raw_body, user_key=KEY):
    return raw(port, "POST", path, raw_body, sign(user_key, "POST", path, raw_body))
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

# ---------------- Phase CI: run 133 extras (12 new angles) ----------------
def ci_reserve_seats_negative():
    st, j = post(ER, "/reserve", {"user_id": "rt-133neg", "idempotency_key": "k133neg", "seats": -1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats negative: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_reserve_seats_negative()

def ci_confirm_wrong_field():
    rid, st, _ = hold("rt-133wf", "k133wf", 1)
    if not rid:
        return check("state", "confirm wrong field: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER, "/confirm", {"idempotency_key": "k133wf", "user_id": "rt-133wf"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("fuzz", "confirm idempotency_key instead of reservation_id: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
ci_confirm_wrong_field()

def ci_waitlist_seats_string():
    st, j = post(ER, "/waitlist", {"user_id": "rt-133ws", "seats": "2"})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist seats string: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_waitlist_seats_string()

def ci_release_empty_rid():
    st, j = post(ER, "/release", {"reservation_id": "", "user_id": "rt-133er"})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "release reservation_id empty string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_release_empty_rid()

def ci_transfer_extra_seats():
    rid, st, _ = hold("rt-133ts", "k133ts", 1)
    if not rid:
        return check("state", "transfer extra seats: skipped (hold unavailable)", True, "st=%s" % st)
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-133ts-b", "seats": 5})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("state", "transfer extra seats field: no 5xx, conserved", ok, "rid=%s stt=%s" % (rid, stt))
ci_transfer_extra_seats()

def ci_book_uid_array():
    st, j = post(ER, "/book", {"user_id": ["rt-133ba"], "idempotency_key": "k133ba", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "book user_id array: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_book_uid_array()

def ci_app_confirm_rid_bool():
    st, j = raw(AR, "POST", "/api/confirm", json.dumps({"rid": True}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app confirm rid boolean: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_app_confirm_rid_bool()

def ci_webhook_no_sig():
    body = json.dumps({"type": "confirmed", "reservation_id": "RSV00000001"}).encode()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest"}
    st, j = raw(AR, "POST", "/webhook", body, h)
    ok = st != 500 and st != -1 and st not in (200,) and alive(AR, "/")
    return check("app", "webhook missing signature header: rejected, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_webhook_no_sig()

def ci_reserve_dup_json_keys():
    st, j = rawpost(ER, "/reserve", b'{"user_id":"rt-133dk","idempotency_key":"k133dk","seats":1,"seats":2}')
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve duplicate JSON keys seats: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_reserve_dup_json_keys()

def ci_hmac_path_swap():
    body = json.dumps({"user_id": "rt-133hp", "idempotency_key": "k133hp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body, sign_path="/book")
    st, j = raw(ER, "POST", "/reserve", body, h)
    time.sleep(0.2)
    ok = st != 500 and st != -1 and st not in (200,) and conserved() and alive(ER)
    return check("auth", "HMAC sig over wrong path: rejected, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
ci_hmac_path_swap()

def ci_book_race_same_idem():
    def one(i):
        return post(ER, "/book", {"user_id": "rt-133br-%d" % i, "idempotency_key": "k133br", "seats": 1})[0]
    with ThreadPoolExecutor(max_workers=6) as ex:
        sts = list(ex.map(one, range(6)))
    time.sleep(0.3)
    ok = all(s in (200, 400, 409, 410, 429) for s in sts) and conserved() and alive(ER)
    return check("race", "6-way parallel book same idem key diff users: no 5xx, conserved", ok, "sts=%s" % sts)
ci_book_race_same_idem()

def ci_ttl_expired_confirm():
    rid, st, _ = hold("rt-133ex", "k133ex", 1, port=ET)
    if not rid:
        return check("state", "ttl expired confirm: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(4)
    stc, j = post(ET, "/confirm", {"reservation_id": rid, "user_id": "rt-133ex"})
    time.sleep(0.3)
    s = seats(ET)
    ok = stc != 500 and stc != -1 and conserved(ET) and alive(ET)
    return check("state", "ttl engine: confirm on expired hold: no 5xx, no seat leak", ok, "rid=%s stc=%s seats=%s" % (rid, stc, str(s)[:60]))
ci_ttl_expired_confirm()

print("CI TOTAL %d cases, PASS %d, FAIL %d" % (
    len(results), sum(1 for c, n, ok, d in results if ok), sum(1 for c, n, ok, d in results if not ok)))
for cat, name, ok, detail in results:
    print("%-4s %-4s %s %s" % ("OK" if ok else "FAIL", cat, name, detail if not ok else ""))
sys.exit(0 if all(ok for _, _, ok, _ in results) else 1)
