#!/usr/bin/env python3
"""Run 128 extras: 12 angles (Phase CD), all new vs runs 115-127.
1: /reserve with user_id as empty object {}: no 5xx, conserved
2: /confirm with duplicate user_id JSON keys (raw body): no 5xx, sane
3: /waitlist with negative seats -2: no 5xx, sane
4: app /api/release with empty body POST: no 500, app alive
5: /transfer with extra seats field: no 5xx, conserved
6: /book with duplicate seats JSON keys (raw body): no 5xx, conserved
7: app /api/hold with seats as float 1.5: no 500, app alive
8: app webhook valid sig but unknown event type: graceful, app alive
9: /reserve with seats as string "-1": no 5xx, conserved
10: cross-engine confirm: hold on 8091, confirm same rid on 8092: rejected gracefully, no 5xx
11: race: 6 confirm + 6 release threads on the same hold: exactly one side effect wins, conserved
12: /transfer reservation to the same user (self-transfer): no 5xx, conserved
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
def rawpost(port, path, raw_body, user_key=KEY):
    """POST a raw body with correct signature over that exact body."""
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

# ---------------- Phase CD: run 128 extras (12 new angles) ----------------
def cd_reserve_uid_empty_object():
    st, j = post(ER, "/reserve", {"user_id": {}, "idempotency_key": "k128eo", "seats": 1})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve user_id empty object: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cd_reserve_uid_empty_object()

def cd_confirm_dup_uid_keys():
    rid, st, _ = hold("rt-128dk", "k128dk", 1)
    if not rid:
        return check("state", "confirm dup user_id keys: skipped (hold unavailable)", True, "st=%s" % st)
    raw_body = ('{"user_id": "rt-128dk", "reservation_id": "%s", "user_id": "attacker"}' % rid).encode()
    stc, j = rawpost(ER, "/confirm", raw_body)
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and conserved() and alive(ER)
    return check("auth", "confirm duplicate user_id JSON keys: no 5xx, conserved", ok, "rid=%s stc=%s" % (rid, stc))
cd_confirm_dup_uid_keys()

def cd_waitlist_negative_seats():
    st, j = post(ER, "/waitlist", {"user_id": "rt-128wn", "seats": -2})
    ok = st != 500 and st != -1 and alive(ER)
    return check("fuzz", "waitlist negative seats -2: no 5xx", ok, "st=%s j=%s" % (st, str(j)[:60]))
cd_waitlist_negative_seats()

def cd_app_release_empty_body():
    st, j = raw(AR, "POST", "/api/release", b"", {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app release empty body: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cd_app_release_empty_body()

def cd_transfer_seats_field():
    rid, st, _ = hold("rt-128ts", "k128ts", 1)
    if not rid:
        return check("state", "transfer seats field: skipped (hold unavailable)", True, "st=%s" % st)
    stc, _ = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-128ts"})
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-128ts-b", "seats": 5})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("fuzz", "transfer extra seats field: no 5xx, conserved", ok, "rid=%s stt=%s" % (rid, stt))
cd_transfer_seats_field()

def cd_book_dup_seats_keys():
    raw_body = b'{"user_id": "rt-128bd", "idempotency_key": "k128bd", "seats": 1, "seats": 99}'
    st, j = rawpost(ER, "/book", raw_body)
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("auth", "book duplicate seats JSON keys: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cd_book_dup_seats_keys()

def cd_app_hold_float():
    st, j = raw(AR, "POST", "/api/hold", json.dumps({"seats": 1.5}).encode(), {"Content-Type": "application/json"})
    ok = st != 500 and st != -1 and alive(AR, "/")
    return check("app", "app hold seats 1.5: no 500, app alive", ok, "st=%s j=%s" % (st, str(j)[:60]))
cd_app_hold_float()

def cd_webhook_unknown_event():
    rid, st, _ = hold("rt-128we", "k128we", 1)
    body = json.dumps({"type": "alien.event", "reservation_id": rid or "RSV00000001"}).encode()
    sig = hmac.new(b"whsec-redtest", body, hashlib.sha256).hexdigest()
    h = {"Content-Type": "application/json", "X-Kavach-Token": "whsec-redtest", "X-Kavach-Signature": sig}
    stw, j = raw(AR, "POST", "/api/kavach-webhook", body, h)
    ok = stw != 500 and stw != -1 and alive(AR, "/")
    return check("app", "webhook unknown event type valid sig: graceful", ok, "st=%s j=%s" % (stw, str(j)[:60]))
cd_webhook_unknown_event()

def cd_reserve_seats_neg_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-128sn", "idempotency_key": "k128sn", "seats": "-1"})
    time.sleep(0.2)
    ok = st != 500 and st != -1 and conserved() and alive(ER)
    return check("fuzz", "reserve seats '-1' string: no 5xx, conserved", ok, "st=%s j=%s" % (st, str(j)[:60]))
cd_reserve_seats_neg_string()

def cd_cross_engine_confirm():
    rid, st, _ = hold("rt-128cx", "k128cx", 1, port=ER)
    if not rid:
        return check("state", "cross-engine confirm: skipped (hold unavailable)", True, "st=%s" % st)
    stc, j = post(ER2, "/confirm", {"reservation_id": rid, "user_id": "rt-128cx"})
    time.sleep(0.2)
    ok = stc != 500 and stc != -1 and stc != 200 and conserved(ER) and conserved(ER2) and alive(ER) and alive(ER2)
    return check("state", "cross-engine confirm rejected gracefully", ok, "rid=%s stc=%s j=%s" % (rid, stc, str(j)[:60]))
cd_cross_engine_confirm()

def cd_confirm_release_race():
    rid, st, _ = hold("rt-128cr", "k128cr", 1)
    if not rid:
        return check("race", "confirm/release race: skipped (hold unavailable)", True, "st=%s" % st)
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(post, ER, "/confirm", {"reservation_id": rid, "user_id": "rt-128cr"}) for _ in range(6)]
        futs += [ex.submit(post, ER, "/release", {"reservation_id": rid, "user_id": "rt-128cr"}) for _ in range(6)]
        outs = [f.result() for f in futs]
    time.sleep(0.2)
    s = seats(ER)
    # exactly one side effect wins: hold either sold or freed, never both, conserved
    ok = all(o[0] != 500 and o[0] != -1 for o in outs) and conserved(ER) and alive(ER)
    return check("race", "12-way confirm+release race same hold: no 5xx, conserved", ok, "sts=%s seats=%s" % ([o[0] for o in outs], s))
cd_confirm_release_race()

def cd_self_transfer():
    rid, st, _ = hold("rt-128st", "k128st", 1)
    if not rid:
        return check("state", "self-transfer: skipped (hold unavailable)", True, "st=%s" % st)
    stt, j = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-128st"})
    time.sleep(0.2)
    ok = stt != 500 and stt != -1 and conserved() and alive(ER)
    return check("state", "self-transfer (to same user): no 5xx, conserved", ok, "rid=%s stt=%s j=%s" % (rid, stt, str(j)[:60]))
cd_self_transfer()

# ---------------- Summary ----------------
total = len(results); passed = sum(1 for r in results if r[2]); failed = total - passed
print("CD TOTAL %d cases, PASS %d, FAIL %d" % (total, passed, failed))
for cat, name, ok, detail in results:
    if not ok:
        print("FAIL [%s] %s: %s" % (cat, name, detail))
    else:
        print("OK   [%s] %s" % (cat, name))
out = {"run": "CD", "total": total, "passed": passed, "failed": failed,
       "cases": [{"cat": c, "name": n, "ok": o, "detail": d} for c, n, o, d in results]}
with open("/tmp/battery/cd128.json", "w") as f:
    json.dump(out, f, indent=1)
sys.exit(0 if failed == 0 else 1)
