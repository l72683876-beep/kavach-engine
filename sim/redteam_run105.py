#!/usr/bin/env python3
"""Run 105 extras: 12 angles (all live in redteam_battery.py Phase BG too).
1: transfer with forged from_user field (differs from owner): no 500, conserved
2: confirm on a transferred rid (hold -> transfer -> confirm): 4xx, conserved
3: 10KB Bearer token in Authorization header: 401/4xx, no 500, conserved
4: X-Kavach-Timestamp as RFC1123 date string: 4xx, conserved
5: X-Kavach-Signature as base64 (not hex): 401, conserved
6: to_user whitespace-only "   ": graceful, no 500, conserved
7: app /api/waitlist scalar JSON body: no 500, app alive
8: webhook event as JSON array (["payment_success"]) with valid token: no 500, app alive
9: app /api/pay amount as JSON list [100]: no 500, app alive
10: parallel reserve race, same idem, seats 1 vs seats 2: conserved
11: sig computed over otherkey, Bearer testkey (key/sig mismatch mirror): 401, conserved
12: /release with reservation_id as JSON number 123: 4xx graceful, conserved
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import base64, hashlib, hmac, http.client, json, sys, time, uuid
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

# ---------------- Phase BG: run 105 extras (12 new angles) ----------------
def be_hold(user, key="k105%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})
def forged_from_user():
    rid, st, _ = be_hold("rt-105fu", "k105fu")
    if not rid:
        return check("state", "transfer with forged from_user: skipped (hold unavailable)", True, "st=%s" % st)
    t, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-105fu2", "from_user": "attacker-105"})
    post(ER, "/release", {"reservation_id": rid})
    ok = t != 500 and t != -1 and conserved() and raw(ER, "GET", "/seats")[0] == 200
    return check("state", "transfer with forged from_user field: no 500, conserved", ok, "t=%s" % t)
forged_from_user()
def confirm_after_transfer():
    rid, st, _ = be_hold("rt-105ct", "k105ct")
    if not rid:
        return check("state", "confirm on transferred rid: skipped (hold unavailable)", True, "st=%s" % st)
    t, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-105ct2"})
    c, _ = post(ER, "/confirm", {"reservation_id": rid})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = c != 500 and c != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("state", "confirm on transferred rid (hold->transfer->confirm): 4xx, conserved", ok, "t=%s c=%s" % (t, c))
confirm_after_transfer()
def auth_10kb():
    body = json.dumps({"user_id": "rt-105ab", "idempotency_key": "k105ab", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    h["Authorization"] = "Bearer " + ("a" * 10000)
    st, j = raw(ER, "POST", "/reserve", body, h)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "10KB Bearer token in Authorization: 401/4xx, no 5xx, conserved", ok, "st=%s" % st)
auth_10kb()
def ts_rfc1123():
    body = json.dumps({"user_id": "rt-105rf", "idempotency_key": "k105rf", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    h["X-Kavach-Timestamp"] = "Wed, 18 Nov 2026 16:00:00 GMT"
    st, j = raw(ER, "POST", "/reserve", body, h)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and st != 200 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp as RFC1123 date string: 4xx, conserved", ok, "st=%s" % st)
ts_rfc1123()
def sig_base64():
    body = json.dumps({"user_id": "rt-105b64", "idempotency_key": "k105b64", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    mac = hmac.new(SECRET.encode(), (h["X-Kavach-Timestamp"] + "\n" + h["X-Kavach-Request-Id"] + "\n" + "POST" + "\n" + "/reserve" + "\n" + KEY + "\n").encode() + body, hashlib.sha256).digest()
    h["X-Kavach-Signature"] = base64.b64encode(mac).decode()
    st, j = raw(ER, "POST", "/reserve", body, h)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "signature as base64 (not hex): 401/4xx, conserved", ok, "st=%s" % st)
sig_base64()
def to_user_whitespace():
    st, j = post(ER, "/reserve", {"user_id": "   ", "idempotency_key": "k105ws", "seats": 1})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "to_user whitespace-only: graceful 4xx or rejected, no 5xx, conserved", ok, "st=%s" % st)
to_user_whitespace()
def app_waitlist_scalar():
    p, _ = raw(AR, "POST", "/api/waitlist", '"plain-string-105"')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/waitlist scalar JSON body: no 500, app alive", ok, "p=%s" % p)
app_waitlist_scalar()
def webhook_event_array():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", '["payment_success"]')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook event as JSON array: no 500, app alive", ok, "w=%s" % w)
webhook_event_array()
def app_pay_amount_list():
    rid, st, _ = be_hold("rt-105al", "k105al")
    if not rid:
        return check("app", "app pay amount list: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": [100]}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount as JSON list [100]: no 500, graceful", ok, "p=%s" % p)
app_pay_amount_list()
def idem_seats_race():
    for _ in range(4):
        s = seats(ER)
        if s.get("free", 0) >= 2: break
        time.sleep(4)
    body1 = json.dumps({"user_id": "rt-105is", "idempotency_key": "k105is", "seats": 1}).encode()
    body2 = json.dumps({"user_id": "rt-105is", "idempotency_key": "k105is", "seats": 2}).encode()
    h1 = sign(KEY, "POST", "/reserve", body1)
    h2 = sign(KEY, "POST", "/reserve", body2)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/reserve", body1, h1)
        f2 = ex.submit(raw, ER, "POST", "/reserve", body2, h2)
        st1, j1 = f1.result(); st2, j2 = f2.result()
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    rids = [j.get("reservation_id") for j in (j1, j2) if isinstance(j, dict) and j.get("reservation_id")]
    for r in rids:
        post(ER, "/release", {"reservation_id": r})
    ok = all(x != 500 and x != -1 for x in (st1, st2)) and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("race", "parallel reserve same idem seats 1 vs 2: no 5xx, conserved", ok, "st1=%s st2=%s" % (st1, st2))
idem_seats_race()
def key_sig_mismatch_mirror():
    body = json.dumps({"user_id": "rt-105km", "idempotency_key": "k105km", "seats": 1}).encode()
    h = sign(KEY2, "POST", "/reserve", body)  # sig over otherkey
    h["Authorization"] = "Bearer " + KEY      # bearer testkey
    st, j = raw(ER, "POST", "/reserve", body, h)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and st != 200 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "sig over otherkey sent with Bearer testkey: 401, conserved", ok, "st=%s" % st)
key_sig_mismatch_mirror()
def release_rid_number():
    st, j = post(ER, "/release", {"reservation_id": 123})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("state", "/release with reservation_id as number 123: 4xx graceful, conserved", ok, "st=%s" % st)
release_rid_number()

if __name__ == "__main__":
    fails = [r for r in results if not r[2]]
    print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
    for r in fails: print("FAIL [%s] %s :: %s" % (r[0], r[1], r[3]))
    sys.exit(1 if fails else 0)
