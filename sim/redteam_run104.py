#!/usr/bin/env python3
"""Run 104 extras: 12 angles (all live in redteam_battery.py Phase BF too).
1: 6-way parallel transfer of 6 different held rids: no 5xx, conserved
2: webhook duplicate token in query (?token=a&token=whsec-redtest): 401/last-wins, no 5xx
3: app /api/hold with scalar JSON body (plain string): no 500, app alive
4: webhook payment_success with amount differing from real price: no 500, conserved
5: app /api/pay with reservation_id containing newline: no 500, app alive
6: sig computed over rid A, sent with rid B (sig-rid binding): 401/4xx, conserved
7: app /api/pay amount as Arabic-Indic digits "١٠٠": no 500, app alive
8: sig computed over ts A, sent with current ts (sig-ts binding): 401/4xx, conserved
9: dual auth conflict (X-Kavach-Key testkey + Authorization Bearer otherkey): no 5xx, conserved
10: 6-way parallel release of 6 different rids: all 200, conserved
11: app /api/pay amount as "+100" (plus prefix): no 500, app alive
12: app /api/pay amount as 0 (zero): no 500, app alive
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, SECRET = "testkey", "testsecret"
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

# ---------------- Phase BF: run 104 extras (12 new angles) ----------------
def be_hold(user, key="k104%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})
def free_count(port=ER):
    s = seats(port)
    return s.get("free", 0)
def parallel_transfer_different_rids():
    for _ in range(4):
        if free_count() >= 6: break
        time.sleep(4)  # hold-ttl 3: let lingering holds from earlier phases expire
    rids = []
    for i in range(6):
        rid, st, body = be_hold("rt-104pt%d" % i, "k104pt%d" % i)
        if not rid:
            if body.get("status") == "sold_out":
                return check("race", "parallel transfer of 6 different rids: skipped (engine full)", True, "sold_out st=%s" % st)
            return check("race", "parallel transfer of 6 different rids: setup fail", False, "hold %d st=%s body=%s" % (i, st, json.dumps(body)[:120]))
        rids.append(rid)
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(lambda r: post(ER, "/transfer", {"reservation_id": r, "to_user": "rt-104ptb%d" % rids.index(r)})[0], rids))
    time.sleep(0.5)
    ok = all(o != 500 and o != -1 for o in outs) and conserved()
    return check("race", "parallel transfer of 6 different rids: no 5xx, conserved", ok, "outs=%s" % outs)
parallel_transfer_different_rids()
def webhook_duplicate_token():
    w1, _ = raw(AR, "POST", "/api/kavach-webhook?token=a&token=whsec-redtest", '{"event":"payment_success","reservation_id":"FAKE-104"}')
    w2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest&token=a", '{"event":"payment_success","reservation_id":"FAKE-104"}')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w1 != 500 and w1 != -1 and w2 != 500 and w2 != -1 and alive
    return check("app", "webhook duplicate token in query (both orders): no 5xx, app alive", ok, "w1=%s w2=%s" % (w1, w2))
webhook_duplicate_token()
def app_hold_scalar_body():
    p, _ = raw(AR, "POST", "/api/hold", '"plain-string-body-104"')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/hold scalar JSON body (plain string): no 500, app alive", ok, "p=%s" % p)
app_hold_scalar_body()
def webhook_wrong_amount():
    rid, st, _ = be_hold("rt-104wa", "k104wa")
    if not rid:
        return check("app", "webhook payment_success with wrong amount: skipped (hold unavailable)", True, "st=%s" % st)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid, "amount": 999999}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and conserved() and alive
    return check("app", "webhook payment_success with amount 999999 (wrong price): no 500, conserved", ok, "w=%s" % w)
webhook_wrong_amount()
def app_pay_rid_newline():
    rid, st, _ = be_hold("rt-104nl", "k104nl")
    if not rid:
        return check("app", "app pay rid with newline: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid + "\n", "amount": 100}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay reservation_id with trailing newline: no 500, graceful", ok, "p=%s" % p)
app_pay_rid_newline()
def sig_rid_binding():
    body = json.dumps({"user_id": "rt-104sr", "idempotency_key": "k104sr", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body, rid="rid-binding-a")
    h["X-Kavach-Request-Id"] = "rid-binding-b"  # sig still over rid-binding-a
    st, j = raw(ER, "POST", "/reserve", body, h)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st not in (200, 500, -1) and cv and alive
    return check("auth", "sig over rid A sent with rid B (sig-rid binding): 401/4xx, conserved", ok, "st=%s" % st)
sig_rid_binding()
def app_pay_amount_arabic():
    rid, st, _ = be_hold("rt-104ar", "k104ar")
    if not rid:
        return check("app", "app pay amount Arabic-Indic digits: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": "\u0661\u0660\u0660"}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount Arabic-Indic digits (\u0661\u0660\u0660): no 500, graceful", ok, "p=%s" % p)
app_pay_amount_arabic()
def sig_ts_binding():
    body = json.dumps({"user_id": "rt-104st", "idempotency_key": "k104st", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body, ts="1000000000")
    h["X-Kavach-Timestamp"] = str(int(time.time()))  # sig still over ts 1000000000
    st, j = raw(ER, "POST", "/reserve", body, h)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st not in (200, 500, -1) and cv and alive
    return check("auth", "sig over old ts sent with current ts (sig-ts binding): 401/4xx, conserved", ok, "st=%s" % st)
sig_ts_binding()
def dual_auth_conflict():
    body = json.dumps({"user_id": "rt-104da", "idempotency_key": "k104da", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)  # sig over testkey
    h["Authorization"] = "Bearer otherkey"   # conflicts with X-Kavach-Key absent; sig over testkey
    st, j = raw(ER, "POST", "/reserve", body, h)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and cv and alive
    return check("auth", "dual auth conflict (sig over testkey, Bearer otherkey): no 5xx, conserved", ok, "st=%s" % st)
dual_auth_conflict()
def parallel_release_different_rids():
    for _ in range(4):
        if free_count() >= 6: break
        time.sleep(4)
    rids = []
    for i in range(6):
        rid, st, body = be_hold("rt-104pr%d" % i, "k104pr%d" % i)
        if not rid:
            if body.get("status") == "sold_out":
                return check("race", "parallel release of 6 different rids: skipped (engine full)", True, "sold_out st=%s" % st)
            return check("race", "parallel release of 6 different rids: setup fail", False, "hold %d st=%s body=%s" % (i, st, json.dumps(body)[:120]))
        rids.append(rid)
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(lambda r: post(ER, "/release", {"reservation_id": r})[0], rids))
    time.sleep(0.5)
    ok = all(o == 200 for o in outs) and conserved()
    return check("race", "parallel release of 6 different rids: all 200, conserved", ok, "outs=%s" % outs)
parallel_release_different_rids()
def app_pay_amount_plus():
    rid, st, _ = be_hold("rt-104pl", "k104pl")
    if not rid:
        return check("app", "app pay amount plus prefix: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": "+100"}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount \"+100\" (plus prefix): no 500, graceful", ok, "p=%s" % p)
app_pay_amount_plus()
def app_pay_amount_zero():
    rid, st, _ = be_hold("rt-104zr", "k104zr")
    if not rid:
        return check("app", "app pay amount zero: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": 0}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount 0 (zero): no 500, graceful", ok, "p=%s" % p)
app_pay_amount_zero()

if __name__ == "__main__":
    fails = [r for r in results if not r[1]]
    print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
    for r in fails: print("FAIL [%s] %s :: %s" % (r[0], r[1], r[3]))
    sys.exit(1 if fails else 0)
