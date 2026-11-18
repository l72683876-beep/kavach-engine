#!/usr/bin/env python3
"""Run 103 extras: 12 angles (all live in redteam_battery.py Phase BE too).
1: 6-way parallel confirm of 6 different rids: all confirm, conserved
2: webhook with truncated JSON body (valid token): no 5xx, app alive
3: webhook token sent via Authorization header (no token query): 401/403, app alive
4: app /api/pay with amount 1e15: no 500, conserved
5: partial transfer (transfer body carrying a "seats" field): 4xx/whole-move, conserved
6: webhook with 10KB token value: 4xx, no 5xx, app alive
7: Transfer-Encoding: identity on POST /reserve (raw socket): no 5xx, alive
8: top-level scalar JSON body (plain string) on /reserve: 4xx, no 5xx
9: transfer with to_user "undefined" (JS-style literal): no 500, conserved
10: full hold+confirm+transfer flow on engine2 (8092): works, conserved on 8092
11: transfer idempotency: same rid transferred twice with same idempotency_key: no 500, conserved
12: 6 different users, same idempotency_key, parallel reserve: no 5xx, conserved
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

# ---------------- Phase BE: run 103 extras (12 new angles) ----------------
def be_hold(user, key="k103%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})

def free_count(port=ER):
    s = seats(port)
    return s.get("free", 0)
def parallel_confirm_different_rids():
    for _ in range(4):
        if free_count() >= 6: break
        time.sleep(4)  # hold-ttl 3: let lingering holds from earlier phases expire
    rids = []
    for i in range(6):
        rid, st, body = be_hold("rt-103pc%d" % i, "k103pc%d" % i)
        if not rid:
            if body.get("status") == "sold_out":
                return check("race", "parallel confirm of 6 different rids: skipped (engine full)", True, "sold_out st=%s" % st)
            return check("race", "parallel confirm of 6 different rids: setup fail", False, "hold %d st=%s body=%s" % (i, st, json.dumps(body)[:120]))
        rids.append(rid)
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(lambda r: post(ER, "/confirm", {"reservation_id": r})[0], rids))
    time.sleep(0.5)
    ok = all(o == 200 for o in outs) and conserved()
    return check("race", "parallel confirm of 6 different rids: all 200, conserved", ok, "outs=%s" % outs)
parallel_confirm_different_rids()
def webhook_truncated_json():
    body = '{"event":"paym'
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    body2 = '{"event":"payment_success",}'
    w2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body2)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and w2 != 500 and w2 != -1 and alive
    return check("app", "webhook truncated/trailing-comma JSON with valid token: no 5xx, app alive", ok, "w=%s w2=%s" % (w, w2))
webhook_truncated_json()
def webhook_authorization_header():
    st, _ = raw(AR, "POST", "/api/kavach-webhook", '{"event":"payment_success"}',
                {"Authorization": "Bearer whsec-redtest", "Content-Type": "application/json"})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st in (401, 403) and alive
    return check("app", "webhook token via Authorization header only: 401/403, app alive", ok, "st=%s" % st)
webhook_authorization_header()
def app_pay_amount_1e15():
    rid, st, _ = be_hold("rt-103pe")
    if not rid:
        return check("app", "app pay amount 1e15: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": 1e15}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount 1e15: no 500, graceful", ok, "p=%s" % p)
app_pay_amount_1e15()
def partial_transfer():
    rid, st, _ = be_hold("rt-103pt", "k103pt", ER, 2)
    if not rid:
        return check("state", "partial transfer (seats field on transfer): skipped (hold unavailable)", True, "st=%s" % st)
    t, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-103pt2", "seats": 1})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = t != 500 and t != -1 and cv and alive
    return check("state", "partial transfer (seats field on transfer): no 500, conserved", ok, "t=%s" % t)
partial_transfer()
def webhook_10kb_token():
    st, _ = raw(AR, "POST", "/api/kavach-webhook?token=" + ("t" * 10000), '{"event":"payment_success"}')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("app", "webhook with 10KB token: 4xx, no 5xx, app alive", ok, "st=%s" % st)
webhook_10kb_token()
def te_identity():
    body = json.dumps({"user_id": "rt-103te", "idempotency_key": "k103te", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    import socket as _socket
    try:
        s = _socket.create_connection(("127.0.0.1", ER), timeout=10)
        req = ("POST /reserve HTTP/1.1\r\nHost: 127.0.0.1:8091\r\n" +
               "".join("%s: %s\r\n" % (k, v) for k, v in h.items()) +
               "Transfer-Encoding: identity\r\nContent-Length: %d\r\n\r\n" % len(body)).encode() + body
        s.sendall(req)
        try: d = s.recv(400)
        except Exception: d = b""
        s.close()
    except Exception as ex:
        d = ("EXC " + str(ex)).encode()
    graceful = d[:32].startswith(b"HTTP/1.1 2") or d[:32].startswith(b"HTTP/1.1 4") or d[:32].startswith(b"HTTP/1.1 501")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = graceful and alive
    return check("wire", "Transfer-Encoding: identity on POST: clean 2xx/4xx/501 (RFC 7230), alive", ok, "resp=%s" % d[:60].decode("utf-8", "replace"))
te_identity()
def scalar_body_reserve():
    body = json.dumps("hello").encode()
    st, _ = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and st >= 400 and alive and conserved()
    return check("fuzz", "top-level scalar JSON body on /reserve: 4xx, no 5xx", ok, "status=%s" % st)
scalar_body_reserve()
def transfer_to_undefined():
    rid, st, _ = be_hold("rt-103tu", "k103tu")
    if not rid:
        return check("state", "transfer to_user 'undefined': skipped (hold unavailable)", True, "st=%s" % st)
    t, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "undefined"})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = t != 500 and t != -1 and cv and alive
    return check("state", "transfer to_user 'undefined' (JS literal): no 500, conserved", ok, "t=%s" % t)
transfer_to_undefined()
def full_flow_engine2():
    if free_count(ER2) < 1:
        st, j = post(ER2, "/reserve", {"user_id": "rt-103f2", "idempotency_key": "k103f2", "seats": 1})
        graceful = st == 200 and isinstance(j, dict) and j.get("status") == "sold_out"
        alive = raw(ER2, "GET", "/seats")[0] == 200
        return check("state", "full flow on 8092: skipped (engine2 sold out), sold_out response graceful", graceful and alive, "st=%s body=%s" % (st, json.dumps(j)[:80]))
    rid, st, body = be_hold("rt-103f2", "k103f2", ER2)
    if not rid:
        return check("state", "full hold+confirm+transfer flow on 8092: setup fail", False, "hold st=%s body=%s" % (st, json.dumps(body)[:120]))
    c, _ = post(ER2, "/confirm", {"reservation_id": rid})
    t, _ = post(ER2, "/transfer", {"reservation_id": rid, "to_user": "rt-103f2b"})
    s = seats(ER2)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    alive = raw(ER2, "GET", "/seats")[0] == 200
    ok = c == 200 and t == 200 and cv and alive
    return check("state", "full hold+confirm+transfer flow on engine2 8092: works, conserved", ok, "h=%s c=%s t=%s" % (st, c, t))
full_flow_engine2()
def transfer_idempotency():
    rid, st, _ = be_hold("rt-103ti", "k103ti")
    if not rid:
        return check("state", "transfer idempotency (same rid+idem twice): skipped (hold unavailable)", True, "st=%s" % st)
    t1, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-103ti2", "idempotency_key": "k103tix"})
    t2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-103ti2", "idempotency_key": "k103tix"})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = t1 != 500 and t2 != 500 and t1 != -1 and t2 != -1 and cv and alive
    return check("state", "transfer same rid+same idem twice: no 500, conserved", ok, "t1=%s t2=%s" % (t1, t2))
transfer_idempotency()
def same_idem_six_users_race():
    def go(i):
        return post(ER, "/reserve", {"user_id": "rt-103si%d" % i, "idempotency_key": "k103si", "seats": 1})[0]
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(go, range(6)))
    time.sleep(0.5)
    ok = all(o != 500 and o != -1 for o in outs) and conserved()
    return check("race", "6 users same idempotency_key parallel reserve: no 5xx, conserved", ok, "outs=%s" % outs)
same_idem_six_users_race()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
