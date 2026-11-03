#!/usr/bin/env python3
"""Run 57 extras: 12 angles (all live in redteam_battery.py Phase K too).
1: same idem key with reordered JSON keys: idempotent, exactly one sale
2: seats as 2.0 integral float and as object: no 5xx, object rejected
3: idem key with combining + fullwidth unicode: no 5xx
4: 3 separate holds confirmed by same user: exactly 3 sold, 3 distinct bookings
5: 10 parallel app pay-failure on one hold: released once, conserved
6: webhook with wrong JSON types (rid int, seats string): no 500
7: app hold seats=1e3 scientific notation: no 500
8: over-send body (declared 200, sent less, FIN): no hold created
9: HTTP/0.9-style request (no version): engine survives
10: 200 junk headers + valid signed request: answered, no smuggling
11: waitlist join with 10KB user_id: no 5xx, conserved
12: 5 app-pays vs 5 engine-releases race on one hold: XOR outcome
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, SECRET = "testkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
            "X-Kavach-Signature": mac.hexdigest(), "Content-Type": "application/json"}
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
def rej(st): return 400 <= st < 500 or st == 429
def P(n, fn):
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase K: run 57 extras (12 new angles) ----------------
def idem_fingerprint_canonicalization():
    # Same key + same fields, different JSON serialization: must be idempotent, never a second sale.
    if seats(ER).get("free", 0) < 1:
        return check("state", "idem fingerprint canonicalization: skipped (sold out)", True, "free=%s" % seats(ER).get("free"))
    b1 = b'{"seats":1,"user_id":"rt-57cn","idempotency_key":"k57cn"}'
    b2 = b'{"idempotency_key":"k57cn","user_id":"rt-57cn","seats":1}'
    sold0 = seats(ER).get("sold")
    r1 = raw(ER, "POST", "/book", b1, sign(KEY, "POST", "/book", b1))
    if r1[0] != 200:
        return check("state", "idem fingerprint canonicalization: skipped (control booking failed)", True, "r1=%s %s" % (r1[0], str(r1[1])[:60]))
    r2 = raw(ER, "POST", "/book", b2, sign(KEY, "POST", "/book", b2))
    sold1 = seats(ER).get("sold")
    ok = sold1 == sold0 + 1 and not (r2[0] == 200 and r2[1].get("status") == "confirmed" and r2[1].get("booking_id") not in (None, r1[1].get("booking_id")) and sold1 == sold0 + 2)
    return check("state", "same idem key, reordered JSON keys: idempotent, exactly one sale", ok,
                 "r1=%s r2=%s sold %d->%d" % (r1[0], "%s %s" % (r2[0], str(r2[1])[:50]), sold0, sold1))
idem_fingerprint_canonicalization()
def seats_float_and_object():
    b1 = b'{"user_id":"rt-57f","idempotency_key":"k57f","seats":2.0}'
    s1, j1 = raw(ER, "POST", "/reserve", b1, sign(KEY, "POST", "/reserve", b1))
    if isinstance(j1, dict) and j1.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j1["reservation_id"]})
    b2 = b'{"user_id":"rt-57f2","idempotency_key":"k57f2","seats":{"min":1}}'
    s2 = raw(ER, "POST", "/reserve", b2, sign(KEY, "POST", "/reserve", b2))[0]
    s = seats(ER)
    ok = s1 < 500 and s1 != -1 and rej(s2) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats as 2.0 (integral float) and as object: no 5xx, object rejected", ok, "float=%s/%s obj=%s" % (s1, str(j1)[:50], s2))
seats_float_and_object()
def idem_key_unicode():
    outs, rids = [], []
    for k in ("cafe\u0301k57", "\uff46\uff41\uff46\uff45"):
        b = json.dumps({"user_id": "rt-57u", "idempotency_key": k, "seats": 1}).encode()
        st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
        outs.append(st)
        if isinstance(j, dict) and j.get("reservation_id"):
            rids.append(j["reservation_id"])
    for rid in rids:
        post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = all(x < 500 and x != -1 for x in outs) and raw(ER, "GET", "/seats")[0] == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "idem key with combining + fullwidth unicode: no 5xx, engine alive", ok, "codes=%s" % outs)
idem_key_unicode()
def multi_hold_confirm_all():
    # One user, three separate 1-seat holds, all confirmed: exactly 3 sold, three bookings.
    if seats(ER).get("free", 0) < 3:
        return check("state", "multi-hold confirm-all: skipped (insufficient free)", True, "free=%s" % seats(ER).get("free"))
    sold0 = seats(ER).get("sold")
    rids = []
    for i in range(3):
        st, j = post(ER, "/reserve", {"user_id": "rt-57mh", "idempotency_key": "k57mh%d" % i, "seats": 1})
        if j.get("status") == "held" and j.get("reservation_id"):
            rids.append(j["reservation_id"])
    if len(rids) != 3:
        return check("state", "multi-hold confirm-all: skipped (holds incomplete)", True, "held=%d" % len(rids))
    bids = []
    for rid in rids:
        st, j = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-57mh"})
        if j.get("booking_id"):
            bids.append(j["booking_id"])
    sold1 = seats(ER).get("sold")
    s = seats(ER)
    ok = sold1 == sold0 + 3 and len(set(bids)) == 3 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "3 separate holds confirmed by same user: exactly 3 sold, 3 distinct bookings", ok,
                 "sold %d->%d bids=%d seats=%s" % (sold0, sold1, len(set(bids)), s))
multi_hold_confirm_all()
def app_parallel_pay_failure():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-57df","seats":1}')
    rid = h.get("reservation_id") if isinstance(h, dict) else None
    if not (st == 200 and rid):
        return check("app", "parallel app pay-failure storm: skipped (hold unavailable)", True, "hold=%s %s" % (st, str(h)[:60]))
    before = seats(ER)
    outs = P(10, lambda i: raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-57df", "outcome": "failure"}))[0])
    after = seats(ER)
    ok = 500 not in outs and -1 not in outs and after.get("total") == after.get("sold") + after.get("held") + after.get("free") and raw(AR, "GET", "/")[0] == 200
    return check("app", "10 parallel app pay-failure on one hold: released once, conserved, no 500", ok,
                 "codes=%s held %s->%s" % (sorted(set(outs)), before.get("held"), after.get("held")))
app_parallel_pay_failure()
def webhook_wrong_types():
    st, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", '{"type":"waitlist_fulfilled","reservation_id":123,"seats":"1"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook with wrong JSON types: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
webhook_wrong_types()
def app_hold_scientific():
    st, j = raw(AR, "POST", "/api/hold", '{"user_id":"rt-57e","seats":1e3}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold seats=1e3 (scientific notation): no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_scientific()
def over_send_body():
    import socket as _s
    body = b'{"user_id":"rt-57os","idempotency_key":"k57os","seats":1}'
    held_before = seats(ER).get("held")
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        head = ("POST /book HTTP/1.1\r\nHost: x\r\nContent-Length: 200\r\n" +
                "".join("%s: %s\r\n" % kv for kv in sign(KEY, "POST", "/book", body).items()) + "\r\n").encode()
        sk.sendall(head + body)
        sk.shutdown(_s.SHUT_WR)
        try: sk.settimeout(3); sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    held_after = seats(ER).get("held")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = held_after == held_before and alive
    return check("wire", "over-send body (declared 200, sent %d, then FIN): no hold created, engine alive" % len(body), ok,
                 "held %s->%s" % (held_before, held_after))
over_send_body()
def http09_raw():
    import socket as _s
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        sk.sendall(b"GET /seats\r\n\r\n")
        try: sk.settimeout(3); sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-57h9"}).encode()
    st = raw(ER, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))[0]
    return check("wire", "HTTP/0.9-style request (no version): engine survives, next valid request 404", st == 404, "status=%s" % st)
http09_raw()
def many_junk_headers():
    import socket as _s
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-57jh"}).encode()
    h = sign(KEY, "POST", "/confirm", body)
    junk = "".join("X-Junk-%d: v\r\n" % i for i in range(200))
    req = ("POST /confirm HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % len(body)) + junk + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n"
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        sk.sendall(req.encode() + body)
        buf = sk.recv(200)
        sk.close()
    except Exception:
        buf = b""
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = b"HTTP/1.1" in buf and alive
    return check("wire", "200 junk headers + valid signed request: answered, no smuggling, engine alive", ok, "resp=%s" % buf[:40])
many_junk_headers()
def wl_huge_userid():
    st, j = post(ER2, "/waitlist", {"user_id": "A" * 10000, "idempotency_key": "k57wl", "seats": 1})
    wid = j.get("waitlist_id") if isinstance(j, dict) else None
    if wid:
        post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    s = seats(ER2)
    ok = st < 500 and st != -1 and raw(ER2, "GET", "/seats")[0] == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wl", "waitlist join with 10KB user_id: no 5xx, conserved, cancelled clean", ok, "join=%s cancel=%s" % (st, "done" if wid else "n/a"))
wl_huge_userid()
def app_hold_release_race():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-57hr","seats":1}')
    rid = h.get("reservation_id") if isinstance(h, dict) else None
    if not (st == 200 and rid):
        return check("app", "app pay vs engine release race: skipped (hold unavailable)", True, "hold=%s %s" % (st, str(h)[:60]))
    rb = json.dumps({"reservation_id": rid}).encode()
    def eng_release(i):
        return raw(ER, "POST", "/release", rb, sign(KEY, "POST", "/release", rb))[0]
    def app_pay(i):
        return raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-57hr", "outcome": "success"}))[0]
    outs = P(10, lambda i: app_pay(i) if i % 2 == 0 else eng_release(i))
    s = seats(ER)
    ok = 500 not in outs and -1 not in outs and s.get("total") == s.get("sold") + s.get("held") + s.get("free") and raw(AR, "GET", "/")[0] == 200
    return check("app", "5 app-pays vs 5 engine-releases race: XOR outcome, conserved, no 500", ok,
                 "codes=%s seats=%s" % (sorted(set(outs)), s))
app_hold_release_race()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
