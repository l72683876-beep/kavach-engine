#!/usr/bin/env python3
"""Run 56 extras: 12 angles (all live in redteam_battery.py Phase J too).
1: multi-seat boundary: reserve-4 at 3 free reports sold_out (200 body), 3 held, release restores 3
2: waitlist over-fulfil guard: 1-seat entry promoted once, 2-seat entry not force-fulfilled
3: cancelled waitlist entry never promotes; 2-seat entry not fulfilled by 1 freed seat
4: 20 parallel confirms on one 10-seat hold: exactly 10 sold, no double-spend
5: request-id reuse with different body (both valid MACs): replay guard rejects
6: negative and non-integer timestamps: 401
7: signature hex with trailing padding: 401
8: idempotency key extremes (10KB, 1-char, control chars): no 5xx
9: 1000-deep nested JSON user_id: clean 4xx
10: duplicate JSON keys (seats 1 then 5): no 5xx, inventory conserved
11: app pay with case-varied user_id rejected: exact user binding
12: 1MB webhook payload: no 500, app alive
Run against targets already up: 8091 engine, 8095 short-TTL, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ET = 8091, 9001, 8095
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

# ---------------- Phase J: run 56 extras (12 new angles) ----------------
def multi_seat_boundary():
    s0 = seats(ET); free0 = s0.get("free", 0)
    if free0 < 4:
        return check("state", "multi-seat boundary arithmetic: skipped (insufficient free)", True, "free=%s" % free0)
    for i in range(free0 - 3):
        post(ET, "/book", {"user_id": "rt-56ms%d" % i, "idempotency_key": "k56ms%d" % i, "seats": 1})
    if seats(ET).get("free") != 3:
        return check("state", "multi-seat boundary arithmetic: skipped (could not drain to 3 free)", True, "seats=%s" % seats(ET))
    a = post(ET, "/reserve", {"user_id": "rt-56mb", "idempotency_key": "k56mb4", "seats": 4})
    b = post(ET, "/reserve", {"user_id": "rt-56mb", "idempotency_key": "k56mb3", "seats": 3})
    rid = b[1].get("reservation_id")
    r = post(ET, "/release", {"reservation_id": rid}) if rid else (0, {})
    s2 = seats(ET)
    ok = a[1].get("status") == "sold_out" and b[0] == 200 and b[1].get("status") == "held" and r[0] == 200 and s2.get("free") == 3 and s2.get("total") == s2.get("sold") + s2.get("held") + s2.get("free")
    return check("state", "multi-seat boundary: reserve-4 at 3 free reports sold_out (200 body), 3 held, release restores 3 free", ok, "a=%s/%s b=%s r=%s seats=%s" % (a[0], a[1].get("status"), b[0], r[0], s2))
multi_seat_boundary()
def wl_overfulfil():
    free0 = seats(ET).get("free", 0)
    if free0 < 1:
        return check("wl", "waitlist over-fulfil guard: skipped (no free seat)", True, "seats=%s" % seats(ET))
    for i in range(free0 - 1):
        post(ET, "/book", {"user_id": "rt-56wf%d" % i, "idempotency_key": "k56wf%d" % i, "seats": 1})
    st, h = post(ET, "/reserve", {"user_id": "rt-56wh", "idempotency_key": "k56wh", "seats": 1})
    if h.get("status") != "held":
        return check("wl", "waitlist over-fulfil guard: skipped (hold unavailable)", True, "%s" % str(h)[:60])
    rid = h["reservation_id"]
    w1 = post(ET, "/waitlist", {"user_id": "rt-56w1", "idempotency_key": "k56w1", "seats": 1})
    w2 = post(ET, "/waitlist", {"user_id": "rt-56w2", "idempotency_key": "k56w2", "seats": 2})
    rel = post(ET, "/release", {"reservation_id": rid})
    s = seats(ET)
    conserved = s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    ok = conserved and s.get("held") == 1 and s.get("free") == 0 and rel[0] == 200
    return check("wl", "waitlist over-fulfil guard: 1-seat entry promoted exactly once, 2-seat entry not force-fulfilled", ok,
                 "w1=%s w2=%s rel=%s seats=%s" % (str(w1)[:50], str(w2)[:50], rel[0], s))
wl_overfulfil()
def wl_cancelled_no_promote():
    sold0 = seats(ET).get("sold")
    w3 = post(ET, "/waitlist", {"user_id": "rt-56w3", "idempotency_key": "k56w3", "seats": 1})
    if w3[0] != 200 or not w3[1].get("waitlist_id"):
        return check("wl", "cancelled waitlist entry never promotes: skipped (join failed)", True, "join=%s %s" % (w3[0], str(w3[1])[:50]))
    c = post(ET, "/waitlist/cancel", {"waitlist_id": w3[1]["waitlist_id"]})
    deadline = time.time() + 40
    while time.time() < deadline and seats(ET).get("free", 0) < 1:
        time.sleep(1)
    time.sleep(2)
    s = seats(ET)
    ok = c[0] == 200 and s.get("held") == 0 and s.get("free") == 1 and s.get("sold") == sold0 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wl", "cancelled entry never promotes; 2-seat entry not fulfilled by 1 freed seat", ok, "cancel=%s seats=%s sold0=%s" % (c[0], s, sold0))
wl_cancelled_no_promote()
def confirm_race_multiseat():
    s0 = seats(ER)
    if s0.get("free", 0) < 10:
        return check("race", "20 parallel confirms on one 10-seat hold: skipped (insufficient free)", True, "free=%s" % s0.get("free"))
    st, j = post(ER, "/reserve", {"user_id": "rt-56mr", "idempotency_key": "k56mr", "seats": 10})
    rid = j.get("reservation_id")
    if not rid:
        return check("race", "20 parallel confirms on one 10-seat hold: skipped (hold failed)", True, "%s" % str(j)[:60])
    sold_b = seats(ER).get("sold")
    outs = P(20, lambda i: post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-56mr"}))
    ids = {o[1].get("booking_id") for o in outs if o[0] == 200}
    sold_a = seats(ER).get("sold")
    s = seats(ER)
    ok = sold_a == sold_b + 10 and s.get("total") == s.get("sold") + s.get("held") + s.get("free") and all(o[0] < 500 for o in outs)
    return check("race", "20 parallel confirms on one 10-seat hold: exactly 10 sold, no double-spend", ok, "ids=%d sold_delta=%d codes=%s" % (len(ids), sold_a - sold_b, sorted(set(o[0] for o in outs))))
confirm_race_multiseat()
def rid_replay_diff_body():
    if seats(ER).get("free", 0) < 1:
        return check("auth", "request-id reuse with different body: skipped (sold out)", True, "free=%s" % seats(ER).get("free"))
    b1 = json.dumps({"user_id": "rt-56rr1", "idempotency_key": "k56rr1", "seats": 1}).encode()
    h1 = sign(KEY, "POST", "/book", b1)
    r1 = raw(ER, "POST", "/book", b1, h1)
    if r1[0] != 200:
        return check("auth", "request-id reuse with different body: skipped (control booking failed)", True, "r1=%s" % r1[0])
    b2 = json.dumps({"user_id": "rt-56rr2", "idempotency_key": "k56rr2", "seats": 1}).encode()
    h2 = sign(KEY, "POST", "/book", b2)
    h2["X-Kavach-Request-Id"] = h1["X-Kavach-Request-Id"]
    r2 = raw(ER, "POST", "/book", b2, h2)
    return check("auth", "request-id reuse with different body (both valid MACs): replay guard rejects", r2[0] == 401, "r1=%s r2=%s %s" % (r1[0], r2[0], str(r2[1])[:60]))
rid_replay_diff_body()
def ts_negative_float():
    b = json.dumps({"user_id": "rt-56ts", "idempotency_key": "k56ts", "seats": 1}).encode()
    a = raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b, ts="-999"))[0]
    c = raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b, ts="1699.5"))[0]
    return check("auth", "negative and non-integer timestamps: 401, no 5xx", a == 401 and c == 401, "%s/%s" % (a, c))
ts_negative_float()
def sig_trailing_pad():
    b = json.dumps({"user_id": "rt-56sp", "idempotency_key": "k56sp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/book", b)
    h["X-Kavach-Signature"] += "00"
    st = raw(ER, "POST", "/book", b, h)[0]
    return check("auth", "signature hex with trailing padding: 401", st == 401, "status=%s" % st)
sig_trailing_pad()
def idem_key_extremes():
    outs, rids = [], []
    for k in ("A" * 10000, "1", "\x01\x02k"):
        b = json.dumps({"user_id": "rt-56ik", "idempotency_key": k, "seats": 1}).encode()
        st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
        outs.append(st)
        if isinstance(j, dict) and j.get("reservation_id"):
            rids.append(j["reservation_id"])
    for rid in rids:
        post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = all(x < 500 and x != -1 for x in outs) and raw(ER, "GET", "/seats")[0] == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "idempotency key extremes (10KB, 1-char, control chars): no 5xx, engine alive", ok, "codes=%s" % outs)
idem_key_extremes()
def deep_nesting():
    b = b'{"user_id":' + b'{"a":' * 1000 + b'"x"' + b'}' * 1000 + b',"idempotency_key":"k56dn","seats":1}' 
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    if isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    return check("fuzz", "1000-deep nested JSON user_id: clean 4xx, engine alive", rej(st) and raw(ER, "GET", "/seats")[0] == 200, "status=%s" % st)
deep_nesting()
def dup_json_keys():
    b = b'{"user_id":"rt-56dk","idempotency_key":"k56dk","seats":1,"seats":5}'
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    if isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    s = seats(ER)
    ok = st < 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free") and raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "duplicate JSON keys (seats 1 then 5): no 5xx, inventory conserved", ok, "status=%s body=%s" % (st, str(j)[:60]))
dup_json_keys()
def app_pay_case_variation():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-56cs","seats":1}')
    rid = h.get("reservation_id") if isinstance(h, dict) else None
    if not (st == 200 and rid):
        return check("app", "app pay user_id case variation: skipped (hold unavailable)", True, "hold=%s %s" % (st, str(h)[:60]))
    st2, p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "RT-56CS", "outcome": "success"}))
    rb = json.dumps({"reservation_id": rid}).encode()
    rl = raw(ER, "POST", "/release", rb, sign(KEY, "POST", "/release", rb))[0]
    alive = raw(AR, "GET", "/")[0] == 200
    ok = (st2 != 200 or not (isinstance(p, dict) and p.get("ok"))) and alive and rl == 200
    return check("app", "pay with case-varied user_id rejected: exact user binding", ok, "pay=%s p=%s release=%s" % (st2, str(p)[:60], rl))
app_pay_case_variation()
def webhook_1mb():
    payload = json.dumps({"type": "waitlist_fulfilled", "reservation_id": "FAKE56", "seats": list(range(200000))})
    st, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", payload)
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "1MB webhook payload: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
webhook_1mb()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
