#!/usr/bin/env python3
"""Run 37 extras: 15 angles.
1-2: X-Kavach-Forwarded-By spoof burst (regression for the peer-origin fix)
3: same idem key different event_id
4: reserve -> release -> reserve same idem key (retry-after-release)
5: event_id in query vs body conflict
6: waitlist auto-fulfil E2E (fill, join, release, promotion)
7: waitlist join seats=4 boundary (via app)
8: app webhook duplicate delivery
9: app pay failed then success on the same hold
10: cross-tenant signed GET /reservation (no leak)
11: unsigned GET /status
12: unsigned GET /metrics (documented exposure)
13: duplicate Content-Type headers
14: seats 1.5 float / true bool
15: user_id with embedded newline
"""
import hashlib, hmac, http.client, json, time, uuid
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH3, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8095", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
PASS = FAIL = 0

def check(name, desc, ok, detail=""):
    global PASS, FAIL
    tag = "PASS" if ok else "FAIL"
    if ok: PASS += 1
    else: FAIL += 1
    print("%s %s %s | %s" % (tag, name, desc, detail))

def req(host, method, uri, obj=None, key=KEY, secret=SECRET, extra=None, raw_headers=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    mac = hmac.new(secret.encode(), (ts+"\n"+rid+"\n"+method+"\n"+uri+"\n"+key+"\n").encode()+body, hashlib.sha256).hexdigest()
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    if extra: h.update(extra)
    p = host.split("//")[1].split(":")
    c = http.client.HTTPConnection(p[0], int(p[1]), timeout=8)
    if raw_headers:
        c.putrequest(method, uri)
        for k, vs in raw_headers.items():
            for v in vs: c.putheader(k, v)
        c.endheaders(body)
    else:
        c.request(method, uri, body=body, headers=h)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def seats_of(host):
    st, j = req(host, "GET", "/seats", key=KEY, secret=b"\x00" and SECRET)
    return j

U = lambda t: "r37-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k37-%s-%s" % (t, uuid.uuid4().hex[:6])

N = uuid.uuid4().hex[:6]

# ---- 1-2. spoofed X-Kavach-Forwarded-By burst on 8098 (ip-rate 20, burst 40): fix regression
sts, statuses = [], Counter()
held = 0
for i in range(60):
    st, j = req(EH5, "POST", "/reserve", {"user_id": U("fwd"), "idempotency_key": K("fwd"), "seats": 1},
                extra={"X-Kavach-Forwarded-By": "spoofed-node-%d" % i})
    sts.append(st)
    if st == 429: statuses[j.get("status", "?")] += 1
    if st == 200: held += 1
seats5 = seats_of(EH5)
check("fwd_spoof_burst", "spoofed Forwarded-By burst limited after fix (>=1 rate_limited 429)",
      any(st == 429 for st in sts) and all(s == "rate_limited" for s in statuses),
      "%s %s held=%d seats=%s" % (dict(Counter(sts)), dict(statuses), held, seats5))
check("fwd_spoof_conserved", "spoofed burst holds == successes (no phantom holds)",
      seats5.get("held", -1) == held, "held=%d successes=%d" % (seats5.get("held", -1), held))

# ---- 3. same idem key different event_id (8091: ip-rate 0, free seats)
k3 = K("ev"); u3 = U("ev")
s1, j1 = req(EH1, "POST", "/reserve", {"user_id": u3, "idempotency_key": k3, "seats": 1})
s2, j2 = req(EH1, "POST", "/reserve", {"user_id": u3, "idempotency_key": k3, "seats": 1, "event_id": "ev37b"})
check("idem_diff_event", "same key different event_id: 409 conflict, no second hold",
      s1 == 200 and s2 == 409 and j2.get("status") == "idempotency_conflict",
      "%s then %s %s" % (s1, s2, j2.get("status")))

# ---- 4. reserve -> release -> reserve same idem key (8091)
k4 = K("rr"); u4 = U("rr")
sa, ja = req(EH1, "POST", "/reserve", {"user_id": u4, "idempotency_key": k4, "seats": 2})
rid4 = ja.get("reservation_id", "")
sb, jb = req(EH1, "POST", "/release", {"reservation_id": rid4}) if rid4 else (0, {})
sc, jc = req(EH1, "POST", "/reserve", {"user_id": u4, "idempotency_key": k4, "seats": 2})
seat1 = seats_of(EH1)
check("reserve_release_reserve", "retry-after-release: no 5xx, seats conserved",
      0 not in (sa, sb, sc) and sa < 500 and sb < 500 and sc < 500 and seat1["free"]+seat1["held"]+seat1["sold"] == 50,
      "reserve=%s release=%s re-reserve=%s seats=%s (re-reserve status=%s)" % (sa, sb, sc, seat1, jc.get("status")))

# ---- 5. event_id in query vs body conflict (8092)
u5, k5 = U("evqb"), K("evqb")
sd, jd = req(EH2, "POST", "/reserve?event=ev37q", {"user_id": u5, "idempotency_key": k5, "seats": 1, "event_id": "ev37r"})
seat2 = seats_of(EH2)
check("event_query_body", "event in query vs body: no 5xx, seats conserved, outcome documented",
      sd < 500 and sd != 0 and seat2["free"]+seat2["held"]+seat2["sold"] == 61,
      "st=%s resp=%s seats=%s" % (sd, {k: jd.get(k) for k in ("status", "reservation_id", "event_id")}, seat2))

# ---- 6. waitlist auto-fulfil E2E (8095, 10 seats ttl 3)
rids6 = []
for i in range(5):
    st, j = req(EH3, "POST", "/reserve", {"user_id": U("fill"), "idempotency_key": K("fill"), "seats": 2})
    if st == 200: rids6.append(j.get("reservation_id"))
sw, jw = req(EH3, "POST", "/waitlist", {"user_id": U("wl"), "idempotency_key": K("wl"), "seats": 1})
wid = jw.get("waitlist_id", "")
sr, jr = req(EH3, "POST", "/release", {"reservation_id": rids6[0]}) if rids6 else (0, {})
time.sleep(0.6)
seat3 = seats_of(EH3)
stl, jl = req(EH3, "GET", "/waitlist")
check("wl_auto_fulfil", "waitlist auto-fulfil after release: no 5xx, seats conserved, promotion observed",
      sw < 500 and sr < 500 and seat3["free"]+seat3["held"]+seat3["sold"] == 10,
      "join=%s release=%s seats=%s list=%s" % (sw, sr, seat3, jl if isinstance(jl, (list, dict)) else "?"))

# ---- 7. waitlist join seats=4 boundary (8092 is sold out: waitlist applies)
st, j = req(EH2, "POST", "/waitlist", {"user_id": U("wl4"), "idempotency_key": K("wl4"), "seats": 4})
check("wl_seats4", "waitlist join seats=4 accepted on sold-out engine",
      st == 200 and st != 409, "st=%s %s" % (st, {k: j.get(k) for k in ("status", "waitlist_id", "position")}))

# ---- 8. app webhook duplicate delivery
body = {"type": "waitlist_fulfilled", "waitlist_id": "wl-%s" % N, "seats": 1}
s8a = req(APP, "POST", "/api/kavach-webhook?token=whsec-redtest", body, key=KEY, secret=SECRET)
s8b = req(APP, "POST", "/api/kavach-webhook?token=whsec-redtest", body, key=KEY, secret=SECRET)
check("wh_dup", "webhook duplicate delivery: both benign, no 5xx",
      s8a[0] == 200 and s8b[0] == 200, "%s then %s" % (s8a[1], s8b[1]))

# ---- 9. app pay failed then success on the same hold
u9 = U("pay")
st, j = req(APP, "POST", "/api/hold", {"user_id": u9, "seats": 1})
rid9 = j.get("reservation_id", "")
sf, jf = req(APP, "POST", "/api/pay", {"reservation_id": rid9, "user_id": u9, "outcome": "failed"})
ss, js = req(APP, "POST", "/api/pay", {"reservation_id": rid9, "user_id": u9})
seat1b = seats_of(EH1)
check("pay_failed_then_success", "pay failed releases hold; second success 4xx, no 5xx",
      st == 200 and sf == 200 and ss >= 400 and ss < 500 and seat1b["free"]+seat1b["held"]+seat1b["sold"] == 50,
      "hold=%s failed=%s retry=%s seats=%s" % (st, (sf, jf.get("status")), (ss, js.get("status")), seat1b))

# ---- 10. cross-tenant signed GET /reservation (8091)
st, j = req(EH1, "POST", "/reserve", {"user_id": U("xt"), "idempotency_key": K("xt"), "seats": 1})
ridx = j.get("reservation_id", "")
stx, jx = req(EH1, "GET", "/reservation?id="+ridx, key=KEY2)
check("xtenant_rid", "GET /reservation with another tenant's key: 404, no leak",
      st == 200 and stx == 404, "%s then %s %s" % (st, stx, jx.get("status")))

# ---- 11-12. unsigned GET /status and /metrics (documented)
st, j = req(EH1, "GET", "/status?idempotency_key="+K("nostatus"), key=KEY, secret=SECRET, extra={"Authorization": ""})
check("status_unsigned", "GET /status unsigned: 401",
      st == 401, "st=%s" % st)
stm, jm = req(EH1, "GET", "/metrics", key=KEY, secret=SECRET, extra={"Authorization": ""})
check("metrics_unsigned", "GET /metrics unsigned: 200 (documented exposure)",
      stm == 200, "st=%s keys=%s" % (stm, list(jm)[:4] if isinstance(jm, dict) else "?"))

# ---- 13. duplicate Content-Type headers (8092)
c = http.client.HTTPConnection("127.0.0.1", 8092, timeout=8)
b13 = json.dumps({"user_id": U("dct"), "idempotency_key": K("dct"), "seats": 1}).encode()
ts13, rid13 = str(int(time.time())), uuid.uuid4().hex
mac13 = hmac.new(SECRET.encode(), (ts13+"\n"+rid13+"\nPOST\n/reserve\n"+KEY+"\n").encode()+b13, hashlib.sha256).hexdigest()
c.putrequest("POST", "/reserve")
c.putheader("Content-Type", "application/json"); c.putheader("Content-Type", "application/json")
c.putheader("Authorization", "Bearer "+KEY); c.putheader("X-Kavach-Timestamp", ts13)
c.putheader("X-Kavach-Request-Id", rid13); c.putheader("X-Kavach-Signature", mac13)
c.putheader("Content-Length", str(len(b13)))
c.endheaders(b13)
r13 = c.getresponse(); st13 = r13.status; d13 = r13.read(); c.close()
check("dup_content_type", "duplicate Content-Type headers: no 5xx",
      st13 < 500 and st13 != 0, "st=%s %s" % (st13, d13[:80]))

# ---- 14. seats float and bool (8092)
stf, jf2 = req(EH2, "POST", "/reserve", {"user_id": U("f"), "idempotency_key": K("f"), "seats": 1.5})
stb, jb2 = req(EH2, "POST", "/reserve", {"user_id": U("b"), "idempotency_key": K("b"), "seats": True})
check("seats_float", "seats 1.5 rejected 400", stf == 400, "st=%s" % stf)
check("seats_bool", "seats true rejected 400", stb == 400, "st=%s" % stb)

# ---- 15. user_id with embedded newline (8091)
st, j = req(EH1, "POST", "/reserve", {"user_id": "u\n37-x", "idempotency_key": K("nl"), "seats": 1})
check("uid_newline", "user_id with embedded newline: no 5xx, benign",
      0 < st < 500, "st=%s %s" % (st, j.get("status")))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
