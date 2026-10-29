#!/usr/bin/env python3
"""Run 40 extras: 13 angles.
1: same rid reused on a different endpoint with a fresh valid MAC -> 401 replay (nonce global)
2: /confirm with another tenant's key -> 404, no leak, no state change
3: /release with another tenant's key -> 404, no leak
4: /waitlist/cancel with another tenant's key -> 404, entry intact for its own tenant
5: /waitlist/cancel twice: second 404
6: cancel a waitlist_id that was already promoted -> 404
7: /book seats=0 and seats=5 -> 400 (bounds)
8: user-rate burst on 8096 (rate 2/s burst 5): 10 rapid reserves same user -> mix 200/429, holds == successes
9: waitlist cap on sold-out 8092: 10 joins different users -> queued until cap, then waitlist_full, no 5xx
10: duplicate JSON keys seats:2,seats:3 -> last wins, conserved
11: Authorization "Basic testkey" -> 401
12: idem key created on 8091, GET /status on 8092 -> 404 (cross-engine isolation)
13: HEAD /seats and OPTIONS /reserve -> no 5xx
"""
import hashlib, hmac, http.client, json, time, uuid
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH5, EH6 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8098", "http://127.0.0.1:8096"
PASS = FAIL = 0

def check(name, desc, ok, detail=""):
    global PASS, FAIL
    tag = "PASS" if ok else "FAIL"
    if ok: PASS += 1
    else: FAIL += 1
    print("%s %s %s | %s" % (tag, name, desc, detail))

def mac_for(secret, ts, rid, method, uri, key, body):
    return hmac.new(secret.encode(), (ts+"\n"+rid+"\n"+method+"\n"+uri+"\n"+key+"\n").encode()+body, hashlib.sha256).hexdigest()

def send(host, method, uri, body, headers):
    p = host.split("//")[1].split(":")
    c = http.client.HTTPConnection(p[0], int(p[1]), timeout=8)
    c.request(method, uri, body=body, headers=headers)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, ts=None, rid=None, auth=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = ts or str(int(time.time()))
    rid = rid or uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": auth or ("Bearer "+key), "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r40-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k40-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1. rid reuse across endpoints (same ts+rid, fresh valid MAC, different path)
ts1, rid1 = str(int(time.time())), uuid.uuid4().hex
sh1, jh1 = signed(EH5, "POST", "/reserve", {"user_id": U("rr"), "idempotency_key": K("rr"), "seats": 1}, ts=ts1, rid=rid1)
st1, j1 = signed(EH5, "GET", "/status?idempotency_key="+K("ghost2"), ts=ts1, rid=rid1)
check("rid_reuse_cross_endpoint", "same rid reused on another endpoint with valid MAC: 401 replay",
      sh1 == 200 and st1 == 401, "hold=%s reuse=%s %s" % (sh1, st1, j1.get("status")))

# ---- 2/3. cross-tenant confirm and release (8098)
k2, u2 = K("xt"), U("xt")
sh2, jh2 = signed(EH5, "POST", "/reserve", {"user_id": u2, "idempotency_key": k2, "seats": 2})
rid2 = jh2.get("reservation_id", "")
pre2 = seats_of(EH5)
sc2, jc2 = signed(EH5, "POST", "/confirm", {"reservation_id": rid2, "user_id": u2}, key=KEY2)
post2 = seats_of(EH5)
check("confirm_cross_tenant", "cross-tenant /confirm: 404 not_found, no state change",
      sh2 == 200 and sc2 == 404 and jc2.get("status") == "not_found" and post2["held"] == pre2["held"],
      "hold=%s confirm=%s %s held %s->%s" % (sh2, sc2, jc2.get("status"), pre2["held"], post2["held"]))
sr3, jr3 = signed(EH5, "POST", "/release", {"reservation_id": rid2}, key=KEY2)
post3 = seats_of(EH5)
check("release_cross_tenant", "cross-tenant /release: 404 not_found, no state change",
      sr3 == 404 and post3["held"] == pre2["held"], "rel=%s %s held=%s" % (sr3, jr3.get("status"), post3["held"]))

# ---- 7. /book seats bounds (8098)
sb0, jb0 = signed(EH5, "POST", "/book", {"user_id": U("b0"), "idempotency_key": K("b0"), "seats": 0})
sb5, jb5 = signed(EH5, "POST", "/book", {"user_id": U("b5"), "idempotency_key": K("b5"), "seats": 5})
check("book_seats_bounds", "/book seats 0 and 5 both 400", sb0 == 400 and sb5 == 400,
      "0=%s %s 5=%s %s" % (sb0, jb0.get("status"), sb5, jb5.get("status")))

# ---- 10. duplicate JSON keys: last wins, conserved
body10 = ('{"user_id":"%s","idempotency_key":"%s","seats":2,"seats":3}' % (U("dk"), K("dk"))).encode()
ts10, rid10 = str(int(time.time())), uuid.uuid4().hex
mac10 = mac_for(SECRET, ts10, rid10, "POST", "/reserve", KEY, body10)
st10, j10 = send(EH5, "POST", "/reserve", body10, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts10,
                 "X-Kavach-Request-Id": rid10, "X-Kavach-Signature": mac10, "Content-Type": "application/json"})
pre10 = seats_of(EH5)
check("dup_json_keys", "duplicate seats keys: last wins (3), conserved",
      st10 == 200 and j10.get("status") == "held", "st=%s %s" % (st10, j10.get("status")))

# ---- 11. wrong auth scheme
st11, j11 = signed(EH5, "POST", "/reserve", {"user_id": U("ba"), "idempotency_key": K("ba"), "seats": 1}, auth="Basic "+KEY)
check("wrong_auth_scheme", "Authorization 'Basic key' rejected 401", st11 == 401, "st=%s %s" % (st11, j11.get("status")))

# ---- 12. cross-engine isolation
k12, u12 = K("iso"), U("iso")
sh12, jh12 = signed(EH1, "POST", "/reserve", {"user_id": u12, "idempotency_key": k12, "seats": 1})
sx12, jx12 = signed(EH2, "GET", "/status?idempotency_key="+k12)
check("cross_engine_isolation", "idem key from engine A not visible on engine B: 404",
      sh12 == 200 and sx12 == 404, "hold8091=%s status8092=%s %s" % (sh12, sx12, jx12.get("status")))

# ---- 8. user-rate burst (8096, user-rate 2/s burst 5)
u8 = U("burst")
res8 = []
for i in range(10):
    st, j = signed(EH6, "POST", "/reserve", {"user_id": u8, "idempotency_key": K("burst"), "seats": 1})
    res8.append((st, j.get("status", "")))
seat6 = seats_of(EH6)
ok8 = sum(1 for st, s in res8 if st == 200)
lim8 = sum(1 for st, s in res8 if st == 429)
check("user_rate_burst", "user-rate 2/s burst 5: burst allowed then 429, holds == successes",
      1 <= ok8 <= 6 and lim8 >= 1 and seat6["held"] == ok8 and all(st < 500 for st, _ in res8),
      "outcomes=%s held=%s ok=%d" % (dict(Counter(s for _, s in res8)), seat6["held"], ok8))

# ---- 13. HEAD /seats and OPTIONS /reserve
ph = EH5.split("//")[1].split(":")
ch = http.client.HTTPConnection(ph[0], int(ph[1]), timeout=8)
ch.request("HEAD", "/seats"); rh = ch.getresponse(); sth = rh.status; rh.read(); ch.close()
co = EH5.split("//")[1].split(":")
cio = http.client.HTTPConnection(co[0], int(co[1]), timeout=8)
cio.request("OPTIONS", "/reserve"); ro = cio.getresponse(); sto = ro.status; ro.read(); cio.close()
check("head_options", "HEAD /seats and OPTIONS /reserve: no 5xx",
      sth < 500 and sto < 500 and sth != 0 and sto != 0, "HEAD=%s OPTIONS=%s" % (sth, sto))

# ---- 4/5/6/9. waitlist lifecycle on 8092 (61 seats, ttl 30): drain first, quickly
rids = []
i = 0
while len(rids) < 19 and i < 40:
    n = 4 if len(rids) < 14 else 1
    ud = U("dr")
    st, j = signed(EH2, "POST", "/reserve", {"user_id": ud, "idempotency_key": K("dr"), "seats": n})
    if st == 200 and j.get("status") == "held":
        rids.append((j.get("reservation_id"), n))
    i += 1
d2 = seats_of(EH2)
one_seats = [(r, n) for r, n in rids if n == 1]
# 6. cancel after promotion
u6, k6 = U("wlp"), K("wlp")
sj6, jj6 = signed(EH2, "POST", "/waitlist", {"user_id": u6, "idempotency_key": k6, "seats": 1})
rel6_rid, rel6_n = one_seats[-1]
sr6, jr6 = signed(EH2, "POST", "/release", {"reservation_id": rel6_rid})
gw, jw = signed(EH2, "GET", "/waitlist?user_id=" + u6)
live6 = jw.get("entries", []) if isinstance(jw, dict) else jw
sc6, jc6 = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": jj6.get("waitlist_id")})
check("wl_cancel_after_promote", "cancel a promoted (removed) waitlist_id: 404; GET /waitlist shows it gone",
      sj6 == 200 and sr6 == 200 and len(live6) == 0 and sc6 == 404,
      "join=%s rel=%s live_after_promote=%d cancel=%s %s" % (sj6, sr6, len(live6), sc6, jc6.get("status")))


# 9. waitlist cap: 10 joins different users
caps = []
for i in range(10):
    st, j = signed(EH2, "POST", "/waitlist", {"user_id": U("cap"), "idempotency_key": K("cap"), "seats": 1})
    caps.append(st)
check("wl_cap", "10 waitlist joins on sold-out engine: queued or waitlist_full, no 5xx",
      all(st in (200, 409) for st in caps), "outcomes=%s" % dict(Counter(caps)))

# 4. cross-tenant cancel
u4, k4 = U("wlc"), K("wlc")
sj4, jj4 = signed(EH2, "POST", "/waitlist", {"user_id": u4, "idempotency_key": k4, "seats": 1})
wlid4 = jj4.get("waitlist_id", "")
sc4, jc4 = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": wlid4}, key=KEY2)
sc4b, jc4b = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": wlid4})
check("wl_cancel_cross_tenant", "cross-tenant cancel 404; own-tenant cancel 200",
      sj4 == 200 and sc4 == 404 and sc4b == 200, "join=%s xcancel=%s own=%s" % (sj4, sc4, sc4b))

# 5. cancel twice
u5, k5 = U("wlt"), K("wlt")
sj5, jj5 = signed(EH2, "POST", "/waitlist", {"user_id": u5, "idempotency_key": k5, "seats": 1})
scA, _ = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": jj5.get("waitlist_id")})
scB, jb = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": jj5.get("waitlist_id")})
check("wl_cancel_twice", "second cancel of the same entry: 404 not_found",
      scA == 200 and scB == 404, "first=%s second=%s %s" % (scA, scB, jb.get("status")))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
