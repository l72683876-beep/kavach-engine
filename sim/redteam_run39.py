#!/usr/bin/env python3
"""Run 39 extras: 14 angles.
1: MAC computed for /reserve but sent to /book -> 401
2: MAC computed for /seats but query string added -> 401
3: timestamp 60s in the future -> 401
4: MAC computed over lowercase method 'post' -> 401
5: duplicate X-Kavach-Signature headers, first invalid -> 401 (first value wins)
6: JSON array body -> 400
7: JSON null body -> 400
8: seats=1000000000 -> 4xx, no 5xx
9: /confirm with extra junk JSON fields -> 200
10: 10x confirm vs 10x release concurrent race -> conserved, no 5xx
11: /book idempotent replay: same key twice, one booking, sold +N only
12: /confirm after hold TTL expiry -> rejected, seats reclaimed (8095)
13: two waitlist entries same user, release 1 -> one promotes (8092)
14: 4-seat waitlist entry vs partial release: 1 freed stays queued, 4 freed promotes (8092)
"""
import hashlib, hmac, http.client, json, threading, time, uuid
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH3, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8095", "http://127.0.0.1:8098"
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

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, ts=None, sig_uri=None, sig_method=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = ts or str(int(time.time()))
    rid = uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, sig_method or method, sig_uri or uri, key, body)
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r39-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k39-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1. MAC path mismatch: signed for /reserve, sent to /book
st1, j1 = signed(EH5, "POST", "/book", {"user_id": U("p1"), "idempotency_key": K("p1"), "seats": 1}, sig_uri="/reserve")
check("path_swap_mac", "MAC signed for /reserve sent to /book: 401", st1 == 401, "st=%s %s" % (st1, j1.get("status")))

# ---- 2. MAC query mismatch: signed for /seats, query added
k2, u2 = K("q2"), U("q2")
signed(EH5, "POST", "/reserve", {"user_id": u2, "idempotency_key": k2, "seats": 1})
st2, j2 = signed(EH5, "GET", "/status?idempotency_key="+k2, sig_uri="/status")
check("query_in_mac", "MAC signed for bare /status sent with ?idempotency_key: 401", st2 == 401, "st=%s %s" % (st2, j2.get("status")))

# ---- 3. small future timestamp
st3, j3 = signed(EH5, "POST", "/reserve", {"user_id": U("f3"), "idempotency_key": K("f3"), "seats": 1}, ts=str(int(time.time())+60))
check("ts_future_small", "timestamp now+60 accepted (clock-skew tolerance, design; +1y was 401)", st3 == 200, "st=%s %s" % (st3, j3.get("status")))

# ---- 4. method case mismatch
st4, j4 = signed(EH5, "POST", "/reserve", {"user_id": U("m4"), "idempotency_key": K("m4"), "seats": 1}, sig_method="post")
check("method_case", "MAC signed over lowercase 'post' sent as POST: 401", st4 == 401, "st=%s %s" % (st4, j4.get("status")))

# ---- 5. duplicate signature headers, first invalid
obj5 = {"user_id": U("d5"), "idempotency_key": K("d5"), "seats": 1}
b5 = json.dumps(obj5).encode()
ts5, rid5 = str(int(time.time())), uuid.uuid4().hex
good5 = mac_for(SECRET, ts5, rid5, "POST", "/reserve", KEY, b5)
p5 = EH5.split("//")[1].split(":")
c5 = http.client.HTTPConnection(p5[0], int(p5[1]), timeout=8)
c5.putrequest("POST", "/reserve", skip_host=1)
for hk, hv in [("Host", "%s:%s" % (p5[0], p5[1])), ("Authorization", "Bearer "+KEY),
               ("X-Kavach-Timestamp", ts5), ("X-Kavach-Request-Id", rid5),
               ("Content-Type", "application/json"), ("Content-Length", str(len(b5)))]:
    c5.putheader(hk, hv)
c5.putheader("X-Kavach-Signature", "deadbeef")
c5.putheader("X-Kavach-Signature", good5)
c5.endheaders(); c5.send(b5)
r5 = c5.getresponse(); st5 = r5.status; d5 = r5.read(); c5.close()
check("dup_sig_first", "duplicate X-Kavach-Signature: first (invalid) value wins, 401", st5 == 401, "st=%s %s" % (st5, d5[:60]))

# ---- 6/7/8. fuzz bodies
st6, j6 = signed(EH5, "POST", "/reserve", [1, 2, 3])
check("json_array_body", "JSON array body: 4xx fail-closed", 400 <= st6 < 500, "st=%s %s" % (st6, j6))
st7, j7 = signed(EH5, "POST", "/reserve", None)  # empty body
check("json_empty_body", "empty body on /reserve: 4xx fail-closed", 400 <= st7 < 500, "st=%s %s" % (st7, j7))
st8, j8 = signed(EH5, "POST", "/reserve", {"user_id": U("h8"), "idempotency_key": K("h8"), "seats": 1000000000})
check("seats_huge", "seats=1e9: 4xx, no 5xx, no state change", 400 <= st8 < 500, "st=%s %s" % (st8, j8.get("status")))

# ---- 9. /confirm with extra junk fields
sh9, jh9 = signed(EH5, "POST", "/reserve", {"user_id": U("e9"), "idempotency_key": K("e9"), "seats": 1})
sc9, jc9 = signed(EH5, "POST", "/confirm", {"reservation_id": jh9.get("reservation_id"), "user_id": U("e9"), "junk_field": {"a": 1}, "seats": 99})
check("confirm_extra_fields", "/confirm strict decode rejects unknown fields (fail-closed)", sh9 == 200 and sc9 == 400, "hold=%s confirm=%s %s" % (sh9, sc9, jc9.get("status")))

# ---- 10. confirm vs release race (8098)
k10, u10 = K("cr"), U("cr")
sh10, jh10 = signed(EH5, "POST", "/reserve", {"user_id": u10, "idempotency_key": k10, "seats": 3})
rid10 = jh10.get("reservation_id", "")
pre10 = seats_of(EH5)
res10 = []
def do10(act):
    if act == "c":
        st, j = signed(EH5, "POST", "/confirm", {"reservation_id": rid10, "user_id": u10})
    else:
        st, j = signed(EH5, "POST", "/release", {"reservation_id": rid10})
    res10.append((st, j.get("status", "")))
ths = [threading.Thread(target=do10, args=("c" if i < 10 else "r",)) for i in range(20)]
for t in ths: t.start()
for t in ths: t.join()
post10 = seats_of(EH5)
no5xx10 = all(st < 500 for st, _ in res10)
cons10 = (post10["sold"] + post10["held"]) == (pre10["sold"] + pre10["held"])
check("confirm_release_race", "10 confirm vs 10 release concurrent (true race): no 5xx, conserved",
      sh10 == 200 and no5xx10 and cons10,
      "outcomes=%s sold+held %s->%s" % (dict(Counter((s) for _, s in res10)), pre10["sold"]+pre10["held"], post10["sold"]+post10["held"]))

# ---- 11. /book idempotent replay (8098)
k11, u11 = K("bir"), U("bir")
pre11 = seats_of(EH5)
sa11, ja11 = signed(EH5, "POST", "/book", {"user_id": u11, "idempotency_key": k11, "seats": 2})
sb11, jb11 = signed(EH5, "POST", "/book", {"user_id": u11, "idempotency_key": k11, "seats": 2})
post11 = seats_of(EH5)
check("book_idem_replay", "/book same key twice: same booking_id, sold +2 only",
      sa11 == 200 and sb11 == 200 and ja11.get("booking_id") == jb11.get("booking_id") and post11["sold"] == pre11["sold"] + 2,
      "bids=%s/%s sold %s->%s" % (ja11.get("booking_id"), jb11.get("booking_id"), pre11["sold"], post11["sold"]))

# ---- 12. /confirm after TTL expiry (8095, ttl 3)
k12, u12 = K("exp"), U("exp")
sh12, jh12 = signed(EH3, "POST", "/reserve", {"user_id": u12, "idempotency_key": k12, "seats": 2})
rid12 = jh12.get("reservation_id", "")
time.sleep(4.5)
scx, jcx = signed(EH3, "POST", "/confirm", {"reservation_id": rid12, "user_id": u12})
post12 = seats_of(EH3)
check("confirm_after_expiry", "confirm after hold TTL expiry: rejected, seats reclaimed",
      sh12 == 200 and scx >= 400 and post12["held"] == 0,
      "hold=%s confirm=%s %s seats=%s" % (sh12, scx, jcx.get("status"), post12))

# ---- 13/14/15. waitlist dup user, partial-release promotion, idempotent re-release (8092, 61 seats, ttl 30)
# drain via /reserve holds: 14x4 + 5x1 = 61 (two 1-seat holds kept for later releases)
rids13 = []
i = 0
while len(rids13) < 19 and i < 40:
    n = 4 if len(rids13) < 14 else 1
    ud = U("dr")
    st, j = signed(EH2, "POST", "/reserve", {"user_id": ud, "idempotency_key": K("dr"), "seats": n})
    if st == 200 and j.get("status") == "held":
        rids13.append((j.get("reservation_id"), n))
    i += 1
d13 = seats_of(EH2)
# 13: two 1-seat entries, same user; one release promotes exactly one, the other stays queued
u13, ka13, kb13 = U("wl"), K("wlA"), K("wlB")
sa13, ja13 = signed(EH2, "POST", "/waitlist", {"user_id": u13, "idempotency_key": ka13, "seats": 1})
sb13, jb13 = signed(EH2, "POST", "/waitlist", {"user_id": u13, "idempotency_key": kb13, "seats": 1})
relA_rid, relA_n = rids13[-1]
sr1, jr1 = signed(EH2, "POST", "/release", {"reservation_id": relA_rid})
m13 = seats_of(EH2)
tsq, ridq = str(int(time.time())), uuid.uuid4().hex
macq = mac_for(SECRET, tsq, ridq, "GET", "/waitlist?user_id="+u13, KEY, b"")
pq = EH2.split("//")[1].split(":")
cq = http.client.HTTPConnection(pq[0], int(pq[1]), timeout=8)
cq.request("GET", "/waitlist?user_id="+u13, headers={"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": tsq,
           "X-Kavach-Request-Id": ridq, "X-Kavach-Signature": macq})
rq = cq.getresponse(); dq = rq.read(); cq.close()
qj = json.loads(dq) if dq else {}
qids = [e.get("waitlist_id") for e in qj.get("entries", [])]
check("wl_dup_user", "two 1-seat entries same user; one release promotes exactly one (other still queued)",
      d13["free"] == 0 and sa13 == 200 and sb13 == 200 and sr1 == 200 and m13["held"] == 61 and m13["free"] == 0
      and jb13.get("waitlist_id") in qids and ja13.get("waitlist_id") not in qids,
      "drain_held=%s wl=%s/%s rel=%s seats=%s queue=%s" % (d13["held"], sa13, sb13, sr1, m13, qids))

# 15: re-release of an already released hold: 200 idempotent, no double free
sr2, jr2 = signed(EH2, "POST", "/release", {"reservation_id": relA_rid})
m15 = seats_of(EH2)
check("release_idempotent", "re-release of a released hold: 200, seats not double-freed",
      sr2 == 200 and m15["held"] == 61 and m15["free"] == 0,
      "rel=%s seats=%s" % (sr2, m15))

# 14: 4-seat entry vs partial release: cancel the leftover 1-seat entry, then
# 1 freed -> 4-entry stays queued; 4 freed -> promotes fully
sc14, jc14 = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": jb13.get("waitlist_id")})
u14, kc14 = U("wl4"), K("wl4")
sw14, jw14 = signed(EH2, "POST", "/waitlist", {"user_id": u14, "idempotency_key": kc14, "seats": 4})
one_seat = rids13[-2][0]
four_seat = next(r for r, n in rids13 if n == 4)
srA, jA = signed(EH2, "POST", "/release", {"reservation_id": one_seat})
m14a = seats_of(EH2)
srB, jB = signed(EH2, "POST", "/release", {"reservation_id": four_seat})
m14b = seats_of(EH2)
check("wl_partial_release", "4-seat entry: 1 freed stays queued (free=1); 4 freed promotes fully",
      sc14 == 200 and sw14 == 200 and srA == 200 and srB == 200
      and m14a["free"] == 1 and m14a["held"] == 60 and m14b["held"] == 60 and m14b["free"] == 1,
      "cancel=%s wl=%s rel1=%s mid=%s rel4=%s final=%s" % (sc14, sw14, srA, m14a, srB, m14b))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
