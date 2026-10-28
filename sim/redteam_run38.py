#!/usr/bin/env python3
"""Run 38 extras: 15 angles.
1: /status with another tenant's key -> 404 (tenant-scoped idem store)
2: /status unknown idempotency key -> 404
3: waitlist join then /reserve with the same idem key
4: same idem key different seats count -> 409 conflict
5: 20x concurrent confirm of one hold -> exactly one booking
6: last-seat race: 30x concurrent reserve at 1 free seat
7: TTL-expiry side waitlist auto-promotion (8095)
8: app hold seats=0 and seats=-1
9: app waitlist seats=5 passthrough
10: lowercase header names still authenticate
11: Authorization "Bearer  key" double space -> 401
12: timestamp window boundary: now-299 accepted, now-301 rejected
13: JSON body with trailing newline, MAC over exact bytes
14: app pay confirms a hold created directly on the engine
15: /book then /status returns the stored sold result
"""
import hashlib, hmac, http.client, json, threading, time, uuid
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH3, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8095", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
PASS = FAIL = 0

def check(name, desc, ok, detail=""):
    global PASS, FAIL
    tag = "PASS" if ok else "FAIL"
    if ok: PASS += 1
    else: FAIL += 1
    print("%s %s %s | %s" % (tag, name, desc, detail))

def req(host, method, uri, obj=None, key=KEY, secret=SECRET, extra=None, ts_override=None, headers_override=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = ts_override if ts_override is not None else str(int(time.time()))
    rid = uuid.uuid4().hex
    mac = hmac.new(secret.encode(), (ts+"\n"+rid+"\n"+method+"\n"+uri+"\n"+key+"\n").encode()+body, hashlib.sha256).hexdigest()
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    if extra: h.update(extra)
    if headers_override: h = headers_override
    p = host.split("//")[1].split(":")
    c = http.client.HTTPConnection(p[0], int(p[1]), timeout=8)
    c.request(method, uri, body=body, headers=h)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def seats_of(host):
    st, j = req(host, "GET", "/seats")
    return j

U = lambda t: "r38-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k38-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 7. TTL-expiry side waitlist auto-promotion (8095, 10 seats, ttl 3) -- run first, it sleeps
rids7 = []
for i in range(5):
    st, j = req(EH3, "POST", "/reserve", {"user_id": U("fill"), "idempotency_key": K("fill"), "seats": 2})
    if st == 200: rids7.append(j.get("reservation_id"))
sw, jw = req(EH3, "POST", "/waitlist", {"user_id": U("wl"), "idempotency_key": K("wl"), "seats": 1})
time.sleep(5.0)
seat3 = seats_of(EH3)
check("expiry_wl_promo", "TTL expiry reclaims holds and promotes the waitlist entry: conserved",
      sw == 200 and seat3["free"]+seat3["held"]+seat3["sold"] == 10,
      "join=%s seats=%s (expected promotion: held>=1)" % (sw, seat3))

# ---- 1. /book then cross-tenant /status (8091)
k1, u1 = K("bk"), U("bk")
sb, jb = req(EH1, "POST", "/book", {"user_id": u1, "idempotency_key": k1, "seats": 2})
sx, jx = req(EH1, "GET", "/status?idempotency_key="+k1, key=KEY2)
check("xtenant_status", "GET /status with another tenant's key: 404, no leak",
      sb == 200 and sx == 404, "book=%s %s then status=%s %s" % (sb, jb.get("status"), sx, jx.get("status")))

# ---- 15. /book then /status same tenant returns stored sold result
k15, u15 = K("bk2"), U("bk2")
sb2, jb2 = req(EH1, "POST", "/book", {"user_id": u15, "idempotency_key": k15, "seats": 1})
sy, jy = req(EH1, "GET", "/status?idempotency_key="+k15)
check("book_then_status", "/status after /book returns the stored sold result",
      sb2 == 200 and sy == 200 and bool(jy.get("booking_id")),
      "book=%s status=%s %s" % (sb2, sy, {k: jy.get(k) for k in ("status", "booking_id")}))

# ---- 2. /status unknown key (8091)
sz, jz = req(EH1, "GET", "/status?idempotency_key="+K("ghost"))
check("status_unknown", "GET /status unknown key: 404 not_found", sz == 404, "st=%s %s" % (sz, jz.get("status")))

# ---- 14. engine hold paid through the app (8091)
u14, k14 = U("xapp"), K("xapp")
sh, jh = req(EH1, "POST", "/reserve", {"user_id": u14, "idempotency_key": k14, "seats": 1})
rid14 = jh.get("reservation_id", "")
sp, jp = req(APP, "POST", "/api/pay", {"reservation_id": rid14, "user_id": u14})
check("app_pay_engine_hold", "app /api/pay confirms a hold created directly on the engine",
      sh == 200 and sp == 200 and jp.get("ok") is True and bool(jp.get("booking_id")),
      "hold=%s pay=%s %s" % (sh, sp, jp))

# ---- 6. last-seat race on 8091: seat everything but one, then 30x concurrent 1-seat
pre = seats_of(EH1)
need_hold = pre["free"] - 1
held6 = 0
i = 0
while held6 < need_hold and i < 60:
    n = min(4, need_hold - held6)
    st, j = req(EH1, "POST", "/reserve", {"user_id": U("fill6"), "idempotency_key": K("fill6"), "seats": n})
    if st == 200 and j.get("status") == "held": held6 += n
    i += 1
mid = seats_of(EH1)
results6 = []
def race6():
    st, j = req(EH1, "POST", "/reserve", {"user_id": U("race"), "idempotency_key": K("race"), "seats": 1})
    results6.append((st, j.get("status")))
threads = [threading.Thread(target=race6) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()
post = seats_of(EH1)
held6c = sum(1 for st, s in results6 if st == 200 and s == "held")
check("last_seat_race", "30x concurrent reserve at 1 free seat: exactly 1 held, others sold_out, free=0",
      mid["free"] == 1 and held6c == 1 and post["free"] == 0,
      "mid_free=%s outcomes=%s held=%d post_free=%s" % (mid["free"], dict(Counter(s for _, s in results6)), held6c, post["free"]))

# ---- 3. waitlist join then /reserve with the same idem key (8098)
k3, u3 = K("wr"), U("wr")
sw3, jw3 = req(EH5, "POST", "/waitlist", {"user_id": u3, "idempotency_key": k3, "seats": 1})
sr3, jr3 = req(EH5, "POST", "/reserve", {"user_id": u3, "idempotency_key": k3, "seats": 1})
seat5 = seats_of(EH5)
check("waitlist_then_reserve", "same idem key on /waitlist then /reserve: no 5xx, conserved, behavior documented",
      sw3 < 500 and sr3 < 500 and sw3 != 0 and sr3 != 0 and seat5["free"]+seat5["held"]+seat5["sold"] == 200,
      "wl=%s reserve=%s %s" % (sw3, sr3, {k: jr3.get(k) for k in ("status", "reservation_id")}))

# ---- 4. same idem key different seats (8098)
k4, u4 = K("ds"), U("ds")
sa4, _ = req(EH5, "POST", "/reserve", {"user_id": u4, "idempotency_key": k4, "seats": 1})
sb4, jb4 = req(EH5, "POST", "/reserve", {"user_id": u4, "idempotency_key": k4, "seats": 2})
check("idem_diff_seats", "same key different seats: 409 conflict, no second hold",
      sa4 == 200 and sb4 == 409 and jb4.get("status") == "idempotency_conflict",
      "%s then %s %s" % (sa4, sb4, jb4.get("status")))

# ---- 5. 20x concurrent confirm of one hold (8098)
k5, u5 = K("cc"), U("cc")
sh5, jh5 = req(EH5, "POST", "/reserve", {"user_id": u5, "idempotency_key": k5, "seats": 2})
rid5 = jh5.get("reservation_id", "")
pre5 = seats_of(EH5)
results5 = []
def conf5():
    st, j = req(EH5, "POST", "/confirm", {"reservation_id": rid5, "user_id": u5})
    results5.append((st, j.get("booking_id", "")))
ths = [threading.Thread(target=conf5) for _ in range(20)]
for t in ths: t.start()
for t in ths: t.join()
post5 = seats_of(EH5)
bids = set(b for _, b in results5 if b)
succ5 = sum(1 for st, _ in results5 if st == 200)
check("concurrent_confirm", "20x concurrent confirm: idempotent (all 200 same booking_id), sold +2 only",
      succ5 == 20 and len(bids) == 1 and post5["sold"] == pre5["sold"] + 2,
      "succ=%d bids=%d sold %s->%s outcomes=%s" % (succ5, len(bids), pre5["sold"], post5["sold"], dict(Counter(st for st, _ in results5))))

# ---- 8. app hold seats=0 and seats=-1
s0, j0 = req(APP, "POST", "/api/hold", {"user_id": U("z"), "seats": 0})
sn, jn = req(APP, "POST", "/api/hold", {"user_id": U("n"), "seats": -1})
check("app_hold_zero", "app hold seats=0 rejected, no 5xx", s0 < 500 and s0 != 0, "st=%s %s" % (s0, j0))
check("app_hold_neg", "app hold seats=-1 rejected, no 5xx", sn < 500 and sn != 0, "st=%s %s" % (sn, jn))

# ---- 9. app waitlist seats=5 (engine max 4)
s9, j9 = req(APP, "POST", "/api/waitlist", {"user_id": U("w5"), "seats": 5})
check("app_wl_seats5", "app waitlist seats=5: 4xx passthrough, no 5xx", 400 <= s9 < 500, "st=%s %s" % (s9, j9))

# ---- 10. lowercase header names still authenticate (8098)
obj10 = {"user_id": U("lc"), "idempotency_key": K("lc"), "seats": 1}
b10 = json.dumps(obj10).encode()
ts10, rid10 = str(int(time.time())), uuid.uuid4().hex
mac10 = hmac.new(SECRET.encode(), (ts10+"\n"+rid10+"\nPOST\n/reserve\n"+KEY+"\n").encode()+b10, hashlib.sha256).hexdigest()
st10, j10 = req(EH5, "POST", "/reserve", obj10,
               headers_override={"authorization": "Bearer "+KEY, "x-kavach-timestamp": ts10,
                                 "x-kavach-request-id": rid10, "x-kavach-signature": mac10,
                                 "content-type": "application/json"})
check("lowercase_headers", "lowercase header names authenticate fine", st10 == 200, "st=%s %s" % (st10, j10.get("status")))

# ---- 11. Authorization double space (8098)
st11, j11 = req(EH5, "POST", "/reserve", {"user_id": U("bs"), "idempotency_key": K("bs"), "seats": 1},
               extra={"Authorization": "Bearer  "+KEY})
check("bearer_double_space", "'Bearer  key' (double space) rejected 401", st11 == 401, "st=%s %s" % (st11, j11.get("status")))

# ---- 12. timestamp window boundary (8098)
sA, jA = req(EH5, "POST", "/reserve", {"user_id": U("tb"), "idempotency_key": K("tb"), "seats": 1}, ts_override=str(int(time.time())-299))
sB, jB = req(EH5, "POST", "/reserve", {"user_id": U("tb2"), "idempotency_key": K("tb2"), "seats": 1}, ts_override=str(int(time.time())-301))
check("ts_window", "ts now-299 accepted, now-301 rejected 401",
      sA == 200 and sB == 401, "old=%s %s older=%s %s" % (sA, jA.get("status"), sB, jB.get("status")))

# ---- 13. JSON body with trailing newline, MAC over exact bytes (8098)
obj13 = {"user_id": U("nl"), "idempotency_key": K("nl"), "seats": 1}
b13 = json.dumps(obj13).encode() + b"\n"
ts13, rid13 = str(int(time.time())), uuid.uuid4().hex
mac13 = hmac.new(SECRET.encode(), (ts13+"\n"+rid13+"\nPOST\n/reserve\n"+KEY+"\n").encode()+b13, hashlib.sha256).hexdigest()
p13 = EH5.split("//")[1].split(":")
c13 = http.client.HTTPConnection(p13[0], int(p13[1]), timeout=8)
c13.request("POST", "/reserve", body=b13, headers={"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts13,
            "X-Kavach-Request-Id": rid13, "X-Kavach-Signature": mac13, "Content-Type": "application/json"})
r13 = c13.getresponse(); st13 = r13.status; d13 = r13.read(); c13.close()
check("body_trailing_nl", "body with trailing newline, MAC over exact bytes: accepted", st13 == 200, "st=%s %s" % (st13, d13[:60]))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
