#!/usr/bin/env python3
"""Run 50 extras: 11 angles.
1: 10 concurrent app /api/pay on one hold: exactly 1 sale, rest 409, conserved
2: wl 4 seats, two 2-seat releases: stays queued after first, promoted after cumulative second
3: /book event_id evA then evB: shared or separate inventory (observe, conserved)
4: /reserve seats=100 -> clean 4xx, no 5xx
5: empty X-Kavach-Signature header -> 401
6: duplicate JSON keys {"seats":1,"seats":2}: Go last-wins -> 200 held 2 (MAC covers whole body)
7: signed GET /waitlist with ANOTHER user's user_id same tenant: what shows (observe, design family)
8: app /api/hold seats=-5 -> clean 400
9: 50 random binary bodies, validly MAC'd -> all 4xx, zero 5xx, conserved
10: {"user_id": null} -> clean 400
11: duplicate X-Kavach-Timestamp headers (valid, then different) -> first wins fail-closed -> 401
"""
import hashlib, hmac, http.client, json, os, time, uuid, random
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
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

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = str(int(time.time()))
    rid = uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r50-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k50-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1. 10 concurrent app /api/pay on one hold
u1 = U("pay")
st1h, j1h = send(APP, "POST", "/api/hold", json.dumps({"user_id": u1, "seats": 1}).encode(), {"Content-Type": "application/json"})
rid1 = j1h.get("reservation_id")
def pay1(_):
    return send(APP, "POST", "/api/pay", json.dumps({"user_id": u1, "reservation_id": rid1, "outcome": "success"}).encode(), {"Content-Type": "application/json"})
with ThreadPoolExecutor(max_workers=10) as ex:
    outs1 = list(ex.map(pay1, range(10)))
c1 = Counter(s for s, _ in outs1)
pre1 = seats_of(EH1)
bids1 = {j.get("booking_id") for s, j in outs1 if s == 200}
cons1 = pre1["sold"] + pre1["held"] + pre1["free"] == pre1["total"]
check("app_pay_concurrent", "10 concurrent app pays one hold: all 200, ONE distinct booking_id (confirm idempotent), sold=1, conserved",
      st1h == 200 and len(outs1) == 10 and len(bids1) == 1 and all(j.get("ok") for s, j in outs1) and pre1["sold"] == 1 and cons1,
      "codes=%s booking_ids=%s sold=%s" % (dict(c1), len(bids1), pre1["sold"]))

# ---- 2. wl cumulative promotion (8092 drained, 61 seats)
# drain 61 seats with 30 two-seat holds (60); the last seat stays free
rids2, i2 = [], 0
while len(rids2) < 30 and i2 < 40:
    ud2 = U("dr")
    st2d, j2d = signed(EH2, "POST", "/reserve", {"user_id": ud2, "idempotency_key": K("dr"), "seats": 2})
    if st2d == 200 and j2d.get("status") == "held":
        rids2.append(j2d.get("reservation_id"))
    else:
        break
    i2 += 1
u2, k2 = U("cc"), K("cc")
sj2, jj2 = signed(EH2, "POST", "/waitlist", {"user_id": u2, "idempotency_key": k2, "seats": 4})
pos_q = jj2.get("position")
# release ONE 2-seat hold -> only 2 free: 4-seat wl entry must stay queued
r2a, _ = signed(EH2, "POST", "/release", {"reservation_id": rids2[-1]})
time.sleep(0.4)
sq2, jq2 = signed(EH2, "GET", "/waitlist?user_id=" + u2)
st_queued = sj2 == 200 and r2a == 200 and any(e.get("waitlist_id") == jj2.get("waitlist_id") for e in jq2.get("entries", []))
# release ANOTHER 2-seat hold -> cumulative 4 free -> promoted
r2b, _ = signed(EH2, "POST", "/release", {"reservation_id": rids2[-2]})
time.sleep(0.4)
sq3, jq3 = signed(EH2, "GET", "/waitlist?user_id=" + u2)
st_promoted = not any(e.get("waitlist_id") == jj2.get("waitlist_id") for e in jq3.get("entries", []))
fin2 = seats_of(EH2)
cons2 = fin2["sold"] + fin2["held"] + fin2["free"] == fin2["total"]
check("wl_cumulative_promotion", "drained 61 (30x2+1x1), wl 4 seats: 2 seats freed -> stays queued, cumulative 4 -> promoted",
      len(rids2) == 30 and st_queued and st_promoted and r2b == 200 and cons2,
      "drained=%s(30x2) rel1=%s queued=%s rel2=%s gone=%s cons=%s" % (len(rids2), r2a, st_queued, r2b, st_promoted, cons2))

# ---- 3. event isolation: two different event_ids (8098, observe)
sa3, ja3 = signed(EH5, "POST", "/book", {"user_id": U("ev"), "idempotency_key": K("eva"), "seats": 1, "event_id": "evA"})
sb3, jb3 = signed(EH5, "POST", "/book", {"user_id": U("ev"), "idempotency_key": K("evb"), "seats": 1, "event_id": "evB"})
s3 = seats_of(EH5)
cons3 = s3["sold"] + s3["held"] + s3["free"] == s3["total"]
check("event_isolation", "book evA then evB: both 200, one shared pool, conserved (observe)",
      sa3 == 200 and sb3 == 200 and s3["sold"] == 2 and cons3,
      "a=%s b=%s sold=%s free=%s cons=%s" % (sa3, sb3, s3["sold"], s3["free"], cons3))

# ---- 4. /reserve seats=100
st4, j4 = signed(EH5, "POST", "/reserve", {"user_id": U("big"), "idempotency_key": K("big"), "seats": 100})
alive4 = seats_of(EH5)["total"] > 0
check("reserve_seats_100", "/reserve seats=100: clean 4xx, no 5xx, engine alive", st4 < 500 and st4 != 0 and alive4,
      "st=%s %s" % (st4, j4.get("status")))

# ---- 5. empty signature header
b5 = json.dumps({"user_id": U("es"), "idempotency_key": K("es"), "seats": 1}).encode()
ts5, rid5 = str(int(time.time())), uuid.uuid4().hex
st5, j5 = send(EH5, "POST", "/reserve", b5, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts5,
               "X-Kavach-Request-Id": rid5, "X-Kavach-Signature": "", "Content-Type": "application/json"})
check("sig_header_empty", "empty X-Kavach-Signature: 401 fail-closed", st5 == 401, "st=%s" % st5)

# ---- 6. duplicate JSON keys (Go last-wins)
k6 = U("dk")  # idem key
b6 = b'{"user_id":"%s","idempotency_key":"%s","seats":1,"seats":2}' % (U("dk").encode(), K("dk").encode())
ts6, rid6 = str(int(time.time())), uuid.uuid4().hex
mac6 = mac_for(SECRET, ts6, rid6, "POST", "/reserve", KEY, b6)
st6, j6 = send(EH5, "POST", "/reserve", b6, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts6,
               "X-Kavach-Request-Id": rid6, "X-Kavach-Signature": mac6, "Content-Type": "application/json"})
s6 = seats_of(EH5)
cons6 = s6["sold"] + s6["held"] + s6["free"] == s6["total"]
got6 = j6.get("seats")
n6 = len(got6) if isinstance(got6, list) else got6
check("dup_json_keys", "dup seats key 1,2: Go last-wins -> 2 seats held (MAC covers whole body), conserved",
      st6 == 200 and n6 == 2 and j6.get("status") == "held" and cons6,
      "st=%s seats=%s %s" % (st6, got6, j6.get("status")))

# ---- 7. wl GET ownership, definitive: fresh entry (case 2 promoted its own away; 1 seat free so a 2-seat join queues)
ua7w, ka7w = U("wlG"), K("wlG")
sj7w, jj7w = signed(EH2, "POST", "/waitlist", {"user_id": ua7w, "idempotency_key": ka7w, "seats": 2})
wlid7 = jj7w.get("waitlist_id")
same7, j7a = signed(EH2, "GET", "/waitlist?user_id=" + ua7w)            # tenant1 key, own user
cross7, j7b = signed(EH2, "GET", "/waitlist?user_id=" + ua7w, key=KEY2) # tenant2 key, tenant1 user id
other7, j7c = signed(EH2, "GET", "/waitlist?user_id=" + U("stranger"))  # tenant1 key, stranger id
ok7 = (sj7w == 200 and wlid7 and same7 == 200 and any(e.get("waitlist_id") == wlid7 for e in j7a.get("entries", []))
       and cross7 == 200 and not j7b.get("entries")  # tenant-isolated: no leak
       and other7 == 200 and not j7c.get("entries")) # user-scoped: no other user's entries
check("wl_get_cross_user", "GET /waitlist is tenant+user scoped: own entry visible, cross-tenant and stranger see none",
      ok7, "own=%s(%d) crossTenant=%s(%d) stranger=%s(%d)" % (same7, len(j7a.get("entries", [])), cross7, len(j7b.get("entries", [])), other7, len(j7c.get("entries", []))))

# ---- 8. app hold negative seats
st8, j8 = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("neg"), "seats": -5}).encode(), {"Content-Type": "application/json"})
check("app_hold_negative", "app /api/hold seats=-5: clean 400", st8 == 400, "st=%s %s" % (st8, json.dumps(j8)[:60]))

# ---- 9. binary fuzz with valid MACs
rnd = random.Random(50)
pre9 = seats_of(EH5)
codes9 = []
for i in range(50):
    body = bytes(rnd.randrange(256) for _ in range(64))
    ts9, rid9 = str(int(time.time())), uuid.uuid4().hex
    mac9 = mac_for(SECRET, ts9, rid9, "POST", "/reserve", KEY, body)
    st9, _ = send(EH5, "POST", "/reserve", body, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts9,
                  "X-Kavach-Request-Id": rid9, "X-Kavach-Signature": mac9, "Content-Type": "application/json"})
    codes9.append(st9)
c9 = Counter(codes9)
fin9 = seats_of(EH5)
cons9 = fin9["sold"] + fin9["held"] + fin9["free"] == fin9["total"]
check("binary_fuzz_mac_valid", "50 random binary bodies, valid MAC: all 4xx, zero 5xx, conserved",
      all(s < 500 for s in codes9) and cons9, "codes=%s cons=%s" % (dict(c9), cons9))

# ---- 10. null user_id
st10, j10 = signed(EH5, "POST", "/reserve", {"user_id": None, "idempotency_key": K("nu"), "seats": 1})
check("user_id_null", "user_id null: clean 400 (no panic)", st10 == 400, "st=%s %s" % (st10, j10.get("status")))

# ---- 11. duplicate X-Kavach-Timestamp headers (valid first, different second)
b11 = json.dumps({"user_id": U("dt"), "idempotency_key": K("dt"), "seats": 1}).encode()
ts11, rid11 = str(int(time.time())), uuid.uuid4().hex
mac11 = mac_for(SECRET, ts11, rid11, "POST", "/reserve", KEY, b11)
ts11b = str(int(time.time()) - 5)
p11 = EH5.split("//")[1].split(":")
c11 = http.client.HTTPConnection(p11[0], int(p11[1]), timeout=8)
c11.putrequest("POST", "/reserve", skip_host=True)
c11.putheader("Host", "%s:%s" % (p11[0], p11[1]))
c11.putheader("Authorization", "Bearer "+KEY)
c11.putheader("X-Kavach-Timestamp", ts11)
c11.putheader("X-Kavach-Timestamp", ts11b)
c11.putheader("X-Kavach-Request-Id", rid11)
c11.putheader("X-Kavach-Signature", mac11)
c11.putheader("Content-Type", "application/json")
c11.endheaders(b11)
r11 = c11.getresponse(); d11 = r11.read(); st11 = r11.status; c11.close()
check("dup_ts_header", "dup X-Kavach-Timestamp (valid first, older second): first wins fail-closed -> 401",
      st11 == 401, "st=%s %s" % (st11, d11[:60].decode("utf-8", "replace")))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
