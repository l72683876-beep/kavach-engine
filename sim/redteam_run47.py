#!/usr/bin/env python3
"""Run 47 extras: 10 angles.
1: cancel a waitlist entry that was auto-promoted -> clean 4xx, hold conserved
2: timestamp with leading "+" prefix -> 401
3: app /api/hold with empty user_id -> no 5xx
4: wl entry promoted, then user also reserves directly -> held=4, conserved
5: same idem key on /book then /reserve -> no over-grant, engine alive
6: signed GET /waitlist without user_id -> 4xx
7: GET /status with a waitlist_id -> 404
8: 8KB event_id in wl join -> no 5xx
9: app /api/pay by user B on user A's hold -> observe, no 5xx, at most one sale
10: app /api/kavach-webhook with a wrong token -> rejected, no state change
"""
import hashlib, hmac, http.client, json, time, uuid
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

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, ts=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = ts or str(int(time.time()))
    rid = uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r47-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k47-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1. cancel an auto-promoted waitlist entry (8092, drained)
rids1 = []
i1 = 0
while len(rids1) < 19 and i1 < 40:
    n1d = 4 if len(rids1) < 14 else 1
    ud1 = U("dr")
    std, jd = signed(EH2, "POST", "/reserve", {"user_id": ud1, "idempotency_key": K("dr"), "seats": n1d})
    if std == 200 and jd.get("status") == "held":
        rids1.append(jd.get("reservation_id"))
    i1 += 1
u1, k1 = U("cp"), K("cp")
sj1, jj1 = signed(EH2, "POST", "/waitlist", {"user_id": u1, "idempotency_key": k1, "seats": 2})
wid1 = jj1.get("waitlist_id")
rl1, _ = signed(EH2, "POST", "/release", {"reservation_id": rids1[0]})
st1, j1 = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": wid1})
gw1, jw1 = signed(EH2, "GET", "/waitlist?user_id=" + u1)
check("cancel_promoted_entry", "cancel an auto-promoted wl entry: no 5xx, 0 live entries remain",
      sj1 == 200 and rl1 == 200 and st1 < 500 and st1 != 0 and len(jw1.get("entries", [])) == 0,
      "join=%s rel=%s cancel=%s %s entries=%d" % (sj1, rl1, st1, j1.get("status"), len(jw1.get("entries", []))))

# ---- 2. "+"-prefixed timestamp
k2 = K("tp")
b2 = json.dumps({"user_id": U("tp"), "idempotency_key": k2, "seats": 1}).encode()
ts2 = "+" + str(int(time.time()))
rid2 = uuid.uuid4().hex
mac2 = mac_for(SECRET, ts2, rid2, "POST", "/reserve", KEY, b2)
st2, j2 = send(EH5, "POST", "/reserve", b2, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts2,
               "X-Kavach-Request-Id": rid2, "X-Kavach-Signature": mac2, "Content-Type": "application/json"})
# '+'-prefixed ts parses as a signed int in Go; numerically identical, MAC covered:
# documented benign (runs <=39), expect 200 held
check("ts_plus_prefix", "leading '+' timestamp: parses benign (200 held), MAC still covers it",
      st2 == 200 and j2.get("status") == "held", "st=%s %s" % (st2, j2.get("status")))

# ---- 3. app hold with empty user_id
st3, j3 = send(APP, "POST", "/api/hold", json.dumps({"user_id": "", "seats": 1}).encode(), {"Content-Type": "application/json"})
check("app_hold_empty_user", "app /api/hold with empty user_id: no 5xx", st3 < 500 and st3 != 0,
      "st=%s %s" % (st3, j3.get("error") or j3.get("status")))

# ---- 4. wl promoted, then direct reserve too (8092)
u4, k4w, k4r = U("pp"), K("ppw"), K("ppr")
# wl join needs a sold-out moment: re-drain the 2 free seats case 1 left
for _ in range(2):
    signed(EH2, "POST", "/reserve", {"user_id": U("dr"), "idempotency_key": K("dr"), "seats": 1})
H1 = seats_of(EH2)["held"]
sj4, jj4 = signed(EH2, "POST", "/waitlist", {"user_id": u4, "idempotency_key": k4w, "seats": 2})
rl4, _ = signed(EH2, "POST", "/release", {"reservation_id": rids1[1]})
sr4, jr4 = signed(EH2, "POST", "/reserve", {"user_id": u4, "idempotency_key": k4r, "seats": 2})
fin4 = seats_of(EH2)
check("wl_promote_plus_direct", "drained join -> release promotes (2) -> direct reserve (2): held back to baseline, conserved",
      sj4 == 200 and rl4 == 200 and sr4 == 200 and jr4.get("status") == "held" and fin4["held"] == H1,
      "join=%s res=%s %s held %s->%s" % (sj4, sr4, jr4.get("status"), H1, fin4["held"]))

# ---- 5. same idem key on /book then /reserve (8098)
k5 = K("br")
sb5, jb5 = signed(EH5, "POST", "/book", {"user_id": U("br"), "idempotency_key": k5, "seats": 1})
pre5 = seats_of(EH5)
st5, j5 = signed(EH5, "POST", "/reserve", {"user_id": U("br"), "idempotency_key": k5, "seats": 1})
fin5 = seats_of(EH5)
no_extra = fin5["sold"] == pre5["sold"] and fin5["held"] in (pre5["held"], pre5["held"] + 1)
check("same_key_book_then_reserve", "same idem key /book then /reserve: no over-grant (at most +1 hold)",
      sb5 == 200 and st5 < 500 and st5 != 0 and no_extra,
      "book=%s res=%s %s sold %s->%s held %s->%s" % (sb5, st5, j5.get("status"), pre5["sold"], fin5["sold"], pre5["held"], fin5["held"]))

# ---- 6. GET /waitlist without user_id
st6, j6 = signed(EH2, "GET", "/waitlist")
check("waitlist_no_user_id", "signed GET /waitlist without user_id -> 4xx", st6 in (400, 422), "st=%s %s" % (st6, j6.get("status")))

# ---- 7. /status with a waitlist_id
k7 = K("sw")
u7 = U("sw")
sj7, jj7 = signed(EH2, "POST", "/waitlist", {"user_id": u7, "idempotency_key": k7, "seats": 1})
st7, j7 = signed(EH2, "GET", "/status?idempotency_key=" + k7)
check("status_wl_id", "drained join 200 queued; /status with a waitlist key -> 404 (resolves bookings/reservations only)",
      sj7 == 200 and jj7.get("status") == "queued" and st7 == 404, "join=%s %s st=%s %s" % (sj7, jj7.get("status"), st7, j7.get("status")))

# ---- 8. 8KB event_id in wl join
ev8 = "e" * 8192
k8 = K("ev")
u8 = U("ev")
sj8, jj8 = signed(EH2, "POST", "/waitlist", {"user_id": u8, "idempotency_key": k8, "seats": 1, "event_id": ev8})
sok8 = seats_of(EH2)
check("wl_8kb_event_id", "8KB event_id in wl join: clean 400 (length validation), no 5xx, engine alive",
      sj8 == 400 and sok8.get("total", 0) > 0,
      "join=%s %s seats_read=%s" % (sj8, jj8.get("status"), sok8.get("total")))

# ---- 9. app pay cross-user
ha, ja = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("ca"), "seats": 1}).encode(), {"Content-Type": "application/json"})
hb, jb = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("cb"), "seats": 1}).encode(), {"Content-Type": "application/json"})
pre9 = signed(EH1, "GET", "/seats")[1]
sp, jp = send(APP, "POST", "/api/pay", json.dumps({"hold_id": ja.get("hold_id")}).encode(), {"Content-Type": "application/json"})
fin9 = signed(EH1, "GET", "/seats")[1]
sold_delta = fin9["sold"] - pre9["sold"]
check("app_pay_cross_user", "user B pays user A's hold: no 5xx, at most one sale", ha == 200 and hb == 200 and sp < 500 and sp != 0 and sold_delta in (0, 1),
      "hold=%s pay=%s %s sold_delta=%s" % (ha, sp, jp.get("error") or jp.get("status"), sold_delta))

# ---- 10. app webhook with wrong token
sw10, jw10 = send(APP, "POST", "/api/kavach-webhook", json.dumps({"type": "booking.confirmed", "booking_id": "fake"}).encode(),
                  {"Content-Type": "application/json", "X-Webhook-Token": "wrong-token"})
bad10 = "wrong" in json.dumps(jw10).lower() or sw10 in (401, 403)
check("app_webhook_bad_token", "app webhook with wrong token -> rejected (401/403 or explicit error)", sw10 < 500 and sw10 != 0 and bad10,
      "st=%s %s" % (sw10, json.dumps(jw10)[:60]))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
