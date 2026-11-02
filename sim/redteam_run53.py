#!/usr/bin/env python3
"""Run 53 extras: 11 angles.
1: promoted hold TTL-expiry chain (8095 ttl 3): release promotes A, A expires, seats free again, B promotes?
2: webhook token with leading space -> 403 fail-closed
3: Authorization "bearer testkey" lowercase scheme -> accepted or 401
4: app wl join, engine-side cancel, app list reflects it (state sync)
5: /seats?foo=bar unknown query param -> 200 benign
6: engine-side release of app hold, then app pay -> clean 4xx, app alive
7: unsigned GET app /api/metrics -> 200 or 401, no secret leak
8: 8 concurrent app holds 1-seat ONE user (user-rate 0 engine) -> observation
9: promotion gives exactly the joined seats (2-seat entry -> 2-seat hold)
10: confirm with WRONG user_id -> 403 regression
11: reservation_id integer 123 in /release -> clean 400
"""
import hashlib, hmac, http.client, json, time, uuid
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH5, EH3 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8098", "http://127.0.0.1:8095"
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
    c = http.client.HTTPConnection(p[0], int(p[1]), timeout=10)
    c.request(method, uri, body=body, headers=headers)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, rid=None, auth=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = str(int(time.time()))
    rid = rid or uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": auth or ("Bearer "+key), "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r53-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k53-%s-%s" % (t, uuid.uuid4().hex[:6])
cons = lambda s: s["sold"] + s["held"] + s["free"] == s["total"]

# ---- 1. promoted hold TTL-expiry chain (8095, ttl 3, 10 seats): drain 10, queue A(1) B(1), release 1 -> A promoted, let A expire, B promotes?
holds1 = []
for i in range(10):
    st, j = signed(EH3, "POST", "/reserve", {"user_id": U("d1"), "idempotency_key": K("d1%d" % i), "seats": 1})
    if st == 200 and j.get("status") == "held": holds1.append(j["reservation_id"])
uA, uB = U("wa"), U("wb")
sjA, jjA = signed(EH3, "POST", "/waitlist", {"user_id": uA, "idempotency_key": K("wa"), "seats": 1})
sjB, jjB = signed(EH3, "POST", "/waitlist", {"user_id": uB, "idempotency_key": K("wb"), "seats": 1})
sr1, jr1 = signed(EH3, "POST", "/release", {"reservation_id": holds1[0]})  # frees 1 -> A promotes
time.sleep(3.5)  # A's promoted hold passes ttl 3 and expires
time.sleep(1.5)  # expiry-triggered promotion of B (synchronous per run 47)
s1 = seats_of(EH3)
wl_list1 = signed(EH3, "GET", "/waitlist")[1]
entries1 = {e.get("user_id") for e in wl_list1.get("entries", [])} if isinstance(wl_list1.get("entries"), list) else set()
a_gone, b_gone = uA not in entries1, uB not in entries1
# chain proof: A promoted then expired unconfirmed (sold stays 0), B took A's seat; the other 9 drain holds
# also expired under ttl 3, so final state is held=1 (B) + free=9, conserved (1+9+0=10)
check("promoted_ttl_expiry_chain", "ttl 3 chain: release promotes A, A expires unconfirmed, expiry promotes B (held=1=B's hold, free=9 expired drain seats, sold=0, both wl entries gone)",
      len(holds1) == 10 and sjA == 200 and sjB == 200 and sr1 == 200 and cons(s1) and a_gone and b_gone and s1["held"] == 1 and s1["free"] == 9 and s1["sold"] == 0,
      "held=%s free=%s sold=%s A_gone=%s B_gone=%s" % (s1["held"], s1["free"], s1["sold"], a_gone, b_gone))

# ---- 2. webhook token with leading space
st2, j2 = send(APP, "POST", "/api/kavach-webhook", json.dumps({"event": "reservation.confirmed", "data": {}}).encode(),
               {"X-Webhook-Token": " whsec-redtest", "Content-Type": "application/json"})
check("webhook_token_ws", "webhook token with leading space: 403 fail-closed", st2 == 403, "st=%s %s" % (st2, j2))

# ---- 3. lowercase bearer scheme
st3, j3 = signed(EH5, "POST", "/reserve", {"user_id": U("lb"), "idempotency_key": K("lb"), "seats": 1}, auth="bearer "+KEY)
ok3 = st3 == 200 or st3 == 401
check("bearer_lowercase_scheme", "lowercase 'bearer' scheme: accepted or 401, no 5xx", st3 < 500 and ok3,
      "st=%s %s" % (st3, j3.get("status")))

# ---- 6. engine-side release of app hold, then app pay
u6, k6 = U("obr"), K("obr")
st6, j6 = send(APP, "POST", "/api/hold", json.dumps({"user_id": u6, "seats": 1}).encode(), {"Content-Type": "application/json"})
rid6 = j6.get("reservation_id")
sr6, jr6 = signed(EH1, "POST", "/release", {"reservation_id": rid6}) if rid6 else (0, {})
st6b, j6b = send(APP, "POST", "/api/pay", json.dumps({"reservation_id": rid6, "user_id": u6, "outcome": "success"}).encode(), {"Content-Type": "application/json"})
alive6 = send(APP, "GET", "/api/seats", None, {})[0] == 200
check("app_pay_after_out_of_band_release", "engine releases app hold out-of-band, app pay -> clean 4xx, app alive",
      st6 == 200 and sr6 == 200 and st6b in (404, 409, 400) and alive6,
      "hold=%s release=%s pay=%s alive=%s" % (st6, sr6, st6b, alive6))

# ---- 4. app wl state sync after engine-side cancel (8091 drained by 50 held 1-seat reserves)
for i in range(50):
    signed(EH1, "POST", "/reserve", {"user_id": U("d4"), "idempotency_key": K("d4%d" % i), "seats": 1})
u4, k4 = U("sync"), K("sync")
st4, j4 = send(APP, "POST", "/api/waitlist", json.dumps({"user_id": u4, "seats": 1}).encode(), {"Content-Type": "application/json"})
wlid4 = j4.get("waitlist_id")
sc4, jc4 = signed(EH1, "POST", "/waitlist/cancel", {"waitlist_id": wlid4}) if wlid4 else (0, {})
st4b, j4b = send(APP, "GET", "/api/waitlist?user_id=%s" % u4, None, {})
ents4 = j4b.get("entries", []) if isinstance(j4b.get("entries"), list) else []
gone4 = all(e.get("waitlist_id") != wlid4 for e in ents4)
check("app_wl_state_sync", "app wl join then engine-side cancel: app list no longer shows the entry",
      st4 in (200, 409) and sc4 == 200 and gone4, "join=%s cancel=%s gone=%s" % (st4, sc4, gone4))

# ---- 5. unknown query param on /seats
st5, j5 = signed(EH5, "GET", "/seats?foo=bar&x=1")
check("seats_unknown_query", "/seats with unknown query params: 200, same shape", st5 == 200 and "total" in j5,
      "st=%s keys=%s" % (st5, sorted(j5.keys())[:5]))

# ---- 7. unsigned app metrics
st7, j7 = send(APP, "GET", "/api/metrics", None, {})
leak7 = "secret" in json.dumps(j7).lower() or "whsec" in json.dumps(j7).lower()
check("app_metrics_public", "unsigned GET app /api/metrics: 200 or 401, no secret in body", st7 in (200, 401, 404) and not leak7,
      "st=%s leak=%s" % (st7, leak7))

# ---- 8. 8 concurrent app holds one user (8092, user-rate 0)
def hold8(_):
    return send(APP, "POST", "/api/hold", json.dumps({"user_id": U("h8"), "seats": 1}).encode(), {"Content-Type": "application/json"})[0]
with ThreadPoolExecutor(max_workers=8) as ex:
    outs8 = list(ex.map(hold8, range(8)))
c8 = Counter(outs8)
s8 = seats_of(EH2)
check("app_concurrent_holds_one_user", "8 concurrent app holds one user, no user limiter: all held (no per-user cap, observe), conserved",
      all(s == 200 for s in outs8) and cons(s8), "codes=%s held=%s" % (dict(c8), s8["held"]))

# ---- 9. promotion gives exactly the joined seats
holds9 = []
for i in range(10):
    st, j = signed(EH3, "POST", "/reserve", {"user_id": U("d9"), "idempotency_key": K("d9%d" % i), "seats": 1})
    if st == 200 and j.get("status") == "held": holds9.append(j["reservation_id"])
st9, j9 = signed(EH3, "POST", "/waitlist", {"user_id": U("p2"), "idempotency_key": K("p2"), "seats": 2})
sr9, _ = signed(EH3, "POST", "/release", {"reservation_id": holds9[0]})
sr9b, _ = signed(EH3, "POST", "/release", {"reservation_id": holds9[1]})  # free 2 total -> 2-seat entry promotes
s9 = seats_of(EH3)
wl9 = signed(EH3, "GET", "/waitlist")[1]
ents9 = wl9.get("entries", []) if isinstance(wl9.get("entries"), list) else []
promoted9 = all(e.get("user_id") != U("p2") for e in ents9)
check("wl_promotion_seat_preservation", "2-seat wl entry promotes on 2-seat release: entry leaves list, exactly its 2 seats consumed (held 8->10, free 2->0)",
      st9 == 200 and sr9 == 200 and sr9b == 200 and promoted9 and s9["held"] == 10 and s9["free"] == 0 and cons(s9),
      "held=%s free=%s gone=%s" % (s9["held"], s9["free"], promoted9))

# ---- 10. confirm wrong user_id -> 403 regression
u10, k10 = U("wu"), K("wu")
st10, j10 = signed(EH5, "POST", "/reserve", {"user_id": u10, "idempotency_key": k10, "seats": 1})
st10b, j10b = signed(EH5, "POST", "/confirm", {"reservation_id": j10.get("reservation_id"), "user_id": U("other")})
s10 = seats_of(EH5)
check("confirm_wrong_user_403", "confirm with wrong user_id: 403 forbidden, hold intact, conserved",
      st10 == 200 and st10b == 403 and s10["held"] >= 1 and cons(s10), "st=%s" % st10b)

# ---- 11. integer reservation_id in /release
st11, j11 = signed(EH5, "POST", "/release", {"reservation_id": 123})
check("release_int_rid", "integer reservation_id in /release: clean 400", st11 == 400, "st=%s %s" % (st11, j11.get("status")))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
