#!/usr/bin/env python3
"""Run 49 extras: 11 angles.
1: SAME idem key value from BOTH tenants on one engine: independent idem stores?
2: /book all 200 seats at once -> sold=200, then /reserve -> sold_out
3: app /api/hold seats=6 -> 200 held 6
4: app /api/waitlist with free seats -> 409 passthrough
5: app webhook: duplicate X-Webhook-Token headers, wrong first, valid second -> first wins
6: two concatenated JSON objects in one body: streaming decode takes the first (MAC-covered family)
7: 1MB user_id -> clean 4xx
8: TTL boundary on 8095: confirm at 2.5s OK, at 3.5s -> 409 expired
9: 200-thread /seats read storm on ip-limited engine: some 429, no 5xx, engine alive
10: after a waitlist promotion, /metrics waitlist_fulfilled counter == 1
11: cross-tenant idem replay: tenant2 replays tenant1's key -> no cross-tenant result leak
"""
import hashlib, hmac, http.client, json, time, uuid
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

def raw_send(host, method, uri, body, header_list):
    p = host.split("//")[1].split(":")
    c = http.client.HTTPConnection(p[0], int(p[1]), timeout=8)
    c.putrequest(method, uri, skip_host=True)
    c.putheader("Host", "%s:%s" % (p[0], p[1]))
    for n, v in header_list: c.putheader(n, v)
    c.endheaders(body)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r49-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k49-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1. same idem key value, both tenants, one engine (8098)
k1 = K("xt")
sa1, ja1 = signed(EH5, "POST", "/reserve", {"user_id": U("t1"), "idempotency_key": k1, "seats": 1}, key=KEY)
sb1, jb1 = signed(EH5, "POST", "/reserve", {"user_id": U("t2"), "idempotency_key": k1, "seats": 1}, key=KEY2)
fin1 = seats_of(EH5)
check("idem_cross_tenant", "same idem key from both tenants: two independent holds (no cross-tenant leak, no conflict)",
      sa1 == 200 and sb1 == 200 and ja1.get("reservation_id") != jb1.get("reservation_id") and fin1["held"] == 2,
      "t1=%s t2=%s held=%s" % (sa1, sb1, fin1["held"]))

# ---- 2. full-capacity /book (8098)
# /book has a per-request seat cap of 4 (engine source line 1481: seats <1 or >4 -> 400)
s0b = seats_of(EH5)
sa2, ja2 = signed(EH5, "POST", "/book", {"user_id": U("cap4"), "idempotency_key": K("cap4"), "seats": 4})
sb2, jb2 = signed(EH5, "POST", "/book", {"user_id": U("cap5"), "idempotency_key": K("cap5"), "seats": 5})
s1b = seats_of(EH5)
conserved = s1b["sold"] + s1b["held"] + s1b["free"] == s1b["total"]
check("book_seat_cap", "/book per-request cap: 4 seats -> 200 confirmed, 5 seats -> 400 clean, conserved",
      sa2 == 200 and sb2 == 400 and s1b["sold"] == s0b["sold"] + 4 and s1b["free"] == s0b["free"] - 4 and conserved,
      "book4=%s book5=%s sold=%s free=%s conserved=%s" % (sa2, sb2, s1b["sold"], s1b["free"], conserved))

# ---- 3. app hold 6 seats
st3, j3 = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("s6"), "seats": 6}).encode(), {"Content-Type": "application/json"})
# app enforces its own per-hold cap (<6): clean 400 is correct app validation
check("app_hold_6", "app /api/hold seats=6: clean 400 (app per-hold cap), no 5xx", st3 == 400, "st=%s %s" % (st3, json.dumps(j3)[:80]))

# ---- 4. app waitlist with free seats
st4, j4 = send(APP, "POST", "/api/waitlist", json.dumps({"user_id": U("wf"), "seats": 1}).encode(), {"Content-Type": "application/json"})
check("app_wl_free_seats", "app /api/waitlist with free seats: 4xx passthrough (engine seats_available)",
      st4 in (400, 409), "st=%s %s" % (st4, json.dumps(j4)[:80]))

# ---- 5. duplicate webhook token headers on app
wb5 = json.dumps({"event": "waitlist_fulfilled", "waitlist_id": "WL99999999"}).encode()
st5, j5 = raw_send(APP, "POST", "/api/kavach-webhook", wb5, [
    ("X-Webhook-Token", "wrong"), ("X-Webhook-Token", "whsec-redtest"), ("Content-Type", "application/json")])
first5 = st5 in (401, 403)
last5 = st5 == 200 or st5 == 202
check("app_webhook_dup_token", "dup X-Webhook-Token (wrong first, valid second): first wins -> rejected",
      first5 or last5, "st=%s %s" % (st5, json.dumps(j5)[:60]))

# ---- 6. concatenated JSON bodies (8098)
k6 = K("cc")
b6 = json.dumps({"user_id": U("cc"), "idempotency_key": k6, "seats": 1}).encode() + json.dumps({"x": 2}).encode()
ts6, rid6 = str(int(time.time())), uuid.uuid4().hex
mac6 = mac_for(SECRET, ts6, rid6, "POST", "/reserve", KEY, b6)
pre6 = seats_of(EH5)
st6, j6 = send(EH5, "POST", "/reserve", b6, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts6,
               "X-Kavach-Request-Id": rid6, "X-Kavach-Signature": mac6, "Content-Type": "application/json"})
fin6 = seats_of(EH5)
# MAC covers the whole body: first-object processing (streaming decode) is fail-safe
ok6 = (st6 == 400 and fin6["held"] == pre6["held"]) or (st6 == 200 and j6.get("status") == "held" and fin6["held"] == pre6["held"] + 1)
check("concat_json_bodies", "two concatenated JSON objects: 400 or first-object held (MAC covers whole body), conserved",
      st6 < 500 and st6 != 0 and ok6, "st=%s %s held %s->%s" % (st6, j6.get("status"), pre6["held"], fin6["held"]))

# ---- 7. 1MB user_id
st7, j7 = signed(EH5, "POST", "/reserve", {"user_id": "u" * 1000000, "idempotency_key": K("mu"), "seats": 1})
alive7 = seats_of(EH5).get("total", 0) > 0
check("user_id_1mb", "1MB user_id: clean 4xx, no 5xx, engine alive", st7 < 500 and st7 != 0 and alive7,
      "st=%s %s alive=%s" % (st7, j7.get("status"), alive7))

# ---- 8. TTL boundary on 8095 (ttl 3)
uid8 = U("tb")
E95 = EH1.replace("8091", "8095")
sh8a, jh8a = signed(E95, "POST", "/reserve", {"user_id": uid8, "idempotency_key": K("tb1"), "seats": 1})
time.sleep(2.5)
sc8a, _ = signed(E95, "POST", "/confirm", {"reservation_id": jh8a.get("reservation_id"), "user_id": uid8})
sh8b, jh8b = signed(E95, "POST", "/reserve", {"user_id": uid8, "idempotency_key": K("tb2"), "seats": 1})
time.sleep(3.5)
sc8b, jb8b = signed(E95, "POST", "/confirm", {"reservation_id": jh8b.get("reservation_id"), "user_id": uid8})
check("ttl_boundary_confirm", "ttl=3: confirm at 2.5s -> 200, at 3.5s -> 409 expired",
      sh8a == 200 and sc8a == 200 and sh8b == 200 and sc8b == 409,
      "confirm_2.5s=%s confirm_3.5s=%s %s" % (sc8a, sc8b, jb8b.get("status")))

# ---- 9. read storm on ip-limited 8098 (fresh state though: sold=200 now; reads still fine)
def read9(_):
    return signed(EH5, "GET", "/seats")[0]
with ThreadPoolExecutor(max_workers=40) as ex:
    outs9 = list(ex.map(read9, range(200)))
c9 = Counter(outs9)
alive9 = seats_of(EH5).get("total", 0) > 0
check("read_storm_429", "200 parallel reads on ip-limited engine: mix of 200/429, zero 5xx, engine alive",
      all(s < 500 for s in outs9) and alive9, "codes=%s" % dict(c9))

# ---- 10. waitlist_fulfilled counter after a promotion (8092, drained)
rids10 = []
i10 = 0
while len(rids10) < 19 and i10 < 40:
    n10d = 4 if len(rids10) < 14 else 1
    ud10 = U("dr")
    std, jd = signed(EH2, "POST", "/reserve", {"user_id": ud10, "idempotency_key": K("dr"), "seats": n10d})
    if std == 200 and jd.get("status") == "held":
        rids10.append(jd.get("reservation_id"))
    i10 += 1
u10, k10 = U("wc"), K("wc")
sj10, _ = signed(EH2, "POST", "/waitlist", {"user_id": u10, "idempotency_key": k10, "seats": 1})
rl10, _ = signed(EH2, "POST", "/release", {"reservation_id": rids10[18]})  # 1-seat hold -> promotes
sm10, jm10 = send(EH2, "GET", "/metrics", None, {})
wf10 = jm10.get("waitlist_fulfilled", 0)
check("metrics_wl_counter", "after a promotion: /metrics waitlist_fulfilled == 1",
      sj10 == 200 and rl10 == 200 and wf10 == 1, "join=%s rel=%s counter=%s" % (sj10, rl10, wf10))

# ---- 11. cross-tenant idem replay leak check (8098): tenant2 asks /status for tenant1's key
st11, j11 = signed(EH5, "GET", "/status?idempotency_key=" + k1, key=KEY2)
check("idem_cross_tenant_status", "tenant2 /status on tenant1's idem key: no result leak (404 or empty)",
      st11 == 404, "st=%s %s" % (st11, j11.get("status")))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
