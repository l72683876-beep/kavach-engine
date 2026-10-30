#!/usr/bin/env python3
"""Run 45 extras: 12 angles.
1: seats as JSON string "2" -> 400
2: event_id as number -> 400
3: duplicate Authorization headers, first unknown, second valid -> 401 (first wins, fail-closed)
4: 20-thread /reserve race on ONE idem key, same payload -> one reservation, held+1
5: future ts edges: now+290 authenticated read OK, now+320 -> 401
6: app hold expired by TTL, then app /api/pay -> no 5xx, no sale
7: /release with a booking_id instead of reservation_id -> 4xx, no state change
8: Content-Length lie (1e9 declared, 100 bytes sent): engine survives
9: /confirm with empty user_id: no 5xx, at most one sale
10: idem key with SQL-ish chars ('--\\x;DROP): accepted, /book + /status lookup clean
11: 20 concurrent 2-seat reserves on a 10-seat engine: exactly 5 holds, rest 4xx, conserved
12: 10 concurrent /waitlist/cancel on one entry: one 200, rest 404, no 5xx
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

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, ts=None, rid=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = ts or str(int(time.time()))
    rid = rid or uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r45-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k45-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1/2. more wrong JSON types (8098)
st1, j1 = signed(EH5, "POST", "/reserve", {"user_id": U("ss"), "idempotency_key": K("ss"), "seats": "2"})
st2, j2 = signed(EH5, "POST", "/reserve", {"user_id": U("en"), "idempotency_key": K("en"), "seats": 1, "event_id": 7})
check("seats_string", "seats as JSON string -> 400", st1 == 400, "st=%s %s" % (st1, j1.get("status")))
check("event_id_number", "event_id as number -> 400", st2 == 400, "st=%s %s" % (st2, j2.get("status")))

# ---- 3. duplicate Authorization headers
k3 = K("da")
b3 = json.dumps({"user_id": U("da"), "idempotency_key": k3, "seats": 1}).encode()
ts3, rid3 = str(int(time.time())), uuid.uuid4().hex
mac3 = mac_for(SECRET, ts3, rid3, "POST", "/reserve", KEY, b3)
st3, j3 = raw_send(EH5, "POST", "/reserve", b3, [
    ("Authorization", "Bearer key-that-does-not-exist"), ("Authorization", "Bearer "+KEY),
    ("X-Kavach-Timestamp", ts3), ("X-Kavach-Request-Id", rid3),
    ("X-Kavach-Signature", mac3), ("Content-Type", "application/json")])
check("dup_auth_header", "dup Authorization: unknown first, valid second -> 401 (first wins, fail-closed)",
      st3 == 401, "st=%s %s" % (st3, j3.get("status")))

# ---- 4. same-key reserve race (8098)
k4 = K("rk")
pre4 = seats_of(EH5)
def race4(_):
    return signed(EH5, "POST", "/reserve", {"user_id": U("rk"), "idempotency_key": k4, "seats": 1})
with ThreadPoolExecutor(max_workers=20) as ex:
    outs4 = list(ex.map(race4, range(20)))
rids4 = {j.get("reservation_id") for s, j in outs4 if s == 200}
fin4 = seats_of(EH5)
check("idem_race_same_key", "20-thread same-key reserve race: one reservation_id, held+1",
      all(s < 500 for s, _ in outs4) and len(rids4) == 1 and fin4["held"] == pre4["held"] + 1,
      "codes=%s rids=%d held %s->%s" % (dict(Counter(s for s, _ in outs4)), len(rids4), pre4["held"], fin4["held"]))

# ---- 5. future ts edges (read-only probes)
now = int(time.time())
st5a, j5a = signed(EH5, "GET", "/status?idempotency_key=" + K("f1"), ts=str(now + 290))
st5b, _ = signed(EH5, "GET", "/status?idempotency_key=" + K("f2"), ts=str(now + 320))
check("ts_future_edges", "future ts: now+290 read proceeds (404 on missing key), now+320 -> 401",
      st5a in (200, 404) and st5b == 401, "now+290=%s now+320=%s" % (st5a, st5b))

# ---- 7. /release with a booking_id (8098)
u7, k7 = U("bw"), K("bw")
sb7, jb7 = signed(EH5, "POST", "/book", {"user_id": u7, "idempotency_key": k7, "seats": 1})
bid7 = jb7.get("booking_id")
pre7 = seats_of(EH5)
st7, j7 = signed(EH5, "POST", "/release", {"reservation_id": bid7})
fin7 = seats_of(EH5)
check("release_wrong_id_type", "release with a booking_id: 4xx, no state change",
      sb7 == 200 and st7 in (400, 404) and fin7["sold"] == pre7["sold"] and fin7["free"] == pre7["free"],
      "book=%s rel=%s sold %s->%s" % (sb7, st7, pre7["sold"], fin7["sold"]))

# ---- 9. confirm with empty user_id (8098)
u9, k9 = U("eu"), K("eu")
sh9, jh9 = signed(EH5, "POST", "/reserve", {"user_id": u9, "idempotency_key": k9, "seats": 1})
pre9 = seats_of(EH5)
st9, j9 = signed(EH5, "POST", "/confirm", {"reservation_id": jh9.get("reservation_id"), "user_id": ""})
fin9 = seats_of(EH5)
sold_once = fin9["sold"] in (pre9["sold"], pre9["sold"] + 1)
check("confirm_empty_user_id", "confirm with empty user_id: no 5xx, at most one sale",
      sh9 == 200 and st9 < 500 and sold_once, "st=%s %s sold %s->%s" % (st9, j9.get("status"), pre9["sold"], fin9["sold"]))

# ---- 10. SQL-ish idem key through /book + /status
k10 = "k45';--\\x" + uuid.uuid4().hex[:4]
sb10, jb10 = signed(EH5, "POST", "/book", {"user_id": U("sq"), "idempotency_key": k10, "seats": 1})
st10, j10 = signed(EH5, "GET", "/status?idempotency_key=" + __import__("urllib.parse", fromlist=["quote"]).quote(k10, safe=""))
check("idem_key_special", "SQL-ish idem key: booked, encoded /status lookup clean (200 confirmed)",
      sb10 == 200 and st10 == 200 and j10.get("status") == "confirmed", "book=%s status=%s %s" % (sb10, st10, j10.get("status")))

# ---- 12. concurrent waitlist cancels (8092, drained first)
rids12 = []
i12 = 0
while len(rids12) < 19 and i12 < 40:
    n12d = 4 if len(rids12) < 14 else 1
    ud12 = U("dr")
    std, jd = signed(EH2, "POST", "/reserve", {"user_id": ud12, "idempotency_key": K("dr"), "seats": n12d})
    if std == 200 and jd.get("status") == "held":
        rids12.append(jd.get("reservation_id"))
    i12 += 1
u12, k12 = U("ccx"), K("ccx")
sj12, jj12 = signed(EH2, "POST", "/waitlist", {"user_id": u12, "idempotency_key": k12, "seats": 2})
wid12 = jj12.get("waitlist_id")
with ThreadPoolExecutor(max_workers=10) as ex:
    outs12 = list(ex.map(lambda _: signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": wid12}), range(10)))
codes12 = Counter(s for s, _ in outs12)
check("concurrent_cancel", "10 concurrent cancels of one entry: exactly one 200, rest 404, no 5xx",
      sj12 == 200 and all(s < 500 for s in codes12) and codes12.get(200, 0) == 1,
      "codes=%s" % dict(codes12))

# ---- 11. multi-seat race to the cap (8095, 10 seats)
def race11(i):
    return signed(EH5.replace("8098", "8095"), "POST", "/reserve",
                  {"user_id": U("mr%d" % i), "idempotency_key": K("mr%d" % i), "seats": 2})
with ThreadPoolExecutor(max_workers=20) as ex:
    outs11 = list(ex.map(race11, range(20)))
c11 = Counter((s, j.get("status")) for s, j in outs11)
fin11 = seats_of(EH5.replace("8098", "8095"))
check("multi_seat_race_cap", "20x2-seat race on a 10-seat engine: exactly 5 held results, rest sold_out/4xx, held=10 conserved",
      all(s < 500 for s, _ in outs11) and c11.get((200, "held"), 0) == 5 and fin11["held"] == 10,
      "codes=%s held=%s" % (dict(c11), fin11["held"]))

# ---- 8. Content-Length lie (8098, after races so budget is free)
b8 = json.dumps({"user_id": U("cl"), "idempotency_key": K("cl"), "seats": 1}).encode()
ts8, rid8 = str(int(time.time())), uuid.uuid4().hex
mac8 = mac_for(SECRET, ts8, rid8, "POST", "/reserve", KEY, b8)
try:
    st8, j8 = raw_send(EH5, "POST", "/reserve", b8, [
        ("Authorization", "Bearer "+KEY), ("X-Kavach-Timestamp", ts8), ("X-Kavach-Request-Id", rid8),
        ("X-Kavach-Signature", mac8), ("Content-Type", "application/json"), ("Content-Length", "1000000000")])
    st8 = st8 or 0
except Exception as e:
    st8, j8 = -1, {"_err": str(e)[:80]}
alive8 = seats_of(EH5).get("total") == 200
check("cl_overshoot_lie", "Content-Length 1e9 with a 100-byte body: request fails clean, engine stays alive",
      st8 != 500 and alive8, "st=%s alive=%s" % (st8, alive8))

# ---- 6. app hold expired by TTL, then app /api/pay (8091, ttl 30)
ah, aj = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("ttl"), "seats": 1}).encode(), {"Content-Type": "application/json"})
time.sleep(32)
ap, jp = send(APP, "POST", "/api/pay", json.dumps({"hold_id": aj.get("hold_id")}).encode(), {"Content-Type": "application/json"})
e1 = seats_of(EH1)
check("app_pay_after_ttl", "app pay after TTL expiry: no 5xx, no sale (seats freed by TTL)",
      ah == 200 and ap < 500 and e1["sold"] == 0,
      "hold=%s pay=%s %s sold=%s" % (ah, ap, jp.get("error") or jp.get("status"), e1["sold"]))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
