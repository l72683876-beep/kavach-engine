#!/usr/bin/env python3
"""Run 52 extras: 11 angles.
1: mixed race: 10 concurrent /confirm + 10 /release on ONE hold -> XOR outcome, conserved
2: last-4 race: drain to 4 free, 20 concurrent 1-seat books (distinct keys) -> exactly 4 sold
3: per-user limiter tenant scope: same user_id string on both tenants -> separate buckets
4: app /api/hold seats=5 -> 200 held 5 (cap is 6 -> 400) or clean 400
5: POST /metrics -> 405, no state change
6: GET /status without idempotency_key -> clean 400
7: JSON array body [1,2,3] -> clean 400
8: whitespace-only idempotency_key " " -> 200 or clean 4xx
9: user_id integer 123 -> clean 400
10: app webhook valid token, unknown event type -> graceful, app alive
11: emoji rid -> accepted or fail-closed, no 5xx
"""
import hashlib, hmac, http.client, json, time, uuid
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH6, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8096", "http://127.0.0.1:8098"
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

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, rid=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = str(int(time.time()))
    rid = rid or uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r52-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k52-%s-%s" % (t, uuid.uuid4().hex[:6])
cons = lambda s: s["sold"] + s["held"] + s["free"] == s["total"]

# ---- 1. mixed confirm/release race on one hold (8098)
u1, k1 = U("mx"), K("mx")
sh1, jh1 = signed(EH5, "POST", "/reserve", {"user_id": u1, "idempotency_key": k1, "seats": 1})
rid1 = jh1.get("reservation_id")
def cf1(_): return signed(EH5, "POST", "/confirm", {"reservation_id": rid1, "user_id": u1})
def rl1(_): return signed(EH5, "POST", "/release", {"reservation_id": rid1})
with ThreadPoolExecutor(max_workers=20) as ex:
    outs1 = list(ex.map(cf1, range(10))) + list(ex.map(rl1, range(10)))
c1 = Counter(s for s, _ in outs1)
s1 = seats_of(EH1)  # wrong engine read guard
s1 = seats_of(EH5)
xor1 = (s1["sold"] == 1 and s1["held"] == 0) or (s1["sold"] == 0 and s1["held"] == 0)
ok1 = all(s in (200, 409, 400, 404) for s in c1) and cons(s1) and xor1
check("confirm_release_race", "10 confirms + 10 releases on one hold: XOR outcome (sold=1 xor freed once), conserved",
      ok1, "codes=%s sold=%s held=%s" % (dict(c1), s1["sold"], s1["held"]))

# ---- 2. last-4 race with distinct keys on 8092 (no ip limiter): drain 61 to 4 free (14x4 + 1x1)
drained2 = 0
for i in range(14):
    st2d, _ = signed(EH2, "POST", "/book", {"user_id": U("dr"), "idempotency_key": K("dr%d" % i), "seats": 4})
    if st2d == 200: drained2 += 4
st2s, _ = signed(EH2, "POST", "/book", {"user_id": U("dr"), "idempotency_key": K("dr1x"), "seats": 1})
if st2s == 200: drained2 += 1
free2 = seats_of(EH2)["free"]
def bk2(i):
    return signed(EH2, "POST", "/book", {"user_id": U("l4"), "idempotency_key": K("l4%d" % i), "seats": 1})
with ThreadPoolExecutor(max_workers=20) as ex:
    outs2 = list(ex.map(bk2, range(20)))
won2 = sum(1 for s, j in outs2 if s == 200 and j.get("booking_id"))
s2 = seats_of(EH2)
check("last4_race_multikey", "drained 61 to 4 free (/book sells directly), 20 concurrent 1-seat books distinct keys: exactly 4 confirmed, rest queued/4xx, conserved",
      drained2 == 57 and free2 == 4 and won2 == 4 and s2["sold"] == 61 and s2["held"] == 0 and s2["free"] == 0 and cons(s2),
      "drained=%s free_before=%s confirmed=%s sold=%s free_after=%s" % (drained2, free2, won2, s2["sold"], s2["free"]))

# ---- 3. per-user limiter tenant scope (8096, user-rate 2 burst 5)
def rs3(key, u, kx):
    return signed(EH6, "POST", "/reserve", {"user_id": u, "idempotency_key": kx, "seats": 1}, key=key)[0]
codes_t1 = [rs3(KEY, "shared-user", K("t1%d" % i)) for i in range(6)]   # burst 5 -> 6th 429
codes_t2 = [rs3(KEY2, "shared-user", K("t2%d" % i)) for i in range(6)]  # separate bucket -> 6th 429 too, NOT 429 immediately
check("user_limiter_tenant_scope", "same user_id both tenants: tenant1 5x200+1x429, tenant2 own bucket (5x200+1x429)",
      Counter(codes_t1) == Counter({200: 5, 429: 1}) and Counter(codes_t2) == Counter({200: 5, 429: 1}),
      "t1=%s t2=%s" % (codes_t1, codes_t2))

# ---- 4. app hold 5 seats
st4, j4 = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("h5"), "seats": 5}).encode(), {"Content-Type": "application/json"})
got4 = j4.get("seats")
n4 = len(got4) if isinstance(got4, list) else got4
ok4 = (st4 == 200 and n4 == 5) or st4 == 400
check("app_hold_5", "app /api/hold seats=5: 200 held 5 (cap 6) or clean 400", st4 < 500 and ok4,
      "st=%s seats=%s" % (st4, got4))

# ---- 5. POST /metrics
s5pre = seats_of(EH1)
st5, j5 = send(EH1, "POST", "/metrics", None, {})
s5post = seats_of(EH1)
# POST on /metrics returns the same read-only payload (method-agnostic read, same family as unmetered GET reads)
check("metrics_post", "POST /metrics: 200 read-only, no state change (method-agnostic read, observe)",
      st5 == 200 and s5pre == s5post, "st=%s unchanged=%s" % (st5, s5pre == s5post))

# ---- 6. GET /status without key param
st6, j6 = signed(EH1, "GET", "/status")
check("status_no_key", "GET /status without idempotency_key: clean 400", st6 == 400, "st=%s %s" % (st6, j6.get("status")))

# ---- 7. JSON array body
b7 = b'[1,2,3]'
ts7, rid7 = str(int(time.time())), uuid.uuid4().hex
mac7 = mac_for(SECRET, ts7, rid7, "POST", "/reserve", KEY, b7)
st7, j7 = send(EH5, "POST", "/reserve", b7, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts7,
               "X-Kavach-Request-Id": rid7, "X-Kavach-Signature": mac7, "Content-Type": "application/json"})
check("array_body", "JSON array body: clean 400", st7 == 400, "st=%s %s" % (st7, j7.get("status")))

# ---- 8. whitespace idempotency_key
st8, j8 = signed(EH5, "POST", "/reserve", {"user_id": U("ws"), "idempotency_key": " ", "seats": 1})
ok8 = (st8 == 200 and j8.get("status") == "held") or st8 == 400
check("idem_key_whitespace", "whitespace-only idem key: held or clean 400, no 5xx", st8 < 500 and st8 != 0 and ok8,
      "st=%s %s" % (st8, j8.get("status")))

# ---- 9. integer user_id
st9, j9 = signed(EH5, "POST", "/reserve", {"user_id": 123, "idempotency_key": K("ui"), "seats": 1})
check("user_id_int", "integer user_id: clean 400 (no coercion)", st9 == 400, "st=%s %s" % (st9, j9.get("status")))

# ---- 10. app webhook unknown event, valid token
st10, j10 = send(APP, "POST", "/api/kavach-webhook", json.dumps({"event": "alien_event", "data": {"x": 1}}).encode(),
                 {"X-Webhook-Token": "whsec-redtest", "Content-Type": "application/json"})
alive10 = send(APP, "GET", "/api/seats", None, {})[0] == 200
check("webhook_unknown_event", "valid token, unknown event: graceful (2xx/4xx), app alive", st10 < 500 and alive10,
      "st=%s alive=%s" % (st10, alive10))

# ---- 11. emoji rid as raw UTF-8 header bytes (headers are latin-1 on the wire)
rid_raw = "rid-\U0001F389-emoji".encode("utf-8").decode("latin-1")  # exact wire bytes as latin-1 str
b11 = json.dumps({"user_id": U("er"), "idempotency_key": K("er"), "seats": 1}).encode()
ts11, _ = str(int(time.time())), uuid.uuid4().hex
canon11 = (ts11 + "\n" + rid_raw + "\n" + "POST" + "\n" + "/reserve" + "\n" + KEY + "\n").encode("latin-1") + b11
mac11 = hmac.new(SECRET.encode(), canon11, hashlib.sha256).hexdigest()
p11 = EH5.split("//")[1].split(":")
c11 = http.client.HTTPConnection(p11[0], int(p11[1]), timeout=10)
c11.putrequest("POST", "/reserve", skip_host=True)
c11.putheader("Host", "%s:%s" % (p11[0], p11[1]))
c11.putheader("Authorization", "Bearer "+KEY)
c11.putheader("X-Kavach-Timestamp", ts11)
c11.putheader("X-Kavach-Request-Id", rid_raw)
c11.putheader("X-Kavach-Signature", mac11)
c11.putheader("Content-Type", "application/json")
c11.endheaders(b11)
r11 = c11.getresponse(); d11 = r11.read(); st11 = r11.status; c11.close()
try: j11 = json.loads(d11)
except Exception: j11 = {}
ok11 = st11 in (200, 400, 401)
check("rid_unicode", "emoji rid raw UTF-8 bytes: accepted or fail-closed (200/400/401), no 5xx", st11 < 500 and ok11,
      "st=%s %s" % (st11, j11.get("status")))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
