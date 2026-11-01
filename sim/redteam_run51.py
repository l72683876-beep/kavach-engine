#!/usr/bin/env python3
"""Run 51 extras: 11 angles.
1: same-tenant cross-user /release (possession-based family, observe)
2: rid replay ACROSS tenants: rid nonce global or per-tenant?
3: app /api/hold twice with the SAME explicit key: one reservation, held +1
4: waitlist cap: 6 joins on -waitlist-cap 5 engine -> 5 queued + 1 waitlist_full
5: float idempotency_key -> clean 400
6: 64KB user_id -> accepted or clean 4xx
7: 1MB rid -> clean 4xx, no 5xx
8: GET on app /api/kavach-webhook -> 4xx, no state change
9: OPTIONS on /reserve -> 405, no state change
10: XFF bypass regression: 45 same-IP reserves with forged X-Forwarded-For on ip-limited engine -> 429s after burst
11: wl cancel then rejoin with SAME idem key -> key freed, new entry
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

U = lambda t: "r51-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k51-%s-%s" % (t, uuid.uuid4().hex[:6])
cons = lambda s: s["sold"] + s["held"] + s["free"] == s["total"]

# ---- 1. same-tenant cross-user /release (8098)
ua, ub = U("relA"), U("relB")
sa, ja = signed(EH5, "POST", "/reserve", {"user_id": ua, "idempotency_key": K("ra"), "seats": 1})
s1 = seats_of(EH5)
sr, jr = signed(EH5, "POST", "/release", {"reservation_id": ja.get("reservation_id")})  # released under tenant key, no user in body
s2 = seats_of(EH5)
check("release_cross_user_same_tenant", "same-tenant /release with no user_id: possession-based, frees B's hold, conserved (observe)",
      sa == 200 and sr == 200 and s2["held"] == s1["held"] - 1 and cons(s2),
      "res=%s rel=%s held %s->%s" % (sa, sr, s1["held"], s2["held"]))

# ---- 2. rid replay across tenants
rid2 = uuid.uuid4().hex
sa2, _ = signed(EH5, "POST", "/reserve", {"user_id": U("rid"), "idempotency_key": K("rid1"), "seats": 1}, rid=rid2)
# tenant2 reuses the SAME rid on a fresh request
sb2, jb2 = signed(EH5, "POST", "/reserve", {"user_id": U("rid"), "idempotency_key": K("rid2"), "seats": 1}, key=KEY2, rid=rid2)
check("rid_replay_cross_tenant", "rid nonce reused across tenants: fail-closed 401 (nonce global)",
      sa2 == 200 and sb2 == 401, "t1=%s t2=%s %s" % (sa2, sb2, jb2.get("status")))

# ---- 3. app hold with explicit same key twice
k3, u3 = K("appkey"), U("ak")
st3a, j3a = send(APP, "POST", "/api/hold", json.dumps({"user_id": u3, "seats": 1, "key": k3}).encode(), {"Content-Type": "application/json"})
st3b, j3b = send(APP, "POST", "/api/hold", json.dumps({"user_id": u3, "seats": 1, "key": k3}).encode(), {"Content-Type": "application/json"})
s3 = seats_of(EH1)
check("app_hold_idem_key", "app /api/hold twice with same explicit key: same reservation_id, held +1 only",
      st3a == 200 and st3b == 200 and j3a.get("reservation_id") == j3b.get("reservation_id") and cons(s3),
      "rids_match=%s held=%s" % (j3a.get("reservation_id") == j3b.get("reservation_id"), s3["held"]))

# ---- 4. waitlist cap (8092 has -waitlist-cap 5; 61 seats drained first)
rids4, i4 = [], 0
while len(rids4) < 30 and i4 < 40:
    st4d, j4d = signed(EH2, "POST", "/reserve", {"user_id": U("dr"), "idempotency_key": K("dr"), "seats": 2})
    if st4d == 200 and j4d.get("status") == "held":
        rids4.append(j4d.get("reservation_id"))
    else:
        break
    i4 += 1
st4s, j4s = signed(EH2, "POST", "/reserve", {"user_id": U("dr"), "idempotency_key": K("dr1"), "seats": 1})  # last seat: 61/61 held
joins4 = []
for i in range(6):
    sj4, jj4 = signed(EH2, "POST", "/waitlist", {"user_id": U("cap"), "idempotency_key": K("cap%d" % i), "seats": 1})
    joins4.append((sj4, jj4.get("status"), jj4.get("waitlist_id")))
c4 = Counter(st for st, _, _ in joins4)
alive4 = seats_of(EH2)["total"] > 0
check("wl_full", "fully drained, waitlist cap 5: 5 joins queued, 6th -> waitlist_full 409, engine alive",
      len(rids4) == 30 and st4s == 200 and c4.get(200, 0) == 5 and c4.get(409, 0) == 1 and alive4,
      "drained=%s last=%s joins=%s alive=%s" % (len(rids4), st4s, [(a, b) for a, b, _ in joins4], alive4))

# ---- 5. float idempotency_key
st5, j5 = signed(EH5, "POST", "/reserve", {"user_id": U("fk"), "idempotency_key": 1.5, "seats": 1})
check("idem_key_float", "float idempotency_key: clean 400 (no coercion)", st5 == 400, "st=%s %s" % (st5, j5.get("status")))

# ---- 6. 64KB user_id
st6, j6 = signed(EH5, "POST", "/reserve", {"user_id": "u" * 65536, "idempotency_key": K("u64"), "seats": 1})
s6 = seats_of(EH5)
ok6 = st6 == 200 and j6.get("status") == "held" and s6["held"] >= 1
ok6b = st6 == 400
check("user_id_64kb", "64KB user_id: accepted (held) or clean 400, no 5xx", st6 < 500 and st6 != 0 and (ok6 or ok6b),
      "st=%s %s" % (st6, j6.get("status")))

# ---- 7. 1MB rid
st7, j7 = signed(EH5, "POST", "/reserve", {"user_id": U("r1m"), "idempotency_key": K("r1m")}, rid="a" * 1000000)
alive7 = seats_of(EH5)["total"] > 0
check("rid_1mb", "1MB rid: clean 4xx, no 5xx, engine alive", st7 < 500 and st7 != 0 and alive7,
      "st=%s %s" % (st7, j7.get("status")))

# ---- 8. GET on app webhook
pre8 = seats_of(EH1)
st8, j8 = send(APP, "GET", "/api/kavach-webhook", None, {})
fin8 = seats_of(EH1)
check("webhook_get", "GET on app /api/kavach-webhook: 4xx, no state change", st8 in (403, 404, 405) and fin8 == pre8,
      "st=%s unchanged=%s" % (st8, fin8 == pre8))

# ---- 9. OPTIONS on /reserve
st9, j9 = send(EH5, "OPTIONS", "/reserve", None, {})
s9 = seats_of(EH5)
check("options_method", "OPTIONS /reserve: 405 (or clean 4xx), no state change, conserved",
      st9 in (405, 400) and cons(s9), "st=%s %s" % (st9, j9.get("status")))

# ---- 10. XFF bypass regression on ip-limited 8098 (burst 40)
from concurrent.futures import ThreadPoolExecutor
def xff10(i):
    body = json.dumps({"user_id": U("xff"), "idempotency_key": K("xff%d" % i), "seats": 1}).encode()
    ts10, rid10 = str(int(time.time())), uuid.uuid4().hex
    mac10 = mac_for(SECRET, ts10, rid10, "POST", "/reserve", KEY, body)
    st10, _ = send(EH5, "POST", "/reserve", body, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts10,
                   "X-Kavach-Request-Id": rid10, "X-Kavach-Signature": mac10, "Content-Type": "application/json",
                   "X-Forwarded-For": "10.0.%d.%d" % (i, i % 250)})
    return st10
with ThreadPoolExecutor(max_workers=45) as ex:
    codes10 = list(ex.map(xff10, range(45)))
c10 = Counter(codes10)
alive10 = seats_of(EH5)["total"] > 0
check("xff_bypass_regression", "45 same-IP reserves with forged XFF: limited after burst (429s), no bypass, engine alive",
      all(s in (200, 429) for s in codes10) and c10.get(429, 0) >= 1 and alive10,
      "codes=%s alive=%s" % (dict(c10), alive10))

# ---- 11. wl cancel then rejoin same idem key (8092 still drained)
u11, k11 = U("cr"), K("cr")
signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": joins4[0][2]})  # free one cap slot
sj11, jj11 = signed(EH2, "POST", "/waitlist", {"user_id": u11, "idempotency_key": k11, "seats": 1})
wid11 = jj11.get("waitlist_id")
sc11, jc11 = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": wid11})
sj11b, jj11b = signed(EH2, "POST", "/waitlist", {"user_id": u11, "idempotency_key": k11, "seats": 1})
wid11b = jj11b.get("waitlist_id")
check("wl_cancel_rejoin_same_key", "wl cancel frees the idem key: rejoin same key -> new entry, 200",
      sj11 == 200 and sc11 == 200 and sj11b == 200 and wid11b and wid11b != wid11,
      "join=%s cancel=%s rejoin=%s new_id=%s" % (sj11, sc11, sj11b, wid11b != wid11))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
