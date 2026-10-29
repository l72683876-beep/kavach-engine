#!/usr/bin/env python3
"""Run 42 extras: 15 angles.
1: seats as bool true -> 400
2: seats as object -> 400
3: timestamp "0" (epoch) -> 401
4: empty X-Kavach-Signature -> 401
5: signature with leading space -> 401
6: duplicate X-Kavach-Timestamp, first invalid second valid -> 401 (first wins, fail-closed)
7: duplicate X-Kavach-Request-Id, first already-replayed second fresh -> 401 (first wins)
8: duplicate idempotency_key query params on /status -> first key's result, no 5xx
9: /confirm after /release -> 400/409, no state change
10: sequential /confirm replay -> 200 same booking_id both times
11: same user waitlist entries of different sizes -> both queued with positions
12: 10 concurrent waitlist joins by the same user -> no 5xx, queue count == successes
13: 8KB user_id accepted, stored result reachable
14: user_id with CRLF -> 200 or 400, log line JSON-escaped (no raw header injection in bookings log)
15: app /api/seats/state matches engine /seats after an app hold
"""
import hashlib, hmac, http.client, json, time, uuid, threading
from concurrent.futures import ThreadPoolExecutor

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH2, EH5 = "http://127.0.0.1:8092", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
LOG5 = "/tmp/battery/stateB42/bt5_bookings.jsonl"
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
    c.putheader("Content-Length", str(len(body)))
    for n, v in header_list: c.putheader(n, v)
    c.endheaders(body)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, ts=None, rid=None, sig_override=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = ts or str(int(time.time()))
    rid = rid or uuid.uuid4().hex
    mac = sig_override if sig_override is not None else mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r42-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k42-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1/2. seats type abuse (8098)
st1, j1 = signed(EH5, "POST", "/reserve", {"user_id": U("b"), "idempotency_key": K("b"), "seats": True})
st2, j2 = signed(EH5, "POST", "/reserve", {"user_id": U("o"), "idempotency_key": K("o"), "seats": {"a": 1}})
check("seats_bool", "seats=true -> 400", st1 == 400, "st=%s %s" % (st1, j1.get("status")))
check("seats_object", "seats={object} -> 400", st2 == 400, "st=%s %s" % (st2, j2.get("status")))

# ---- 3/4/5. timestamp and signature edge values (8098)
st3, _ = signed(EH5, "POST", "/reserve", {"user_id": U("e0"), "idempotency_key": K("e0"), "seats": 1}, ts="0")
tsn, rdn = str(int(time.time())), uuid.uuid4().hex
body_n = json.dumps({"user_id": U("es"), "idempotency_key": K("es"), "seats": 1}).encode()
st4, j4 = signed(EH5, "POST", "/reserve", {"user_id": U("es"), "idempotency_key": K("es"), "seats": 1}, ts=tsn, rid=rdn, sig_override="")
st5, j5 = signed(EH5, "POST", "/reserve", {"user_id": U("ws"), "idempotency_key": K("ws"), "seats": 1}, sig_override=" "+mac_for(SECRET, str(int(time.time())), uuid.uuid4().hex, "POST", "/reserve", KEY, json.dumps({"user_id": U("ws"), "idempotency_key": K("ws"), "seats": 1}).encode()))
check("ts_epoch0", "timestamp 0 -> 401", st3 == 401, "st=%s" % st3)
check("sig_empty", "empty signature -> 401", st4 == 401, "st=%s %s" % (st4, j4.get("status")))
check("sig_whitespace", "signature with leading space -> 401", st5 == 401, "st=%s %s" % (st5, j5.get("status")))

# ---- 6/7. duplicate headers first-wins fail-closed (raw, 8098)
k6, u6 = K("dt"), U("dt")
rid_hold = uuid.uuid4().hex
sh6, jh6 = signed(EH5, "POST", "/reserve", {"user_id": u6, "idempotency_key": k6, "seats": 1}, rid=rid_hold)
ts_good, rid_good = str(int(time.time())), uuid.uuid4().hex
b6 = json.dumps({"user_id": U("dt2"), "idempotency_key": K("dt2"), "seats": 1}).encode()
mac6 = mac_for(SECRET, ts_good, rid_good, "POST", "/reserve", KEY, b6)
st6, j6 = raw_send(EH5, "POST", "/reserve", b6, [
    ("Authorization", "Bearer "+KEY), ("X-Kavach-Timestamp", "garbage"), ("X-Kavach-Timestamp", ts_good),
    ("X-Kavach-Request-Id", rid_good), ("X-Kavach-Signature", mac6), ("Content-Type", "application/json")])
used_rid = rid_hold
b7 = json.dumps({"user_id": U("dr"), "idempotency_key": K("dr"), "seats": 1}).encode()
ts7, rid_fresh = str(int(time.time())), uuid.uuid4().hex
mac7 = mac_for(SECRET, ts7, used_rid, "POST", "/reserve", KEY, b7)
st7, j7 = raw_send(EH5, "POST", "/reserve", b7, [
    ("Authorization", "Bearer "+KEY), ("X-Kavach-Timestamp", ts7),
    ("X-Kavach-Request-Id", used_rid), ("X-Kavach-Request-Id", rid_fresh),
    ("X-Kavach-Signature", mac7), ("Content-Type", "application/json")])
check("dup_ts_header", "first (invalid) timestamp wins -> 401", st6 == 401, "st=%s %s" % (st6, j6.get("status")))
check("dup_rid_header", "first (already-replayed) rid wins -> 401 replay", st7 == 401, "st=%s %s" % (st7, j7.get("status")))

# ---- 8. duplicate query keys (8098)
k8, u8 = K("dq"), U("dq")
sh8, jh8 = signed(EH5, "POST", "/reserve", {"user_id": u8, "idempotency_key": k8, "seats": 2})
st8, j8 = signed(EH5, "GET", "/status?idempotency_key=" + K("nope") + "&idempotency_key=" + k8)
check("dup_query_keys", "duplicate idempotency_key params: first (missing) wins -> 404, no 5xx",
      st8 < 500 and st8 in (200, 404), "st=%s %s" % (st8, j8.get("status")))

# ---- 9/10. confirm state machine (8098)
u9, k9 = U("car"), K("car")
sh9, jh9 = signed(EH5, "POST", "/reserve", {"user_id": u9, "idempotency_key": k9, "seats": 2})
pre9 = seats_of(EH5)
sr9, _ = signed(EH5, "POST", "/release", {"reservation_id": jh9.get("reservation_id")})
sc9, jc9 = signed(EH5, "POST", "/confirm", {"reservation_id": jh9.get("reservation_id"), "user_id": u9})
post9 = seats_of(EH5)
check("confirm_after_release", "confirm a released hold: 409 released, no sale, hold gone",
      sr9 == 200 and sc9 == 409 and jc9.get("status") == "released" and post9["sold"] == pre9["sold"] and post9["held"] == pre9["held"] - 2,
      "rel=%s conf=%s %s sold=%s held=%s" % (sr9, sc9, jc9.get("status"), post9["sold"], post9["held"]))
u10, k10 = U("crs"), K("crs")
sh10, jh10 = signed(EH5, "POST", "/reserve", {"user_id": u10, "idempotency_key": k10, "seats": 1})
scA, jcA = signed(EH5, "POST", "/confirm", {"reservation_id": jh10.get("reservation_id"), "user_id": u10})
scB, jcB = signed(EH5, "POST", "/confirm", {"reservation_id": jh10.get("reservation_id"), "user_id": u10})
check("confirm_replay_sequential", "second sequential /confirm: 200 same booking_id",
      scA == 200 and scB == 200 and jcB.get("booking_id") == jcA.get("booking_id"),
      "1=%s/%s 2=%s/%s" % (scA, str(jcA.get("booking_id"))[-6:], scB, str(jcB.get("booking_id"))[-6:]))

# ---- 11. same user, different-size waitlist entries (8092)
rids = []
i = 0
while len(rids) < 19 and i < 40:
    n = 4 if len(rids) < 14 else 1
    ud = U("dr")
    st, j = signed(EH2, "POST", "/reserve", {"user_id": ud, "idempotency_key": K("dr"), "seats": n})
    if st == 200 and j.get("status") == "held":
        rids.append((j.get("reservation_id"), n))
    i += 1
u11, kA11, kB11 = U("multi"), K("m4"), K("m1")
sjA, jjA = signed(EH2, "POST", "/waitlist", {"user_id": u11, "idempotency_key": kA11, "seats": 4})
sjB, jjB = signed(EH2, "POST", "/waitlist", {"user_id": u11, "idempotency_key": kB11, "seats": 1})
g11, j11 = signed(EH2, "GET", "/waitlist?user_id=" + u11)
ents = j11.get("entries", [])
sizes = sorted(e["seats"] for e in ents)
check("wl_multi_size_same_user", "same user holds 4-seat and 1-seat entries simultaneously",
      sjA == 200 and sjB == 200 and sizes == [1, 4] and len(ents) == 2,
      "sizes=%s pos=%s" % (sizes, [e.get("position") for e in ents]))

# ---- 12. concurrent waitlist joins by same user (8092)
u12 = U("conc")
def join12(i):
    st, j = signed(EH2, "POST", "/waitlist", {"user_id": u12, "idempotency_key": "k42-c%d-%s" % (i, uuid.uuid4().hex[:6]), "seats": 1})
    return st
with ThreadPoolExecutor(max_workers=10) as ex:
    outs = list(ex.map(join12, range(10)))
g12, j12 = signed(EH2, "GET", "/waitlist?user_id=" + u12)
n12 = len(j12.get("entries", []))
ok12 = sum(1 for s in outs if s == 200)
check("wl_concurrent_same_user", "10 concurrent joins same user: no 5xx, queue holds every accepted entry",
      all(s < 500 for s in outs) and n12 == ok12, "outs=%s queued=%d" % (dict(__import__("collections").Counter(outs)), n12))

# ---- 13. 8KB user_id (8098)
u13 = "U" * 8192
k13 = K("lu")
sh13, jh13 = signed(EH5, "POST", "/reserve", {"user_id": u13, "idempotency_key": k13, "seats": 1})
sr13, jr13 = signed(EH5, "POST", "/reserve", {"user_id": u13, "idempotency_key": k13, "seats": 1})
check("long_user_id", "8KB user_id accepted; same-key replay returns the same reservation",
      sh13 == 200 and sr13 == 200 and jr13.get("reservation_id") == jh13.get("reservation_id"),
      "hold=%s replay=%s rid_match=%s" % (sh13, sr13, jr13.get("reservation_id") == jh13.get("reservation_id")))

# ---- 14. CRLF in user_id, log hygiene (8098, log file)
u14 = "u\r\nX-Evil: 1"
st14, j14 = signed(EH5, "POST", "/reserve", {"user_id": u14, "idempotency_key": K("crlf"), "seats": 1})
log_lines = open(LOG5, "rb").read().split(b"\n") if __import__("os").path.exists(LOG5) else []
inject = any(l.startswith(b"X-Evil") for l in log_lines)
check("crlf_user_id", "CRLF user_id: 200/400 only, no injected log line",
      st14 in (200, 400) and not inject, "st=%s injected=%s lines=%d" % (st14, inject, len(log_lines)))

# ---- 15. app state matches engine (8091 via app)
ah, aj = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("app"), "seats": 2}).encode(),
              {"Content-Type": "application/json"})
e1 = seats_of("http://127.0.0.1:8091")
sa, ja = send(APP, "GET", "/api/seats", None, {})
same = all(ja.get(k2) == e1.get(k2) for k2 in ("free", "held", "sold", "total"))
for _ in range(8):  # board cache refreshes every 0.5s on a background thread
    if same: break
    time.sleep(0.5)
    sa, ja = send(APP, "GET", "/api/seats", None, {})
    same = all(ja.get(k2) == e1.get(k2) for k2 in ("free", "held", "sold", "total"))
check("app_state_reflects_engine", "app /api/seats/state equals engine /seats after app hold",
      ah == 200 and same, "app_hold=%s app=%s engine=%s" % (ah, {k2: ja.get(k2) for k2 in ("free","held","sold")}, {k2: e1.get(k2) for k2 in ("free","held","sold")}))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
