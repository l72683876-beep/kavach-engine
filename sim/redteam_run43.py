#!/usr/bin/env python3
"""Run 43 extras: 14 angles.
1: idempotency_key as array -> 400
2: user_id as number -> 400
3: over-send body (Content-Length smaller than actual body) -> 400 (regression of run-32 fix)
4: GET /status carrying a body with MAC over that body: no 5xx (read fail-closed or accepted)
5: idem key with '/' and space, /status lookup URL-encoded -> 200 found
6: webhook payload from a /book contains no HMAC secret
7: 20-thread mixed reserve/confirm/release chaos: seats conserved, no 5xx
8: Authorization with trailing space in key -> 401
9: empty request-id: no 5xx; if accepted, reuse -> 401 replay
10: 1MB whitespace-padded JSON body: no 5xx, conserved
11: timestamp now-320 -> 401 (outside window)
12: timestamp now-290 -> authenticated read works (404 on missing key)
13: waitlist join idempotent replay: same key returns same waitlist_id, one entry
14: app /api/seats/state bitmap marks exactly the held seats after an app hold
"""
import hashlib, hmac, http.client, json, time, uuid, random
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
WLLOG = "examples/demo-app/webhooks.jsonl"
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

U = lambda t: "r43-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k43-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1/2. wrong JSON types (8098)
st1, j1 = signed(EH5, "POST", "/reserve", {"user_id": U("ka"), "idempotency_key": ["x"], "seats": 1})
st2, j2 = signed(EH5, "POST", "/reserve", {"user_id": 12345, "idempotency_key": K("un"), "seats": 1})
check("idem_key_array", "idempotency_key as array -> 400", st1 == 400, "st=%s %s" % (st1, j1.get("status")))
check("user_id_number", "user_id as number -> 400", st2 == 400, "st=%s %s" % (st2, j2.get("status")))

# ---- 3. over-send body (declare CL smaller than actual)
b3 = json.dumps({"user_id": U("ov"), "idempotency_key": K("ov"), "seats": 1}).encode()
ts3, rid3 = str(int(time.time())), uuid.uuid4().hex
mac3 = mac_for(SECRET, ts3, rid3, "POST", "/reserve", KEY, b3)
st3, j3 = raw_send(EH5, "POST", "/reserve", b3, [
    ("Authorization", "Bearer "+KEY), ("X-Kavach-Timestamp", ts3), ("X-Kavach-Request-Id", rid3),
    ("X-Kavach-Signature", mac3), ("Content-Type", "application/json"), ("Content-Length", "10")])
check("oversend_body", "Content-Length 10 with a larger real body: server reads only CL bytes, full-body MAC fails -> 401 fail-closed", st3 == 401,
      "st=%s %s" % (st3, j3.get("status")))

# ---- 4. GET with a body, MAC covers the body
gb = b"unexpected-body"
uri4 = "/status?idempotency_key=" + K("gb")
ts4, rid4 = str(int(time.time())), uuid.uuid4().hex
mac4 = mac_for(SECRET, ts4, rid4, "GET", uri4, KEY, gb)
st4, j4 = send(EH5, "GET", uri4, gb, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts4,
               "X-Kavach-Request-Id": rid4, "X-Kavach-Signature": mac4, "Content-Type": "application/json"})
check("get_with_body", "GET with body: no 5xx, engine alive", st4 < 500 and st4 != 0,
      "st=%s %s" % (st4, j4.get("status")))

# ---- 5. URL-encoded query key lookup
import urllib.parse
k5 = "a/b c" + uuid.uuid4().hex[:4]
sh5, jh5 = signed(EH5, "POST", "/book", {"user_id": U("eq"), "idempotency_key": k5, "seats": 1})
st5, j5 = signed(EH5, "GET", "/status?idempotency_key=" + urllib.parse.quote(k5, safe=""))
check("encoded_query_key", "key with / and space booked via /book: encoded /status lookup finds it (200)",
      sh5 == 200 and st5 == 200 and j5.get("status") == "confirmed", "book=%s status=%s %s" % (sh5, st5, j5.get("status")))

# ---- 8. Authorization trailing space
st8, j8 = signed(EH5, "POST", "/reserve", {"user_id": U("ts"), "idempotency_key": K("ts"), "seats": 1}, key=KEY+" ")
check("auth_trailing_space", "key with trailing space -> 401", st8 == 401, "st=%s %s" % (st8, j8.get("status")))

# ---- 9. empty request-id
rid9 = ""
k9 = K("er")
b9 = json.dumps({"user_id": U("er"), "idempotency_key": k9, "seats": 1}).encode()
ts9 = str(int(time.time()))
mac9 = mac_for(SECRET, ts9, rid9, "POST", "/reserve", KEY, b9)
st9, j9 = send(EH5, "POST", "/reserve", b9, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts9,
               "X-Kavach-Request-Id": rid9, "X-Kavach-Signature": mac9, "Content-Type": "application/json"})
if st9 == 200:
    mac9b = mac_for(SECRET, str(int(time.time())), rid9, "POST", "/reserve", KEY, b9)
    st9b, j9b = send(EH5, "POST", "/reserve", b9, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": str(int(time.time())),
                     "X-Kavach-Request-Id": rid9, "X-Kavach-Signature": mac9b, "Content-Type": "application/json"})
    ok9 = st9b == 401
else:
    st9b, ok9 = None, True
check("empty_rid", "empty request-id: no 5xx; if accepted, reuse is replay-rejected",
      st9 < 500 and st9 != 0 and ok9, "first=%s %s second=%s" % (st9, j9.get("status"), st9b))

# ---- 10. 1MB whitespace-padded body
pad = b" " * 1000000
b10 = b'{"user_id":"' + U("pad").encode() + b'","seats":1,' + pad + b'"idempotency_key":"' + K("pad").encode() + b'"}'
ts10, rid10 = str(int(time.time())), uuid.uuid4().hex
mac10 = mac_for(SECRET, ts10, rid10, "POST", "/reserve", KEY, b10)
pre10 = seats_of(EH5)
st10, j10 = send(EH5, "POST", "/reserve", b10, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts10,
                 "X-Kavach-Request-Id": rid10, "X-Kavach-Signature": mac10, "Content-Type": "application/json"})
post10 = seats_of(EH5)
ok10 = st10 < 500 and (st10 == 400 or post10["held"] == pre10["held"] + 1)
check("padded_body_1mb", "1MB padded JSON: no 5xx, conserved if accepted", ok10,
      "st=%s %s held %s->%s" % (st10, j10.get("status"), pre10["held"], post10["held"]))

# ---- 11/12. timestamp window edges (read-only probes on /status)
now = int(time.time())
st11, _ = signed(EH5, "GET", "/status?idempotency_key=" + K("old"), ts=str(now - 320))
st12, j12 = signed(EH5, "GET", "/status?idempotency_key=" + K("rec"), ts=str(now - 290))
check("ts_window_old", "timestamp now-320 -> 401", st11 == 401, "st=%s" % st11)
check("ts_window_recent", "timestamp now-290 inside window: authenticated read proceeds (404 on missing key)",
      st12 in (200, 404), "st=%s %s" % (st12, j12.get("status")))

# ---- 13. waitlist join idempotent replay (8092, drained so joins stay queued)
rids13 = []
i13 = 0
while len(rids13) < 19 and i13 < 40:
    n13d = 4 if len(rids13) < 14 else 1
    ud13 = U("dr")
    std, jd = signed(EH2, "POST", "/reserve", {"user_id": ud13, "idempotency_key": K("dr"), "seats": n13d})
    if std == 200 and jd.get("status") == "held":
        rids13.append(jd.get("reservation_id"))
    i13 += 1
u13, k13 = U("wr"), K("wr")
sj, jj = signed(EH2, "POST", "/waitlist", {"user_id": u13, "idempotency_key": k13, "seats": 2})
sr, jr = signed(EH2, "POST", "/waitlist", {"user_id": u13, "idempotency_key": k13, "seats": 2})
g13, j13 = signed(EH2, "GET", "/waitlist?user_id=" + u13)
n13 = len(j13.get("entries", []))
check("wl_idem_replay", "waitlist same-key replay: same waitlist_id, exactly one entry",
      sj == 200 and sr == 200 and jr.get("waitlist_id") == jj.get("waitlist_id") and n13 == 1,
      "rid_match=%s entries=%d" % (jr.get("waitlist_id") == jj.get("waitlist_id"), n13))

# ---- 7. mixed chaos conservation (8098)
def chaos(i):
    u, k = U("ch%d" % i), K("ch%d" % i)
    n = random.randint(1, 3)
    st, j = signed(EH5, "POST", "/reserve", {"user_id": u, "idempotency_key": k, "seats": n})
    if st != 200 or j.get("status") != "held": return st
    r = random.random()
    if r < 0.5:
        return signed(EH5, "POST", "/confirm", {"reservation_id": j.get("reservation_id"), "user_id": u})[0]
    if r < 0.8:
        return signed(EH5, "POST", "/release", {"reservation_id": j.get("reservation_id")})[0]
    return st
random.seed(43)
with ThreadPoolExecutor(max_workers=20) as ex:
    outs = list(ex.map(chaos, range(20)))
fin = seats_of(EH5)
inv_ok = fin["free"] + fin["held"] + fin["sold"] == fin["total"]
check("chaos_mixed_conservation", "20-thread mixed ops: no 5xx, free+held+sold == total",
      all(s < 500 for s in outs) and inv_ok, "outs=%s state=%s" % (dict(Counter(outs)), fin))

# ---- 6. webhook payload must not carry the HMAC secret
u6, k6 = U("wh"), K("wh")
sb, jb = signed(EH1, "POST", "/book", {"user_id": u6, "idempotency_key": k6, "seats": 2})
time.sleep(1.5)
lines = open(WLLOG).read().strip().split("\n") if __import__("os").path.exists(WLLOG) else []
last = lines[-1] if lines else ""
leak = "testsecret" in last
check("webhook_no_secret_leak", "/book webhook delivered, payload has no HMAC secret",
      sb == 200 and last != "" and not leak, "book=%s webhook_lines=%d leak=%s tail=%s" % (sb, len(lines), leak, last[-120:]))

# ---- 14. app bitmap marks held seats
ah, aj = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("bm"), "seats": 2}).encode(), {"Content-Type": "application/json"})
time.sleep(1.2)
ss, js = send(APP, "GET", "/api/seats/state", None, {})
states = js.get("states", "")
n_held = states.count("1")
e1 = seats_of(EH1)
check("app_bitmap_held", "app bitmap: exactly 2 seats marked held after app hold of 2",
      ah == 200 and n_held == 2 and e1["held"] == 2, "app_hold=%s bitmap_1s=%d engine_held=%s" % (ah, n_held, e1["held"]))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
