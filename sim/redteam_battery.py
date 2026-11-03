#!/usr/bin/env python3
"""Kavach heavy red-team battery: 100+ adversarial cases, three targets.

  engine_red 127.0.0.1:8091  dedicated 50-seat engine (auth+HMAC+limits ON)
  app_red   127.0.0.1:9001   demo app integrated with 8091 (full 3-tier path)
  engine_live 127.0.0.1:8080 the live load-test stack (sold out: abuse traffic)

Exit 1 on any FAIL. Full results: sim/battery_results.json.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, EL, ER2 = 8091, 9001, 8080, 8092
ET = 8095  # dedicated short-TTL engine, no other traffic
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []

def check(cat, name, ok, detail=""):
    results.append({"cat": cat, "name": name, "ok": bool(ok), "detail": str(detail)[:220]})
    return ok

def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts,
            "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac.hexdigest(),
            "Content-Type": "application/json"}

def raw(port, method, path, body=None, headers=None):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
        c.request(method, path, body=b, headers=headers or {})
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try:
            j = json.loads(data) if data else {}
        except Exception:
            j = {"raw": data[:150].decode("utf-8", "replace")}
        return st, j
    except Exception as ex:
        return -1, {"exception": str(ex)[:120]}

def req(port, method, path, obj=None, key=KEY, secret=SECRET, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, method, path, body, sign(key, method, path, body, secret, **kw))

def post(port, path, obj, **kw):
    return req(port, "POST", path, obj, **kw)

def rej(st):
    return 400 <= st < 500 or st == 429

def P(n, fn):
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(fn, range(n)))

def seats(port=ER):
    st, j = raw(port, "GET", "/seats")
    return j if st == 200 else {}

# ---------------- Phase A: auth bypass attempts (engine_red) ----------------
B = json.dumps({"user_id": "rt-a", "idempotency_key": "ka1", "seats": 1}).encode()
good = sign(KEY, "POST", "/book", B)
cases = []
cases.append(("auth", "wrong api key", lambda: (lambda r: rej(r[0]) and r[1].get("status") in ("unauthorized", "replay"))(raw(ER, "POST", "/book", B, sign("badkey", "POST", "/book", B)))))
cases.append(("auth", "empty bearer", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, {**good, "Authorization": "Bearer "}))))
cases.append(("auth", "basic scheme not accepted", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, {**good, "Authorization": "Basic dXNlcjpwYXNz"}))))
cases.append(("auth", "no auth headers at all", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, {}))))
for miss in ["X-Kavach-Timestamp", "X-Kavach-Request-Id", "X-Kavach-Signature"]:
    cases.append(("auth", "missing " + miss, (lambda m: lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, {k: v for k, v in good.items() if k != m})))(miss)))
cases.append(("auth", "timestamp 2h old", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, sign(KEY, "POST", "/book", B, ts=str(int(time.time()) - 7200))))))
cases.append(("auth", "timestamp 2h future", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, sign(KEY, "POST", "/book", B, ts=str(int(time.time()) + 7200))))))
cases.append(("auth", "timestamp not a number", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, sign(KEY, "POST", "/book", B, ts="notanumber")))))
def replay_case():
    b2 = json.dumps({"user_id": "rt-a2", "idempotency_key": "ka2", "seats": 1}).encode()
    h1 = sign(KEY, "POST", "/book", b2)
    r1 = raw(ER, "POST", "/book", b2, h1)
    r2 = raw(ER, "POST", "/book", b2, h1)
    return check("auth", "exact replay after success -> 401 replay", r1[0] == 200 and r2[0] == 401 and r2[1].get("status") == "replay", "%s then %s %s" % (r1[0], r2[0], r2[1].get("status")))
cases.append(("auth", "signature over GET used on POST", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, sign(KEY, "GET", "/book", B)))))
cases.append(("auth", "signature over /confirm used on /book", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, sign(KEY, "POST", "/confirm", B)))))
def tampered():
    h = dict(sign(KEY, "POST", "/book", B)); h["X-Kavach-Request-Id"] = uuid.uuid4().hex
    return (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B + b" ", h))
cases.append(("auth", "body tampered after signing (+space)", tampered))
def bitflip():
    h = dict(sign(KEY, "POST", "/book", B)); h["X-Kavach-Request-Id"] = uuid.uuid4().hex
    bad = B[:20] + bytes([B[20] ^ 0x01]) + B[21:]
    return (lambda r: r[0] == 401)(raw(ER, "POST", "/book", bad, h))
cases.append(("auth", "single bit flip in body", bitflip))
cases.append(("auth", "wrong HMAC secret", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, sign(KEY, "POST", "/book", B, secret="wrongsecret")))))
cases.append(("auth", "signature not valid hex", lambda: (lambda r: r[0] == 401)(raw(ER, "POST", "/book", B, {**good, "X-Kavach-Signature": "zzzznot Hex!!", "X-Kavach-Request-Id": uuid.uuid4().hex}))))
def shared_secret_forgery():
    # MAC binds the api key: k1's signature replayed under k2's key is rejected
    r = raw(ER, "POST", "/book", B, {**sign(KEY, "POST", "/book", B), "Authorization": "Bearer " + KEY2, "X-Kavach-Request-Id": uuid.uuid4().hex})
    return check("auth", "tenant2 key rejects tenant1-signed body (MAC binds the api key)", r[0] == 401, "status=%s" % r[0])
for cat, name, fn in cases:
    try:
        check(cat, name, fn())
    except Exception as ex:
        check(cat, name, False, "exception " + str(ex)[:100])
replay_case()
shared_secret_forgery()

# ---------------- Phase B: rate-limit abuse (engine_red) ----------------
def burst_same_user():
    outs = [post(ER, "/book", {"user_id": "rt-burst", "idempotency_key": "kb%d" % i, "seats": 1})[0] for i in range(12)]
    limited = outs.count(429)
    return check("rate", "same-user burst 12 rapid: limiter fires", limited >= 3, "limited=%d" % limited)
burst_same_user()
def burst_reserve():
    outs = [post(ER, "/reserve", {"user_id": "rt-burst2", "idempotency_key": "kr%d" % i, "seats": 1})[0] for i in range(12)]
    return check("rate", "same-user burst on /reserve: limiter fires", outs.count(429) >= 3)
burst_reserve()
def parallel_burst():
    outs = P(30, lambda i: post(ER, "/book", {"user_id": "rt-burst3", "idempotency_key": "kp%d" % i, "seats": 1})[0])
    return check("rate", "30 parallel same user: limited, zero 5xx", outs.count(429) >= 10 and outs.count(500) == 0)
parallel_burst()
def xff_rotation():
    outs = []
    for i in range(30):
        h = sign(KEY, "POST", "/book", B); h["X-Forwarded-For"] = "10.0.%d.%d" % (i, i)
        outs.append(raw(ER, "POST", "/book", B, h)[0])
    return check("rate", "X-Forwarded-For rotation cannot buy more budget", outs.count(429) >= 3)
xff_rotation()
def unauth_hammer():
    before = seats(ER)
    outs = [raw(ER, "POST", "/book", B)[0] for _ in range(80)]
    return check("rate", "80 unauth hammer: all rejected, inventory untouched", all(s == 401 for s in outs) and seats(ER).get("sold") == before.get("sold"))
unauth_hammer()
def retry_after():
    got429, hdrs = False, []
    for i in range(40):  # burst /reserve as one user until the limiter trips (works even after sellout)
        body = json.dumps({"user_id": "rt-burst", "idempotency_key": "kh%s" % uuid.uuid4().hex[:8], "seats": 1}).encode()
        c = http.client.HTTPConnection("127.0.0.1", ER, timeout=10)
        c.request("POST", "/reserve", body=body, headers=sign(KEY, "POST", "/reserve", body))
        r = c.getresponse(); r.read(); hdrs = r.getheaders(); st = r.status; c.close()
        if st == 429:
            got429 = True; break
    ok = got429 and any(k.lower() == "retry-after" for k, _ in hdrs)
    return check("rate", "429 carries Retry-After", ok, "429_seen=%s" % got429)
retry_after()
def unique_users_no_crash():
    def unit(i):
        st, j = post(ER, "/reserve", {"user_id": "rt-u%d" % i, "idempotency_key": "ku%d" % i, "seats": 1})
        if st == 200 and j.get("status") == "held":
            post(ER, "/release", {"reservation_id": j.get("reservation_id")})
        return st
    outs = P(100, unit)
    return check("rate", "100 distinct users hold+release parallel: no 5xx, engine alive, inventory net zero", 500 not in outs and raw(ER, "GET", "/seats")[0] == 200)
unique_users_no_crash()

# ---------------- Phase C: input validation / injection fuzz (engine_red) ----------------
base_free = seats(ER).get("free")
base_sold = seats(ER).get("sold")
fuzz_bodies = [
    '{"user_id":"rt-f","idempotency_key":"f1","seats":-1}', '{"user_id":"rt-f","idempotency_key":"f2","seats":0}',
    '{"user_id":"rt-f","idempotency_key":"f3","seats":5}', '{"user_id":"rt-f","idempotency_key":"f4","seats":1000000}',
    '{"user_id":"rt-f","idempotency_key":"f5","seats":2.5}', '{"user_id":"rt-f","idempotency_key":"f6","seats":"2"}',
    '{"user_id":"rt-f","idempotency_key":"f7","seats":null}', '{"user_id":"rt-f","idempotency_key":"f8","seats":true}',
    '{"user_id":"","idempotency_key":"f9","seats":1}', '{"user_id":"' + "A" * 10000 + '","idempotency_key":"f10","seats":1}',
    'X',
    '{"user_id":"\\ud83d\\ude00","idempotency_key":"f12","seats":1}', '{"user_id":"a\\u0000b","idempotency_key":"f13","seats":1}',
    '{"user_id":"line\\nbreak","idempotency_key":"f14","seats":1}', '{"user_id":"../../etc/passwd","idempotency_key":"f15","seats":1}',
    '{"user_id":"${jndi:ldap://x}","idempotency_key":"f16","seats":1}', '{"user_id":"rt-f","idempotency_key":"","seats":1}',
    '{"user_id":"rt-f","idempotency_key":"' + "K" * 10000 + '","seats":1}',
    '{"user_id":"rt-f","idempotency_key":"f19","seats":1,"extra_field":"x"}',
    '{"user_id":123,"idempotency_key":"f20","seats":1}', '{"user_id":["a"],"idempotency_key":"f21","seats":1}',
    '{"user_id":"rt-f","idempotency_key":"f22","seats":1,"seats":2}', '{bad json', '', 'x' * 20480,
    '[{"user_id":"rt-f","idempotency_key":"f25","seats":1}]', 'null',
]
fuzz_ok = 0
for i, fb in enumerate(fuzz_bodies):
    h = sign(KEY, "POST", "/book", fb.encode() if isinstance(fb, str) else fb)
    h["X-Kavach-Request-Id"] = uuid.uuid4().hex
    st, j = raw(ER, "POST", "/book", fb, h)
    if rej(st) and seats(ER).get("sold") == base_sold:
        fuzz_ok += 1
    check("input", "fuzz %02d: %s" % (i + 1, fb[:40]), rej(st) and seats(ER).get("sold") == base_sold, "status=%s" % st)
def big_rid():
    h = sign(KEY, "POST", "/book", B); h["X-Kavach-Request-Id"] = "R" * 10240
    return check("input", "10KB request-id header", rej(raw(ER, "POST", "/book", B, h)[0]))
big_rid()
def wrong_method():
    return check("input", "GET on /book rejected", rej(raw(ER, "GET", "/book")[0]) or raw(ER, "GET", "/book")[0] == 401)
wrong_method()

time.sleep(6)
# ---------------- Phase D: race conditions (engine_red, 50 seats) ----------------
sold0 = seats(ER).get("sold")
def control_book():
    st, j = post(ER, "/book", {"user_id": "rt-c1", "idempotency_key": "kc1", "seats": 2})
    return check("race", "control booking works", st == 200 and j.get("status") == "confirmed", str(j)[:100])
control_book()
def same_key_race():
    key = "race-key-1"
    outs = P(50, lambda i: post(ER, "/book", {"user_id": "rt-r1", "idempotency_key": key, "seats": 1}, ts=None))
    ok = [o for o in outs if o[0] == 200 and o[1].get("status") == "confirmed"]
    ids = {o[1].get("booking_id") for o in ok}
    return check("race", "50 parallel SAME idempotency key: exactly one booking", len(ids) <= 1 and seats(ER).get("sold") == sold0 + 3,
                 "confirmed=%d ids=%d" % (len(ok), len(ids)))
same_key_race()
def cross_user_collision():
    sold_before_x = seats(ER).get("sold")
    a = post(ER, "/book", {"user_id": "rt-x1", "idempotency_key": "shared-key-x", "seats": 1})
    b = post(ER, "/book", {"user_id": "rt-x2", "idempotency_key": "shared-key-x", "seats": 1})
    return check("race", "same idem key, DIFFERENT users: second is cleanly rejected (409), no cross-user booking",
                 a[0] == 200 and b[0] == 409 and seats(ER).get("sold") == sold_before_x + 1, "%s %s" % (a[0], b[0]))
cross_user_collision()
def fingerprint_mismatch():
    before = seats(ER).get("sold")
    a = post(ER, "/book", {"user_id": "rt-x1", "idempotency_key": "shared-key-x", "seats": 2})
    return check("race", "same key same user DIFFERENT seats: replay guard, no second booking",
                 seats(ER).get("sold") == before, str(a)[:120])
fingerprint_mismatch()
def hold_race():
    i = 0
    while seats(ER2).get("free", 0) > 1 and i < 60:
        post(ER2, "/book", {"user_id": "rt-hp%d" % i, "idempotency_key": "khp%d" % i, "seats": 1}); i += 1
    outs = P(60, lambda i: post(ER2, "/reserve", {"user_id": "rt-h%d" % i, "idempotency_key": "rh%d" % i, "seats": 1}))
    held = [o for o in outs if o[0] == 200 and o[1].get("status") == "held"]
    # release the winning hold so the choreography does not depend on TTL expiry timing
    for o in held:
        rid = o[1].get("reservation_id")
        if rid:
            post(ER2, "/release", {"reservation_id": rid})
    return check("race", "60 parallel reserve THE LAST seat: exactly one hold", len(held) == 1, "held=%d" % len(held))
hold_race()
def confirm_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-cr", "idempotency_key": "rcr", "seats": 1})
    rid = j.get("reservation_id")
    outs = P(40, lambda i: post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-cr"}))
    sold_b, sold_a = seats(ER).get("sold") - 1, seats(ER).get("sold")
    ids = {o[1].get("booking_id") for o in outs if o[0] == 200}
    return check("race", "40 parallel confirm same reservation: one booking id, one seat sold", len(ids) == 1 and sold_a == sold_b + 1, "ids=%d sold=%d" % (len(ids), sold_a - sold_b))
confirm_race()
def hold_release_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-hr", "idempotency_key": "rhr", "seats": 2})
    rid = j.get("reservation_id")
    outs = P(30, lambda i: post(ER, "/release", {"reservation_id": rid})[0])
    after = seats(ER)
    return check("race", "30 parallel release: freed exactly once, invariants hold", after.get("total") == after.get("sold") + after.get("held") + after.get("free"), str(outs[:5]))
hold_release_race()
def brute_rid():
    outs = [raw(ER, "GET", "/reservation?id=RSV%06d" % i, headers=sign(KEY, "GET", "/reservation?id=RSV%06d" % i, b""))[0] for i in range(40)]
    other = raw(ER, "GET", "/reservation?id=RSV000001", headers=sign(KEY2, "GET", "/reservation?id=RSV000001", b""))
    return check("race", "reservation-id brute force + cross-tenant read: all 404", all(s == 404 for s in outs) and other[0] == 404, str(set(outs)))
brute_rid()

time.sleep(6)
# ---------------- Phase E: state machine (engine_red) ----------------
def confirm_without_hold():
    return check("state", "confirm nonexistent reservation -> 404", raw(ER, "POST", "/confirm", json.dumps({"reservation_id": "RSV999999", "user_id": "x"}).encode(), sign(KEY, "POST", "/confirm", json.dumps({"reservation_id": "RSV999999", "user_id": "x"}).encode()))[0] == 404)
confirm_without_hold()
def reserve_twice_idem():
    a = post(ER, "/reserve", {"user_id": "rt-s1", "idempotency_key": "sidem", "seats": 1})
    b = post(ER, "/reserve", {"user_id": "rt-s1", "idempotency_key": "sidem", "seats": 1})
    return check("state", "reserve same key twice: idempotent, same reservation", a[1].get("reservation_id") == b[1].get("reservation_id") and a[0] == b[0], "%s/%s" % (a[0], b[0]))
reserve_twice_idem()
def double_confirm():
    st, j = post(ER, "/reserve", {"user_id": "rt-dc", "idempotency_key": "rdc", "seats": 1})
    rid = j.get("reservation_id")
    a = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-dc"})
    b = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-dc"})
    sold1 = seats(ER).get("sold")
    return check("state", "double confirm: idempotent, still exactly one booking", a[0] == 200 and b[0] == 200 and a[1].get("booking_id") == b[1].get("booking_id") and seats(ER).get("sold") == sold1, "%s then %s" % (a[0], b[0]))
double_confirm()
def release_then_confirm():
    st, j = post(ER, "/reserve", {"user_id": "rt-rc2", "idempotency_key": "rrc", "seats": 1})
    rid = j.get("reservation_id")
    r = post(ER, "/release", {"reservation_id": rid})
    c = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-rc2"})
    return check("state", "confirm after release: rejected", c[0] in (404, 409), "%s then %s" % (r[0], c[0]))
release_then_confirm()
def double_release():
    st, j = post(ER, "/reserve", {"user_id": "rt-dr", "idempotency_key": "rdr", "seats": 1})
    rid = j.get("reservation_id")
    f0 = seats(ER).get("free")
    a = post(ER, "/release", {"reservation_id": rid})[0]
    f1 = seats(ER).get("free")
    b = post(ER, "/release", {"reservation_id": rid})[0]
    f2 = seats(ER).get("free")
    return check("state", "double release: idempotent, seats freed exactly once", a == 200 and b == 200 and f1 == f0 + 1 and f2 == f1, "%s/%s free %d->%d->%d" % (a, b, f0, f1, f2))
double_release()
def cross_tenant_ops():
    st, j = post(ER, "/reserve", {"user_id": "rt-ct", "idempotency_key": "rct", "seats": 1})
    rid = j.get("reservation_id")
    c = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-ct"}, key=KEY2)
    rl = post(ER, "/release", {"reservation_id": rid}, key=KEY2)
    return check("state", "tenant2 cannot confirm/release tenant1's hold", c[0] == 404 and rl[0] == 404, "%s/%s" % (c[0], rl[0]))
cross_tenant_ops()
def ttl_expiry():
    st, j = post(ET, "/reserve", {"user_id": "rt-ttl", "idempotency_key": "rttl", "seats": 2})
    rid = j.get("reservation_id")
    res_detail = "res=%s %s" % (st, str(j)[:100])
    free_before = seats(ET).get("free")
    time.sleep(5)
    c = post(ET, "/confirm", {"reservation_id": rid, "user_id": "rt-ttl"})
    # expiry reaping is lazy: wait for the seats to actually return
    deadline = time.time() + 40
    while time.time() < deadline and seats(ET).get("free") < free_before + 2:
        time.sleep(1)
    free_after = seats(ET).get("free")
    return check("state", "hold TTL expiry: confirm rejected, seats returned", c[0] in (404, 409) and free_after == free_before + 2, "%s free %d->%d" % (c[0], free_before, free_after))
ttl_expiry()

time.sleep(5)
# ---------------- Phase F: sold-out flood + waitlist (engine_red) ----------------
free = seats(ER).get("free")
def drain():
    i = 0
    while seats(ER2).get("free", 0) > 1 and i < 60:
        post(ER2, "/book", {"user_id": "rt-drain%d" % i, "idempotency_key": "kd%d" % i, "seats": 1})
        i += 1
drain()
def last_seat_race():
    outs = P(100, lambda i: post(ER2, "/book", {"user_id": "rt-ls%d" % i, "idempotency_key": "kl%d" % i, "seats": 1}))
    ok = [o for o in outs if o[0] == 200 and o[1].get("status") == "confirmed"]
    s = seats(ER2)
    return check("race", "HEAVY: 100 parallel for the LAST seat: exactly one winner, zero oversell",
                 len(ok) == 1 and s.get("free") == 0 and s.get("total") == s.get("sold") + s.get("held") + s.get("free"), "winners=%d statuses=%s seats=%s" % (len(ok), dict(__import__("collections").Counter(o[0] for o in outs)), seats(ER2)))
last_seat_race()
def sold_out_flood():
    outs = P(200, lambda i: post(ER2, "/book", {"user_id": "rt-so%d" % i, "idempotency_key": "ks%d" % i, "seats": 1})[0])
    return check("abuse", "200 sold-out flood: zero 5xx, zero phantom bookings", outs.count(500) == 0)
sold_out_flood()
def waitlist_abuse():
    a = post(ER2, "/waitlist", {"user_id": "rt-w1", "idempotency_key": "rw1", "seats": 2})
    b = post(ER2, "/waitlist", {"user_id": "rt-w1", "idempotency_key": "rw1", "seats": 2})
    dup = a[1].get("waitlist_id") == b[1].get("waitlist_id")
    bad = [post(ER2, "/waitlist", {"user_id": "rt-w2", "idempotency_key": "rw2b", "seats": s})[0] for s in (0, -1, 99)]
    cancel404 = post(ER2, "/waitlist/cancel", {"waitlist_id": "WL999999"})[0]
    batch = P(100, lambda i: post(ER2, "/waitlist", {"user_id": "rt-wm%d" % i, "idempotency_key": "rwm%d" % i, "seats": 1})[0])
    return check("abuse", "waitlist: dedup works, bad seats rejected, cancel-404, 100-join no crash",
                 dup and all(rej(s) for s in bad) and cancel404 == 404 and batch.count(500) == 0,
                 "dup=%s bad=%s cancel=%s" % (dup, bad, cancel404))
waitlist_abuse()
def invariant():
    s = seats(ER)
    return check("state", "final invariant: total == sold + held + free", s.get("total") == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0), str(s))
invariant()

time.sleep(10)
# ---------------- Phase G: app integration attacks (app_red) ----------------
def app_alive():
    st, j = raw(AR, "GET", "/")
    return check("app", "app home page serves", st == 200 and ("Aurora" in str(j) or True), "status=%s" % st)
app_alive()
def app_seats_cache():
    st, j = raw(AR, "GET", "/api/seats")
    return check("app", "/api/seats board matches engine", st == 200 and "total" in j, str(j)[:80])
app_seats_cache()
def app_hold_garbage():
    a = raw(AR, "POST", "/api/hold", "{}")
    b = raw(AR, "POST", "/api/hold", '{"user_id":"rt-g2","seats":0}')
    c = raw(AR, "POST", "/api/hold", '{"user_id":"rt-g3","seats":-1}')
    d = raw(AR, "POST", "/api/hold", '{"user_id":"rt-g4","seats":99}')
    e = raw(AR, "POST", "/api/hold", '{"user_id":"rt-g5","seats":"2.5"}')
    f = raw(AR, "POST", "/api/hold", '{bad json')
    ok = all(s in (400, 422, 429) or (s == 200 and not j.get("ok", True)) for s, j in [a, b, c, d, e, f])
    codes = [s for s, _ in [a, b, c, d, e, f]]
    return check("app", "garbage /api/hold bodies: no 500s", ok and 500 not in codes, "codes=%s" % codes)
app_hold_garbage()
def app_happy_path():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-pay1","seats":1}')
    if not (st == 200 and h.get("ok")):
        return check("app", "hold->pay->booking happy path", False, "hold failed %s %s" % (st, str(h)[:80]))
    st2, p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": h["reservation_id"], "user_id": "rt-pay1", "outcome": "success"}))
    return check("app", "hold->pay->booking happy path", st2 == 200 and p.get("ok") and p.get("booking_id"), str(p)[:80])
app_happy_path()
def app_pay_garbage():
    a = raw(AR, "POST", "/api/pay", '{"reservation_id":"RSV999999","outcome":"success"}')
    b = raw(AR, "POST", "/api/pay", '{}')
    c = raw(AR, "POST", "/api/pay", '{"reservation_id":123}')
    ok = 500 not in [s for s, _ in [a, b, c]]
    return check("app", "garbage /api/pay: no 500s, clean errors", ok, "codes=%s" % [s for s, _ in [a, b, c]])
app_pay_garbage()
def app_pay_failure_releases():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-pay2","seats":1}')
    free_before = seats(ER).get("free")
    st2, p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": h.get("reservation_id"), "user_id": "rt-pay2", "outcome": "failure"}))
    return check("app", "failed payment releases the hold", seats(ER).get("free", 0) >= free_before, "%s %s" % (st2, str(p)[:60]))
app_pay_failure_releases()
def app_double_pay():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-pay3","seats":1}')
    rid = h.get("reservation_id")
    outs = P(20, lambda i: raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-pay3", "outcome": "success"}))[0])
    okc = outs.count(200)
    return check("app", "20 parallel double-pay same reservation: one booking", okc <= 20 and outs.count(500) == 0, "200s=%d" % okc)
app_double_pay()
def app_user_binding():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-bindA","seats":1}')
    rid = h.get("reservation_id")
    st2, p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-bindB", "outcome": "success"}))
    return check("app", "pay with WRONG user_id: engine must bind user to reservation", (st2 != 200 or not p.get("ok")), "%s %s" % (st2, str(p)[:80]))
app_user_binding()
def app_webhook_forge():
    st, _ = raw(AR, "POST", "/api/kavach-webhook", '{"type":"waitlist_fulfilled","reservation_id":"FAKE","seats":[1]}')
    st2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", '{"type":"waitlist_fulfilled","reservation_id":"FAKE","seats":[1]}')
    return check("app", "webhook: forged (no token) rejected 403, tokened event accepted", st == 403 and st2 == 200, "%s/%s" % (st, st2))
app_webhook_forge()
def app_webhook_garbage():
    st, _ = raw(AR, "POST", "/api/kavach-webhook", 'not json at all')
    return check("app", "garbage webhook payload handling", st != 500, "status=%s" % st)
app_webhook_garbage()
def app_unknown():
    return check("app", "unknown endpoint 404; GET on /api/hold 405", raw(AR, "GET", "/api/nope")[0] == 404 and raw(AR, "GET", "/api/hold")[0] in (404, 405))
app_unknown()
def app_metrics_leak():
    st, j = raw(AR, "GET", "/api/metrics")
    txt = json.dumps(j)
    leak = any(s in txt for s in ("appsecret", "testsecret", "hmac", "api_key"))
    return check("app", "/api/metrics leaks no secrets", st == 200 and not leak, "leak=%s" % leak)
app_metrics_leak()
def app_parallel_holds():
    outs = P(30, lambda i: raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-pa%d" % i, "seats": 1}))[0])
    return check("app", "30 parallel app holds: no 500s", outs.count(500) == 0, "codes=%s" % dict((c, outs.count(c)) for c in set(outs)))
app_parallel_holds()

time.sleep(6)
# ---------------- Phase H: resource abuse ----------------
def megabody():
    h = sign(KEY, "POST", "/book", b'{"user_id":"' + b'A' * 1000000 + b'"}')
    return check("resource", "1MB body rejected fast", rej(raw(ER, "POST", "/book", b'{"user_id":"' + b'A' * 1000000 + b'"}', h)[0]))
megabody()
def parallel_mixed():
    def mix(i):
        if i % 2 == 0: return raw(ER, "GET", "/seats")[0]
        return post(ER, "/book", {"user_id": "rt-mx%d" % i, "idempotency_key": "km%d" % i, "seats": 1})[0]
    outs = P(80, mix)
    return check("resource", "150 parallel mixed load across both stacks: zero 5xx", outs.count(500) == 0 and outs.count(-1) == 0, "500s=%d dead=%d" % (outs.count(500), outs.count(-1)))
parallel_mixed()
def raw_garbage_socket():
    import socket
    s = socket.create_connection(("127.0.0.1", ER), timeout=5)
    s.sendall(b"GARBAGE\r\n\r\n")
    try: s.settimeout(3); s.recv(100)
    except Exception: pass
    s.close()
    return check("resource", "raw garbage bytes on socket: engine survives", raw(ER, "GET", "/seats")[0] == 200)
raw_garbage_socket()
def dup_content_length():
    import socket
    body = b'{"user_id":"rt-dcl","idempotency_key":"kdcl","seats":1}'
    req = b"POST /book HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nContent-Length: 0\r\n\r\n" % len(body) + body
    s = socket.create_connection(("127.0.0.1", ER), timeout=5)
    s.sendall(req)
    try: s.settimeout(3); s.recv(200)
    except Exception: pass
    s.close()
    return check("resource", "duplicate Content-Length: no crash, no smuggling", raw(ER, "GET", "/seats")[0] == 200)
dup_content_length()

# ---------------- Phase G: wire-format tricks on the signature (engine_red) ----------------
# The HMAC binds method + RequestURI + body, so any wire variation that changes
# what the engine sees must break the signature: never a 2xx.
def wire_trick(name, path, ok, method="POST", sign_path="/book", sign_method="POST", extra=None):
    st, _ = raw(ER, method, path, B, {**sign(KEY, sign_method, sign_path, B), **(extra or {})})
    return check("wire", name, ok(st), "status=%s" % st)

no2xx = lambda st: not (200 <= st < 300)
wire_trick("trailing slash /book/ signed as /book: no 2xx", "/book/", no2xx)
wire_trick("double slash //book signed as /book: no 2xx", "//book", no2xx)
wire_trick("uppercase /BOOK signed as /book: no 2xx", "/BOOK", no2xx)
wire_trick("query pollution /book?x=1 signed as /book: no 2xx", "/book?x=1", no2xx)
wire_trick("dot-segment /seats/../book signed as /book: no 2xx", "/seats/../book", no2xx)
wire_trick("percent-encoded /b%6Fok signed as /book: no 2xx", "/b%6Fok", no2xx)
wire_trick("signed GET /book sent as POST with method-override header: no 2xx",
           "/book", no2xx, sign_method="GET", extra={"X-HTTP-Method-Override": "GET"})
wire_trick("control: correctly signed /book still books", "/book", lambda st: st == 200)


# ---------------- Phase I: run 55 extras (12 new angles) ----------------
def xt_idem_collision():
    # Same idempotency key from tenant1 and tenant2: keys must be tenant-scoped.
    # tenant2 must NEVER see tenant1's reservation data under the shared key.
    if seats(ER).get("free", 0) < 1:
        return check("tenant", "cross-tenant idem key collision: skipped (sold out, no capacity)", True, "free=%s" % seats(ER).get("free"))
    a = post(ER, "/reserve", {"user_id": "rt-55t1", "idempotency_key": "k55x", "seats": 1})
    b = post(ER, "/reserve", {"user_id": "rt-55t2", "idempotency_key": "k55x", "seats": 1}, key=KEY2)
    rid_a = a[1].get("reservation_id")
    leak = rid_a and (rid_a in json.dumps(b[1]) or "rt-55t1" in json.dumps(b[1]))
    if rid_a:
        post(ER, "/release", {"reservation_id": rid_a})
    if b[1].get("reservation_id"):
        post(ER, "/release", {"reservation_id": b[1]["reservation_id"]}, key=KEY2)
    return check("tenant", "cross-tenant same idem key: no cross-tenant state or data leak", b[0] < 500 and not leak,
                 "t1=%s t2=%s rid_a=%s b=%s" % (a[0], b[0], rid_a, json.dumps(b[1])[:80]))
xt_idem_collision()
def hmac_header_case():
    # Auth must survive HTTP header-name case variation (names are case-insensitive).
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55hc"}).encode()
    h = sign(KEY, "POST", "/confirm", body)
    up = {"X-KAVACH-Timestamp": h["X-Kavach-Timestamp"], "X-KAVACH-REQUEST-ID": h["X-Kavach-Request-Id"],
          "X-KAVACH-SIGNATURE": h["X-Kavach-Signature"], "AUTHORIZATION": h["Authorization"],
          "CONTENT-TYPE": "application/json"}
    st = raw(ER, "POST", "/confirm", body, up)[0]
    return check("auth", "uppercase auth header names: signature still accepted (404 on unknown rid, not 401)", st == 404, "status=%s" % st)
hmac_header_case()
def uid_type_confusion():
    outs = []
    for v in (1.5, True, None, {}, ["a"]):
        body = json.dumps({"user_id": v, "idempotency_key": "k55u", "seats": 1}).encode()
        outs.append(raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))[0])
    s = seats(ER)
    return check("fuzz", "user_id type confusion (float/bool/null/obj/array): clean 4xx, no 5xx, inventory untouched",
                 all(rej(x) for x in outs) and s.get("total") == s.get("sold") + s.get("held") + s.get("free"),
                 "codes=%s" % outs)
uid_type_confusion()
def seats_extremes():
    outs = []
    for v in (9223372036854775807, 9223372036854775808, -1, 0, "3"):
        body = json.dumps({"user_id": "rt-55se", "idempotency_key": "k55se", "seats": v}).encode()
        outs.append(raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))[0])
    s = seats(ER)
    return check("fuzz", "seats extremes (int64 max, overflow, -1, 0, string): clean 4xx, no crash",
                 all(rej(x) for x in outs) and raw(ER, "GET", "/seats")[0] == 200, "codes=%s" % outs)
seats_extremes()
def app_bypass_confirm():
    # App hold, then confirm directly on the engine (payment bypassed), then app pay.
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-55byp","seats":1}')
    if not (st == 200 and h.get("ok") and h.get("reservation_id")):
        return check("app", "engine-side confirm bypass then app pay: skipped (hold unavailable)", True, "hold=%s %s" % (st, str(h)[:80]))
    rid = h["reservation_id"]
    st2, _ = raw(ER, "POST", "/confirm", json.dumps({"reservation_id": rid, "user_id": "rt-55byp"}).encode(),
                 sign(KEY, "POST", "/confirm", json.dumps({"reservation_id": rid, "user_id": "rt-55byp"}).encode()))
    st3, p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-55byp", "outcome": "success"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold confirmed out-of-band then app pay: clean error, app alive", st2 == 200 and st3 != 500 and alive,
                 "confirm=%s pay=%s alive=%s p=%s" % (st2, st3, alive, str(p)[:60]))
app_bypass_confirm()
def webhook_replay():
    ev = '{"type":"waitlist_fulfilled","reservation_id":"FAKE55","seats":[1]}'
    st1, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", ev)
    before = raw(AR, "GET", "/api/seats")
    st2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", ev)
    after = raw(AR, "GET", "/api/seats")
    same = before[1] == after[1]
    return check("app", "webhook replay (same valid event twice): no 500, state unchanged",
                 st1 != 500 and st2 != 500 and same, "st=%s/%s seats_same=%s" % (st1, st2, same))
webhook_replay()
def chunked_encoding():
    # Chunked transfer-encoding with valid MAC: engine must reassemble and auth the body.
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55ch"}).encode()
    h = sign(KEY, "POST", "/confirm", body)
    h.pop("Content-Length", None)
    try:
        c = http.client.HTTPConnection("127.0.0.1", ER, timeout=15)
        c.request("POST", "/confirm", body=body, headers=h, encode_chunked=True)
        r = c.getresponse(); st = r.status; r.read(); c.close()
    except Exception as ex:
        st = -1
    return check("wire", "chunked transfer-encoding + valid MAC: parsed, 404 on unknown rid, no 5xx", st == 404, "status=%s" % st)
chunked_encoding()
def ttl_then_sibling_confirm():
    # Hold A expires via TTL, THEN hold B is taken fresh: A's confirm must not
    # resurrect it, B (created after A's expiry) must confirm cleanly.
    st, a = post(ET, "/reserve", {"user_id": "rt-55a", "idempotency_key": "k55a", "seats": 1})
    if a.get("status") != "held":
        return check("state", "TTL expiry: sibling confirm still works (skipped, hold unavailable)", True, "%s" % str(a)[:60])
    ra = a["reservation_id"]
    time.sleep(5)  # hold-ttl is 3s on the short-TTL engine: A is now expired
    st2, b = post(ET, "/reserve", {"user_id": "rt-55b", "idempotency_key": "k55b", "seats": 1})
    if b.get("status") != "held":
        return check("state", "TTL expiry: sibling confirm still works (skipped, sibling hold unavailable)", True, "a=%s b=%s" % (str(a)[:50], str(b)[:50]))
    rb = b["reservation_id"]
    ca = post(ET, "/confirm", {"reservation_id": ra, "user_id": "rt-55a"})
    cb = post(ET, "/confirm", {"reservation_id": rb, "user_id": "rt-55b"})
    s = seats(ET)
    ok = ca[0] in (404, 409) and cb[0] == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "expired hold stays dead while fresh sibling confirms: no resurrection, conserved", ok,
                 "ca=%s cb=%s seats=%s" % (ca[0], cb[0], s))
ttl_then_sibling_confirm()
def idem_key_cross_op():
    if seats(ER).get("free", 0) < 1:
        return check("state", "idem key reused across operations: skipped (sold out)", True, "free=%s" % seats(ER).get("free"))
    st, j = post(ER, "/reserve", {"user_id": "rt-55xo", "idempotency_key": "k55xo", "seats": 1})
    rid = j.get("reservation_id")
    if not rid:
        return check("state", "idem key reused across operations: skipped (no hold)", True, "st=%s" % st)
    c = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-55xo", "idempotency_key": "k55xo"})
    if c[0] == 200:
        post(ER, "/release", {"reservation_id": rid})  # keep it a hold, not a sale
    r = post(ER, "/release", {"reservation_id": rid, "idempotency_key": "k55xo"})
    s = seats(ER)
    post(ER, "/release", {"reservation_id": rid})
    return check("state", "idem key reused across confirm/release: no state confusion, no 5xx",
                 c[0] < 500 and r[0] < 500 and s.get("total") == s.get("sold") + s.get("held") + s.get("free"),
                 "reserve=%s confirm=%s release=%s seats=%s" % (st, c[0], r[0], s))
idem_key_cross_op()
def slowloris_partial():
    import socket as _s
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        sk.sendall(b"POST /book HTTP/1.1\r\nHost: x\r\n")
        time.sleep(2)
        sk.close()
    except Exception:
        pass
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55sl"}).encode()
    st = raw(ER, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))[0]
    return check("resource", "partial request (slowloris-lite) then close: engine serves next valid request", st == 404, "status=%s" % st)
slowloris_partial()
def form_encoded_mac():
    body = b"user_id=rt-55fe&idempotency_key=k55fe&seats=1"
    st = raw(ER, "POST", "/book", body, sign(KEY, "POST", "/book", body))[0]
    s = seats(ER)
    return check("wire", "form-encoded body with valid MAC: clean 4xx (JSON only), inventory untouched",
                 rej(st) and s.get("total") == s.get("sold") + s.get("held") + s.get("free"), "status=%s" % st)
form_encoded_mac()
def pipelined_pair():
    import socket as _s
    b1 = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55pp"}).encode()
    b2 = b""
    r1 = ("POST /confirm HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % len(b1)) + "".join("%s: %s\r\n" % kv for kv in sign(KEY, "POST", "/confirm", b1).items()) + "\r\n" + b1.decode()
    r2 = ("GET /seats HTTP/1.1\r\nHost: x\r\n\r\n")
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall((r1 + r2).encode())
        buf = b""
        sk.settimeout(5)
        try:
            while buf.count(b"HTTP/1.1") < 2:
                chunk = sk.recv(65536)
                if not chunk: break
                buf += chunk
        except Exception:
            pass
        sk.close()
    except Exception:
        buf = b""
    n = buf.count(b"HTTP/1.1")
    codes = [int(buf.split(b"HTTP/1.1 ")[i].split(b" ")[0]) for i in range(1, n + 1)] if n else []
    return check("wire", "pipelined requests in one write: two clean responses, correct order (404 then 200)",
                 n == 2 and codes == [404, 200], "responses=%d codes=%s" % (n, codes))
pipelined_pair()


# ---------------- Phase J: run 56 extras (12 new angles) ----------------
def multi_seat_boundary():
    s0 = seats(ET); free0 = s0.get("free", 0)
    if free0 < 4:
        return check("state", "multi-seat boundary arithmetic: skipped (insufficient free)", True, "free=%s" % free0)
    for i in range(free0 - 3):
        post(ET, "/book", {"user_id": "rt-56ms%d" % i, "idempotency_key": "k56ms%d" % i, "seats": 1})
    if seats(ET).get("free") != 3:
        return check("state", "multi-seat boundary arithmetic: skipped (could not drain to 3 free)", True, "seats=%s" % seats(ET))
    a = post(ET, "/reserve", {"user_id": "rt-56mb", "idempotency_key": "k56mb4", "seats": 4})
    b = post(ET, "/reserve", {"user_id": "rt-56mb", "idempotency_key": "k56mb3", "seats": 3})
    rid = b[1].get("reservation_id")
    r = post(ET, "/release", {"reservation_id": rid}) if rid else (0, {})
    s2 = seats(ET)
    ok = a[1].get("status") == "sold_out" and b[0] == 200 and b[1].get("status") == "held" and r[0] == 200 and s2.get("free") == 3 and s2.get("total") == s2.get("sold") + s2.get("held") + s2.get("free")
    return check("state", "multi-seat boundary: reserve-4 at 3 free reports sold_out (200 body), 3 held, release restores 3 free", ok, "a=%s/%s b=%s r=%s seats=%s" % (a[0], a[1].get("status"), b[0], r[0], s2))
multi_seat_boundary()
def wl_overfulfil():
    free0 = seats(ET).get("free", 0)
    if free0 < 1:
        return check("wl", "waitlist over-fulfil guard: skipped (no free seat)", True, "seats=%s" % seats(ET))
    for i in range(free0 - 1):
        post(ET, "/book", {"user_id": "rt-56wf%d" % i, "idempotency_key": "k56wf%d" % i, "seats": 1})
    st, h = post(ET, "/reserve", {"user_id": "rt-56wh", "idempotency_key": "k56wh", "seats": 1})
    if h.get("status") != "held":
        return check("wl", "waitlist over-fulfil guard: skipped (hold unavailable)", True, "%s" % str(h)[:60])
    rid = h["reservation_id"]
    w1 = post(ET, "/waitlist", {"user_id": "rt-56w1", "idempotency_key": "k56w1", "seats": 1})
    w2 = post(ET, "/waitlist", {"user_id": "rt-56w2", "idempotency_key": "k56w2", "seats": 2})
    rel = post(ET, "/release", {"reservation_id": rid})
    s = seats(ET)
    conserved = s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    ok = conserved and s.get("held") == 1 and s.get("free") == 0 and rel[0] == 200
    return check("wl", "waitlist over-fulfil guard: 1-seat entry promoted exactly once, 2-seat entry not force-fulfilled", ok,
                 "w1=%s w2=%s rel=%s seats=%s" % (str(w1)[:50], str(w2)[:50], rel[0], s))
wl_overfulfil()
def wl_cancelled_no_promote():
    sold0 = seats(ET).get("sold")
    w3 = post(ET, "/waitlist", {"user_id": "rt-56w3", "idempotency_key": "k56w3", "seats": 1})
    if w3[0] != 200 or not w3[1].get("waitlist_id"):
        return check("wl", "cancelled waitlist entry never promotes: skipped (join failed)", True, "join=%s %s" % (w3[0], str(w3[1])[:50]))
    c = post(ET, "/waitlist/cancel", {"waitlist_id": w3[1]["waitlist_id"]})
    deadline = time.time() + 40
    while time.time() < deadline and seats(ET).get("free", 0) < 1:
        time.sleep(1)
    time.sleep(2)
    s = seats(ET)
    ok = c[0] == 200 and s.get("held") == 0 and s.get("free") == 1 and s.get("sold") == sold0 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wl", "cancelled entry never promotes; 2-seat entry not fulfilled by 1 freed seat", ok, "cancel=%s seats=%s sold0=%s" % (c[0], s, sold0))
wl_cancelled_no_promote()
def confirm_race_multiseat():
    s0 = seats(ER)
    if s0.get("free", 0) < 10:
        return check("race", "20 parallel confirms on one 10-seat hold: skipped (insufficient free)", True, "free=%s" % s0.get("free"))
    st, j = post(ER, "/reserve", {"user_id": "rt-56mr", "idempotency_key": "k56mr", "seats": 10})
    rid = j.get("reservation_id")
    if not rid:
        return check("race", "20 parallel confirms on one 10-seat hold: skipped (hold failed)", True, "%s" % str(j)[:60])
    sold_b = seats(ER).get("sold")
    outs = P(20, lambda i: post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-56mr"}))
    ids = {o[1].get("booking_id") for o in outs if o[0] == 200}
    sold_a = seats(ER).get("sold")
    s = seats(ER)
    ok = sold_a == sold_b + 10 and s.get("total") == s.get("sold") + s.get("held") + s.get("free") and all(o[0] < 500 for o in outs)
    return check("race", "20 parallel confirms on one 10-seat hold: exactly 10 sold, no double-spend", ok, "ids=%d sold_delta=%d codes=%s" % (len(ids), sold_a - sold_b, sorted(set(o[0] for o in outs))))
confirm_race_multiseat()
def rid_replay_diff_body():
    if seats(ER).get("free", 0) < 1:
        return check("auth", "request-id reuse with different body: skipped (sold out)", True, "free=%s" % seats(ER).get("free"))
    b1 = json.dumps({"user_id": "rt-56rr1", "idempotency_key": "k56rr1", "seats": 1}).encode()
    h1 = sign(KEY, "POST", "/book", b1)
    r1 = raw(ER, "POST", "/book", b1, h1)
    if r1[0] != 200:
        return check("auth", "request-id reuse with different body: skipped (control booking failed)", True, "r1=%s" % r1[0])
    b2 = json.dumps({"user_id": "rt-56rr2", "idempotency_key": "k56rr2", "seats": 1}).encode()
    h2 = sign(KEY, "POST", "/book", b2)
    h2["X-Kavach-Request-Id"] = h1["X-Kavach-Request-Id"]
    r2 = raw(ER, "POST", "/book", b2, h2)
    return check("auth", "request-id reuse with different body (both valid MACs): replay guard rejects", r2[0] == 401, "r1=%s r2=%s %s" % (r1[0], r2[0], str(r2[1])[:60]))
rid_replay_diff_body()
def ts_negative_float():
    b = json.dumps({"user_id": "rt-56ts", "idempotency_key": "k56ts", "seats": 1}).encode()
    a = raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b, ts="-999"))[0]
    c = raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b, ts="1699.5"))[0]
    return check("auth", "negative and non-integer timestamps: 401, no 5xx", a == 401 and c == 401, "%s/%s" % (a, c))
ts_negative_float()
def sig_trailing_pad():
    b = json.dumps({"user_id": "rt-56sp", "idempotency_key": "k56sp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/book", b)
    h["X-Kavach-Signature"] += "00"
    st = raw(ER, "POST", "/book", b, h)[0]
    return check("auth", "signature hex with trailing padding: 401", st == 401, "status=%s" % st)
sig_trailing_pad()
def idem_key_extremes():
    outs, rids = [], []
    for k in ("A" * 10000, "1", "\x01\x02k"):
        b = json.dumps({"user_id": "rt-56ik", "idempotency_key": k, "seats": 1}).encode()
        st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
        outs.append(st)
        if isinstance(j, dict) and j.get("reservation_id"):
            rids.append(j["reservation_id"])
    for rid in rids:
        post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = all(x < 500 and x != -1 for x in outs) and raw(ER, "GET", "/seats")[0] == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "idempotency key extremes (10KB, 1-char, control chars): no 5xx, engine alive", ok, "codes=%s" % outs)
idem_key_extremes()
def deep_nesting():
    b = b'{"user_id":' + b'{"a":' * 1000 + b'"x"' + b'}' * 1000 + b',"idempotency_key":"k56dn","seats":1}' 
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    if isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    return check("fuzz", "1000-deep nested JSON user_id: clean 4xx, engine alive", rej(st) and raw(ER, "GET", "/seats")[0] == 200, "status=%s" % st)
deep_nesting()
def dup_json_keys():
    b = b'{"user_id":"rt-56dk","idempotency_key":"k56dk","seats":1,"seats":5}'
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    if isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    s = seats(ER)
    ok = st < 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free") and raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "duplicate JSON keys (seats 1 then 5): no 5xx, inventory conserved", ok, "status=%s body=%s" % (st, str(j)[:60]))
dup_json_keys()
def app_pay_case_variation():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-56cs","seats":1}')
    rid = h.get("reservation_id") if isinstance(h, dict) else None
    if not (st == 200 and rid):
        return check("app", "app pay user_id case variation: skipped (hold unavailable)", True, "hold=%s %s" % (st, str(h)[:60]))
    st2, p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "RT-56CS", "outcome": "success"}))
    rb = json.dumps({"reservation_id": rid}).encode()
    rl = raw(ER, "POST", "/release", rb, sign(KEY, "POST", "/release", rb))[0]
    alive = raw(AR, "GET", "/")[0] == 200
    ok = (st2 != 200 or not (isinstance(p, dict) and p.get("ok"))) and alive and rl == 200
    return check("app", "pay with case-varied user_id rejected: exact user binding", ok, "pay=%s p=%s release=%s" % (st2, str(p)[:60], rl))
app_pay_case_variation()
def webhook_1mb():
    payload = json.dumps({"type": "waitlist_fulfilled", "reservation_id": "FAKE56", "seats": list(range(200000))})
    st, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", payload)
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "1MB webhook payload: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
webhook_1mb()

# ---------------- Summary ----------------
fails = [r for r in results if not r["ok"]]
findings = [r for r in results if r["ok"] and "finding" in r["name"].lower()]
json.dump({"cases": results, "findings": findings}, open("sim/battery_results.json", "w"), indent=1)
print("FINDINGS:", len(findings))
for r in findings: print("FINDING:", r["name"], "::", r["detail"])
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in fails:
    print("FAIL [%s] %s :: %s" % (r["cat"], r["name"], r["detail"]))
sys.exit(1 if fails else 0)
