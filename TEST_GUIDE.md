# Kavach self-test guide

Follow this top to bottom and you will have personally run every layer of the
engine: booking, idempotency, the cart flow, the waitlist, and the acceptance
suites. Total time: about 15 minutes. All you need is a browser.

## 1. Get a machine in your browser

Open https://github.com/l72683876-beep/kavach-engine, press the green
**Code** button, choose the **Codespaces** tab, and press **Create codespace**.
After a few seconds you have a full Linux machine with a terminal, in a
browser tab.

## 2. Build and start the engine

In the terminal:

```bash
cd engine
go build -o kavach .
./kavach -seats 100 -workers 4 &
```

The `&` runs the engine in the background. You should see:
`kavach engine on :8080: 100 seats, 4 workers, ...`.

## 3. Book a seat, and prove no double booking

```bash
curl -X POST http://localhost:8080/book \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"lucky","idempotency_key":"meri-booking-1","seats":1}'
```

Run that exact command two or three times. Every response carries the SAME
`booking_id`. That is idempotency: a network retry can never buy a seat twice.
Now try changing the seats value in the same key: the engine answers
`idempotency_conflict` instead of silently booking something new.

## 4. The cart flow: hold, pay later, confirm

```bash
# hold two seats for 5 minutes
curl -X POST http://localhost:8080/reserve \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"lucky","idempotency_key":"meri-cart-1","seats":2}'

# copy the reservation_id from the response, then confirm it
curl -X POST http://localhost:8080/confirm \
  -H 'Content-Type: application/json' \
  -d '{"reservation_id":"RSV00000001","user_id":"lucky"}'
```

Confirming twice returns the same booking. To see expiry, reserve two more
seats, do NOT confirm them, wait 5 minutes (or restart with
`-hold-ttl 10` for a 10-second TTL), and watch `/seats` hand them back.

## 5. The waitlist

Fill every seat (or use a small `-seats` value), then:

```bash
curl -X POST http://localhost:8080/waitlist \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"lucky","idempotency_key":"meri-line-1","seats":1}'
```

Release any held reservation and, within a second, the waitlist entry is
fulfilled automatically: a fresh reservation appears for that user, and if you
started the engine with `-webhook-url http://...`, a `waitlist_fulfilled`
event arrives there.

## 6. Watch the numbers

Open these in the browser (or curl them):

- `/seats`: total, sold, held, free. The invariants are visible here.
- `/metrics`: counters for every rejection type, plus latency percentiles.

## 7. Run the acceptance suites

```bash
# security: 14 checks (auth, replay, conflicts, rush)
./kavach -seats 100 -workers 4 -api-keys testkey:tenant1 \
  -hmac-secret testsecret -ip-rate 0 -log sec.jsonl -holds-log sec_holds.jsonl &
python3 sim/security_test.py 8080
kill %1

# lifecycle: 19 checks (hold/confirm/release/expiry, tenant isolation)
./kavach -seats 100 -workers 4 -api-keys testkey:tenant1 -hmac-secret testsecret \
  -ip-rate 0 -hold-ttl 3 -log lc.jsonl -holds-log lc_holds.jsonl &
python3 sim/lifecycle_test.py 8080
kill %1

# waitlist: 13 checks (FIFO fairness, webhook, cancel)
./kavach -seats 10 -workers 4 -api-keys testkey:tenant1 -hmac-secret testsecret \
  -ip-rate 0 -hold-ttl 10 -webhook-url http://127.0.0.1:9099/hook \
  -log wl.jsonl -holds-log wl_holds.jsonl &
python3 sim/waitlist_test.py 8080
kill %1
```

Each suite prints `PASS` lines and ends with `N/N passed`.

## 8. The stampede

```bash
pip install aiohttp
python3 sim/simulate.py --users 20000 --concurrency 10000
python3 sim/verify.py engine/bookings.jsonl 5000
```

## 9. Use it from your own code

```python
# Python (sdk/python/kavach.py, standard library only)
from kavach import Kavach
k = Kavach("http://localhost:8080")
print(k.book("priya", "priya-booking-1", seats=1))
```

```js
// JavaScript (sdk/javascript/kavach.mjs, Node 18+)
import { Kavach } from "./kavach.mjs";
const k = new Kavach("http://localhost:8080");
console.log(await k.book("priya", "priya-booking-1", 1));
```

Both SDKs speak the auth handshake (API key + HMAC) when you pass the keys,
so the same two lines work in local and production mode.
