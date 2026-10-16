# Embedding Kavach in a real app: pricing, GST, payments, and the speed question

A common worry: "Kavach only does inventory. My app needs pricing, coupons, GST,
user verification and payments. Won't bolting all that on slow it down?"

Short answer: no, because the heavy work never touches the stampede path.

## Where the heavy logic lives

A flash sale has two very different moments:

1. **The stampede** - lakhs of people hitting "buy" at the same second, fighting
   for limited stock. This is the only moment where speed decides whether the
   system survives. In Kavach this is the `/reserve` path: validate, rate-limit,
   hold seats atomically, respond in single-digit milliseconds.
2. **The checkout** - once a user HOLDS a reservation, the fight is over. There
   are now thousands of holders, not millions of contenders. This is where your
   application computes the price, applies the coupon, adds GST, verifies the
   user and takes payment. It can take 2 seconds and nobody races anybody.

Kavach's reservation lifecycle (v1.6) is built exactly for this gap: `/reserve`
holds stock for a TTL (default 5 minutes), your app does everything else, and
then `/confirm` turns the hold into a sale - or the TTL returns the stock
automatically if payment never lands.

## A realistic checkout flow

```python
import requests, time

KAVACH = "http://kavach.internal:8080"

def checkout(user_id, cart):
    idem = f"{user_id}-cart-{cart['id']}"          # from YOUR order id

    # 1. win the inventory race (the only hot-path call)
    r = requests.post(f"{KAVACH}/reserve", json={
        "user_id": user_id, "idempotency_key": idem, "seats": cart["qty"]})
    if r.json()["status"] != "held":
        return {"error": "sold out"}               # or join the waitlist
    reservation = r.json()["reservation_id"]

    # 2. ALL the business logic: this code is YOURS, in YOUR stack,
    #    with YOUR frameworks, and it is NOT in the stampede path
    price   = cart["mrp"]
    price  -= coupon_discount(cart["coupon"])      # your coupon service
    price  += gst(price, cart["hsn"])              # your tax rules
    user_ok = verify_user(user_id)                 # your KYC/fraud checks

    # 3. take payment with YOUR provider
    paid = charge(user_id, price)
    if not paid:
        requests.post(f"{KAVACH}/release", json={"reservation_id": reservation})
        return {"error": "payment failed"}         # stock returns via TTL anyway

    # 4. turn the hold into a sale (one winner, idempotent)
    r = requests.post(f"{KAVACH}/confirm", json={
        "reservation_id": reservation, "user_id": user_id})
    return r.json()
```

The stampede-facing call is one HTTP round trip. Pricing, tax, KYC and payment
run between `/reserve` and `/confirm`, where contention no longer exists. This
is the same shape mature ticketing and e-commerce systems use: an inventory
core that wins the race, and an application layer that does commerce.

## What about the numbers?

The k6 cart-flow benchmark already measures this exact end-to-end shape
(reserve + confirm per iteration, group commit, v2.1): about 2,277 req/s with
0 failures and 0 duplicate seats on a 2-core box, p95 157 ms WITH a live
Postgres sharing the container. The details and caveats are in
[BENCHMARK_K6.md](../BENCHMARK_K6.md) and [RESULTS.md](../RESULTS.md).

Two honest points:

- Kavach adds one fast hop (its own p50 is ~0.004 ms server-side). Your app's
  own latency (pricing, payment gateway) is yours and happens off the hot path.
- If you later need business features INSIDE the core, the waitlist webhook
  (`-webhook-url`) shows the pattern: fire-and-forget events out, never
  blocking the request path.

## Integration checklist

- Speak plain HTTP/JSON: nothing exotic to install next to your stack.
- Client SDKs for Python and JavaScript ship in `sdk/`.
- Pass idempotency keys derived from YOUR order IDs, so a retried checkout
  can never create two bookings.
- Read `/seats` for your availability UI and `/metrics` for dashboards.
- Postgres write-behind (v2.1) mirrors every event into SQL, so analytics and
  order history read from your own database.
- Set `-webhook-url` to get `waitlist_fulfilled` events pushed to your app.
