#!/usr/bin/env python3
"""Big real-world load test: hammers the DEMO APP (not the engine) exactly
like a flash-sale crowd would, in waves so nobody queues for hours.

    python3 loadtest_app.py [app_port] [buyers] [concurrency] [wave]

Each buyer refreshes the seat board (60%), holds seats, then either pays
(70%) or abandons (30%) so the engine's hold-expiry and waitlist
promotion layers get exercised too. Wave size defaults to concurrency*8.
The engine's final /seats readout is the double-sell oracle.
"""
import asyncio, json, os, sys, time
import aiohttp

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
BUYERS = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
CONC = int(sys.argv[3]) if len(sys.argv) > 3 else 500
WAVE = int(sys.argv[4]) if len(sys.argv) > 4 else CONC * 8
BASE = f"http://127.0.0.1:{PORT}"
REQ_BUDGET = int(os.environ.get("REQ_BUDGET", "2600000"))
lat, stats = [], {"req": 0, "seat_reads": 0, "hold_ok": 0, "hold_sold_out": 0,
                  "hold_other": 0, "pay_ok": 0, "pay_fail": 0, "abandoned": 0,
                  "waitlisted": 0, "wl_other": 0, "errors": 0, "seats_confirmed": 0}
lock = asyncio.Lock()

async def buyer(session, i):
    t0 = time.perf_counter()
    try:
        if i % 5 < 3:
            async with session.get(f"{BASE}/api/seats") as r:
                await r.read()
            async with lock: stats["req"] += 1; stats["seat_reads"] += 1
        n = 2 if i % 10 == 0 else 1
        async with session.post(f"{BASE}/api/hold", json={"user_id": f"u{i}", "seats": n}) as r:
            h = await r.json(content_type=None)
        async with lock: stats["req"] += 1
        if h.get("ok"):
            async with lock: stats["hold_ok"] += 1
            if i % 10 < 7:
                async with session.post(f"{BASE}/api/pay", json={
                        "reservation_id": h["reservation_id"], "user_id": f"u{i}"}) as r:
                    p = await r.json(content_type=None)
                async with lock:
                    stats["req"] += 1
                    if p.get("ok"):
                        stats["pay_ok"] += 1; stats["seats_confirmed"] += len(p.get("seats", []))
                    else:
                        stats["pay_fail"] += 1
            else:
                async with lock: stats["abandoned"] += 1
        elif h.get("status") == "sold_out":
            async with lock: stats["hold_sold_out"] += 1
            if i % 2 == 0:
                async with session.post(f"{BASE}/api/waitlist", json={"user_id": f"u{i}", "seats": n}) as r:
                    w = await r.json(content_type=None)
                async with lock:
                    stats["req"] += 1
                    stats["waitlisted" if w.get("ok") else "wl_other"] += 1
        else:
            async with lock: stats["hold_other"] += 1
    except Exception as e:
        async with lock: stats["errors"] += 1
    async with lock: lat.append((time.perf_counter() - t0) * 1000)

async def main():
    conn = aiohttp.TCPConnector(limit=CONC)
    async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=90)) as s:
        t0 = time.perf_counter(); done = 0
        for start in range(0, BUYERS, WAVE):
            n = min(WAVE, BUYERS - start)
            await asyncio.gather(*(buyer(s, start + j) for j in range(n)))
            done += n
            wall = time.perf_counter() - t0
            if (start // WAVE) % 20 == 0:
                ls = sorted(lat); p = lambda q: ls[int(q * (len(ls) - 1))] if ls else 0
                print(f"[{time.strftime('%H:%M:%S')}] buyers {done} req {stats['req']} "
                      f"{stats['req'] / max(wall, 1e-9):.0f} req/s "
                      f"p50 {p(.50):.0f} p95 {p(.95):.0f} p99 {p(.99):.0f} ms err {stats['errors']}",
                      flush=True)
            if stats["req"] >= REQ_BUDGET:
                print(f"request budget {REQ_BUDGET} reached, stopping", flush=True)
                break
        wall = time.perf_counter() - t0
    ls = sorted(lat); p = lambda q: ls[int(q * (len(ls) - 1))] if ls else 0
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{BASE}/api/seats") as r: seats = await r.json(content_type=None)
        async with s.get(f"{BASE}/api/metrics") as r: met = await r.json(content_type=None)
    print(f"\nFINAL buyers {done} wall {wall:.0f}s app req {stats['req']} ({stats['req'] / wall:.0f} req/s)")
    print(f"engine received {met.get('received')} of {stats['req']} app requests")
    print(f"latency ms per buyer flow: p50 {p(.50):.0f} p95 {p(.95):.0f} p99 {p(.99):.0f} max {ls[-1]:.0f}")
    for k, v in stats.items():
        if k != "req": print(f"  {k}: {v}")
    ok = seats["sold"] == stats["seats_confirmed"] and stats["errors"] == 0
    print(f"engine final: {seats}")
    print("DOUBLE-SELL CHECK:", "PASS" if ok else "FAIL")
    json.dump({"wall_s": wall, "app_requests": stats["req"], "buyers": done,
               "req_s": stats["req"] / wall, **stats, "engine_final": seats,
               "engine_received": met.get("received")},
              open("app-loadtest-final.json", "w"), indent=1)

asyncio.run(main())
