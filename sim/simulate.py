#!/usr/bin/env python3
"""Kavach load simulator: fakes a Tatkal-style rush against the engine."""
import argparse, asyncio, collections, json, random, time
import aiohttp

async def attempt(session, uid, key, seats, stats, is_bot, base, max_tries=8):
    for i in range(max_tries):
        try:
            async with session.post(base + "/book", json={
                "user_id": uid, "idempotency_key": key, "seats": seats}) as r:
                data = await r.json()
                st = data.get("status", "?")
                stats["statuses"][st] += 1
                if st == "confirmed":
                    stats["confirmed_seats"] += seats
                    return
                if st == "sold_out":
                    return
                # rate_limited / queue_full / processing: retry
                if not is_bot:
                    await asyncio.sleep(random.uniform(0.05, 0.6))
        except Exception:
            stats["errors"] += 1
            await asyncio.sleep(0.2)
    stats["gave_up"] += 1

async def burst_mode(args, stats):
    """Run A: every user fires at once, one booking attempt each."""
    conn = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=conn) as s:
        sem = asyncio.Semaphore(args.concurrency or args.users)
        async def one(n):
            async with sem:
                uid = f"user{n}"
                seats = 2 if random.random() < 0.1 else 1
                await attempt(s, uid, f"{uid}-key", seats, stats, False, args.base)
        t0 = time.perf_counter()
        await asyncio.gather(*[one(i) for i in range(args.users)])
        return time.perf_counter() - t0

async def hammer_mode(args, stats):
    """Run B: constant pressure until N requests are sent, with bots."""
    conn = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=conn) as s:
        counter = 0
        t0 = time.perf_counter()
        sem = asyncio.Semaphore(args.concurrency)
        async def worker(wid):
            nonlocal counter
            while True:
                async with sem:
                    n = counter
                    counter += 1
                    if n >= args.total:
                        return
                    uid = f"user{random.randrange(args.users)}"
                    is_bot = random.random() < args.bots
                    await attempt(s, uid, f"{uid}-{n}", 1, stats, is_bot, args.base,
                                  max_tries=6 if is_bot else 4)
        await asyncio.gather(*[worker(i) for i in range(args.concurrency)])
        return time.perf_counter() - t0

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", type=int, default=20000)
    ap.add_argument("--total", type=int, default=0, help="hammer mode total requests")
    ap.add_argument("--concurrency", type=int, default=0)
    ap.add_argument("--bots", type=float, default=0.0)
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--out", default="sim_results.json")
    args = ap.parse_args()

    stats = {"statuses": collections.Counter(), "confirmed_seats": 0,
             "errors": 0, "gave_up": 0}
    dur = await (hammer_mode(args, stats) if args.total else burst_mode(args, stats))

    async with aiohttp.ClientSession() as s:
        seats = await (await s.get(args.base + "/seats")).json()
        metrics = await (await s.get(args.base + "/metrics")).json()

    total_sent = sum(stats["statuses"].values())
    report = {
        "mode": "hammer" if args.total else "burst",
        "wall_seconds": round(dur, 2),
        "requests_sent_by_clients": total_sent,
        "throughput_rps": round(total_sent / dur, 1) if dur else 0,
        "statuses": dict(stats["statuses"]),
        "confirmed_seats_client_view": stats["confirmed_seats"],
        "server_view": seats,
        "server_metrics": metrics,
        "client_errors": stats["errors"],
        "gave_up": stats["gave_up"],
        "config": vars(args),
    }
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
