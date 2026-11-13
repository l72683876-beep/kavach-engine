//go:build redis

package main

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newTestRedis(t *testing.T) string {
	t.Helper()
	mr := miniredis.RunT(t)
	return "redis://" + mr.Addr()
}

func TestRedisLimiterSharedAcrossNodes(t *testing.T) {
	addr := newTestRedis(t)
	a, err := newRedisLimiter(addr, "t1", 0.001, 3) // refill is negligible inside the test: burst is the budget
	if err != nil {
		t.Fatal(err)
	}
	b, err := newRedisLimiter(addr, "t1", 0.001, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if !a.Allow("u1") {
			t.Fatalf("call %d: node A denied with budget left", i+1)
		}
	}
	if a.Allow("u1") {
		t.Fatal("node A passed an empty shared budget")
	}
	if b.Allow("u1") {
		t.Fatal("node B saw its own budget: state is NOT shared")
	}
	if !b.Allow("u2") {
		t.Fatal("a different key must have its own bucket")
	}
}

func TestRedisLimiterRefills(t *testing.T) {
	addr := newTestRedis(t)
	l, err := newRedisLimiter(addr, "t2", 50, 1) // 50 tokens/s
	if err != nil {
		t.Fatal(err)
	}
	if !l.Allow("k") {
		t.Fatal("fresh bucket must allow")
	}
	if l.Allow("k") {
		t.Fatal("empty bucket must deny before refill")
	}
	time.Sleep(30 * time.Millisecond) // ~1.5 tokens refill
	if !l.Allow("k") {
		t.Fatal("refilled bucket must allow again")
	}
}

func TestRedisLimiterZeroRateDisables(t *testing.T) {
	addr := newTestRedis(t)
	l, err := newRedisLimiter(addr, "t3", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if !l.Allow("k") {
			t.Fatal("rate 0 must disable the layer")
		}
	}
}

func TestRedisLimiterFailsOpenWhenRedisDies(t *testing.T) {
	mr := miniredis.RunT(t)
	l, err := newRedisLimiter("redis://"+mr.Addr(), "t4", 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	mr.Close() // Redis dies between startup and the sale
	if !l.Allow("k") {
		t.Fatal("a shared limiter must fail open, never take the sale down")
	}
}

func TestRedisLimiterRefusesABadAddress(t *testing.T) {
	if _, err := newRedisLimiter("redis://127.0.0.1:1", "t5", 10, 5); err == nil {
		t.Fatal("startup must surface an unreachable Redis instead of pretending")
	}
}

func TestLimitersSatisfyTheInterface(t *testing.T) {
	var _ rateLimiter = NewLimiter(1, 1)
	var _ rateLimiter = (*RedisLimiter)(nil)
}
