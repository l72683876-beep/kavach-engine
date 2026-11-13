//go:build redis

package main

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func newWLPair(t *testing.T) (*RedisWaitlist, *RedisWaitlist, *Inventory) {
	t.Helper()
	mr := miniredis.RunT(t)
	a, err := newRedisWaitlist("redis://"+mr.Addr(), "kavach:wl")
	if err != nil {
		t.Fatal(err)
	}
	b, err := newRedisWaitlist("redis://"+mr.Addr(), "kavach:wl")
	if err != nil {
		t.Fatal(err)
	}
	return a.(*RedisWaitlist), b.(*RedisWaitlist), NewInventory(10, 0)
}

func TestRedisWaitlistSharedAcrossNodes(t *testing.T) {
	a, b, inv := newWLPair(t)
	if _, err := a.join("t1", "k1", "u1", 2, 100, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.byIdem("t1", "k1"); !ok { // a join on A is visible on B
		t.Fatal("node B cannot see node A's queued entry")
	}
	if got := b.depth(); got != 1 {
		t.Fatalf("shared depth = %d, want 1", got)
	}
	entry, seats, ok := b.popReady(inv) // B serves the line A joined
	if !ok {
		t.Fatal("node B could not serve the front node A queued")
	}
	if entry.User != "u1" || len(seats) != 2 {
		t.Fatalf("wrong entry served: %+v seats %v", entry, seats)
	}
	if _, ok := b.byIdem("t1", "k1"); ok {
		t.Fatal("a served entry must free its idempotency key")
	}
	if got := b.depth(); got != 0 {
		t.Fatalf("shared depth after serve = %d, want 0", got)
	}
}

func TestRedisWaitlistFIFOAcrossNodes(t *testing.T) {
	a, b, inv := newWLPair(t)
	a.join("t1", "k1", "u1", 1, 100, "")
	b.join("t1", "k2", "u2", 1, 100, "")
	entry, _, ok := b.popReady(inv)
	if !ok || entry.User != "u1" { // whoever queued first is served first, wherever they queued
		t.Fatalf("FIFO broken across nodes: served %+v", entry)
	}
	entry, _, ok = a.popReady(inv)
	if !ok || entry.User != "u2" {
		t.Fatalf("second entry lost: served %+v", entry)
	}
}

func TestRedisWaitlistFrontBlocksAcrossNodes(t *testing.T) {
	a, b, inv := newWLPair(t)
	a.join("t1", "k1", "u1", 3, 100, "") // the front needs 3 seats
	b.join("t1", "k2", "u2", 1, 100, "")
	small := NewInventory(1, 0)
	if _, _, ok := smallPop(small, b); ok {
		t.Fatal("the line served behind a blocked front")
	}
	if _, _, ok := b.popReady(inv); !ok { // 10 seats free: the same front serves now
		t.Fatal("the blocked front never recovered on a node with room")
	}
	// u2 is the front now: with one seat free, u2's single seat serves.
	one := NewInventory(1, 0)
	if entry, seats, ok := b.popReady(one); !ok || entry.User != "u2" || len(seats) != 1 {
		t.Fatalf("the next in line was not served once the front cleared: %+v", entry)
	}
}

// smallPop is a one-shot pop against a different inventory.
func smallPop(inv *Inventory, w *RedisWaitlist) (*WaitEntry, []int, bool) {
	return w.popReady(inv)
}

func TestRedisWaitlistCapShared(t *testing.T) {
	a, b, _ := newWLPair(t)
	if _, err := a.join("t1", "k1", "u1", 1, 1, ""); err != nil {
		t.Fatal(err)
	}
	entry, err := b.join("t1", "k2", "u2", 1, 1, "") // the cap is shared, not per node
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Fatal("node B joined past the shared cap")
	}
}

func TestRedisWaitlistCancelAcrossNodes(t *testing.T) {
	a, b, _ := newWLPair(t)
	e, err := a.join("t1", "k1", "u1", 2, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.cancel(e.ID, "t1"); !ok { // cancel on B reaches A's entry
		t.Fatal("node B could not cancel the entry queued on node A")
	}
	if _, ok := a.byIdem("t1", "k1"); ok {
		t.Fatal("a cancelled entry must free its idempotency key")
	}
	if got := b.depth(); got != 0 {
		t.Fatalf("depth after cancel = %d, want 0", got)
	}
	if _, ok := a.cancel(e.ID, "other"); ok {
		t.Fatal("a cancel under the wrong tenant succeeded")
	}
}

func TestRedisWaitlistClaimsNeverDoubleServe(t *testing.T) {
	a, b, inv := newWLPair(t)
	a.join("t1", "k1", "u1", 2, 100, "")
	if _, _, ok := a.popReady(inv); !ok {
		t.Fatal("first claim failed")
	}
	if _, _, ok := b.popReady(inv); ok {
		t.Fatal("node B served the same entry node A just committed")
	}
	if got := b.depth(); got != 0 {
		t.Fatalf("the committed entry is still in line: depth %d", got)
	}
}

func TestRedisWaitlistStallsGracefullyWhenRedisDies(t *testing.T) {
	mr := miniredis.RunT(t)
	a, err := newRedisWaitlist("redis://"+mr.Addr(), "kavach:wl")
	if err != nil {
		t.Fatal(err)
	}
	b, err := newRedisWaitlist("redis://"+mr.Addr(), "kavach:wl")
	if err != nil {
		t.Fatal(err)
	}
	inv := NewInventory(10, 0)
	a.(*RedisWaitlist).join("t1", "k1", "u1", 2, 100, "")
	mr.Close() // Redis dies between startup and the sale
	if entry, err := a.(*RedisWaitlist).join("t1", "k2", "u2", 1, 100, ""); err == nil {
		t.Fatal("a dead queue must say so, not silently accept joins")
	} else if entry != nil {
		t.Fatal("a dead queue handed out an entry")
	}
	if _, _, ok := b.(*RedisWaitlist).popReady(inv); ok {
		t.Fatal("a dead queue served an entry")
	}
	if got := b.(*RedisWaitlist).depth(); got != 0 {
		t.Fatal("a dead queue reported depth")
	}
}
