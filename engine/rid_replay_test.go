package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression test: recovery from the WAL alone must restore the reservation
// id counter. idNum used to strip a fixed 2-character prefix ("BK"), so
// "RSV00000007"[2:] was "V00000007" and every reservation id parsed to 0.
// After a snapshot-less restart the counter restarted at 1 and collided
// with ids already on file.
func TestRIDReplayRestoresReservationCounter(t *testing.T) {
	dir := t.TempDir()
	hold := filepath.Join(dir, "holds.jsonl")
	if err := os.WriteFile(hold, []byte(
		`{"booking_id":"","event":"reserved","expires_at":9999999999,"reservation_id":"RSV00000007","seats":[1],"tenant":"t1","ts":100,"user":"u7"}`+"\n"+
			`{"booking_id":"","event":"reserved","expires_at":9999999999,"reservation_id":"RSV00000009","seats":[2],"tenant":"t1","ts":101,"user":"u9"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	inv := NewInventory(50, 0)
	res := NewReservationStore()
	wl := NewWaitlist()
	idem := NewIdemStore()
	var bid, rid, wlSeq uint64
	b, r, w := replayLogs(filepath.Join(dir, "none.jsonl"), hold, inv, res, wl, idem, 60000000000, &bid, &rid, &wlSeq)
	if rid != 9 {
		t.Fatalf("rid not restored from reserved events: got %d want 9", rid)
	}
	if bid != 0 {
		t.Fatalf("bid must stay 0 with no booking lines, got %d", bid)
	}
	if r != 2 || b != 0 || w != 0 {
		t.Fatalf("unexpected replay counts: bookings=%d reservations=%d waitlist=%d", b, r, w)
	}
}
