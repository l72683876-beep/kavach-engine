package main

import (
	"encoding/json"
	"testing"
)

// TestLayoutAttrsFor: first matching range wins; negative to spans the rest.
func TestLayoutAttrsFor(t *testing.T) {
	l := &Layout{Ranges: []SeatRange{
		{From: 0, To: 9, Attrs: map[string]string{"tier": "A", "row": "1"}},
		{From: 10, To: -1, Attrs: map[string]string{"tier": "B"}},
	}}
	if got := l.attrsFor(0)["tier"]; got != "A" {
		t.Fatalf("seat 0 tier: %v", got)
	}
	if got := l.attrsFor(9)["row"]; got != "1" {
		t.Fatalf("seat 9 row: %v", got)
	}
	if got := l.attrsFor(10)["tier"]; got != "B" {
		t.Fatalf("seat 10 tier: %v", got)
	}
	if got := l.attrsFor(500)["tier"]; got != "B" {
		t.Fatalf("seat 500 tier: %v", got)
	}
	if l.attrsFor(0)["tier"] != "A" || len(l.attrsFor(0)) != 2 {
		t.Fatalf("seat 0 attrs: %v", l.attrsFor(0))
	}
	if err := (&Layout{Ranges: []SeatRange{{From: 5, To: 2}}}).validate(); err == nil {
		t.Fatal("to<from accepted")
	}
	if err := (&Layout{Ranges: []SeatRange{{From: -1, To: 5}}}).validate(); err == nil {
		t.Fatal("from<0 accepted")
	}
}

// TestTakeMatching: only seats matching the filter are taken, a shortage
// rolls back what was taken, and the plain pool is untouched by mismatches.
func TestTakeMatching(t *testing.T) {
	inv := NewInventory(10, 100) // global indices 100..109
	l := &Layout{Ranges: []SeatRange{
		{From: 0, To: 4, Attrs: map[string]string{"tier": "A"}},
		{From: 5, To: -1, Attrs: map[string]string{"tier": "B"}},
	}}
	got := takeMatching(inv, l, 2, map[string]string{"tier": "A"})
	if len(got) != 2 || got[0] != 100 || got[1] != 101 {
		t.Fatalf("take A: %v", got)
	}
	// only 3 tier-A seats remain (102,103,104): a 4-count take rolls back
	if got := takeMatching(inv, l, 4, map[string]string{"tier": "A"}); got != nil {
		t.Fatalf("expected rollback, got %v", got)
	}
	_, _, held := inv.stats()
	if held != 2 {
		t.Fatalf("held after rollback: %d", held)
	}
	// tier B works
	got = takeMatching(inv, l, 3, map[string]string{"tier": "B"})
	if len(got) != 3 || got[0] != 105 {
		t.Fatalf("take B: %v", got)
	}
	// no filter matches any free seat, including rolled-back ones
	got = takeMatching(inv, l, 5, nil)
	if len(got) != 5 {
		t.Fatalf("take any: %v", got)
	}
}

// TestLayoutReserveHTTP: a filtered reserve through the real handler
// returns per-seat attributes, a bad filter shortages out whole, and a
// different filter under the same key conflicts.
func TestLayoutReserveHTTP(t *testing.T) {
	e := newMskuEngine(t, 20)
	e.layouts = map[string]*Layout{
		"vip": {Ranges: []SeatRange{
			{From: 0, To: 1, Attrs: map[string]string{"tier": "A"}},
			{From: 2, To: -1, Attrs: map[string]string{"tier": "B"}},
		}},
	}
	w := postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":2,"attrs":{"tier":"A"}}]}`)
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "held" {
		t.Fatalf("status: %v (%s)", resp["status"], w.Body.String())
	}
	items, _ := resp["items"].([]interface{})
	first, _ := items[0].(map[string]interface{})
	sa, _ := first["seat_attrs"].([]interface{})
	if len(sa) != 2 {
		t.Fatalf("seat_attrs: %v", first)
	}
	// a 3-count tier-A take now fails whole (only 0 tier-A seats remain)
	w = postReserve(t, e, `{"user_id":"u2","idempotency_key":"k2","items":[{"sku":"vip","count":3,"attrs":{"tier":"A"}}]}`)
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "sold_out" {
		t.Fatalf("expected shortage, got %v", resp["status"])
	}
	// same key, different filter: conflict, never a silent replay
	w = postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":2,"attrs":{"tier":"B"}}]}`)
	if w.Code != 409 {
		t.Fatalf("filter conflict code %d: %s", w.Code, w.Body.String())
	}
	// attrs on a SKU with no layout: rejected
	w = postReserve(t, e, `{"user_id":"u3","idempotency_key":"k3","items":[{"sku":"standard","count":1,"attrs":{"tier":"A"}}]}`)
	if w.Code != 400 {
		t.Fatalf("no-layout code %d: %s", w.Code, w.Body.String())
	}
}
