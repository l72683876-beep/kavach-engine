package main

// v2.4 part 2: attribute inventory. A SKU's seats can carry attributes
// (tier, row, section) from a layout file, and a reserve request can ask
// for seats matching a filter. The plain count path is untouched: a
// request with no attrs behaves exactly as before.

import (
	"fmt"
	"sync/atomic"
)

// SeatRange gives one attribute map to a seat-index span of a SKU's
// inventory. Indices are LOCAL to the SKU's slice (0..count-1); the first
// matching range wins, so more specific ranges go first.
type SeatRange struct {
	From  int               `json:"from"`
	To    int               `json:"to"` // inclusive; negative means "to the end of the inventory"
	Attrs map[string]string `json:"attrs"`
}

// Layout is a SKU's attribute map.
type Layout struct {
	Ranges []SeatRange `json:"ranges"`
}

// attrsFor returns the attributes of one local seat index, or nil when no
// range covers it.
func (l *Layout) attrsFor(idx int) map[string]string {
	for _, r := range l.Ranges {
		to := r.To
		if to < 0 {
			to = int(^uint(0) >> 1) // max int: the rest of the inventory
		}
		if idx >= r.From && idx <= to {
			return r.Attrs
		}
	}
	return nil
}

// validate checks the layout's shape before the engine serves with it.
func (l *Layout) validate() error {
	for i, r := range l.Ranges {
		if r.From < 0 {
			return fmt.Errorf("range %d: from < 0", i)
		}
		if r.To >= 0 && r.To < r.From {
			return fmt.Errorf("range %d: to < from", i)
		}
		if r.To == 0 && r.From == 0 {
			return fmt.Errorf("range %d: empty span (use a negative to for 'to the end')", i)
		}
	}
	return nil
}

// attrsMatch reports whether a seat's attributes satisfy a request filter:
// every requested key must be present with the requested value.
func attrsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have == nil || have[k] != v {
			return false
		}
	}
	return true
}

// takeMatching locks n free seats whose attributes match the filter, or
// returns nil (giving back anything already taken) when not enough match.
// This is a linear scan over the SKU's seats with a CAS per candidate, so
// it stays correct under concurrency: only free seats flip to held. It is
// the attribute-filtered sibling of Inventory.tryTake and returns GLOBAL
// seat indices like every other take.
func takeMatching(inv *Inventory, layout *Layout, n int, want map[string]string) []int {
	l := len(inv.seats)
	if int(atomic.LoadInt64(&inv.sold))+int(atomic.LoadInt64(&inv.held))+n > l {
		return nil // fast path: everything gone or held
	}
	picked := make([]int, 0, n)
	for i := 0; i < l && len(picked) < n; i++ {
		if len(want) > 0 && !attrsMatch(layout.attrsFor(i), want) {
			continue
		}
		if atomic.CompareAndSwapInt32(&inv.seats[i], seatFree, seatHeld) {
			picked = append(picked, i)
		}
	}
	if len(picked) < n {
		for _, idx := range picked {
			atomic.CompareAndSwapInt32(&inv.seats[idx], seatHeld, seatFree)
		}
		return nil
	}
	atomic.AddInt64(&inv.held, int64(n))
	out := make([]int, len(picked))
	for i, idx := range picked {
		out[i] = idx + inv.offset
	}
	return out
}
