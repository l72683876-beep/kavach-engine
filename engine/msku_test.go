package main

import (
	"encoding/json"
	"os"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newMskuEngine: a small engine with two named SKUs plus the default
// inventory, shaped like newIdemEngine.
func newMskuEngine(t *testing.T, seats int) *Engine {
	t.Helper()
	dir := t.TempDir()
	e := &Engine{
		inv:       NewInventory(seats, 0),
		skus:      map[string]*Inventory{"vip": NewInventory(3, 0), "standard": NewInventory(20, 0)},
		userLim:   NewLimiter(1e9, 1e9),
		ipLim:     NewLimiter(1e9, 1e9),
		auth:      NewAuth("bench:btenant", "bsecret"),
		idem:      NewIdemStore(),
		res:       NewReservationStore(),
		queue:     make(chan *job, 1000),
		lat:       NewLatencyRing(1000),
		holdTTL:   300 * time.Second,
		wl:        NewWaitlist(),
		waitCap:   1000,
		webhookCh: make(chan map[string]interface{}, 100),
		httpc:     &http.Client{Timeout: 5 * time.Second},
		started:   time.Now(),
	}
	gc1, err := NewGroupCommit(dir+"/b.jsonl", 1000)
	if err != nil {
		t.Fatal(err)
	}
	gc2, err := NewGroupCommit(dir+"/h.jsonl", 1000)
	if err != nil {
		t.Fatal(err)
	}
	e.bookGC, e.holdGC = gc1, gc2
	for i := 0; i < 2; i++ {
		go e.worker()
	}
	return e
}

func postReserve(t *testing.T, e *Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/reserve", e.handleReserve)
	r := httptest.NewRequest("POST", "/reserve", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	signedReq(r, []byte(body), e.auth.secret, fmt.Sprintf("r%d", time.Now().UnixNano()))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// TestMultiSKUAllOrNothing: a reservation spanning two SKUs lands whole or
// not at all, and a shortage anywhere gives back everything already taken.
func TestMultiSKUAllOrNothing(t *testing.T) {
	e := newMskuEngine(t, 50)

	w := postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":2},{"sku":"standard","count":4}]}`)
	if w.Code != 200 {
		t.Fatalf("code %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "held" {
		t.Fatalf("status: %v (%s)", resp["status"], w.Body.String())
	}
	items, _ := resp["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("items: %v", resp["items"])
	}
	vt, vs, vh := e.skus["vip"].stats()
	if vh != 2 || vt != 3 || vs != 0 {
		t.Fatalf("vip stats: total=%d sold=%d held=%d", vt, vs, vh)
	}
	_, _, sh := e.skus["standard"].stats()
	if sh != 4 {
		t.Fatalf("standard held: %d", sh)
	}

	// shortage: vip only has 8 free left, so a 9-count hold must roll back
	w = postReserve(t, e, `{"user_id":"u2","idempotency_key":"k2","items":[{"sku":"vip","count":3},{"sku":"standard","count":1}]}`)
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "sold_out" {
		t.Fatalf("expected sold_out, got %v (%s)", resp["status"], w.Body.String())
	}
	if _, ok := resp["shortage"]; !ok {
		t.Fatalf("no shortage map: %s", w.Body.String())
	}
	// rollback: u1's holds are the ONLY holds left on both SKUs
	if _, _, vh := e.skus["vip"].stats(); vh != 2 {
		t.Fatalf("vip held after rollback: %d", vh)
	}
	if _, _, sh := e.skus["standard"].stats(); sh != 4 {
		t.Fatalf("standard held after rollback: %d", sh)
	}
}

// TestMultiSKUIdempotency: the same key replays the same multi-SKU hold; a
// different item list under the same key is a conflict.
func TestMultiSKUIdempotency(t *testing.T) {
	e := newMskuEngine(t, 50)
	body := `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"standard","count":2},{"sku":"vip","count":1}]}`
	postReserve(t, e, body)
	w := postReserve(t, e, body) // same items, different order in the JSON
	if w.Code != 200 {
		t.Fatalf("replay code %d: %s", w.Code, w.Body.String())
	}
	if _, _, vh := e.skus["vip"].stats(); vh != 1 {
		t.Fatalf("vip held after replay: %d (double-take)", vh)
	}
	w = postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":2}]}`)
	if w.Code != 409 {
		t.Fatalf("conflict code %d: %s", w.Code, w.Body.String())
	}
}

// TestMultiSKUConfirmReleasePerSKU: confirm marks each SKU's seats sold and
// release gives each back, never crossing SKUs.
func TestMultiSKUConfirmReleasePerSKU(t *testing.T) {
	e := newMskuEngine(t, 50)
	w := postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":1},{"sku":"standard","count":2}]}`)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	rid, _ := resp["reservation_id"].(string)
	if rid == "" {
		t.Fatalf("no reservation id: %s", w.Body.String())
	}

	// release path
	mux := http.NewServeMux()
	mux.HandleFunc("/release", e.handleRelease)
	r := httptest.NewRequest("POST", "/release", strings.NewReader(`{"reservation_id":"`+rid+`"}`))
	signedReq(r, []byte(`{"reservation_id":"`+rid+`"}`), e.auth.secret, "r1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("release code %d: %s", rec.Code, rec.Body.String())
	}
	if _, _, vh := e.skus["vip"].stats(); vh != 0 {
		t.Fatalf("vip held after release: %d", vh)
	}
	if _, _, sh := e.skus["standard"].stats(); sh != 0 {
		t.Fatalf("standard held after release: %d", sh)
	}

	// confirm path: re-reserve, then confirm through handleConfirm
	w = postReserve(t, e, `{"user_id":"u1","idempotency_key":"k2","items":[{"sku":"vip","count":2}]}`)
	json.Unmarshal(w.Body.Bytes(), &resp)
	rid, _ = resp["reservation_id"].(string)
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/confirm", e.handleConfirm)
	body := `{"reservation_id":"` + rid + `","user_id":"u1"}`
	r2 := httptest.NewRequest("POST", "/confirm", strings.NewReader(body))
	signedReq(r2, []byte(body), e.auth.secret, "r2")
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, r2)
	if rec2.Code != 200 {
		t.Fatalf("confirm code %d: %s", rec2.Code, rec2.Body.String())
	}
	vt, vs, vh := e.skus["vip"].stats()
	if vs != 2 || vh != 0 {
		t.Fatalf("vip after confirm: sold=%d held=%d", vs, vh)
	}
	if vt != 3 {
		t.Fatalf("vip total: %d", vt)
	}
}

// TestMultiSKUExpiryPerSKU: an abandoned multi-SKU hold expires back to its
// own SKUs.
func TestMultiSKUExpiryPerSKU(t *testing.T) {
	e := newMskuEngine(t, 50)
	e.holdTTL = 10 * time.Millisecond
	w := postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":2},{"sku":"standard","count":3}]}`)
	if w.Code != 200 {
		t.Fatalf("code %d: %s", w.Code, w.Body.String())
	}
	time.Sleep(30 * time.Millisecond)
	e.expireSweep()
	if _, _, vh := e.skus["vip"].stats(); vh != 0 {
		t.Fatalf("vip held after expiry: %d", vh)
	}
	if _, _, sh := e.skus["standard"].stats(); sh != 0 {
		t.Fatalf("standard held after expiry: %d", sh)
	}
}

// TestMultiSKUWALReplay: a multi-SKU hold's WAL lines replay back onto the
// right SKUs: reserved, confirmed, released.
func TestMultiSKUWALReplay(t *testing.T) {
	e := newMskuEngine(t, 50)
	e.holdTTL = time.Hour
	postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":1},{"sku":"standard","count":2}]}`)
	time.Sleep(50 * time.Millisecond) // let the group committer flush

	// a fresh engine over the same logs: recovery re-reads them per SKU
	e2 := newMskuEngine(t, 50)
	e2.holdTTL = time.Hour
	src := e.bookGC.path
	hsrc := e.holdGC.path
	// copy the logs into e2's dirs under the same base names
	copyFile(t, src, e2.bookGC.path)
	copyFile(t, hsrc, e2.holdGC.path)
	e2.skuMu.Lock()
	e2.skus = map[string]*Inventory{"vip": NewInventory(10, 0), "standard": NewInventory(20, 0)}
	e2.skuMu.Unlock()
	recoverState(t.TempDir(), e2.bookGC.path, e2.holdGC.path,
		e2.inv, e2.res, e2.wl.(*Waitlist), e2.idem, e2.holdTTL, &e2.bid, &e2.rid, &waitlistSeq, e2.skus)
	if _, _, vh := e2.skus["vip"].stats(); vh != 1 {
		t.Fatalf("vip held after replay: %d", vh)
	}
	if _, _, sh := e2.skus["standard"].stats(); sh != 2 {
		t.Fatalf("standard held after replay: %d", sh)
	}
	// the reservation carries its items
	var found *Reservation
	for _, r := range e2.res.m {
		found = r
	}
	if found == nil || len(found.Items) != 2 {
		t.Fatalf("replayed reservation items: %+v", found)
	}
}

// TestMultiSKUSnapshotRoundTrip: SKUs and item reservations survive a
// snapshot capture and restore.
func TestMultiSKUSnapshotRoundTrip(t *testing.T) {
	e := newMskuEngine(t, 50)
	postReserve(t, e, `{"user_id":"u1","idempotency_key":"k1","items":[{"sku":"vip","count":2}]}`)
	e2 := newMskuEngine(t, 50)

	e.freeze.Lock()
	p := e.capture()
	e.freeze.Unlock()
	// restore into e2's stores
	e2.skuMu.Lock()
	e2.skus = map[string]*Inventory{}
	e2.skuMu.Unlock()
	applySnapshot(p, e2.inv, e2.res, e2.wl.(*Waitlist), e2.idem, &e2.bid, &e2.rid, &waitlistSeq, e2.skus)
	si, ok := e2.skus["vip"]
	if !ok {
		t.Fatalf("vip missing after restore: %v", e2.skus)
	}
	if _, _, vh := si.stats(); vh != 2 {
		t.Fatalf("vip held after restore: %d", vh)
	}
	var found *Reservation
	for _, r := range e2.res.m {
		found = r
	}
	if found == nil || len(found.Items) != 1 || found.Items[0].SKU != "vip" {
		t.Fatalf("restored reservation: %+v", found)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
