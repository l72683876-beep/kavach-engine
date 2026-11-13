package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// postConfirm drives handleConfirm for a reservation id.
func postConfirm(t *testing.T, e *Engine, rid, user string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"reservation_id":"` + rid + `","user_id":"` + user + `"}`
	mux := http.NewServeMux()
	mux.HandleFunc("/confirm", e.handleConfirm)
	r := httptest.NewRequest("POST", "/confirm", strings.NewReader(body))
	signedReq(r, []byte(body), e.auth.secret, fmt.Sprintf("c%d", time.Now().UnixNano()))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func postTransfer(t *testing.T, e *Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/transfer", e.handleTransfer)
	r := httptest.NewRequest("POST", "/transfer", strings.NewReader(body))
	signedReq(r, []byte(body), e.auth.secret, fmt.Sprintf("t%d", time.Now().UnixNano()))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func reserveOnce(t *testing.T, e *Engine, body string) string {
	t.Helper()
	w := postReserve(t, e, body)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	rid, _ := resp["reservation_id"].(string)
	if rid == "" {
		t.Fatalf("no reservation id: %s", w.Body.String())
	}
	return rid
}

// TestTransferConfirmedBooking: a confirmed booking moves to the new user,
// a repeat to the same user is idempotent, and a held booking cannot move.
func TestTransferConfirmedBooking(t *testing.T) {
	e := newMskuEngine(t, 50)
	rid := reserveOnce(t, e, `{"user_id":"u1","idempotency_key":"k1","seats":2}`)
	if w := postConfirm(t, e, rid, "u1"); w.Code != 200 {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	w := postTransfer(t, e, `{"reservation_id":"`+rid+`","user_id":"u1","to_user":"priya"}`)
	if w.Code != 200 {
		t.Fatalf("transfer: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["user_id"] != "priya" {
		t.Fatalf("owner: %v (%s)", resp["user_id"], w.Body.String())
	}
	// idempotent: same to_user again
	w = postTransfer(t, e, `{"reservation_id":"`+rid+`","to_user":"priya"}`)
	if w.Code != 200 {
		t.Fatalf("idempotent transfer: %d %s", w.Code, w.Body.String())
	}
	// resale onward: a different user works when unlocked
	w = postTransfer(t, e, `{"reservation_id":"`+rid+`","user_id":"priya","to_user":"rahul"}`)
	if w.Code != 200 {
		t.Fatalf("resale: %d %s", w.Code, w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["user_id"] != "rahul" {
		t.Fatalf("owner after resale: %v", resp["user_id"])
	}
	// a held booking cannot move
	rid2 := reserveOnce(t, e, `{"user_id":"u2","idempotency_key":"k2","seats":1}`)
	w = postTransfer(t, e, `{"reservation_id":"`+rid2+`","to_user":"priya"}`)
	if w.Code != 409 {
		t.Fatalf("held transfer: %d %s", w.Code, w.Body.String())
	}
	// a wrong owner is forbidden
	rid3 := reserveOnce(t, e, `{"user_id":"u3","idempotency_key":"k3","seats":1}`)
	if w := postConfirm(t, e, rid3, "u3"); w.Code != 200 {
		t.Fatalf("confirm3: %d %s", w.Code, w.Body.String())
	}
	w = postTransfer(t, e, `{"reservation_id":"`+rid3+`","user_id":"someone-else","to_user":"priya"}`)
	if w.Code != 403 {
		t.Fatalf("wrong owner: %d %s", w.Code, w.Body.String())
	}
}

// TestResaleLock: reserve with resale_lock refuses every transfer, and the
// lock survives a WAL replay.
func TestResaleLock(t *testing.T) {
	e := newMskuEngine(t, 50)
	rid := reserveOnce(t, e, `{"user_id":"u1","idempotency_key":"k1","seats":1,"resale_lock":true}`)
	if w := postConfirm(t, e, rid, "u1"); w.Code != 200 {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	w := postTransfer(t, e, `{"reservation_id":"`+rid+`","user_id":"u1","to_user":"priya"}`)
	if w.Code != 409 {
		t.Fatalf("locked transfer: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "resale_locked") {
		t.Fatalf("body: %s", w.Body.String())
	}
	// unlocked booking transfers fine
	rid2 := reserveOnce(t, e, `{"user_id":"u2","idempotency_key":"k2","seats":1}`)
	if w := postConfirm(t, e, rid2, "u2"); w.Code != 200 {
		t.Fatalf("confirm2: %d %s", w.Code, w.Body.String())
	}
	if w := postTransfer(t, e, `{"reservation_id":"`+rid2+`","to_user":"priya"}`); w.Code != 200 {
		t.Fatalf("unlocked transfer: %d %s", w.Code, w.Body.String())
	}
}

// TestTransferWALReplay: transfers and resale locks replay back in order.
func TestTransferWALReplay(t *testing.T) {
	e := newMskuEngine(t, 50)
	rid := reserveOnce(t, e, `{"user_id":"u1","idempotency_key":"k1","seats":1,"resale_lock":true}`)
	if w := postConfirm(t, e, rid, "u1"); w.Code != 200 {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	rid2 := reserveOnce(t, e, `{"user_id":"u2","idempotency_key":"k2","seats":1}`)
	if w := postConfirm(t, e, rid2, "u2"); w.Code != 200 {
		t.Fatalf("confirm2: %d %s", w.Code, w.Body.String())
	}
	if w := postTransfer(t, e, `{"reservation_id":"`+rid2+`","to_user":"priya"}`); w.Code != 200 {
		t.Fatalf("transfer: %d %s", w.Code, w.Body.String())
	}
	time.Sleep(50 * time.Millisecond) // let the group committer flush

	e2 := newMskuEngine(t, 50)
	copyFile(t, e.bookGC.path, e2.bookGC.path)
	copyFile(t, e.holdGC.path, e2.holdGC.path)
	recoverState(t.TempDir(), e2.bookGC.path, e2.holdGC.path,
		e2.inv, e2.res, e2.wl.(*Waitlist), e2.idem, e2.holdTTL, &e2.bid, &e2.rid, &waitlistSeq, e2.skus)
	r1, ok := e2.res.m[rid]
	if !ok {
		t.Fatalf("rid missing after replay")
	}
	if !r1.ResaleLock || r1.User != "u1" {
		t.Fatalf("locked booking after replay: user=%s lock=%v", r1.User, r1.ResaleLock)
	}
	r2, ok := e2.res.m[rid2]
	if !ok {
		t.Fatalf("rid2 missing after replay")
	}
	if r2.User != "priya" || r2.ResaleLock {
		t.Fatalf("transferred booking after replay: user=%s lock=%v", r2.User, r2.ResaleLock)
	}
}
