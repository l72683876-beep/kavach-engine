package main

// Tests for the engine-wide monitor. The invariants under test:
//   1. the monitor never alters a response (monitoring only);
//   2. suspicious patterns raise exactly one alert per window per identity;
//   3. legitimate traffic stays silent;
//   4. storage is bounded and identities are private;
//   5. a backlogged alert writer cannot slow a request.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testMonitor(t *testing.T, mutate func(*MonitorConfig)) *Monitor {
	t.Helper()
	cfg := MonitorConfig{
		Window:        time.Second,
		MaxIdentities: 100,
		AuthBurst:     5,
		ReplayBurst:   3,
		LimitedBurst:  5,
		Flood:         10,
		ErrorSpike:    3,
		Cooldown:      300 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	m := NewMonitor(cfg)
	t.Cleanup(func() { m.Close() })
	return m
}

func readAlerts(t *testing.T, path string) []monAlert {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []monAlert
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var a monAlert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("bad alert line %q: %v", line, err)
		}
		out = append(out, a)
	}
	return out
}

func countType(alerts []monAlert, typ string) int {
	n := 0
	for _, a := range alerts {
		if a.Type == typ {
			n++
		}
	}
	return n
}

// ok200 returns a handler that answers 200 and a recorder per request.
func ok200() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// 1. The monitor is pass-through for every response class, and a nil
// monitor compiles away entirely.
func TestMonitorNeverTouchesResponses(t *testing.T) {
	for _, status := range []int{200, 201, 400, 401, 403, 429, 500} {
		m := testMonitor(t, nil)
		rec := httptest.NewRecorder()
		m.middleware(ok200With(status)).ServeHTTP(rec, httptest.NewRequest("POST", "/book", nil))
		if rec.Code != status {
			t.Fatalf("status %d came back as %d: the monitor must never alter a response", status, rec.Code)
		}
	}
	var nilMon *Monitor
	rec := httptest.NewRecorder()
	nilMon.middleware(ok201()).ServeHTTP(rec, httptest.NewRequest("GET", "/seats", nil))
	if rec.Code != 201 {
		t.Fatal("nil monitor changed the handler")
	}
}

func ok200With(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	})
}

func ok201() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	})
}

// 2. A flood raises exactly one flood alert in the window; the requests
// themselves all still succeed.
func TestMonitorFloodAlertOnce(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "alerts.jsonl")
	m := testMonitor(t, func(c *MonitorConfig) { c.AlertLog = logPath; c.Flood = 5 })
	for i := 0; i < 6; i++ {
		rec := httptest.NewRecorder()
		m.middleware(ok200()).ServeHTTP(rec, httptest.NewRequest("GET", "/seats", nil))
		if rec.Code != 200 {
			t.Fatal("a legitimate request was disturbed by the monitor")
		}
	}
	m.Close()
	alerts := readAlerts(t, logPath)
	if n := countType(alerts, "flood"); n != 1 {
		t.Fatalf("want exactly 1 flood alert, got %d (%v)", n, alerts)
	}
	for _, a := range alerts {
		if !strings.HasPrefix(a.Identity, "ip:") || strings.Contains(a.Identity, "192.0.2.1") {
			t.Fatalf("identity must be a hash, got %q", a.Identity)
		}
	}
}

// 3. Failed auths and replays raise their alerts; a successful tenant's
// flood is visible under its tenant identity.
func TestMonitorAuthReplayAndTenantFlood(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "alerts.jsonl")
	m := testMonitor(t, func(c *MonitorConfig) { c.AlertLog = logPath })
	req := httptest.NewRequest("POST", "/book", nil)
	for i := 0; i < 5; i++ {
		m.NoteAuth(req, "", 401, "unauthorized")
	}
	for i := 0; i < 3; i++ {
		m.NoteAuth(req, "", 401, "replay")
	}
	ok := httptest.NewRequest("GET", "/seats", nil)
	for i := 0; i < 11; i++ {
		m.NoteAuth(ok, "acme", 0, "")
	}
	m.Close()
	alerts := readAlerts(t, logPath)
	if n := countType(alerts, "auth_burst"); n != 1 {
		t.Fatalf("want 1 auth_burst, got %d", n)
	}
	if n := countType(alerts, "replay_burst"); n != 1 {
		t.Fatalf("want 1 replay_burst, got %d", n)
	}
	if n := countType(alerts, "flood"); n != 1 {
		t.Fatalf("want 1 tenant flood, got %d", n)
	}
	for _, a := range alerts {
		if a.Type == "flood" && a.Identity != "tenant:acme" {
			t.Fatalf("tenant flood identity = %q, want tenant:acme", a.Identity)
		}
	}
}

// 4. Rate-limited responses and 5xx spikes alert; the limiter still
// enforced (the monitor only observes).
func TestMonitorLimitedAndErrorSpike(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "alerts.jsonl")
	m := testMonitor(t, func(c *MonitorConfig) { c.AlertLog = logPath })
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/seats", nil)
		rec := httptest.NewRecorder()
		m.middleware(ok200With(http.StatusTooManyRequests)).ServeHTTP(rec, req)
	}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/seats", nil)
		req.RemoteAddr = "198.51.100.9:9"
		rec := httptest.NewRecorder()
		m.middleware(ok200With(500)).ServeHTTP(rec, req)
	}
	m.Close()
	alerts := readAlerts(t, logPath)
	if n := countType(alerts, "rate_limit_burst"); n != 1 {
		t.Fatalf("want 1 rate_limit_burst, got %d", n)
	}
	if n := countType(alerts, "server_error_spike"); n != 1 {
		t.Fatalf("want 1 server_error_spike, got %d", n)
	}
}

// 5. Identity cardinality is capped: memory stays bounded even under an
// attack from thousands of addresses.
func TestMonitorBoundedIdentities(t *testing.T) {
	m := testMonitor(t, func(c *MonitorConfig) { c.MaxIdentities = 4 })
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/seats", nil)
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:5000", i%200+1)
		m.Observe(req, 200)
	}
	m.mu.RLock()
	tracked := len(m.cur.entries)
	overflow := m.cur.overflow.Load()
	m.mu.RUnlock()
	if tracked > 5 { // the cap, plus the shared overflow entry
		t.Fatalf("storage unbounded: %d identities tracked", tracked)
	}
	if overflow == 0 {
		t.Fatal("the overflow counter never engaged")
	}
}

// 6. Alerts carry no request data: no headers, no query, no body, no raw IP.
func TestMonitorAlertsArePrivate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "alerts.jsonl")
	m := testMonitor(t, func(c *MonitorConfig) { c.AlertLog = logPath; c.AuthBurst = 2 })
	req := httptest.NewRequest("POST", "/book?user_id=secret-user-42&api_key=supersecret", strings.NewReader(`{"seats":2,"card":"4111"}`))
	req.Header.Set("Authorization", "Bearer sk-live-topsecret")
	req.RemoteAddr = "203.0.113.7:4444"
	for i := 0; i < 3; i++ {
		m.NoteAuth(req, "", 401, "unauthorized")
	}
	m.Close()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"supersecret", "sk-live-topsecret", "secret-user-42", "203.0.113.7", "4111", "user_id"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("alert log leaked %q:\n%s", secret, raw)
		}
	}
}

// 7. The cooldown holds across window rotations: one alert per type per
// identity per cooldown, not one per window.
func TestMonitorCooldownAcrossWindows(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "alerts.jsonl")
	m := testMonitor(t, func(c *MonitorConfig) {
		c.AlertLog = logPath
		c.AuthBurst = 1
		c.Cooldown = 500 * time.Millisecond
		c.Window = 50 * time.Millisecond
	})
	req := httptest.NewRequest("POST", "/book", nil)
	for i := 0; i < 3; i++ {
		m.NoteAuth(req, "", 401, "unauthorized")
	}
	time.Sleep(120 * time.Millisecond) // the window rotates, counters reset
	for i := 0; i < 3; i++ {
		m.NoteAuth(req, "", 401, "unauthorized")
	}
	m.Close()
	alerts := readAlerts(t, logPath)
	if n := countType(alerts, "auth_burst"); n != 1 {
		t.Fatalf("cooldown failed: %d auth_burst alerts, want 1", n)
	}
}

// 8. A backlogged writer (a webhook that never answers) cannot slow a
// request: the observe path drops alerts instead of blocking.
func TestMonitorDropsWhenBacklogged(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unpark := func() { releaseOnce.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		unpark()
		srv.Close()
	}()
	m := testMonitor(t, func(c *MonitorConfig) {
		c.Webhook = srv.URL
		c.MaxIdentities = 1000 // every producer identity must count on its own
		c.Flood = 1
		c.AuthBurst = 1
		c.ReplayBurst = 1
		c.LimitedBurst = 1
		c.ErrorSpike = 1
	})
	// The first alert parks in the blocked webhook; keep feeding alerts
	// until the channel is full, then prove requests still answer fast.
	for i := 0; i < 400; i++ {
		req := httptest.NewRequest("GET", "/seats", nil)
		req.RemoteAddr = fmt.Sprintf("10.2.%d.%d:2", i/250, i%250+1)
		m.NoteAuth(req, "", 401, "unauthorized")
	}
	start := time.Now()
	rec := httptest.NewRecorder()
	m.middleware(ok200()).ServeHTTP(rec, httptest.NewRequest("GET", "/seats", nil))
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Fatalf("a backlogged monitor slowed a request by %v", el)
	}
	if m.dropped.Load() == 0 {
		t.Fatalf("expected dropped alerts once the channel filled (sent=%d dropped=%d)",
			m.sent.Load(), m.dropped.Load())
	}
	unpark()
	m.Close()
}

// 9. Windows rotate: the new window starts clean, the previous one keeps
// its entries until it too is rotated out (bounded at all times).
func TestMonitorWindowRotation(t *testing.T) {
	m := testMonitor(t, func(c *MonitorConfig) {
		c.Window = 40 * time.Millisecond
		c.MaxIdentities = 1000
	})
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/seats", nil)
		req.RemoteAddr = fmt.Sprintf("10.3.0.%d:3", i+1)
		m.Observe(req, 200)
	}
	time.Sleep(80 * time.Millisecond)                         // age the window out
	m.Observe(httptest.NewRequest("GET", "/seats", nil), 200) // force one rotation
	m.mu.RLock()
	cur := len(m.cur.entries)
	prev := 0
	if m.prev != nil {
		prev = len(m.prev.entries)
	}
	m.mu.RUnlock()
	if cur != 1 {
		t.Fatalf("the rotated-in window should hold just the new request, holds %d", cur)
	}
	if prev != 50 {
		t.Fatalf("the rotated-out window lost entries: %d", prev)
	}
}

// 10. GET /monitor exposes only counters.
func TestMonitorSnapshotEndpoint(t *testing.T) {
	m := testMonitor(t, func(c *MonitorConfig) { c.AuthBurst = 1 })
	req := httptest.NewRequest("POST", "/book", nil)
	m.NoteAuth(req, "", 401, "unauthorized")
	m.Close() // flush the writer
	rec := httptest.NewRecorder()
	m.handleStatus(rec, httptest.NewRequest("GET", "/monitor", nil))
	if rec.Code != 200 {
		t.Fatalf("/monitor answered %d", rec.Code)
	}
	var snap map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap["mode"] != "observe_only" {
		t.Fatalf("mode = %v, want observe_only", snap["mode"])
	}
	if snap["tracked_identities"].(float64) != 1 {
		t.Fatalf("tracked_identities = %v", snap["tracked_identities"])
	}
	if snap["alerts_sent"].(float64) != 1 {
		t.Fatalf("alerts_sent = %v", snap["alerts_sent"])
	}
	// non-GET is refused
	rec2 := httptest.NewRecorder()
	m.handleStatus(rec2, httptest.NewRequest("POST", "/monitor", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /monitor answered %d", rec2.Code)
	}
}

// 11. The auth hook fires with the real outcomes and never changes them.
func TestAuthOnVerifyHook(t *testing.T) {
	a := NewAuth("key1:tenant1", "")
	type call struct {
		tenant string
		st     int
		msg    string
	}
	var mu sync.Mutex
	var calls []call
	a.onVerify = func(r *http.Request, tenant string, st int, msg string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call{tenant, st, msg})
	}
	req := httptest.NewRequest("GET", "/seats", nil)
	req.Header.Set("Authorization", "Bearer key1")
	if _, st, _ := a.verify(req, nil); st != 0 {
		t.Fatal("a valid key was rejected with the hook installed")
	}
	bad := httptest.NewRequest("GET", "/seats", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	if _, st, _ := a.verify(bad, nil); st != 401 {
		t.Fatal("a bad key was accepted with the hook installed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("the hook fired %d times, want 2", len(calls))
	}
	if calls[0] != (call{"tenant1", 0, ""}) {
		t.Fatalf("success outcome wrong: %+v", calls[0])
	}
	if calls[1].st != 401 || calls[1].msg != "unauthorized" {
		t.Fatalf("failure outcome wrong: %+v", calls[1])
	}
}
