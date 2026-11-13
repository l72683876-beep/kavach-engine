package main

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newPromEngine: a minimal engine good enough for metricsMap, shaped like
// newMskuEngine but without workers.
func newPromEngine(t *testing.T) *Engine {
	t.Helper()
	e := &Engine{
		inv:     NewInventory(100, 0),
		userLim: NewLimiter(1e9, 1e9),
		ipLim:   NewLimiter(1e9, 1e9),
		auth:    NewAuth("ptenant", "psecret"),
		idem:    NewIdemStore(),
		res:     NewReservationStore(),
		lat:     NewLatencyRing(1000),
		started: time.Now().Add(-90 * time.Second),
	}
	return e
}

var promLineRe = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? ([-+0-9.eE]+)$`)

func readProm(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Fatalf("content-type: %q", ct)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(w.Body.String()))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := promLineRe.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("bad prometheus line: %q", line)
		}
		out[m[1]+m[2]] = m[3]
	}
	return out
}

// TestPromFormatAndCounters: the exposition is valid text format, counters
// carry live values, and gauges and the role line are present.
func TestPromFormatAndCounters(t *testing.T) {
	e := newPromEngine(t)
	atomic.AddInt64(&e.received, 3)
	atomic.AddInt64(&e.errors, 1)
	atomic.AddInt64(&e.inFlight, 2)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics/prometheus", nil)
	e.handleMetricsProm(w, r)
	got := readProm(t, w)

	if got["kavach_received_total"] != "3" {
		t.Fatalf("received: %v", got["kavach_received_total"])
	}
	if got["kavach_errors_total"] != "1" {
		t.Fatalf("errors: %v", got["kavach_errors_total"])
	}
	if got["kavach_in_flight"] != "2" {
		t.Fatalf("in_flight: %v", got["kavach_in_flight"])
	}
	if got["kavach_role_info{role=\"leader\"}"] != "1" {
		t.Fatalf("role line missing")
	}
	if got[`kavach_latency_ms{quantile="0.5"}`] == "" || got[`kavach_latency_ms{quantile="0.95"}`] == "" || got[`kavach_latency_ms{quantile="0.99"}`] == "" {
		t.Fatalf("latency quantiles missing: %v", got)
	}
	if got["kavach_uptime_seconds"] == "" || got["kavach_last_snapshot_age_seconds"] == "" {
		t.Fatalf("uptime/snapshot gauges missing")
	}
	if got["kavach_holds_created_total"] != "0" {
		t.Fatalf("holds_created: %v", got["kavach_holds_created_total"])
	}
	// snapshots_total already ends in _total: no doubled suffix.
	if got["kavach_snapshots_total"] == "" || got["kavach_snapshots_total_total"] != "" {
		t.Fatalf("snapshots_total naming wrong")
	}
}

// TestPromMultiShard: counters sum across shards, percentiles stay per shard.
func TestPromMultiShard(t *testing.T) {
	a, b := newPromEngine(t), newPromEngine(t)
	atomic.AddInt64(&a.received, 2)
	atomic.AddInt64(&b.received, 5)
	sr := NewShardRouter([]*Engine{a, b})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics/prometheus", nil)
	sr.handleMetricsProm(w, r)
	got := readProm(t, w)

	if got["kavach_received_total"] != "7" {
		t.Fatalf("sum received: %v", got["kavach_received_total"])
	}
	if got["kavach_shards"] != "2" {
		t.Fatalf("shards: %v", got["kavach_shards"])
	}
	if got[`kavach_latency_ms{quantile="0.5",shard="0"}`] == "" || got[`kavach_latency_ms{quantile="0.95",shard="1"}`] == "" {
		t.Fatalf("per-shard latency missing: %v", got)
	}
	if got[`kavach_role_info{role="leader"}`] != "1" {
		t.Fatalf("role line missing")
	}
}
