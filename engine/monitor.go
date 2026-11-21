package main

// engine/monitor.go — engine-wide suspicious-activity monitoring (2026-11-21).
//
// MONITORING ONLY, by explicit design decision: the monitor observes and
// alerts. It never blocks, delays, rejects or otherwise alters any request;
// there is no code path from its counters or alerts back into the request
// path. It uses plain deterministic counters, never anomaly scores and never
// AI. The engine's existing controls (HMAC auth, the replay cache, the
// token-bucket rate limiters, the capacity gate) keep doing ALL enforcement.
// Two honest caveats: those existing rate limiters can still reject a
// genuine user who exceeds their configured limits, so no absolute
// zero-block guarantee can be made for the engine as a whole; this monitor
// itself adds no new blocking of any kind.
//
// What it watches per identity over a sliding window:
//   - failed authentications (401s from the auth path)
//   - requests rejected as replays by the HMAC replay cache
//   - requests answered by a rate limiter (429): an attacker pushing on the
//     limits; the limiter still enforces, this only observes
//   - sheer request volume per identity (flood), per IP and per tenant
//   - engine-wide 5xx spikes (a possible in-flight attack or an outage)
//
// Privacy: identity is an authenticated tenant label, or a truncated
// SHA-256 of the client IP. Bodies, query strings and headers are never
// read or recorded. Alerts carry type, identity, count, window and reason
// text only.
//
// Overhead: the observe path is a few atomic increments under a read-locked
// window pointer. Alerts cross a buffered channel that drops rather than
// blocks when full. Storage is bounded: two windows of at most
// -monitor-max-identities entries each, the older window dropped on
// rotation; alerts live in one size-rotating JSONL file.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// MonitorConfig is the monitor's runtime configuration; every field is a
// -monitor-* CLI flag in main() (see docs/MONITORING.md).
type MonitorConfig struct {
	Off           bool          // monitor disabled entirely
	Window        time.Duration // evaluation window (default 60s)
	MaxIdentities int           // identities tracked per window (bounded memory)
	AuthBurst     int           // failed auths per identity per window (0 = off)
	ReplayBurst   int           // replays per identity per window (0 = off)
	LimitedBurst  int           // 429 responses per identity per window (0 = off)
	Flood         int           // requests per identity per window (0 = off)
	ErrorSpike    int           // engine-wide 5xx per window (0 = off)
	AlertLog      string        // JSONL alert log path ("" = no file)
	AlertLogMaxMB int           // rotate the alert log at this size
	Webhook       string        // POST alerts here ("" = off)
	Cooldown      time.Duration // min seconds between same-type alerts per identity
}

const (
	monAlertAuthBurst = iota
	monAlertReplayBurst
	monAlertLimitedBurst
	monAlertFlood
	monAlertErrorSpike
	monAlertCount
)

var monAlertNames = [monAlertCount]string{
	"auth_burst", "replay_burst", "rate_limit_burst", "flood", "server_error_spike",
}

// monEntry holds one identity's counters for one window. All fields are
// atomics: the observe path never holds a lock while touching them.
type monEntry struct {
	reqs      atomic.Int64
	authFails atomic.Int64
	replays   atomic.Int64
	limited   atomic.Int64
	errs      atomic.Int64  // 4xx responses (not 429) to this identity
	alerted   atomic.Uint32 // one bit per alert type; reset by rotation
}

// monWindow is one evaluation window of counters. Two are kept (current and
// previous) so storage stays bounded however many identities appear.
type monWindow struct {
	started  int64 // unix nanos
	entries  map[string]*monEntry
	overflow atomic.Int64 // identities dropped because the map hit its cap
	err5xx   atomic.Int64 // engine-wide 5xx in this window
}

// monAlert is one alert, as written to the log and POSTed to the webhook.
type monAlert struct {
	Ts       string  `json:"ts"`
	Type     string  `json:"type"`
	Identity string  `json:"identity"`
	Reason   string  `json:"reason"`
	Count    int64   `json:"count"`
	WindowS  int     `json:"window_s"`
	PerSec   float64 `json:"per_second"`
}

// Monitor observes every request the engine serves and raises developer
// alerts when deterministic counters cross thresholds. MONITORING ONLY: no
// code path here blocks, slows, or alters any request (see file header).
type Monitor struct {
	cfg MonitorConfig

	mu   sync.RWMutex // guards cur/prev and each window's entries map
	cur  *monWindow
	prev *monWindow

	alerts   chan monAlert // buffered; drops on full, never blocks
	dropped  atomic.Int64
	sent     atomic.Int64
	sentBy   [monAlertCount]atomic.Int64
	coolMu   sync.Mutex
	coolAt   map[string]time.Time // "type|identity" -> last send
	webhookF atomic.Int64

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewMonitor builds a monitor and starts its alert writer. Returns nil when
// the monitor is off; every Monitor method tolerates a nil receiver.
func NewMonitor(cfg MonitorConfig) *Monitor {
	if cfg.Off {
		return nil
	}
	if cfg.Window <= 0 {
		cfg.Window = 60 * time.Second
	}
	if cfg.MaxIdentities <= 0 {
		cfg.MaxIdentities = 10000
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	if cfg.AlertLogMaxMB <= 0 {
		cfg.AlertLogMaxMB = 5
	}
	m := &Monitor{
		cfg:    cfg,
		alerts: make(chan monAlert, 256),
		coolAt: map[string]time.Time{},
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go m.writeLoop()
	return m
}

// Close stops the alert writer and waits for it to drain. Safe to call twice.
func (m *Monitor) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() { close(m.stop) })
	<-m.done
}

// middleware wraps the whole handler chain. It never changes a response: it
// records the status the handler produced (0 = no header written, e.g. a
// panic, counted as a server error) and re-panics untouched. With a nil
// monitor it returns next unchanged: zero overhead.
func (m *Monitor) middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		written := false
		defer func() {
			if !written {
				m.Observe(r, 0)
			}
		}()
		next.ServeHTTP(sw, r)
		written = true
		m.Observe(r, sw.status)
	})
}

// Observe records one finished request. Monitoring only: it cannot fail a
// request or change its response.
func (m *Monitor) Observe(r *http.Request, status int) {
	if m == nil {
		return
	}
	ident := monIPIdentity(r)
	e, w := m.entryFor(ident)
	if e == nil {
		return
	}
	e.reqs.Add(1)
	switch {
	case status == 0 || status >= 500:
		w.err5xx.Add(1)
		e.errs.Add(1)
		m.maybeAlert(e, monAlertErrorSpike, "engine", w.err5xx.Load(), "engine-wide 5xx spike in one window")
	case status == http.StatusTooManyRequests:
		e.limited.Add(1)
		m.maybeAlert(e, monAlertLimitedBurst, ident, e.limited.Load(),
			"rate limiter answered many requests; the limiter still enforces, this only observes")
	default:
		if status >= 400 {
			e.errs.Add(1)
		}
	}
	m.maybeAlert(e, monAlertFlood, ident, e.reqs.Load(), "one identity sent an unusually high number of requests")
}

// NoteAuth records one auth-path outcome (wired as Auth.onVerify). Successes
// are tracked per tenant, so a flood of requests from a VALID key is still
// visible; failures are tracked per client IP, keyed by reason.
func (m *Monitor) NoteAuth(r *http.Request, tenant string, status int, reason string) {
	if m == nil {
		return
	}
	if status == 0 {
		ident := "tenant:" + tenant
		e, _ := m.entryFor(ident)
		if e == nil {
			return
		}
		e.reqs.Add(1)
		m.maybeAlert(e, monAlertFlood, ident, e.reqs.Load(), "one tenant sent an unusually high number of requests")
		return
	}
	ident := monIPIdentity(r)
	e, _ := m.entryFor(ident)
	if e == nil {
		return
	}
	if reason == "replay" {
		e.replays.Add(1)
		m.maybeAlert(e, monAlertReplayBurst, ident, e.replays.Load(), "replay-protected requests rejected repeatedly")
	} else {
		e.authFails.Add(1)
		m.maybeAlert(e, monAlertAuthBurst, ident, e.authFails.Load(), "repeated authentication failures")
	}
}

// entryFor returns the current window and the identity's entry in it,
// rotating the window first when it aged out. Locking discipline: the fast
// path takes one short read lock and returns the entry when it exists; on a
// miss it takes the write lock once and does the rotation and the insert
// inline, never acquiring a second lock while one is held.
func (m *Monitor) entryFor(ident string) (*monEntry, *monWindow) {
	now := time.Now().UnixNano()
	m.mu.RLock()
	w := m.cur
	if w != nil && now-w.started < int64(m.cfg.Window) {
		if e := w.entries[ident]; e != nil {
			m.mu.RUnlock()
			return e, w
		}
	}
	m.mu.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	w = m.cur
	if w == nil || time.Now().UnixNano()-w.started >= int64(m.cfg.Window) {
		m.prev = w
		w = &monWindow{started: time.Now().UnixNano(), entries: map[string]*monEntry{}}
		m.cur = w
	}
	if e := w.entries[ident]; e != nil {
		return e, w
	}
	if len(w.entries) >= m.cfg.MaxIdentities { // bounded: share one overflow entry
		w.overflow.Add(1)
		if e := w.entries["__overflow__"]; e != nil {
			return e, w
		}
		e := &monEntry{}
		w.entries["__overflow__"] = e
		return e, w
	}
	e := &monEntry{}
	w.entries[ident] = e
	return e, w
}

// maybeAlert raises one alert type for one identity at most once per window
// (per-entry bit) and at most once per cooldown across windows.
func (m *Monitor) maybeAlert(e *monEntry, kind int, ident string, count int64, reason string) {
	if e == nil || count <= 0 {
		return
	}
	var threshold int64
	switch kind {
	case monAlertAuthBurst:
		threshold = int64(m.cfg.AuthBurst)
	case monAlertReplayBurst:
		threshold = int64(m.cfg.ReplayBurst)
	case monAlertLimitedBurst:
		threshold = int64(m.cfg.LimitedBurst)
	case monAlertFlood:
		threshold = int64(m.cfg.Flood)
	case monAlertErrorSpike:
		threshold = int64(m.cfg.ErrorSpike)
	}
	if threshold <= 0 || count < threshold {
		return
	}
	if !monTryAlertBit(e, uint32(kind)) {
		return
	}
	m.emit(kind, ident, count, reason)
}

// emit applies the per-type-per-identity cooldown and hands the alert to the
// writer. It drops, never blocks, when the alert channel is full.
func (m *Monitor) emit(kind int, ident string, count int64, reason string) {
	key := monAlertNames[kind] + "|" + ident
	now := time.Now()
	m.coolMu.Lock()
	if last, seen := m.coolAt[key]; seen && now.Sub(last) < m.cfg.Cooldown {
		m.coolMu.Unlock()
		return
	}
	m.coolAt[key] = now
	if len(m.coolAt) > 4096 { // bounded: purge expired entries when it grows big
		for k, t := range m.coolAt {
			if now.Sub(t) >= m.cfg.Cooldown {
				delete(m.coolAt, k)
			}
		}
	}
	m.coolMu.Unlock()
	a := monAlert{
		Ts:       now.UTC().Format(time.RFC3339Nano),
		Type:     monAlertNames[kind],
		Identity: ident,
		Reason:   reason,
		Count:    count,
		WindowS:  int(m.cfg.Window / time.Second),
		PerSec:   float64(count) / m.cfg.Window.Seconds(),
	}
	select {
	case m.alerts <- a:
	default:
		m.dropped.Add(1)
	}
}

// writeLoop consumes alerts off the buffered channel: append to the JSONL
// alert log (with size rotation) and POST to the webhook when configured.
// It runs off the request path: producers drop when the buffer is full.
func (m *Monitor) writeLoop() {
	defer close(m.done)
	var client *http.Client
	if m.cfg.Webhook != "" {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	for {
		select {
		case a := <-m.alerts:
			m.deliver(a, client)
		case <-m.stop:
			for {
				select {
				case a := <-m.alerts:
					m.deliver(a, client)
				default:
					return
				}
			}
		}
	}
}

// deliver records one alert: sent counter, alert log, webhook.
func (m *Monitor) deliver(a monAlert, client *http.Client) {
	m.sent.Add(1)
	m.sentBy[monAlertIndex(a.Type)].Add(1)
	if m.cfg.AlertLog != "" {
		m.appendLog(a)
	}
	if client == nil {
		return
	}
	b, err := json.Marshal(a)
	if err != nil {
		return
	}
	resp, err := client.Post(m.cfg.Webhook, "application/json", bytes.NewReader(b))
	if err != nil {
		m.webhookF.Add(1)
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		m.webhookF.Add(1)
	}
}

// appendLog appends one JSON alert line to the log, rotating the file at
// -monitor-log-max-mb (one previous generation kept: path.1 replaces path).
func (m *Monitor) appendLog(a monAlert) {
	path := m.cfg.AlertLog
	if st, err := os.Stat(path); err == nil && st.Size() >= int64(m.cfg.AlertLogMaxMB)*1024*1024 {
		_ = os.Rename(path, path+".1")
	}
	b, err := json.Marshal(a)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		m.dropped.Add(1)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		m.dropped.Add(1)
	}
}

// Snapshot returns the monitor's live counters for the /monitor endpoint:
// totals and the current window's shape. No identities are listed here.
func (m *Monitor) Snapshot() map[string]interface{} {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	tracked := 0
	var overflow, err5 int64
	if m.cur != nil {
		tracked = len(m.cur.entries)
		overflow = m.cur.overflow.Load()
		err5 = m.cur.err5xx.Load()
	}
	m.mu.RUnlock()
	byType := map[string]int64{}
	for i, name := range monAlertNames {
		if n := m.sentBy[i].Load(); n > 0 {
			byType[name] = n
		}
	}
	return map[string]interface{}{
		"enabled":                true,
		"mode":                   "observe_only",
		"window_seconds":         int(m.cfg.Window / time.Second),
		"tracked_identities":     tracked,
		"overflow_identities":    overflow,
		"five_xx_current_window": err5,
		"alerts_sent":            m.sent.Load(),
		"alerts_dropped":         m.dropped.Load(),
		"alerts_webhook_failed":  m.webhookF.Load(),
		"alerts_by_type":         byType,
	}
}

// handleStatus serves GET /monitor: the observation snapshot. It exposes no
// identities, no paths and no request data, only counters.
func (m *Monitor) handleStatus(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		http.Error(w, "monitor off", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, m.Snapshot())
}

// monIPIdentity is the monitor's identity for an unauthenticated request: a
// truncated SHA-256 of the client IP, never the raw address.
func monIPIdentity(r *http.Request) string {
	ip := monClientIP(r)
	if ip == "" {
		return "ip:unknown"
	}
	return "ip:" + monHash(ip)
}

// monClientIP is the socket-peer host, the same key the IP rate limiter
// uses. X-Forwarded-For is deliberately ignored: a client can forge it.
func monClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func monHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// monTryAlertBit flips the alert bit for one type on one entry, returning
// true only for the observer that flips it first (one alert per window).
func monTryAlertBit(e *monEntry, bit uint32) bool {
	for {
		old := e.alerted.Load()
		if old&(1<<bit) != 0 {
			return false
		}
		if e.alerted.CompareAndSwap(old, old|1<<bit) {
			return true
		}
	}
}

func monAlertIndex(name string) int {
	for i, n := range monAlertNames {
		if n == name {
			return i
		}
	}
	return 0
}
