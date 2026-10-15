// Kavach: a booking engine built to survive a stampede.
// Core v1.5: adds security hardening (bearer API keys, HMAC request signing,
// replay protection, layered rate limits, an in-flight capacity gate, strict
// input validation, and persist-before-ack durable logging) on top of the v1
// core: bounded admission queue, worker pool, atomic CAS inventory,
// idempotency keys, append-only booking log.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- seat inventory (the accuracy core) ----------

const (
	seatFree = int32(0)
	seatHeld = int32(1)
	seatSold = int32(2)
)

type Inventory struct {
	seats  []int32
	cursor uint64
	sold   int64
}

func NewInventory(n int) *Inventory { return &Inventory{seats: make([]int32, n)} }

// tryTake atomically locks n seats, or returns nil when not enough are free.
// A compare-and-swap on each seat means two workers can never hold the same seat.
func (inv *Inventory) tryTake(n int) []int {
	l := len(inv.seats)
	if int(atomic.LoadInt64(&inv.sold))+n > l {
		return nil // fast path: everything gone
	}
	picked := make([]int, 0, n)
	start := int(atomic.AddUint64(&inv.cursor, uint64(n)) % uint64(l))
	for i := 0; i < l && len(picked) < n; i++ {
		idx := (start + i) % l
		if atomic.CompareAndSwapInt32(&inv.seats[idx], seatFree, seatHeld) {
			picked = append(picked, idx)
		}
	}
	if len(picked) < n { // not enough together: give back what we held
		for _, idx := range picked {
			atomic.CompareAndSwapInt32(&inv.seats[idx], seatHeld, seatFree)
		}
		return nil
	}
	return picked
}

func (inv *Inventory) commit(seats []int) {
	for _, idx := range seats {
		atomic.StoreInt32(&inv.seats[idx], seatSold)
	}
	atomic.AddInt64(&inv.sold, int64(len(seats)))
}

func (inv *Inventory) stats() (total, sold int) {
	return len(inv.seats), int(atomic.LoadInt64(&inv.sold))
}

// ---------- rate limiter (the anti-bot gate) ----------

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	bucket map[string]*bucket
}

func NewLimiter(rate, burst float64) *Limiter {
	return &Limiter{rate: rate, burst: burst, bucket: make(map[string]*bucket)}
}

func (l *Limiter) Allow(key string) bool {
	if l.rate <= 0 { // 0 disables this layer
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.bucket[key]
	if !ok {
		if len(l.bucket) >= 1000000 { // bound memory; recycle an old bucket
			for k := range l.bucket {
				delete(l.bucket, k)
				break
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.bucket[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ---------- authentication: bearer keys, HMAC signing, replay protection ----------

type Auth struct {
	mu      sync.Mutex
	enabled bool
	keys    map[string]string // bearer key -> tenant
	secret  []byte            // when non-empty, HMAC signing is required
	window  int64             // timestamp tolerance in seconds
	nonces  map[string]int64  // request id -> expiry unix
}

func NewAuth(keySpec, secret string) *Auth {
	a := &Auth{keys: map[string]string{}, nonces: map[string]int64{}, window: 300}
	if keySpec != "" {
		a.enabled = true
		for _, kv := range strings.Split(keySpec, ",") {
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) == 2 {
				a.keys[parts[0]] = parts[1]
			} else if parts[0] != "" {
				a.keys[parts[0]] = parts[0] // key doubles as tenant name
			}
		}
	}
	if secret != "" {
		a.secret = []byte(secret)
	}
	return a
}

// verify authenticates the request. body is the raw request body (may be nil
// for GET). Returns the tenant, or a non-zero HTTP status on rejection.
func (a *Auth) verify(r *http.Request, body []byte) (string, int, string) {
	if !a.enabled {
		return "local", 0, ""
	}
	key := r.Header.Get("Authorization")
	key = strings.TrimPrefix(key, "Bearer ")
	tenant, ok := a.keys[key]
	if !ok {
		return "", http.StatusUnauthorized, "unauthorized"
	}
	if a.secret == nil { // bearer-only mode: keys are the whole story
		return tenant, 0, ""
	}
	ts := r.Header.Get("X-Kavach-Timestamp")
	rid := r.Header.Get("X-Kavach-Request-Id")
	sig := r.Header.Get("X-Kavach-Signature")
	if ts == "" || rid == "" || sig == "" {
		return "", http.StatusUnauthorized, "unauthorized"
	}
	tsVal, err := strconv.ParseInt(ts, 10, 64)
	now := time.Now().Unix()
	if err != nil || tsVal < now-a.window || tsVal > now+a.window {
		return "", http.StatusUnauthorized, "unauthorized"
	}
	a.mu.Lock()
	if exp, seen := a.nonces[rid]; seen && exp > now {
		a.mu.Unlock()
		return "", http.StatusUnauthorized, "replay"
	}
	a.nonces[rid] = now + a.window
	a.mu.Unlock()
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(ts + "\n" + rid + "\n"))
	mac.Write(body)
	want, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(mac.Sum(nil), want) {
		return "", http.StatusUnauthorized, "unauthorized"
	}
	return tenant, 0, ""
}

func (a *Auth) pruneNonces() {
	now := time.Now().Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, exp := range a.nonces {
		if exp < now {
			delete(a.nonces, k)
		}
	}
}

// ---------- idempotency (a retry never double-books) ----------

type Result struct {
	Status    string `json:"status"`
	Seats     []int  `json:"seats,omitempty"`
	BookingID string `json:"booking_id,omitempty"`
}

type idemEntry struct {
	Result
	Fingerprint string
	Tenant      string
	LastSeen    time.Time
}

type IdemStore struct {
	mu sync.Mutex
	m  map[string]*idemEntry // key = tenant + "|" + idempotency key
}

func NewIdemStore() *IdemStore { return &IdemStore{m: make(map[string]*idemEntry)} }

func (s *IdemStore) lookup(tenant, key string) (*idemEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[tenant+"|"+key]
	return e, ok
}

// claim registers a new operation. Returns (existing entry, true) when the
// key is already known, (nil, false) when this call won the race. A known key
// with a different fingerprint is a conflict (fingerprint != "").
func (s *IdemStore) claim(tenant, key, fp string) (*idemEntry, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tenant + "|" + key
	if e, ok := s.m[k]; ok {
		e.LastSeen = time.Now()
		if fp != "" && e.Fingerprint != "" && e.Fingerprint != fp {
			return e, true, true // conflict: same key, different request
		}
		return e, true, false
	}
	s.m[k] = &idemEntry{Fingerprint: fp, Tenant: tenant, LastSeen: time.Now(),
		Result: Result{Status: "processing"}}
	return nil, false, false
}

func (s *IdemStore) finish(tenant, key string, r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[tenant+"|"+key]; ok {
		e.Result = r
		e.LastSeen = time.Now()
	}
}

// trim evicts only entries idle beyond minAge, never an in-flight one.
func (s *IdemStore) trim(max int, minAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) <= max {
		return
	}
	cutoff := time.Now().Add(-minAge)
	for k, e := range s.m {
		if len(s.m) <= max {
			break
		}
		if e.Status != "processing" && e.LastSeen.Before(cutoff) {
			delete(s.m, k)
		}
	}
}

// ---------- latency sampling ----------

type LatencyRing struct {
	buf []int64 // microseconds
	n   uint64
}

func NewLatencyRing(size int) *LatencyRing { return &LatencyRing{buf: make([]int64, size)} }

func (r *LatencyRing) add(us int64) {
	i := atomic.AddUint64(&r.n, 1) - 1
	r.buf[i%uint64(len(r.buf))] = us
}

func (r *LatencyRing) snapshot() (count int, p50, p95, p99 float64) {
	total := atomic.LoadUint64(&r.n)
	if total == 0 {
		return 0, 0, 0, 0
	}
	valid := int(total)
	if valid > len(r.buf) {
		valid = len(r.buf)
	}
	sample := make([]int64, valid)
	copy(sample, r.buf[:valid])
	sort.Slice(sample, func(i, j int) bool { return sample[i] < sample[j] })
	pick := func(p float64) float64 {
		return float64(sample[int(p*float64(valid-1))]) / 1000.0 // ms
	}
	return valid, pick(0.50), pick(0.95), pick(0.99)
}

// ---------- the engine ----------

type job struct {
	key    string
	tenant string
	user   string
	fp     string
	seats  int
	resp   chan Result
}

type Engine struct {
	inv      *Inventory
	userLim  *Limiter
	ipLim    *Limiter
	auth     *Auth
	idem     *IdemStore
	queue    chan *job
	bookFile *os.File
	logMu    sync.Mutex
	bookW    *bufio.Writer
	bid      uint64
	inFlight int64

	received     int64
	ipLimited    int64
	userLimited  int64
	overloaded   int64
	authFailures int64
	replays      int64
	conflicts    int64
	confirmed    int64
	soldOut      int64
	errors       int64
	lat          *LatencyRing
	started      time.Time
}

// appendLog writes, flushes, and fsyncs the booking BEFORE the caller may
// acknowledge it: persist-before-ack. A confirmed response means the record
// is on disk.
func (e *Engine) appendLog(id, user string, seats []int) {
	line, _ := json.Marshal(map[string]interface{}{
		"booking_id": id, "user": user, "seats": seats, "ts": time.Now().UnixNano(),
	})
	e.logMu.Lock()
	defer e.logMu.Unlock()
	e.bookW.Write(line)
	e.bookW.WriteByte('\n')
	e.bookW.Flush()
	e.bookFile.Sync()
}

func (e *Engine) process(j *job) {
	if prev, ok := e.idem.lookup(j.tenant, j.key); ok {
		// same key: same payload returns the stored result, a different
		// payload is a conflict, either way never a second booking
		if prev.Fingerprint != "" && j.fp != "" && prev.Fingerprint != j.fp {
			atomic.AddInt64(&e.conflicts, 1)
			j.resp <- Result{Status: "idempotency_conflict"}
			return
		}
		j.resp <- prev.Result
		return
	}
	existing, claimed, conflict := e.idem.claim(j.tenant, j.key, j.fp)
	if conflict {
		atomic.AddInt64(&e.conflicts, 1)
		j.resp <- Result{Status: "idempotency_conflict"}
		return
	}
	if claimed {
		j.resp <- existing.Result // stored result or "processing"
		return
	}
	seats := e.inv.tryTake(j.seats)
	if seats == nil {
		e.idem.finish(j.tenant, j.key, Result{Status: "sold_out"})
		atomic.AddInt64(&e.soldOut, 1)
		j.resp <- Result{Status: "sold_out"}
		return
	}
	id := fmt.Sprintf("BK%08d", atomic.AddUint64(&e.bid, 1))
	e.appendLog(id, j.user, seats) // durable BEFORE the ack leaves the process
	e.inv.commit(seats)
	atomic.AddInt64(&e.confirmed, 1)
	res := Result{Status: "confirmed", Seats: seats, BookingID: id}
	e.idem.finish(j.tenant, j.key, res)
	j.resp <- res
}

func (e *Engine) worker() {
	for j := range e.queue {
		e.process(j)
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (e *Engine) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (e *Engine) handleBook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	atomic.AddInt64(&e.received, 1)
	r.Body = http.MaxBytesReader(w, r.Body, 16384) // bounded input
	body, err := io.ReadAll(r.Body)
	if err != nil {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	tenant, st, msg := e.auth.verify(r, body)
	if st != 0 {
		if msg == "replay" {
			atomic.AddInt64(&e.replays, 1)
		} else {
			atomic.AddInt64(&e.authFailures, 1)
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, st, Result{Status: msg})
		return
	}
	var req struct {
		User    string `json:"user_id"`
		IdemKey string `json:"idempotency_key"`
		Seats   int    `json:"seats"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields() // strict schema: reject, never sanitize silently
	if err := dec.Decode(&req); err != nil || req.User == "" || req.IdemKey == "" || req.Seats < 1 || req.Seats > 4 {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	if !e.ipLim.Allow(e.clientIP(r)) { // layer 1: per IP, absorbs botnets
		atomic.AddInt64(&e.ipLimited, 1)
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "rate_limited"})
		return
	}
	if !e.userLim.Allow(tenant + ":" + req.User) { // layer 2: per user
		atomic.AddInt64(&e.userLimited, 1)
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "rate_limited"})
		return
	}
	if n := atomic.AddInt64(&e.inFlight, 1); n > 500000 { // global capacity gate
		atomic.AddInt64(&e.inFlight, -1)
		atomic.AddInt64(&e.overloaded, 1)
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, Result{Status: "overloaded"})
		return
	}
	defer atomic.AddInt64(&e.inFlight, -1)

	j := &job{key: req.IdemKey, tenant: tenant, user: req.User, fp: fmt.Sprintf("%x", sha256.Sum256(body)),
		seats: req.Seats, resp: make(chan Result, 1)}
	t0 := time.Now()
	select {
	case e.queue <- j:
	default: // queue full: say so instantly instead of dying later
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "queue_full"})
		return
	}
	select {
	case res := <-j.resp:
		e.lat.add(time.Since(t0).Microseconds())
		writeJSON(w, http.StatusOK, res)
	case <-time.After(20 * time.Second):
		e.lat.add(time.Since(t0).Microseconds())
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, Result{Status: "timeout"})
	}
}

// handleStatus lets a client resolve an ambiguous timeout: query the stored
// outcome of an idempotency key instead of blindly re-submitting.
func (e *Engine) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, st, msg := e.auth.verify(r, nil)
	if st != 0 {
		writeJSON(w, st, Result{Status: msg})
		return
	}
	key := r.URL.Query().Get("idempotency_key")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	if entry, ok := e.idem.lookup(tenant, key); ok {
		writeJSON(w, http.StatusOK, entry.Result)
		return
	}
	writeJSON(w, http.StatusNotFound, Result{Status: "not_found"})
}

func (e *Engine) handleSeats(w http.ResponseWriter, r *http.Request) {
	total, sold := e.inv.stats()
	writeJSON(w, http.StatusOK, map[string]int{"total": total, "sold": sold, "free": total - sold})
}

func (e *Engine) handleMetrics(w http.ResponseWriter, r *http.Request) {
	count, p50, p95, p99 := e.lat.snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"received":          atomic.LoadInt64(&e.received),
		"rate_limited":      atomic.LoadInt64(&e.userLimited) + atomic.LoadInt64(&e.ipLimited),
		"ip_rate_limited":   atomic.LoadInt64(&e.ipLimited),
		"user_rate_limited": atomic.LoadInt64(&e.userLimited),
		"auth_failures":     atomic.LoadInt64(&e.authFailures),
		"replays_rejected":  atomic.LoadInt64(&e.replays),
		"idem_conflicts":    atomic.LoadInt64(&e.conflicts),
		"overloaded":        atomic.LoadInt64(&e.overloaded),
		"in_flight":         atomic.LoadInt64(&e.inFlight),
		"confirmed":         atomic.LoadInt64(&e.confirmed),
		"sold_out":          atomic.LoadInt64(&e.soldOut),
		"errors":            atomic.LoadInt64(&e.errors),
		"latency_ms":        map[string]interface{}{"p50": p50, "p95": p95, "p99": p99, "samples": count},
		"uptime_seconds":    time.Since(e.started).Seconds(),
	})
}

func main() {
	seats := flag.Int("seats", 5000, "seats in inventory")
	addr := flag.String("addr", ":8080", "listen address")
	workers := flag.Int("workers", 16, "worker count")
	logPath := flag.String("log", "bookings.jsonl", "booking event log path")
	apiKeys := flag.String("api-keys", "", "API keys as key:tenant,key:tenant (empty = local mode, auth off)")
	secret := flag.String("hmac-secret", "", "HMAC secret; when set, requests must be signed (X-Kavach-Timestamp, X-Kavach-Request-Id, X-Kavach-Signature over timestamp\\nrequest-id\\nbody)")
	userRate := flag.Float64("user-rate", 2, "per-user requests/second (0 disables)")
	userBurst := flag.Float64("user-burst", 5, "per-user burst")
	ipRate := flag.Float64("ip-rate", 20, "per-IP requests/second (0 disables)")
	ipBurst := flag.Float64("ip-burst", 40, "per-IP burst")
	flag.Parse()

	logf, err := os.Create(*logPath)
	if err != nil {
		log.Fatal(err)
	}

	e := &Engine{
		inv:      NewInventory(*seats),
		userLim:  NewLimiter(*userRate, *userBurst),
		ipLim:    NewLimiter(*ipRate, *ipBurst),
		auth:     NewAuth(*apiKeys, *secret),
		idem:     NewIdemStore(),
		queue:    make(chan *job, 100000),
		bookFile: logf,
		bookW:    bufio.NewWriter(logf),
		lat:      NewLatencyRing(1000000),
		started:  time.Now(),
	}
	for i := 0; i < *workers; i++ {
		go e.worker()
	}
	go func() { // idempotency store hygiene: evict only idle entries
		t := time.NewTicker(20 * time.Second)
		for range t.C {
			e.idem.trim(2000000, 10*time.Minute)
		}
	}()
	go func() { // replay-nonce hygiene
		t := time.NewTicker(60 * time.Second)
		for range t.C {
			e.auth.pruneNonces()
		}
	}()

	http.HandleFunc("/book", e.handleBook)
	http.HandleFunc("/status", e.handleStatus)
	http.HandleFunc("/seats", e.handleSeats)
	http.HandleFunc("/metrics", e.handleMetrics)
	mode := "local (auth off)"
	if e.auth.enabled {
		mode = "authenticated"
	}
	log.Printf("kavach engine on %s: %d seats, %d workers, %d CPUs, mode=%s", *addr, *seats, *workers, runtime.NumCPU(), mode)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
