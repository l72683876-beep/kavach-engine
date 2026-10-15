// Kavach: a booking engine built to survive a stampede.
// Core v1: rate limiting, bounded admission queue, worker pool,
// atomic seat inventory, idempotency keys, append-only booking log.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
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

// ---------- idempotency (a retry never double-books) ----------

type Result struct {
	Status    string `json:"status"`
	Seats     []int  `json:"seats,omitempty"`
	BookingID string `json:"booking_id,omitempty"`
}

type IdemStore struct {
	mu sync.Mutex
	m  map[string]Result
}

func NewIdemStore() *IdemStore { return &IdemStore{m: make(map[string]Result)} }

func (s *IdemStore) get(key string) (Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[key]
	return r, ok
}

func (s *IdemStore) claim(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key]; ok {
		return false
	}
	s.m[key] = Result{Status: "processing"}
	return true
}

func (s *IdemStore) finish(key string, r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = r
}

func (s *IdemStore) trim(max, batch int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < batch && len(s.m) > max; i++ {
		for k := range s.m {
			delete(s.m, k)
			break
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
	key   string
	user  string
	seats int
	resp  chan Result
}

type Engine struct {
	inv      *Inventory
	limiter  *Limiter
	idem     *IdemStore
	queue    chan *job
	bookFile *os.File
	logMu    sync.Mutex
	bookW    *bufio.Writer
	bid      uint64

	received    int64
	rateLimited int64
	queueFull   int64
	confirmed   int64
	soldOut     int64
	errors      int64
	lat         *LatencyRing
	started     time.Time
}

func (e *Engine) appendLog(id, user string, seats []int) {
	line, _ := json.Marshal(map[string]interface{}{
		"booking_id": id, "user": user, "seats": seats, "ts": time.Now().UnixNano(),
	})
	e.logMu.Lock()
	e.bookW.Write(line)
	e.bookW.WriteByte('\n')
	e.logMu.Unlock()
}

func (e *Engine) process(j *job) {
	if prev, ok := e.idem.get(j.key); ok && prev.Status == "confirmed" {
		j.resp <- prev // same idempotency key: same booking, never a second one
		return
	}
	if !e.idem.claim(j.key) {
		j.resp <- Result{Status: "processing"}
		return
	}
	seats := e.inv.tryTake(j.seats)
	if seats == nil {
		e.idem.finish(j.key, Result{Status: "sold_out"})
		atomic.AddInt64(&e.soldOut, 1)
		j.resp <- Result{Status: "sold_out"}
		return
	}
	id := fmt.Sprintf("BK%08d", atomic.AddUint64(&e.bid, 1))
	e.appendLog(id, j.user, seats)
	e.inv.commit(seats)
	atomic.AddInt64(&e.confirmed, 1)
	res := Result{Status: "confirmed", Seats: seats, BookingID: id}
	e.idem.finish(j.key, res)
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

func (e *Engine) handleBook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	atomic.AddInt64(&e.received, 1)
	var req struct {
		User    string `json:"user_id"`
		IdemKey string `json:"idempotency_key"`
		Seats   int    `json:"seats"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.User == "" || req.IdemKey == "" || req.Seats < 1 || req.Seats > 4 {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	if !e.limiter.Allow(req.User) {
		atomic.AddInt64(&e.rateLimited, 1)
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "rate_limited"})
		return
	}
	j := &job{key: req.IdemKey, user: req.User, seats: req.Seats, resp: make(chan Result, 1)}
	t0 := time.Now()
	select {
	case e.queue <- j:
	default: // queue full: say so instantly instead of dying later
		atomic.AddInt64(&e.queueFull, 1)
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
		writeJSON(w, http.StatusServiceUnavailable, Result{Status: "timeout"})
	}
}

func (e *Engine) handleSeats(w http.ResponseWriter, r *http.Request) {
	total, sold := e.inv.stats()
	writeJSON(w, http.StatusOK, map[string]int{"total": total, "sold": sold, "free": total - sold})
}

func (e *Engine) handleMetrics(w http.ResponseWriter, r *http.Request) {
	count, p50, p95, p99 := e.lat.snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"received":     atomic.LoadInt64(&e.received),
		"rate_limited": atomic.LoadInt64(&e.rateLimited),
		"queue_full":   atomic.LoadInt64(&e.queueFull),
		"confirmed":    atomic.LoadInt64(&e.confirmed),
		"sold_out":     atomic.LoadInt64(&e.soldOut),
		"errors":       atomic.LoadInt64(&e.errors),
		"latency_ms":   map[string]interface{}{"p50": p50, "p95": p95, "p99": p99, "samples": count},
		"uptime_seconds": time.Since(e.started).Seconds(),
	})
}

func main() {
	seats := flag.Int("seats", 5000, "seats in inventory")
	addr := flag.String("addr", ":8080", "listen address")
	workers := flag.Int("workers", 16, "worker count")
	logPath := flag.String("log", "bookings.jsonl", "booking event log path")
	flag.Parse()

	logf, err := os.Create(*logPath)
	if err != nil {
		log.Fatal(err)
	}

	e := &Engine{
		inv:      NewInventory(*seats),
		limiter:  NewLimiter(2, 5),
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
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		for range t.C {
			e.logMu.Lock()
			e.bookW.Flush()
			e.logMu.Unlock()
		}
	}()
	go func() {
		t := time.NewTicker(20 * time.Second)
		for range t.C {
			e.idem.trim(2000000, 200000)
		}
	}()

	http.HandleFunc("/book", e.handleBook)
	http.HandleFunc("/seats", e.handleSeats)
	http.HandleFunc("/metrics", e.handleMetrics)
	log.Printf("kavach engine on %s: %d seats, %d workers, %d CPUs", *addr, *seats, *workers, runtime.NumCPU())
	log.Fatal(http.ListenAndServe(*addr, nil))
}
