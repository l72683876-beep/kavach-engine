// Kavach: a booking engine built to survive a stampede.
// Core v1.8: adds waitlist mode (sold out? join a FIFO queue; freed seats
// go to the front of the line automatically, with optional webhook
// notifications) on top of v1.7: group commit (concurrent writes share one
// fsync; the persist-before-ack guarantee is unchanged) on top of core v1.6 (Milestone 2):
// the hold/confirm reservation lifecycle
// (reserve with a TTL, confirm, release, an expiry worker that returns
// abandoned holds to inventory atomically) on top of core v1.5:
// bearer API keys, HMAC request signing, replay protection, layered rate
// limits, an in-flight capacity gate, strict input validation, and
// persist-before-ack durable logging, on top of the v1 core: bounded
// admission queue, worker pool, atomic CAS inventory, idempotency keys,
// append-only booking log.
package main

import (
	"bufio"
	"bytes"
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
	held   int64
}

func NewInventory(n int) *Inventory { return &Inventory{seats: make([]int32, n)} }

// tryTake atomically locks n seats, or returns nil when not enough are free.
// A compare-and-swap on each seat means two workers can never hold the same seat.
func (inv *Inventory) tryTake(n int) []int {
	l := len(inv.seats)
	if int(atomic.LoadInt64(&inv.sold))+int(atomic.LoadInt64(&inv.held))+n > l {
		return nil // fast path: everything gone or held
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
	atomic.AddInt64(&inv.held, int64(n))
	return picked
}

// commit moves held seats to sold (the confirm step).
func (inv *Inventory) commit(seats []int) {
	for _, idx := range seats {
		atomic.StoreInt32(&inv.seats[idx], seatSold)
	}
	atomic.AddInt64(&inv.sold, int64(len(seats)))
	atomic.AddInt64(&inv.held, -int64(len(seats)))
}

// release returns held seats to the free pool (cancel or expiry).
func (inv *Inventory) release(seats []int) {
	for _, idx := range seats {
		atomic.CompareAndSwapInt32(&inv.seats[idx], seatHeld, seatFree)
	}
	atomic.AddInt64(&inv.held, -int64(len(seats)))
}

func (inv *Inventory) stats() (total, sold, held int) {
	return len(inv.seats), int(atomic.LoadInt64(&inv.sold)), int(atomic.LoadInt64(&inv.held))
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

// ---------- reservations: the hold/confirm lifecycle ----------

const (
	resHeld      = int32(1)
	resConfirmed = int32(2)
	resExpired   = int32(3)
	resReleased  = int32(4)
)

func resStateName(s int32) string {
	switch s {
	case resHeld:
		return "held"
	case resConfirmed:
		return "confirmed"
	case resExpired:
		return "expired"
	case resReleased:
		return "released"
	}
	return "unknown"
}

type Reservation struct {
	ID          string
	Tenant      string
	User        string
	Seats       []int
	State       int32 // atomic; CAS gives single-winner transitions
	Fingerprint string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	BookingID   string
}

// transition returns true when this caller won the state change.
func (r *Reservation) transition(from, to int32) bool {
	return atomic.CompareAndSwapInt32(&r.State, from, to)
}

type ReservationStore struct {
	mu        sync.Mutex
	m         map[string]*Reservation
	idemIndex map[string]string // tenant|key -> reservation id
}

func NewReservationStore() *ReservationStore {
	return &ReservationStore{m: map[string]*Reservation{}, idemIndex: map[string]string{}}
}

func (s *ReservationStore) get(id string) (*Reservation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[id]
	return r, ok
}

func (s *ReservationStore) byIdem(tenant, key string) (*Reservation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.idemIndex[tenant+"|"+key]
	if !ok {
		return nil, false
	}
	r, ok := s.m[id]
	return r, ok
}

// put registers a reservation and its idempotency alias. Returns false when
// the idempotency key was already claimed (the caller then re-reads byIdem).
func (s *ReservationStore) put(r *Reservation, idemKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idemKey != "" {
		ik := r.Tenant + "|" + idemKey
		if _, exists := s.idemIndex[ik]; exists {
			return false
		}
		s.idemIndex[ik] = r.ID
	}
	s.m[r.ID] = r
	return true
}

// expire candidates collects held reservations past their deadline; the
// caller then transitions each one (outside the lock, single-winner CAS).
func (s *ReservationStore) expired(now time.Time) []*Reservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Reservation
	for _, r := range s.m {
		if atomic.LoadInt32(&r.State) == resHeld && now.After(r.ExpiresAt) {
			out = append(out, r)
		}
	}
	return out
}

// ---------- waitlist (sold out? join the queue) ----------

// WaitEntry is one place in line. Entries are strictly FIFO: when seats free
// up, the front of the line is served first; a front entry that needs more
// seats than are free blocks the ones behind it (fairness over utilization).
type WaitEntry struct {
	ID       string
	Tenant   string
	User     string
	Seats    int
	pos      int // filled in by listFor
	QueuedAt time.Time
}

var waitlistSeq uint64

type Waitlist struct {
	mu    sync.Mutex
	order []*WaitEntry
	idem  map[string]string // tenant|key -> waitlist id
}

func NewWaitlist() *Waitlist { return &Waitlist{idem: map[string]string{}} }

// byIdem returns the live entry for an idempotency key, if it is still queued.
func (w *Waitlist) byIdem(tenant, key string) (*WaitEntry, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	id, ok := w.idem[tenant+"|"+key]
	if !ok {
		return nil, false
	}
	for _, e := range w.order {
		if e.ID == id {
			return e, true
		}
	}
	return nil, false // fulfilled or cancelled: the key is free again
}

// join appends to the line. Returns (nil) when the waitlist is full.
func (w *Waitlist) join(tenant, key, user string, seats int, cap int) *WaitEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.order) >= cap {
		return nil
	}
	e := &WaitEntry{ID: fmt.Sprintf("WL%08d", atomic.AddUint64(&waitlistSeq, 1)), Tenant: tenant,
		User: user, Seats: seats, QueuedAt: time.Now()}
	w.order = append(w.order, e)
	if key != "" {
		w.idem[tenant+"|"+key] = e.ID
	}
	return e
}

// cancel removes an entry from the line. Tenant-scoped.
func (w *Waitlist) cancel(id, tenant string) (*WaitEntry, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, e := range w.order {
		if e.ID == id && e.Tenant == tenant {
			w.order = append(w.order[:i], w.order[i+1:]...)
			return e, true
		}
	}
	return nil, false
}

// listFor returns the caller's live entries with their 1-based positions.
func (w *Waitlist) listFor(tenant, user string) []*WaitEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*WaitEntry
	for pos, e := range w.order {
		if e.Tenant == tenant && e.User == user {
			e.pos = pos + 1
			out = append(out, e)
		}
	}
	return out
}

// popReady serves the front of the line while the inventory can satisfy it.
// The seats are taken atomically; the caller owns them from that moment.
func (w *Waitlist) popReady(inv *Inventory) (*WaitEntry, []int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.order) > 0 {
		front := w.order[0]
		seats := inv.tryTake(front.Seats)
		if seats == nil {
			return nil, nil, false // front blocked: FIFO discipline
		}
		w.order = w.order[1:]
		return front, seats, true
	}
	return nil, nil, false
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

// ---------- group commit: one fsync per batch of writes ----------

// GroupCommit turns per-write fsyncs into per-batch fsyncs. Concurrent
// writers hand their line to the batcher and block until a single
// flush+fsync covering the whole batch completes. The durability guarantee
// is unchanged: nothing is acknowledged before it is on disk.
type commitReq struct {
	line string
	done chan struct{}
}

type GroupCommit struct {
	ch   chan commitReq
	file *os.File
	w    *bufio.Writer
}

func NewGroupCommit(path string, queue int) (*GroupCommit, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	g := &GroupCommit{ch: make(chan commitReq, queue), file: f, w: bufio.NewWriterSize(f, 1<<20)}
	go g.run()
	return g, nil
}

// run owns the file: it takes the first pending write, drains everything
// already queued behind it, writes the whole batch, syncs ONCE, and releases
// every writer in the batch.
func (g *GroupCommit) run() {
	for first := range g.ch {
		batch := []commitReq{first}
	drain:
		for len(batch) < 4096 {
			select {
			case r := <-g.ch:
				batch = append(batch, r)
			default:
				break drain
			}
		}
		for _, r := range batch {
			g.w.WriteString(r.line)
			g.w.WriteByte('\n')
		}
		g.w.Flush()
		g.file.Sync()
		for _, r := range batch {
			close(r.done)
		}
	}
}

// commit blocks until the batch containing line has been flushed and fsynced.
func (g *GroupCommit) commit(line string) {
	r := commitReq{line: line, done: make(chan struct{})}
	g.ch <- r
	<-r.done
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
	res      *ReservationStore
	queue    chan *job
	bookGC   *GroupCommit
	holdGC   *GroupCommit
	bid      uint64
	rid      uint64
	inFlight int64
	holdTTL    time.Duration
	wl         *Waitlist
	waitCap    int
	webhookURL string
	webhookCh  chan map[string]interface{}

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
	holdsCreated int64
	holdsConfirm int64
	holdsRelease int64
	holdsExpired int64
	waitQueued   int64
	waitFulfilled int64
	waitCancelled int64
	webhookSent   int64
	webhookFailed int64
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
	e.bookGC.commit(string(line))
}

// appendHold records a reservation lifecycle event (reserved/confirmed/
// released/expired) with the same persist-before-ack discipline.
func (e *Engine) appendHold(event string, r *Reservation, bookingID string) {
	line, _ := json.Marshal(map[string]interface{}{
		"event": event, "reservation_id": r.ID, "tenant": r.Tenant, "user": r.User,
		"seats": r.Seats, "booking_id": bookingID, "ts": time.Now().UnixNano(),
	})
	e.holdGC.commit(string(line))
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

// expireSweep returns abandoned holds to the free pool. Each reservation
// changes state by CAS, so a confirm racing an expiry has exactly one winner.
func (e *Engine) expireSweep() {
	now := time.Now()
	for _, r := range e.res.expired(now) {
		if r.transition(resHeld, resExpired) {
			e.inv.release(r.Seats)
			atomic.AddInt64(&e.holdsExpired, 1)
			e.appendHold("expired", r, "")
		}
	}
	e.serveWaitlist()
}

// notifyWebhook posts a fire-and-forget JSON event to the integrator's URL
// if one is configured. It never blocks the request path: full or failing
// deliveries are counted, never propagated.
func (e *Engine) notifyWebhook(ev map[string]interface{}) {
	if e.webhookURL == "" {
		return
	}
	select {
	case e.webhookCh <- ev:
	default:
		atomic.AddInt64(&e.webhookFailed, 1)
	}
}

// serveWaitlist serves the front of the line while seats are free. Called
// after every event that returns seats to the pool (expiry or release).
func (e *Engine) serveWaitlist() {
	for {
		entry, seats, ok := e.wl.popReady(e.inv)
		if !ok {
			return
		}
		res := &Reservation{
			ID:        fmt.Sprintf("RSV%08d", atomic.AddUint64(&e.rid, 1)),
			Tenant:    entry.Tenant,
			User:      entry.User,
			Seats:     seats,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(e.holdTTL),
			State:     resHeld,
		}
		e.res.put(res, "") // no idempotency alias: the engine holds on their behalf
		atomic.AddInt64(&e.holdsCreated, 1)
		atomic.AddInt64(&e.waitFulfilled, 1)
		e.appendHold("reserved", res, "")
		e.appendWaitEvent("waitlist_fulfilled", entry)
		e.notifyWebhook(map[string]interface{}{
			"event":           "waitlist_fulfilled",
			"waitlist_id":     entry.ID,
			"reservation_id":  res.ID,
			"tenant":          entry.Tenant,
			"user_id":         entry.User,
			"seats":           seats,
			"hold_expires_at": res.ExpiresAt.Unix(),
		})
	}
}

func (e *Engine) handleWaitlistJoin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User    string `json:"user_id"`
		IdemKey string `json:"idempotency_key"`
		Seats   int    `json:"seats"`
	}
	tenant, ok := e.precheck(w, r, &req)
	if !ok {
		return
	}
	defer atomic.AddInt64(&e.inFlight, -1)
	if req.User == "" || req.IdemKey == "" || req.Seats < 1 || req.Seats > 4 {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	if !e.userLim.Allow(tenant + ":" + req.User) {
		atomic.AddInt64(&e.userLimited, 1)
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "rate_limited"})
		return
	}
	if prev, found := e.wl.byIdem(tenant, req.IdemKey); found { // idempotent join
		if prev.Seats != req.Seats { // same key, different payload: conflict
			atomic.AddInt64(&e.conflicts, 1)
			writeJSON(w, http.StatusConflict, map[string]interface{}{"status": "idempotency_conflict"})
			return
		}
		e.writeWaitEntry(w, http.StatusOK, prev)
		return
	}
	entry := e.wl.join(tenant, req.IdemKey, req.User, req.Seats, e.waitCap)
	if entry == nil {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"status": "waitlist_full"})
		return
	}
	atomic.AddInt64(&e.waitQueued, 1)
	e.appendWaitEvent("waitlisted", entry) // durable BEFORE the ack
	e.writeWaitEntry(w, http.StatusOK, entry)
}

// handleWaitlistList: the caller's live entries with positions.
func (e *Engine) handleWaitlistList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, st, msg := e.auth.verify(r, nil)
	if st != 0 {
		writeJSON(w, st, Result{Status: msg})
		return
	}
	user := r.URL.Query().Get("user_id")
	if user == "" {
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	entries := e.wl.listFor(tenant, user)
	type row struct {
		WaitlistID string `json:"waitlist_id"`
		Seats      int    `json:"seats"`
		Position   int    `json:"position"`
	}
	rows := make([]row, 0, len(entries))
	for _, en := range entries {
		rows = append(rows, row{WaitlistID: en.ID, Seats: en.Seats, Position: en.pos})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "entries": rows})
}

// handleWaitlistCancel: leave the line before your turn comes.
func (e *Engine) handleWaitlistCancel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WaitlistID string `json:"waitlist_id"`
	}
	tenant, ok := e.precheck(w, r, &req)
	if !ok {
		return
	}
	defer atomic.AddInt64(&e.inFlight, -1)
	entry, found := e.wl.cancel(req.WaitlistID, tenant)
	if !found {
		writeJSON(w, http.StatusNotFound, Result{Status: "not_found"})
		return
	}
	atomic.AddInt64(&e.waitCancelled, 1)
	e.appendWaitEvent("waitlist_cancelled", entry)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "cancelled", "waitlist_id": entry.ID})
}

func (e *Engine) appendWaitEvent(event string, en *WaitEntry) {
	line, _ := json.Marshal(map[string]interface{}{
		"event": event, "waitlist_id": en.ID, "tenant": en.Tenant, "user_id": en.User,
		"seats": en.Seats, "ts": time.Now().UnixNano(),
	})
	e.holdGC.commit(string(line))
}

func (e *Engine) writeWaitEntry(w http.ResponseWriter, code int, en *WaitEntry) {
	pos := 0
	for _, x := range e.wl.listFor(en.Tenant, en.User) {
		if x.ID == en.ID {
			pos = x.pos
		}
	}
	writeJSON(w, code, map[string]interface{}{
		"status": "queued", "waitlist_id": en.ID, "seats": en.Seats, "position": pos,
	})
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

// precheck runs the shared front half of every write endpoint: method,
// bounded body read, authentication, strict schema validation, the layered
// rate limits, and the global in-flight gate. It returns the tenant, the
// parsed request, and an ok flag (a response was already written when false).
func (e *Engine) precheck(w http.ResponseWriter, r *http.Request, dst interface{}) (string, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	atomic.AddInt64(&e.received, 1)
	r.Body = http.MaxBytesReader(w, r.Body, 16384) // bounded input
	body, err := io.ReadAll(r.Body)
	if err != nil {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return "", false
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
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields() // strict schema: reject, never sanitize silently
	if err := dec.Decode(dst); err != nil {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return "", false
	}
	if !e.ipLim.Allow(e.clientIP(r)) { // layer 1: per IP, absorbs botnets
		atomic.AddInt64(&e.ipLimited, 1)
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "rate_limited"})
		return "", false
	}
	if n := atomic.AddInt64(&e.inFlight, 1); n > 500000 { // global capacity gate
		atomic.AddInt64(&e.inFlight, -1)
		atomic.AddInt64(&e.overloaded, 1)
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, Result{Status: "overloaded"})
		return "", false
	}
	return tenant, true
}

func (e *Engine) handleBook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User    string `json:"user_id"`
		IdemKey string `json:"idempotency_key"`
		Seats   int    `json:"seats"`
	}
	tenant, ok := e.precheck(w, r, &req)
	if !ok {
		return
	}
	defer atomic.AddInt64(&e.inFlight, -1)
	if req.User == "" || req.IdemKey == "" || req.Seats < 1 || req.Seats > 4 {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	if !e.userLim.Allow(tenant + ":" + req.User) { // layer 2: per user
		atomic.AddInt64(&e.userLimited, 1)
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "rate_limited"})
		return
	}

	j := &job{key: req.IdemKey, tenant: tenant, user: req.User,
		fp:    fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%d", req.IdemKey, req.Seats)))),
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

// handleReserve: PUT A HOLD on seats with a TTL, without buying yet.
// The seats leave the free pool immediately; they return automatically when
// the hold expires, or on an explicit release.
func (e *Engine) handleReserve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User    string `json:"user_id"`
		IdemKey string `json:"idempotency_key"`
		Seats   int    `json:"seats"`
	}
	tenant, ok := e.precheck(w, r, &req)
	if !ok {
		return
	}
	defer atomic.AddInt64(&e.inFlight, -1)
	if req.User == "" || req.IdemKey == "" || req.Seats < 1 || req.Seats > 4 {
		atomic.AddInt64(&e.errors, 1)
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	if !e.userLim.Allow(tenant + ":" + req.User) { // layer 2: per user
		atomic.AddInt64(&e.userLimited, 1)
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusTooManyRequests, Result{Status: "rate_limited"})
		return
	}

	// idempotent reserve: the same key returns the same reservation; the same
	// key with a different payload is a conflict
	fp := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%d", req.IdemKey, req.Seats))))
	if prev, found := e.res.byIdem(tenant, req.IdemKey); found {
		if prev.Fingerprint != fp {
			atomic.AddInt64(&e.conflicts, 1)
			writeJSON(w, http.StatusConflict, map[string]interface{}{"status": "idempotency_conflict"})
			return
		}
		e.writeReservation(w, http.StatusOK, prev)
		return
	}

	seats := e.inv.tryTake(req.Seats)
	if seats == nil {
		atomic.AddInt64(&e.soldOut, 1)
		writeJSON(w, http.StatusOK, Result{Status: "sold_out"})
		return
	}
	res := &Reservation{
		ID:          fmt.Sprintf("RSV%08d", atomic.AddUint64(&e.rid, 1)),
		Tenant:      tenant,
		User:        req.User,
		Seats:       seats,
		Fingerprint: fp,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(e.holdTTL),
		State:       resHeld,
	}
	if !e.res.put(res, req.IdemKey) { // lost a concurrent race on the same key
		e.inv.release(seats)
		if prev, found := e.res.byIdem(tenant, req.IdemKey); found {
			e.writeReservation(w, http.StatusOK, prev)
			return
		}
		writeJSON(w, http.StatusInternalServerError, Result{Status: "error"})
		return
	}
	atomic.AddInt64(&e.holdsCreated, 1)
	e.appendHold("reserved", res, "") // durable BEFORE the ack
	e.writeReservation(w, http.StatusOK, res)
}

// handleConfirm: turn a live hold into a confirmed booking. The transition
// HELD -> CONFIRMED is a single-winner CAS: a confirm racing the expiry
// worker has exactly one winner, so a seat can never be both expired and sold.
func (e *Engine) handleConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReservationID string `json:"reservation_id"`
		User          string `json:"user_id"`
	}
	tenant, ok := e.precheck(w, r, &req)
	if !ok {
		return
	}
	defer atomic.AddInt64(&e.inFlight, -1)
	res, found := e.res.get(req.ReservationID)
	if !found || res.Tenant != tenant { // 404 both ways: never leak existence
		writeJSON(w, http.StatusNotFound, Result{Status: "not_found"})
		return
	}
	if req.User != "" && req.User != res.User {
		writeJSON(w, http.StatusForbidden, Result{Status: "forbidden"})
		return
	}
	switch atomic.LoadInt32(&res.State) {
	case resConfirmed: // idempotent confirm: same booking back
		e.writeReservation(w, http.StatusOK, res)
		return
	case resExpired:
		writeJSON(w, http.StatusConflict, map[string]interface{}{"status": "expired"})
		return
	case resReleased:
		writeJSON(w, http.StatusConflict, map[string]interface{}{"status": "released"})
		return
	}
	if !res.transition(resHeld, resConfirmed) { // expiry or release won the race
		e.writeReservationState(w, res)
		return
	}
	bookingID := fmt.Sprintf("BK%08d", atomic.AddUint64(&e.bid, 1))
	res.BookingID = bookingID
	e.appendLog(bookingID, res.User, res.Seats) // durable BEFORE the ack
	e.inv.commit(res.Seats)
	atomic.AddInt64(&e.confirmed, 1)
	atomic.AddInt64(&e.holdsConfirm, 1)
	e.appendHold("confirmed", res, bookingID)
	e.writeReservation(w, http.StatusOK, res)
}

// handleRelease: give held seats back before the TTL runs out.
func (e *Engine) handleRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReservationID string `json:"reservation_id"`
	}
	tenant, ok := e.precheck(w, r, &req)
	if !ok {
		return
	}
	defer atomic.AddInt64(&e.inFlight, -1)
	res, found := e.res.get(req.ReservationID)
	if !found || res.Tenant != tenant {
		writeJSON(w, http.StatusNotFound, Result{Status: "not_found"})
		return
	}
	switch atomic.LoadInt32(&res.State) {
	case resReleased:
		e.writeReservation(w, http.StatusOK, res)
		return
	case resConfirmed:
		writeJSON(w, http.StatusConflict, map[string]interface{}{"status": "confirmed"})
		return
	case resExpired:
		writeJSON(w, http.StatusConflict, map[string]interface{}{"status": "expired"})
		return
	}
	if res.transition(resHeld, resReleased) {
		e.inv.release(res.Seats)
		atomic.AddInt64(&e.holdsRelease, 1)
		e.appendHold("released", res, "")
		e.writeReservation(w, http.StatusOK, res)
		go e.serveWaitlist()
		return
	}
	e.writeReservationState(w, res)
}

// handleReservation: the status of one hold, tenant-scoped. A client that
// lost a response can resolve the outcome here instead of guessing.
func (e *Engine) handleReservation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, st, msg := e.auth.verify(r, nil)
	if st != 0 {
		writeJSON(w, st, Result{Status: msg})
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, Result{Status: "bad_request"})
		return
	}
	res, found := e.res.get(id)
	if !found || res.Tenant != tenant {
		writeJSON(w, http.StatusNotFound, Result{Status: "not_found"})
		return
	}
	e.writeReservation(w, http.StatusOK, res)
}

func (e *Engine) writeReservation(w http.ResponseWriter, code int, res *Reservation) {
	writeJSON(w, code, map[string]interface{}{
		"status":          resStateName(atomic.LoadInt32(&res.State)),
		"reservation_id":  res.ID,
		"seats":           res.Seats,
		"hold_expires_at": res.ExpiresAt.Unix(),
		"hold_seconds":    int(time.Until(res.ExpiresAt).Seconds()),
		"booking_id":      res.BookingID,
	})
}

func (e *Engine) writeReservationState(w http.ResponseWriter, res *Reservation) {
	writeJSON(w, http.StatusConflict, map[string]interface{}{
		"status":         resStateName(atomic.LoadInt32(&res.State)),
		"reservation_id": res.ID,
		"booking_id":     res.BookingID,
	})
}

// handleStatus lets a client resolve an ambiguous timeout on the direct
// /book path: query the stored outcome of an idempotency key instead of
// blindly re-submitting.
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
	total, sold, held := e.inv.stats()
	writeJSON(w, http.StatusOK, map[string]int{"total": total, "sold": sold, "held": held, "free": total - sold - held})
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
		"holds_created":     atomic.LoadInt64(&e.holdsCreated),
		"holds_confirmed":   atomic.LoadInt64(&e.holdsConfirm),
		"holds_released":    atomic.LoadInt64(&e.holdsRelease),
		"holds_expired":     atomic.LoadInt64(&e.holdsExpired),
		"waitlist_queued":     atomic.LoadInt64(&e.waitQueued),
		"waitlist_fulfilled":  atomic.LoadInt64(&e.waitFulfilled),
		"waitlist_cancelled":  atomic.LoadInt64(&e.waitCancelled),
		"webhook_sent":        atomic.LoadInt64(&e.webhookSent),
		"webhook_failed":      atomic.LoadInt64(&e.webhookFailed),
		"latency_ms":        map[string]interface{}{"p50": p50, "p95": p95, "p99": p99, "samples": count},
		"uptime_seconds":    time.Since(e.started).Seconds(),
	})
}

func main() {
	seats := flag.Int("seats", 5000, "seats in inventory")
	addr := flag.String("addr", ":8080", "listen address")
	workers := flag.Int("workers", 16, "worker count")
	logPath := flag.String("log", "bookings.jsonl", "confirmed-booking event log path")
	holdsLog := flag.String("holds-log", "holds.jsonl", "reservation lifecycle event log path")
	holdTTL := flag.Int("hold-ttl", 300, "reservation hold time-to-live in seconds")
	waitCap := flag.Int("waitlist-cap", 100000, "maximum waitlist entries")
	webhookURL := flag.String("webhook-url", "", "POST waitlist_fulfilled events to this URL")
	apiKeys := flag.String("api-keys", "", "API keys as key:tenant,key:tenant (empty = local mode, auth off)")
	secret := flag.String("hmac-secret", "", "HMAC secret; when set, requests must be signed (X-Kavach-Timestamp, X-Kavach-Request-Id, X-Kavach-Signature over timestamp\\nrequest-id\\nbody)")
	userRate := flag.Float64("user-rate", 2, "per-user requests/second (0 disables)")
	userBurst := flag.Float64("user-burst", 5, "per-user burst")
	ipRate := flag.Float64("ip-rate", 20, "per-IP requests/second (0 disables)")
	ipBurst := flag.Float64("ip-burst", 40, "per-IP burst")
	flag.Parse()

	bookGC, err := NewGroupCommit(*logPath, 200000)
	if err != nil {
		log.Fatal(err)
	}
	holdGC, err := NewGroupCommit(*holdsLog, 200000)
	if err != nil {
		log.Fatal(err)
	}

	e := &Engine{
		inv:      NewInventory(*seats),
		userLim:  NewLimiter(*userRate, *userBurst),
		ipLim:    NewLimiter(*ipRate, *ipBurst),
		auth:     NewAuth(*apiKeys, *secret),
		idem:     NewIdemStore(),
		res:      NewReservationStore(),
		queue:    make(chan *job, 100000),
		bookGC:   bookGC,
		holdGC:   holdGC,
		lat:      NewLatencyRing(1000000),
		holdTTL:  time.Duration(*holdTTL) * time.Second,
		wl:       NewWaitlist(),
		waitCap:    *waitCap,
		webhookURL: *webhookURL,
		webhookCh:  make(chan map[string]interface{}, 10000),
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
	go func() { // hold expiry: abandoned holds return to the free pool
		t := time.NewTicker(1 * time.Second)
		for range t.C {
			e.expireSweep()
		}
	}()
	go func() { // webhook poster: deliveries never block the request path
		client := &http.Client{Timeout: 5 * time.Second}
		for ev := range e.webhookCh {
			b, _ := json.Marshal(ev)
			resp, err := client.Post(e.webhookURL, "application/json", bytes.NewReader(b))
			if err != nil {
				atomic.AddInt64(&e.webhookFailed, 1)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode < 300 {
				atomic.AddInt64(&e.webhookSent, 1)
			} else {
				atomic.AddInt64(&e.webhookFailed, 1)
			}
		}
	}()

	http.HandleFunc("/book", e.handleBook)
	http.HandleFunc("/reserve", e.handleReserve)
	http.HandleFunc("/confirm", e.handleConfirm)
	http.HandleFunc("/release", e.handleRelease)
	http.HandleFunc("/reservation", e.handleReservation)
	http.HandleFunc("/waitlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			e.handleWaitlistList(w, r)
			return
		}
		e.handleWaitlistJoin(w, r)
	})
	http.HandleFunc("/waitlist/cancel", e.handleWaitlistCancel)
	http.HandleFunc("/status", e.handleStatus)
	http.HandleFunc("/seats", e.handleSeats)
	http.HandleFunc("/metrics", e.handleMetrics)
	mode := "local (auth off)"
	if e.auth.enabled {
		mode = "authenticated"
	}
	log.Printf("kavach engine on %s: %d seats, %d workers, %d CPUs, hold-ttl=%ds, mode=%s", *addr, *seats, *workers, runtime.NumCPU(), *holdTTL, mode)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
