//go:build redis

// ---------- shared waitlist (v2.2, cluster phase 2) ----------

// The same strictly-FIFO waitlist every node keeps in memory, kept in Redis
// so a cluster of nodes serves ONE line: a user who queues on node A is
// served by node B the moment B frees seats, and nobody behind the front of
// the line is served anywhere until the front is served (the same
// fairness-over-utilization rule the single-node engine enforces). The
// queue is the state: whoever pops the front first wins an atomic claim, so
// two nodes can never serve the same entry twice. In-memory waitlists
// remain the zero-dependency default; this file compiles only under
// `-tags redis`.
package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const wlClaimTTL = 3 * time.Second // a crashed claimer must not hold the line

// joinScript appends one entry atomically: cap check, cluster-unique id,
// queue push, entry fields, idempotency alias, count. One round trip, so
// two nodes joining at the same instant can never race past the cap or
// scramble the order.
var wlJoinScript = goredis.NewScript(`
local count = tonumber(redis.call('GET', KEYS[2]) or '0')
if count >= tonumber(ARGV[1]) then return '' end
local id = redis.call('INCR', KEYS[3])
local eid = 'WL' .. string.format('%08d', id)
redis.call('RPUSH', KEYS[1], eid)
redis.call('HSET', KEYS[4] .. eid, 'tenant', ARGV[2], 'key', ARGV[3],
  'user', ARGV[4], 'seats', ARGV[5], 'event', ARGV[6], 'ts', ARGV[7])
if ARGV[3] ~= '' then
  redis.call('SET', KEYS[5] .. ARGV[2] .. '|' .. ARGV[3], eid)
end
redis.call('INCR', KEYS[2])
return eid
`)

// wlCancelScript removes one entry by id, tenant-checked when ARGV[2] is
// non-empty, cleaning the queue, the entry, its idempotency alias and the
// count in the same atomic step.
var wlCancelScript = goredis.NewScript(`
local ent = KEYS[2] .. ARGV[1]
local tenant = redis.call('HGET', ent, 'tenant')
if not tenant then return '' end
if ARGV[2] ~= '' and tenant ~= ARGV[2] then return 'WRONGTENANT' end
local key = redis.call('HGET', ent, 'key')
local user = redis.call('HGET', ent, 'user')
local seats = redis.call('HGET', ent, 'seats')
redis.call('LREM', KEYS[1], 1, ARGV[1])
redis.call('DEL', ent)
if key and key ~= '' then redis.call('DEL', KEYS[3] .. tenant .. '|' .. key) end
redis.call('DECR', KEYS[4])
return {user, seats}
`)

// wlClaimScript atomically claims the front of the line: it returns the
// front entry's fields and marks it claimed for a short TTL, or reports
// another claimer (”) or an empty line (nil). The claim, not the pop, is
// the lock: the claiming node tries its own seats, and only a node that
// actually served the front commits it.
var wlClaimScript = goredis.NewScript(`
local id = redis.call('LRANGE', KEYS[1], 0, 0)[1]
if not id then return nil end
if redis.call('EXISTS', KEYS[2]) == 1 then return '' end
redis.call('SET', KEYS[2], id, 'PX', tonumber(ARGV[1]))
local ent = KEYS[3] .. id
return {id,
  redis.call('HGET', ent, 'tenant'), redis.call('HGET', ent, 'key'),
  redis.call('HGET', ent, 'user'), redis.call('HGET', ent, 'seats'),
  redis.call('HGET', ent, 'event'), redis.call('HGET', ent, 'ts')}
`)

// wlCommitScript retires a served front entry: queue, entry, idempotency
// alias, count, claim. Only the node that took the seats runs it.
var wlCommitScript = goredis.NewScript(`
local ent = KEYS[4] .. ARGV[1]
local tenant = redis.call('HGET', ent, 'tenant')
local key = redis.call('HGET', ent, 'key')
redis.call('LREM', KEYS[1], 1, ARGV[1])
redis.call('DEL', ent)
if key and key ~= '' then redis.call('DEL', KEYS[5] .. tenant .. '|' .. key) end
redis.call('DECR', KEYS[3])
if redis.call('GET', KEYS[2]) == ARGV[1] then redis.call('DEL', KEYS[2]) end
return 1
`)

// wlReleaseScript gives the claim back when the claiming node could not
// serve the front: the entry stays exactly where it was, and the next
// release (here or on another node) tries again.
var wlReleaseScript = goredis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]) end
return 1
`)

type RedisWaitlist struct {
	rdb    *goredis.Client
	prefix string
}

func newRedisWaitlist(addr, prefix string) (waitlistStore, error) {
	opts, err := goredis.ParseURL(addr)
	if err != nil {
		return nil, err
	}
	opts.DialTimeout = 3 * time.Second
	rdb := goredis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil { // fail fast at startup, not mid-sale
		rdb.Close()
		return nil, err
	}
	return &RedisWaitlist{rdb: rdb, prefix: prefix}, nil
}

func (w *RedisWaitlist) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 250*time.Millisecond)
}

func (w *RedisWaitlist) keys() ([]string, []string, []string, []string) {
	list := []string{w.prefix + ":q", w.prefix + ":count", w.prefix + ":seq", w.prefix + ":ent:", w.prefix + ":idem:"}
	cancelKeys := []string{w.prefix + ":q", w.prefix + ":ent:", w.prefix + ":idem:", w.prefix + ":count"}
	claimKeys := []string{w.prefix + ":q", w.prefix + ":claim", w.prefix + ":ent:"}
	commitKeys := []string{w.prefix + ":q", w.prefix + ":claim", w.prefix + ":count", w.prefix + ":ent:", w.prefix + ":idem:"}
	return list, cancelKeys, claimKeys, commitKeys
}

func (w *RedisWaitlist) entKey(id string) string { return w.prefix + ":ent:" + id }

// entryFromHash rebuilds a WaitEntry from the entry hash's field values.
func entryFromHash(id string, vals []interface{}) *WaitEntry {
	get := func(i int) string {
		if i < len(vals) {
			if s, ok := vals[i].(string); ok {
				return s
			}
		}
		return ""
	}
	ts, _ := strconv.ParseInt(get(5), 10, 64)
	seats, _ := strconv.Atoi(get(3))
	queuedAt := time.Time{}
	if ts > 0 {
		queuedAt = time.UnixMilli(ts)
	}
	return &WaitEntry{ID: id, Tenant: get(0), User: get(2), Seats: seats, Event: get(4), QueuedAt: queuedAt}
}

func (w *RedisWaitlist) join(tenant, key, user string, seats, cap int, ev string) (*WaitEntry, error) {
	if ev == "" {
		ev = defaultEventID
	}
	ctx, cancel := w.ctx()
	defer cancel()
	list, _, _, _ := w.keys()
	id, err := wlJoinScript.Run(ctx, w.rdb, list, cap, tenant, key, user, seats, ev,
		time.Now().UnixMilli()).Text()
	if err != nil {
		return nil, err // Redis down: say so, never pretend the line is full
	}
	if id == "" {
		return nil, nil // the shared line is at capacity
	}
	return &WaitEntry{ID: id, Tenant: tenant, User: user, Seats: seats, Event: ev, QueuedAt: time.Now()}, nil
}

func (w *RedisWaitlist) byIdem(tenant, key string) (*WaitEntry, bool) {
	if key == "" {
		return nil, false
	}
	ctx, cancel := w.ctx()
	defer cancel()
	id, err := w.rdb.Get(ctx, w.prefix+":idem:"+tenant+"|"+key).Result()
	if err != nil {
		return nil, false
	}
	vals, err := w.rdb.HGetAll(ctx, w.entKey(id)).Result()
	if err != nil || len(vals) == 0 { // fulfilled or cancelled: the key is free again
		return nil, false
	}
	return entryFromHash(id, []interface{}{vals["tenant"], vals["key"], vals["user"],
		vals["seats"], vals["event"], vals["ts"]}), true
}

func (w *RedisWaitlist) cancel(id, tenant string) (*WaitEntry, bool) {
	return w.removeChecked(id, tenant)
}

// remove drops an entry by id regardless of tenant.
func (w *RedisWaitlist) remove(id string) bool {
	_, ok := w.removeChecked(id, "")
	return ok
}

func (w *RedisWaitlist) removeChecked(id, tenant string) (*WaitEntry, bool) {
	ctx, cancel := w.ctx()
	defer cancel()
	_, cancelKeys, _, _ := w.keys()
	row, err := wlCancelScript.Run(ctx, w.rdb, cancelKeys, id, tenant).Slice()
	if err != nil || len(row) < 2 {
		return nil, false // absent, wrong tenant, or the queue is unreachable
	}
	user, _ := row[0].(string)
	seats, _ := strconv.Atoi(fmt.Sprint(row[1]))
	return &WaitEntry{ID: id, Tenant: tenant, User: user, Seats: seats}, true
}

func (w *RedisWaitlist) listFor(tenant, user string) []*WaitEntry {
	all := w.snapshot()
	var out []*WaitEntry
	for pos, e := range all {
		if e.Tenant == tenant && e.User == user {
			e.pos = pos + 1
			out = append(out, e)
		}
	}
	return out
}

// snapshot returns every live entry in queue order.
func (w *RedisWaitlist) snapshot() []*WaitEntry {
	ctx, cancel := w.ctx()
	defer cancel()
	ids, err := w.rdb.LRange(ctx, w.prefix+":q", 0, -1).Result()
	if err != nil {
		return nil
	}
	pipe := w.rdb.Pipeline()
	cmds := make([]*goredis.MapStringStringCmd, len(ids))
	for i, id := range ids {
		cmds[i] = pipe.HGetAll(ctx, w.entKey(id))
	}
	if _, err := pipe.Exec(ctx); err != nil && err != goredis.Nil {
		return nil
	}
	out := make([]*WaitEntry, 0, len(ids))
	for i, id := range ids {
		vals := cmds[i].Val()
		if len(vals) == 0 {
			continue // entry retired between the read and the fetch
		}
		out = append(out, entryFromHash(id, []interface{}{vals["tenant"], vals["key"],
			vals["user"], vals["seats"], vals["event"], vals["ts"]}))
	}
	return out
}

func (w *RedisWaitlist) depth() int {
	ctx, cancel := w.ctx()
	defer cancel()
	n, err := w.rdb.LLen(ctx, w.prefix+":q").Result()
	if err != nil {
		return 0 // Redis down: nothing to serve from the shared line
	}
	return int(n)
}

// popReady claims the front of the shared line and tries to satisfy it
// from THIS node's inventory. The claim guards against two nodes serving
// the same entry; a node that cannot cover the front gives the claim back
// and the front keeps blocking the line, exactly as the single-node
// waitlist behaves.
func (w *RedisWaitlist) popReady(inv *Inventory) (*WaitEntry, []int, bool) {
	ctx, cancel := w.ctx()
	defer cancel()
	_, _, claimKeys, commitKeys := w.keys()
	res, err := wlClaimScript.Run(ctx, w.rdb, claimKeys, wlClaimTTL.Milliseconds()).Result()
	if err != nil {
		return nil, nil, false // Redis down: the queue stalls, the sale goes on
	}
	if res == nil {
		return nil, nil, false // empty line
	}
	row, _ := res.([]interface{})
	if len(row) < 6 {
		return nil, nil, false // another node holds the claim
	}
	id, _ := row[0].(string)
	if id == "" {
		return nil, nil, false
	}
	entry := entryFromHash(id, row[1:])
	if entry.Seats <= 0 {
		w.releaseClaim(id)
		return nil, nil, false
	}
	seats := inv.tryTake(entry.Seats)
	if seats == nil { // front blocked: give the claim back, FIFO discipline holds
		w.releaseClaim(id)
		return nil, nil, false
	}
	if err := wlCommitScript.Run(ctx, w.rdb, commitKeys, id).Err(); err != nil {
		// The seats are taken locally but the queue entry could not be
		// retired; give the seats back rather than double-serve later.
		inv.release(seats)
		w.releaseClaim(id)
		return nil, nil, false
	}
	return entry, seats, true
}

// Close shuts the shared queue's client down (tests and graceful exits).
func (w *RedisWaitlist) Close() error { return w.rdb.Close() }

func (w *RedisWaitlist) releaseClaim(id string) {
	ctx, cancel := w.ctx()
	defer cancel()
	wlReleaseScript.Run(ctx, w.rdb, []string{w.prefix + ":claim"}, id)
}

var _ waitlistStore = (*RedisWaitlist)(nil)
