//go:build redis

// ---------- shared token buckets (v2.2, cluster phase 2) ----------

// The same per-user, per-IP and global token buckets every node already
// enforces in memory, kept in Redis so a cluster of nodes enforces ONE
// shared budget instead of N separate ones (a client can no longer buy N
// rate limits by writing to N nodes). In-memory buckets remain the
// zero-dependency default; this file compiles only under `-tags redis`.
package main

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// allowScript is the whole token bucket in one atomic step: read the bucket,
// refill by elapsed time, consume one token if one is available, write back,
// expire. Every node runs the same script against the same key, so the
// budget is shared no matter which node a request lands on.
var allowScript = goredis.NewScript(`
local st = redis.call('HMGET', KEYS[1], 'tokens', 'last')
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local tokens = burst
local last = now
if st[1] then
  tokens = tonumber(st[1])
  last = tonumber(st[2])
end
if tokens > burst then tokens = burst end
local elapsed = now - last
if elapsed > 0 then
  tokens = math.min(burst, tokens + elapsed * rate)
end
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HMSET', KEYS[1], 'tokens', tokens, 'last', now)
redis.call('PEXPIRE', KEYS[1], math.floor(ttl))
return allowed
`)

type RedisLimiter struct {
	rdb    *goredis.Client
	prefix string
	rate   float64 // tokens per second
	burst  float64
	ttl    time.Duration // idle buckets expire; idle traffic is no traffic
}

func newRedisLimiter(addr, prefix string, rate, burst float64) (*RedisLimiter, error) {
	opts, err := goredis.ParseURL(addr)
	if err != nil {
		return nil, err
	}
	rdb := goredis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &RedisLimiter{rdb: rdb, prefix: prefix, rate: rate, burst: burst,
		ttl: 2 * time.Hour}, nil
}

// Allow decides against the shared bucket. If Redis is unreachable the call
// FAILS OPEN: a shared limiter must never be the thing that takes the sale
// down, and the in-flight capacity gate still caps the process.
func (l *RedisLimiter) Allow(key string) bool {
	if l.rate <= 0 { // 0 disables this layer, same as the in-memory limiter
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	res, err := allowScript.Run(ctx, l.rdb, []string{l.prefix + "|" + key},
		float64(time.Now().UnixNano())/1e9, l.rate, l.burst,
		l.ttl.Seconds()*1000).Int()
	if err != nil {
		return true
	}
	return res == 1
}
