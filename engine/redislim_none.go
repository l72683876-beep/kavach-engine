//go:build !redis

// Without `-tags redis` the engine has no shared limiter: token buckets stay
// per-node in memory and the default build stays dependency-free. This stub
// only exists so the -redis flag can explain itself at startup instead of
// failing to compile.
package main

import "errors"

var errRedisNotBuilt = errors.New("shared token buckets need a build with -tags redis; per-node in-memory buckets are on")

// RedisLimiter is the no-Redis stub; rate limiting stays per-node in memory.
type RedisLimiter struct{}

func newRedisLimiter(addr, prefix string, rate, burst float64) (*RedisLimiter, error) {
	return nil, errRedisNotBuilt
}

// Allow always succeeds: the stub satisfies the limiter interface without
func (l *RedisLimiter) Allow(string) bool { return true }
