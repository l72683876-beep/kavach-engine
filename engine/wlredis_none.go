//go:build !redis

package main

// newRedisWaitlist is a stub in the default build: the shared waitlist
// needs `go build -tags redis`.
func newRedisWaitlist(addr, prefix string) (waitlistStore, error) {
	return nil, errRedisNotBuilt
}
