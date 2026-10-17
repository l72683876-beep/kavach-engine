package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func signedAuthReq(t *testing.T, a *Auth, key, secret, body string) (string, int, string) {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	rid := "rid-" + body
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + rid + "\nPOST\n/book\n"))
	mac.Write([]byte(body))
	r := httptest.NewRequest("POST", "/book", bytes.NewReader([]byte(body)))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Kavach-Timestamp", ts)
	r.Header.Set("X-Kavach-Request-Id", rid)
	r.Header.Set("X-Kavach-Signature", hex.EncodeToString(mac.Sum(nil)))
	tenant, st, msg := a.verify(r, []byte(body))
	return tenant, st, msg
}

// Per-tenant secrets: a signature made under tenant1's secret must not be
// accepted under tenant2's key, and a tenant with no entry is rejected.
func TestPerTenantSecrets(t *testing.T) {
	a := newAuthWithTenantSecrets("k1:t1,k2:t2,k3:t3", "shared", "t1:s1,t2:s2")
	body := `{"user_id":"u","idempotency_key":"k","seats":1}`
	if tenant, st, _ := signedAuthReq(t, a, "k1", "s1", body); tenant != "t1" || st != 0 {
		t.Fatalf("correct tenant1: got tenant=%q status=%d, want t1/0", tenant, st)
	}
	if _, st, _ := signedAuthReq(t, a, "k2", "s1", body); st != 401 {
		t.Fatalf("tenant1 secret under tenant2 key: status=%d, want 401", st)
	}
	if _, st, _ := signedAuthReq(t, a, "k3", "s3", body); st != 401 {
		t.Fatalf("tenant without a per-tenant secret entry: status=%d, want 401", st)
	}
}

// Default (shared secret) behavior is unchanged: valid signatures pass. The
// cross-tenant swap under one shared secret remains possible by default; that
// is the documented gap -hmac-secrets closes when it is enabled.
func TestSharedSecretUnchanged(t *testing.T) {
	a := newAuthWithTenantSecrets("k1:t1,k2:t2", "shared", "")
	body := `{"user_id":"u","idempotency_key":"k","seats":1}`
	if tenant, st, _ := signedAuthReq(t, a, "k2", "shared", body); tenant != "t2" || st != 0 {
		t.Fatalf("shared secret default: got tenant=%q status=%d, want t2/0", tenant, st)
	}
}
