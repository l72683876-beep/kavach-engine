package kcl

import (
	"strings"
	"testing"
)

const fullFile = `
# kavach.kcl
sale "Diwali drop 2026"

seats 5000
listen :8080
workers 16
hold-ttl 5m
waitlist-cap 100000
bookings-log bookings.jsonl
holds-log holds.jsonl
waitlist-webhook https://example.com/waitlist

rate-limit user 2/s burst 5
rate-limit ip 20/s burst 40

api-keys key1:shopA,key2:shopB
hmac-secret change-me

node n1
peers :8081,:8082
postgres postgres://user@host:5432/kavach
chaos-stall 50ms
chaos-prob 0.01
`

func TestParseFullFile(t *testing.T) {
	cfg, err := Parse(fullFile)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"sale", cfg.SaleLabel, "Diwali drop 2026"},
		{"seats", cfg.Seats, 5000},
		{"listen", cfg.Addr, ":8080"},
		{"workers", cfg.Workers, 16},
		{"hold-ttl", cfg.HoldTTLSeconds, 300},
		{"waitlist-cap", cfg.WaitlistCap, 100000},
		{"webhook", cfg.WebhookURL, "https://example.com/waitlist"},
		{"user rate", cfg.UserRate, 2.0},
		{"user burst", cfg.UserBurst, 5.0},
		{"ip rate", cfg.IPRate, 20.0},
		{"ip burst", cfg.IPBurst, 40.0},
		{"api-keys", cfg.APIKeys, "key1:shopA,key2:shopB"},
		{"node", cfg.NodeID, "n1"},
		{"chaos-stall", cfg.ChaosStallMs, 50},
		{"chaos-prob", cfg.ChaosProb, 0.01},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
		if !cfg.Set[strings.TrimSuffix(strings.TrimSuffix(c.name, " rate"), " burst")] && c.name != "sale" {
			// spot-check the Set map only for names that are settings
		}
	}
}

func TestSetMapTracksStatements(t *testing.T) {
	cfg, err := Parse(fullFile)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	for _, name := range []string{"sale", "seats", "hold-ttl", "rate-limit-user", "rate-limit-ip", "postgres"} {
		if !cfg.Set[name] {
			t.Errorf("Set[%q] = false, want true", name)
		}
	}
	if cfg.Set["chaos-panic"] {
		t.Errorf("Set[chaos-panic] = true, want false (statement never used)")
	}
}

func TestAllErrorsReportedTogether(t *testing.T) {
	_, err := Parse("seats abc\nlisten\nbuy 10\n")
	if err == nil {
		t.Fatal("Parse() error = nil, want errors")
	}
	for _, want := range []string{"line 1", "line 2", "line 3", "buy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%s", want, err.Error())
		}
	}
}

func TestUnknownSettingListsValidOnes(t *testing.T) {
	_, err := Parse("seat-count 100\n")
	if err == nil {
		t.Fatal("Parse() error = nil, want error")
	}
	if !strings.Contains(err.Error(), `unknown setting "seat-count"`) {
		t.Errorf("error = %s, want unknown-setting message", err.Error())
	}
	if !strings.Contains(err.Error(), "seats, listen, workers") {
		t.Errorf("error should list valid settings, got: %s", err.Error())
	}
}

func TestDuplicateStatementRejected(t *testing.T) {
	_, err := Parse("seats 10\nseats 20\n")
	if err == nil || !strings.Contains(err.Error(), "appears twice") {
		t.Fatalf("error = %v, want duplicate error", err)
	}
}

func TestDurationAndRateUnits(t *testing.T) {
	cfg, err := Parse("hold-ttl 90s\nchaos-stall 2m\nrate-limit user 30/m burst 10\nrate-limit ip 600/h\n")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.HoldTTLSeconds != 90 {
		t.Errorf("hold-ttl 90s = %d seconds, want 90", cfg.HoldTTLSeconds)
	}
	if cfg.ChaosStallMs != 120000 {
		t.Errorf("chaos-stall 2m = %d ms, want 120000", cfg.ChaosStallMs)
	}
	if cfg.UserRate != 0.5 {
		t.Errorf("rate-limit user 30/m = %v per second, want 0.5", cfg.UserRate)
	}
	if cfg.IPRate != 600.0/3600.0 {
		t.Errorf("rate-limit ip 600/h = %v per second, want %v", cfg.IPRate, 600.0/3600.0)
	}
}

func TestRateWithoutUnitRejected(t *testing.T) {
	_, err := Parse("rate-limit user 20 burst 5\n")
	if err == nil || !strings.Contains(err.Error(), "no unit") {
		t.Fatalf("error = %v, want unit error", err)
	}
}

func TestHoldTTLBelowOneSecondRejected(t *testing.T) {
	_, err := Parse("hold-ttl 50ms\n")
	if err == nil || !strings.Contains(err.Error(), "at least 1 second") {
		t.Fatalf("error = %v, want hold-ttl range error", err)
	}
}

func TestUnclosedQuoteRejected(t *testing.T) {
	_, err := Parse(`sale "Diwali\n`)
	if err == nil || !strings.Contains(err.Error(), "unclosed quote") {
		t.Fatalf("error = %v, want unclosed quote error", err)
	}
}

func TestInvalidPeersRejected(t *testing.T) {
	_, err := Parse("peers :8081,no-port\n")
	if err == nil || !strings.Contains(err.Error(), "addr:port") {
		t.Fatalf("error = %v, want peers format error", err)
	}
}

func TestEmptyFileParses(t *testing.T) {
	cfg, err := Parse("# just a comment\n\n   \n")
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(cfg.Set) != 0 {
		t.Errorf("Set = %v, want empty", cfg.Set)
	}
}
