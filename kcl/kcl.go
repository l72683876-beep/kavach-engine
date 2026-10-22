// Package kcl parses the Kavach Config Language (.kcl files): one small,
// human readable file that describes a Kavach engine instead of a wall of
// CLI flags.
//
// The grammar is deliberately tiny: one statement per line, "name value ...".
// "#" starts a comment. Values carry units, so 5m is five minutes, 50ms is
// fifty milliseconds and 20/s is twenty per second.
//
// The parser is built for the person editing the file at 2am before a sale:
// every bad line is reported with its line number, all errors come back in
// one pass, and an unknown setting lists the settings that DO exist.
package kcl

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config holds every engine setting the language can set.
// Set records which settings actually appeared in the file, so a caller can
// apply the file's values while CLI flags the user typed explicitly still win.
type Config struct {
	SaleLabel      string
	Seats          int
	Addr           string
	Workers        int
	LogPath        string
	HoldsLogPath   string
	HoldTTLSeconds int
	WaitlistCap    int
	WebhookURL     string
	PeersSpec      string
	PGDSN          string
	NodeID         string
	ChaosStallMs   int
	ChaosProb      float64
	APIKeys        string
	HMACSecret     string
	UserRate       float64
	UserBurst      float64
	IPRate         float64
	IPBurst        float64

	Set map[string]bool
}

func (c *Config) mark(name string) {
	if c.Set == nil {
		c.Set = map[string]bool{}
	}
	c.Set[name] = true
}

// ParseError points at one bad line.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// lineErrors collects every bad line and reports them together.
type lineErrors []*ParseError

func (es lineErrors) Error() string {
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "\n")
}

// ValidSettings is the canonical list of statements, used both for docs and
// for the "unknown setting" error.
var ValidSettings = []string{
	"sale", "seats", "listen", "workers", "hold-ttl", "waitlist-cap",
	"bookings-log", "holds-log", "waitlist-webhook",
	"rate-limit", "api-keys", "hmac-secret",
	"node", "peers", "postgres",
	"chaos-stall", "chaos-prob",
}

// Parse parses the whole file text. All problems found are returned together,
// each with its line number.
func Parse(text string) (*Config, error) {
	cfg := &Config{Set: map[string]bool{}}
	var errs lineErrors
	for i, raw := range strings.Split(text, "\n") {
		lineNo := i + 1
		toks, tokErr := tokenize(raw)
		if tokErr != nil {
			errs = append(errs, &ParseError{lineNo, tokErr.Error()})
			continue
		}
		if len(toks) == 0 {
			continue // blank or comment-only line
		}
		if err := parseStatement(cfg, toks); err != nil {
			errs = append(errs, &ParseError{lineNo, err.Error()})
		}
	}
	if len(errs) > 0 {
		return nil, errors.New(errs.Error())
	}
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseFile reads path and parses it.
func ParseFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(b))
}

// tokenize splits one line into tokens, honoring double-quoted values and
// stripping comments. An unclosed quote is an error.
func tokenize(line string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inQ := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inQ {
			if ch == '"' {
				inQ = false
				toks = append(toks, cur.String())
				cur.Reset()
			} else {
				cur.WriteByte(ch)
			}
			continue
		}
		switch {
		case ch == '"':
			flush()
			inQ = true
		case ch == '#':
			return toks, nil
		case ch == ' ' || ch == '\t':
			flush()
		default:
			cur.WriteByte(ch)
		}
	}
	if inQ {
		return toks, errors.New(`unclosed quote ("), close it or remove it`)
	}
	flush()
	return toks, nil
}

func unknown(name string) error {
	return fmt.Errorf("unknown setting %q. Valid settings: %s", name, strings.Join(ValidSettings, ", "))
}

func wantArgs(toks []string, n int) error {
	if len(toks) < n+1 {
		return fmt.Errorf("%q needs %d value(s), got %d", toks[0], n, len(toks)-1)
	}
	if len(toks) > n+1 {
		return fmt.Errorf("%q takes exactly %d value(s), got %d", toks[0], n, len(toks)-1)
	}
	return nil
}

func parseStatement(cfg *Config, toks []string) error {
	name := toks[0]
	if !member(name) {
		return unknown(name)
	}
	if name != "rate-limit" && cfg.Set[name] {
		return fmt.Errorf("%q appears twice; each setting may be set once", name)
	}
	switch name {
	case "sale":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		cfg.SaleLabel = toks[1]
	case "seats":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		n, err := strconv.Atoi(toks[1])
		if err != nil || n < 1 {
			return fmt.Errorf("seats wants a whole number of 1 or more, got %q", toks[1])
		}
		cfg.Seats = n
	case "listen":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		cfg.Addr = toks[1]
	case "workers":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		n, err := strconv.Atoi(toks[1])
		if err != nil || n < 1 {
			return fmt.Errorf("workers wants a whole number of 1 or more, got %q", toks[1])
		}
		cfg.Workers = n
	case "hold-ttl":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		secs, err := parseDuration(toks[1])
		if err != nil {
			return fmt.Errorf("hold-ttl %s", err)
		}
		if secs < 1 {
			return fmt.Errorf("hold-ttl must be at least 1 second, got %q", toks[1])
		}
		cfg.HoldTTLSeconds = int(secs)
	case "waitlist-cap":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		n, err := strconv.Atoi(toks[1])
		if err != nil || n < 0 {
			return fmt.Errorf("waitlist-cap wants a whole number of 0 or more, got %q", toks[1])
		}
		cfg.WaitlistCap = n
	case "bookings-log":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		cfg.LogPath = toks[1]
	case "holds-log":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		cfg.HoldsLogPath = toks[1]
	case "waitlist-webhook":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		cfg.WebhookURL = toks[1]
	case "rate-limit":
		return parseRateLimit(cfg, toks)
	case "api-keys":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		for _, pair := range strings.Split(toks[1], ",") {
			if !strings.Contains(pair, ":") {
				return fmt.Errorf("api-keys wants key:tenant pairs like key1:shopA, got %q", pair)
			}
		}
		cfg.APIKeys = toks[1]
	case "hmac-secret":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		cfg.HMACSecret = toks[1]
	case "node":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		cfg.NodeID = toks[1]
	case "peers":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		for _, p := range strings.Split(toks[1], ",") {
			if _, _, err := net.SplitHostPort(p); err != nil {
				return fmt.Errorf("peers wants comma-separated addr:port entries, %q is not one", p)
			}
		}
		cfg.PeersSpec = toks[1]
	case "postgres":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		if !strings.HasPrefix(toks[1], "postgres://") && !strings.HasPrefix(toks[1], "postgresql://") {
			return fmt.Errorf("postgres wants a DSN like postgres://user@host:5432/db, got %q", toks[1])
		}
		cfg.PGDSN = toks[1]
	case "chaos-stall":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		secs, err := parseDuration(toks[1])
		if err != nil {
			return fmt.Errorf("chaos-stall %s", err)
		}
		cfg.ChaosStallMs = int(secs * 1000)
	case "chaos-prob":
		if err := wantArgs(toks, 1); err != nil {
			return err
		}
		f, err := strconv.ParseFloat(toks[1], 64)
		if err != nil || f < 0 || f >= 1 {
			return fmt.Errorf("chaos-prob wants a probability between 0 and 1 (0.01 = 1%%), got %q", toks[1])
		}
		cfg.ChaosProb = f
	default:
		return unknown(name)
	}
	cfg.mark(name)
	return nil
}

// parseRateLimit: rate-limit user 2/s burst 5   (burst clause optional)
func parseRateLimit(cfg *Config, toks []string) error {
	if len(toks) < 3 {
		return errors.New("rate-limit needs: rate-limit user|ip RATE burst N (e.g. rate-limit user 2/s burst 5)")
	}
	kind := toks[1]
	if kind != "user" && kind != "ip" {
		return fmt.Errorf("rate-limit kind must be user or ip, got %q", kind)
	}
	rate, err := parseRate(toks[2])
	if err != nil {
		return fmt.Errorf("rate-limit %s %s", kind, err)
	}
	var burst float64
	switch {
	case len(toks) == 3:
	case len(toks) == 5 && toks[3] == "burst":
		burst, err = strconv.ParseFloat(toks[4], 64)
		if err != nil || burst < 0 {
			return fmt.Errorf("rate-limit %s burst wants a number of 0 or more, got %q", kind, toks[4])
		}
	default:
		return errors.New(`rate-limit ends with "burst N", e.g. rate-limit user 2/s burst 5`)
	}
	if kind == "user" {
		cfg.UserRate, cfg.UserBurst = rate, burst
	} else {
		cfg.IPRate, cfg.IPBurst = rate, burst
	}
	cfg.mark("rate-limit-" + kind)
	return nil
}

func member(name string) bool {
	for _, s := range ValidSettings {
		if s == name {
			return true
		}
	}
	return false
}

// parseDuration reads "300" (seconds), "5m", "50ms", "1h" into seconds.
func parseDuration(v string) (float64, error) {
	unit := ""
	num := v
	for _, u := range []string{"ms", "s", "m", "h"} {
		if strings.HasSuffix(v, u) {
			unit, num = u, v[:len(v)-len(u)]
			break
		}
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("is not a duration: %q (try 5m, 300s, 50ms)", v)
	}
	switch unit {
	case "m":
		return f * 60, nil
	case "h":
		return f * 3600, nil
	case "ms":
		return f / 1000, nil
	default:
		return f, nil
	}
}

// parseRate reads "20/s" (per second), "20/m", "5/h" into per-second.
func parseRate(v string) (float64, error) {
	i := strings.IndexByte(v, '/')
	if i < 0 {
		return 0, fmt.Errorf("rate %q has no unit; write 20/s (per second), 20/m or 5/h", v)
	}
	n, err := strconv.ParseFloat(v[:i], 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("rate %q is not a number of 0 or more", v)
	}
	switch v[i+1:] {
	case "s":
		return n, nil
	case "m":
		return n / 60, nil
	case "h":
		return n / 3600, nil
	default:
		return 0, fmt.Errorf("rate %q has an unknown unit; use /s, /m or /h", v)
	}
}

func validate(cfg *Config) error {
	var bad []string
	if cfg.Set["seats"] && cfg.Seats < 1 {
		bad = append(bad, "seats must be 1 or more")
	}
	if cfg.Set["workers"] && cfg.Workers < 1 {
		bad = append(bad, "workers must be 1 or more")
	}
	if cfg.Set["hold-ttl"] && cfg.HoldTTLSeconds < 1 {
		bad = append(bad, "hold-ttl must be at least 1 second")
	}
	if cfg.Set["rate-limit-user"] && cfg.UserRate < 0 {
		bad = append(bad, "user rate must be 0 or more")
	}
	if cfg.Set["rate-limit-ip"] && cfg.IPRate < 0 {
		bad = append(bad, "ip rate must be 0 or more")
	}
	if len(bad) > 0 {
		return errors.New(strings.Join(bad, "; "))
	}
	return nil
}
