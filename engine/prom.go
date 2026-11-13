package main

// v2.3: Prometheus text-format (0.0.4) exposition of the same counters and
// gauges the /metrics JSON serves. /metrics keeps its JSON shape for the
// operators and scripts that already parse it; /metrics/prometheus serves
// the scrape endpoint. Counters come from metricSumKeys (they sum across
// shards); in_flight, replication_connected, snapshot age and uptime are
// gauges, latency percentiles are exported per shard because percentiles
// do not sum.

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const promContentType = "text/plain; version=0.0.4; charset=utf-8"

// promCounterHelp gives a short help line per /metrics counter key; keys
// missing here fall back to the generic wording.
var promCounterHelp = map[string]string{
	"received":                "Requests received by the engine.",
	"rate_limited":            "Requests rejected by any rate limiter.",
	"ip_rate_limited":         "Requests rejected by the per-IP rate limiter.",
	"user_rate_limited":       "Requests rejected by the per-user rate limiter.",
	"auth_failures":           "Requests rejected by HMAC authentication.",
	"replays_rejected":        "Requests rejected as replays.",
	"idem_conflicts":          "Idempotency-key conflicts.",
	"overloaded":              "Requests rejected by the capacity gate.",
	"confirmed":               "Bookings confirmed.",
	"sold_out":                "Requests rejected because inventory ran out.",
	"errors":                  "Internal errors returned.",
	"holds_created":           "Reservation holds created.",
	"holds_confirmed":         "Holds confirmed into bookings.",
	"holds_released":          "Holds released explicitly.",
	"holds_expired":           "Holds expired after their TTL.",
	"waitlist_queued":         "Waitlist joins.",
	"waitlist_fulfilled":      "Waitlist entries served a seat.",
	"waitlist_cancelled":      "Waitlist entries cancelled.",
	"webhook_sent":            "Webhook deliveries attempted.",
	"webhook_failed":          "Webhook deliveries that failed.",
	"forwarded":               "Requests forwarded to another node.",
	"replication_streams":     "Replication streams opened to peers.",
	"replicated_lines":        "WAL lines replicated to peers.",
	"pg_shipped":              "WAL lines shipped to Postgres.",
	"pg_failed":               "Postgres shipments that failed.",
	"chaos_stalls":            "Chaos-injected stalls.",
	"chaos_panics":            "Chaos-injected panics.",
	"snapshots_total":         "Snapshots written.",
	"recovery_replayed_lines": "WAL lines replayed on recovery.",
}

func promName(key string) string {
	if !strings.HasSuffix(key, "_total") {
		key += "_total"
	}
	return "kavach_" + key
}

// handleMetricsProm serves the Prometheus exposition for one shard.
func (e *Engine) handleMetricsProm(w http.ResponseWriter, r *http.Request) {
	writeProm(w, e.metricsMap(), nil)
}

// handleMetricsProm serves the Prometheus exposition: counters summed
// across shards, gauges and per-shard latency percentiles as labeled series.
func (sr *ShardRouter) handleMetricsProm(w http.ResponseWriter, r *http.Request) {
	if len(sr.shards) == 1 {
		sr.shards[0].handleMetricsProm(w, r)
		return
	}
	views := make([]map[string]interface{}, 0, len(sr.shards))
	for _, e := range sr.shards {
		views = append(views, e.metricsMap())
	}
	sum := make(map[string]interface{}, len(metricSumKeys)+4)
	for _, k := range metricSumKeys {
		var t int64
		for _, v := range views {
			switch n := v[k].(type) {
			case int64:
				t += n
			case int:
				t += int64(n)
			}
		}
		sum[k] = t
	}
	sum["shards"] = len(sr.shards)
	sum["role"] = "leader"
	var up, snap float64
	for _, v := range views {
		if u, _ := v["uptime_seconds"].(float64); u > up {
			up = u
		}
		if s, _ := v["last_snapshot_age_seconds"].(float64); s > snap {
			snap = s
		}
	}
	sum["uptime_seconds"] = up
	sum["last_snapshot_age_seconds"] = snap
	writeProm(w, sum, views)
}

type promSample struct {
	name   string
	labels string // rendered "{...}" or ""
	value  string
}

func writeProm(w http.ResponseWriter, m map[string]interface{}, views []map[string]interface{}) {
	samples := make([]promSample, 0, len(metricSumKeys)+12)
	add := func(name, labels string, value interface{}) {
		switch v := value.(type) {
		case int:
			samples = append(samples, promSample{name, labels, strconv.Itoa(v)})
		case int64:
			samples = append(samples, promSample{name, labels, strconv.FormatInt(v, 10)})
		case float64:
			samples = append(samples, promSample{name, labels, strconv.FormatFloat(v, 'g', -1, 64)})
		}
	}

	// Counters, sorted for a stable scrape body.
	keys := make([]string, 0, len(metricSumKeys))
	for _, k := range metricSumKeys {
		if k != "in_flight" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(promName(k), "", m[k])
	}

	add("kavach_in_flight", "", m["in_flight"])
	add("kavach_replication_connected", "", maxOf(m, views, "replication_connected"))
	add("kavach_last_snapshot_age_seconds", "", m["last_snapshot_age_seconds"])
	add("kavach_uptime_seconds", "", m["uptime_seconds"])
	if _, multi := m["shards"]; multi {
		add("kavach_shards", "", m["shards"])
	}
	if role, ok := m["role"].(string); ok {
		add("kavach_role_info", `{role="`+role+`"}`, 1)
	}

	// Latency: single shard has no labels; multi-shard exports each shard's
	// percentiles with a shard label, plus the summed sample count.
	emitLat := func(shard string, lm map[string]interface{}) {
		ql, sl := "", ""
		if shard != "" {
			ql = `,shard="` + shard + `"`
			sl = `{shard="` + shard + `"}`
		}
		for q, key := range map[string]string{"0.5": "p50", "0.95": "p95", "0.99": "p99"} {
			add("kavach_latency_ms", `{quantile="`+q+`"`+ql+"}", lm[key])
		}
		add("kavach_latency_samples", sl, lm["samples"])
	}
	if lm, ok := m["latency_ms"].(map[string]interface{}); ok {
		emitLat("", lm)
	}
	for i, v := range views {
		if lm, ok := v["latency_ms"].(map[string]interface{}); ok {
			emitLat(strconv.Itoa(i), lm)
		}
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i].name < samples[j].name })

	var b strings.Builder
	prev := ""
	for _, s := range samples {
		if s.name != prev {
			b.WriteString("# HELP " + s.name + " " + promHelpFor(s.name) + "\n")
			b.WriteString("# TYPE " + s.name + " " + promTypeFor(s.name) + "\n")
			prev = s.name
		}
		b.WriteString(s.name + s.labels + " " + s.value + "\n")
	}
	w.Header().Set("Content-Type", promContentType)
	_, _ = w.Write([]byte(b.String()))
}

func maxOf(m map[string]interface{}, views []map[string]interface{}, key string) interface{} {
	if v, ok := m[key]; ok {
		return v
	}
	var best int64
	for _, view := range views {
		switch n := view[key].(type) {
		case int:
			if int64(n) > best {
				best = int64(n)
			}
		case int64:
			if n > best {
				best = n
			}
		}
	}
	return best
}

var promTypeOverrides = map[string]string{
	"kavach_role_info":                 "info",
	"kavach_in_flight":                 "gauge",
	"kavach_replication_connected":     "gauge",
	"kavach_last_snapshot_age_seconds": "gauge",
	"kavach_uptime_seconds":            "gauge",
	"kavach_shards":                    "gauge",
	"kavach_latency_ms":                "gauge",
	"kavach_latency_samples":           "gauge",
}

func promTypeFor(name string) string {
	if t, ok := promTypeOverrides[name]; ok {
		return t
	}
	return "counter"
}

func promHelpFor(name string) string {
	for k, h := range promCounterHelp {
		if promName(k) == name {
			return h
		}
	}
	switch name {
	case "kavach_in_flight":
		return "Requests currently being served."
	case "kavach_replication_connected":
		return "1 when a replication stream to a peer is connected."
	case "kavach_last_snapshot_age_seconds":
		return "Seconds since the last snapshot (-1 = none yet)."
	case "kavach_uptime_seconds":
		return "Engine uptime in seconds."
	case "kavach_shards":
		return "Number of event shards in this process."
	case "kavach_role_info":
		return "This node's replication role."
	case "kavach_latency_ms":
		return "Request latency percentiles in milliseconds."
	case "kavach_latency_samples":
		return "Latency samples observed."
	}
	return "Kavach counter."
}
