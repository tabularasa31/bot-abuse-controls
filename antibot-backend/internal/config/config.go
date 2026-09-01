// Package config gathers env-driven settings for the antibot-backend skeleton.
//
// Only the knobs the [B2] skeleton actually consumes live here. Per-feature
// settings (catalog ETag policy, log-receiver batch sizes, rDNS strategy)
// belong to B3/B6/B7/B9 and will land alongside those features.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Instance — a short instance label in /health and the logs, so that LB round-robin
	// is observable (see step 3, "HA", in infra/demo-backend/scripts/verify.sh).
	Instance string
	// HTTPAddr — exactly what we listen on. The LB goes to :8080, like the B1 placeholder.
	HTTPAddr string
	// PostgresDSN — the DSN for pgxpool. An empty string means the DB is optional
	// (skeleton mode: the service comes up and passes the B1 acceptance, but any
	// future B3/B6/B7 features that need the DB must check for it explicitly).
	PostgresDSN string
	// RDNSInterval — a deprecated knob from the B2 skeleton (a background worker tick).
	// In B7 the worker is reactive — there are no periodic ticks over the queue and the
	// trigger is the log stream. It is kept for backward compatibility with
	// compose files; the actual value is ignored. It will be removed in B15
	// (the config migration).
	RDNSInterval time.Duration
	// RDNSQueueSize — the reactive queue buffer (Enqueue → consumer).
	// An overflow means the receiver gets a dropped task in a metric, and the edge
	// keeps issuing provisional passes. See rdns.DefaultConfig().
	RDNSQueueSize int
	// RDNSWorkers — parallel DNS resolvers per worker.
	RDNSWorkers int
	// RDNSDNSTimeout — the ceiling on one IP check iteration. It protects the
	// consumer slot from a hung DNS resolver.
	RDNSDNSTimeout time.Duration
	// RDNSGCInterval — how often we DELETE expired verified_bot_ips.
	// An hour is far rarer than the TTL (1 h) — the table does not bloat and the DB sees no load.
	RDNSGCInterval time.Duration
	// ShutdownTimeout — the graceful shutdown timeout of the HTTP server.
	ShutdownTimeout time.Duration
	// CatalogsDir — the root directory of the slow catalogs from the git repo (ADR-006).
	// The backend reads tls_fp_blocklist.yaml / ua_blacklist.yaml / etc. from there on
	// every reloader tick; the reloader's mtime cache guards against needless
	// YAML parsing when the files have not moved. The source is mandatory — without the
	// files the slow catalogs are empty and the edge gets a "successful" payload without
	// the records product has already added (a silent regression).
	CatalogsDir string

	// CatalogReloadInterval — how often the backend rereads the catalogs
	// (filesource plus dbloader runtime → Merge → Store). The default of 5 s is shorter
	// than the edge poll (30 s), so that a dashboard edit reliably reaches the
	// edge in ≤30 s (acceptance B4/B13). The same interval is used as the
	// per-tick deadline in Reloader.Run.
	CatalogReloadInterval time.Duration

	// MigrateOnStartup — when true and POSTGRES_DSN is set, the backend applies the
	// built-in migrations before the reloader's Bootstrap. The default is true: the migrations are
	// idempotent (CREATE TABLE IF NOT EXISTS), and a manual step before B15
	// would add an external failure mode, "we forgot to apply them".
	MigrateOnStartup bool

	// LogsSinkSpoolDir — where to put NDJSON BAC_LOG batches during a
	// PostgreSQL outage ([B9]). An empty string disables the spill (the sink will lose
	// lines while the DB is unavailable — acceptable for dev/CI; in production a
	// persistent volume must be set in compose, otherwise the B9 acceptance "a disk queue
	// in the backend" is not met). There is deliberately NO default: a default
	// /var/lib/... under root would upset a dev run without root, while the
	// edge case "forgot to set it in production" is visible in the log as an explicit
	// WARN at initialisation.
	LogsSinkSpoolDir string
	// LogsSinkBatchSize / LogsSinkFlushInterval — the flush thresholds towards the DB.
	LogsSinkBatchSize     int
	LogsSinkFlushInterval time.Duration
	// LogsSinkQueueSize — the bound on the in-memory Submit→consumer queue.
	LogsSinkQueueSize int
	// LogsSinkSpoolMaxBytes — the ceiling on the spool directory size. Above it,
	// the oldest batches are deleted with the spool_dropped_files_total metric.
	LogsSinkSpoolMaxBytes int64
	// LogsSinkDrainInterval — how often we try to return the spool to the DB.
	LogsSinkDrainInterval time.Duration

	// DashboardAPIToken — the shared M2M secret for bearer auth between the
	// dashboard backend and antibot-backend ([B10] / internal/antibotapi).
	// An empty string means /antibot/v1/* is not registered (fail-closed; a warn
	// in the log). There are no other consumers of the policy API and none are planned, so
	// we do not introduce per-tenant tokens — the only subject is always
	// dashboard-backend.
	DashboardAPIToken string
}

func Load() (Config, error) {
	cfg := Config{
		Instance:              getenv("INSTANCE_NAME", mustHostname()),
		HTTPAddr:              getenv("HTTP_ADDR", ":8080"),
		PostgresDSN:           os.Getenv("POSTGRES_DSN"),
		RDNSInterval:          30 * time.Minute,
		RDNSQueueSize:         1024,
		RDNSWorkers:           4,
		RDNSDNSTimeout:        5 * time.Second,
		RDNSGCInterval:        time.Hour,
		ShutdownTimeout:       10 * time.Second,
		CatalogsDir:           getenv("CATALOGS_DIR", "./catalogs"),
		CatalogReloadInterval: 5 * time.Second,
		MigrateOnStartup:      true,
		LogsSinkSpoolDir:      os.Getenv("LOGS_SINK_SPOOL_DIR"),
		LogsSinkBatchSize:     500,
		LogsSinkFlushInterval: 2 * time.Second,
		LogsSinkQueueSize:     8192,
		LogsSinkSpoolMaxBytes: 256 << 20,
		LogsSinkDrainInterval: 10 * time.Second,
		DashboardAPIToken:     os.Getenv("DASHBOARD_API_TOKEN"),
	}
	if v := os.Getenv("CATALOG_RELOAD_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("CATALOG_RELOAD_INTERVAL: %w", err)
		}
		cfg.CatalogReloadInterval = d
	}
	if v := os.Getenv("MIGRATE_ON_STARTUP"); v != "" {
		// We accept:
		//   - everything strconv.ParseBool understands (1/t/T/TRUE/true/True and
		//     0/f/F/FALSE/false/False — idiomatic for YAML and k8s secrets);
		//   - the historical 'yes'/'no' (case-insensitive) — which the previous
		//     hand-written switch accepted and ParseBool does not know. We do not break other people's
		//     compose files and manifests for the sake of a pure Go parser. From review.
		b, err := parseBoolWithYesNo(v)
		if err != nil {
			return cfg, fmt.Errorf("MIGRATE_ON_STARTUP: %w", err)
		}
		cfg.MigrateOnStartup = b
	}
	// RDNS_INTERVAL — deprecated after B7 (the worker is reactive, with no periodic tick).
	// We accept any value, invalid / 0 / -1 included, so that old
	// compose files from the B2 era do not break startup. It is never actually read.
	// PR #53 review.
	_ = os.Getenv("RDNS_INTERVAL")
	if v := os.Getenv("RDNS_QUEUE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("RDNS_QUEUE_SIZE: must be positive int, got %q", v)
		}
		cfg.RDNSQueueSize = n
	}
	if v := os.Getenv("RDNS_WORKERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("RDNS_WORKERS: must be positive int, got %q", v)
		}
		cfg.RDNSWorkers = n
	}
	if v := os.Getenv("RDNS_DNS_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("RDNS_DNS_TIMEOUT: %w", err)
		}
		cfg.RDNSDNSTimeout = d
	}
	if v := os.Getenv("RDNS_GC_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("RDNS_GC_INTERVAL: %w", err)
		}
		cfg.RDNSGCInterval = d
	}
	if v := os.Getenv("SHUTDOWN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = d
	}
	// time.NewTicker panics on <=0, so we do not let the user shoot themselves in the foot.
	// RDNSInterval is deprecated and not validated (see above).
	if cfg.ShutdownTimeout <= 0 {
		return cfg, fmt.Errorf("SHUTDOWN_TIMEOUT must be > 0, got %s", cfg.ShutdownTimeout)
	}
	if cfg.CatalogReloadInterval <= 0 {
		return cfg, fmt.Errorf("CATALOG_RELOAD_INTERVAL must be > 0, got %s", cfg.CatalogReloadInterval)
	}
	if cfg.RDNSDNSTimeout <= 0 {
		return cfg, fmt.Errorf("RDNS_DNS_TIMEOUT must be > 0, got %s", cfg.RDNSDNSTimeout)
	}
	if cfg.RDNSGCInterval <= 0 {
		return cfg, fmt.Errorf("RDNS_GC_INTERVAL must be > 0, got %s", cfg.RDNSGCInterval)
	}
	if v := os.Getenv("LOGS_SINK_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_BATCH_SIZE: must be positive int, got %q", v)
		}
		cfg.LogsSinkBatchSize = n
	}
	if v := os.Getenv("LOGS_SINK_FLUSH_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_FLUSH_INTERVAL: %w", err)
		}
		cfg.LogsSinkFlushInterval = d
	}
	if v := os.Getenv("LOGS_SINK_QUEUE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_QUEUE_SIZE: must be positive int, got %q", v)
		}
		cfg.LogsSinkQueueSize = n
	}
	if v := os.Getenv("LOGS_SINK_SPOOL_MAX_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_SPOOL_MAX_BYTES: must be positive int, got %q", v)
		}
		cfg.LogsSinkSpoolMaxBytes = n
	}
	if v := os.Getenv("LOGS_SINK_DRAIN_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_DRAIN_INTERVAL: %w", err)
		}
		cfg.LogsSinkDrainInterval = d
	}
	return cfg, nil
}

// parseBoolWithYesNo extends strconv.ParseBool — it adds the
// case-insensitive 'yes'/'no' the previous hand-written switch accepted
// and which still turn up in k8s/YAML configs.
// PR #43 follow-up.
func parseBoolWithYesNo(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return strconv.ParseBool(v)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "antibot-backend"
	}
	return h
}
