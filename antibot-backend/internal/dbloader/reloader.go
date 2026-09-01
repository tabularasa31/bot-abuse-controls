// Reloader periodically reloads both catalog layers, merges them and publishes
// the result.
//
// Its interval is shorter than the edge's poll, so a fresh snapshot is already
// in place when the edge asks — which is what bounds how long an edit takes to
// reach the edge.
//
// The slow layer is only reparsed when the files change; the runtime layer is
// read every tick. An error from either source leaves the previous snapshot in
// place and shows up in the failure counter.
package dbloader

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/catalog"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/filesource"
)

// The first load is more generous than a tick: a cold pool pays for handshakes
// and session setup before its first query. Later ticks keep the tighter
// deadline so a hung database cannot stall the loop.
const bootstrapTimeout = 60 * time.Second

type Reloader struct {
	pool       *pgxpool.Pool
	store      *catalog.Store
	interval   time.Duration
	logger     *slog.Logger
	fileLoader *filesource.Loader

	// Reused while the files are untouched, which is the common case: the
	// runtime layer changes every tick, the files rarely.
	slowCache *catalog.SlowData

	reloadOK   prometheus.Counter
	reloadFail prometheus.Counter
	// reloadDur — labelled `outcome={success,failure}`, so that the p99 in dashboards
	// does not mix good ticks with ones where the Load hung until the per-tick deadline
	// (see the tick and its context.WithTimeout).
	reloadDur  *prometheus.HistogramVec
	lastReload prometheus.Gauge // unix seconds, for debugging "when was the last one"
}

func NewReloader(
	pool *pgxpool.Pool,
	store *catalog.Store,
	fileLoader *filesource.Loader,
	interval time.Duration,
	logger *slog.Logger,
	reg prometheus.Registerer,
) (*Reloader, error) {
	if interval <= 0 {
		// A zero interval panics the ticker and expires every context instantly,
		// so refuse it explicitly rather than fail obscurely later.
		return nil, fmt.Errorf("dbloader: reload interval must be > 0, got %s", interval)
	}
	if fileLoader == nil {
		// Mandatory: without it the edge would get a successful payload missing
		// every record product has added.
		return nil, fmt.Errorf("dbloader: fileLoader is required (catalogs dir source)")
	}
	r := &Reloader{
		pool:       pool,
		store:      store,
		fileLoader: fileLoader,
		interval:   interval,
		logger:     logger,
		reloadOK: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_catalog_reload_total",
			Help: "Successful catalog reloads (slow files + runtime DB merged).",
		}),
		reloadFail: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_catalog_reload_failures_total",
			Help: "Failed catalog reloads (fail-stale: Store untouched).",
		}),
		reloadDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "antibot_backend_catalog_reload_duration_seconds",
			Help:    "Wall time of a single catalog reload tick, labelled by outcome.",
			Buckets: prometheus.DefBuckets,
		}, []string{"outcome"}),
		lastReload: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "antibot_backend_catalog_last_reload_unixtime",
			Help: "Unix timestamp of the last successful reload (0 if never).",
		}),
	}
	reg.MustRegister(r.reloadOK, r.reloadFail, r.reloadDur, r.lastReload)
	return r, nil
}

// Run reloads until the context is cancelled. The first tick is skipped:
// Bootstrap already ran one synchronously. A failed tick logs and continues, so
// the edge stays on its last good catalog.
func (r *Reloader) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Without a deadline a half-open connection would block the loop,
			// the ticks would coalesce, and the failure counter would never move.
			if err := r.tickWith(ctx, r.interval); err != nil {
				r.logger.Error("catalog reload failed", "err", err)
			}
		}
	}
}

// Bootstrap runs the first reload synchronously, before the server starts. A
// failure is fatal on purpose: a backend with no catalogs must not accept
// traffic.
// the first Acquire with a TCP/TLS handshake plus eight SELECTs on a cold
// buffer cache easily exceed the periodic 5-second tick. Sharing that
// budget with the hot path would mean crashing the backend at startup on a
// slow link.
func (r *Reloader) Bootstrap(ctx context.Context) error {
	return r.tickWith(ctx, bootstrapTimeout)
}

func (r *Reloader) tickWith(ctx context.Context, timeout time.Duration) error {
	tickCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	// The slow catalogs: we parse the YAML only when a file's mtime changed OR
	// the cache is empty (the first Bootstrap). Without the mtime cache we would reparse
	// several YAML files every 5 s for nothing: the typical load is new
	// verified_bot rows from the database while the files sit still.
	if r.slowCache == nil || r.fileLoader.Changed() {
		slow, err := r.fileLoader.Load()
		if err != nil {
			r.reloadDur.WithLabelValues("failure").Observe(time.Since(start).Seconds())
			r.reloadFail.Inc()
			return fmt.Errorf("filesource: %w", err)
		}
		r.slowCache = slow
	}

	runtime, err := LoadRuntime(tickCtx, r.pool)
	if err != nil {
		r.reloadDur.WithLabelValues("failure").Observe(time.Since(start).Seconds())
		r.reloadFail.Inc()
		return fmt.Errorf("dbloader runtime: %w", err)
	}

	d := catalog.Merge(r.slowCache, runtime)
	r.reloadDur.WithLabelValues("success").Observe(time.Since(start).Seconds())
	r.store.Replace(d)
	r.reloadOK.Inc()
	r.lastReload.Set(float64(time.Now().Unix()))
	r.logger.Debug("catalog reloaded",
		"version", d.Version,
		"hosts", len(d.Policy),
		"tls_fp_blocklist", len(d.TLSFPBlocklist),
		"ua_blacklist", len(d.UABlacklist),
		"ip_blocklist", len(d.IPBlocklist),
		"ip_whitelist", len(d.IPWhitelist),
		"asn_datacenters", len(d.ASNDatacenters),
		"verified_bot_ips", len(d.VerifiedBotIPs),
	)
	return nil
}
