// Reloader ticks (filesource.Load plus dbloader.LoadRuntime → Merge →
// Store.Replace) on a given interval.
//
// The edge contract from config-distribution.md §"Channel C / Cadence":
// the edge polls /catalog/* every 30 s. For a dashboard edit to reach the
// edge in ≤30 s (acceptance B4 / B13), the backend must have a fresh
// *catalog.Data in the Store BEFORE the edge tick arrives — hence the backend's
// interval is shorter by default (5 s). A stale payload is possible between two
// ticks, but within the window "the edge sees the edit within ≤ edgeInterval
// + backendInterval" — which is enough for the dashboard UX.
//
// The data sources:
//   - filesource (the slow catalogs from the catalogs/ git repo, ADR-006).
//     An mtime cache: we reparse the YAML only when something changed, otherwise
//     we reuse the cached *catalog.SlowData.
//   - dbloader.LoadRuntime (verified_bot_ips, policy from the database).
//
// An error from either source does NOT zero the Store: fail-stale. The edge
// keeps seeing the last good catalog and the operator sees the
// `*_failures_total` metric (with a source label).
package dbloader

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
	"github.com/tabularasa31/antibot-backend/internal/filesource"
)

// bootstrapTimeout — a separate (more generous) budget for the first
// synchronous Reload in Bootstrap. A cold pool does a TCP plus TLS handshake plus
// pgxpool session setup plus eight SELECTs, which on a slow link or a cold cache
// easily exceeds r.interval (typically 5 s). For the periodic tick the
// per-tick deadline = r.interval (see tickContext) remains — so that a
// hung Postgres does not freeze the Run goroutine. A follow-up from review.
const bootstrapTimeout = 60 * time.Second

type Reloader struct {
	pool       *pgxpool.Pool
	store      *catalog.Store
	interval   time.Duration
	logger     *slog.Logger
	fileLoader *filesource.Loader

	// slowCache — the last successfully parsed snapshot of the slow
	// catalogs from filesource. It is reused on ticks where the files'
	// mtime has not changed, so as not to spend time parsing YAML for nothing
	// (the typical case: a per-tick LoadRuntime brings a new verified_bot while
	// the files sit still).
	slowCache *catalog.SlowData

	reloadOK   prometheus.Counter
	reloadFail prometheus.Counter
	// reloadDur — labelled `outcome={success,failure}`, so that the p99 in dashboards
	// does not mix good ticks with ones where the Load hung until the per-tick deadline
	// (see the tick and its context.WithTimeout). From review.
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
		// Defence in depth: the config layer validates this already, but alternative
		// callers (tests, future hot-reload code) can get it wrong.
		// `time.NewTicker(0)` panics and `context.WithTimeout(ctx, 0)` is immediately
		// expired — both branches give junk messages. Better an explicit refusal.
		return nil, fmt.Errorf("dbloader: reload interval must be > 0, got %s", interval)
	}
	if fileLoader == nil {
		// The source of truth for the slow catalogs is now mandatory. Without
		// it the merge would produce empty tls_fp_blocklist / ua_blacklist / etc.,
		// and the edge would get a "successful" payload missing the records already added
		// to catalogs/ — a silent regression in production.
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

// Run blocks until ctx.Done(), reloading the catalogs periodically at the
// r.interval. We do NOT run the first tick — it already happened in Bootstrap
// synchronously before the HTTP server started; repeating it immediately would mean going
// to the database twice at startup for nothing.
//
// A tick error: log and continue (fail-stale). The edge stays on the last
// good catalog and the operator sees it through `_failures_total`.
func (r *Reloader) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// The per-tick deadline = r.interval is applied ONLY on the hot
			// Run path: without it a hung pgx (a half-open TCP connection or a NAT timeout)
			// would block the goroutine, the tickers would coalesce, and
			// reloadFail would never increment — leaving the operator with no signal.
			if err := r.tickWith(ctx, r.interval); err != nil {
				r.logger.Error("catalog reload failed", "err", err)
			}
		}
	}
}

// Bootstrap — the synchronous first Reload before the HTTP server starts. If the database
// is empty or broken, main fails; that is deliberate: a backend with no catalogs
// must not accept traffic from the edge.
//
// The budget is bootstrapTimeout (60 s), NOT r.interval: a cold pool plus
// the first Acquire with a TCP/TLS handshake plus eight SELECTs on a cold
// buffer cache easily exceed the periodic 5-second tick. Sharing that
// budget with the hot path would mean crashing the backend at startup on a
// slow link. A follow-up from review.
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
