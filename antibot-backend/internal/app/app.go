// Package app assembles the process: config, database, catalog, HTTP server and
// background workers. main only sets up the signal context and the logger, so
// the same assembly can be driven from a test or a wrapper.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/antibotapi"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/catalog"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/config"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/db"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/dbloader"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/filesource"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/health"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/logs"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/logsink"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/rdns"
)

// App is an assembled but not yet started process. Run starts the workers and
// blocks until a signal or a server error, then shuts down gracefully.
type App struct {
	cfg      config.Config
	logger   *slog.Logger
	pool     *pgxpool.Pool // nil in skeleton mode without a database
	srv      *http.Server
	reg      *prometheus.Registry
	store    *catalog.Store     // the rDNS worker needs this reference (HasVerifiedBotIP)
	reloader *dbloader.Reloader // nil in skeleton mode without a database
	rdns     *rdns.Worker       // nil in skeleton mode without a database
	logSink  *logsink.Sink      // nil without a database (skeleton) or on a spool initialisation error
}

// New assembles the dependency graph, failing before the listening socket opens
// rather than leaving the process up with a broken subsystem.
//
// The context covers bootstrap only; the workers get their own in Run. The
// return is named so a defer can close the pool on any later error path, which
// matters when New is called from a test rather than from main.
func New(ctx context.Context, logger *slog.Logger) (a *App, retErr error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	logger = logger.With("instance", cfg.Instance)
	logger.Info("starting antibot-backend",
		"http_addr", cfg.HTTPAddr,
		"rdns_interval", cfg.RDNSInterval,
		"shutdown_timeout", cfg.ShutdownTimeout,
		"postgres", cfg.PostgresDSN != "",
	)

	a = &App{cfg: cfg, logger: logger}

	// The database is optional in the skeleton. If a DSN is set and it is unreachable, that is a clear
	// deployment error and we fail: the B1 substrate guarantees that postgres is nearby
	// and healthy before the backend starts (depends_on/condition: service_healthy).
	if cfg.PostgresDSN != "" {
		pool, err := db.Open(ctx, cfg.PostgresDSN)
		if err != nil {
			return nil, fmt.Errorf("postgres open: %w", err)
		}
		a.pool = pool
		// Closes over the local pool, not the field: the error paths return a nil
		// App, so reaching through it here would panic on exactly the path this
		// cleanup exists for.
		defer func() {
			if retErr != nil {
				pool.Close()
			}
		}()
		logger.Info("postgres connected")
	} else {
		logger.Warn("POSTGRES_DSN not set — running without DB (skeleton mode; B3/B6/B7 will require it)")
	}

	a.reg = prometheus.NewRegistry()
	a.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	// We pin the method at the ServeMux level (Go 1.22+): POST /health → 405, and
	// hitting /metrics with anything but GET is likewise no reason to touch the registry.
	mux.HandleFunc("GET /health", health.Handler(cfg.Instance, healthPinger(a.pool)))
	mux.Handle("GET /metrics", promhttp.HandlerFor(a.reg, promhttp.HandlerOpts{}))

	if err := a.buildCatalog(ctx, mux); err != nil {
		return nil, err
	}

	// Needs both a database to write to and a catalog to deduplicate against.
	// Without them the receiver still counts, but enqueues nothing.
	if a.pool != nil && a.store != nil {
		a.rdns = rdns.New(
			a.reg, logger,
			rdns.Config{
				QueueSize:  cfg.RDNSQueueSize,
				Workers:    cfg.RDNSWorkers,
				DNSTimeout: cfg.RDNSDNSTimeout,
				GCInterval: cfg.RDNSGCInterval,
				// Covers the gap until the reloader publishes the write, plus
				// headroom for database latency.
				PostWriteHold: cfg.CatalogReloadInterval + 2*time.Second,
			},
			rdns.NetResolver{},
			a.store,
			rdns.NewPgxWriter(a.pool),
		)
	} else {
		logger.Warn("rdns worker disabled — no DB / catalog store (skeleton mode)")
	}

	// LogSink (B9) — the BAC_LOG batch inserter into PostgreSQL with a disk queue.
	// We bring it up only when a pool exists: with no database the sink has nowhere to write, and the
	// receiver goes without it (the logs will simply return 202 as in the B2 skeleton).
	if a.pool != nil {
		sink, err := logsink.New(logsink.Config{
			BatchSize:     cfg.LogsSinkBatchSize,
			FlushInterval: cfg.LogsSinkFlushInterval,
			QueueSize:     cfg.LogsSinkQueueSize,
			SpoolDir:      cfg.LogsSinkSpoolDir,
			SpoolMaxBytes: cfg.LogsSinkSpoolMaxBytes,
			DrainInterval: cfg.LogsSinkDrainInterval,
		}, a.pool, logger, a.reg)
		if err != nil {
			// The spool directory cannot be created → a deployment tooling error
			// (the volume is not mounted, or permissions are missing). Better to fail than to
			// lose logs quietly in the spillover.
			return nil, fmt.Errorf("logsink init: %w", err)
		}
		a.logSink = sink
		if cfg.LogsSinkSpoolDir == "" {
			logger.Warn("logsink wired without spool dir — DB outage will drop log lines; set LOGS_SINK_SPOOL_DIR in production",
				"batch_size", cfg.LogsSinkBatchSize,
				"flush_interval", cfg.LogsSinkFlushInterval,
			)
		} else {
			logger.Info("logsink wired",
				"spool_dir", cfg.LogsSinkSpoolDir,
				"batch_size", cfg.LogsSinkBatchSize,
				"flush_interval", cfg.LogsSinkFlushInterval,
			)
		}
	}

	// The receiver is registered here, after rdns plus the sink: if the worker exists we
	// give the receiver an Enqueuer plus a classifier; the sink is wired independently.
	// Without a pool both branches are nil and the receiver works as a line counter (B2).
	var sinkArg logs.LogSink
	if a.logSink != nil {
		sinkArg = a.logSink
	}
	if a.rdns != nil {
		logs.NewWithDeps(a.reg, a.rdns, rdns.FamilyOfUA, sinkArg).Register(mux)
	} else if sinkArg != nil {
		logs.NewWithDeps(a.reg, nil, nil, sinkArg).Register(mux)
	} else {
		logs.New(a.reg).Register(mux)
	}

	// Fail-closed: with no token the routes are never registered, so a missing
	// secret shows up immediately as a 404 rather than as an open write API.
	if a.pool != nil {
		auth := antibotapi.NewAuthenticator(a.cfg.DashboardAPIToken, a.reg)
		if auth != nil {
			if srv := antibotapi.New(a.pool, auth, logger, a.reg); srv != nil {
				srv.Register(mux)
				logger.Info("policy API wired", "prefix", "/antibot/v1/")
			}
		} else {
			logger.Warn("policy API disabled — DASHBOARD_API_TOKEN not set; /antibot/v1/* will 404")
		}
	}

	a.srv = &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return a, nil
}

// buildCatalog wires the two sources — the slow catalogs from files and the
// runtime state from the database — and registers the routes. The reloader ticks
// both on one interval, merges them and publishes the result atomically.
func (a *App) buildCatalog(ctx context.Context, mux *http.ServeMux) error {
	catalogSrv := catalog.New()
	a.store = catalogSrv.Store()

	if a.pool == nil {
		// Without a database the catalogs stay unloaded and answer 503, which is
		// the honest signal: serving an empty runtime layer would be worse.
		a.logger.Warn("no POSTGRES_DSN — Channel C stays not-loaded (returns 503); set POSTGRES_DSN + CATALOGS_DIR to enable")
		catalogSrv.Register(mux)
		return nil
	}

	if a.cfg.MigrateOnStartup {
		if err := dbloader.Migrate(ctx, a.pool); err != nil {
			return fmt.Errorf("catalog migrate: %w", err)
		}
		a.logger.Info("catalog migrations applied")
	}

	fileLoader := filesource.New(a.cfg.CatalogsDir)
	reloader, err := dbloader.NewReloader(a.pool, catalogSrv.Store(), fileLoader, a.cfg.CatalogReloadInterval, a.logger, a.reg)
	if err != nil {
		return fmt.Errorf("catalog reloader: %w", err)
	}
	// The first Bootstrap is synchronous — if the files or the database are broken, the backend must not
	// come up "successfully" and answer 503 on every /catalog/* until the first tick.
	if err := reloader.Bootstrap(ctx); err != nil {
		return fmt.Errorf("catalog bootstrap: %w", err)
	}
	a.reloader = reloader
	a.logger.Info("catalog wired",
		"catalogs_dir", a.cfg.CatalogsDir,
		"reload_interval", a.cfg.CatalogReloadInterval,
	)

	catalogSrv.Register(mux)
	// logs.Receiver is registered AFTER rdns.Worker (see App.New), so that it
	// can get an Enqueuer. Here we only put the catalog plus /metrics on the mux.
	return nil
}

// Run starts the workers and the server and blocks until the context is
// cancelled or the server fails, then shuts down gracefully.
func (a *App) Run(ctx context.Context) error {
	// workerCtx lives under Run and is closed on exit, so that the workers
	// get the stop signal even when Run returns through an
	// HTTP error (rather than through the outer ctx being cancelled).
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// The rDNS worker — a background goroutine, the only active compute for now.
	// In skeleton mode without a database the worker was never constructed — so there is simply
	// nothing to start.
	if a.rdns != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.rdns.Run(workerCtx)
		}()
	}

	// LogSink (B9): consumer + drainer.
	if a.logSink != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.logSink.Run(workerCtx)
		}()
	}

	// The catalog reloader (B4): it ticks Load → Store.Replace.
	if a.reloader != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.reloader.Run(workerCtx)
		}()
	}

	serverErr := make(chan error, 1)
	go func() {
		a.logger.Info("http listening", "addr", a.cfg.HTTPAddr)
		if err := a.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	var runErr error
	select {
	case err := <-serverErr:
		a.logger.Error("http server error", "err", err)
		runErr = err
	case <-ctx.Done():
		a.logger.Info("shutdown signal received")
		// The listener may have failed for a real reason between the signal and
		// the shutdown call. Without this drain that error is lost and Run
		// returns nil, leaving nothing to investigate.
		select {
		case err := <-serverErr:
			a.logger.Error("late http server error during shutdown", "err", err)
			runErr = err
		default:
		}
	}

	a.shutdown(ctx, cancel, &wg)
	a.logger.Info("antibot-backend stopped")
	return runErr
}

// shutdown terminates in order under one shared deadline: drain the server, then
// cancel the workers, then wait for them — bounded, because a DNS lookup can
// hang on the network.
//  4. pgxpool.Close under the deadline: it blocks on active connections, which B3/B7
//     bring — we bound it by the same budget.
func (a *App) shutdown(parent context.Context, cancelWorkers context.CancelFunc, wg *sync.WaitGroup) {
	// The parent was already cancelled by the signal — we need a fresh ctx with a deadline that
	// inherits the values (tracing/log). WithoutCancel + WithDeadline is
	// the same trick as in the B4 advisory_unlock (contextcheck).
	deadline := time.Now().Add(a.cfg.ShutdownTimeout)
	shutdownCtx, cancel := context.WithDeadline(context.WithoutCancel(parent), deadline)
	defer cancel()

	a.logger.Info("shutdown: draining HTTP", "deadline", a.cfg.ShutdownTimeout)
	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		a.logger.Error("shutdown: http drain failed — forcing close", "err", err)
		if closeErr := a.srv.Close(); closeErr != nil {
			a.logger.Error("shutdown: http force-close failed", "err", closeErr)
		}
	}

	a.logger.Info("shutdown: stopping background workers")
	cancelWorkers()
	if !waitBounded(shutdownCtx, wg.Wait) {
		// The goroutine keeps running until os.Exit — that is deliberate abandonment,
		// not a leak: the process follows and the runtime collects it. We log it explicitly,
		// so that the operator does not wonder why the process took longer than ShutdownTimeout.
		a.logger.Error("shutdown: workers did not exit within deadline — abandoning")
	}

	if a.pool != nil {
		a.logger.Info("shutdown: closing postgres pool")
		if !waitBounded(shutdownCtx, a.pool.Close) {
			a.logger.Error("shutdown: postgres pool did not close within deadline — abandoning")
		}
	}
}

// waitBounded calls a blocking fn in a goroutine and waits either for it to finish
// or for ctx.Done(). true means fn made it, false means it was abandoned (the goroutine may
// keep living until os.Exit).
func waitBounded(ctx context.Context, fn func()) bool {
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// healthPinger turns a nil pool into a nil Pinger (a skeleton with no database) and otherwise
// passes *pgxpool.Pool through as a health.Pinger. Without it we would have to drag the
// pgx dependency into the health package.
func healthPinger(pool *pgxpool.Pool) health.Pinger {
	if pool == nil {
		return nil
	}
	return pool
}
