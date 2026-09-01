// Package app — the assembly of the antibot-backend process.
//
// main() here deals only with the signal context and the logger; everything to do with
// the config, the database, the catalog, the HTTP server and the background workers is
// assembled in App.New and driven from App.Run. If tomorrow we need to
// bring the backend up from tests or from a wrapper (for an integration test
// against a real Postgres, say), the call stays identical to main.
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

	"github.com/tabularasa31/antibot-backend/internal/antibotapi"
	"github.com/tabularasa31/antibot-backend/internal/catalog"
	"github.com/tabularasa31/antibot-backend/internal/config"
	"github.com/tabularasa31/antibot-backend/internal/db"
	"github.com/tabularasa31/antibot-backend/internal/dbloader"
	"github.com/tabularasa31/antibot-backend/internal/filesource"
	"github.com/tabularasa31/antibot-backend/internal/health"
	"github.com/tabularasa31/antibot-backend/internal/logs"
	"github.com/tabularasa31/antibot-backend/internal/logsink"
	"github.com/tabularasa31/antibot-backend/internal/rdns"
)

// App — an assembled but not yet started process. Every dependency is initialised
// (the config is read, the database is connected, the catalog is bootstrapped, the HTTP server is built);
// Run() starts the workers and blocks until a signal or an HTTP error, after which
// it performs a graceful shutdown itself.
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

// New assembles the dependency graph. It returns an error if the config cannot be read,
// the database cannot be opened, the migrations do not apply or the catalog does not bootstrap —
// we prefer to catch all of those BEFORE opening the listening socket,
// so that the process does not hang "successfully" with a broken subsystem.
//
// Ctx is used only during the bootstrap (migrations, the first Load); the background
// workers get their own ctx in Run.
//
// A named return — so that a defer can clean up the pgxpool on any error path AFTER
// db.Open. In main() that is mostly masked by os.Exit(1), but App.New
// is positioned as callable from tests and wrappers, where leaking goroutines or
// pool connections would be real.
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
		// Cleanup on error: any return with retErr != nil after this point
		// (migrations, reloader init, the catalog bootstrap) must close the pool —
		// otherwise an in-process caller (a test or a wrapper) drags live connections
		// and background pgx goroutines along. We close over the local `pool` rather than
		// `a.pool`: the function body does `return nil, err`, which zeroes the
		// named return `a`, and touching `a.pool` in the defer would give a
		// nil-deref panic on exactly the error path we are trying to clean up.
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

	// The rDNS worker ([B7]) exists only when there is a database and a catalog — it writes
	// verified_bot_ips and reads "already in the catalog" from catalog.Store.
	// Without a pool (a skeleton with no database) the worker stays nil; the receiver is then
	// left without enqueue and works as a counter.
	if a.pool != nil && a.store != nil {
		a.rdns = rdns.New(
			a.reg, logger,
			rdns.Config{
				QueueSize:  cfg.RDNSQueueSize,
				Workers:    cfg.RDNSWorkers,
				DNSTimeout: cfg.RDNSDNSTimeout,
				GCInterval: cfg.RDNSGCInterval,
				// PostWriteHold covers the window between "the worker wrote it"
				// and "the reloader put a fresh Data into the Store". Without the buffer a
				// hot IP inside that window would pass Enqueue again and
				// do a repeat DNS lookup. +2 s of headroom for pgx latency.
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

	// The Policy API ([B10]) — the write side for the dashboard backend. We bring it up only
	// if there is a DB AND a token is set: with no token /antibot/v1/* is not registered
	// (fail-closed; the dashboard gets a 404, which immediately shows that the secret was not
	// passed through env).
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

// buildCatalog assembles the Channel C sources and registers the HTTP routes.
// There are now two sources, both mandatory when a database is present (per ADR-006):
//
//   - filesource (catalogs/): the slow catalogs from product. Without the files it is
//     impossible to assemble a meaningful slow layer — the Store will not come up.
//   - dbloader.LoadRuntime: verified_bot_ips, policy. Without a database (skeleton
//     mode) both are empty and /catalog/* answers 503.
//
// The reloader ticks both sources on one interval, merges them into a *catalog.Data and
// publishes into the Store through an atomic Replace.
func (a *App) buildCatalog(ctx context.Context, mux *http.ServeMux) error {
	catalogSrv := catalog.New()
	a.store = catalogSrv.Store()

	if a.pool == nil {
		// Skeleton mode without a database: Channel C stays in the not-loaded state
		// (503 on any /catalog/*). That is an explicit sign to the operator — with no database the
		// rDNS worker does not write verified_bot_ips, antibotapi does not accept a
		// policy, and serving an empty runtime part would be worse than a 503.
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

// Run starts the background workers and the HTTP server, blocks until ctx is cancelled or a
// fatal HTTP error occurs, and then performs a graceful shutdown itself. It returns
// the HTTP server's error (if it fell over), otherwise nil.
//
// Ctx must be cancelled by a signal (see signal.NotifyContext in main) —
// its cancellation is what triggers the start of the shutdown.
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
		// A race: between the signal closing ctx.Done and us calling
		// srv.Shutdown, the listener could have returned a NON-ErrServerClosed
		// error (an EMFILE in the accept loop, a network fault, a recovered panic).
		// The HTTP goroutine writes it into the buffered serverErr (cap=1),
		// but nobody reads it any more — without a drain the error is quietly lost,
		// Run returns nil, and after the incident the operator cannot find the cause.
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

// shutdown — an ordered termination under the shared cfg.ShutdownTimeout budget.
// The steps run in sequence and each knows about the shared deadline:
//  1. HTTP: srv.Shutdown drains what is in flight; if it does not fit, srv.Close()
//     tears down the tail, otherwise systemd kills us with SIGKILL without grace.
//  2. cancelWorkers: it stops the background workers (rDNS now, the B6 disk queue
//     later).
//  3. wg.Wait under the deadline: B7 brings real DNS lookups that can
//     hang on the network — we do not let them delay the exit.
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
