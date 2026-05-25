// Package app — сборка процесса antibot-backend.
//
// main() здесь занимается только signal-context'ом и логгером; всё, что
// связано с конфигом, БД, каталогом, HTTP-сервером и фоновыми воркерами,
// собирается в App.New и крутится из App.Run. Если завтра потребуется
// поднимать backend из тестов или из обёртки (например, для integration-теста
// с реальным Postgres), вызов остаётся идентичным main.
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

// App — собранный, но ещё не запущенный процесс. Все зависимости проинициализированы
// (config прочитан, БД подключена, каталог забутстраплен, HTTP-сервер собран);
// Run() запускает воркеры и блокирует до сигнала / ошибки HTTP, после чего
// сам делает graceful shutdown.
type App struct {
	cfg      config.Config
	logger   *slog.Logger
	pool     *pgxpool.Pool // nil в skeleton-режиме без БД
	srv      *http.Server
	reg      *prometheus.Registry
	store    *catalog.Store     // ссылка нужна rDNS-воркеру (HasVerifiedBotIP)
	reloader *dbloader.Reloader // nil в skeleton-режиме без БД
	rdns     *rdns.Worker       // nil в skeleton-режиме без БД
	logSink  *logsink.Sink      // nil без БД (skeleton) или при ошибке инициализации спула
}

// New собирает граф зависимостей. Возвращает ошибку, если конфиг не читается,
// БД не открывается, миграции не накатываются или каталог не бутстрапится —
// все эти случаи мы предпочитаем поймать ДО открытия listening-сокета,
// чтобы процесс не висел "успешно" с битой подсистемой.
//
// Ctx используется только под bootstrap (миграции, первый Load); фоновые
// воркеры получат свой ctx в Run.
//
// Named return — чтобы defer'ом подчищать pgxpool на любом error-пути ПОСЛЕ
// db.Open. В main() это в основном маскируется os.Exit(1), но App.New
// позиционируется как callable из тестов и обёрток — там утечка горутин/
// коннектов pool'a была бы реальной.
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

	// БД — опциональна на скелете. Если DSN задан и недоступна — это явная
	// ошибка деплоя, валимся: B1-substrate гарантирует, что postgres рядом
	// и healthy до старта backend (depends_on/condition: service_healthy).
	if cfg.PostgresDSN != "" {
		pool, err := db.Open(ctx, cfg.PostgresDSN)
		if err != nil {
			return nil, fmt.Errorf("postgres open: %w", err)
		}
		a.pool = pool
		// Cleanup-on-error: любой возврат с retErr != nil после этой точки
		// (миграции, reloader-init, bootstrap каталога) должен закрыть pool —
		// иначе in-process caller (тест / обёртка) утаскивает живые коннекты
		// и фоновые pgx-горутины. Замыкаемся на локальный `pool`, а не на
		// `a.pool`: тело функции делает `return nil, err`, что зануляет
		// именованный возврат `a`, и обращение к `a.pool` в defer'е дало бы
		// nil-deref панику ровно на error-пути, который мы пытаемся убрать.
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
	// Метод фиксируем на уровне ServeMux (Go 1.22+): POST /health → 405,
	// дёргать /metrics чем-то кроме GET — тоже не повод трогать registry.
	mux.HandleFunc("GET /health", health.Handler(cfg.Instance, healthPinger(a.pool)))
	mux.Handle("GET /metrics", promhttp.HandlerFor(a.reg, promhttp.HandlerOpts{}))

	if err := a.buildCatalog(ctx, mux); err != nil {
		return nil, err
	}

	// rDNS-воркер ([B7]) живёт только когда есть БД и каталог — пишет
	// verified_bot_ips, читает «уже есть в каталоге» из catalog.Store.
	// Без pool'a (skeleton без БД) воркер остаётся nil; receiver тогда
	// тоже без enqueue и работает как счётчик.
	if a.pool != nil && a.store != nil {
		a.rdns = rdns.New(
			a.reg, logger,
			rdns.Config{
				QueueSize:  cfg.RDNSQueueSize,
				Workers:    cfg.RDNSWorkers,
				DNSTimeout: cfg.RDNSDNSTimeout,
				GCInterval: cfg.RDNSGCInterval,
				// PostWriteHold перекрывает окно между «воркер записал»
				// и «reloader положил свежий Data в Store». Без буфера
				// hot IP внутри этого окна снова прошёл бы Enqueue и
				// сделал повторный DNS. +2с с запасом на pgx latency.
				PostWriteHold: cfg.CatalogReloadInterval + 2*time.Second,
			},
			rdns.NetResolver{},
			a.store,
			rdns.NewPgxWriter(a.pool),
		)
	} else {
		logger.Warn("rdns worker disabled — no DB / catalog store (skeleton mode)")
	}

	// LogSink (B9) — батч-инсертер BAC_LOG в PostgreSQL с disk-queue.
	// Поднимаем только при наличии пула: без БД sink'у некуда писать,
	// receiver останется без него (логи будут просто 202-ить как в B2-скелете).
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
			// Спул-каталог не создаётся → инструментальная ошибка деплоя
			// (volume не примонтирован / нет прав). Лучше упасть, чем
			// тихо терять логи в spillover.
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

	// Receiver регистрируется здесь, после rdns + sink: если воркер есть —
	// даём receiver'у Enqueuer + classifier; sink подключаем независимо.
	// Без пула обе ветки = nil, receiver работает как счётчик строк (B2).
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

	// Policy API ([B10]) — write-side для dashboard-backend. Поднимаем только
	// если DB есть И токен задан: без токена /antibot/v1/* не регистрируется
	// (fail-closed; dashboard получит 404, и сразу видно что secret не
	// прокинут в env).
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

// buildCatalog собирает источники Channel C и регистрирует HTTP-роуты.
// Источников теперь два, оба обязательны при наличии БД (по ADR-006):
//
//   - filesource (catalogs/): медленные каталоги от продакта. Без файлов
//     невозможно собрать осмысленный slow-слой — Store не поднимется.
//   - dbloader.LoadRuntime: verified_bot_ips, policy. Без БД (skeleton-
//     режим) — оба пустые, /catalog/* отвечает 503.
//
// Reloader тикает оба источника на одном interval'е, мерджит в *catalog.Data,
// публикует в Store через атомарный Replace.
func (a *App) buildCatalog(ctx context.Context, mux *http.ServeMux) error {
	catalogSrv := catalog.New()
	a.store = catalogSrv.Store()

	if a.pool == nil {
		// Skeleton-режим без БД: Channel C остаётся в not-loaded состоянии
		// (503 на любой /catalog/*). Это явный знак оператору — без БД
		// rDNS-воркер не пишет verified_bot_ips, antibotapi не принимает
		// policy, отдавать пустую runtime-часть было бы хуже, чем 503.
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
	// Первый Bootstrap синхронно — если файлы / БД биты, backend не должен
	// подниматься "успешно" с 503 на каждый /catalog/* до первого тика.
	if err := reloader.Bootstrap(ctx); err != nil {
		return fmt.Errorf("catalog bootstrap: %w", err)
	}
	a.reloader = reloader
	a.logger.Info("catalog wired",
		"catalogs_dir", a.cfg.CatalogsDir,
		"reload_interval", a.cfg.CatalogReloadInterval,
	)

	catalogSrv.Register(mux)
	// logs.Receiver регистрируется ПОСЛЕ rdns.Worker (см. App.New), чтобы
	// мог получить Enqueuer. Здесь только catalog + /metrics уже на mux.
	return nil
}

// Run запускает фоновые воркеры и HTTP-сервер, блокирует до отмены ctx или
// фатальной ошибки HTTP, затем сам делает graceful shutdown. Возвращает
// ошибку HTTP-сервера (если он упал), иначе nil.
//
// Ctx должен отменяться по сигналу (см. signal.NotifyContext в main) —
// именно его отмена триггерит начало shutdown'а.
func (a *App) Run(ctx context.Context) error {
	// workerCtx живёт под Run и закрывается при выходе, чтобы воркеры
	// получили сигнал к остановке даже если Run возвращается через
	// HTTP-ошибку (а не через отмену внешнего ctx).
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// rDNS-воркер — фоновая горутина, единственный активный compute сейчас.
	// В skeleton-режиме без БД воркер не сконструирован — тогда просто
	// нечего запускать.
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

	// Catalog-reloader (B4): тикает Load → Store.Replace.
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
		// Гонка: между тем, как сигнал закрыл ctx.Done и тем, как мы успели
		// вызвать srv.Shutdown, listener мог вернуть НЕ-ErrServerClosed
		// ошибку (accept loop EMFILE, network fault, recovered panic).
		// HTTP-горутина запишет её в буферизованный serverErr (cap=1),
		// но никто уже не читает — без drain'а ошибка тихо потеряется,
		// Run вернёт nil, оператор после инцидента не найдёт причину.
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

// shutdown — упорядоченное завершение под общим бюджетом cfg.ShutdownTimeout.
// Шаги идут последовательно и каждый знает про общий deadline:
//  1. HTTP: srv.Shutdown дренирует in-flight; если не уложился — srv.Close()
//     рвёт хвост, иначе systemd прибьёт SIGKILL'ом без grace.
//  2. cancelWorkers: останавливает фоновые воркеры (rDNS сейчас, B6 disk-queue
//     потом).
//  3. wg.Wait под deadline: B7 принесёт реальные DNS-запросы, которые могут
//     висеть на сети — не даём им задержать выход.
//  4. pgxpool.Close под deadline: блокирует на активных коннектах, B3/B7
//     принесут их — ограничиваем по тому же бюджету.
func (a *App) shutdown(parent context.Context, cancelWorkers context.CancelFunc, wg *sync.WaitGroup) {
	// parent уже отменён сигналом — нам нужен fresh ctx с deadline, но
	// унаследовавший values (tracing/log). WithoutCancel + WithDeadline —
	// тот же приём, что в advisory_unlock из B4 (contextcheck).
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
		// Горутина продолжит крутиться до os.Exit — это осознанный abandonment,
		// а не leak: процесс уходит следом, рантайм её собирёт. Логируем явно,
		// чтобы оператор не гадал, почему процесс выходит дольше ShutdownTimeout.
		a.logger.Error("shutdown: workers did not exit within deadline — abandoning")
	}

	if a.pool != nil {
		a.logger.Info("shutdown: closing postgres pool")
		if !waitBounded(shutdownCtx, a.pool.Close) {
			a.logger.Error("shutdown: postgres pool did not close within deadline — abandoning")
		}
	}
}

// waitBounded зовёт блокирующую fn в горутине и ждёт её либо до завершения,
// либо до ctx.Done(). true — fn успела, false — abandoned (горутина может
// продолжить жить до os.Exit).
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

// healthPinger превращает nil-pool в nil-Pinger (skeleton без БД) и наоборот
// пробрасывает *pgxpool.Pool как health.Pinger. Без этого пришлось бы тащить
// pgx-зависимость в пакет health.
func healthPinger(pool *pgxpool.Pool) health.Pinger {
	if pool == nil {
		return nil
	}
	return pool
}
