// antibot-backend — централизованный Go-сервис по ADR-005.
//
// Три функции, ничего сверх:
//  1. catalog server   — отдаёт каталоги на edge по Channel C (B3 наполняет).
//  2. log receiver     — принимает поток BAC_LOG с эджей (B6/B9 наполняют).
//  3. rDNS worker      — единственная активная вычислительная задача (B7).
//
// Сервис stateless поверх своей PostgreSQL. На hot-path не висит: edge при
// недоступности backend остаётся на последнем хорошем каталоге (fail-stale,
// config-distribution §"Channel C / Failure mode").
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
	"github.com/tabularasa31/antibot-backend/internal/config"
	"github.com/tabularasa31/antibot-backend/internal/db"
	"github.com/tabularasa31/antibot-backend/internal/health"
	"github.com/tabularasa31/antibot-backend/internal/logs"
	"github.com/tabularasa31/antibot-backend/internal/rdns"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// run возвращает ошибку вместо os.Exit, чтобы defer'ы (cancel ctx, закрытие
// pgxpool) реально отрабатывали при ранних обломах.
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger = logger.With("instance", cfg.Instance)
	logger.Info("starting antibot-backend",
		"http_addr", cfg.HTTPAddr,
		"rdns_interval", cfg.RDNSInterval,
		"shutdown_timeout", cfg.ShutdownTimeout,
		"postgres", cfg.PostgresDSN != "",
	)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// DB — опциональна на скелете. Если DSN задан и недоступна — это явная
	// ошибка деплоя, валимся: B1-substrate гарантирует, что postgres рядом
	// и healthy до старта backend (depends_on/condition: service_healthy).
	var pool *pgxpool.Pool
	if cfg.PostgresDSN != "" {
		pool, err = db.Open(ctx, cfg.PostgresDSN)
		if err != nil {
			return fmt.Errorf("postgres open: %w", err)
		}
		logger.Info("postgres connected")
	} else {
		logger.Warn("POSTGRES_DSN not set — running without DB (skeleton mode; B3/B6/B7 will require it)")
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	// Метод фиксируем на уровне ServeMux (Go 1.22+): POST /health → 405,
	// дёргать /metrics чем-то кроме GET — тоже не повод трогать registry.
	mux.HandleFunc("GET /health", health.Handler(cfg.Instance, healthPinger(pool)))
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	catalogSrv := catalog.New()
	if cfg.CatalogYAMLPath != "" {
		// Падаем на старте, если YAML битый: пустой Store отдаёт всем
		// эджам defaultVersion и пустые наборы — это валидный wire-стейт,
		// но операторы хотят знать, что конфигурация не доехала, не
		// гадать по prometheus'у.
		d, err := catalog.LoadYAML(cfg.CatalogYAMLPath)
		if err != nil {
			return fmt.Errorf("catalog load: %w", err)
		}
		catalogSrv.Store().Replace(d)
		logger.Info("catalog loaded",
			"path", cfg.CatalogYAMLPath,
			"version", d.Version,
			"hosts_with_policy", len(d.Policy),
		)
	} else {
		logger.Warn("CATALOG_YAML not set — catalog server returns empty payloads with version=" + "0.0.0" + " (B4 will replace YAML loader with pgx)")
	}
	catalogSrv.Register(mux)
	logs.New(reg).Register(mux)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var wg sync.WaitGroup

	// rDNS-воркер — фоновая горутина, единственный активный compute.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rdns.New(reg, logger, cfg.RDNSInterval).Run(ctx)
	}()

	// HTTP-сервер.
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("http listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Ловим SIGINT/SIGTERM. signal.Stop вызываем явно — пригодится, если когда-то
	// run() будут звать из тестов или из обёртки (а не из main()).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var runErr error
	select {
	case err := <-serverErr:
		logger.Error("http server error", "err", err)
		runErr = err
	case sig := <-sigCh:
		logger.Info("shutdown signal", "signal", sig.String())
	}

	shutdown(logger, cfg.ShutdownTimeout, srv, cancelCtx, &wg, pool)
	logger.Info("antibot-backend stopped")
	return runErr
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

// shutdown — упорядоченное завершение под общим бюджетом cfg.ShutdownTimeout.
// Шаги идут последовательно и каждый знает про общий deadline:
//  1. HTTP: srv.Shutdown дренирует in-flight; если не уложился — srv.Close()
//     рвёт хвост, иначе systemd прибьёт SIGKILL'ом без grace.
//  2. ctx cancel: останавливает фоновые воркеры (rDNS сейчас, B6 disk-queue
//     потом).
//  3. wg.Wait под deadline: B7 принесёт реальные DNS-запросы, которые могут
//     висеть на сети — не даём им задержать выход.
//  4. pgxpool.Close под deadline: блокирует на активных коннектах, B3/B7
//     принесут их — ограничиваем по тому же бюджету.
func shutdown(
	logger *slog.Logger,
	timeout time.Duration,
	srv *http.Server,
	cancelCtx context.CancelFunc,
	wg *sync.WaitGroup,
	pool *pgxpool.Pool,
) {
	deadline := time.Now().Add(timeout)
	shutdownCtx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	logger.Info("shutdown: draining HTTP", "deadline", timeout)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown: http drain failed — forcing close", "err", err)
		if closeErr := srv.Close(); closeErr != nil {
			logger.Error("shutdown: http force-close failed", "err", closeErr)
		}
	}

	logger.Info("shutdown: stopping background workers")
	cancelCtx()
	if !waitBounded(shutdownCtx, wg.Wait) {
		// Горутина продолжит крутиться до os.Exit — это осознанный abandonment,
		// а не leak: процесс уходит следом, рантайм её собирёт. Логируем явно,
		// чтобы оператор не гадал, почему процесс выходит дольше ShutdownTimeout.
		logger.Error("shutdown: workers did not exit within deadline — abandoning")
	}

	if pool != nil {
		logger.Info("shutdown: closing postgres pool")
		if !waitBounded(shutdownCtx, pool.Close) {
			logger.Error("shutdown: postgres pool did not close within deadline — abandoning")
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
