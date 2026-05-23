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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
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

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load", "err", err)
		os.Exit(1)
	}
	logger = logger.With("instance", cfg.Instance)
	logger.Info("starting antibot-backend",
		"http_addr", cfg.HTTPAddr,
		"rdns_interval", cfg.RDNSInterval,
		"postgres", cfg.PostgresDSN != "",
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// DB — опциональна на скелете. Если DSN задан и недоступна — это явная
	// ошибка деплоя, валимся: B1-substrate гарантирует, что postgres рядом
	// и healthy до старта backend (depends_on/condition: service_healthy).
	var pool *pgxpool.Pool
	if cfg.PostgresDSN != "" {
		pool, err = db.Open(ctx, cfg.PostgresDSN)
		if err != nil {
			logger.Error("postgres open", "err", err)
			os.Exit(1)
		}
		defer pool.Close()
		logger.Info("postgres connected")
	} else {
		logger.Warn("POSTGRES_DSN not set — running without DB (skeleton mode; B3/B6/B7 will require it)")
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	mux := http.NewServeMux()
	mux.HandleFunc("/health", health.Handler(cfg.Instance))
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	catalog.New().Register(mux)
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-serverErr:
		logger.Error("http server error", "err", err)
	case sig := <-sigCh:
		logger.Info("shutdown signal", "signal", sig.String())
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown", "err", err)
	}
	cancel() // останавливает rDNS-воркер
	wg.Wait()
	logger.Info("antibot-backend stopped")
}
