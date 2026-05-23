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
//
// main здесь — только bootstrap-обвязка: логгер, signal-context, передача
// управления в internal/app. Всё остальное — там.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/tabularasa31/antibot-backend/internal/app"
	"github.com/tabularasa31/antibot-backend/internal/logger"
)

func main() {
	log := logger.New()

	// signal.NotifyContext: ctx закрывается на SIGINT/SIGTERM, app.Run
	// блокирует до этого момента и сам делает graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}

	if err := a.Run(ctx); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}
