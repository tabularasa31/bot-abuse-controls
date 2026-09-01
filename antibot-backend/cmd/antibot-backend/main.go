// antibot-backend — the centralized Go service per ADR-005.
//
// Three functions, nothing more:
//  1. the catalog server   — serves the catalogs to the edge over Channel C (B3 populates it).
//  2. the log receiver     — accepts the BAC_LOG stream from the edges (B6/B9 populate it).
//  3. the rDNS worker      — the only active computational task.
//
// The service is stateless on top of its own PostgreSQL. It does not sit on the hot path: when the
// backend is unavailable the edge stays on the last good catalog (fail-stale,
// config-distribution §"Channel C / Failure mode").
//
// main here is only the bootstrap wiring: the logger, the signal context, and handing
// control to internal/app. Everything else lives there.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/app"
	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/logger"
)

func main() { os.Exit(realMain()) }

// realMain — a separate function so that the defers (signal.Stop through stop())
// really run: an os.Exit in main would bypass them (gocritic
// exitAfterDefer).
func realMain() int {
	log := logger.New()

	// signal.NotifyContext: ctx closes on SIGINT/SIGTERM, app.Run
	// blocks until then and performs the graceful shutdown itself.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		return 1
	}

	if err := a.Run(ctx); err != nil {
		log.Error("fatal", "err", err)
		return 1
	}
	return 0
}
