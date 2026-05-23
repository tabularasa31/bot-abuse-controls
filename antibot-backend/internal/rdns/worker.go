// Package rdns — единственная активная вычислительная задача backend по
// ADR-005: PTR + forward DNS, наполняет каталог verified_bot_ips. Это третья
// функция backend.
//
// Skeleton-уровень ([B2]): таймер тикает на заданном интервале, считает
// собственный счётчик и логирует "стучу"; никаких реальных DNS-запросов,
// 3-state машины (verified/rejected/provisional) и записи в DB здесь нет —
// это задача [B7] поверх [B4] (схема verified_bot_ips). Цель скелета —
// доказать "rDNS-воркер живёт" из acceptance B2.
package rdns

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Worker struct {
	interval time.Duration
	logger   *slog.Logger
	ticks    prometheus.Counter
}

func New(reg prometheus.Registerer, logger *slog.Logger, interval time.Duration) *Worker {
	w := &Worker{
		interval: interval,
		logger:   logger,
		ticks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_rdns_ticks_total",
			Help: "rDNS worker iterations (skeleton: ticks only, real PTR+forward DNS lands in B7).",
		}),
	}
	reg.MustRegister(w.ticks)
	return w
}

// Run блокирует до ctx.Done(), как и любой background-воркер в Go.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("rdns worker started", "interval", w.interval)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("rdns worker stopped")
			return
		case <-t.C:
			w.ticks.Inc()
			w.logger.Debug("rdns tick (no-op until B7)")
		}
	}
}
