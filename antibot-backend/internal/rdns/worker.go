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
	"runtime/debug"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Worker struct {
	interval time.Duration
	logger   *slog.Logger
	ticks    prometheus.Counter
	panics   prometheus.Counter
}

func New(reg prometheus.Registerer, logger *slog.Logger, interval time.Duration) *Worker {
	w := &Worker{
		interval: interval,
		logger:   logger,
		ticks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_rdns_ticks_total",
			Help: "rDNS worker iterations (skeleton: ticks only, real PTR+forward DNS lands in B7).",
		}),
		panics: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_rdns_panics_total",
			Help: "rDNS worker iterations that panicked and were recovered (alert on > 0).",
		}),
	}
	reg.MustRegister(w.ticks, w.panics)
	return w
}

// Run блокирует до ctx.Done(). Паника в одной итерации НЕ роняет воркер:
// stateless-сервис за LB живёт реплицированным, но обе реплики идут с
// одинаковым кодом — детерминированная паника положила бы обе сразу. Поэтому
// recover per-iteration, факт фиксируем в antibot_backend_rdns_panics_total
// (на это вешать alert: > 0 ⇒ баг в B7-коде).
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
			w.tickSafely(ctx)
		}
	}
}

func (w *Worker) tickSafely(ctx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			w.panics.Inc()
			w.logger.Error("rdns iteration panic — recovered",
				"panic", rec,
				"stack", string(debug.Stack()),
			)
		}
	}()
	w.tick(ctx)
}

// tick — рабочая итерация. На скелете только инкремент; B7 положит сюда
// PTR+forward DNS и запись в verified_bot_ips.
func (w *Worker) tick(_ context.Context) {
	w.ticks.Inc()
	w.logger.Debug("rdns tick (no-op until B7)")
}
