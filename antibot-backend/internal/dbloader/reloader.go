// Reloader тикает Load → Store.Replace на заданном интервале.
//
// Контракт edge'а из config-distribution.md §"Channel C / Cadence":
// edge поллит /catalog/* каждые 30 с. Backend, чтобы дашборд-edit
// доезжал до edge ≤30 c (acceptance B4 / B13), должен иметь свежую
// *catalog.Data в Store ДО прихода edge-тика — поэтому интервал
// backend'a по умолчанию короче (5 с). Между двумя тиками возможен
// stale-payload, но в окне «edge увидит правки через ≤ edgeInterval
// + backendInterval» — для дашборд-UX этого хватает.
//
// Ошибка Load НЕ зануляет Store: fail-stale. Edge продолжит видеть
// последний хороший каталог, оператор видит метрику reload_failures.
package dbloader

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
)

type Reloader struct {
	pool     *pgxpool.Pool
	store    *catalog.Store
	interval time.Duration
	logger   *slog.Logger

	reloadOK   prometheus.Counter
	reloadFail prometheus.Counter
	reloadDur  prometheus.Histogram
	lastReload prometheus.Gauge // unix seconds, для дебага «когда последний раз»
}

func NewReloader(
	pool *pgxpool.Pool,
	store *catalog.Store,
	interval time.Duration,
	logger *slog.Logger,
	reg prometheus.Registerer,
) *Reloader {
	r := &Reloader{
		pool:     pool,
		store:    store,
		interval: interval,
		logger:   logger,
		reloadOK: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_catalog_reload_total",
			Help: "Successful catalog reloads from PostgreSQL.",
		}),
		reloadFail: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_catalog_reload_failures_total",
			Help: "Failed catalog reloads (fail-stale: Store untouched).",
		}),
		reloadDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "antibot_backend_catalog_reload_duration_seconds",
			Help:    "Wall time of a single catalog reload tick.",
			Buckets: prometheus.DefBuckets,
		}),
		lastReload: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "antibot_backend_catalog_last_reload_unixtime",
			Help: "Unix timestamp of the last successful reload (0 if never).",
		}),
	}
	reg.MustRegister(r.reloadOK, r.reloadFail, r.reloadDur, r.lastReload)
	return r
}

// Run блокируется до ctx.Done(). Делает один синхронный Reload до входа
// в цикл, чтобы main мог стартовать с непустым Store — иначе первые
// 0..interval секунд после старта HTTP-сервер отвечал бы 503
// (см. server.handle про IsLoaded). Ошибку первого тика возвращаем
// в main, чтобы backend не поднимался с битой БД молча.
func (r *Reloader) Run(ctx context.Context) {
	if err := r.tick(ctx); err != nil {
		// Первый тик уже сделан в Bootstrap (см. ниже) перед стартом
		// сервера; здесь повторный неуспех — логируем, не выходим.
		// Edge остаётся на последнем хорошем каталоге.
		r.logger.Error("catalog reload failed", "err", err)
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.tick(ctx); err != nil {
				r.logger.Error("catalog reload failed", "err", err)
			}
		}
	}
}

// Bootstrap — синхронный первый Reload до старта HTTP-сервера. Если БД
// пустая или битая, main падает; это сознательно: backend без каталогов
// не должен принимать трафик с эджа.
func (r *Reloader) Bootstrap(ctx context.Context) error {
	return r.tick(ctx)
}

func (r *Reloader) tick(ctx context.Context) error {
	start := time.Now()
	d, err := Load(ctx, r.pool)
	r.reloadDur.Observe(time.Since(start).Seconds())
	if err != nil {
		r.reloadFail.Inc()
		return err
	}
	r.store.Replace(d)
	r.reloadOK.Inc()
	r.lastReload.Set(float64(time.Now().Unix()))
	r.logger.Debug("catalog reloaded",
		"version", d.Version,
		"hosts", len(d.Policy),
		"fp_blocklist", len(d.FPBlocklist),
		"ua_blacklist", len(d.UABlacklist),
		"ip_blocklist", len(d.IPBlocklist),
		"ip_whitelist", len(d.IPWhitelist),
		"asn_datacenters", len(d.ASNDatacenters),
		"verified_bot_ips", len(d.VerifiedBotIPs),
	)
	return nil
}
