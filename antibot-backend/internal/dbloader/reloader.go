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
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tabularasa31/antibot-backend/internal/catalog"
)

// bootstrapTimeout — отдельный (более щедрый) бюджет на первый
// синхронный Reload в Bootstrap. Cold pool делает TCP + TLS handshake +
// pgxpool session-setup + восемь SELECT'ов, на slow link / cold cache
// это легко уходит за r.interval (типично 5 с). На периодический тик
// per-tick deadline = r.interval (см. tickContext) остается — чтобы
// зависший Postgres не замораживал Run-горутину. PR #43 follow-up.
const bootstrapTimeout = 60 * time.Second

type Reloader struct {
	pool     *pgxpool.Pool
	store    *catalog.Store
	interval time.Duration
	logger   *slog.Logger

	reloadOK   prometheus.Counter
	reloadFail prometheus.Counter
	// reloadDur — labelled `outcome={success,failure}`, чтобы p99 в дашбордах
	// не смешивал хорошие тики с теми, где Load висел до per-tick deadline
	// (см. tick про context.WithTimeout). PR #43 review (Angle A).
	reloadDur  *prometheus.HistogramVec
	lastReload prometheus.Gauge // unix seconds, для дебага «когда последний раз»
}

func NewReloader(
	pool *pgxpool.Pool,
	store *catalog.Store,
	interval time.Duration,
	logger *slog.Logger,
	reg prometheus.Registerer,
) (*Reloader, error) {
	if interval <= 0 {
		// Defense-in-depth: config-слой уже валидирует, но альтернативные
		// callers (тесты, future hot-reload code) могут промахнуться.
		// `time.NewTicker(0)` паникует, `context.WithTimeout(ctx, 0)` сразу
		// expired — обе ветки дают мусорные сообщения. Лучше явный refuse.
		return nil, fmt.Errorf("dbloader: reload interval must be > 0, got %s", interval)
	}
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
		reloadDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "antibot_backend_catalog_reload_duration_seconds",
			Help:    "Wall time of a single catalog reload tick, labelled by outcome.",
			Buckets: prometheus.DefBuckets,
		}, []string{"outcome"}),
		lastReload: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "antibot_backend_catalog_last_reload_unixtime",
			Help: "Unix timestamp of the last successful reload (0 if never).",
		}),
	}
	reg.MustRegister(r.reloadOK, r.reloadFail, r.reloadDur, r.lastReload)
	return r, nil
}

// Run блокируется до ctx.Done(), периодически перегружая каталоги с
// интервалом r.interval. Первый тик НЕ делаем — он уже сделан в Bootstrap
// синхронно до старта HTTP-сервера; повторять его сразу значит ходить
// в БД дважды на старте без надобности.
//
// Ошибка тика: log + продолжаем (fail-stale). Edge остаётся на последнем
// хорошем каталоге, оператор видит её через `_failures_total`.
func (r *Reloader) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Per-tick deadline = r.interval применяем ТОЛЬКО на горячем
			// пути Run: без него зависший pgx (half-open TCP / NAT-таймаут)
			// заблокировал бы горутину, ticker'ы коалесцировались, и
			// reloadFail не инкрементировался бы — оператору ни сигнала.
			if err := r.tickWith(ctx, r.interval); err != nil {
				r.logger.Error("catalog reload failed", "err", err)
			}
		}
	}
}

// Bootstrap — синхронный первый Reload до старта HTTP-сервера. Если БД
// пустая или битая, main падает; это сознательно: backend без каталогов
// не должен принимать трафик с эджа.
//
// Бюджет — bootstrapTimeout (60 с), а НЕ r.interval: cold pool +
// первый Acquire с TCP/TLS handshake + восемь SELECT'ов на холодном
// buffer cache легко уходят за периодический 5-секундный тик. Поделить
// этот budget с горячим путём — значит крашить backend на старте на
// медленном link'е. PR #43 review (Angle A follow-up).
func (r *Reloader) Bootstrap(ctx context.Context) error {
	return r.tickWith(ctx, bootstrapTimeout)
}

func (r *Reloader) tickWith(ctx context.Context, timeout time.Duration) error {
	tickCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	d, err := Load(tickCtx, r.pool)
	dur := time.Since(start).Seconds()
	if err != nil {
		r.reloadDur.WithLabelValues("failure").Observe(dur)
		r.reloadFail.Inc()
		return err
	}
	r.reloadDur.WithLabelValues("success").Observe(dur)
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
