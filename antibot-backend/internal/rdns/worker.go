// Package rdns — reverse-DNS воркер antibot-backend ([B7]).
//
// Единственная активная вычислительная задача backend по ADR-005. Не на
// hot-path edge'а: edge на L2.2 (B8) только читает каталог
// bot_verification_status, наполненный этим воркером.
//
// Триггер — поток логов: receiver видит запись с IP и поисковым UA
// (Googlebot/bingbot/YandexBot/DuckDuckBot) и зовёт Enqueue. Воркер
// проверяет PTR → forward DNS (оба шага должны сойтись на официальный
// домен поисковика) и пишет результат в таблицу verified_bot_ips:
//
//   - verified — оба DNS-этапа сошлись, IP — реальный бот, TTL 1ч.
//   - rejected — PTR не вернулся / не из официальной зоны / forward DNS
//     не указал на исходный IP, IP — impersonator, TTL 1ч симметрично
//     с verified.
//
// Симметричный TTL — фикс v0.6 vision.md (Шаг 2.2). При 5м для rejected
// один impersonator-IP получал ~288 бесплатных provisional-проходов в
// сутки между ре-проверками; 1ч это закрывает.
//
// Reactive (не превентивный перебор): воркер ходит в DNS только когда
// receiver увидел новый IP с поисковым UA. Дедуп — через catalog.Store
// (если IP уже в каталоге — не дёргаем DNS повторно) и in-flight set
// (если IP уже в очереди — не плодим параллельные DNS-запросы за тот же
// результат).
//
// Concurrency: N резолверов читают одну очередь; queue-overflow роняет
// задачу в метрику, edge продолжит выдавать provisional (это самый
// мягкий деградационный сценарий). GC-горутина периодически удаляет
// протухшие строки.
package rdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// VerificationTTL — время жизни записи verified_bot_ips, симметрично
// для verified и rejected. См. vision.md §Шаг 2.2 (v0.6).
const VerificationTTL = time.Hour

// Канонические семейства поисковых ботов. Edge различает их по значению
// в каталоге ("<status>:<family>"); ключевые слова — те же четыре,
// что в config-distribution.md §"The 'catalog' concept".
const (
	FamilyGoogle = "google"
	FamilyBing   = "bing"
	FamilyYandex = "yandex"
	FamilyDDG    = "ddg"
)

// ptrSuffixes — официальные DNS-зоны, на которые должен сойтись PTR
// чтобы IP считался реальным ботом. Источник — публичные documentation
// каждого поисковика; имена нормализуем без trailing dot.
//
// google: googlebot.com и google.com — оба валидны (Googlebot, Google
// Image, Google StoreBot живут в смеси этих зон).
// bing: search.msn.com — каноничная зона Bingbot.
// yandex: yandex.com / yandex.net / yandex.ru — Yandex'ы публикуют
// разные суффиксы для разных регионов crawler'ов.
// ddg: duckduckgo.com — единственная официальная зона DuckDuckBot.
var ptrSuffixes = map[string][]string{
	FamilyGoogle: {".googlebot.com", ".google.com"},
	FamilyBing:   {".search.msn.com"},
	FamilyYandex: {".yandex.com", ".yandex.net", ".yandex.ru"},
	FamilyDDG:    {".duckduckgo.com"},
}

// Resolver — DNS-зависимости, заинжекчены для тестов (production:
// rdns.NetResolver{} оборачивает net.Resolver). Контракт совпадает с
// net.Resolver.LookupAddr/LookupHost — те же имена, чтобы тестовая
// заглушка не требовала адаптера.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// NetResolver — production-резолвер на base net.Resolver. PreferGo=true,
// чтобы pure-Go резолвер использовал контекст для отмены (cgo-резолвер
// игнорирует ctx). Это критично: shutdown воркера должен быть быстрым.
//
// Один общий *net.Resolver на весь воркер: методы thread-safe, новый
// инстанс на каждый запрос — пустая нагрузка на аллокатор. PR #53
// gemini review.
type NetResolver struct{}

var sharedResolver = &net.Resolver{PreferGo: true}

func (NetResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return sharedResolver.LookupAddr(ctx, addr)
}

func (NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return sharedResolver.LookupHost(ctx, host)
}

// CatalogStore — read-side каталога: воркер по этому интерфейсу проверяет,
// есть ли уже verdict для IP, чтобы не дублировать DNS-работу. Реализуется
// catalog.Store через адаптер в app.go.
type CatalogStore interface {
	HasVerifiedBotIP(ip string) bool
}

// DB — write-side: воркер пишет результат и периодически удаляет
// протухшие записи. Реализуется поверх pgxpool.Pool в writer.go.
type DB interface {
	UpsertVerifiedBot(ctx context.Context, ip, family, status string, expiresAt time.Time) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// Config — настройки воркера. Дефолты под dev-стенд; в продакшен
// прокидываются через env (см. config.Config).
type Config struct {
	// QueueSize — буфер reactive-очереди. Переполнение = receiver
	// получает Enqueue в дроп (метрика dropped_total), edge продолжит
	// выдавать provisional до следующего нового лога с этим IP.
	QueueSize int
	// Workers — параллельных DNS-резолверов. DNS ходит по сети,
	// но мы не хотим завалить апстрим-резолвер — держим скромно.
	Workers int
	// DNSTimeout — потолок на одну итерацию проверки IP. Защита от
	// зависшего DNS-резолвера; rejected-исход всё равно даст fastpath
	// для legit-ботов на следующий тик, провальный таймаут — это
	// rejected на 1ч, что аккуратно: реальный Googlebot никогда не
	// должен таймаутить, а медленный impersonator пусть рассасывается.
	DNSTimeout time.Duration
	// GCInterval — как часто удаляем строки с expires_at <= NOW().
	// dbloader.Load уже фильтрует протухшие на чтении, GC только
	// чтобы таблица не пухла; час — сильно реже чем TTL, нагрузки нет.
	GCInterval time.Duration
}

func DefaultConfig() Config {
	return Config{
		QueueSize:  1024,
		Workers:    4,
		DNSTimeout: 5 * time.Second,
		GCInterval: time.Hour,
	}
}

type task struct {
	ip            string
	claimedFamily string
}

type Worker struct {
	cfg      Config
	resolver Resolver
	catalog  CatalogStore
	db       DB
	logger   *slog.Logger
	now      func() time.Time

	queue chan task

	// inFlight — IP, для которых уже идёт проверка. Receiver проверяет
	// catalog.HasVerifiedBotIP перед enqueue, но между моментом «нет
	// в каталоге» и моментом «воркер дописал в каталог + reloader тикнул»
	// есть окно секунд-десятков-секунд — без inFlight мы плодили бы
	// один и тот же DNS-lookup сотни раз для популярного нового IP.
	inFlight sync.Map // ip → struct{}

	// Метрики.
	enqueued  prometheus.Counter
	dropped   prometheus.Counter
	skipped   prometheus.Counter // уже в каталоге / уже in-flight
	verified  prometheus.Counter
	rejected  prometheus.Counter
	dnsErr    prometheus.Counter
	dbErr     prometheus.Counter
	gcDeleted prometheus.Counter
	panics    prometheus.Counter
	queueLen  prometheus.GaugeFunc
}

// New собирает воркера. resolver/catalog/db инжектятся, чтобы тесты
// могли подменить DNS и DB без поднятия Postgres/сети.
func New(
	reg prometheus.Registerer,
	logger *slog.Logger,
	cfg Config,
	resolver Resolver,
	catalog CatalogStore,
	db DB,
) *Worker {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultConfig().QueueSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultConfig().Workers
	}
	if cfg.DNSTimeout <= 0 {
		cfg.DNSTimeout = DefaultConfig().DNSTimeout
	}
	if cfg.GCInterval <= 0 {
		cfg.GCInterval = DefaultConfig().GCInterval
	}
	w := &Worker{
		cfg:      cfg,
		resolver: resolver,
		catalog:  catalog,
		db:       db,
		logger:   logger,
		now:      time.Now,
		queue:    make(chan task, cfg.QueueSize),
	}
	w.enqueued = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_enqueued_total",
		Help: "rDNS: tasks accepted into the queue (post catalog/in-flight dedup).",
	})
	w.dropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_dropped_total",
		Help: "rDNS: tasks dropped because the queue was full (edge falls back to provisional).",
	})
	w.skipped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_skipped_total",
		Help: "rDNS: enqueue requests skipped — ip already in catalog or already in flight.",
	})
	w.verified = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_verified_total",
		Help: "rDNS: IPs published as verified (PTR+forward DNS converged on official zone).",
	})
	w.rejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_rejected_total",
		Help: "rDNS: IPs published as rejected (PTR/forward mismatch, NXDOMAIN, SERVFAIL, timeout).",
	})
	w.dnsErr = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_dns_errors_total",
		Help: "rDNS: DNS-level errors (timeout/SERVFAIL/NXDOMAIN — see logs for breakdown). NXDOMAIN is normal for impostors and still counts here.",
	})
	w.dbErr = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_db_errors_total",
		Help: "rDNS: DB upsert failures (verdict computed but not persisted; alert on > 0).",
	})
	w.gcDeleted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_gc_deleted_total",
		Help: "rDNS: expired verified_bot_ips rows deleted by the GC tick.",
	})
	w.panics = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_rdns_panics_total",
		Help: "rDNS: worker iterations that panicked and were recovered (alert on > 0).",
	})
	w.queueLen = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "antibot_backend_rdns_queue_length",
		Help: "rDNS: current pending tasks in the reactive queue.",
	}, func() float64 { return float64(len(w.queue)) })
	reg.MustRegister(
		w.enqueued, w.dropped, w.skipped, w.verified, w.rejected,
		w.dnsErr, w.dbErr, w.gcDeleted, w.panics, w.queueLen,
	)
	return w
}

// Enqueue — точка входа из receiver'а. Non-blocking: при переполнении
// очереди дроп + метрика; edge продолжит провизионально пропускать
// этот IP, на следующем логе с него попробуем снова.
//
// Параметры:
//   - ip — клиентский IP в строковом виде (то, что edge видит как
//     remote_addr; то же, что net.Resolver.LookupAddr принимает).
//   - claimedFamily — что клиент назвал в UA (см. FamilyOfUA). Это
//     ключ для выбора официальной DNS-зоны: если PTR ушёл не в ту
//     зону, что заявлена в UA, мы пишем rejected с claimedFamily —
//     полезно в аналитике («IP представлялся Googlebot, но PTR в
//     .yandex.com»).
func (w *Worker) Enqueue(ip, claimedFamily string) {
	if ip == "" || claimedFamily == "" {
		return
	}
	if w.catalog != nil && w.catalog.HasVerifiedBotIP(ip) {
		w.skipped.Inc()
		return
	}
	// LoadOrStore — атомарный «положи если нет». Если уже in-flight —
	// получили loaded=true, дроп задачи. Без этого популярный новый
	// Googlebot-IP дал бы N параллельных DNS-запросов за один и тот
	// же результат, мы бы их все писали поочерёдно в DB.
	if _, loaded := w.inFlight.LoadOrStore(ip, struct{}{}); loaded {
		w.skipped.Inc()
		return
	}
	select {
	case w.queue <- task{ip: ip, claimedFamily: claimedFamily}:
		w.enqueued.Inc()
	default:
		// Очередь переполнена — снимаем in-flight, дроп задачи. Без снятия
		// этот IP заблокировался бы навсегда (LoadOrStore вернёт loaded
		// на каждом следующем Enqueue, очередь так и не получит задачу).
		w.inFlight.Delete(ip)
		w.dropped.Inc()
	}
}

// Run блокирует до ctx.Done(). Запускает N consumer-горутин и одну
// GC-горутину. Все они корректно завершаются по ctx.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("rdns worker started",
		"workers", w.cfg.Workers,
		"queue", w.cfg.QueueSize,
		"dns_timeout", w.cfg.DNSTimeout,
		"gc_interval", w.cfg.GCInterval,
	)
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.consume(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runGC(ctx)
	}()
	wg.Wait()
	w.logger.Info("rdns worker stopped")
}

func (w *Worker) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-w.queue:
			w.processSafely(ctx, t)
		}
	}
}

func (w *Worker) processSafely(ctx context.Context, t task) {
	defer w.inFlight.Delete(t.ip)
	defer func() {
		if rec := recover(); rec != nil {
			w.panics.Inc()
			w.logger.Error("rdns process panic — recovered",
				"ip", t.ip,
				"family", t.claimedFamily,
				"panic", rec,
				"stack", string(debug.Stack()),
			)
		}
	}()
	w.process(ctx, t)
}

func (w *Worker) process(ctx context.Context, t task) {
	// Per-task deadline. На зависшем DNS воркер бы съел consumer-слот
	// до родительского shutdown'a — это убивало бы throughput для
	// нормальных задач после первого зависшего IP.
	taskCtx, cancel := context.WithTimeout(ctx, w.cfg.DNSTimeout)
	defer cancel()

	status, family := w.classify(taskCtx, t)
	expiresAt := w.now().Add(VerificationTTL)

	// Используем родительский ctx для DB-write: задаче DNS-таймаут
	// мог истечь, но писать результат всё равно надо (writes быстрые,
	// держим запас на shutdown).
	if err := w.db.UpsertVerifiedBot(ctx, t.ip, family, status, expiresAt); err != nil {
		w.dbErr.Inc()
		w.logger.Error("rdns: db upsert failed",
			"ip", t.ip, "family", family, "status", status, "err", err)
		return
	}
	switch status {
	case "verified":
		w.verified.Inc()
	case "rejected":
		w.rejected.Inc()
	}
	w.logger.Debug("rdns verdict",
		"ip", t.ip, "claim", t.claimedFamily,
		"family", family, "status", status,
	)
}

// classify — ядро решения. Возвращает status ∈ {verified, rejected} и
// family (для verified — реально подтверждённое; для rejected —
// claimedFamily, чтобы аналитика видела «что представлялся»).
//
// Логика:
//  1. PTR на IP. Пусто/ошибка → rejected.
//  2. Хотя бы один PTR должен оканчиваться на официальный суффикс
//     заявленной семьи (claimedFamily). Если PTR ушёл в чужую зону —
//     это уже не тот бот, что в UA → rejected.
//  3. forward DNS на найденное имя. Среди A/AAAA должен быть исходный
//     IP. Если нет — DNS-mismatch (PTR можно подделать без forward'а)
//     → rejected.
//  4. Иначе — verified.
func (w *Worker) classify(ctx context.Context, t task) (status, family string) {
	suffixes, ok := ptrSuffixes[t.claimedFamily]
	if !ok {
		// Незнакомая family — receiver не должен такое пропускать; защита.
		return "rejected", t.claimedFamily
	}
	ptrs, err := w.resolver.LookupAddr(ctx, t.ip)
	if err != nil || len(ptrs) == 0 {
		w.dnsErr.Inc()
		return "rejected", t.claimedFamily
	}
	// net.IP.Equal сравнивает по байтам нормализованного IP — для IPv6
	// это критично: "2001:db8::1" и "2001:0db8:0000:0000:0000:0000:0000:0001"
	// один и тот же адрес, но разные строки. LookupHost может вернуть
	// любую форму. Парсим target один раз вне цикла. PR #53 gemini review.
	targetIP := net.ParseIP(t.ip)
	for _, ptr := range ptrs {
		name := normalizePTR(ptr)
		if !matchesAnySuffix(name, suffixes) {
			continue
		}
		hosts, err := w.resolver.LookupHost(ctx, name)
		if err != nil {
			w.dnsErr.Inc()
			continue
		}
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil && targetIP != nil && ip.Equal(targetIP) {
				return "verified", t.claimedFamily
			}
		}
	}
	return "rejected", t.claimedFamily
}

func (w *Worker) runGC(ctx context.Context) {
	t := time.NewTicker(w.cfg.GCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.gcOnce(ctx)
		}
	}
}

func (w *Worker) gcOnce(ctx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			w.panics.Inc()
			w.logger.Error("rdns gc panic — recovered",
				"panic", rec, "stack", string(debug.Stack()))
		}
	}()
	n, err := w.db.DeleteExpired(ctx)
	if err != nil {
		// Не критично: dbloader.Load всё равно фильтрует expires_at > NOW(),
		// edge не увидит протухшие записи. Логируем для оператора.
		if !errors.Is(err, context.Canceled) {
			w.logger.Warn("rdns: gc delete-expired failed", "err", err)
		}
		return
	}
	if n > 0 {
		w.gcDeleted.Add(float64(n))
		w.logger.Debug("rdns: gc deleted expired rows", "n", n)
	}
}

// FamilyOfUA — каноничное семейство, заявленное в UA. Возвращает "" если
// UA не содержит ни одного из известных search-bot-маркеров. Сравнение
// case-insensitive: реальный Googlebot пишет "Googlebot/2.1", но
// impersonator может намеренно ломать кейс.
func FamilyOfUA(ua string) string {
	if ua == "" {
		return ""
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "googlebot"):
		return FamilyGoogle
	case strings.Contains(lower, "bingbot"):
		return FamilyBing
	case strings.Contains(lower, "yandexbot"):
		return FamilyYandex
	case strings.Contains(lower, "duckduckbot"):
		return FamilyDDG
	}
	return ""
}

// normalizePTR — убирает trailing dot и приводит к нижнему регистру.
// LookupAddr возвращает FQDN с точкой ("crawl-66-249-66-1.googlebot.com.");
// для сравнения с суффиксами и для повторного LookupHost нужно без неё.
func normalizePTR(s string) string {
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

func matchesAnySuffix(name string, suffixes []string) bool {
	for _, sfx := range suffixes {
		if strings.HasSuffix(name, sfx) {
			return true
		}
	}
	return false
}

// String — короткая диагностика воркера для health-endpoint'a (B14).
func (w *Worker) String() string {
	return fmt.Sprintf("rdns(queue=%d/%d, workers=%d)",
		len(w.queue), w.cfg.QueueSize, w.cfg.Workers)
}
