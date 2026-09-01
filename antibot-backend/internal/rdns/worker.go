// Package rdns — the antibot-backend reverse-DNS worker ([B7]).
//
// The backend's only active computational task per ADR-005. It is not on the
// edge hot path: at L2.2 (B8) the edge only reads the
// bot_verification_status catalog this worker populates.
//
// The trigger is the log stream: the receiver sees a record with an IP and a search engine UA
// (Googlebot/bingbot/YandexBot/DuckDuckBot) and calls Enqueue. The worker
// checks PTR → forward DNS (both steps must resolve to the search engine's official
// domain) and writes the result into the verified_bot_ips table:
//
//   - verified — both DNS steps agreed, the IP is a real bot, TTL 1 h.
//   - rejected — no PTR / it is not in the official zone / forward DNS
//     did not point back at the original IP; the IP is an impersonator, TTL 1 h symmetric
//     with verified.
//
// The symmetric TTL is a v0.6 vision.md fix (stage 2.2). At 5 min for rejected,
// one impersonator IP got ~288 free provisional passes per
// day between re-checks; 1 h closes that.
//
// Reactive (not a pre-emptive sweep): the worker touches DNS only when the
// receiver has seen a new IP with a search engine UA. Deduplication happens through catalog.Store
// (if the IP is already in the catalog we do not touch DNS again) and an in-flight set
// (if the IP is already queued we do not spawn parallel DNS lookups for the same
// result).
//
// Concurrency: N resolvers read one queue; a queue overflow drops the
// task into a metric and the edge keeps issuing provisional passes (the mildest
// degradation scenario). A GC goroutine periodically deletes
// expired rows.
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

// VerificationTTL — the lifetime of a verified_bot_ips record, symmetric
// for verified and rejected. See vision.md §Stage 2.2 (v0.6).
const VerificationTTL = time.Hour

// dbWriteTimeout — the budget for UpsertVerifiedBot after the parent ctx
// may already have been cancelled (a graceful shutdown). An UPSERT by PK plus an index takes
// milliseconds; 5 s leaves room to survive a busy postgres under load
// without strangling the shutdown if the pgxpool is occupied.
const dbWriteTimeout = 5 * time.Second

// The canonical search engine bot families. The edge tells them apart by the value
// in the catalog ("<status>:<family>"); the keywords are the same four
// as in config-distribution.md §"The 'catalog' concept".
const (
	FamilyGoogle = "google"
	FamilyBing   = "bing"
	FamilyYandex = "yandex"
	FamilyDDG    = "ddg"
)

// ptrSuffixes — the official DNS zones a PTR must resolve into
// for the IP to count as a real bot. The source is each search engine's public
// documentation; we normalise the names without a trailing dot.
//
// google: googlebot.com and google.com are both valid (Googlebot, Google
// Image and Google StoreBot live across both zones).
// bing: search.msn.com is Bingbot's canonical zone.
// yandex: yandex.com / yandex.net / yandex.ru — Yandex publishes
// different suffixes for the crawlers of different regions.
// ddg: duckduckgo.com is DuckDuckBot's only official zone.
var ptrSuffixes = map[string][]string{
	FamilyGoogle: {".googlebot.com", ".google.com"},
	FamilyBing:   {".search.msn.com"},
	FamilyYandex: {".yandex.com", ".yandex.net", ".yandex.ru"},
	FamilyDDG:    {".duckduckgo.com"},
}

// Resolver — the DNS dependencies, injected for tests (in production
// rdns.NetResolver{} wraps net.Resolver). The contract matches
// net.Resolver.LookupAddr/LookupHost — the same names, so that a test
// stub needs no adapter.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// NetResolver — the production resolver on top of net.Resolver. PreferGo=true,
// so that the pure-Go resolver uses the context for cancellation (the cgo resolver
// ignores ctx). That matters: the worker's shutdown must be fast.
//
// One shared *net.Resolver for the whole worker: the methods are thread-safe, and a new
// instance per request is pure load on the allocator. From review.
// gemini review.
type NetResolver struct{}

var sharedResolver = &net.Resolver{PreferGo: true}

func (NetResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return sharedResolver.LookupAddr(ctx, addr)
}

func (NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return sharedResolver.LookupHost(ctx, host)
}

// CatalogStore — the catalog's read side: through this interface the worker checks
// whether a verdict for an IP already exists, so as not to duplicate DNS work. It is implemented by
// catalog.Store through an adapter in app.go.
type CatalogStore interface {
	HasVerifiedBotIP(ip string) bool
}

// DB — the write side: the worker writes the result and periodically deletes
// expired records. Implemented on top of pgxpool.Pool in writer.go.
type DB interface {
	UpsertVerifiedBot(ctx context.Context, ip, family, status string, expiresAt time.Time) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// Config — the worker's settings. The defaults suit a dev stand; in production they
// come through env (see config.Config).
type Config struct {
	// QueueSize — the reactive queue buffer. An overflow means the receiver
	// gets its Enqueue dropped (the dropped_total metric) and the edge keeps
	// issuing provisional passes until the next new log from that IP.
	QueueSize int
	// Workers — the number of parallel DNS resolvers. DNS goes over the network,
	// and we do not want to swamp the upstream resolver — so we keep it modest.
	Workers int
	// DNSTimeout — the ceiling on one IP check iteration. Protection from a
	// hung DNS resolver; a rejected outcome still gives legitimate bots a fastpath
	// on the next tick, and a failed timeout means
	// rejected for 1 h, which is fine: a real Googlebot should never
	// time out, and a slow impersonator can wait it out.
	DNSTimeout time.Duration
	// GCInterval — how often we delete rows with expires_at <= NOW().
	// dbloader.Load already filters expired ones on read; the GC only
	// keeps the table from bloating. An hour is far rarer than the TTL, so there is no load.
	GCInterval time.Duration
	// PostWriteHold — how long we keep an IP in inFlight AFTER a successful
	// upsert. Between "the worker wrote it" and "the reloader
	// put a fresh catalog into the Store" lies CatalogReloadInterval
	// (5 s by default); without the hold, every new log from that same
	// hot IP during that window would see HasVerifiedBotIP=false and spawn repeat
	// DNS/UPSERTs. The default of 0 means immediate release (the old behaviour);
	// app.New passes CatalogReloadInterval + 2 s. A follow-up from review.
	PostWriteHold time.Duration
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

	// inFlight — the IPs already being checked. The receiver checks
	// catalog.HasVerifiedBotIP before enqueuing, but between "it is not
	// in the catalog" and "the worker wrote it into the catalog and the reloader ticked"
	// lies a window of seconds to tens of seconds — without inFlight we would spawn
	// the same DNS lookup hundreds of times for a popular new IP.
	inFlight sync.Map // ip → struct{}

	// The metrics.
	enqueued  prometheus.Counter
	dropped   prometheus.Counter
	skipped   prometheus.Counter // already in the catalog / already in flight
	verified  prometheus.Counter
	rejected  prometheus.Counter
	dnsErr    prometheus.Counter
	dbErr     prometheus.Counter
	gcDeleted prometheus.Counter
	panics    prometheus.Counter
	queueLen  prometheus.GaugeFunc
}

// New assembles the worker. resolver/catalog/db are injected so that tests
// can substitute DNS and the DB without standing up Postgres or a network.
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

// Enqueue — the entry point from the receiver. Non-blocking: on a queue
// overflow it drops plus a metric; the edge keeps letting that IP through
// provisionally, and we try again on its next log line.
//
// The parameters:
//   - ip — the client IP as a string (what the edge sees as
//     remote_addr; the same thing net.Resolver.LookupAddr accepts).
//   - claimedFamily — what the client called itself in its UA (see FamilyOfUA). That is the
//     key for choosing the official DNS zone: if the PTR went to a different
//     zone than the UA claimed, we write rejected with claimedFamily —
//     useful in analytics ("the IP claimed to be Googlebot, but its PTR points into
//     .yandex.com»).
func (w *Worker) Enqueue(ip, claimedFamily string) {
	if ip == "" || claimedFamily == "" {
		return
	}
	if w.catalog != nil && w.catalog.HasVerifiedBotIP(ip) {
		w.skipped.Inc()
		return
	}
	// LoadOrStore — an atomic "store if absent". If it is already in flight,
	// we get loaded=true and drop the task. Without that, a popular new
	// Googlebot IP would produce N parallel DNS lookups for one and the
	// same result, and we would write them all into the DB in turn.
	if _, loaded := w.inFlight.LoadOrStore(ip, struct{}{}); loaded {
		w.skipped.Inc()
		return
	}
	select {
	case w.queue <- task{ip: ip, claimedFamily: claimedFamily}:
		w.enqueued.Inc()
	default:
		// The queue is full — we clear in-flight and drop the task. Without clearing it,
		// that IP would be blocked forever (LoadOrStore would return loaded
		// on every later Enqueue and the queue would never receive the task).
		w.inFlight.Delete(ip)
		w.dropped.Inc()
	}
}

// Run blocks until ctx.Done(). It starts N consumer goroutines and one
// GC goroutine. All of them terminate cleanly on ctx.
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
	// Clearing inFlight is deferred to process(): a successful upsert sets an
	// AfterFunc(PostWriteHold), while every other path (skipped, dbErr, panic)
	// clears it immediately — otherwise the IP would stay stuck until the GC.
	defer func() {
		if rec := recover(); rec != nil {
			w.panics.Inc()
			w.logger.Error("rdns process panic — recovered",
				"ip", t.ip,
				"family", t.claimedFamily,
				"panic", rec,
				"stack", string(debug.Stack()),
			)
			w.inFlight.Delete(t.ip)
		}
	}()
	w.process(ctx, t)
}

// releaseInFlight clears t.ip from inFlight: immediately when hold==0
// (the deprecated/test path), or through a PostWriteHold time.AfterFunc —
// which has to cover the window "the worker wrote it, but the reloader has not yet put a
// fresh Data into the Store", otherwise the next log from that same hot IP again
// sees HasVerifiedBotIP=false and spawns a repeat DNS/UPSERT.
// PR #53 follow-up.
func (w *Worker) releaseInFlight(ip string) {
	if w.cfg.PostWriteHold <= 0 {
		w.inFlight.Delete(ip)
		return
	}
	time.AfterFunc(w.cfg.PostWriteHold, func() {
		w.inFlight.Delete(ip)
	})
}

func (w *Worker) process(ctx context.Context, t task) {
	// Sanitize: net.Resolver.LookupAddr expects a clean IP literal. If
	// the log carried "1.2.3.4:54321", "[::1]:443" or anything else with
	// emitter artefacts, the lookup fails and a legitimate bot IP
	// would get rejected:family for an hour (HasVerifiedBotIP would block
	// the re-check). Better to drop the task quietly with a metric —
	// the next log event from that IP will try again. From review.
	if net.ParseIP(t.ip) == nil {
		w.skipped.Inc()
		w.logger.Debug("rdns: skip task with unparseable ip",
			"ip", t.ip, "family", t.claimedFamily)
		w.inFlight.Delete(t.ip)
		return
	}

	// A per-task deadline. On hung DNS the worker would eat a consumer slot
	// until the parent shutdown — which would kill throughput for
	// normal tasks after the first hung IP.
	taskCtx, cancel := context.WithTimeout(ctx, w.cfg.DNSTimeout)
	defer cancel()

	status, family := w.classify(taskCtx, t)

	// A shutdown-induced rejected is NOT persisted. classify cannot tell an
	// authoritative NXDOMAIN from ctx.Canceled; both turn into rejected.
	// Without this check, an in-flight Googlebot/Bingbot whose parent
	// ctx was cancelled during DNS would be written as rejected:google with a TTL of
	// 1 h; HasVerifiedBotIP would block the re-check; and a legitimate bot would lose
	// its fastpath for an hour after every deploy. A verified verdict is left
	// alone — it was obtained BEFORE ctx.Err() and is valid. A follow-up from review.
	if status == "rejected" && ctx.Err() != nil {
		w.skipped.Inc()
		w.logger.Debug("rdns: skip persist of shutdown-induced rejected",
			"ip", t.ip, "family", t.claimedFamily, "ctx_err", ctx.Err())
		w.inFlight.Delete(t.ip)
		return
	}
	expiresAt := w.now().Add(VerificationTTL)

	// The DB write: the parent ctx is already cancelled during a graceful shutdown
	// (app.shutdown calls cancelWorkers() BEFORE wg.Wait). Using
	// that ctx would make UpsertVerifiedBot return context.Canceled for every
	// task that made it through classify before the cancel, spiking dbErr on
	// every deploy. We detach the cancellation through context.WithoutCancel and
	// set a short deadline of our own — the same trick as in
	// dbloader.Migrate for pg_advisory_unlock. From review.
	writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), dbWriteTimeout)
	defer writeCancel()
	if err := w.db.UpsertVerifiedBot(writeCtx, t.ip, family, status, expiresAt); err != nil {
		w.dbErr.Inc()
		w.logger.Error("rdns: db upsert failed",
			"ip", t.ip, "family", family, "status", status, "err", err)
		// Clear inFlight immediately — with no DB write, the next log must
		// be able to retry.
		w.inFlight.Delete(t.ip)
		return
	}
	switch status {
	case "verified":
		w.verified.Inc()
	case "rejected":
		w.rejected.Inc()
	}
	// Hold inFlight for PostWriteHold (≈ CatalogReloadInterval + a buffer):
	// until the reloader puts a fresh Data into the Store, a hot IP would see
	// HasVerifiedBotIP=false and spawn repeat DNS/UPSERTs.
	w.releaseInFlight(t.ip)
	w.logger.Debug("rdns verdict",
		"ip", t.ip, "claim", t.claimedFamily,
		"family", family, "status", status,
	)
}

// classify — the core of the decision. It returns status ∈ {verified, rejected} and
// the family (for verified the genuinely confirmed one; for rejected the
// claimedFamily, so that analytics can see what it claimed to be).
//
// The logic:
//  1. A PTR on the IP. Empty or an error → rejected.
//  2. At least one PTR must end with an official suffix of the
//     claimed family (claimedFamily). If the PTR went into a foreign zone,
//     this is not the bot the UA claims → rejected.
//  3. Forward DNS on the name found. The original IP must be among the A/AAAA
//     records. If not, that is a DNS mismatch (a PTR can be forged without a forward record)
//     → rejected.
//  4. Otherwise — verified.
func (w *Worker) classify(ctx context.Context, t task) (status, family string) {
	suffixes, ok := ptrSuffixes[t.claimedFamily]
	if !ok {
		// An unknown family — the receiver should never let this through; a guard.
		return "rejected", t.claimedFamily
	}
	// dnsErr — a per-task flag, incremented at most once. Before
	// review we incremented it on every failed LookupAddr/LookupHost,
	// so a task with 3 PTRs plus 3 LookupHost failures gave dnsErr=4 — breaking
	// the rate metrics (dnsErr/enqueued > 100%).
	dnsTrouble := false
	ptrs, err := w.resolver.LookupAddr(ctx, t.ip)
	if err != nil || len(ptrs) == 0 {
		w.dnsErr.Inc()
		return "rejected", t.claimedFamily
	}
	// net.IP.Equal compares the bytes of the normalised IP — which is critical for IPv6:
	// "2001:db8::1" and "2001:0db8:0000:0000:0000:0000:0000:0001" are
	// the same address but different strings. LookupHost can return
	// either form. We parse the target once outside the loop. From review.
	targetIP := net.ParseIP(t.ip)
	for _, ptr := range ptrs {
		name := normalizePTR(ptr)
		if !matchesAnySuffix(name, suffixes) {
			continue
		}
		hosts, err := w.resolver.LookupHost(ctx, name)
		if err != nil {
			dnsTrouble = true
			continue
		}
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil && targetIP != nil && ip.Equal(targetIP) {
				return "verified", t.claimedFamily
			}
		}
	}
	if dnsTrouble {
		w.dnsErr.Inc()
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
		// Not critical: dbloader.Load filters expires_at > NOW() anyway, so
		// the edge never sees expired records. We log it for the operator.
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

// FamilyOfUA — the canonical family claimed in the UA. It returns "" if
// the UA contains none of the known search-bot markers. The comparison is
// case-insensitive: a real Googlebot writes "Googlebot/2.1", but an
// impersonator may deliberately break the case.
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

// normalizePTR — strips the trailing dot and lowercases. LookupAddr
// returns an FQDN with a dot ("crawl-66-249-66-1.googlebot.com.");
// comparing against the suffixes and re-running LookupHost needs it without.
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

// String — a short diagnostic of the worker for the health endpoint (B14).
func (w *Worker) String() string {
	return fmt.Sprintf("rdns(queue=%d/%d, workers=%d)",
		len(w.queue), w.cfg.QueueSize, w.cfg.Workers)
}
