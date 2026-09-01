// rDNS worker unit tests. The DNS dependencies and the DB are mocked — the test needs
// neither the network nor Postgres. We cover:
//   - FamilyOfUA (the UA → family classifier).
//   - classify: a correct PTR plus forward → verified; a foreign suffix → rejected;
//     a forward that did not point at the original IP → rejected; NXDOMAIN → rejected.
//   - Enqueue: deduplication through CatalogStore and through in-flight.
//   - GC: it returns 0 with no errors; the counter increments above 0.
package rdns

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type fakeResolver struct {
	addr map[string][]string // ip → PTR list
	host map[string][]string // host → IP list
	err  error
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.addr[addr]
	if !ok {
		return nil, errors.New("nxdomain")
	}
	return v, nil
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.host[host]
	if !ok {
		return nil, errors.New("nxdomain")
	}
	return v, nil
}

type fakeCatalog struct{ has map[string]bool }

func (f *fakeCatalog) HasVerifiedBotIP(ip string) bool { return f.has[ip] }

type fakeDB struct {
	mu      sync.Mutex
	upserts []upsertCall
	deleted int64
	err     error
	deleteN int64
}
type upsertCall struct {
	ip, family, status string
	expiresAt          time.Time
}

func (d *fakeDB) UpsertVerifiedBot(_ context.Context, ip, family, status string, expiresAt time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.upserts = append(d.upserts, upsertCall{ip, family, status, expiresAt})
	return nil
}

func (d *fakeDB) DeleteExpired(_ context.Context) (int64, error) {
	d.deleted++
	return d.deleteN, nil
}

func newTestWorker(t *testing.T, r Resolver, c CatalogStore, db DB) *Worker {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	return New(reg, logger, Config{QueueSize: 16, Workers: 1, DNSTimeout: time.Second, GCInterval: time.Hour}, r, c, db)
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func TestFamilyOfUA(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", FamilyGoogle},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", FamilyBing},
		{"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", FamilyYandex},
		{"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)", FamilyDDG},
		// The case is not normalised outwards — we only check containment.
		{"GOOGLEBOT", FamilyGoogle},
		{"curl/7.81", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := FamilyOfUA(c.ua); got != c.want {
			t.Errorf("FamilyOfUA(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

func TestClassify_VerifiedGooglebot(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		host: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	}
	w := newTestWorker(t, r, &fakeCatalog{}, &fakeDB{})
	status, fam := w.classify(context.Background(), task{ip: "66.249.66.1", claimedFamily: FamilyGoogle})
	if status != "verified" || fam != FamilyGoogle {
		t.Errorf("got status=%s family=%s, want verified/google", status, fam)
	}
}

func TestClassify_RejectsForeignSuffix(t *testing.T) {
	// A PTR in a foreign zone — it must be rejected with no forward lookup.
	r := &fakeResolver{
		addr: map[string][]string{"1.2.3.4": {"impostor.example.org."}},
	}
	w := newTestWorker(t, r, &fakeCatalog{}, &fakeDB{})
	status, fam := w.classify(context.Background(), task{ip: "1.2.3.4", claimedFamily: FamilyGoogle})
	if status != "rejected" || fam != FamilyGoogle {
		t.Errorf("got %s/%s, want rejected/google", status, fam)
	}
}

func TestClassify_RejectsForwardMismatch(t *testing.T) {
	// A PTR in the right zone, but forward DNS did not point at the original IP —
	// the classic PTR forgery. It must be rejected.
	r := &fakeResolver{
		addr: map[string][]string{"1.2.3.4": {"fake.googlebot.com."}},
		host: map[string][]string{"fake.googlebot.com": {"5.6.7.8"}},
	}
	w := newTestWorker(t, r, &fakeCatalog{}, &fakeDB{})
	status, _ := w.classify(context.Background(), task{ip: "1.2.3.4", claimedFamily: FamilyGoogle})
	if status != "rejected" {
		t.Errorf("got %s, want rejected (PTR ok but forward mismatch)", status)
	}
}

func TestClassify_RejectsNXDOMAIN(t *testing.T) {
	r := &fakeResolver{} // empty maps → both lookups return error
	w := newTestWorker(t, r, &fakeCatalog{}, &fakeDB{})
	status, _ := w.classify(context.Background(), task{ip: "1.2.3.4", claimedFamily: FamilyGoogle})
	if status != "rejected" {
		t.Errorf("got %s, want rejected on NXDOMAIN", status)
	}
}

func TestEnqueue_SkipsIfAlreadyInCatalog(t *testing.T) {
	r := &fakeResolver{}
	db := &fakeDB{}
	w := newTestWorker(t, r, &fakeCatalog{has: map[string]bool{"1.2.3.4": true}}, db)
	w.Enqueue("1.2.3.4", FamilyGoogle)
	if len(w.queue) != 0 {
		t.Errorf("queue should be empty when IP is already in catalog, got %d items", len(w.queue))
	}
	if counterValue(t, w.skipped) != 1 {
		t.Errorf("skipped counter expected 1, got %v", counterValue(t, w.skipped))
	}
}

func TestEnqueue_DedupesInFlight(t *testing.T) {
	r := &fakeResolver{}
	w := newTestWorker(t, r, &fakeCatalog{}, &fakeDB{})
	w.Enqueue("1.2.3.4", FamilyGoogle)
	w.Enqueue("1.2.3.4", FamilyGoogle) // a duplicate — it must land in skipped
	if len(w.queue) != 1 {
		t.Errorf("queue len=%d, want 1 (dedup)", len(w.queue))
	}
	if counterValue(t, w.skipped) != 1 {
		t.Errorf("skipped=%v, want 1", counterValue(t, w.skipped))
	}
}

func TestEnqueue_DropsOnFullQueue(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	w := New(reg, logger, Config{QueueSize: 1, Workers: 1, DNSTimeout: time.Second, GCInterval: time.Hour},
		&fakeResolver{}, &fakeCatalog{}, &fakeDB{})
	w.Enqueue("1.1.1.1", FamilyGoogle)
	w.Enqueue("2.2.2.2", FamilyGoogle) // queue full → drop
	if counterValue(t, w.dropped) != 1 {
		t.Errorf("dropped=%v, want 1", counterValue(t, w.dropped))
	}
	// In-flight for a dropped task must be cleared, otherwise the IP is stuck.
	if _, in := w.inFlight.Load("2.2.2.2"); in {
		t.Error("in-flight for dropped IP must be cleared")
	}
}

func TestProcess_UpsertsAndIncrementsMetric(t *testing.T) {
	r := &fakeResolver{
		addr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		host: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	}
	db := &fakeDB{}
	w := newTestWorker(t, r, &fakeCatalog{}, db)
	// We pin the clock — the TTL must land exactly on now+1 h.
	frozen := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return frozen }

	w.process(context.Background(), task{ip: "66.249.66.1", claimedFamily: FamilyGoogle})

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.upserts) != 1 {
		t.Fatalf("got %d upserts, want 1", len(db.upserts))
	}
	u := db.upserts[0]
	if u.status != "verified" || u.family != FamilyGoogle {
		t.Errorf("upsert=%+v, want verified/google", u)
	}
	if !u.expiresAt.Equal(frozen.Add(VerificationTTL)) {
		t.Errorf("expiresAt=%v, want now+%s (%v)", u.expiresAt, VerificationTTL, frozen.Add(VerificationTTL))
	}
	if counterValue(t, w.verified) != 1 {
		t.Errorf("verified counter = %v, want 1", counterValue(t, w.verified))
	}
}

func TestProcess_SkipsPersistOnShutdownInducedReject(t *testing.T) {
	// P1: classify cannot tell an authoritative NXDOMAIN from ctx.Canceled —
	// both turn into "rejected". With the parent ctx cancelled during a
	// shutdown, the worker used to write rejected:family with a 1 h TTL,
	// blocking a legitimate Googlebot for an hour. We check that with a cancelled ctx
	// no upsert happens.
	r := &fakeResolver{} // empty maps → LookupAddr returns error
	db := &fakeDB{}
	w := newTestWorker(t, r, &fakeCatalog{}, db)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately — simulating a shutdown
	w.process(ctx, task{ip: "66.249.66.1", claimedFamily: FamilyGoogle})

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.upserts) != 0 {
		t.Errorf("shutdown-induced rejected was persisted: %+v", db.upserts)
	}
	if counterValue(t, w.skipped) != 1 {
		t.Errorf("skipped counter = %v, want 1", counterValue(t, w.skipped))
	}
}

func TestEnqueue_HoldsInFlightPastWrite(t *testing.T) {
	// P2: after a successful upsert, inFlight must stay occupied
	// for PostWriteHold, to cover the window until the reloader ticks.
	r := &fakeResolver{
		addr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		host: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
	}
	db := &fakeDB{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	w := New(reg, logger,
		Config{
			QueueSize: 16, Workers: 1,
			DNSTimeout: time.Second, GCInterval: time.Hour,
			PostWriteHold: time.Hour, // a long hold — guaranteed not to expire during the test
		},
		r, &fakeCatalog{}, db)

	// We go through the full path Enqueue → consume(ctx) with a single consumer,
	// so that inFlight is genuinely populated before process().
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()

	w.Enqueue("66.249.66.1", FamilyGoogle)

	// We wait for the consumer to write the upsert.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		db.mu.Lock()
		n := len(db.upserts)
		db.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	db.mu.Lock()
	gotUpserts := len(db.upserts)
	db.mu.Unlock()
	if gotUpserts != 1 {
		cancel()
		<-done
		t.Fatalf("expected 1 upsert, got %d", gotUpserts)
	}
	// inFlight must still contain the ip — releaseInFlight is deferred by an hour.
	if _, ok := w.inFlight.Load("66.249.66.1"); !ok {
		cancel()
		<-done
		t.Error("inFlight for the written IP was cleared immediately — the hold is not working")
	}
	// A second Enqueue for the same IP must be skipped (inFlight holds it).
	w.Enqueue("66.249.66.1", FamilyGoogle)
	if counterValue(t, w.skipped) < 1 {
		t.Errorf("second Enqueue not skipped: skipped=%v", counterValue(t, w.skipped))
	}
	cancel()
	<-done
}

func TestRun_ConsumesQueueAndShutsDown(t *testing.T) {
	// End to end through Run: enqueue → consume → upsert → ctx.Done() → stop.
	r := &fakeResolver{
		addr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		host: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
	}
	db := &fakeDB{}
	w := newTestWorker(t, r, &fakeCatalog{}, db)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()

	w.Enqueue("66.249.66.1", FamilyGoogle)

	// Polling up to 2 s — we wait for the consumer to take the task off the queue.
	deadline := time.Now().Add(2 * time.Second)
	gotOne := false
	for time.Now().Before(deadline) {
		db.mu.Lock()
		n := len(db.upserts)
		db.mu.Unlock()
		if n > 0 {
			gotOne = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !gotOne {
		t.Fatalf("worker did not process the task within 2s")
	}
	cancel()
	<-done // the shutdown completed cleanly
}
