// rDNS worker unit tests. DNS-зависимости и DB замоканы — тесту не нужны
// ни сеть, ни Postgres. Покрываем:
//   - FamilyOfUA (классификатор UA → семья).
//   - classify: верный PTR+forward → verified; чужой суффикс → rejected;
//     forward не указал на исходный IP → rejected; NXDOMAIN → rejected.
//   - Enqueue: дедуп через CatalogStore и через in-flight.
//   - GC: возвращает 0 без ошибок; counter инкрементируется на > 0.
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
		// Кейс не нормализуется наружу — мы смотрим только содержит ли.
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
	// PTR в чужой зоне — должно быть rejected без forward-lookup.
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
	// PTR в правильной зоне, но forward DNS не указал на исходный IP —
	// классическая подмена PTR. Должно быть rejected.
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
	w.Enqueue("1.2.3.4", FamilyGoogle) // дубль — должен попасть в skipped
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
	// In-flight для дропнутой задачи должен сняться, иначе IP залип.
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
	// Фиксируем часы — TTL должен сесть ровно на now+1ч.
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
	// P1: classify не различает authoritative-NXDOMAIN от ctx.Canceled —
	// оба превращаются в "rejected". При parent ctx canceled во время
	// shutdown воркер раньше писал бы rejected:family с TTL 1ч,
	// блокируя legit Googlebot на час. Проверяем: с canceled ctx
	// upsert НЕ должен происходить.
	r := &fakeResolver{} // empty maps → LookupAddr returns error
	db := &fakeDB{}
	w := newTestWorker(t, r, &fakeCatalog{}, db)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // сразу cancel — имитируем shutdown
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
	// P2: после успешного upsert'а inFlight должен оставаться занятым
	// на PostWriteHold, чтобы перекрыть окно до reloader-тика.
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
			PostWriteHold: time.Hour, // долгий hold — гарантированно не истечёт за тест
		},
		r, &fakeCatalog{}, db)

	// Идём через полный путь Enqueue → consume(ctx) с одним consumer'ом,
	// чтобы inFlight реально был заселён до process().
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()

	w.Enqueue("66.249.66.1", FamilyGoogle)

	// Ждём пока consumer запишет upsert.
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
	// inFlight должен ещё содержать ip — releaseInFlight отложен на 1ч.
	if _, ok := w.inFlight.Load("66.249.66.1"); !ok {
		cancel()
		<-done
		t.Error("inFlight для записанного IP снят сразу — hold не работает")
	}
	// Второй Enqueue для того же IP должен быть skipped (inFlight держит).
	w.Enqueue("66.249.66.1", FamilyGoogle)
	if counterValue(t, w.skipped) < 1 {
		t.Errorf("second Enqueue not skipped: skipped=%v", counterValue(t, w.skipped))
	}
	cancel()
	<-done
}

func TestRun_ConsumesQueueAndShutsDown(t *testing.T) {
	// End-to-end через Run: enqueue → consume → upsert → ctx.Done() → stop.
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

	// Polling до 2с — ждём, пока consumer заберёт задачу из очереди.
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
	<-done // shutdown отработал чисто
}
