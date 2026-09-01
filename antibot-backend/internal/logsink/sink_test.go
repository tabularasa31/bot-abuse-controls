package logsink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// fakeWriter — a controllable error through an atomic. It stores the inserted batches
// for checking.
type fakeWriter struct {
	mu      sync.Mutex
	batches [][][]any
	failN   atomic.Int32 // how many of the next Inserts return an error
}

func (f *fakeWriter) Insert(_ context.Context, rows [][]any) error {
	if f.failN.Load() > 0 {
		f.failN.Add(-1)
		return errors.New("fake writer: down")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([][]any, len(rows))
	for i, r := range rows {
		c := make([]any, len(r))
		copy(c, r)
		cp[i] = c
	}
	f.batches = append(f.batches, cp)
	return nil
}

func (f *fakeWriter) totalRows() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func newTestSink(t *testing.T, cfg Config) (*Sink, *fakeWriter) {
	t.Helper()
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 2
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 50 * time.Millisecond
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 16
	}
	if cfg.DrainInterval == 0 {
		cfg.DrainInterval = 30 * time.Millisecond
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &fakeWriter{}
	reg := prometheus.NewRegistry()
	s, err := NewWithWriter(cfg, w, logger, reg)
	if err != nil {
		t.Fatal(err)
	}
	return s, w
}

func goodLine(t *testing.T, reqID string) []byte {
	t.Helper()
	rec := map[string]any{
		"request_id":    reqID,
		"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
		"edge_id":       "stand-test",
		"host":          "example.com",
		"path":          "/x",
		"method":        "GET",
		"status":        200,
		"ip":            "1.2.3.4",
		"ua":            "curl/8",
		"stage":         "egress",
		"verdict":       "pass",
		"action":        "pass",
		"mode":          "shadow",
		"latency_ms":    1.25,
		"tags":          []string{},
		"flags":         []string{},
		"staging_match": []string{},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRow_Roundtrip(t *testing.T) {
	row, err := parseRow(goodLine(t, "req-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := row[0].(string); got != "req-1" {
		t.Errorf("request_id=%q", got)
	}
	if _, ok := row[1].(time.Time); !ok {
		t.Errorf("ts type=%T", row[1])
	}
	// raw is the last element and must be the original bytes.
	rawBytes, ok := row[len(row)-1].([]byte)
	if !ok || len(rawBytes) == 0 {
		t.Errorf("raw bytes missing: %T", row[len(row)-1])
	}
}

func TestParseRow_MissingRequired(t *testing.T) {
	if _, err := parseRow([]byte(`{"edge_id":"e","timestamp":"2026-05-24T00:00:00Z"}`)); err == nil {
		t.Fatal("want error on missing request_id")
	}
	if _, err := parseRow([]byte(`{"request_id":"r","edge_id":"e"}`)); err == nil {
		t.Fatal("want error on missing timestamp")
	}
}

func TestParseRow_TrailingJunkRejected(t *testing.T) {
	good := goodLine(t, "r")
	body := append([]byte{}, good...)
	body = append(body, []byte("garbage")...)
	if _, err := parseRow(body); err == nil {
		t.Fatal("want error on trailing data after JSON")
	}
}

func TestParseRow_MalformedTimestamp(t *testing.T) {
	body := `{"request_id":"r","edge_id":"e","timestamp":"not-a-time"}`
	if _, err := parseRow([]byte(body)); err == nil {
		t.Fatal("want timestamp parse error")
	}
}

func TestSink_HappyPath_BatchFlushes(t *testing.T) {
	s, w := newTestSink(t, Config{BatchSize: 3, FlushInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	for i := 0; i < 3; i++ {
		s.Submit(goodLine(t, "req-h"))
	}
	// The batch size was reached — the flush must be almost immediate.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if w.totalRows() == 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected 3 rows inserted, got %d", w.totalRows())
}

func TestSink_FlushOnTimer(t *testing.T) {
	s, w := newTestSink(t, Config{BatchSize: 100, FlushInterval: 30 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Submit(goodLine(t, "req-t"))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if w.totalRows() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timer flush not triggered: got %d rows", w.totalRows())
}

func TestSink_DropOnFullQueue(t *testing.T) {
	// QueueSize=1 and we do not start Run — Submit is never drained, so the second Submit
	// must drop.
	cfg := Config{QueueSize: 1, BatchSize: 100, FlushInterval: time.Hour}
	s, _ := newTestSink(t, cfg)
	s.Submit(goodLine(t, "a"))
	s.Submit(goodLine(t, "b")) // must be dropped
	if got := promCounterValue(t, s.dropped); got != 1 {
		t.Fatalf("dropped=%v, want 1", got)
	}
	if got := promCounterValue(t, s.submitted); got != 1 {
		t.Fatalf("submitted=%v, want 1", got)
	}
}

func TestSink_SpillToDiskOnInsertError(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		BatchSize:     1,
		FlushInterval: time.Hour,
		SpoolDir:      dir,
		SpoolMaxBytes: 1 << 20,
		DrainInterval: time.Hour, // we disable the drain in this test
	}
	s, w := newTestSink(t, cfg)
	w.failN.Store(1) // the first Insert fails
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Submit(goodLine(t, "spilled"))

	// spill renames the file into place before bumping the counter, so the file
	// appearing does not yet mean the metric has moved. Wait for both.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if batches, _ := countSpoolFiles(t, dir); batches > 0 && promCounterValue(t, s.spooledFiles) >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	batches, _ := countSpoolFiles(t, dir)
	t.Fatalf("spool file not produced after insert error: batch files=%d, spooledFiles=%v",
		batches, promCounterValue(t, s.spooledFiles))
}

func TestSink_DrainerRecoversSpool(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		BatchSize:     1,
		FlushInterval: time.Hour,
		SpoolDir:      dir,
		SpoolMaxBytes: 1 << 20,
		DrainInterval: 20 * time.Millisecond,
	}
	s, w := newTestSink(t, cfg)
	w.failN.Store(1) // the first Insert fails, the second (the drain) succeeds
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Submit(goodLine(t, "drain-me"))

	// drainOnce inserts, then removes the file, then bumps the metric. Waiting on
	// the rows alone would observe the middle of that sequence, so poll until
	// every effect is visible and only then decide.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		batches, leftover := countSpoolFiles(t, dir)
		if w.totalRows() == 1 && batches == 0 && leftover == 0 && promCounterValue(t, s.drained) >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	batches, leftover := countSpoolFiles(t, dir)
	t.Fatalf("drain did not recover the spooled batch: rows=%d, batch files=%d, other files=%d, drained=%v",
		w.totalRows(), batches, leftover, promCounterValue(t, s.drained))
}

func TestSink_SpoolBudgetEvictsOldest(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		BatchSize:     1,
		FlushInterval: time.Hour,
		SpoolDir:      dir,
		SpoolMaxBytes: 100, // a tiny ceiling — we will certainly exceed it
		DrainInterval: time.Hour,
	}
	s, w := newTestSink(t, cfg)
	// Let every Insert fail, so that every batch flies into the spool.
	w.failN.Store(10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	for i := 0; i < 5; i++ {
		s.Submit(goodLine(t, "evict"))
		time.Sleep(20 * time.Millisecond) // we guarantee unique UnixNano values
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if promCounterValue(t, s.spoolDropped) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("spool budget did not evict any file")
}

// listSpoolFiles must skip .quarantine and .partial — otherwise
// drainOnce rereads a file already in the DB and inserts duplicates.
func TestListSpoolFiles_SkipsQuarantineAndPartial(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"batch-100-1.ndjson",
		"batch-101-2.ndjson.quarantine",
		"batch-102-3.ndjson.partial",
		"batch-103-4.ndjson",
		"unrelated.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := listSpoolFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		names := []string{}
		for _, e := range got {
			names = append(names, e.Name())
		}
		t.Fatalf("got %d files %v, want exactly 2 active batch files", len(got), names)
	}
	if got[0].Name() != "batch-100-1.ndjson" || got[1].Name() != "batch-103-4.ndjson" {
		t.Fatalf("unexpected order/contents: %s, %s", got[0].Name(), got[1].Name())
	}
}

func TestSink_ParseErrorSkippedNotSpilled(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		BatchSize:     1,
		FlushInterval: time.Hour,
		SpoolDir:      dir,
		SpoolMaxBytes: 1 << 20,
		DrainInterval: time.Hour,
	}
	s, w := newTestSink(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Submit([]byte(`{garbage`))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if promCounterValue(t, s.parseErr) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := promCounterValue(t, s.parseErr); got < 1 {
		t.Fatalf("parseErr=%v, want >=1", got)
	}
	// parseErr is bumped in the middle of the flush, so give the rest of it a
	// moment before asserting on what it must NOT have done.
	time.Sleep(50 * time.Millisecond)
	if w.totalRows() != 0 {
		t.Fatalf("rows inserted=%d, want 0", w.totalRows())
	}
	// The spool must not fill up — insert returns nil on empty rows.
	if batches, leftover := countSpoolFiles(t, dir); batches != 0 || leftover != 0 {
		t.Fatalf("spool not empty after parse error: batch files=%d, other files=%d", batches, leftover)
	}
}

// countSpoolFiles reports how many drainable batch files are in dir and how many
// other files are left behind (a mid-write .partial, or a .quarantine the drain
// could not remove). Both matter: drainOnce bumps drained on the quarantine path
// too, so an empty batch count alone does not prove the spool was cleaned up.
// Returns -1 on a read error rather than failing, so it stays usable inside a
// t.Fatalf argument list.
func countSpoolFiles(t *testing.T, dir string) (batches, leftover int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return -1, -1
	}
	for _, e := range ents {
		switch {
		case e.IsDir():
		case filepath.Ext(e.Name()) == ".ndjson":
			batches++
		default:
			leftover++
		}
	}
	return batches, leftover
}

func promCounterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}
