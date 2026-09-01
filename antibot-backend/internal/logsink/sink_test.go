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
	time.Sleep(120 * time.Millisecond)
	if w.totalRows() != 1 {
		t.Fatalf("timer flush not triggered: got %d", w.totalRows())
	}
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

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir(dir)
		hasBatch := false
		for _, e := range ents {
			if filepath.Ext(e.Name()) == ".ndjson" {
				hasBatch = true
			}
		}
		if hasBatch {
			if promCounterValue(t, s.spooledFiles) < 1 {
				t.Fatalf("spooledFiles metric not bumped")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("spool file not produced after insert error")
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

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.totalRows() == 1 {
			// the file must disappear.
			ents, _ := os.ReadDir(dir)
			leftover := 0
			for _, e := range ents {
				if filepath.Ext(e.Name()) == ".ndjson" {
					leftover++
				}
			}
			if leftover != 0 {
				t.Fatalf("spool not cleaned: %d files", leftover)
			}
			if got := promCounterValue(t, s.drained); got < 1 {
				t.Fatalf("drained metric not bumped: %v", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("drain did not recover spooled batch, inserted=%d", w.totalRows())
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
	if w.totalRows() != 0 {
		t.Fatalf("rows inserted=%d, want 0", w.totalRows())
	}
	// The spool must not fill up — insert returns nil on empty rows.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".ndjson" {
			t.Fatalf("unexpected spool file %s after parse error", e.Name())
		}
	}
}

func promCounterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}
