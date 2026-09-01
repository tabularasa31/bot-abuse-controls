// Package logsink ingests the edge's structured log stream into PostgreSQL.
//
// Submit is non-blocking and feeds a bounded queue; a consumer batches from it
// and writes with CopyFrom, flushing on size or on a timer. A failed write
// spills the whole batch to disk as one file, and a drainer retries the oldest
// spool file later. That is what keeps a sink outage from losing logs.
//
// The spool is bounded: past the limit the oldest files are dropped and
// counted, so a long outage cannot fill the disk.
//
// Storing the payload as JSONB keeps the schema stable, so the sink can be
// swapped for a column store later without touching the edge.
package logsink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// Config — the sink settings. The defaults live in DefaultConfig().
type Config struct {
	// BatchSize — the flush threshold by line count.
	BatchSize int
	// FlushInterval — the flush threshold by time (when BatchSize is not reached).
	FlushInterval time.Duration
	// Bounded, and dropping on overflow is deliberate: the guarantee covers a
	// sink outage, not overload, and blocking here would push backpressure onto
	// the receiver.
	QueueSize int
	// SpoolDir — where to put NDJSON batches during a sink outage. An empty
	// string disables the spill (for tests and a dev mode without disk).
	SpoolDir string
	// SpoolMaxBytes — the ceiling on the spool directory's total size. Above
	// it we delete the oldest files; a sink outage must not
	// fill the whole disk.
	SpoolMaxBytes int64
	// DrainInterval — how often we try to drain the spool directory.
	DrainInterval time.Duration
}

// DefaultConfig trades a second or so of ingest latency for one round trip per
// batch, which is the right side of the trade for analytics.
func DefaultConfig() Config {
	return Config{
		BatchSize:     500,
		FlushInterval: 2 * time.Second,
		QueueSize:     8192,
		SpoolMaxBytes: 256 << 20, // 256 MiB
		DrainInterval: 10 * time.Second,
	}
}

// Writer — what Sink calls for one batch. The production implementation
// is pgxWriter (CopyFrom into logs); tests substitute a fake with a controllable
// error, to exercise spill/drain without a live database.
type Writer interface {
	Insert(ctx context.Context, rows [][]any) error
}

// pgxWriter — the production implementation of Writer over pgxpool. CopyFrom in one
// round is the cheapest bulk insert.
type pgxWriter struct{ pool *pgxpool.Pool }

func (w *pgxWriter) Insert(ctx context.Context, rows [][]any) error {
	_, err := w.pool.CopyFrom(ctx, pgx.Identifier{"logs"}, copyColumns, pgx.CopyFromRows(rows))
	return err
}

// Sink — a batch inserter with a disk queue. Created through New, started with Run,
// and fed through Submit.
type Sink struct {
	cfg     Config
	logger  *slog.Logger
	writer  Writer
	ch      chan []byte
	stopped atomic.Bool

	// the metrics
	submitted    prometheus.Counter
	dropped      prometheus.Counter
	parseErr     prometheus.Counter
	inserted     prometheus.Counter
	insertErr    prometheus.Counter
	spooledFiles prometheus.Counter
	spooledLines prometheus.Counter
	drained      prometheus.Counter
	spoolDropped prometheus.Counter
	spoolBytes   prometheus.Gauge
	queueDepth   prometheus.GaugeFunc
}

// New creates the sink, preparing the spool directory. An error means the
// environment is unusable, such as a spool directory that cannot be written.
func New(cfg Config, pool *pgxpool.Pool, logger *slog.Logger, reg prometheus.Registerer) (*Sink, error) {
	if pool == nil {
		return nil, errors.New("logsink: pool is nil")
	}
	return NewWithWriter(cfg, &pgxWriter{pool: pool}, logger, reg)
}

// NewWithWriter — for tests and for a future DuckDB/ClickHouse swap
// (a different Writer, the same Sink).
func NewWithWriter(cfg Config, w Writer, logger *slog.Logger, reg prometheus.Registerer) (*Sink, error) {
	if w == nil {
		return nil, errors.New("logsink: writer is nil")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultConfig().BatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultConfig().FlushInterval
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultConfig().QueueSize
	}
	if cfg.DrainInterval <= 0 {
		cfg.DrainInterval = DefaultConfig().DrainInterval
	}
	if cfg.SpoolDir != "" {
		if err := os.MkdirAll(cfg.SpoolDir, 0o750); err != nil {
			return nil, fmt.Errorf("logsink: spool dir: %w", err)
		}
	}

	s := &Sink{
		cfg:    cfg,
		logger: logger,
		writer: w,
		ch:     make(chan []byte, cfg.QueueSize),
	}
	s.submitted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_submitted_total",
		Help: "Lines accepted by Sink.Submit (before parse/batch).",
	})
	s.dropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_submit_dropped_total",
		Help: "Lines dropped because the in-memory submit queue was full.",
	})
	s.parseErr = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_parse_errors_total",
		Help: "Lines rejected by sink JSON parser (skipped, not retried).",
	})
	s.inserted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_inserted_total",
		Help: "Lines successfully written into the logs table.",
	})
	s.insertErr = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_insert_errors_total",
		Help: "Batch insert failures (batch then spilled to disk if SpoolDir set).",
	})
	s.spooledFiles = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_spooled_files_total",
		Help: "Batches written to the on-disk spool because the DB was unreachable.",
	})
	s.spooledLines = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_spooled_lines_total",
		Help: "Total lines spilled to the on-disk spool.",
	})
	s.drained = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_drained_lines_total",
		Help: "Lines re-inserted from the on-disk spool after recovery.",
	})
	s.spoolDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "antibot_backend_log_sink_spool_dropped_files_total",
		Help: "Oldest spool files deleted because SpoolMaxBytes was exceeded.",
	})
	s.spoolBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "antibot_backend_log_sink_spool_bytes",
		Help: "Current total size of the on-disk spool directory.",
	})
	s.queueDepth = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "antibot_backend_log_sink_queue_depth",
		Help: "Current depth of the submit→consumer in-memory queue.",
	}, func() float64 { return float64(len(s.ch)) })

	reg.MustRegister(
		s.submitted, s.dropped, s.parseErr,
		s.inserted, s.insertErr,
		s.spooledFiles, s.spooledLines, s.drained, s.spoolDropped,
		s.spoolBytes, s.queueDepth,
	)
	return s, nil
}

// Submit is non-blocking and copies the line, since the caller's scanner reuses
// its buffer.
//
// The stopped check is best effort. There is a formal window where a line could
// be orphaned at shutdown, but the server is drained before the workers are
// cancelled, so it cannot happen in practice — and a lock here would cost on
// every log line.
func (s *Sink) Submit(line []byte) {
	if s.stopped.Load() {
		return
	}
	cp := make([]byte, len(line))
	copy(cp, line)
	select {
	case s.ch <- cp:
		s.submitted.Inc()
	default:
		s.dropped.Inc()
	}
}

// Run runs the consumer plus the drainer. It returns after ctx.Done() and the final
// flush of the remaining batch (to disk if the DB is unavailable).
func (s *Sink) Run(ctx context.Context) {
	// An initial inventory of the spool — so that the gauge shows the real
	// size straight away (rather than "0 → bump" after the first spill).
	s.updateSpoolGauge()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.consume(ctx) }()
	go func() { defer wg.Done(); s.drain(ctx) }()
	wg.Wait()
}

func (s *Sink) consume(ctx context.Context) {
	batch := make([][]byte, 0, s.cfg.BatchSize)
	flush := time.NewTicker(s.cfg.FlushInterval)
	defer flush.Stop()

	doFlush := func() {
		if len(batch) == 0 {
			return
		}
		s.flush(ctx, batch)
		batch = batch[:0]
	}

	// Flushes during shutdown need a context that is no longer cancelled, or a
	// healthy database would still spill. The timeout is what keeps a hung write
	// against a dead database from outliving the shutdown, which would abandon
	// the worker and lose the batch from both the database and the spool.
	detachedFlush := func(b [][]byte) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.FlushInterval)
		defer cancel()
		s.flush(fctx, b)
	}

	for {
		select {
		case <-ctx.Done():
			// Set before draining, or a Submit already past its check could write
			// after the drain and orphan the line.
			s.stopped.Store(true)
			for {
				select {
				case line := <-s.ch:
					batch = append(batch, line)
					if len(batch) >= s.cfg.BatchSize {
						// Every flush here, not only the last: otherwise a
						// mid-drain batch spills without ever trying the
						// database.
						detachedFlush(batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						detachedFlush(batch)
					}
					return
				}
			}
		case line := <-s.ch:
			batch = append(batch, line)
			if len(batch) >= s.cfg.BatchSize {
				doFlush()
			}
		case <-flush.C:
			doFlush()
		}
	}
}

// flush — an attempt to put the batch into the DB. On an error → a spill into the spool.
func (s *Sink) flush(ctx context.Context, lines [][]byte) {
	// A local copy of the slice — the caller reuses its buffer.
	cp := make([][]byte, len(lines))
	copy(cp, lines)

	if err := s.insert(ctx, cp); err != nil {
		s.insertErr.Inc()
		s.logger.Warn("logsink: batch insert failed, spilling to disk",
			"err", err, "lines", len(cp))
		s.spill(cp)
	}
}

// insert parses the lines and copies them into logs with a single CopyFrom. A parse failure
// on one line does not fail the whole batch — we skip the line (parseErr++) and the rest
// go into the DB. That way one malformed JSON does not lock the sink forever.
func (s *Sink) insert(ctx context.Context, lines [][]byte) error {
	rows := make([][]any, 0, len(lines))
	for _, line := range lines {
		row, err := parseRow(line)
		if err != nil {
			s.parseErr.Inc()
			continue
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil
	}
	// The whole batch spills rather than hunting for the offending line: for
	// analytics that is an acceptable trade during a rare outage.
	if err := s.writer.Insert(ctx, rows); err != nil {
		return fmt.Errorf("writer insert: %w", err)
	}
	s.inserted.Add(float64(len(rows)))
	return nil
}

// spill writes the batch as one file. With no spool directory configured the
// lines are dropped, which shows up as the gap between accepted and inserted.
func (s *Sink) spill(lines [][]byte) {
	if s.cfg.SpoolDir == "" {
		return
	}
	if err := s.enforceSpoolBudget(); err != nil {
		s.logger.Warn("logsink: spool budget check failed", "err", err)
	}
	name := fmt.Sprintf("batch-%d-%d.ndjson", time.Now().UnixNano(), spoolCounter.Add(1))
	path := filepath.Join(s.cfg.SpoolDir, name)
	// We write to tmp plus rename, so that the drainer does not pick up a partially written
	// file (a concurrent drain versus a spill in the same directory).
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		s.logger.Error("logsink: spool open failed", "err", err, "path", tmp)
		return
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		_, _ = w.Write(l)
		_, _ = w.Write([]byte{'\n'})
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		s.logger.Error("logsink: spool flush failed", "err", err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		s.logger.Error("logsink: spool close failed", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		s.logger.Error("logsink: spool rename failed", "err", err)
		return
	}
	s.spooledFiles.Inc()
	s.spooledLines.Add(float64(len(lines)))
	// Enforced again after the write: the batch can be larger than the room the
	// first pass made, and this second pass is what makes the bound hard.
	if err := s.enforceSpoolBudget(); err != nil {
		s.logger.Warn("logsink: post-write budget check failed", "err", err)
	}
	s.updateSpoolGauge()
}

// drain periodically takes the oldest file from the spool and tries to insert it.
// On success it deletes the file; on an error we stop until the next tick
// (the DB has not recovered yet).
func (s *Sink) drain(ctx context.Context) {
	if s.cfg.SpoolDir == "" {
		return
	}
	t := time.NewTicker(s.cfg.DrainInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.drainOnce(ctx)
		}
	}
}

func (s *Sink) drainOnce(ctx context.Context) {
	files, err := listSpoolFiles(s.cfg.SpoolDir)
	if err != nil {
		s.logger.Warn("logsink: drain list failed", "err", err)
		return
	}
	for _, f := range files {
		path := filepath.Join(s.cfg.SpoolDir, f.Name())
		lines, err := readNDJSON(path)
		if err != nil {
			// A broken file is NOT deleted automatically — the operator will sort it out
			// (it may be a partial write from a crash, or junk);
			// we simply skip it and drain will try the others.
			s.logger.Warn("logsink: drain read failed", "err", err, "path", path)
			continue
		}
		if err := s.insert(ctx, lines); err != nil {
			s.logger.Warn("logsink: drain insert failed, stopping cycle",
				"err", err, "path", path, "remaining_files", len(files))
			return
		}
		if err := os.Remove(path); err != nil {
			// The rows are already in the database and the table has no natural
			// key, so leaving the file in place would duplicate them on the next
			// tick. Renaming takes it out of the drain's view.
			quar := path + ".quarantine"
			if rerr := os.Rename(path, quar); rerr != nil {
				s.logger.Error("logsink: drain remove AND quarantine-rename failed — RISK OF DUPLICATES on next tick",
					"err", err, "rename_err", rerr, "path", path)
				return
			}
			s.logger.Warn("logsink: drain remove failed, file quarantined to avoid duplicate insert",
				"err", err, "path", path, "quarantined_to", quar)
			s.drained.Add(float64(len(lines)))
			s.updateSpoolGauge()
			continue
		}
		s.drained.Add(float64(len(lines)))
		s.updateSpoolGauge()
	}
}

// enforceSpoolBudget deletes the oldest files until the total size drops
// below SpoolMaxBytes. Protection against "the sink is down for a day and the disk
// is full".
func (s *Sink) enforceSpoolBudget() error {
	if s.cfg.SpoolMaxBytes <= 0 {
		return nil
	}
	files, err := listSpoolFiles(s.cfg.SpoolDir)
	if err != nil {
		return err
	}
	var total int64
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	// Never evict the last file. If one batch alone exceeds the cap the limit is
	// misconfigured, and deleting it would turn a bound into guaranteed loss of
	// every spill even on an empty disk.
	for total > s.cfg.SpoolMaxBytes && len(files) > 1 {
		victim := files[0]
		path := filepath.Join(s.cfg.SpoolDir, victim.Name())
		info, _ := victim.Info()
		if err := os.Remove(path); err != nil {
			s.logger.Warn("logsink: spool evict failed", "err", err, "path", path)
			break
		}
		if info != nil {
			total -= info.Size()
		}
		s.spoolDropped.Inc()
		files = files[1:]
	}
	if total > s.cfg.SpoolMaxBytes && len(files) == 1 {
		s.logger.Error("logsink: single spool file exceeds SpoolMaxBytes — bump cap or shrink batch size",
			"bytes", total, "cap", s.cfg.SpoolMaxBytes, "file", files[0].Name())
	}
	s.updateSpoolGauge()
	return nil
}

func (s *Sink) updateSpoolGauge() {
	if s.cfg.SpoolDir == "" {
		return
	}
	files, err := listSpoolFiles(s.cfg.SpoolDir)
	if err != nil {
		return
	}
	var total int64
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	s.spoolBytes.Set(float64(total))
}

// spoolCounter — a monotonic suffix for the spool file name, so that two
// simultaneous spill operations within the same nanosecond do not collide on the
// same name.
var spoolCounter atomic.Uint64

// copyColumns — the column order for CopyFrom. It must match the order of the
// values in parseRow.
var copyColumns = []string{
	"request_id", "ts", "edge_id", "resource_id",
	"host", "path", "method", "status",
	"ip", "asn", "geo_country", "ua",
	"tls_fp", "tls_cipher_count", "tls_alpn", "tls_sni_present",
	"stage", "verdict", "rule", "action", "mode",
	"latency_ms", "tags", "flags", "staging_match",
	"rule_source", "client_rule_name",
	"raw",
}

// rawRecord mirrors a log line. Every field is a pointer, since the edge sends
// null for whatever did not apply to that request.
//
// json.Number for status — the field arrives as an int, but through a float64 in a
// generic decoder it loses precision; we store it as a Number and parse it
// by hand. The same goes for tls_cipher_count and latency_ms.
type rawRecord struct {
	RequestID      string      `json:"request_id"`
	Timestamp      string      `json:"timestamp"`
	EdgeID         string      `json:"edge_id"`
	ResourceID     *string     `json:"resource_id"`
	Host           *string     `json:"host"`
	Path           *string     `json:"path"`
	Method         *string     `json:"method"`
	Status         json.Number `json:"status"`
	IP             *string     `json:"ip"`
	ASN            *string     `json:"asn"`
	GeoCountry     *string     `json:"geo_country"`
	UA             *string     `json:"ua"`
	TLSFP          *string     `json:"tls_fp"`
	TLSCipherCount json.Number `json:"tls_cipher_count"`
	TLSAlpn        *string     `json:"tls_alpn"`
	TLSSniPresent  *bool       `json:"tls_sni_present"`
	Stage          *string     `json:"stage"`
	Verdict        *string     `json:"verdict"`
	Rule           *string     `json:"rule"`
	Action         *string     `json:"action"`
	Mode           *string     `json:"mode"`
	LatencyMs      json.Number `json:"latency_ms"`
	Tags           []string    `json:"tags"`
	Flags          []string    `json:"flags"`
	StagingMatch   []string    `json:"staging_match"`
	RuleSource     *string     `json:"rule_source"`
	ClientRuleName *string     `json:"client_rule_name"`
}

func parseRow(line []byte) ([]any, error) {
	// json.Decoder.Decode accepts one JSON object and silently ignores
	// trailing bytes — a line like `{...}garbage` would pass the parse, but the same
	// line as jsonb in PostgreSQL is rejected and the whole CopyFrom batch
	// fails; the sink carries it into the spool, the drainer returns it to the DB,
	// CopyFrom fails again — and sink throughput dies on one malformed
	// line. So after the Decode we check that
	// only whitespace remains in the buffer up to EOF.
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var r rawRecord
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON object")
	}
	if r.RequestID == "" || r.EdgeID == "" || r.Timestamp == "" {
		return nil, errors.New("missing required fields (request_id/edge_id/timestamp)")
	}
	ts, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("timestamp: %w", err)
	}
	row := []any{
		r.RequestID,
		ts,
		r.EdgeID,
		nullStr(r.ResourceID),
		nullStr(r.Host),
		nullStr(r.Path),
		nullStr(r.Method),
		nullIntNum(r.Status),
		nullStr(r.IP),
		nullStr(r.ASN),
		nullStr(r.GeoCountry),
		nullStr(r.UA),
		nullStr(r.TLSFP),
		nullIntNum(r.TLSCipherCount),
		nullStr(r.TLSAlpn),
		nullBool(r.TLSSniPresent),
		nullStr(r.Stage),
		nullStr(r.Verdict),
		nullStr(r.Rule),
		nullStr(r.Action),
		nullStr(r.Mode),
		nullFloatNum(r.LatencyMs),
		emptyArr(r.Tags),
		emptyArr(r.Flags),
		emptyArr(r.StagingMatch),
		nullStr(r.RuleSource),
		nullStr(r.ClientRuleName),
		// raw — the whole line as jsonb. pgx converts []byte to jsonb itself, and
		// does not check the JSON's validity — we parsed it successfully above.
		line,
	}
	return row, nil
}

func nullStr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func nullBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func nullIntNum(n json.Number) any {
	if n == "" {
		return nil
	}
	v, err := n.Int64()
	if err != nil {
		// status/tls_cipher_count can sometimes arrive as a float (if the
		// serialiser emitted 200.0, say); we try float→int64.
		f, ferr := n.Float64()
		if ferr != nil {
			return nil
		}
		return int64(f)
	}
	return v
}

func nullFloatNum(n json.Number) any {
	if n == "" {
		return nil
	}
	v, err := n.Float64()
	if err != nil {
		return nil
	}
	return v
}

func emptyArr(a []string) any {
	if a == nil {
		// pgx dislikes a nil text[] — we hand it an empty slice. In Postgres it lands as '{}'.
		return []string{}
	}
	return a
}

// readNDJSON unwraps one spool file into []line. Each line is a separate
// BAC_LOG record. Empty lines are skipped (the trailing '\n').
func readNDJSON(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	// 1 MiB per line — comfortably above the receiver's 32 KiB cap.
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		out = append(out, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// listSpoolFiles returns the spool files sorted by name (the name
// starts with UnixNano, so lexicographic order is chronological).
// We accept only `batch-*.ndjson` — WITHOUT the exact suffix check, `.quarantine`
// files (created by drainOnce when Remove is unavailable) and `.partial` (unfinished
// spills) also carry the `batch-` prefix, and without checking the .ndjson suffix the
// drainer would reread them and insert duplicates.
func listSpoolFiles(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]os.DirEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "batch-") || !strings.HasSuffix(name, ".ndjson") {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}
