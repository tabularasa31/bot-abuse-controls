// Package logsink — приёмник BAC_LOG в PostgreSQL для аналитики ([B9]).
//
// vision §"Приёмник логов" + phase1-spec §"Открытые вопросы (приёмник
// телеметрии)" — куда лить структурированный поток логов. Стартовый sink —
// та же PostgreSQL, что держит каталоги (B1/B4), таблица `logs` из
// миграции 0003_logs.sql. Когда объём перерастёт Postgres — swap на
// DuckDB/ClickHouse за границей «receiver→sink»: edge-сторона и schema
// (за счёт raw JSONB) не меняются.
//
// Контракт пакета:
//
//   - Submit(line) — non-blocking; вызывает receiver на hot-path POST /v1/logs.
//     Очередь bounded; переполнение → drop с метрикой `…_submit_dropped_total`,
//     edge продолжит работать, NDJSON осядет в следующий батч.
//
//   - Run(ctx) — крутит две горутины:
//     (a) consumer: батчит из канала, флашит по size/timer через CopyFrom.
//     На ошибку записи → spill всего батча на диск (одна спул-файла
//     NDJSON = один батч), консумер продолжает принимать новые строки.
//     (b) drainer: периодически выгребает старейший спул-файл и пробует
//     вставить заново; на ошибку — backoff (ничего не удаляет).
//
//   - Disk-queue: гарантия «sink-простой не теряет логи» (acceptance B9).
//     Bound: SpoolMaxBytes; при превышении — удаляем старейшие спул-файлы
//     с метрикой `…_spool_dropped_files_total` (защита от unbounded роста
//     при длительном outage'е sink).
package logsink

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Config — настройки sink. Дефолты в DefaultConfig().
type Config struct {
	// BatchSize — порог флаша по числу строк.
	BatchSize int
	// FlushInterval — порог флаша по времени (если BatchSize не набран).
	FlushInterval time.Duration
	// QueueSize — bound на in-memory очередь Submit→consumer. Подбирается
	// под пиковую частоту POST'ов c эджей; при переполнении дропаем
	// (acceptance — «не теряем при простое sink», а не «при перегрузке»;
	// перегрузка in-memory очереди = receiver падает в backpressure,
	// что сильно хуже).
	QueueSize int
	// SpoolDir — где складывать NDJSON-батчи при простое sink. Пустая
	// строка = spill отключён (для тестов и dev-режима без диска).
	SpoolDir string
	// SpoolMaxBytes — потолок суммарного размера спул-каталога. При
	// превышении удаляем самые старые файлы; sink-outage не должен
	// заливать диск целиком.
	SpoolMaxBytes int64
	// DrainInterval — как часто пробуем выгрести спул-каталог.
	DrainInterval time.Duration
}

// DefaultConfig — разумные значения для демо-стенда.
// BatchSize/FlushInterval: 500 строк ИЛИ 2 с — pgx CopyFrom за один RTT
// на батч; при умеренном QPS эджа (десятки RPS на инстанс) это секундная
// задержка ingest-видимости, под аналитикой нормально.
func DefaultConfig() Config {
	return Config{
		BatchSize:     500,
		FlushInterval: 2 * time.Second,
		QueueSize:     8192,
		SpoolMaxBytes: 256 << 20, // 256 MiB
		DrainInterval: 10 * time.Second,
	}
}

// Writer — то, что Sink дёргает для одного батча. Production-реализация
// — pgxWriter (CopyFrom в logs); тесты подменяют на фейк с управляемой
// ошибкой, чтобы проверять spill/drain без живой БД.
type Writer interface {
	Insert(ctx context.Context, rows [][]any) error
}

// pgxWriter — production-реализация Writer над pgxpool. CopyFrom за один
// раунд — самый дешёвый bulk-insert.
type pgxWriter struct{ pool *pgxpool.Pool }

func (w *pgxWriter) Insert(ctx context.Context, rows [][]any) error {
	_, err := w.pool.CopyFrom(ctx, pgx.Identifier{"logs"}, copyColumns, pgx.CopyFromRows(rows))
	return err
}

// Sink — батч-инсертер с disk-queue. Создаётся через New, запускается Run,
// получает работу через Submit.
type Sink struct {
	cfg     Config
	logger  *slog.Logger
	writer  Writer
	ch      chan []byte
	stopped atomic.Bool

	// метрики
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

// New создаёт sink. Если cfg.SpoolDir задан и существует — создаст подкаталог
// при необходимости. Возврат ошибки = неустранимая проблема среды (нет прав
// на спул-каталог) — receiver/app должны решить, валить процесс или работать
// без sink.
func New(cfg Config, pool *pgxpool.Pool, logger *slog.Logger, reg prometheus.Registerer) (*Sink, error) {
	if pool == nil {
		return nil, errors.New("logsink: pool is nil")
	}
	return NewWithWriter(cfg, &pgxWriter{pool: pool}, logger, reg)
}

// NewWithWriter — для тестов и для будущего DuckDB/ClickHouse swap'a
// (другой Writer, тот же Sink).
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

// Submit — non-blocking, дёргается с hot-path receiver. Копия line — её
// уже сделал bufio.Scanner владельцу, нам безопасно держать ссылку, но
// scanner переиспользует свой буфер на следующей итерации → нужно скопировать.
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

// Run крутит consumer + drainer. Возвращает после ctx.Done() и финального
// флаша оставшегося батча (на диск, если DB недоступна).
func (s *Sink) Run(ctx context.Context) {
	// Стартовая инвентаризация спула — чтобы gauge сразу показывал реальный
	// размер (не «0 → bump» после первого spill).
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

	for {
		select {
		case <-ctx.Done():
			// Дренируем оставшийся канал, чтобы submitted-counter сошёлся
			// с inserted+spooled+parseErr на штатной остановке. Финальный
			// флаш — после.
			s.stopped.Store(true)
			for {
				select {
				case line := <-s.ch:
					batch = append(batch, line)
					if len(batch) >= s.cfg.BatchSize {
						s.flush(ctx, batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						// ctx уже отменён shutdown'ом, но финальный
						// флаш должен пройти — WithoutCancel сохраняет
						// values (tracing/log), но рвёт cancellation,
						// иначе writer.Insert упадёт на canceled ctx
						// и батч уйдёт в spill вместо DB.
						s.flush(context.WithoutCancel(ctx), batch)
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

// flush — попытка положить батч в DB. На ошибку → spill в spool.
func (s *Sink) flush(ctx context.Context, lines [][]byte) {
	// Локальная копия слайса — caller переиспользует свой буфер.
	cp := make([][]byte, len(lines))
	copy(cp, lines)

	if err := s.insert(ctx, cp); err != nil {
		s.insertErr.Inc()
		s.logger.Warn("logsink: batch insert failed, spilling to disk",
			"err", err, "lines", len(cp))
		s.spill(cp)
	}
}

// insert парсит строки и копирует их в logs одним CopyFrom. Неудача парса
// одной строки не валит весь батч — строку пропускаем (parseErr++), остальные
// идут в DB. Так один кривой JSON не запирает sink навсегда.
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
	// Ошибка на любой строке — вся транзакция rollback; мы тогда отдаём
	// весь батч в spill, а не пытаемся локализовать виноватую строку (для
	// аналитики приемлемо при редких outage'ах; парсинг отдельных строк
	// уже отфильтрован выше).
	if err := s.writer.Insert(ctx, rows); err != nil {
		return fmt.Errorf("writer insert: %w", err)
	}
	s.inserted.Add(float64(len(rows)))
	return nil
}

// spill пишет батч одной NDJSON-файлой в SpoolDir. Если SpoolDir не задан —
// просто роняем строки (метрика dropped уже не подходит, sink_insert_errors
// уже инкрементирован, осиротевшие строки видны как разность). В реальной
// конфигурации demo-VM SpoolDir всегда задан.
func (s *Sink) spill(lines [][]byte) {
	if s.cfg.SpoolDir == "" {
		return
	}
	if err := s.enforceSpoolBudget(); err != nil {
		s.logger.Warn("logsink: spool budget check failed", "err", err)
	}
	name := fmt.Sprintf("batch-%d-%d.ndjson", time.Now().UnixNano(), spoolCounter.Add(1))
	path := filepath.Join(s.cfg.SpoolDir, name)
	// Пишем в tmp + rename, чтобы drainer не подхватил частично записанный
	// файл (concurrent drain vs spill в одном каталоге).
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
	s.updateSpoolGauge()
}

// drain периодически берёт самый старый файл из спула и пытается вставить.
// На успех — удаляет файл; на ошибку — стопаемся до следующего тика
// (DB ещё не восстановилась).
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
			// Битый файл — НЕ удаляем автоматически, оператор разберётся
			// (могла случиться частичная запись при crash'е, либо мусор);
			// просто пропускаем, drain попробует другие.
			s.logger.Warn("logsink: drain read failed", "err", err, "path", path)
			continue
		}
		if err := s.insert(ctx, lines); err != nil {
			s.logger.Warn("logsink: drain insert failed, stopping cycle",
				"err", err, "path", path, "remaining_files", len(files))
			return
		}
		if err := os.Remove(path); err != nil {
			s.logger.Warn("logsink: drain remove failed", "err", err, "path", path)
			// Файл уже в DB — повторное чтение даст дубликаты. Stop'аемся,
			// чтобы оператор увидел в логах и руками удалил/переименовал.
			return
		}
		s.drained.Add(float64(len(lines)))
		s.updateSpoolGauge()
	}
}

// enforceSpoolBudget удаляет старейшие файлы пока суммарный размер не
// уйдёт под SpoolMaxBytes. Защита от ситуации «sink лежит сутки, диск
// забит».
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
	for total > s.cfg.SpoolMaxBytes && len(files) > 0 {
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

// spoolCounter — монотонный суффикс к имени спул-файла, чтобы две
// одновременные spill-операции в пределах одной нс не столкнулись на
// одинаковом имени.
var spoolCounter atomic.Uint64

// copyColumns — порядок колонок для CopyFrom. Должен совпадать с порядком
// значений в parseRow.
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

// rawRecord — гибкое представление JSON-строки лога. Все поля
// nullable-указатели: edge выставляет null'ом то, что не применимо
// (entities-reference: resource_id, tls_*, asn, gео и т.д.).
//
// json.Number для status — поле приходит как int, но через float64 в
// generic decoder'е оно теряет точность; пишем как Number и парсим
// руками. Аналогично tls_cipher_count и latency_ms.
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
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.UseNumber()
	var r rawRecord
	if err := dec.Decode(&r); err != nil {
		return nil, err
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
		// raw — целая строка как jsonb. pgx сам конвертит []byte в jsonb,
		// валидность JSON pgx не проверяет — мы выше успешно его распарсили.
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
		// status/tls_cipher_count иногда могут прийти как float (например,
		// сериализатор выдал 200.0); пробуем float→int64.
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
		// pgx text[] не любит nil — отдаём пустой slice. В Postgres ляжет '{}'.
		return []string{}
	}
	return a
}

// readNDJSON разворачивает один спул-файл в []line. Каждая строка — отдельная
// запись BAC_LOG. Пустые строки пропускаем (хвостовой '\n').
func readNDJSON(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	// 1 MiB на строку — с запасом от 32 KiB receiver-cap'a.
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

// listSpoolFiles возвращает спул-файлы, отсортированные по имени (имя
// начинается с UnixNano → лексикографический порядок = хронологический).
// Пропускаем `.partial` (незаконченные spill'ы).
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
		if strings.HasSuffix(name, ".partial") {
			continue
		}
		if !strings.HasPrefix(name, "batch-") {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}
