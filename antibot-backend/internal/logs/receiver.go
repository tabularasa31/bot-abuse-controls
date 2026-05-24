// Package logs принимает поток BAC_LOG с эджей (вторая функция backend по
// ADR-005).
//
// Skeleton-уровень B2 только считал строки и возвращал 202. В B7 receiver
// получил ещё одну ответственность — это единственная точка backend'а, через
// которую rDNS-воркер узнаёт о новых IP с поисковым UA (см. vision §"Reverse-
// DNS воркер": триггер на проверку именно поток логов, никакого превентивного
// перебора). Receiver парсит каждую строку как JSON, и если видит IP +
// бот-UA — дёргает Enqueuer (rdns.Worker).
//
// Реальные части — валидация схемы под аналитику, батч в sink, disk-queue
// на случай недоступности sink (логи не теряются) — задача [B6] поверх [B9]
// (sink: PostgreSQL → DuckDB/ClickHouse). Edge-сторона (отправка лога) —
// часть [A2]/[B5].
package logs

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// errOversizedLine — одна строка батча длиннее maxLineBytes. bufio.Scanner
// поднимает bufio.ErrTooLong; для receiver это "одна битая строка", а не
// "битый батч" — отвечаем 202 и инкрементим parseErr, чтобы edge не
// ретраил весь батч (что задублировало бы Enqueue для всех нормальных
// строк до плохой). См. PR #53 review.
var errOversizedLine = errors.New("logs: oversized line in batch")

// maxBodyBytes — потолок на одно тело запроса. Edge батчит BAC_LOG короткими
// строками; 10 MiB — с запасом на батч из сотен тысяч записей и одновременно
// твёрдый предохранитель от случайного/злонамеренного огромного POST'а.
// B6 уточнит, когда будет известен реальный размер батча.
const maxBodyBytes = 10 * 1024 * 1024

// maxLineBytes — потолок на одну JSON-строку. UA capped в bac_log.lua на 2 KiB,
// плюс остальные поля — реалистичный максимум ~4 KiB. 32 KiB с запасом на
// эволюцию схемы; защита от случайной huge-line без хвоста '\n'.
const maxLineBytes = 32 * 1024

// Enqueuer — sink для rDNS-воркера. Receiver зовёт его для каждой
// JSON-строки с известным бот-UA и непустым IP. Реализация — *rdns.Worker;
// интерфейс здесь, чтобы пакет logs не зависел от rdns (cycle).
type Enqueuer interface {
	Enqueue(ip, claimedFamily string)
}

// FamilyClassifier — функция, превращающая UA-строку в каноничную семью
// бота или "" если UA не похож на поискового. Реализация —
// rdns.FamilyOfUA. Инжектится через конструктор по той же причине, что
// Enqueuer (изоляция зависимостей).
type FamilyClassifier func(ua string) string

// logLine — поля BAC_LOG, нужные rDNS-воркеру. JSON приходит с большим
// числом полей (см. infra/demo-stand/lua/bac_log.lua); читаем только два,
// всё остальное игнорируется decoder'ом.
type logLine struct {
	IP string `json:"ip"`
	UA string `json:"ua"`
}

type Receiver struct {
	received   prometheus.Counter
	parsed     prometheus.Counter
	parseErr   prometheus.Counter
	botSpotted prometheus.Counter

	enqueue  Enqueuer
	classify FamilyClassifier
}

// New возвращает receiver без rDNS-интеграции (skeleton-режим / тесты,
// которым нужен только подсчёт строк).
func New(reg prometheus.Registerer) *Receiver {
	return NewWithEnqueuer(reg, nil, nil)
}

// NewWithEnqueuer возвращает receiver, который дополнительно дёргает
// enqueue.Enqueue для каждой строки с известным бот-UA. enqueue/classify
// могут быть nil — тогда receiver работает как скелетный счётчик. Если
// задана одна — должна быть задана и вторая.
func NewWithEnqueuer(reg prometheus.Registerer, enqueue Enqueuer, classify FamilyClassifier) *Receiver {
	r := &Receiver{
		received: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_lines_received_total",
			Help: "BAC_LOG lines accepted by the receiver. Counts every line read from the body, regardless of parse outcome.",
		}),
		enqueue:  enqueue,
		classify: classify,
	}
	reg.MustRegister(r.received)
	// parsed/parseErr/botSpotted — это метрики dispatch-пути. В skeleton-
	// режиме (enqueue==nil) dispatch уходит в ранний return и эти счётчики
	// никогда не двигались бы, но висели в /metrics на нуле — оператор
	// видел бы flatline и думал, что receiver сломан. Регистрируем их
	// только когда dispatch реально работает. PR #53 review.
	if enqueue != nil && classify != nil {
		r.parsed = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_lines_parsed_total",
			Help: "BAC_LOG lines successfully parsed as JSON.",
		})
		r.parseErr = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_lines_parse_errors_total",
			Help: "BAC_LOG lines rejected as invalid JSON / oversized. Receiver still 202s — one bad line per batch must not poison the rest of the batch.",
		})
		r.botSpotted = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_bot_ua_spotted_total",
			Help: "Lines with a known search-bot UA (Googlebot/bingbot/YandexBot/DuckDuckBot) — upper bound on rDNS enqueue attempts.",
		})
		reg.MustRegister(r.parsed, r.parseErr, r.botSpotted)
	}
	return r
}

// Register монтирует POST /v1/logs. Метод — на уровне ServeMux (Go 1.22+),
// чужие методы сразу отбиваются 405.
func (rcv *Receiver) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/logs", rcv.handle)
}

// bufPool переиспользует scanner-буферы между запросами — иначе под
// нагрузкой от edge каждый POST аллоцировал бы 32 KiB и грузил GC.
//
// make длиной maxLineBytes (не cap'ом нулевой длины): bufio.Scanner.Buffer
// делает `buf[0:cap(buf)]`, так что cap уже достаточен; но `len=maxLineBytes`
// делает контракт пула явным («полноразмерный готовый буфер»), не зависим
// от внутренней реализации Scanner. PR #53 gemini review.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxLineBytes)
		return &b
	},
}

func (rcv *Receiver) handle(w http.ResponseWriter, r *http.Request) {
	// MaxBytesReader — твёрдый потолок на тело: при переборе чтение вернёт
	// ошибку *http.MaxBytesError, мы отвечаем 413 и НЕ инкрементим счётчик
	// (иначе атакующий мог бы накачивать метрику дёшево).
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer func() { _ = r.Body.Close() }()

	n, err := rcv.consume(r.Body)
	// received инкрементим всегда по числу обработанных строк, даже если
	// дальше вернём 4xx: dispatch уже мог дёрнуть Enqueue/parseErr/botSpotted
	// для строк ДО ошибки, и без received_total получились бы метрики
	// botSpotted > received (инверсия, ломающая capacity-планирование).
	// PR #53 review.
	if n > 0 {
		rcv.received.Add(float64(n))
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, `{"error":"request_too_large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		if errors.Is(err, errOversizedLine) {
			// Одна строка батча длиннее maxLineBytes. Отвечаем 202 —
			// edge не должен ретраить из-за одной плохой строки
			// (иначе Enqueue для всех нормальных строк до неё
			// задвоится). parseErr уже инкрементирован в consume().
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"accepted","note":"oversized line skipped"}`))
			return
		}
		// Обрыв соединения / прочее IO — отвечать в сломанный сокет
		// смысла мало, но явный 400 пусть будет на случай, если связь
		// успела восстановиться к моменту записи.
		http.Error(w, `{"error":"read_failed"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted","note":"sink/batching wiring lands in B6/B9"}`))
}

// consume читает тело построчно, парсит каждую как JSON и для строк с
// бот-UA дёргает enqueue. Возвращает число строк (включая невалидные —
// received-счётчик считает «что приехало», parseErr — отдельная метрика).
//
// Контракт BAC_LOG из bac_log.lua: одна JSON-запись на строку,
// разделитель \n, последняя строка может быть без \n.
func (rcv *Receiver) consume(body io.Reader) (int, error) {
	bufPtr, _ := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	sc := bufio.NewScanner(body)
	sc.Buffer(buf, maxLineBytes)

	count := 0
	for sc.Scan() {
		count++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		rcv.dispatch(line)
	}
	if err := sc.Err(); err != nil {
		// bufio.ErrTooLong — одна строка длиннее maxLineBytes. Это
		// "битая строка", а не "битый батч": считаем как parseErr и
		// возвращаем sentinel'ную ошибку, которую handle() мапит в
		// 202 вместо 400/ErrServerClosed. См. errOversizedLine.
		if errors.Is(err, bufio.ErrTooLong) {
			// parseErr регистрируется только когда есть enqueue (skeleton-
			// режим без него — без счётчика). Защищаем nil-deref.
			if rcv.parseErr != nil {
				rcv.parseErr.Inc()
			}
			return count, errOversizedLine
		}
		return count, err
	}
	return count, nil
}

// dispatch — парсит одну JSON-строку и, если IP+UA содержат поискового
// бота, дёргает enqueue. Любая ошибка парсинга — инкремент parseErr и
// тихий пропуск: receiver не отвечает 4xx за одну битую строку
// (один кривой батч не должен ронять остальные строки этого батча).
func (rcv *Receiver) dispatch(line []byte) {
	if rcv.enqueue == nil || rcv.classify == nil {
		// Skeleton-режим: rdns не подключён, парсить незачем.
		return
	}
	var ll logLine
	if err := json.Unmarshal(line, &ll); err != nil {
		rcv.parseErr.Inc()
		return
	}
	rcv.parsed.Inc()
	if ll.IP == "" || ll.UA == "" {
		return
	}
	family := rcv.classify(ll.UA)
	if family == "" {
		return
	}
	rcv.botSpotted.Inc()
	// Enqueue сам проверит catalog/in-flight и решит, реально ли
	// слать в DNS-очередь.
	rcv.enqueue.Enqueue(ll.IP, family)
}
