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
			Help: "BAC_LOG lines accepted by the receiver. Increments before parsing — counts what arrived, not what was understood.",
		}),
		parsed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_lines_parsed_total",
			Help: "BAC_LOG lines successfully parsed as JSON.",
		}),
		parseErr: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_lines_parse_errors_total",
			Help: "BAC_LOG lines rejected as invalid JSON. Receiver still 202s — one bad line per batch must not poison the rest of the batch.",
		}),
		botSpotted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_bot_ua_spotted_total",
			Help: "Lines with a known search-bot UA (Googlebot/bingbot/YandexBot/DuckDuckBot) — upper bound on rDNS enqueue attempts.",
		}),
		enqueue:  enqueue,
		classify: classify,
	}
	reg.MustRegister(r.received, r.parsed, r.parseErr, r.botSpotted)
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
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, `{"error":"request_too_large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		// Обрыв соединения / прочее IO — счётчик не двигаем, отвечать в
		// сломанный сокет смысла мало, но явный 400 пусть будет на случай,
		// если связь успела восстановиться к моменту записи.
		http.Error(w, `{"error":"read_failed"}`, http.StatusBadRequest)
		return
	}
	rcv.received.Add(float64(n))
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
