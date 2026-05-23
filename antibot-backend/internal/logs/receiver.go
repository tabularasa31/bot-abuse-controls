// Package logs принимает поток BAC_LOG с эджей (вторая функция backend по
// ADR-005). Skeleton-уровень ([B2]): принимаем POST /v1/logs, считаем счётчик,
// возвращаем 202 — этого хватает, чтобы доказать "сервис принимает логи" из
// acceptance B2.
//
// Реальные части — валидация схемы, батч в sink, disk-queue на случай
// недоступности sink (логи не теряются) — задача [B6] поверх [B9] (sink:
// PostgreSQL → DuckDB/ClickHouse при росте). Edge-сторона (отправка лога) —
// часть [A2]/[B5].
package logs

import (
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

// readBufSize — размер чанка чтения тела. 32 KiB — стандартный io.Copy'шный
// компромисс между числом syscall'ов и пайплайнингом TCP.
const readBufSize = 32 * 1024

// bufPool переиспользует 32-KiB буферы между запросами — иначе под нагрузкой
// от edge (десятки RPS батчей) каждый POST аллоцировал бы 32 KiB и грузил GC.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, readBufSize)
		return &b
	},
}

type Receiver struct {
	received prometheus.Counter
}

func New(reg prometheus.Registerer) *Receiver {
	r := &Receiver{
		received: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_lines_received_total",
			Help: "BAC_LOG lines accepted by the receiver (skeleton: counted, not yet forwarded — sink wiring is B6/B9).",
		}),
	}
	reg.MustRegister(r.received)
	return r
}

// Register монтирует POST /v1/logs. Метод — на уровне ServeMux (Go 1.22+),
// чужие методы сразу отбиваются 405.
func (rcv *Receiver) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/logs", rcv.handle)
}

func (rcv *Receiver) handle(w http.ResponseWriter, r *http.Request) {
	// MaxBytesReader — твёрдый потолок на тело: при переборе чтение вернёт
	// ошибку *http.MaxBytesError, мы отвечаем 413 и НЕ инкрементим счётчик
	// (иначе атакующий мог бы накачивать метрику дёшево).
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer func() { _ = r.Body.Close() }()

	n, err := countNewlines(r.Body)
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

func countNewlines(r io.Reader) (int, error) {
	bufPtr, _ := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr
	count := 0
	for {
		nr, err := r.Read(buf)
		for i := 0; i < nr; i++ {
			if buf[i] == '\n' {
				count++
			}
		}
		if errors.Is(err, io.EOF) {
			// Хвост без \n — тоже строка.
			if nr > 0 && buf[nr-1] != '\n' {
				count++
			}
			return count, nil
		}
		if err != nil {
			return count, err
		}
	}
}
