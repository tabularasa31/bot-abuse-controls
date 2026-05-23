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
	"io"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

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

func (rcv *Receiver) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/logs", rcv.handle)
}

func (rcv *Receiver) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// Считаем строки по «\n» — достаточно, чтобы метрика двигалась под нагрузкой
	// от edge ([A2]). Парсинг JSON-схемы и батч-форвард в sink — B6.
	n, _ := countNewlines(r.Body)
	rcv.received.Add(float64(n))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted","note":"sink/batching wiring lands in B6/B9"}`))
}

func countNewlines(r io.Reader) (int, error) {
	const bufSize = 32 * 1024
	buf := make([]byte, bufSize)
	count := 0
	for {
		nr, err := r.Read(buf)
		for i := 0; i < nr; i++ {
			if buf[i] == '\n' {
				count++
			}
		}
		if err == io.EOF {
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
