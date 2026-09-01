// Package logs accepts the BAC_LOG stream from the edges (the backend's second function per
// ADR-005).
//
// The B2 skeleton level only counted lines and returned 202. In B7 the receiver
// gained one more responsibility — it is the backend's only point through
// which the rDNS worker learns about new IPs with a search engine UA (see vision §"The reverse-
// DNS worker": the check is triggered by the log stream itself, with no pre-emptive
// sweeping). The receiver parses every line as JSON and, when it sees an IP plus a
// bot UA, calls the Enqueuer (rdns.Worker).
//
// The sink side (validation for analytics, batching, the disk queue) lives in the
// internal/logsink package ([B9]); the receiver simply calls LogSink.Submit on every
// line. The edge side (sending the log) is part of [A2]/[B6].
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

// errOversizedLine — one line of the batch is longer than maxLineBytes. bufio.Scanner
// raises bufio.ErrTooLong; for the receiver that is "one broken line", not
// "a broken batch" — we answer 202 and increment parseErr, so that the edge does not
// retry the whole batch (which would duplicate the Enqueue for every good
// line before the bad one). See review.
var errOversizedLine = errors.New("logs: oversized line in batch")

// maxBodyBytes — the ceiling on one request body. The edge batches BAC_LOG as short
// lines; 10 MiB leaves room for a batch of hundreds of thousands of records while being a
// hard fuse against an accidental or malicious enormous POST.
// B6 will refine it once the real batch size is known.
const maxBodyBytes = 10 * 1024 * 1024

// maxLineBytes — the ceiling on one JSON line. The UA is capped at 2 KiB in bac_log.lua,
// and with the other fields a realistic maximum is ~4 KiB. 32 KiB leaves room for
// schema evolution and guards against an accidental huge line with no trailing '\n'.
const maxLineBytes = 32 * 1024

// Enqueuer — the sink for the rDNS worker. The receiver calls it for every
// JSON line with a known bot UA and a non-empty IP. The implementation is *rdns.Worker;
// the interface lives here so that the logs package does not depend on rdns (a cycle).
type Enqueuer interface {
	Enqueue(ip, claimedFamily string)
}

// LogSink — the BAC_LOG receiver ([B9]). The receiver submits every line
// here; the sink package parses, batches and writes into PostgreSQL with a disk-queue
// fallback of its own. The interface exists so that the receiver does not depend on logsink (impl
// — *logsink.Sink).
type LogSink interface {
	Submit(line []byte)
}

// FamilyClassifier — a function turning a UA string into a canonical bot
// family, or "" when the UA does not look like a search engine. The implementation is
// rdns.FamilyOfUA. It is injected through the constructor for the same reason as
// Enqueuer (dependency isolation).
type FamilyClassifier func(ua string) string

// logLine — the BAC_LOG fields the rDNS worker needs. The JSON arrives with far more
// fields (see infra/demo-stand/lua/bac_log.lua); we read only two and
// the decoder ignores the rest.
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
	sink     LogSink
}

// New returns a receiver with no rDNS integration and no sink (skeleton mode /
// tests that only need line counting).
func New(reg prometheus.Registerer) *Receiver {
	return NewWithDeps(reg, nil, nil, nil)
}

// NewWithEnqueuer — backward compatibility with the B7 start: a receiver with rDNS
// but no sink. Equivalent to NewWithDeps(..., nil).
func NewWithEnqueuer(reg prometheus.Registerer, enqueue Enqueuer, classify FamilyClassifier) *Receiver {
	return NewWithDeps(reg, enqueue, classify, nil)
}

// NewWithDeps — a receiver with both optional dependencies. Either of
// them may be nil:
//   - enqueue+classify both set → dispatch into the rDNS worker (the B7 function);
//   - sink set → every line goes to logsink (the B9 function);
//   - everything nil → skeleton mode, only the received counter.
func NewWithDeps(reg prometheus.Registerer, enqueue Enqueuer, classify FamilyClassifier, sink LogSink) *Receiver {
	r := &Receiver{
		received: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "antibot_backend_log_lines_received_total",
			Help: "BAC_LOG lines accepted by the receiver. Counts every line read from the body, regardless of parse outcome.",
		}),
		enqueue:  enqueue,
		classify: classify,
		sink:     sink,
	}
	reg.MustRegister(r.received)
	// parsed/parseErr/botSpotted are metrics of the dispatch path. In skeleton
	// mode (enqueue==nil) the dispatch returns early and these counters
	// would never move while sitting at zero in /metrics — the operator
	// would see a flatline and think the receiver was broken. We register them
	// only when the dispatch really works. From review.
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

// Register mounts POST /v1/logs. The method is pinned at the ServeMux level (Go 1.22+),
// so other methods are rejected with a 405 immediately.
func (rcv *Receiver) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/logs", rcv.handle)
}

// bufPool reuses scanner buffers between requests — otherwise, under
// load from the edge, every POST would allocate 32 KiB and load the GC.
//
// make with length maxLineBytes (rather than a cap with zero length): bufio.Scanner.Buffer
// does `buf[0:cap(buf)]`, so the cap alone would suffice; but `len=maxLineBytes`
// makes the pool's contract explicit ("a full-size ready buffer") without depending
// on Scanner's internals. From review.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxLineBytes)
		return &b
	},
}

func (rcv *Receiver) handle(w http.ResponseWriter, r *http.Request) {
	// MaxBytesReader — a hard ceiling on the body: on an overflow the read returns
	// an *http.MaxBytesError, we answer 413 and do NOT increment the counter
	// (otherwise an attacker could inflate the metric cheaply).
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer func() { _ = r.Body.Close() }()

	n, err := rcv.consume(r.Body)
	// received is always incremented by the number of lines processed, even when we
	// return a 4xx afterwards: the dispatch may already have called Enqueue/parseErr/botSpotted
	// for the lines BEFORE the error, and without received_total we would get metrics where
	// botSpotted > received (an inversion that breaks capacity planning).
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
			// One line of the batch is longer than maxLineBytes. We answer 202 —
			// the edge must not retry because of one bad line
			// (otherwise the Enqueue for every good line before it
			// would be duplicated). parseErr was already incremented in consume().
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"accepted","note":"oversized line skipped"}`))
			return
		}
		// A dropped connection or other IO — writing into a broken socket
		// makes little sense, but let there be an explicit 400 in case the
		// link recovered by the time of the write.
		http.Error(w, `{"error":"read_failed"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted","note":"sink/batching wiring lands in B6/B9"}`))
}

// consume reads the body line by line, parses each as JSON and, for lines with a
// bot UA, calls enqueue. It returns the number of lines (invalid ones included —
// the received counter counts "what arrived", and parseErr is a separate metric).
//
// The BAC_LOG contract from bac_log.lua: one JSON record per line,
// separated by \n, and the last line may lack a \n.
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
		// We call the sink unconditionally — it parses and batches on its own. In skeleton
		// mode (sink==nil) we skip it; the rDNS path works independently.
		if rcv.sink != nil {
			rcv.sink.Submit(line)
		}
		rcv.dispatch(line)
	}
	if err := sc.Err(); err != nil {
		// bufio.ErrTooLong — one line longer than maxLineBytes. That is
		// "a broken line", not "a broken batch": we count it as parseErr and
		// return a sentinel error that handle() maps to a
		// 202 instead of a 400/ErrServerClosed. See errOversizedLine.
		if errors.Is(err, bufio.ErrTooLong) {
			// parseErr is registered only when enqueue exists (in skeleton
			// mode there is no counter). We guard against a nil deref.
			if rcv.parseErr != nil {
				rcv.parseErr.Inc()
			}
			// An oversized line never reaches sink.Submit below — the scanner rejected it.
			// There will be no movement in antibot_backend_log_sink_*;
			// an analytics dashboard should treat parse_errors_total at the
			// receiver level as the full picture of losses (from code review).
			return count, errOversizedLine
		}
		return count, err
	}
	return count, nil
}

// dispatch — parses one JSON line and, if the IP and UA carry a search engine
// bot, calls enqueue. Any parse error increments parseErr and is
// silently skipped: the receiver does not answer 4xx because of one broken line
// (one malformed batch must not take down the rest of that batch's lines).
func (rcv *Receiver) dispatch(line []byte) {
	if rcv.enqueue == nil || rcv.classify == nil {
		// Skeleton mode: rdns is not wired in, so there is nothing to parse for.
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
	// Enqueue checks the catalog and in-flight state itself and decides whether to
	// really send it to the DNS queue.
	rcv.enqueue.Enqueue(ll.IP, family)
}
