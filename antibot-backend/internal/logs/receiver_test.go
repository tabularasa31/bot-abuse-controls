// receiver_test — покрывает parsing + Enqueue-интеграцию. Тестирует только
// HTTP-handler через httptest; rDNS-зависимости заменены на запись в slice.
package logs_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tabularasa31/antibot-backend/internal/logs"
)

func postLogs(t *testing.T, url string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

type enq struct {
	mu   sync.Mutex
	rows []row
}
type row struct{ ip, family string }

func (e *enq) Enqueue(ip, family string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rows = append(e.rows, row{ip, family})
}

// классификатор — упрощённый: ищем "Googlebot"/"bingbot" в UA.
func classify(ua string) string {
	switch {
	case strings.Contains(strings.ToLower(ua), "googlebot"):
		return "google"
	case strings.Contains(strings.ToLower(ua), "bingbot"):
		return "bing"
	}
	return ""
}

func newSrv(t *testing.T) (*httptest.Server, *enq) {
	t.Helper()
	e := &enq{}
	reg := prometheus.NewRegistry()
	rcv := logs.NewWithEnqueuer(reg, e, classify)
	mux := http.NewServeMux()
	rcv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, e
}

func TestReceiver_EnqueuesBotUAs(t *testing.T) {
	ts, e := newSrv(t)
	body := strings.Join([]string{
		`{"ip":"66.249.66.1","ua":"Googlebot/2.1"}`,
		`{"ip":"1.2.3.4","ua":"curl/7"}`,                          // не бот — игнор
		`{"ip":"40.77.167.1","ua":"Mozilla/5.0 ... bingbot/2.0"}`, // бот
		`{"ip":"","ua":"Googlebot"}`,                              // пустой IP — игнор
		`{not-json}`,                                              // битый JSON — игнор + parseErr
	}, "\n")
	resp := postLogs(t, ts.URL+"/v1/logs", bytes.NewBufferString(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d want 202", resp.StatusCode)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.rows) != 2 {
		t.Fatalf("enqueued=%d, want 2: %+v", len(e.rows), e.rows)
	}
	if e.rows[0] != (row{"66.249.66.1", "google"}) || e.rows[1] != (row{"40.77.167.1", "bing"}) {
		t.Errorf("rows=%+v", e.rows)
	}
}

func TestReceiver_AcceptsEmptyBody(t *testing.T) {
	ts, e := newSrv(t)
	resp := postLogs(t, ts.URL+"/v1/logs", bytes.NewBuffer(nil))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d want 202 on empty body", resp.StatusCode)
	}
	if len(e.rows) != 0 {
		t.Errorf("no enqueue expected on empty body, got %+v", e.rows)
	}
}

func TestReceiver_MethodNotAllowed(t *testing.T) {
	ts, _ := newSrv(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/v1/logs", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", resp.StatusCode)
	}
}
