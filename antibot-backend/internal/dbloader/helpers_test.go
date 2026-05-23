package dbloader_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// discardLogger — лог в /dev/null для тестов. NewReloader требует *slog.Logger,
// но проверять формат сообщений в этих тестах не нужно — Bootstrap/tick
// возвращают error напрямую.
func discardLogger(_ *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// discardReg — новый prometheus.Registry на тест, чтобы MustRegister'ы не
// конфликтовали между запусками одного процесса (parallel test runs).
func discardReg() prometheus.Registerer {
	return prometheus.NewRegistry()
}
