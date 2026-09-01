package dbloader_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// discardLogger — logging to /dev/null for the tests. NewReloader requires a *slog.Logger,
// but these tests need not check message formats — Bootstrap/tick
// return the error directly.
func discardLogger(_ *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// discardReg — a fresh prometheus.Registry per test, so that MustRegister calls do not
// clash between runs within one process (parallel test runs).
func discardReg() prometheus.Registerer {
	return prometheus.NewRegistry()
}
