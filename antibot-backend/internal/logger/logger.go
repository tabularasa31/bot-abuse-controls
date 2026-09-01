// Package logger — the single assembly point for the process's slog.Logger.
//
// Extracted from main so that (a) tests can instantiate the same logger without
// duplicating the options block and (b) if we ever move to a text handler in dev
// or to an OTel exporter, the change stays in one file.
package logger

import (
	"io"
	"log/slog"
	"os"
)

// New — the production logger: a JSON handler to stdout at level Info.
// It matches what main() wrote by hand before the extraction.
func New() *slog.Logger {
	return NewWithWriter(os.Stdout)
}

// NewWithWriter — for tests and redirection (to a file or a bytes.Buffer, say).
// The schema is identical to New(); only the sink differs.
func NewWithWriter(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
