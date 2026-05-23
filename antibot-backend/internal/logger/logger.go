// Package logger — единая точка сборки slog.Logger для процесса.
//
// Вынесено из main, чтобы (а) тесты могли инстанцировать тот же логгер без
// дублирования options-блока и (б) если завтра поедем на text-handler в dev
// или на OTel-exporter, правка остаётся в одном файле.
package logger

import (
	"io"
	"log/slog"
	"os"
)

// New — production-логгер: JSON-handler в stdout, уровень Info.
// Совпадает с тем, что main() писал руками до выноса.
func New() *slog.Logger {
	return NewWithWriter(os.Stdout)
}

// NewWithWriter — для тестов и переадресации (например, в файл / в bytes.Buffer).
// Schema идентична New(), отличается только sink.
func NewWithWriter(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
