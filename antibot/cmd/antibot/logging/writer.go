package logging

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

// Writer интерфейс для записи событий.
type Writer interface {
	Write(event *Event) error
	Close() error
}

// JSONLWriter записывает события в JSONL файл.
type JSONLWriter struct {
	file   *os.File
	writer *bufio.Writer
	mu     sync.Mutex
}

// NewJSONLWriter создаёт новый JSONL writer.
func NewJSONLWriter(filepath string) (*JSONLWriter, error) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	return &JSONLWriter{
		file:   file,
		writer: bufio.NewWriter(file),
	}, nil
}

// Write записывает событие в файл.
func (w *JSONLWriter) Write(event *Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := w.writer.Write(data); err != nil {
		return err
	}

	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}

	return w.writer.Flush()
}

// Close закрывает файл.
func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}

	return w.file.Close()
}
