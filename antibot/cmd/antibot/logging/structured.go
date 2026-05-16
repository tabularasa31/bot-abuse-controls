package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel определяет уровень логирования.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

// String возвращает строковое представление уровня.
func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// ParseLogLevel парсит строку в LogLevel.
func ParseLogLevel(s string) LogLevel {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// LogEntry представляет структурированную запись лога.
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	RequestID string                 `json:"request_id,omitempty"`
	IP        string                 `json:"ip,omitempty"`
	Nonce     string                 `json:"nonce,omitempty"`
	Handler   string                 `json:"handler,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// StructuredLogger структурированный логгер с JSON выводом.
type StructuredLogger struct {
	mu        sync.Mutex
	writer    io.Writer
	minLevel  LogLevel
	requestID string // Текущий request ID из контекста
	ip        string // Текущий IP из контекста
	nonce     string // Текущий nonce из контекста
	handler   string // Текущий handler из контекста
}

// NewStructuredLogger создаёт новый структурированный логгер.
func NewStructuredLogger(writer io.Writer, minLevel LogLevel) *StructuredLogger {
	if writer == nil {
		writer = os.Stdout
	}
	return &StructuredLogger{
		writer:   writer,
		minLevel: minLevel,
	}
}

// WithContext создаёт копию логгера с контекстом.
func (l *StructuredLogger) WithContext(requestID, ip, nonce, handler string) *StructuredLogger {
	l.mu.Lock()
	defer l.mu.Unlock()

	return &StructuredLogger{
		writer:    l.writer,
		minLevel:  l.minLevel,
		requestID: requestID,
		ip:        ip,
		nonce:     nonce,
		handler:   handler,
	}
}

// log записывает лог с указанным уровнем.
func (l *StructuredLogger) log(level LogLevel, message string, fields map[string]interface{}, err error) {
	if level < l.minLevel {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level.String(),
		Message:   message,
		RequestID: l.requestID,
		IP:        l.ip,
		Nonce:     l.nonce,
		Handler:   l.handler,
		Fields:    fields,
	}

	if err != nil {
		entry.Error = err.Error()
	}

	jsonData, jsonErr := json.Marshal(entry)
	if jsonErr != nil {
		// Fallback на простой вывод если JSON не удался
		fmt.Fprintf(l.writer, "%s [%s] %s", entry.Timestamp, entry.Level, message)
		if err != nil {
			fmt.Fprintf(l.writer, " error=%v", err)
		}
		fmt.Fprintln(l.writer)
		return
	}

	fmt.Fprintln(l.writer, string(jsonData))
}

// Debug логирует сообщение уровня debug.
func (l *StructuredLogger) Debug(message string, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	l.log(LevelDebug, message, mergedFields, nil)
}

// Info логирует сообщение уровня info.
func (l *StructuredLogger) Info(message string, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	l.log(LevelInfo, message, mergedFields, nil)
}

// Warn логирует сообщение уровня warn.
func (l *StructuredLogger) Warn(message string, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	l.log(LevelWarn, message, mergedFields, nil)
}

// Error логирует сообщение уровня error.
func (l *StructuredLogger) Error(message string, err error, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	l.log(LevelError, message, mergedFields, err)
}

// Errorf логирует сообщение уровня error с форматированием.
func (l *StructuredLogger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(format, args...), nil, nil)
}

// Infof логирует сообщение уровня info с форматированием.
func (l *StructuredLogger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(format, args...), nil, nil)
}

// Warnf логирует сообщение уровня warn с форматированием.
func (l *StructuredLogger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(format, args...), nil, nil)
}
