package handlers

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"
)

// MetricsMiddleware обёртка для измерения метрик HTTP запросов.
func (s *Server) MetricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Metrics == nil {
			next(w, r)
			return
		}

		startTime := time.Now()
		handler := getHandlerFromContext(r)
		method := r.Method

		// Измеряем размер запроса
		var requestSize int64
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil {
				requestSize = int64(len(bodyBytes))
				// Восстанавливаем body для следующего handler
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		}

		// Обёртка для ResponseWriter для измерения размера ответа
		responseWriter := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			size:           0,
		}

		// Вызываем следующий handler
		next(responseWriter, r)

		// Записываем метрики
		duration := time.Since(startTime)
		statusCode := strconv.Itoa(responseWriter.statusCode)

		s.Metrics.RecordHTTPRequest(
			method,
			handler,
			statusCode,
			duration,
			requestSize,
			responseWriter.size,
		)
	}
}

// responseWriterWrapper обёртка для ResponseWriter для измерения размера ответа.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func (w *responseWriterWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	w.size += int64(len(b))
	return w.ResponseWriter.Write(b)
}
