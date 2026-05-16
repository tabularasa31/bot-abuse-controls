package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"antibot/cmd/antibot/logging"
)

// requestContextKey тип для ключа контекста запроса.
type requestContextKey string

const (
	requestIDKey requestContextKey = "request_id"
	ipKey        requestContextKey = "ip"
	nonceKey     requestContextKey = "nonce"
	handlerKey   requestContextKey = "handler"
	startTimeKey requestContextKey = "start_time"
)

// getRequestID извлекает request ID из контекста.
func getRequestID(r *http.Request) string {
	if id := r.Context().Value(requestIDKey); id != nil {
		return id.(string)
	}
	return ""
}

// getIPFromContext извлекает IP из контекста.
func getIPFromContext(r *http.Request) string {
	if ip := r.Context().Value(ipKey); ip != nil {
		return ip.(string)
	}
	return ""
}

// getNonceFromContext извлекает nonce из контекста.
func getNonceFromContext(r *http.Request) string {
	if nonce := r.Context().Value(nonceKey); nonce != nil {
		return nonce.(string)
	}
	return ""
}

// getHandlerFromContext извлекает handler из контекста.
func getHandlerFromContext(r *http.Request) string {
	if handler := r.Context().Value(handlerKey); handler != nil {
		return handler.(string)
	}
	return ""
}

// LoggingMiddleware добавляет контекст к запросу (request ID, IP, handler)
// Экспортированный метод для использования в main.go.
func (s *Server) LoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Генерируем request ID для каждого запроса
		requestID := uuid.New().String()

		// Извлекаем IP адрес
		clientIP := s.GetClientIP(r)

		// Определяем handler по пути
		handler := r.URL.Path
		switch handler {
		case "/bot-check":
			handler = "bot-check"
		case "/bot-verify":
			handler = "bot-verify"
		case "/bot-validate":
			handler = "bot-validate"
		case "/health":
			handler = "health"
		default:
			handler = "unknown"
		}

		// Добавляем контекст к запросу
		ctx := r.Context()
		ctx = context.WithValue(ctx, requestIDKey, requestID)
		ctx = context.WithValue(ctx, ipKey, clientIP)
		ctx = context.WithValue(ctx, handlerKey, handler)
		ctx = context.WithValue(ctx, startTimeKey, time.Now())

		// Создаём новый запрос с контекстом
		r = r.WithContext(ctx)

		// Вызываем следующий handler
		next(w, r)
	}
}

// setNonceInContext устанавливает nonce в контекст запроса.
func setNonceInContext(r *http.Request, nonce string) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, nonceKey, nonce)
	return r.WithContext(ctx)
}

// getLoggerWithContext возвращает логгер с контекстом из запроса.
func (s *Server) getLoggerWithContext(r *http.Request) *logging.StructuredLogger {
	if s.Logger == nil {
		return nil
	}

	return s.Logger.WithContext(
		getRequestID(r),
		getIPFromContext(r),
		getNonceFromContext(r),
		getHandlerFromContext(r),
	)
}
