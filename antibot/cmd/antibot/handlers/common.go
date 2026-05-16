package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"antibot/cmd/antibot/logging"
	"antibot/cmd/antibot/metrics"
	"antibot/cmd/antibot/nonce"
	"antibot/cmd/antibot/ratelimit"
	"antibot/cmd/antibot/scoring"
)

// statusClientClosedRequest — нестандартный код 499 (nginx-конвенция),
// используется когда клиент закрыл соединение до получения ответа.
const statusClientClosedRequest = 499

// Server представляет сервер с зависимостями для handlers.
type Server struct {
	Nonces         nonce.StoreInterface // Используем интерфейс для поддержки sharded store
	ClearanceTTL   time.Duration        // Время жизни clearance cookie
	MasterSecret   []byte
	RateLimiter    ratelimit.LimiterInterface
	ScoringModel   *scoring.Model
	ScoringEnabled bool // Включена ли модель scoring
	CaptchaEnabled bool // Включена ли капча (если false, капча никогда не показывается)
	GetClientIP    func(*http.Request) string
	MLLogger       *logging.Logger           // Логгер для ML данных
	RequestTimeout time.Duration             // Таймаут для обработки запросов
	Logger         *logging.StructuredLogger // Структурированный логгер
	Metrics        *metrics.Metrics          // Prometheus метрики
	ReturnURL      string                    // URL для редиректа после успешного challenge
}

// withTimeout устанавливает контекст с таймаутом для запроса.
func (s *Server) withTimeout(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.RequestTimeout)
}

// checkContext проверяет, не отменён ли контекст, и возвращает ошибку если да.
// Ошибка обёрнута через %w, поэтому errors.Is(err, context.DeadlineExceeded)
// и errors.Is(err, context.Canceled) работают для определения причины.
func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("request timeout: %w", ctx.Err())
		}
		return fmt.Errorf("request cancelled: %w", ctx.Err())
	default:
		return nil
	}
}

// contextStatus возвращает HTTP-статус для ошибки контекста:
// 408 Request Timeout — серверный таймаут (DeadlineExceeded),
// 499 Client Closed Request — клиент закрыл соединение (Canceled).
func contextStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusRequestTimeout
	}
	return statusClientClosedRequest
}

// generateRandomHex генерирует случайную hex строку заданной длины.
func generateRandomHex(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
