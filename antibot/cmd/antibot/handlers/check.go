package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"antibot/cmd/antibot/token"
)

// needCaptchaFor решает, требуется ли капча для текущего запроса.
// Если CAPTCHA_ENABLED=false, капча никогда не показывается.
// При наличии валидного score, превышающего threshold, капча также не показывается.
func (s *Server) needCaptchaFor(r *http.Request) bool {
	if !s.CaptchaEnabled {
		return false
	}
	scoreStr := r.URL.Query().Get("score")
	if scoreStr == "" {
		return true
	}
	score, err := strconv.ParseFloat(scoreStr, 64)
	if err != nil {
		return true
	}
	if s.ScoringEnabled && score >= s.ScoringModel.Threshold() {
		return false
	}
	return true
}

// BotCheckHandler генерирует nonce, сохраняет его и отдаёт страницу с JS-челленджем.
func (s *Server) BotCheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.withTimeout(r)
	defer cancel()

	logger := s.getLoggerWithContext(r)

	// Проверяем контекст перед началом обработки
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before processing", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	// После проверки всегда редиректим на сконфигурированный ReturnURL.
	// Игнорируем параметр ?return=, чтобы не было редиректов на /login и другие
	// произвольные пути (защита от open redirect и от подмены пути в nginx).
	returnURL := s.ReturnURL

	// Определяем, нужна ли капча
	needCaptcha := s.needCaptchaFor(r)

	nonce, err := generateRandomHex(16)
	if err != nil {
		if logger != nil {
			logger.Error("Failed to generate nonce", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Устанавливаем nonce в контекст для логирования
	r = setNonceInContext(r, nonce)
	logger = s.getLoggerWithContext(r)

	// Проверяем контекст перед операцией записи
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled during nonce generation", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	s.Nonces.Put(nonce)

	// Метрики
	if s.Metrics != nil {
		s.Metrics.RecordNonceOperation("created")
		s.Metrics.RecordChallengeShown()
		if needCaptcha {
			s.Metrics.RecordCaptchaShown() // Показываем капчу только при низком score
		}
	}

	if logger != nil {
		logger.Info("Nonce generated and stored", map[string]interface{}{"nonce": nonce})
	}

	// Генерируем уникальный секрет для этого nonce
	// Secret одноразовый (связан с nonce), поэтому даже если его перехватят,
	// он уже будет использован и не пригодится для повторного использования
	secret := token.DeriveSecret(nonce, s.MasterSecret)

	// Проверяем контекст перед JSON маршалингом
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before JSON marshaling", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	payload, err := json.Marshal(map[string]interface{}{
		"nonce":       nonce,
		"secret":      secret,      // Secret одноразовый, поэтому безопасно передавать клиенту
		"returnUrl":   returnURL,   // Всегда https://the platform.ru/ после проверки
		"needCaptcha": needCaptcha, // Нужна ли капча (только при низком score)
	})
	if err != nil {
		if logger != nil {
			logger.Error("Failed to marshal payload", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Проверяем контекст перед отправкой ответа
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before response", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	html := fmt.Sprintf(botCheckHTMLTemplate, string(payload))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}
