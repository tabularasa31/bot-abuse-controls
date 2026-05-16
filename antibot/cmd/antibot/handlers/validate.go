package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"antibot/cmd/antibot/logging"
	"antibot/cmd/antibot/scoring"
	"antibot/cmd/antibot/token"
)

// verdictChallenge — вердикт, требующий прохождения JS-челленджа.
const verdictChallenge = "challenge"

// ValidateResponse содержит ответ от BotValidateHandler.
type ValidateResponse struct {
	Score     float64 `json:"score"`     // Вычисленный score
	Verdict   string  `json:"verdict"`   // Вердикт: "allow" или "challenge"
	Threshold float64 `json:"threshold"` // Порог для принятия решения
}

// buildMLEvent создаёт событие для ML логирования из метаданных запроса.
func (s *Server) buildMLEvent(
	r *http.Request,
	metadata *scoring.Metadata,
	score float64,
	verdict string,
	hasClearance bool,
	clearanceValid bool,
	startTime time.Time,
) *logging.Event {
	// Извлекаем дополнительные признаки из запроса
	referer := r.Header.Get("Referer")
	refererDomain := ""
	if referer != "" {
		if u, err := url.Parse(referer); err == nil {
			refererDomain = u.Hostname()
		}
	}

	// Подсчитываем заголовки
	headerCount := len(r.Header)
	hasAccept := r.Header.Get("Accept") != ""
	hasConnection := r.Header.Get("Connection") != ""
	hasSecFetch := r.Header.Get("Sec-Fetch-Site") != "" ||
		r.Header.Get("Sec-Fetch-Mode") != "" ||
		r.Header.Get("Sec-Fetch-User") != ""
	hasUpgradeInsecure := r.Header.Get("Upgrade-Insecure-Requests") != ""

	// Определяем ground truth на основе clearance cookie
	groundTruth := ""
	if hasClearance && clearanceValid {
		groundTruth = "human" // Валидный clearance означает, что пользователь прошёл challenge
	} else if verdict == verdictChallenge {
		// Если показан challenge, ground truth пока неизвестен
		groundTruth = ""
	}

	return &logging.Event{
		Timestamp: time.Now(),
		RequestID: "", // Будет сгенерирован в логгере
		Features: logging.Features{
			IPHash:             logging.HashIP(metadata.IP),
			UserAgent:          metadata.UserAgent,
			UserAgentLength:    len(metadata.UserAgent),
			AcceptLanguage:     metadata.AcceptLanguage,
			AcceptEncoding:     metadata.AcceptEncoding,
			HasStandardHeaders: metadata.HasStandardHeaders,
			HasCookies:         metadata.HasCookies,
			ClientType:         metadata.ClientType,
			HeaderCount:        headerCount,
			HasAccept:          hasAccept,
			HasConnection:      hasConnection,
			HasSecFetch:        hasSecFetch,
			HasUpgradeInsecure: hasUpgradeInsecure,
			Method:             r.Method,
			Path:               r.URL.Path,
			HasReferer:         referer != "",
			RefererDomain:      refererDomain,
		},
		ModelOutput: logging.ModelOutput{
			ComputedScore: score,
			Threshold:     s.ScoringModel.Threshold(),
			Verdict:       verdict,
		},
		Labels: logging.Labels{
			HasClearance:    hasClearance,
			ClearanceValid:  clearanceValid,
			ChallengeShown:  verdict == verdictChallenge,
			ChallengePassed: nil, // Будет установлено в BotVerifyHandler
			GroundTruth:     groundTruth,
		},
		Metadata: logging.EventMetadata{
			Handler:        "bot-validate",
			ResponseTimeMs: float64(time.Since(startTime).Nanoseconds()) / 1e6,
		},
	}
}

// BotValidateHandler проверяет валидность clearance cookie и вычисляет score
// Вызывается nginx на edge серверах перед проксированием запроса на origin
// Возвращает JSON с score и вердиктом (allow/challenge).
func (s *Server) BotValidateHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.withTimeout(r)
	defer cancel()

	startTime := time.Now()
	logger := s.getLoggerWithContext(r)
	handler := getHandlerFromContext(r)

	// Проверяем контекст перед началом обработки
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before processing", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	// Rate limiting: защита от брутфорса и DDoS
	// Проверяем rate limit ДО вычисления score для экономии ресурсов
	clientIP := s.GetClientIP(r)
	if !s.RateLimiter.Allow(clientIP) {
		// Метрики
		if s.Metrics != nil {
			s.Metrics.RecordRateLimitExceeded(handler)
		}
		if logger != nil {
			logger.Warn("Rate limit exceeded", map[string]interface{}{"ip": clientIP})
		}
		// Возвращаем 403 (challenge) при превышении rate limit
		// Это заставит nginx редиректить на /bot-check
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Bot-Verdict", verdictChallenge)
		w.Header().Set("X-Bot-Score", "0.00")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(ValidateResponse{
			Score:     0.0,
			Verdict:   verdictChallenge,
			Threshold: s.ScoringModel.Threshold(),
		}); err != nil && logger != nil {
			logger.Error("Failed to encode rate-limit response", err)
		}
		return
	}

	// Собираем HTTP-метаданные всегда — ClientType нужен для решения о challenge
	// независимо от того, включён ли scoring
	metadata := scoring.CollectMetadata(r, s.GetClientIP)

	var score float64
	if s.ScoringEnabled {
		// Проверяем контекст перед вычислением score
		if err := checkContext(ctx); err != nil {
			if logger != nil {
				logger.Warn("Request cancelled before score computation", map[string]interface{}{"error": err.Error()})
			}
			http.Error(w, err.Error(), contextStatus(err))
			return
		}

		// Вычисляем score
		score = s.ScoringModel.ComputeScore(metadata)

		// Метрики - записываем bot score
		if s.Metrics != nil {
			s.Metrics.RecordBotScore(handler, score)
		}
	}

	// Проверяем контекст перед проверкой clearance
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before clearance validation", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	// Проверяем clearance cookie (если есть)
	hasClearance, clearanceValid := s.checkClearance(r, logger)

	// Определяем вердикт на основе clearance cookie и типа клиента
	verdict, score := s.computeVerdict(hasClearance, clearanceValid, metadata, score)

	// Проверяем контекст перед логированием и отправкой ответа
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before response", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	// Логируем событие для ML (асинхронно, не блокирует ответ)
	if s.MLLogger != nil {
		event := s.buildMLEvent(r, metadata, score, verdict, hasClearance, clearanceValid, startTime)
		event.RequestID = getRequestID(r)
		s.MLLogger.Log(event)
	}

	// Структурированное логирование
	if logger != nil {
		responseTime := time.Since(startTime)
		logger.Info("Request processed", map[string]interface{}{
			"score":            score,
			"verdict":          verdict,
			"has_clearance":    hasClearance,
			"clearance_valid":  clearanceValid,
			"response_time_ms": float64(responseTime.Nanoseconds()) / 1e6,
		})
	}

	s.writeValidateResponse(ctx, w, logger, score, verdict)
}

// checkClearance проверяет наличие и валидность clearance cookie.
func (s *Server) checkClearance(r *http.Request, logger *logging.StructuredLogger) (hasClearance, clearanceValid bool) {
	cookie, err := r.Cookie("BOT_CLEARANCE")
	if err != nil {
		return false, false
	}
	hasClearance = true
	clearanceValid = token.ValidateClearanceToken(cookie.Value, s.MasterSecret)
	if s.Metrics != nil {
		s.Metrics.RecordClearanceTokenValidated(clearanceValid)
	}
	if logger != nil {
		logger.Debug("Clearance cookie checked", map[string]interface{}{
			"has_clearance": hasClearance,
			"valid":         clearanceValid,
		})
	}
	return hasClearance, clearanceValid
}

// computeVerdict определяет вердикт и (если scoring включён) корректирует score.
func (s *Server) computeVerdict(
	hasClearance, clearanceValid bool,
	metadata *scoring.Metadata,
	score float64,
) (string, float64) {
	switch {
	case hasClearance && clearanceValid:
		if s.ScoringEnabled {
			score = s.ScoringModel.Threshold() + 1.0
		}
		return "allow", score
	case metadata.ClientType == "browser":
		return verdictChallenge, score
	default:
		return "allow", score
	}
}

// writeValidateResponse кодирует и отправляет ответ BotValidateHandler.
func (s *Server) writeValidateResponse(
	ctx context.Context,
	w http.ResponseWriter,
	logger *logging.StructuredLogger,
	score float64,
	verdict string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Bot-Verdict", verdict)
	w.Header().Set("X-Bot-Score", fmt.Sprintf("%.2f", score))

	if verdict == verdictChallenge {
		w.WriteHeader(http.StatusForbidden)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	response := ValidateResponse{
		Score:     score,
		Verdict:   verdict,
		Threshold: s.ScoringModel.Threshold(),
	}

	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled during JSON encoding", map[string]interface{}{"error": err.Error()})
		}
		return
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		if logger != nil {
			logger.Error("Failed to encode validate response", err)
		}
	}
}
