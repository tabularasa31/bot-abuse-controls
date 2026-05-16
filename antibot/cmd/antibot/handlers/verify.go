package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"antibot/cmd/antibot/logging"
	"antibot/cmd/antibot/token"
)

// verifyRequest — тело запроса BotVerifyHandler. Поля приходят camelCase от JS-клиента.
//
//nolint:tagliatelle // inbound JSON from JS client uses camelCase
type verifyRequest struct {
	Nonce                string                 `json:"nonce"`
	Fingerprint          string                 `json:"fingerprint"`
	FingerprintSignature string                 `json:"fingerprintSignature"`
	Token                string                 `json:"token"`
	CaptchaVerified      bool                   `json:"captchaVerified"`
	HumanBehavior        map[string]interface{} `json:"humanBehavior"`
}

// BotVerifyHandler обрабатывает верификацию nonce и выдачу clearance cookie.
func (s *Server) BotVerifyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.withTimeout(r)
	defer cancel()

	logger := s.getLoggerWithContext(r)
	handler := getHandlerFromContext(r)

	if !s.preflightVerify(ctx, w, r, logger, handler) {
		return
	}

	req, newLogger, ok := s.decodeAndValidateVerifyRequest(ctx, w, r, logger)
	if !ok {
		return
	}
	logger = newLogger

	if !s.checkCaptchaAndBehavior(w, req, logger) {
		return
	}

	if !s.validateFingerprintAndToken(w, req, logger) {
		return
	}

	s.consumeNonceAndIssueClearance(ctx, w, req, logger, handler)
}

// preflightVerify проверяет метод, контекст и rate limit. Возвращает false при отклонении.
func (s *Server) preflightVerify(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	logger *logging.StructuredLogger,
	handler string,
) bool {
	if r.Method != http.MethodPost {
		if logger != nil {
			logger.Warn("Method not allowed", map[string]interface{}{"method": r.Method})
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before processing", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return false
	}

	clientIP := s.GetClientIP(r)
	if !s.RateLimiter.Allow(clientIP) {
		if s.Metrics != nil {
			s.Metrics.RecordRateLimitExceeded(handler)
		}
		if logger != nil {
			logger.Warn("Rate limit exceeded", map[string]interface{}{"ip": clientIP})
		}
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return false
	}
	return true
}

// decodeAndValidateVerifyRequest декодирует JSON и валидирует обязательные поля.
// Возвращает обновлённый logger (с nonce в контексте) после успешного декодирования.
func (s *Server) decodeAndValidateVerifyRequest(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	logger *logging.StructuredLogger,
) (*verifyRequest, *logging.StructuredLogger, bool) {
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before JSON decoding", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return nil, logger, false
	}

	var req verifyRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if logger != nil {
			logger.Warn("Failed to decode request", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, logger, false
	}

	// Обновляем контекст запроса nonce-ом для последующего логирования.
	r2 := setNonceInContext(r, req.Nonce)
	logger = s.getLoggerWithContext(r2)

	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled after JSON decoding", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return nil, logger, false
	}
	if !requireFields(w, &req) {
		return nil, logger, false
	}
	return &req, logger, true
}

// requireFields проверяет наличие обязательных полей запроса.
func requireFields(w http.ResponseWriter, req *verifyRequest) bool {
	switch {
	case req.Nonce == "":
		http.Error(w, "nonce required", http.StatusBadRequest)
		return false
	case req.Fingerprint == "":
		http.Error(w, "fingerprint required", http.StatusBadRequest)
		return false
	case req.FingerprintSignature == "":
		http.Error(w, "fingerprint signature required", http.StatusBadRequest)
		return false
	case req.Token == "":
		http.Error(w, "token required", http.StatusBadRequest)
		return false
	}
	return true
}

// checkCaptchaAndBehavior проверяет подтверждение капчи и поведенческие признаки.
func (s *Server) checkCaptchaAndBehavior(
	w http.ResponseWriter,
	req *verifyRequest,
	logger *logging.StructuredLogger,
) bool {
	if !req.CaptchaVerified {
		if s.Metrics != nil {
			s.Metrics.RecordCaptchaFailed()
		}
		if logger != nil {
			logger.Warn("Captcha not verified", map[string]interface{}{"nonce": req.Nonce})
		}
		http.Error(w, "captcha verification required", http.StatusForbidden)
		return false
	}
	if !s.checkHumanBehavior(w, req, logger) {
		return false
	}
	if s.Metrics != nil {
		s.Metrics.RecordCaptchaPassed()
	}
	return true
}

// consumeNonceAndIssueClearance валидирует nonce и устанавливает clearance cookie.
func (s *Server) consumeNonceAndIssueClearance(
	ctx context.Context,
	w http.ResponseWriter,
	req *verifyRequest,
	logger *logging.StructuredLogger,
	handler string,
) {
	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before nonce validation", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	// Атомарно проверяем и потребляем nonce (защита от race condition).
	// Важно: проверяем nonce ПОСЛЕ проверки токена, чтобы время выполнения
	// было одинаковым независимо от валидности nonce (защита от timing attacks).
	if !s.Nonces.ConsumeIfValid(req.Nonce) {
		if s.Metrics != nil {
			s.Metrics.RecordNonceOperation("invalid")
		}
		if logger != nil {
			logger.Warn("Nonce invalid or expired", map[string]interface{}{"nonce": req.Nonce})
		}
		http.Error(w, "nonce invalid or expired", http.StatusBadRequest)
		return
	}

	if s.Metrics != nil {
		s.Metrics.RecordNonceOperation("validated")
	}

	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before token creation", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	clearanceToken, err := token.CreateClearanceToken(s.MasterSecret, s.ClearanceTTL)
	if err != nil {
		if logger != nil {
			logger.Error("Failed to create clearance token", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := checkContext(ctx); err != nil {
		if logger != nil {
			logger.Warn("Request cancelled before setting cookie", map[string]interface{}{"error": err.Error()})
		}
		http.Error(w, err.Error(), contextStatus(err))
		return
	}

	if s.Metrics != nil {
		s.Metrics.RecordClearanceTokenIssued(handler)
		s.Metrics.RecordChallengePassed()
	}

	if logger != nil {
		logger.Info("Clearance token issued successfully", map[string]interface{}{"nonce": req.Nonce})
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "BOT_CLEARANCE",
		Value:    clearanceToken,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(s.ClearanceTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// validateFingerprintAndToken проверяет формат fingerprint, подпись, формат токена и его соответствие.
// Возвращает false, если запрос отклонён (ответ уже записан в w).
func (s *Server) validateFingerprintAndToken(
	w http.ResponseWriter,
	req *verifyRequest,
	logger *logging.StructuredLogger,
) bool {
	if len(req.Fingerprint) < 20 {
		http.Error(w, "invalid fingerprint format", http.StatusBadRequest)
		return false
	}
	if strings.Contains(req.Fingerprint, "bot_detection:webdriver:true") {
		if logger != nil {
			logger.Warn("Automated browser detected (webdriver)", map[string]interface{}{"nonce": req.Nonce})
		}
		http.Error(w, "automated browser detected", http.StatusForbidden)
		return false
	}
	botDetectionCount := strings.Count(req.Fingerprint, "bot_detection:")
	if botDetectionCount >= 2 {
		if logger != nil {
			logger.Warn("Multiple bot detection signs", map[string]interface{}{
				"nonce": req.Nonce,
				"signs": botDetectionCount,
			})
		}
		http.Error(w, "automated browser detected", http.StatusForbidden)
		return false
	}

	secret := token.DeriveSecret(req.Nonce, s.MasterSecret)

	expectedSignature := token.SignFingerprint(req.Fingerprint, secret)
	if !token.ConstantTimeCompare(req.FingerprintSignature, expectedSignature) {
		if logger != nil {
			logger.Warn("Fingerprint signature mismatch", map[string]interface{}{"nonce": req.Nonce})
		}
		http.Error(w, "invalid fingerprint signature", http.StatusBadRequest)
		return false
	}

	expectedToken := token.ComputeExpectedToken(req.Fingerprint, secret)
	if len(req.Token) != 64 {
		http.Error(w, "invalid token format", http.StatusBadRequest)
		return false
	}
	if _, err := hex.DecodeString(req.Token); err != nil {
		http.Error(w, "invalid token format", http.StatusBadRequest)
		return false
	}
	if !token.ConstantTimeCompare(req.Token, expectedToken) {
		if logger != nil {
			logger.Warn("Token mismatch", map[string]interface{}{"nonce": req.Nonce})
		}
		http.Error(w, "invalid token", http.StatusBadRequest)
		return false
	}
	return true
}

// checkHumanBehavior валидирует человеческие признаки в запросе.
// Возвращает false, если запрос отклонён (ответ уже записан в w).
func (s *Server) checkHumanBehavior(w http.ResponseWriter, req *verifyRequest, logger *logging.StructuredLogger) bool {
	if req.HumanBehavior == nil {
		return true
	}
	if !s.checkCaptchaTime(w, req, logger) {
		return false
	}
	if !s.checkMouseMoves(w, req, logger) {
		return false
	}
	return true
}

func (s *Server) checkCaptchaTime(w http.ResponseWriter, req *verifyRequest, logger *logging.StructuredLogger) bool {
	timeToComplete, ok := req.HumanBehavior["timeToComplete"].(float64)
	if !ok {
		return true
	}
	const minTimeMs = 2000.0 // Минимум 2 секунды
	if timeToComplete >= minTimeMs {
		return true
	}
	if logger != nil {
		logger.Warn("Suspicious captcha completion time", map[string]interface{}{
			"nonce": req.Nonce,
			"time":  timeToComplete,
		})
	}
	if s.Metrics != nil {
		s.Metrics.RecordCaptchaFailed()
	}
	http.Error(w, "suspicious behavior detected", http.StatusForbidden)
	return false
}

func (s *Server) checkMouseMoves(w http.ResponseWriter, req *verifyRequest, logger *logging.StructuredLogger) bool {
	mouseMoveCount, ok := req.HumanBehavior["mouseMoveCount"].(float64)
	if !ok {
		return true
	}
	const minMouseMoves = 3.0
	if mouseMoveCount >= minMouseMoves {
		return true
	}
	if logger != nil {
		logger.Warn("Insufficient mouse movements", map[string]interface{}{
			"nonce":      req.Nonce,
			"mouseMoves": mouseMoveCount,
		})
	}
	if s.Metrics != nil {
		s.Metrics.RecordCaptchaFailed()
	}
	http.Error(w, "suspicious behavior detected", http.StatusForbidden)
	return false
}
