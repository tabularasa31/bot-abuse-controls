//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Integration тесты требуют флаг -tags=integration при запуске
// go test -tags=integration ./cmd/antibot

func TestBotCheckHandlerIntegration(t *testing.T) {
	masterSecret, _ := generateMasterSecret()
	s := &server{
		nonces:       newNonceStore(1 * time.Minute),
		clearanceTTL: 1 * time.Hour,
		masterSecret: masterSecret,
		rateLimiter:  newRateLimiter(100, 1*time.Minute),
	}

	req := httptest.NewRequest("GET", "/bot-check?return=/test", nil)
	w := httptest.NewRecorder()

	s.botCheckHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("response body should not be empty")
	}

	// Проверяем, что в HTML есть JavaScript
	if !strings.Contains(body, "bot-check") && !strings.Contains(body, "bot-verify") {
		t.Error("response should contain JavaScript challenge code")
	}
}

func TestBotVerifyHandlerIntegration(t *testing.T) {
	masterSecret, _ := generateMasterSecret()
	s := &server{
		nonces:       newNonceStore(1 * time.Minute),
		clearanceTTL: 1 * time.Hour,
		masterSecret: masterSecret,
		rateLimiter:  newRateLimiter(100, 1*time.Minute),
	}

	// Сначала получаем nonce и secret
	checkReq := httptest.NewRequest("GET", "/bot-check", nil)
	checkW := httptest.NewRecorder()
	s.botCheckHandler(checkW, checkW)

	// Генерируем тестовые данные
	nonce, _ := generateRandomHex(16)
	s.nonces.put(nonce)
	secret := s.deriveSecret(nonce)
	fingerprint := "test-fingerprint|userAgent|1920x1080|en|0"
	token := computeExpectedToken(fingerprint, secret)
	signature := signFingerprint(fingerprint, secret)

	// Создаём запрос верификации
	verifyData := map[string]string{
		"nonce":                nonce,
		"fingerprint":          fingerprint,
		"fingerprintSignature": signature,
		"token":                token,
	}

	body, _ := json.Marshal(verifyData)
	verifyReq := httptest.NewRequest("POST", "/bot-verify", bytes.NewReader(body))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyW := httptest.NewRecorder()

	s.botVerifyHandler(verifyW, verifyReq)

	if verifyW.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", verifyW.Code, verifyW.Body.String())
	}

	// Проверяем, что установлена cookie
	cookies := verifyW.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "BOT_CLEARANCE" {
			found = true
			if cookie.Value == "" {
				t.Error("clearance cookie should have a value")
			}
		}
	}

	if !found {
		t.Error("BOT_CLEARANCE cookie should be set")
	}
}

func TestFullFlowIntegration(t *testing.T) {
	masterSecret, _ := generateMasterSecret()
	s := &server{
		nonces:       newNonceStore(1 * time.Minute),
		clearanceTTL: 1 * time.Hour,
		masterSecret: masterSecret,
		rateLimiter:  newRateLimiter(100, 1*time.Minute),
	}

	// 1. Запрос на /bot-check
	checkReq := httptest.NewRequest("GET", "/bot-check?return=/test", nil)
	checkW := httptest.NewRecorder()
	s.botCheckHandler(checkW, checkReq)

	if checkW.Code != http.StatusOK {
		t.Fatalf("bot-check failed with status %d", checkW.Code)
	}

	// 2. Извлекаем nonce и secret из HTML (упрощённо)
	nonce, _ := generateRandomHex(16)
	s.nonces.put(nonce)
	secret := s.deriveSecret(nonce)

	// 3. Создаём валидный fingerprint и токен
	fingerprint := "test-fingerprint|userAgent|1920x1080|en|0"
	token := computeExpectedToken(fingerprint, secret)
	signature := signFingerprint(fingerprint, secret)

	// 4. Верификация
	verifyData := map[string]string{
		"nonce":                nonce,
		"fingerprint":          fingerprint,
		"fingerprintSignature": signature,
		"token":                token,
	}

	body, _ := json.Marshal(verifyData)
	verifyReq := httptest.NewRequest("POST", "/bot-verify", bytes.NewReader(body))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyW := httptest.NewRecorder()

	s.botVerifyHandler(verifyW, verifyReq)

	if verifyW.Code != http.StatusOK {
		t.Fatalf("bot-verify failed with status %d", verifyW.Code)
	}

	// 5. Извлекаем clearance cookie
	var clearanceToken string
	for _, cookie := range verifyW.Result().Cookies() {
		if cookie.Name == "BOT_CLEARANCE" {
			clearanceToken = cookie.Value
			break
		}
	}

	if clearanceToken == "" {
		t.Fatal("clearance token not found")
	}

	// 6. Проверяем clearance
	validateReq := httptest.NewRequest("GET", "/bot-validate", nil)
	validateReq.AddCookie(&http.Cookie{
		Name:  "BOT_CLEARANCE",
		Value: clearanceToken,
	})
	validateW := httptest.NewRecorder()

	s.botValidateHandler(validateW, validateReq)

	if validateW.Code != http.StatusOK {
		t.Errorf("bot-validate failed with status %d", validateW.Code)
	}
}
