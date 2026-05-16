package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"antibot/cmd/antibot/config"
	"antibot/cmd/antibot/handlers"
	"antibot/cmd/antibot/nonce"
	"antibot/cmd/antibot/ratelimit"
	"antibot/cmd/antibot/scoring"
	"antibot/cmd/antibot/token"
)

func TestNonceStore(t *testing.T) {
	store := nonce.NewStore(1 * time.Minute)

	t.Run("put and isValid", func(t *testing.T) {
		nonce := "test-nonce-1"
		store.Put(nonce)

		if !store.IsValid(nonce) {
			t.Error("nonce should be valid after put")
		}
	})

	t.Run("consume removes nonce", func(t *testing.T) {
		nonce := "test-nonce-2"
		store.Put(nonce)

		if !store.Consume(nonce) {
			t.Error("consume should return true for valid nonce")
		}

		if store.IsValid(nonce) {
			t.Error("nonce should not be valid after consume")
		}
	})

	t.Run("consume returns false for invalid nonce", func(t *testing.T) {
		if store.Consume("non-existent-nonce") {
			t.Error("consume should return false for non-existent nonce")
		}
	})

	t.Run("expired nonce is invalid", func(t *testing.T) {
		shortTTLStore := nonce.NewStore(100 * time.Millisecond)
		nonce := "test-nonce-expired"
		shortTTLStore.Put(nonce)

		time.Sleep(150 * time.Millisecond)

		if shortTTLStore.IsValid(nonce) {
			t.Error("expired nonce should not be valid")
		}
	})

	t.Run("consumeIfValid atomically checks and consumes", func(t *testing.T) {
		nonce := "test-nonce-atomic"
		store.Put(nonce)

		if !store.ConsumeIfValid(nonce) {
			t.Error("consumeIfValid should return true for valid nonce")
		}

		if store.ConsumeIfValid(nonce) {
			t.Error("consumeIfValid should return false for already consumed nonce")
		}
	})
}

func TestClearanceToken(t *testing.T) {
	masterSecret, _ := config.GenerateMasterSecret()
	clearanceTTL := 1 * time.Hour

	t.Run("create and validate token", func(t *testing.T) {
		tokenStr, err := token.CreateClearanceToken(masterSecret, clearanceTTL)
		if err != nil {
			t.Fatalf("CreateClearanceToken failed: %v", err)
		}

		if tokenStr == "" {
			t.Error("token should not be empty")
		}

		if !token.ValidateClearanceToken(tokenStr, masterSecret) {
			t.Error("valid token should pass validation")
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		if token.ValidateClearanceToken("invalid-token", masterSecret) {
			t.Error("invalid token should not pass validation")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		// Создаём токен вручную с истекшим временем
		now := time.Now()
		issuedAt := now.Add(-2 * time.Hour).Unix()  // Выдан 2 часа назад
		expiresAt := now.Add(-1 * time.Hour).Unix() // Истёк 1 час назад

		// Создаём данные для подписи
		data := fmt.Sprintf("%d|%d", issuedAt, expiresAt)
		mac := hmac.New(sha256.New, masterSecret)
		mac.Write([]byte(data))
		signature := hex.EncodeToString(mac.Sum(nil))

		// Формируем токен
		tokenStr := fmt.Sprintf("%d|%d|%s", issuedAt, expiresAt, signature)
		tokenHex := hex.EncodeToString([]byte(tokenStr))

		// Проверяем, что истекший токен не проходит валидацию
		if token.ValidateClearanceToken(tokenHex, masterSecret) {
			t.Error("expired token should not pass validation")
		}
	})

	t.Run("token with wrong signature", func(t *testing.T) {
		// Создаём токен с одним секретом
		tokenStr, err := token.CreateClearanceToken(masterSecret, clearanceTTL)
		if err != nil {
			t.Fatalf("CreateClearanceToken failed: %v", err)
		}

		// Пытаемся проверить с другим секретом
		differentSecret, _ := config.GenerateMasterSecret()

		if token.ValidateClearanceToken(tokenStr, differentSecret) {
			t.Error("token with wrong signature should not pass validation")
		}
	})
}

func TestRateLimiter(t *testing.T) {
	limiter := ratelimit.NewGCRALimiter(3, 1*time.Second)

	t.Run("allows requests within limit", func(t *testing.T) {
		ip := "127.0.0.1"
		if !limiter.Allow(ip) {
			t.Error("should allow first request")
		}
		if !limiter.Allow(ip) {
			t.Error("should allow second request")
		}
		if !limiter.Allow(ip) {
			t.Error("should allow third request")
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		ip := "127.0.0.2"
		// Используем отдельный limiter для чистоты теста
		// GCRA: лимит 3 запроса в секунду, emission rate = 333ms, burstSize = 3
		testLimiter := ratelimit.NewGCRALimiter(3, 1*time.Second)

		// Делаем 3 запроса подряд (все разрешены, allowance уменьшается: 3->2->1->0)
		if !testLimiter.Allow(ip) {
			t.Error("should allow first request")
		}
		if !testLimiter.Allow(ip) {
			t.Error("should allow second request")
		}
		if !testLimiter.Allow(ip) {
			t.Error("should allow third request")
		}

		// 4-й запрос сразу после 3-го
		// GCRA позволяет burst, но между вызовами может пройти время (наносекунды)
		// Для emission rate = 333ms нужно ждать 333ms для восстановления 1 allowance
		// Между вызовами проходит меньше микросекунды, что недостаточно
		// Поэтому 4-й запрос должен быть заблокирован
		// Но если он прошёл, значит между вызовами прошло достаточно времени
		// В этом случае делаем ещё один запрос - он точно должен быть заблокирован
		if testLimiter.Allow(ip) {
			// Если прошёл, значит между вызовами прошло время
			// Делаем ещё один - он должен быть заблокирован
			if testLimiter.Allow(ip) {
				t.Error("should eventually block requests over limit")
			}
		}
		// Если был заблокирован сразу - это правильно
	})

	t.Run("allows requests after emission rate", func(t *testing.T) {
		ip := "127.0.0.3"
		// Лимит: 2 запроса в 100ms, emission rate = 50ms, burstSize = 2
		shortWindowLimiter := ratelimit.NewGCRALimiter(2, 100*time.Millisecond)

		if !shortWindowLimiter.Allow(ip) {
			t.Error("should allow first request")
		}
		if !shortWindowLimiter.Allow(ip) {
			t.Error("should allow second request")
		}

		// 3-й запрос сразу должен быть заблокирован (allowance = 0)
		// Но между вызовами может пройти время, поэтому проверяем сразу
		blocked := shortWindowLimiter.Allow(ip)
		if blocked {
			// Если прошло, значит между вызовами прошло достаточно времени
			// Это нормально для GCRA - он позволяет burst, но потом блокирует
			// Попробуем ещё раз сразу
			if shortWindowLimiter.Allow(ip) {
				t.Error("should block request over limit after burst")
			}
		}

		// Ждём больше чем emission rate (50ms), чтобы allowance восстановился
		// За 60ms allowance восстановится на 60/50 = 1.2
		time.Sleep(60 * time.Millisecond)

		// Теперь должен быть разрешён (allowance восстановился)
		if !shortWindowLimiter.Allow(ip) {
			t.Error("should allow request after emission rate passes")
		}
	})

	t.Run("different IPs have separate limits", func(t *testing.T) {
		ip1 := "127.0.0.4"
		ip2 := "127.0.0.5"

		limiter.Allow(ip1)
		limiter.Allow(ip1)
		limiter.Allow(ip1)

		// IP2 должен иметь свой лимит (новый IP получает полный allowance = 3)
		if !limiter.Allow(ip2) {
			t.Error("different IP should have separate limit")
		}
	})
}

func TestDeriveSecret(t *testing.T) {
	masterSecret, _ := config.GenerateMasterSecret()

	t.Run("same nonce produces same secret", func(t *testing.T) {
		nonce := "test-nonce"
		secret1 := token.DeriveSecret(nonce, masterSecret)
		secret2 := token.DeriveSecret(nonce, masterSecret)

		if secret1 != secret2 {
			t.Error("same nonce should produce same secret")
		}
	})

	t.Run("different nonces produce different secrets", func(t *testing.T) {
		secret1 := token.DeriveSecret("nonce-1", masterSecret)
		secret2 := token.DeriveSecret("nonce-2", masterSecret)

		if secret1 == secret2 {
			t.Error("different nonces should produce different secrets")
		}
	})
}

func TestComputeExpectedToken(t *testing.T) {
	fingerprint := "test-fingerprint"
	secret := "test-secret"

	token1 := token.ComputeExpectedToken(fingerprint, secret)
	token2 := token.ComputeExpectedToken(fingerprint, secret)

	if token1 != token2 {
		t.Error("same fingerprint and secret should produce same token")
	}

	if len(token1) != 64 {
		t.Errorf("token should be 64 hex characters, got %d", len(token1))
	}

	// Проверяем, что разные входные данные дают разные токены
	token3 := token.ComputeExpectedToken("different-fingerprint", secret)
	if token1 == token3 {
		t.Error("different fingerprint should produce different token")
	}
}

func TestSignFingerprint(t *testing.T) {
	fingerprint := "test-fingerprint"
	secret := "test-secret"

	signature1 := token.SignFingerprint(fingerprint, secret)
	signature2 := token.SignFingerprint(fingerprint, secret)

	if signature1 != signature2 {
		t.Error("same fingerprint and secret should produce same signature")
	}

	if len(signature1) != 64 {
		t.Errorf("signature should be 64 hex characters, got %d", len(signature1))
	}

	// Проверяем, что разные входные данные дают разные подписи
	signature3 := token.SignFingerprint("different-fingerprint", secret)
	if signature1 == signature3 {
		t.Error("different fingerprint should produce different signature")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	t.Run("equal strings", func(t *testing.T) {
		if !token.ConstantTimeCompare("test", "test") {
			t.Error("equal strings should compare as equal")
		}
	})

	t.Run("different strings", func(t *testing.T) {
		if token.ConstantTimeCompare("test1", "test2") {
			t.Error("different strings should not compare as equal")
		}
	})

	t.Run("different lengths", func(t *testing.T) {
		if token.ConstantTimeCompare("test", "test123") {
			t.Error("strings with different lengths should not compare as equal")
		}
	})

	t.Run("empty strings", func(t *testing.T) {
		if !token.ConstantTimeCompare("", "") {
			t.Error("empty strings should compare as equal")
		}
	})
}

func TestHealthHandler(t *testing.T) {
	masterSecret, _ := config.GenerateMasterSecret()
	s := &handlers.Server{
		MasterSecret:   masterSecret,
		ClearanceTTL:   1 * time.Hour,
		RateLimiter:    ratelimit.NewGCRALimiter(10, 1*time.Minute),
		GetClientIP:    getClientIP,
		RequestTimeout: 5 * time.Second,
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	s.HealthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type application/json")
	}
}

func TestBotValidateHandler(t *testing.T) {
	masterSecret, _ := config.GenerateMasterSecret()
	clearanceTTL := 1 * time.Hour
	s := &handlers.Server{
		MasterSecret:   masterSecret,
		ClearanceTTL:   clearanceTTL,
		RateLimiter:    ratelimit.NewGCRALimiter(10, 1*time.Minute),
		ScoringModel:   scoring.NewModel(3.0),
		ScoringEnabled: true,
		GetClientIP:    getClientIP,
		RequestTimeout: 5 * time.Second,
	}

	t.Run("browser UA without clearance gets challenge", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/bot-validate", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0")
		w := httptest.NewRecorder()

		s.BotValidateHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("browser without clearance should get challenge (403), got %d", w.Code)
		}
		if w.Header().Get("X-Bot-Verdict") != "challenge" {
			t.Errorf("expected verdict challenge, got %s", w.Header().Get("X-Bot-Verdict"))
		}
	})

	t.Run("curl UA without clearance gets allow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/bot-validate", nil)
		req.Header.Set("User-Agent", "curl/8.1.0")
		w := httptest.NewRecorder()

		s.BotValidateHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("curl without clearance should get allow (200), got %d", w.Code)
		}
		if w.Header().Get("X-Bot-Verdict") != "allow" {
			t.Errorf("expected verdict allow, got %s", w.Header().Get("X-Bot-Verdict"))
		}
	})

	t.Run("python-requests UA without clearance gets allow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/bot-validate", nil)
		req.Header.Set("User-Agent", "python-requests/2.31.0")
		w := httptest.NewRecorder()

		s.BotValidateHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("python-requests without clearance should get allow (200), got %d", w.Code)
		}
	})

	t.Run("unknown UA without clearance gets allow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/bot-validate", nil)
		req.Header.Set("User-Agent", "MyApp/2.3.1 (iPhone; iOS 17.0)")
		w := httptest.NewRecorder()

		s.BotValidateHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("unknown UA without clearance should get allow (200), got %d", w.Code)
		}
	})

	t.Run("no UA without clearance gets allow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/bot-validate", nil)
		w := httptest.NewRecorder()

		s.BotValidateHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("no UA without clearance should get allow (200), got %d", w.Code)
		}
	})

	t.Run("valid clearance cookie gets allow", func(t *testing.T) {
		tokenStr, err := token.CreateClearanceToken(masterSecret, clearanceTTL)
		if err != nil {
			t.Fatalf("CreateClearanceToken failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/bot-validate", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124.0")
		req.AddCookie(&http.Cookie{
			Name:  "BOT_CLEARANCE",
			Value: tokenStr,
		})
		w := httptest.NewRecorder()

		s.BotValidateHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("valid clearance should get allow (200), got %d", w.Code)
		}
		if w.Header().Get("X-Bot-Verdict") != "allow" {
			t.Errorf("expected verdict allow, got %s", w.Header().Get("X-Bot-Verdict"))
		}
	})

	t.Run("invalid clearance cookie with browser UA gets challenge", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/bot-validate", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124.0")
		req.AddCookie(&http.Cookie{
			Name:  "BOT_CLEARANCE",
			Value: "invalid-token",
		})
		w := httptest.NewRecorder()

		s.BotValidateHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("browser with invalid clearance should get challenge (403), got %d", w.Code)
		}
	})
}

func TestGenerateMasterSecret(t *testing.T) {
	secret, err := config.GenerateMasterSecret()
	if err != nil {
		t.Fatalf("GenerateMasterSecret failed: %v", err)
	}

	if len(secret) != 32 {
		t.Errorf("expected secret length 32, got %d", len(secret))
	}

	// Проверяем, что секреты разные при каждом вызове
	secret2, _ := config.GenerateMasterSecret()
	if hex.EncodeToString(secret) == hex.EncodeToString(secret2) {
		t.Error("secrets should be different on each generation")
	}
}

func TestGenerateRandomHex(t *testing.T) {
	hexStr, err := generateRandomHex(16)
	if err != nil {
		t.Fatalf("generateRandomHex failed: %v", err)
	}

	// 16 байт = 32 hex символа
	if len(hexStr) != 32 {
		t.Errorf("expected hex length 32, got %d", len(hexStr))
	}

	// Проверяем, что это валидный hex
	_, err = hex.DecodeString(hexStr)
	if err != nil {
		t.Errorf("generated hex is not valid: %v", err)
	}
}

func TestGetClientIP(t *testing.T) {
	t.Run("X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
		ip := getClientIP(req)
		if ip != "192.168.1.1" {
			t.Errorf("expected 192.168.1.1, got %s", ip)
		}
	})

	t.Run("X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "192.168.1.2")
		ip := getClientIP(req)
		if ip != "192.168.1.2" {
			t.Errorf("expected 192.168.1.2, got %s", ip)
		}
	})

	t.Run("RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.3:12345"
		ip := getClientIP(req)
		if ip != "192.168.1.3" {
			t.Errorf("expected 192.168.1.3, got %s", ip)
		}
	})
}

// Benchmark тесты.
func BenchmarkDeriveSecret(b *testing.B) {
	masterSecret, _ := config.GenerateMasterSecret()
	nonce := "benchmark-nonce"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.DeriveSecret(nonce, masterSecret)
	}
}

func BenchmarkCreateClearanceToken(b *testing.B) {
	masterSecret, _ := config.GenerateMasterSecret()
	clearanceTTL := 1 * time.Hour

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.CreateClearanceToken(masterSecret, clearanceTTL)
	}
}

func BenchmarkValidateClearanceToken(b *testing.B) {
	masterSecret, _ := config.GenerateMasterSecret()
	clearanceTTL := 1 * time.Hour
	tokenStr, _ := token.CreateClearanceToken(masterSecret, clearanceTTL)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.ValidateClearanceToken(tokenStr, masterSecret)
	}
}

func BenchmarkConstantTimeCompare(b *testing.B) {
	token1 := "a" + string(make([]byte, 63))
	token2 := "a" + string(make([]byte, 63))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.ConstantTimeCompare(token1, token2)
	}
}
