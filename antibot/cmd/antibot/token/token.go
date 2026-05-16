package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// CreateClearanceToken создаёт подписанный clearance токен
// Stateless подход: токен содержит всю необходимую информацию и подпись
// Это позволяет проверять токен на любом edge сервере без общего хранилища.
func CreateClearanceToken(masterSecret []byte, clearanceTTL time.Duration) (string, error) {
	now := time.Now()
	issuedAt := now.Unix()
	expiresAt := now.Add(clearanceTTL).Unix()

	// Создаём данные для подписи: issuedAt|expiresAt
	data := fmt.Sprintf("%d|%d", issuedAt, expiresAt)

	// Подписываем данные с помощью masterSecret
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte(data))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Формируем токен: issuedAt|expiresAt|signature
	token := fmt.Sprintf("%d|%d|%s", issuedAt, expiresAt, signature)

	// Кодируем в hex для безопасной передачи в cookie
	return hex.EncodeToString([]byte(token)), nil
}

// ValidateClearanceToken проверяет валидность подписанного clearance токена
// Stateless проверка: не требует обращения к хранилищу.
func ValidateClearanceToken(tokenStr string, masterSecret []byte) bool {
	// Декодируем из hex
	tokenBytes, err := hex.DecodeString(tokenStr)
	if err != nil {
		return false
	}

	// Парсим токен: issuedAt|expiresAt|signature
	parts := make([][]byte, 0, 3)
	current := []byte{}
	for _, b := range tokenBytes {
		if b == '|' {
			parts = append(parts, current)
			current = []byte{}
		} else {
			current = append(current, b)
		}
	}
	parts = append(parts, current)

	if len(parts) != 3 {
		return false
	}

	// Парсим временные метки
	issuedAt, err := strconv.ParseInt(string(parts[0]), 10, 64)
	if err != nil {
		return false
	}
	expiresAt, err := strconv.ParseInt(string(parts[1]), 10, 64)
	if err != nil {
		return false
	}
	signature := string(parts[2])

	// Проверяем, что токен не истёк
	now := time.Now().Unix()
	if now < issuedAt || now > expiresAt {
		return false
	}

	// Проверяем подпись
	data := fmt.Sprintf("%d|%d", issuedAt, expiresAt)
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte(data))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Constant-time сравнение для защиты от timing attacks
	return ConstantTimeCompare(signature, expectedSignature)
}

// DeriveSecret генерирует уникальный секрет для конкретного nonce
// Использует HMAC-SHA256 с мастер-ключом и nonce
// Это гарантирует, что каждый nonce имеет свой уникальный секрет.
func DeriveSecret(nonce string, masterSecret []byte) string {
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignFingerprint подписывает fingerprint с помощью HMAC-SHA256 используя secret
// Это защищает от подделки fingerprint злоумышленником.
func SignFingerprint(fingerprintData, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fingerprintData))
	return hex.EncodeToString(mac.Sum(nil))
}

// ComputeExpectedToken вычисляет ожидаемый токен на основе fingerprint и секрета
// Используется для проверки точного значения токена от клиента
// Алгоритм: SHA-256(fingerprint|secret).
func ComputeExpectedToken(fingerprintData, secret string) string {
	// Объединяем fingerprint клиента с секретом
	// Порядок важен: fingerprint|secret (как на клиенте)
	data := fingerprintData + "|" + secret

	// Вычисляем SHA-256 хеш
	hash := sha256.Sum256([]byte(data))

	// Преобразуем в hex строку (64 символа)
	return hex.EncodeToString(hash[:])
}

// ConstantTimeCompare сравнивает два токена за постоянное время
// Защищает от timing attacks.
func ConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	aBytes := []byte(a)
	bBytes := []byte(b)
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}
