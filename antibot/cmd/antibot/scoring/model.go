package scoring

import (
	"net/http"
	"strings"
)

// ClientTypeSuspicious описывает тип клиента, помеченного как подозрительный.
const ClientTypeSuspicious = "suspicious"

// Metadata содержит HTTP-метаданные запроса для scoring.
type Metadata struct {
	IP                 string // IP адрес клиента
	UserAgent          string // User-Agent заголовок
	AcceptLanguage     string // Accept-Language заголовок
	AcceptEncoding     string // Accept-Encoding заголовок
	HasStandardHeaders bool   // Наличие стандартных заголовков браузера
	HasCookies         bool   // Наличие cookies
	ClientType         string // Тип клиента (определяется по UA)
	ASN                string // ASN (пока не используется, для будущего расширения)
}

// Model содержит веса для scoring-модели (жестко зашитые).
type Model struct {
	// Веса для различных признаков (логистическая регрессия)
	weightUserAgent       float64 // Вес для подозрительных User-Agent
	weightAcceptEncoding  float64 // Вес для отсутствия Accept-Encoding
	weightCookies         float64 // Вес для наличия cookies
	weightStandardHeaders float64 // Вес для наличия стандартных заголовков браузера
	weightClientType      float64 // Вес для типа клиента
	bias                  float64 // Смещение (bias)
	threshold             float64 // Порог для принятия решения
}

// NewModel создаёт scoring-модель с жестко зашитыми весами.
func NewModel(threshold float64) *Model {
	return &Model{
		weightUserAgent:       -2.5, // Подозрительные UA снижают score
		weightAcceptEncoding:  -1.8, // Отсутствие Accept-Encoding снижает score
		weightCookies:         +1.2, // Наличие cookies повышает score
		weightStandardHeaders: +1.0, // Наличие стандартных заголовков браузера повышает score
		weightClientType:      -3.0, // Подозрительный тип клиента сильно снижает score
		bias:                  5.0,  // Базовый score
		threshold:             threshold,
	}
}

// Threshold возвращает порог для принятия решения.
func (sm *Model) Threshold() float64 {
	return sm.threshold
}

// ComputeScore вычисляет score на основе HTTP-метаданных используя scoring-модель.
func (sm *Model) ComputeScore(metadata *Metadata) float64 {
	score := sm.bias

	// Проверка User-Agent
	if isSuspiciousUserAgent(metadata.UserAgent) {
		score += sm.weightUserAgent
	}

	// Проверка Accept-Encoding (отсутствие - подозрительно)
	if metadata.AcceptEncoding == "" {
		score += sm.weightAcceptEncoding
	}

	// Наличие cookies (хороший признак)
	if metadata.HasCookies {
		score += sm.weightCookies
	}

	// Наличие стандартных заголовков браузера (хороший признак)
	// Браузеры обычно отправляют стандартные заголовки, боты часто их пропускают
	if metadata.HasStandardHeaders {
		score += sm.weightStandardHeaders
	}

	// Тип клиента
	switch metadata.ClientType {
	case ClientTypeSuspicious:
		score += sm.weightClientType
	case "browser":
		score += -sm.weightClientType // Инвертируем для браузеров (положительный эффект)
	}

	return score
}

// DetectClientType определяет тип клиента по User-Agent.
func DetectClientType(userAgent string) string {
	ua := strings.ToLower(userAgent)

	// Подозрительные User-Agent
	suspiciousPatterns := []string{
		"python-requests",
		"go-http-client",
		"curl",
		"wget",
		"scrapy",
		"httpclient",
		"okhttp",
		"java/",
		"apache-httpclient",
		"postman",
		"insomnia",
		"httpie",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ua, pattern) {
			return ClientTypeSuspicious
		}
	}

	// Нормальные браузеры
	browserPatterns := []string{
		"mozilla",
		"chrome",
		"safari",
		"firefox",
		"edge",
		"opera",
	}

	for _, pattern := range browserPatterns {
		if strings.Contains(ua, pattern) {
			return "browser"
		}
	}

	// Неизвестный тип
	return "unknown"
}

// isSuspiciousUserAgent проверяет, является ли User-Agent подозрительным.
func isSuspiciousUserAgent(userAgent string) bool {
	return DetectClientType(userAgent) == ClientTypeSuspicious
}

// hasStandardHeaders проверяет наличие стандартных заголовков браузера
// Браузеры обычно отправляют эти заголовки, боты часто их пропускают.
func hasStandardHeaders(r *http.Request) bool {
	// Стандартные заголовки, которые обычно есть у браузеров:
	// - Accept (есть почти всегда)
	// - Accept-Language (есть у большинства)
	// - Connection (keep-alive у современных браузеров)
	// - Upgrade-Insecure-Requests (современные браузеры)
	// - Sec-Fetch-* заголовки (современные браузеры)
	// - DNT (Do Not Track, опционально)
	// - Cache-Control (часто есть)

	hasAccept := r.Header.Get("Accept") != ""
	hasAcceptLanguage := r.Header.Get("Accept-Language") != ""
	hasConnection := r.Header.Get("Connection") != ""

	// Проверяем наличие хотя бы 2 из 3 базовых заголовков
	// или наличие современных заголовков безопасности
	basicHeadersCount := 0
	if hasAccept {
		basicHeadersCount++
	}
	if hasAcceptLanguage {
		basicHeadersCount++
	}
	if hasConnection {
		basicHeadersCount++
	}

	// Современные браузеры отправляют Sec-Fetch-* заголовки
	hasSecFetch := r.Header.Get("Sec-Fetch-Site") != "" ||
		r.Header.Get("Sec-Fetch-Mode") != "" ||
		r.Header.Get("Sec-Fetch-User") != ""

	// Upgrade-Insecure-Requests - признак современного браузера
	hasUpgradeInsecure := r.Header.Get("Upgrade-Insecure-Requests") != ""

	// Считаем, что есть стандартные заголовки, если:
	// - Есть хотя бы 2 из 3 базовых заголовков, ИЛИ
	// - Есть современные заголовки безопасности
	return basicHeadersCount >= 2 || hasSecFetch || hasUpgradeInsecure
}

// CollectMetadata собирает HTTP-метаданные из запроса
// getClientIP - функция для получения IP адреса клиента.
func CollectMetadata(r *http.Request, getClientIP func(*http.Request) string) *Metadata {
	// Получаем IP адрес (учитываем X-Forwarded-For и X-Real-IP)
	ip := getClientIP(r)

	// Собираем заголовки
	userAgent := r.Header.Get("User-Agent")
	acceptLanguage := r.Header.Get("Accept-Language")
	acceptEncoding := r.Header.Get("Accept-Encoding")

	// Проверяем наличие стандартных заголовков браузера
	hasStandardHeaders := hasStandardHeaders(r)

	// Проверяем наличие cookies
	hasCookies := len(r.Cookies()) > 0

	// Определяем тип клиента
	clientType := DetectClientType(userAgent)

	return &Metadata{
		IP:                 ip,
		UserAgent:          userAgent,
		AcceptLanguage:     acceptLanguage,
		AcceptEncoding:     acceptEncoding,
		HasStandardHeaders: hasStandardHeaders,
		HasCookies:         hasCookies,
		ClientType:         clientType,
		ASN:                "", // Пока не используется
	}
}
