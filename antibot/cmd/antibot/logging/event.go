package logging

import (
	"time"
)

// Event представляет одно событие для логирования.
type Event struct {
	Timestamp   time.Time     `json:"timestamp"`
	RequestID   string        `json:"request_id"`
	Features    Features      `json:"features"`
	ModelOutput ModelOutput   `json:"model_output"`
	Labels      Labels        `json:"labels"`
	Metadata    EventMetadata `json:"metadata"`
}

// Features содержит признаки запроса для ML модели.
type Features struct {
	IPHash             string `json:"ip_hash"`              // SHA256 хеш IP адреса
	UserAgent          string `json:"user_agent"`           // Полный User-Agent
	UserAgentLength    int    `json:"user_agent_length"`    // Длина User-Agent
	AcceptLanguage     string `json:"accept_language"`      // Accept-Language заголовок
	AcceptEncoding     string `json:"accept_encoding"`      // Accept-Encoding заголовок
	HasStandardHeaders bool   `json:"has_standard_headers"` // Наличие стандартных заголовков
	HasCookies         bool   `json:"has_cookies"`          // Наличие cookies
	ClientType         string `json:"client_type"`          // Тип клиента (suspicious/browser/unknown)
	HeaderCount        int    `json:"header_count"`         // Количество заголовков
	HasAccept          bool   `json:"has_accept"`           // Наличие Accept заголовка
	HasConnection      bool   `json:"has_connection"`       // Наличие Connection заголовка
	HasSecFetch        bool   `json:"has_sec_fetch"`        // Наличие Sec-Fetch-* заголовков
	HasUpgradeInsecure bool   `json:"has_upgrade_insecure"` // Наличие Upgrade-Insecure-Requests
	Method             string `json:"method"`               // HTTP метод
	Path               string `json:"path"`                 // Путь запроса
	HasReferer         bool   `json:"has_referer"`          // Наличие Referer заголовка
	RefererDomain      string `json:"referer_domain"`       // Домен из Referer (если есть)
}

// ModelOutput содержит выходные данные текущей модели.
type ModelOutput struct {
	ComputedScore float64 `json:"computed_score"` // Вычисленный score
	Threshold     float64 `json:"threshold"`      // Порог для принятия решения
	Verdict       string  `json:"verdict"`        // Вердикт: "allow" или "challenge"
}

// Labels содержит метки для обучения ML модели.
type Labels struct {
	HasClearance    bool   `json:"has_clearance"`    // Наличие clearance cookie
	ClearanceValid  bool   `json:"clearance_valid"`  // Валидность clearance cookie
	ChallengeShown  bool   `json:"challenge_shown"`  // Был ли показан challenge
	ChallengePassed *bool  `json:"challenge_passed"` // Прошёл ли challenge (null если не было)
	GroundTruth     string `json:"ground_truth"`     // "human", "bot" или "" если неизвестно
}

// EventMetadata содержит метаданные о событии.
type EventMetadata struct {
	Handler        string  `json:"handler"`          // Название handler'а (bot-validate, bot-verify и т.д.)
	ResponseTimeMs float64 `json:"response_time_ms"` // Время обработки в миллисекундах
}
