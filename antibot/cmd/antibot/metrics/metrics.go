package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics содержит все Prometheus метрики для сервиса.
type Metrics struct {
	// HTTP метрики
	HTTPRequestsTotal   *prometheus.CounterVec   // Общее количество HTTP запросов
	HTTPRequestDuration *prometheus.HistogramVec // Длительность HTTP запросов
	HTTPRequestSize     *prometheus.HistogramVec // Размер HTTP запросов (bytes)
	HTTPResponseSize    *prometheus.HistogramVec // Размер HTTP ответов (bytes)

	// Rate limiting метрики
	RateLimitExceededTotal *prometheus.CounterVec // Количество заблокированных запросов

	// Nonce метрики
	NonceOperationsTotal *prometheus.CounterVec // Операции с nonce (создание, валидация, истечение)
	NonceStoreSize       prometheus.Gauge       // Текущий размер nonce store

	// Clearance токены метрики
	ClearanceTokensIssuedTotal    *prometheus.CounterVec // Выданные clearance токены
	ClearanceTokensValidatedTotal *prometheus.CounterVec // Валидированные clearance токены

	// Bot detection метрики
	BotScores            *prometheus.HistogramVec // Распределение bot scores
	BotVerdictsTotal     *prometheus.CounterVec   // Вердикты (allow/challenge)
	ChallengeShownTotal  prometheus.Counter       // Количество показанных challenge
	ChallengePassedTotal prometheus.Counter       // Количество пройденных challenge

	// Captcha метрики
	CaptchaShownTotal  prometheus.Counter // Количество показанных капч
	CaptchaPassedTotal prometheus.Counter // Количество пройденных капч
	CaptchaFailedTotal prometheus.Counter // Количество проваленных капч

	// Системные метрики
	ActiveConnections prometheus.Gauge // Текущее количество активных соединений
	GoroutineCount    prometheus.Gauge // Количество горутин
}

// NewMetrics создаёт новый экземпляр метрик.
func NewMetrics() *Metrics {
	return &Metrics{
		// HTTP метрики
		HTTPRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "antibot_http_requests_total",
				Help: "Total number of HTTP requests processed",
			},
			[]string{"method", "handler", "status_code"},
		),

		HTTPRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "antibot_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets, // [.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10]
			},
			[]string{"method", "handler", "status_code"},
		),

		HTTPRequestSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "antibot_http_request_size_bytes",
				Help:    "HTTP request size in bytes",
				Buckets: []float64{100, 500, 1000, 5000, 10000, 50000, 100000},
			},
			[]string{"method", "handler"},
		),

		HTTPResponseSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "antibot_http_response_size_bytes",
				Help:    "HTTP response size in bytes",
				Buckets: []float64{100, 500, 1000, 5000, 10000, 50000, 100000, 500000},
			},
			[]string{"method", "handler", "status_code"},
		),

		// Rate limiting метрики
		RateLimitExceededTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "antibot_rate_limit_exceeded_total",
				Help: "Total number of requests blocked by rate limiter",
			},
			[]string{"handler"},
		),

		// Nonce метрики
		NonceOperationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "antibot_nonce_operations_total",
				Help: "Total number of nonce operations (created, validated, expired)",
			},
			[]string{"operation"}, // operation: "created", "validated", "expired", "invalid"
		),

		NonceStoreSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "antibot_nonce_store_size",
				Help: "Current number of nonces in store",
			},
		),

		// Clearance токены метрики
		ClearanceTokensIssuedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "antibot_clearance_tokens_issued_total",
				Help: "Total number of clearance tokens issued",
			},
			[]string{"handler"},
		),

		ClearanceTokensValidatedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "antibot_clearance_tokens_validated_total",
				Help: "Total number of clearance tokens validated",
			},
			[]string{"valid"}, // valid: "true", "false"
		),

		// Bot detection метрики
		BotScores: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "antibot_bot_scores",
				Help:    "Distribution of bot detection scores",
				Buckets: []float64{0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
			},
			[]string{"handler"},
		),

		BotVerdictsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "antibot_bot_verdicts_total",
				Help: "Total number of bot verdicts (allow/challenge)",
			},
			[]string{"handler", "verdict"}, // verdict: "allow", "challenge"
		),

		ChallengeShownTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "antibot_challenge_shown_total",
				Help: "Total number of challenges shown to users",
			},
		),

		ChallengePassedTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "antibot_challenge_passed_total",
				Help: "Total number of challenges successfully passed",
			},
		),

		// Captcha метрики
		CaptchaShownTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "antibot_captcha_shown_total",
				Help: "Total number of captchas shown to users",
			},
		),

		CaptchaPassedTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "antibot_captcha_passed_total",
				Help: "Total number of captchas successfully passed",
			},
		),

		CaptchaFailedTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "antibot_captcha_failed_total",
				Help: "Total number of captchas failed",
			},
		),

		// Системные метрики
		ActiveConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "antibot_active_connections",
				Help: "Current number of active HTTP connections",
			},
		),

		GoroutineCount: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "antibot_goroutines",
				Help: "Current number of goroutines",
			},
		),
	}
}

// RecordHTTPRequest записывает метрики для HTTP запроса.
func (m *Metrics) RecordHTTPRequest(
	method, handler, statusCode string,
	duration time.Duration,
	requestSize, responseSize int64,
) {
	m.HTTPRequestsTotal.WithLabelValues(method, handler, statusCode).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, handler, statusCode).Observe(duration.Seconds())
	if requestSize > 0 {
		m.HTTPRequestSize.WithLabelValues(method, handler).Observe(float64(requestSize))
	}
	if responseSize > 0 {
		m.HTTPResponseSize.WithLabelValues(method, handler, statusCode).Observe(float64(responseSize))
	}
}

// RecordRateLimitExceeded записывает метрику превышения rate limit.
func (m *Metrics) RecordRateLimitExceeded(handler string) {
	m.RateLimitExceededTotal.WithLabelValues(handler).Inc()
}

// RecordNonceOperation записывает метрику операции с nonce.
func (m *Metrics) RecordNonceOperation(operation string) {
	m.NonceOperationsTotal.WithLabelValues(operation).Inc()
}

// SetNonceStoreSize устанавливает размер nonce store.
func (m *Metrics) SetNonceStoreSize(size int) {
	m.NonceStoreSize.Set(float64(size))
}

// RecordClearanceTokenIssued записывает метрику выданного clearance токена.
func (m *Metrics) RecordClearanceTokenIssued(handler string) {
	m.ClearanceTokensIssuedTotal.WithLabelValues(handler).Inc()
}

// RecordClearanceTokenValidated записывает метрику валидированного clearance токена.
func (m *Metrics) RecordClearanceTokenValidated(valid bool) {
	validStr := "false"
	if valid {
		validStr = "true"
	}
	m.ClearanceTokensValidatedTotal.WithLabelValues(validStr).Inc()
}

// RecordBotScore записывает метрику bot score.
func (m *Metrics) RecordBotScore(handler string, score float64) {
	m.BotScores.WithLabelValues(handler).Observe(score)
}

// RecordBotVerdict записывает метрику вердикта.
func (m *Metrics) RecordBotVerdict(handler, verdict string) {
	m.BotVerdictsTotal.WithLabelValues(handler, verdict).Inc()
}

// RecordChallengeShown записывает метрику показанного challenge.
func (m *Metrics) RecordChallengeShown() {
	m.ChallengeShownTotal.Inc()
}

// RecordChallengePassed записывает метрику пройденного challenge.
func (m *Metrics) RecordChallengePassed() {
	m.ChallengePassedTotal.Inc()
}

// SetActiveConnections устанавливает количество активных соединений.
func (m *Metrics) SetActiveConnections(count int) {
	m.ActiveConnections.Set(float64(count))
}

// SetGoroutineCount устанавливает количество горутин.
func (m *Metrics) SetGoroutineCount(count int) {
	m.GoroutineCount.Set(float64(count))
}

// RecordCaptchaShown записывает метрику показанной капчи.
func (m *Metrics) RecordCaptchaShown() {
	m.CaptchaShownTotal.Inc()
}

// RecordCaptchaPassed записывает метрику пройденной капчи.
func (m *Metrics) RecordCaptchaPassed() {
	m.CaptchaPassedTotal.Inc()
}

// RecordCaptchaFailed записывает метрику проваленной капчи.
func (m *Metrics) RecordCaptchaFailed() {
	m.CaptchaFailedTotal.Inc()
}
