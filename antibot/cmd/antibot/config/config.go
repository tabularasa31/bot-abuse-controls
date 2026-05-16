package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Константы для настройки TTL (значения по умолчанию).
const (
	// ClearanceTTL определяет, как долго действует clearance cookie после успешной проверки
	// 24 часа — баланс между безопасностью (частая перепроверка) и удобством (не раздражать пользователей).
	DefaultClearanceTTL     = 24 * time.Hour
	DefaultNonceTTL         = 1 * time.Minute
	DefaultPort             = "9000"
	DefaultRateLimitMax     = 10
	DefaultRateLimitWindow  = 1 * time.Minute
	DefaultScoringThreshold = 3.0  // Порог для scoring-модели (score < threshold → challenge)
	DefaultScoringEnabled   = true // Включена ли модель scoring по умолчанию
	DefaultCaptchaEnabled   = true // Включена ли капча по умолчанию

	// ML Logging defaults.
	DefaultMLLoggingEnabled = false
	DefaultMLLogPath        = "/var/log/antibot/ml_logs.jsonl"
	DefaultMLBufferSize     = 1000
	DefaultMLFlushInterval  = 5 * time.Second
	DefaultMLSampleRate     = 1.0 // 100% sampling по умолчанию

	// Graceful shutdown defaults.
	DefaultShutdownTimeout = 30 * time.Second // Таймаут для завершения активных соединений

	// Request timeout defaults.
	DefaultRequestTimeout = 10 * time.Second // Таймаут для обработки одного HTTP запроса

	// Rate limit defaults.
	DefaultRateLimitShards = 0 // 0 = автоматически (количество CPU ядер)

	// Nonce store defaults.
	DefaultNonceShards = 0 // 0 = автоматически (количество CPU ядер)

	// Structured logging defaults.
	DefaultLogLevel = "info" // "debug", "info", "warn", "error"

	// Return URL after successful challenge.
	DefaultReturnURL = "https://the platform.ru/"
)

// Config содержит конфигурацию сервера из переменных окружения.
type Config struct {
	MasterSecret     []byte
	Port             string
	NonceTTL         time.Duration
	ClearanceTTL     time.Duration
	RateLimitMax     int
	RateLimitWindow  time.Duration
	ScoringThreshold float64 // Порог для scoring-модели
	ScoringEnabled   bool    // Включена ли модель scoring
	CaptchaEnabled   bool    // Включена ли капча (если false, капча никогда не показывается)

	// ML Logging configuration
	MLLoggingEnabled bool
	MLLogPath        string
	MLBufferSize     int
	MLFlushInterval  time.Duration
	MLSampleRate     float64

	// Graceful shutdown configuration
	ShutdownTimeout time.Duration // Таймаут для graceful shutdown

	// Request timeout configuration
	RequestTimeout time.Duration // Таймаут для обработки одного HTTP запроса

	// Rate limit configuration
	RateLimitShards int // Количество shards для rate limiter (0 = автоматически)

	// Nonce store configuration
	NonceShards int // Количество shards для nonce store (0 = автоматически)

	// Structured logging configuration
	LogLevel string // Уровень логирования ("debug", "info", "warn", "error")

	// Return URL configuration
	ReturnURL string // URL для редиректа после успешного challenge
}

// GenerateMasterSecret создаёт мастер-ключ при старте сервера
// Этот ключ используется для генерации уникальных секретов для каждого nonce.
func GenerateMasterSecret() ([]byte, error) {
	secret := make([]byte, 32) // 256 бит
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// Load загружает конфигурацию из переменных окружения.
func Load() (*Config, error) {
	cfg := &Config{}

	if err := loadMasterSecret(cfg); err != nil {
		return nil, err
	}
	if err := loadServerConfig(cfg); err != nil {
		return nil, err
	}
	if err := loadRateLimitConfig(cfg); err != nil {
		return nil, err
	}
	if err := loadScoringConfig(cfg); err != nil {
		return nil, err
	}
	if err := loadMLConfig(cfg); err != nil {
		return nil, err
	}
	if err := loadRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	if err := loadLoggingAndReturnConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func loadMasterSecret(cfg *Config) error {
	// MASTER_SECRET - обязательный параметр для продакшена
	// Если не указан, генерируется случайный (только для разработки)
	masterSecretStr := os.Getenv("MASTER_SECRET")
	if masterSecretStr == "" {
		log.Println("WARNING: MASTER_SECRET not set, generating random secret (unsafe for production!)")
		secret, err := GenerateMasterSecret()
		if err != nil {
			return fmt.Errorf("failed to generate master secret: %w", err)
		}
		cfg.MasterSecret = secret
		return nil
	}
	secret, err := hex.DecodeString(strings.TrimSpace(masterSecretStr))
	if err != nil {
		return fmt.Errorf("invalid MASTER_SECRET format (must be hex): %w", err)
	}
	if len(secret) != 32 {
		return fmt.Errorf("MASTER_SECRET must be 32 bytes (64 hex characters), got %d bytes", len(secret))
	}
	cfg.MasterSecret = secret
	return nil
}

func loadServerConfig(cfg *Config) error {
	cfg.Port = os.Getenv("ANTIBOT_PORT")
	if cfg.Port == "" {
		cfg.Port = DefaultPort
	}

	nonceTTLStr := os.Getenv("NONCE_TTL")
	if nonceTTLStr == "" {
		cfg.NonceTTL = DefaultNonceTTL
	} else {
		duration, err := time.ParseDuration(nonceTTLStr)
		if err != nil {
			return fmt.Errorf("invalid NONCE_TTL format: %w", err)
		}
		cfg.NonceTTL = duration
	}

	clearanceTTLStr := os.Getenv("CLEARANCE_TTL")
	if clearanceTTLStr == "" {
		cfg.ClearanceTTL = DefaultClearanceTTL
	} else {
		duration, err := time.ParseDuration(clearanceTTLStr)
		if err != nil {
			return fmt.Errorf("invalid CLEARANCE_TTL format: %w", err)
		}
		cfg.ClearanceTTL = duration
	}
	return nil
}

func loadRateLimitConfig(cfg *Config) error {
	rateLimitMaxStr := os.Getenv("RATE_LIMIT_MAX")
	if rateLimitMaxStr == "" {
		cfg.RateLimitMax = DefaultRateLimitMax
	} else {
		maxVal, err := strconv.Atoi(rateLimitMaxStr)
		if err != nil {
			return fmt.Errorf("invalid RATE_LIMIT_MAX format: %w", err)
		}
		if maxVal <= 0 {
			return fmt.Errorf("RATE_LIMIT_MAX must be positive")
		}
		cfg.RateLimitMax = maxVal
	}

	rateLimitWindowStr := os.Getenv("RATE_LIMIT_WINDOW")
	if rateLimitWindowStr == "" {
		cfg.RateLimitWindow = DefaultRateLimitWindow
	} else {
		duration, err := time.ParseDuration(rateLimitWindowStr)
		if err != nil {
			return fmt.Errorf("invalid RATE_LIMIT_WINDOW format: %w", err)
		}
		cfg.RateLimitWindow = duration
	}
	return nil
}

func loadScoringConfig(cfg *Config) error {
	scoringThresholdStr := os.Getenv("SCORING_THRESHOLD")
	if scoringThresholdStr == "" {
		cfg.ScoringThreshold = DefaultScoringThreshold
	} else {
		threshold, err := strconv.ParseFloat(scoringThresholdStr, 64)
		if err != nil {
			return fmt.Errorf("invalid SCORING_THRESHOLD format: %w", err)
		}
		if threshold < 0 {
			return fmt.Errorf("SCORING_THRESHOLD must be non-negative")
		}
		cfg.ScoringThreshold = threshold
	}

	scoringEnabledStr := os.Getenv("SCORING_ENABLED")
	if scoringEnabledStr == "" {
		cfg.ScoringEnabled = DefaultScoringEnabled
	} else {
		enabled, err := strconv.ParseBool(scoringEnabledStr)
		if err != nil {
			return fmt.Errorf("invalid SCORING_ENABLED format: %w", err)
		}
		cfg.ScoringEnabled = enabled
	}

	captchaEnabledStr := os.Getenv("CAPTCHA_ENABLED")
	if captchaEnabledStr == "" {
		cfg.CaptchaEnabled = DefaultCaptchaEnabled
	} else {
		enabled, err := strconv.ParseBool(captchaEnabledStr)
		if err != nil {
			return fmt.Errorf("invalid CAPTCHA_ENABLED format: %w", err)
		}
		cfg.CaptchaEnabled = enabled
	}
	return nil
}

func loadMLConfig(cfg *Config) error {
	mlLoggingEnabledStr := os.Getenv("ML_LOGGING_ENABLED")
	if mlLoggingEnabledStr == "" {
		cfg.MLLoggingEnabled = DefaultMLLoggingEnabled
	} else {
		enabled, err := strconv.ParseBool(mlLoggingEnabledStr)
		if err != nil {
			return fmt.Errorf("invalid ML_LOGGING_ENABLED format: %w", err)
		}
		cfg.MLLoggingEnabled = enabled
	}

	cfg.MLLogPath = os.Getenv("ML_LOG_PATH")
	if cfg.MLLogPath == "" {
		cfg.MLLogPath = DefaultMLLogPath
	}

	mlBufferSizeStr := os.Getenv("ML_LOG_BUFFER_SIZE")
	if mlBufferSizeStr == "" {
		cfg.MLBufferSize = DefaultMLBufferSize
	} else {
		size, err := strconv.Atoi(mlBufferSizeStr)
		if err != nil {
			return fmt.Errorf("invalid ML_LOG_BUFFER_SIZE format: %w", err)
		}
		if size <= 0 {
			return fmt.Errorf("ML_LOG_BUFFER_SIZE must be positive")
		}
		cfg.MLBufferSize = size
	}

	mlFlushIntervalStr := os.Getenv("ML_LOG_FLUSH_INTERVAL")
	if mlFlushIntervalStr == "" {
		cfg.MLFlushInterval = DefaultMLFlushInterval
	} else {
		interval, err := time.ParseDuration(mlFlushIntervalStr)
		if err != nil {
			return fmt.Errorf("invalid ML_LOG_FLUSH_INTERVAL format: %w", err)
		}
		if interval <= 0 {
			return fmt.Errorf("ML_LOG_FLUSH_INTERVAL must be positive")
		}
		cfg.MLFlushInterval = interval
	}

	mlSampleRateStr := os.Getenv("ML_LOG_SAMPLE_RATE")
	if mlSampleRateStr == "" {
		cfg.MLSampleRate = DefaultMLSampleRate
	} else {
		rate, err := strconv.ParseFloat(mlSampleRateStr, 64)
		if err != nil {
			return fmt.Errorf("invalid ML_LOG_SAMPLE_RATE format: %w", err)
		}
		if rate < 0 || rate > 1 {
			return fmt.Errorf("ML_LOG_SAMPLE_RATE must be between 0.0 and 1.0")
		}
		cfg.MLSampleRate = rate
	}
	return nil
}

func loadRuntimeConfig(cfg *Config) error {
	shutdownTimeoutStr := os.Getenv("SHUTDOWN_TIMEOUT")
	if shutdownTimeoutStr == "" {
		cfg.ShutdownTimeout = DefaultShutdownTimeout
	} else {
		timeout, err := time.ParseDuration(shutdownTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid SHUTDOWN_TIMEOUT format: %w", err)
		}
		if timeout <= 0 {
			return fmt.Errorf("SHUTDOWN_TIMEOUT must be positive")
		}
		cfg.ShutdownTimeout = timeout
	}

	requestTimeoutStr := os.Getenv("REQUEST_TIMEOUT")
	if requestTimeoutStr == "" {
		cfg.RequestTimeout = DefaultRequestTimeout
	} else {
		timeout, err := time.ParseDuration(requestTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid REQUEST_TIMEOUT format: %w", err)
		}
		if timeout <= 0 {
			return fmt.Errorf("REQUEST_TIMEOUT must be positive")
		}
		cfg.RequestTimeout = timeout
	}

	rateLimitShardsStr := os.Getenv("RATE_LIMIT_SHARDS")
	if rateLimitShardsStr == "" {
		cfg.RateLimitShards = DefaultRateLimitShards
	} else {
		shards, err := strconv.Atoi(rateLimitShardsStr)
		if err != nil {
			return fmt.Errorf("invalid RATE_LIMIT_SHARDS format: %w", err)
		}
		if shards < 0 {
			return fmt.Errorf("RATE_LIMIT_SHARDS must be non-negative")
		}
		cfg.RateLimitShards = shards
	}

	nonceShardsStr := os.Getenv("NONCE_SHARDS")
	if nonceShardsStr == "" {
		cfg.NonceShards = DefaultNonceShards
	} else {
		shards, err := strconv.Atoi(nonceShardsStr)
		if err != nil {
			return fmt.Errorf("invalid NONCE_SHARDS format: %w", err)
		}
		if shards < 0 {
			return fmt.Errorf("NONCE_SHARDS must be non-negative")
		}
		cfg.NonceShards = shards
	}
	return nil
}

func loadLoggingAndReturnConfig(cfg *Config) error {
	cfg.LogLevel = os.Getenv("LOG_LEVEL")
	if cfg.LogLevel == "" {
		cfg.LogLevel = DefaultLogLevel
	}
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[cfg.LogLevel] {
		return fmt.Errorf("invalid LOG_LEVEL: %s (must be debug, info, warn, or error)", cfg.LogLevel)
	}

	cfg.ReturnURL = os.Getenv("RETURN_URL")
	if cfg.ReturnURL == "" {
		cfg.ReturnURL = DefaultReturnURL
	}
	return nil
}
