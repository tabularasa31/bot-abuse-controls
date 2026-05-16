package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"antibot/cmd/antibot/config"
	"antibot/cmd/antibot/handlers"
	"antibot/cmd/antibot/logging"
	"antibot/cmd/antibot/metrics"
	"antibot/cmd/antibot/nonce"
	"antibot/cmd/antibot/ratelimit"
	"antibot/cmd/antibot/scoring"
)

// getClientIP извлекает IP адрес клиента из запроса
// Учитывает заголовки X-Forwarded-For и X-Real-IP для работы за прокси
// Оптимизация: использует strings.IndexByte вместо []rune для лучшей производительности.
func getClientIP(r *http.Request) string {
	// Проверяем X-Forwarded-For (может содержать несколько IP через запятую)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Берём первый IP из списка
		// Оптимизация: используем IndexByte вместо []rune (быстрее и без аллокаций)
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			// Обрезаем пробелы после запятой
			ip := xff[:idx]
			return strings.TrimSpace(ip)
		}
		return xff
	}
	// Проверяем X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Используем RemoteAddr
	ip := r.RemoteAddr
	// Убираем порт, если есть
	// Оптимизация: ищем с конца строки (быстрее для IPv6)
	if idx := strings.LastIndexByte(ip, ':'); idx >= 0 {
		// Проверяем, что это не IPv6 адрес (IPv6 содержит много ':')
		// Если это IPv6 в формате [::1]:port, то ищем последнюю ']'
		if strings.Contains(ip, "]") {
			// IPv6 с портом: [::1]:8080
			if bracketIdx := strings.LastIndexByte(ip, ']'); bracketIdx >= 0 && idx > bracketIdx {
				return ip[1:bracketIdx] // Убираем [ и ]
			}
		} else {
			// IPv4 с портом: 127.0.0.1:8080
			return ip[:idx]
		}
	}
	return ip
}

// generateRandomHex генерирует случайную hex строку заданной длины.
func generateRandomHex(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// loadConfigOrExit загружает конфигурацию или завершает работу при ошибке.
func loadConfigOrExit() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	return cfg
}

// setupLogger создаёт структурированный логгер и пишет туда стартовые сообщения.
func setupLogger(cfg *config.Config) *logging.StructuredLogger {
	logLevel := logging.ParseLogLevel(cfg.LogLevel)
	structuredLogger := logging.NewStructuredLogger(os.Stdout, logLevel)

	structuredLogger.Info("Configuration loaded", map[string]interface{}{
		"port":              cfg.Port,
		"nonce_ttl":         cfg.NonceTTL.String(),
		"clearance_ttl":     cfg.ClearanceTTL.String(),
		"rate_limit_max":    cfg.RateLimitMax,
		"rate_limit_window": cfg.RateLimitWindow.String(),
		"scoring_enabled":   cfg.ScoringEnabled,
		"scoring_threshold": cfg.ScoringThreshold,
		"request_timeout":   cfg.RequestTimeout.String(),
		"shutdown_timeout":  cfg.ShutdownTimeout.String(),
		"log_level":         cfg.LogLevel,
	})

	if os.Getenv("MASTER_SECRET") == "" {
		structuredLogger.Warn("Master Secret not set, generating random secret (unsafe for production!)")
	} else {
		structuredLogger.Info("Master Secret loaded from MASTER_SECRET")
	}
	return structuredLogger
}

// setupMLLogger инициализирует ML логгер (если включён).
func setupMLLogger(cfg *config.Config, structuredLogger *logging.StructuredLogger) *logging.Logger {
	if !cfg.MLLoggingEnabled {
		structuredLogger.Info("ML Logging disabled")
		return nil
	}
	loggerConfig := logging.Config{
		Enabled:       cfg.MLLoggingEnabled,
		LogPath:       cfg.MLLogPath,
		BufferSize:    cfg.MLBufferSize,
		FlushInterval: cfg.MLFlushInterval,
		SampleRate:    cfg.MLSampleRate,
	}
	mlLogger, err := logging.NewLogger(loggerConfig)
	if err != nil {
		structuredLogger.Error("Failed to initialize ML logger", err, map[string]interface{}{
			"ml_logging": "disabled",
		})
		return nil
	}
	structuredLogger.Info("ML Logging enabled", map[string]interface{}{
		"log_path":       cfg.MLLogPath,
		"buffer_size":    cfg.MLBufferSize,
		"flush_interval": cfg.MLFlushInterval.String(),
		"sample_rate":    cfg.MLSampleRate,
	})
	return mlLogger
}

// resolveShardCount возвращает либо явное значение, либо число CPU (минимум 1).
func resolveShardCount(configured int) int {
	if configured != 0 {
		return configured
	}
	count := runtime.NumCPU()
	if count < 1 {
		count = 1
	}
	return count
}

// setupRateLimiter создаёт rate limiter с учётом конфигурации шардов.
func setupRateLimiter(cfg *config.Config, structuredLogger *logging.StructuredLogger) ratelimit.LimiterInterface {
	shardCount := resolveShardCount(cfg.RateLimitShards)
	if shardCount > 1 {
		structuredLogger.Info("Rate Limit: GCRA (leaky bucket) with sharding", map[string]interface{}{
			"algorithm":    "gcra",
			"shards":       shardCount,
			"max_requests": cfg.RateLimitMax,
			"window":       cfg.RateLimitWindow.String(),
		})
		return ratelimit.NewShardedGCRALimiter(cfg.RateLimitMax, cfg.RateLimitWindow, shardCount)
	}
	structuredLogger.Info("Rate Limit: GCRA (leaky bucket)", map[string]interface{}{
		"algorithm":    "gcra",
		"max_requests": cfg.RateLimitMax,
		"window":       cfg.RateLimitWindow.String(),
	})
	return ratelimit.NewGCRALimiter(cfg.RateLimitMax, cfg.RateLimitWindow)
}

// setupNonceStore создаёт nonce store с учётом конфигурации шардов.
func setupNonceStore(cfg *config.Config, structuredLogger *logging.StructuredLogger) nonce.StoreInterface {
	shardCount := resolveShardCount(cfg.NonceShards)
	if shardCount > 1 {
		structuredLogger.Info("Nonce Store: sharded", map[string]interface{}{
			"shards": shardCount,
			"ttl":    cfg.NonceTTL.String(),
		})
		return nonce.NewShardedStore(cfg.NonceTTL, shardCount)
	}
	structuredLogger.Info("Nonce Store: single shard", map[string]interface{}{
		"ttl": cfg.NonceTTL.String(),
	})
	return nonce.NewStore(cfg.NonceTTL)
}

// setupRoutes регистрирует все HTTP маршруты сервера.
func setupRoutes(mux *http.ServeMux, s *handlers.Server, structuredLogger *logging.StructuredLogger) {
	// Применяем middleware: сначала логирование (для контекста), потом метрики
	// Страница с JS-челленджем
	mux.HandleFunc("/bot-check", s.MetricsMiddleware(s.LoggingMiddleware(s.BotCheckHandler)))
	// Верификация nonce и выдача clearance
	mux.HandleFunc("/bot-verify", s.MetricsMiddleware(s.LoggingMiddleware(s.BotVerifyHandler)))
	// Проверка валидности clearance (для nginx)
	mux.HandleFunc("/bot-validate", s.MetricsMiddleware(s.LoggingMiddleware(s.BotValidateHandler)))
	// Health check для мониторинга
	mux.HandleFunc("/health", s.MetricsMiddleware(s.LoggingMiddleware(s.HealthHandler)))

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())
	structuredLogger.Info("Prometheus metrics endpoint registered at /metrics")
}

// startBackgroundWorkers запускает фоновые горутины очистки и обновления метрик.
// Возвращает функцию остановки.
func startBackgroundWorkers(s *handlers.Server) func() {
	cleanupTicker := time.NewTicker(1 * time.Hour)
	cleanupDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-cleanupDone:
				return
			case <-cleanupTicker.C:
				s.Nonces.CleanupExpired()
				s.RateLimiter.Cleanup()
				if s.Metrics != nil {
					s.Metrics.SetGoroutineCount(runtime.NumGoroutine())
				}
				if s.Logger != nil {
					s.Logger.Info("Cleaned up expired nonces and rate limiter entries")
				}
			}
		}
	}()

	metricsTicker := time.NewTicker(10 * time.Second)
	metricsDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-metricsDone:
				return
			case <-metricsTicker.C:
				if s.Metrics != nil {
					s.Metrics.SetGoroutineCount(runtime.NumGoroutine())
				}
			}
		}
	}()

	return func() {
		cleanupTicker.Stop()
		close(cleanupDone)
		metricsTicker.Stop()
		close(metricsDone)
	}
}

// runServer запускает HTTP сервер и обрабатывает graceful shutdown.
func runServer(cfg *config.Config, mux *http.ServeMux, structuredLogger *logging.StructuredLogger,
	mlLogger *logging.Logger, stopWorkers func(),
) {
	addr := ":" + cfg.Port
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		structuredLogger.Info("Antibot server started", map[string]interface{}{"addr": addr})
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		signal.Stop(sigChan)
		structuredLogger.Error("Server error", err)
		os.Exit(1)
	case sig := <-sigChan:
		signal.Stop(sigChan)
		structuredLogger.Info("Received shutdown signal, starting graceful shutdown", map[string]interface{}{
			"signal": sig.String(),
		})

		stopWorkers()
		structuredLogger.Info("Background workers stopped")

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()

		structuredLogger.Info("Shutting down HTTP server", map[string]interface{}{
			"timeout": cfg.ShutdownTimeout.String(),
		})
		if err := server.Shutdown(ctx); err != nil {
			structuredLogger.Error("Error during server shutdown", err)
			if err := server.Close(); err != nil {
				structuredLogger.Error("Error closing server", err)
			}
		} else {
			structuredLogger.Info("HTTP server stopped gracefully")
		}

		if mlLogger != nil {
			structuredLogger.Info("Closing ML logger")
			if err := mlLogger.Close(); err != nil {
				structuredLogger.Error("Error closing ML logger", err)
			} else {
				structuredLogger.Info("ML logger closed")
			}
		}

		structuredLogger.Info("Shutdown complete")
	}
}

func main() {
	cfg := loadConfigOrExit()
	structuredLogger := setupLogger(cfg)
	mlLogger := setupMLLogger(cfg, structuredLogger)
	rateLimiter := setupRateLimiter(cfg, structuredLogger)
	nonceStore := setupNonceStore(cfg, structuredLogger)

	appMetrics := metrics.NewMetrics()
	structuredLogger.Info("Prometheus metrics initialized")

	s := &handlers.Server{
		Nonces:         nonceStore,
		ClearanceTTL:   cfg.ClearanceTTL,
		MasterSecret:   cfg.MasterSecret,
		RateLimiter:    rateLimiter,
		ScoringModel:   scoring.NewModel(cfg.ScoringThreshold),
		ScoringEnabled: cfg.ScoringEnabled,
		CaptchaEnabled: cfg.CaptchaEnabled,
		GetClientIP:    getClientIP,
		MLLogger:       mlLogger,
		RequestTimeout: cfg.RequestTimeout,
		Logger:         structuredLogger,
		Metrics:        appMetrics,
		ReturnURL:      cfg.ReturnURL,
	}

	mux := http.NewServeMux()
	setupRoutes(mux, s, structuredLogger)

	stopWorkers := startBackgroundWorkers(s)
	runServer(cfg, mux, structuredLogger, mlLogger, stopWorkers)
}
