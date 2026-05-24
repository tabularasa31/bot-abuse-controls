// Package config gathers env-driven settings for the antibot-backend skeleton.
//
// Only the knobs the [B2] skeleton actually consumes live here. Per-feature
// settings (catalog ETag policy, log-receiver batch sizes, rDNS strategy)
// belong to B3/B6/B7/B9 and will land alongside those features.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Instance — короткая метка экземпляра в /health и логах, чтобы LB-round-robin
	// был наблюдаем (см. infra/demo-backend/scripts/verify.sh шаг 3 "HA").
	Instance string
	// HTTPAddr — слушаем именно его. LB ходит на :8080, как и плейсхолдер из B1.
	HTTPAddr string
	// PostgresDSN — DSN для pgxpool. Пустая строка = DB необязательна
	// (skeleton-режим: сервис поднимется и пройдёт acceptance B1, но любые
	// будущие фичи B3/B6/B7, которым DB нужна, должны это явно проверять).
	PostgresDSN string
	// RDNSInterval — устаревший knob от B2-скелета (фоновый тик воркера).
	// В B7 воркер reactive — никаких периодических тиков по очереди нет,
	// триггер — поток логов. Оставлен для обратной совместимости с
	// compose-файлами; реальное значение игнорируется. Будет удалён в B15
	// (миграция конфига).
	RDNSInterval time.Duration
	// RDNSQueueSize — буфер reactive-очереди (Enqueue → consumer).
	// Переполнение = receiver получает дроп задачи в метрику, edge
	// продолжит выдавать provisional. См. rdns.DefaultConfig().
	RDNSQueueSize int
	// RDNSWorkers — параллельных DNS-резолверов на воркера.
	RDNSWorkers int
	// RDNSDNSTimeout — потолок на одну итерацию проверки IP. Защищает
	// consumer-слот от зависшего DNS-резолвера.
	RDNSDNSTimeout time.Duration
	// RDNSGCInterval — как часто DELETE'им протухшие verified_bot_ips.
	// Час сильно реже TTL (1ч) — таблица не пухнет, нагрузки на DB нет.
	RDNSGCInterval time.Duration
	// ShutdownTimeout — таймаут graceful-shutdown HTTP-сервера.
	ShutdownTimeout time.Duration
	// CatalogYAMLPath — путь до YAML с восемью каталогами Channel C (B3).
	// Пустая строка = не грузим из YAML. Если задан POSTGRES_DSN, источником
	// каталогов становится БД (B4), CATALOG_YAML игнорируется (либо может быть
	// прогнан до миграций как fallback на dev-стенде — об этом решает main).
	CatalogYAMLPath string

	// CatalogReloadInterval — как часто backend перечитывает каталоги из
	// PostgreSQL (B4). Дефолт 5 с короче, чем edge-poll (30 с), чтобы
	// дашборд-edit гарантированно доезжал на edge ≤30 c (acceptance B4/B13).
	CatalogReloadInterval time.Duration

	// MigrateOnStartup — если true и POSTGRES_DSN задан, backend применит
	// встроенные миграции до Bootstrap'a reloader'a. Дефолт true: миграции
	// идемпотентны (CREATE TABLE IF NOT EXISTS), а ручной шаг до B15
	// добавил бы внешний failure-mode "забыли накатить".
	MigrateOnStartup bool

	// LogsSinkSpoolDir — где складывать NDJSON-батчи BAC_LOG при простое
	// PostgreSQL ([B9]). Пустая строка = spill отключён (sink будет терять
	// строки при недоступности DB — допустимо для dev/CI; в проде надо
	// задать persistent volume в compose'е, иначе acceptance B9 «disk-queue
	// в backend» не выполняется). Дефолта НЕТ намеренно: дефолтный
	// /var/lib/... под root upset'ил бы dev-запуск без root'a, а
	// пограничный сценарий «забыл задать в проде» виден в логе как явный
	// WARN при инициализации.
	LogsSinkSpoolDir string
	// LogsSinkBatchSize / LogsSinkFlushInterval — пороги флаша на DB.
	LogsSinkBatchSize     int
	LogsSinkFlushInterval time.Duration
	// LogsSinkQueueSize — bound на in-memory очередь Submit→consumer.
	LogsSinkQueueSize int
	// LogsSinkSpoolMaxBytes — потолок размера спул-каталога. При превышении
	// старейшие батчи удаляются с метрикой spool_dropped_files_total.
	LogsSinkSpoolMaxBytes int64
	// LogsSinkDrainInterval — как часто пробуем вернуть спул в DB.
	LogsSinkDrainInterval time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Instance:              getenv("INSTANCE_NAME", mustHostname()),
		HTTPAddr:              getenv("HTTP_ADDR", ":8080"),
		PostgresDSN:           os.Getenv("POSTGRES_DSN"),
		RDNSInterval:          30 * time.Minute,
		RDNSQueueSize:         1024,
		RDNSWorkers:           4,
		RDNSDNSTimeout:        5 * time.Second,
		RDNSGCInterval:        time.Hour,
		ShutdownTimeout:       10 * time.Second,
		CatalogYAMLPath:       os.Getenv("CATALOG_YAML"),
		CatalogReloadInterval: 5 * time.Second,
		MigrateOnStartup:      true,
		LogsSinkSpoolDir:      os.Getenv("LOGS_SINK_SPOOL_DIR"),
		LogsSinkBatchSize:     500,
		LogsSinkFlushInterval: 2 * time.Second,
		LogsSinkQueueSize:     8192,
		LogsSinkSpoolMaxBytes: 256 << 20,
		LogsSinkDrainInterval: 10 * time.Second,
	}
	if v := os.Getenv("CATALOG_RELOAD_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("CATALOG_RELOAD_INTERVAL: %w", err)
		}
		cfg.CatalogReloadInterval = d
	}
	if v := os.Getenv("MIGRATE_ON_STARTUP"); v != "" {
		// Принимаем:
		//   - всё, что понимает strconv.ParseBool (1/t/T/TRUE/true/True и
		//     0/f/F/FALSE/false/False — идиоматично для YAML/k8s-secret'ов);
		//   - историческое 'yes'/'no' (case-insensitive) — раньше брал
		//     ручной switch, ParseBool их не знает. Не ломаем чужие
		//     compose/manifest'ы из-за чистоты Go-парсера. PR #43 review.
		b, err := parseBoolWithYesNo(v)
		if err != nil {
			return cfg, fmt.Errorf("MIGRATE_ON_STARTUP: %w", err)
		}
		cfg.MigrateOnStartup = b
	}
	// RDNS_INTERVAL — deprecated после B7 (воркер reactive, периодики нет).
	// Принимаем любое значение, включая невалидное / 0 / -1, чтобы старые
	// compose'ы из B2 эры не ломали запуск. Реально нигде не читается.
	// PR #53 review.
	_ = os.Getenv("RDNS_INTERVAL")
	if v := os.Getenv("RDNS_QUEUE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("RDNS_QUEUE_SIZE: must be positive int, got %q", v)
		}
		cfg.RDNSQueueSize = n
	}
	if v := os.Getenv("RDNS_WORKERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("RDNS_WORKERS: must be positive int, got %q", v)
		}
		cfg.RDNSWorkers = n
	}
	if v := os.Getenv("RDNS_DNS_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("RDNS_DNS_TIMEOUT: %w", err)
		}
		cfg.RDNSDNSTimeout = d
	}
	if v := os.Getenv("RDNS_GC_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("RDNS_GC_INTERVAL: %w", err)
		}
		cfg.RDNSGCInterval = d
	}
	if v := os.Getenv("SHUTDOWN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = d
	}
	// time.NewTicker паникует при <=0, не даём пользователю прострелить ногу.
	// RDNSInterval — deprecated, не валидируем (см. выше).
	if cfg.ShutdownTimeout <= 0 {
		return cfg, fmt.Errorf("SHUTDOWN_TIMEOUT must be > 0, got %s", cfg.ShutdownTimeout)
	}
	if cfg.CatalogReloadInterval <= 0 {
		return cfg, fmt.Errorf("CATALOG_RELOAD_INTERVAL must be > 0, got %s", cfg.CatalogReloadInterval)
	}
	if cfg.RDNSDNSTimeout <= 0 {
		return cfg, fmt.Errorf("RDNS_DNS_TIMEOUT must be > 0, got %s", cfg.RDNSDNSTimeout)
	}
	if cfg.RDNSGCInterval <= 0 {
		return cfg, fmt.Errorf("RDNS_GC_INTERVAL must be > 0, got %s", cfg.RDNSGCInterval)
	}
	if v := os.Getenv("LOGS_SINK_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_BATCH_SIZE: must be positive int, got %q", v)
		}
		cfg.LogsSinkBatchSize = n
	}
	if v := os.Getenv("LOGS_SINK_FLUSH_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_FLUSH_INTERVAL: %v", err)
		}
		cfg.LogsSinkFlushInterval = d
	}
	if v := os.Getenv("LOGS_SINK_QUEUE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_QUEUE_SIZE: must be positive int, got %q", v)
		}
		cfg.LogsSinkQueueSize = n
	}
	if v := os.Getenv("LOGS_SINK_SPOOL_MAX_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_SPOOL_MAX_BYTES: must be positive int, got %q", v)
		}
		cfg.LogsSinkSpoolMaxBytes = n
	}
	if v := os.Getenv("LOGS_SINK_DRAIN_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("LOGS_SINK_DRAIN_INTERVAL: %v", err)
		}
		cfg.LogsSinkDrainInterval = d
	}
	return cfg, nil
}

// parseBoolWithYesNo расширяет strconv.ParseBool — добавляет
// case-insensitive 'yes'/'no', которые принимал предыдущий ручной
// switch и которые до сих пор встречаются в k8s/YAML конфигах.
// PR #43 follow-up.
func parseBoolWithYesNo(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return strconv.ParseBool(v)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "antibot-backend"
	}
	return h
}
