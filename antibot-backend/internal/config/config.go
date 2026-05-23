// Package config gathers env-driven settings for the antibot-backend skeleton.
//
// Only the knobs the [B2] skeleton actually consumes live here. Per-feature
// settings (catalog ETag policy, log-receiver batch sizes, rDNS strategy)
// belong to B3/B6/B7/B9 and will land alongside those features.
package config

import (
	"fmt"
	"os"
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
	// RDNSInterval — тик rDNS-воркера (наполнение verified_bot_ips, B7).
	// Сам воркер — заглушка под B7; на скелете просто доказываем, что он живёт.
	RDNSInterval time.Duration
	// ShutdownTimeout — таймаут graceful-shutdown HTTP-сервера.
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Instance:        getenv("INSTANCE_NAME", mustHostname()),
		HTTPAddr:        getenv("HTTP_ADDR", ":8080"),
		PostgresDSN:     os.Getenv("POSTGRES_DSN"),
		RDNSInterval:    30 * time.Minute,
		ShutdownTimeout: 10 * time.Second,
	}
	if v := os.Getenv("RDNS_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("RDNS_INTERVAL: %w", err)
		}
		cfg.RDNSInterval = d
	}
	if v := os.Getenv("SHUTDOWN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = d
	}
	// time.NewTicker паникует при <=0, не даём пользователю прострелить ногу.
	if cfg.RDNSInterval <= 0 {
		return cfg, fmt.Errorf("RDNS_INTERVAL must be > 0, got %s", cfg.RDNSInterval)
	}
	if cfg.ShutdownTimeout <= 0 {
		return cfg, fmt.Errorf("SHUTDOWN_TIMEOUT must be > 0, got %s", cfg.ShutdownTimeout)
	}
	return cfg, nil
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
