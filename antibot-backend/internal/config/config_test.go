package config_test

import (
	"testing"

	"github.com/tabularasa31/antibot-backend/internal/config"
)

// TestLoad_MigrateOnStartup_AcceptsCaseVariants — PR #43 review (Angle A):
// раньше switch'е по литералам отказывал на 'True'/'False'/'FALSE', хотя
// они идиоматичны для YAML/k8s-secret. Сейчас через strconv.ParseBool.
func TestLoad_MigrateOnStartup_AcceptsCaseVariants(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"t", true},
		{"T", true},
		{"yes", true}, // legacy — PR #43 follow-up
		{"YES", true},
		{"false", false},
		{"False", false},
		{"FALSE", false},
		{"0", false},
		{"f", false},
		{"F", false},
		{"no", false},
		{"NO", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Setenv("MIGRATE_ON_STARTUP", tc.in)
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.MigrateOnStartup != tc.want {
				t.Errorf("MIGRATE_ON_STARTUP=%q → %v, want %v", tc.in, cfg.MigrateOnStartup, tc.want)
			}
		})
	}
}

func TestLoad_MigrateOnStartup_RejectsGarbage(t *testing.T) {
	t.Setenv("MIGRATE_ON_STARTUP", "maybe")
	if _, err := config.Load(); err == nil {
		t.Fatal("Load: ожидалась ошибка для невалидного MIGRATE_ON_STARTUP")
	}
}

// TestLoad_DashboardAPIToken — пустой по умолчанию (fail-closed: handler
// не регистрируется), читается из ENV.
func TestLoad_DashboardAPIToken(t *testing.T) {
	t.Run("default empty", func(t *testing.T) {
		t.Setenv("DASHBOARD_API_TOKEN", "")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.DashboardAPIToken != "" {
			t.Errorf("DashboardAPIToken default = %q, want empty", cfg.DashboardAPIToken)
		}
	})
	t.Run("from env", func(t *testing.T) {
		t.Setenv("DASHBOARD_API_TOKEN", "s3cret-xyz")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.DashboardAPIToken != "s3cret-xyz" {
			t.Errorf("DashboardAPIToken = %q, want s3cret-xyz", cfg.DashboardAPIToken)
		}
	})
}
