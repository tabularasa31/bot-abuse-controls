# abuse-controls — developer Makefile.
#
# `make test` and `make lint` are the only two targets you need to know.
# Both run via docker if the host tool isn't installed, so admins can
# run them without setting up a Lua toolchain locally.

OPENRESTY_IMAGE  := openresty/openresty:alpine
LUACHECK_IMAGE   := pipelinecomponents/luacheck:latest
SHELLCHECK_IMAGE := koalaman/shellcheck:stable

LUA_FILES := $(shell find infra -name "*.lua" 2>/dev/null)
SH_FILES  := $(shell find scripts infra tests -name "*.sh" 2>/dev/null)

# ---------- Top-level ----------

.PHONY: help test test-host test-docker test-integration lint lint-lua lint-sh ci

HARNESS_DIR := infra/test-harness
HARNESS_COMPOSE := $(HARNESS_DIR)/docker-compose.test.yml

help:
	@printf "abuse-controls\n\n"
	@printf "Targets:\n"
	@printf "  test              Run unit tests (host luajit if available, else docker).\n"
	@printf "  test-host         Run tests via host luajit (requires luajit installed).\n"
	@printf "  test-docker       Run tests via openresty/openresty:alpine container.\n"
	@printf "  test-integration  Run Channel C contract tests (B13/D8) via docker compose.\n"
	@printf "  lint              Run all linters (luacheck + shellcheck) via docker.\n"
	@printf "  lint-lua          luacheck against all Lua files.\n"
	@printf "  lint-sh           shellcheck against all shell scripts.\n"
	@printf "  ci                Run tests + linters (what CI runs).\n"

test:
	@if command -v luajit >/dev/null 2>&1; then $(MAKE) test-host; \
	else echo "luajit not on host; falling back to docker"; $(MAKE) test-docker; fi

test-host:
	sh -c 'export LUA_PATH="infra/demo-stand/lua/?.lua;;"; luajit tests/ja4_helpers_test.lua && luajit tests/hygiene_test.lua && luajit tests/reputation_test.lua && luajit tests/rate_limit_test.lua && luajit tests/tls_fp_blocklist_state_test.lua && luajit tests/tls_fp_test.lua && luajit tests/catalog_pull_test.lua && luajit tests/log_shipper_test.lua && luajit tests/verified_bots_test.lua && luajit tests/policy_matchers_test.lua'

test-docker:
	docker run --rm -v $(PWD):/work -w /work $(OPENRESTY_IMAGE) \
		sh -c 'export LUA_PATH="infra/demo-stand/lua/?.lua;;"; luajit tests/ja4_helpers_test.lua && luajit tests/hygiene_test.lua && luajit tests/reputation_test.lua && luajit tests/rate_limit_test.lua && luajit tests/tls_fp_blocklist_state_test.lua && luajit tests/tls_fp_test.lua && luajit tests/catalog_pull_test.lua && luajit tests/log_shipper_test.lua && luajit tests/verified_bots_test.lua && luajit tests/policy_matchers_test.lua'

# ---------- Integration (D8 / B13) ----------

# Boot the harness stack, run tests/integration/run.sh against it, tear
# everything down regardless of outcome. Pass -v on the down step so
# postgres tmpfs / images that linger don't accumulate across CI jobs.
# `--wait` blocks `up` until all healthchecks are green; failures bail.
test-integration:
	$(HARNESS_DIR)/scripts/setup.sh
	docker compose -f $(HARNESS_COMPOSE) up -d --wait --quiet-pull
	@# Backend has no docker healthcheck (distroless image), so --wait
	@# doesn't gate cases on a ready /health. Poll host-side for up to
	@# 60s; the cascade tolerates a not-ready backend (fail-stale) but
	@# case 01 needs a working PATCH endpoint immediately.
	@printf "Waiting for backend /health..."
	@for i in $$(seq 1 60); do \
	  if curl -fsS http://127.0.0.1:18080/health >/dev/null 2>&1; then \
	    echo " ready in $${i}s"; break; \
	  fi; \
	  printf "."; sleep 1; \
	  if [ "$$i" -eq 60 ]; then echo " TIMEOUT"; exit 1; fi; \
	done
	@trap 'docker compose -f $(HARNESS_COMPOSE) down -v --remove-orphans >/dev/null' EXIT; \
	  tests/integration/run.sh

# ---------- Linters ----------

lint: lint-lua lint-sh

lint-lua:
	docker run --rm -v $(PWD):/work -w /work $(LUACHECK_IMAGE) \
		luacheck $(LUA_FILES)

lint-sh:
	docker run --rm -v $(PWD):/work -w /work $(SHELLCHECK_IMAGE) \
		-x $(SH_FILES)

# ---------- CI ----------

ci: test-docker lint
	@echo
	@echo "All checks passed."
