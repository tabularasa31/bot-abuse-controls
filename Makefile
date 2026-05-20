# abuse-controls — developer Makefile.
#
# `make test` and `make lint` are the only two targets you need to know.
# Both run via docker if the host tool isn't installed, so admins can
# run them without setting up a Lua toolchain locally.

OPENRESTY_IMAGE  := openresty/openresty:alpine
LUACHECK_IMAGE   := pipelinecomponents/luacheck:latest
SHELLCHECK_IMAGE := koalaman/shellcheck:stable

LUA_FILES := $(shell find infra -name "*.lua" 2>/dev/null)
SH_FILES  := $(shell find scripts infra -name "*.sh" 2>/dev/null)

# ---------- Top-level ----------

.PHONY: help test test-host test-docker lint lint-lua lint-sh ci

help:
	@printf "abuse-controls\n\n"
	@printf "Targets:\n"
	@printf "  test         Run unit tests (host luajit if available, else docker).\n"
	@printf "  test-host    Run tests via host luajit (requires luajit installed).\n"
	@printf "  test-docker  Run tests via openresty/openresty:alpine container.\n"
	@printf "  lint         Run all linters (luacheck + shellcheck) via docker.\n"
	@printf "  lint-lua     luacheck against all Lua files.\n"
	@printf "  lint-sh      shellcheck against all shell scripts.\n"
	@printf "  ci           Run tests + linters (what CI runs).\n"

test:
	@if command -v luajit >/dev/null 2>&1; then $(MAKE) test-host; \
	else echo "luajit not on host; falling back to docker"; $(MAKE) test-docker; fi

test-host:
	luajit tests/ja4_helpers_test.lua
	luajit tests/hygiene_test.lua

test-docker:
	docker run --rm -v $(PWD):/work -w /work $(OPENRESTY_IMAGE) \
		sh -c "luajit tests/ja4_helpers_test.lua && luajit tests/hygiene_test.lua"

# ---------- Linters ----------

lint: lint-lua lint-sh

lint-lua:
	docker run --rm -v $(PWD):/work -w /work $(LUACHECK_IMAGE) \
		luacheck $(LUA_FILES)

lint-sh:
	docker run --rm -v $(PWD):/work -w /work $(SHELLCHECK_IMAGE) \
		$(SH_FILES)

# ---------- CI ----------

ci: test-docker lint
	@echo
	@echo "All checks passed."
