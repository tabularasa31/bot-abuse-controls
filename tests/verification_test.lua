-- Unit tests for infra/demo-stand/lua/verification.lua (C4 L5 should_challenge).
-- Pure Lua under host luajit: только verification.decide() — чистая функция,
-- ngx и bac_log/policy не нужны. Покрытие — четыре acceptance-сценария задачи
-- плюс guard-кейсы (block/allow priority, пустые flags, неизвестный flag).

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

-- Стаб package.loaded для bac_log/policy — verification.lua делает
-- require, но decide() их не зовёт, так что заглушки достаточно.
package.loaded["bac_log"] = { set_verdict = function() end, add_flag = function() end }
package.loaded["policy"]  = { get = function() return {} end }

local verification = require "verification"

local passed, failed = 0, 0
local function check(actual_v, actual_r, want_v, want_r, name)
    if actual_v == want_v and actual_r == want_r then
        passed = passed + 1
    else
        failed = failed + 1
        io.write(string.format("FAIL %s: got (%s,%s), want (%s,%s)\n",
            name, tostring(actual_v), tostring(actual_r),
            tostring(want_v), tostring(want_r)))
    end
end

-- Helpers
local function ctx(verdict, flags, client, rule)
    return {
        verdict = verdict or "pass",
        rule = rule,
        flags = flags or {},
        client_challenge_flags = client,
    }
end
local function pol(strictness, attack_mode)
    return { strictness = strictness or "standard", attack_mode = attack_mode or false }
end

-- ---------------------------------------------------------------------------
-- Acceptance #1: Standard + системный flag → challenge
local v, r = verification.decide(
    ctx("pass", { "tls_fp_impersonator" }),
    pol("standard", false))
check(v, r, "challenge", "tls_fp_impersonator",
    "Standard + tls_fp_impersonator → challenge")

v, r = verification.decide(
    ctx("pass", { "tls_fp_suspicious_ciphers" }),
    pol("standard", false))
check(v, r, "challenge", "tls_fp_suspicious_ciphers",
    "Standard + tls_fp_suspicious_ciphers → challenge")

-- Both flags accumulate; last-system wins as rule (matches log convention).
v, r = verification.decide(
    ctx("pass", { "tls_fp_impersonator", "tls_fp_suspicious_ciphers" }),
    pol("standard", false))
check(v, r, "challenge", "tls_fp_suspicious_ciphers",
    "Standard + two system flags → challenge, rule = last")

-- ---------------------------------------------------------------------------
-- Acceptance #2: Permissive + системный flag → verdict=permissive
v, r = verification.decide(
    ctx("pass", { "tls_fp_impersonator" }),
    pol("permissive", false))
check(v, r, "permissive", "tls_fp_impersonator",
    "Permissive + system flag → permissive (log-only)")

v, r = verification.decide(
    ctx("pass", { "tls_fp_impersonator", "tls_fp_suspicious_ciphers" }),
    pol("permissive", false))
check(v, r, "permissive", "tls_fp_suspicious_ciphers",
    "Permissive + two system flags → permissive, rule = last")

-- ---------------------------------------------------------------------------
-- Acceptance #3: Permissive + клиентское rate-rule action=challenge → challenge
-- Контракт: client flag override'ит Permissive (явная настройка клиента).
v, r = verification.decide(
    ctx("pass", {}, { "rate_custom" }),
    pol("permissive", false))
check(v, r, "challenge", "rate_custom",
    "Permissive + client rate-rule challenge → challenge")

-- Client flag override'ит даже когда системные flag'и тоже есть.
v, r = verification.decide(
    ctx("pass", { "tls_fp_impersonator" }, { "rate_custom" }),
    pol("permissive", false))
check(v, r, "challenge", "rate_custom",
    "Permissive + system + client → challenge by client (override)")

-- ---------------------------------------------------------------------------
-- attack_mode (C7) override — force challenge, любой Strictness.
v, r = verification.decide(
    ctx("pass", { "tls_fp_impersonator" }),
    pol("permissive", true))
check(v, r, "challenge", "tls_fp_impersonator",
    "attack_mode + Permissive + system flag → challenge (rule = last flag)")

v, r = verification.decide(
    ctx("pass", {}),
    pol("standard", true))
check(v, r, "challenge", "attack_mode",
    "attack_mode + no flags → challenge with sentinel rule=attack_mode")

-- ---------------------------------------------------------------------------
-- Нет повода → ничего не делаем.
v, r = verification.decide(ctx("pass", {}), pol("standard", false))
check(v, r, nil, nil, "no flags + Standard → no decision (verdict stays pass)")

v, r = verification.decide(ctx("pass", {}), pol("permissive", false))
check(v, r, nil, nil, "no flags + Permissive → no decision")

-- Информационный тег (не системный flag) не триггерит — flag set явный.
v, r = verification.decide(
    ctx("pass", { "tls_fp:automation_ua" }),
    pol("standard", false))
check(v, r, nil, nil, "non-system flag (informational) → no decision")

-- ---------------------------------------------------------------------------
-- Guards: уже выставленный block не перезаписываем (даже attack_mode'ом).
v, r = verification.decide(
    ctx("block", { "tls_fp_impersonator" }),
    pol("standard", false))
check(v, r, nil, nil, "verdict=block already set → L5 keeps hands off")

v, r = verification.decide(
    ctx("block", {}, nil, "ip_blocklist"),
    pol("standard", true))
check(v, r, nil, nil, "verdict=block + attack_mode → block wins, no override")

-- allow guards — по rule различаем кто его поставил.
-- cookie_valid под attack_mode → override → challenge (codex PR #86 review).
v, r = verification.decide(
    ctx("allow", {}, nil, "cookie_valid"),
    pol("standard", true))
check(v, r, "challenge", "attack_mode",
    "attack_mode + verdict=allow,cookie_valid → challenge (pre-attack cookie)")

v, r = verification.decide(
    ctx("allow", { "tls_fp_impersonator" }, nil, "cookie_valid"),
    pol("permissive", true))
check(v, r, "challenge", "tls_fp_impersonator",
    "attack_mode + cookie_valid allow + system flag → challenge (rule = last flag)")

-- ip_whitelist / bot_verified allow остаются fastpass даже под attack_mode
-- (rules-reference §attack_mode: verified-bot и IP-whitelist продолжают фастпасить).
v, r = verification.decide(
    ctx("allow", {}, nil, "ip_whitelist"),
    pol("standard", true))
check(v, r, nil, nil,
    "attack_mode + verdict=allow,ip_whitelist → fastpass stays (no override)")

v, r = verification.decide(
    ctx("allow", { "tls_fp_impersonator" }, nil, "bot_verified"),
    pol("standard", true))
check(v, r, nil, nil,
    "attack_mode + verdict=allow,bot_verified + system flag → fastpass stays")

v, r = verification.decide(
    ctx("allow", {}, nil, "policy.ip_whitelist"),
    pol("permissive", true))
check(v, r, nil, nil,
    "attack_mode + verdict=allow,policy.ip_whitelist → fastpass stays")

-- allow без attack_mode — L5 не трогает вне зависимости от rule.
v, r = verification.decide(
    ctx("allow", { "tls_fp_impersonator" }, { "rate_custom" }, "cookie_valid"),
    pol("permissive", false))
check(v, r, nil, nil,
    "no attack_mode + allow + flags + client → fastpass (L5 keeps hands off)")

-- Defensive: client_challenge_flags non-table (boolean/string) не должен ронять
-- decide() — gemini PR #86 review.
v, r = verification.decide(
    { verdict = "pass", flags = {}, client_challenge_flags = true },
    pol("standard", false))
check(v, r, nil, nil, "non-table client_challenge_flags → ignored (no crash)")

v, r = verification.decide(
    { verdict = "pass", flags = {}, client_challenge_flags = "rate_custom" },
    pol("standard", false))
check(v, r, nil, nil, "string client_challenge_flags → ignored (no crash)")

-- ---------------------------------------------------------------------------
-- nil-safety
v, r = verification.decide(nil, pol())
check(v, r, nil, nil, "nil ctx → no decision")
v, r = verification.decide(ctx(), nil)
check(v, r, nil, nil, "nil policy → no decision")

-- ---------------------------------------------------------------------------
io.write(string.format("\nverification_test: %d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
