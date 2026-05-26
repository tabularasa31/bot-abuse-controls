-- Unit tests for infra/demo-stand/lua/challenge_secret.lua.
-- Pure Lua under host luajit (no openresty), so ngx is stubbed and
-- resty.sha256 is replaced with a fake digest that returns deterministic
-- bytes. We exercise load() + get() + fingerprint() against a tmp file.
--
-- Run with:
--   make test            (host luajit)
--   make test-docker     (inside openresty/openresty:alpine)

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

-- Minimal ngx.shared.<name> stub. Matches the subset of shdict API
-- challenge_secret.lua uses: get/set/delete. Pure in-memory.
local function make_shdict()
    local store = {}
    return {
        get    = function(self, k) return store[k] end,
        set    = function(self, k, v) store[k] = v; return true, nil, false end,
        delete = function(self, k) store[k] = nil; return true end,
    }
end

local shared = { challenge_secret = make_shdict() }
local log_calls = {}
_G.ngx = {
    shared = shared,
    log    = function(level, ...)
        log_calls[#log_calls + 1] = { level = level, msg = table.concat({...}, "") }
    end,
    -- log-level constants — challenge_secret.lua uses ERR/WARN/INFO.
    ERR  = "ERR",
    WARN = "WARN",
    INFO = "INFO",
}

-- Fake resty.sha256 — deterministic, returns 32 bytes derived from the
-- input length so fingerprint() is testable without pulling the real C
-- module under host luajit.
package.loaded["resty.sha256"] = {
    new = function()
        return {
            _buf = "",
            update = function(self, s) self._buf = self._buf .. s; return true end,
            final  = function(self)
                -- 32 bytes: byte 0 = #buf mod 256, rest = (i + first byte) mod 256.
                -- Stable per input, distinct between secrets of different lengths
                -- or content. Good enough for tests; production uses real SHA-256.
                local first = self._buf:byte(1) or 0
                local len   = #self._buf
                local bytes = {}
                bytes[1] = string.char(len % 256)
                for i = 2, 32 do
                    bytes[i] = string.char((first + i + len) % 256)
                end
                return table.concat(bytes)
            end,
        }
    end,
}

local cs = require "challenge_secret"

local function reset()
    shared.challenge_secret = make_shdict()
    -- Re-attach to ngx.shared so the module's `ngx.shared[DICT_NAME]`
    -- lookup picks up the fresh dict.
    _G.ngx.shared = shared
    log_calls = {}
end

local function write_tmp(content)
    local path = os.tmpname()
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
    return path
end

local function assert_eq(a, b, msg)
    if a ~= b then
        error((msg or "assert_eq") .. ": expected " .. tostring(b)
              .. ", got " .. tostring(a), 2)
    end
end

local tests = {}

-- 0. Nil / empty path → ERR, no crash (defensive guard so a misconfigured
--    caller can't take the worker down at init_by_lua time).
tests.nil_path = function()
    reset()
    assert_eq(cs.load(nil), false, "load(nil) should return false")
    assert_eq(cs.load(""), false, "load('') should return false")
    local errs = 0
    for _, c in ipairs(log_calls) do
        if c.level == "ERR" then errs = errs + 1 end
    end
    if errs < 2 then error("expected ERR for nil and empty path") end
end

-- 1. Missing file → WARN, get()/fingerprint() return nil.
tests.missing_file = function()
    reset()
    local ok = cs.load("/no/such/file/challenge_secret.key")
    assert_eq(ok, false, "load should fail on missing file")
    assert_eq(cs.get(), nil, "get should be nil on missing file")
    assert_eq(cs.fingerprint(), nil, "fingerprint should be nil on missing file")
    -- exactly one WARN line, mentions the path
    local warns = 0
    for _, c in ipairs(log_calls) do
        if c.level == "WARN" and c.msg:find("challenge_secret", 1, true) then
            warns = warns + 1
        end
    end
    assert_eq(warns, 1, "expected one WARN for missing file")
end

-- 2. Empty file / short secret → ERR, dict cleared.
tests.too_short = function()
    reset()
    local path = write_tmp("short\n")
    local ok = cs.load(path)
    os.remove(path)
    assert_eq(ok, false, "load should fail on short secret")
    assert_eq(cs.get(), nil)
    local errs = 0
    for _, c in ipairs(log_calls) do
        if c.level == "ERR" then errs = errs + 1 end
    end
    if errs == 0 then error("expected ERR log for short secret") end
end

-- 2b. Oversize file (e.g. mount accidentally pointing at /dev/urandom or
--     a large file) → ERR, dict cleared. Bounded read keeps init_by_lua
--     from blocking the master.
tests.too_large = function()
    reset()
    -- 2 KiB body — well over MAX_BYTES (1024) so the bounded read returns
    -- MAX_BYTES+1 bytes and the size guard rejects it.
    local path = write_tmp(string.rep("A", 2048))
    local ok = cs.load(path)
    os.remove(path)
    assert_eq(ok, false, "load should fail on oversize secret")
    assert_eq(cs.get(), nil)
    local saw_size_err = false
    for _, c in ipairs(log_calls) do
        if c.level == "ERR" and c.msg:find("larger than", 1, true) then
            saw_size_err = true
        end
    end
    if not saw_size_err then error("expected ERR mentioning size limit") end
end

-- 3. Valid secret → secret + fp in dict, INFO log, get/fingerprint match.
tests.valid_load = function()
    reset()
    local body = string.rep("A", 44)  -- 44 chars, like base64(32 bytes)
    local path = write_tmp(body .. "\n")  -- trailing newline trimmed
    local ok = cs.load(path)
    os.remove(path)
    assert_eq(ok, true, "load should succeed")
    local secret, fp = cs.get()
    assert_eq(secret, body, "secret should be the file body without trailing nl")
    if not fp or #fp ~= 8 then error("fp should be 8 hex chars, got " .. tostring(fp)) end
    assert_eq(cs.fingerprint(), fp, "fingerprint() should match get()'s fp")
end

-- 4. Rotation: second load overwrites secret and fp (simulates reload after
--    file replacement).
tests.rotation_overwrites = function()
    reset()
    local p1 = write_tmp(string.rep("A", 44))
    cs.load(p1)
    local s1, fp1 = cs.get()
    os.remove(p1)

    local p2 = write_tmp(string.rep("B", 44))
    cs.load(p2)
    local s2, fp2 = cs.get()
    os.remove(p2)

    if s1 == s2 then error("secret should change after rotation") end
    if fp1 == fp2 then error("fp should change after rotation") end
end

-- 5. Failure after a successful load wipes the previous secret (no
--    zombie secret across reload).
tests.failure_wipes_previous = function()
    reset()
    local p = write_tmp(string.rep("A", 44))
    cs.load(p)
    os.remove(p)
    assert(cs.get() ~= nil, "precondition: secret loaded")

    cs.load("/no/such/file/challenge_secret.key")
    assert_eq(cs.get(), nil, "failed reload should wipe previous secret")
    assert_eq(cs.fingerprint(), nil, "failed reload should wipe previous fp")
end

-- Runner
local failed = 0
for name, fn in pairs(tests) do
    local ok, err = pcall(fn)
    if ok then
        print("ok  - " .. name)
    else
        print("FAIL - " .. name .. ": " .. tostring(err))
        failed = failed + 1
    end
end

if failed > 0 then os.exit(1) end
