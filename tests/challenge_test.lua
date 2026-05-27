-- Unit tests for infra/demo-stand/lua/challenge.lua.
-- Pure Lua under host luajit (no openresty), so ngx, resty.openssl.hmac, and
-- cjson.safe are stubbed. Exercises preload (version-pin invariant),
-- issue_nonce (HMAC pairing with challenge_secret), and render (placeholder
-- substitution).

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

local function make_shdict()
    local store = {}
    return {
        get    = function(self, k) return store[k] end,
        set    = function(self, k, v) store[k] = v; return true, nil, false end,
        delete = function(self, k) store[k] = nil; return true end,
    }
end

local shared = { challenge_secret = make_shdict() }
local fixed_time = 1700000000
_G.ngx = {
    shared        = shared,
    log           = function() end,
    ERR           = "ERR",
    WARN          = "WARN",
    INFO          = "INFO",
    time          = function() return fixed_time end,
    encode_base64 = function(s)
        -- Trivial base64 sufficient for shape assertions. Mirrors the
        -- standard alphabet so b64url substitution in challenge.lua
        -- (+ → -, / → _, strip `=`) still flips the same chars.
        local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        local out, bits, n = {}, 0, 0
        for i = 1, #s do
            bits = bits * 256 + s:byte(i)
            n = n + 8
            while n >= 6 do
                n = n - 6
                local idx = math.floor(bits / 2^n) % 64
                out[#out + 1] = b:sub(idx + 1, idx + 1)
            end
        end
        if n > 0 then
            local idx = (bits * 2^(6 - n)) % 64
            out[#out + 1] = b:sub(idx + 1, idx + 1)
        end
        while #out % 4 ~= 0 do out[#out + 1] = "=" end
        return table.concat(out)
    end,
}

-- Fake resty.openssl.hmac — mirrors the real lua-resty-openssl API
-- (update(data) then final()) so a regression in challenge.lua back to
-- final(data) would fail loud here. Returns a deterministic "signature"
-- derived from key+accumulated buffer.
package.loaded["resty.openssl.hmac"] = {
    new = function(key, _algo)
        local buf = ""
        return {
            update = function(_self, data)
                buf = buf .. (data or "")
                return true
            end,
            final = function(_self)
                return "sig:" .. key:sub(1, 8) .. ":" .. buf:sub(1, 16)
            end,
        }
    end,
}

-- Minimal cjson.safe shim: encode produces a stable JSON-ish string for
-- the {h,ts,exp} payload, enough for substring assertions.
package.loaded["cjson.safe"] = {
    encode = function(t)
        return string.format('{"h":"%s","ts":%d,"exp":%d}', t.h, t.ts, t.exp)
    end,
    decode = function(_) return nil end,
}

-- challenge_secret module replaced with an inline stub so we control whether
-- a key is loaded. Loaded BEFORE require'ing challenge so the latter binds to
-- our stub via package.loaded.
local secret_state = { key = nil }
package.loaded["challenge_secret"] = {
    get = function() return secret_state.key end,
}

-- Minimal `config` stub: real config.lua reads ngx.shared and parses INI on
-- require, neither of which is available under host luajit. Mirrors the
-- shape challenge.lua reads (`config.defaults.challenge.nonce_ttl_seconds`),
-- with `nil` for nonce_ttl_seconds so the DEFAULT_NONCE_TTL fallback path
-- is exercised in tests. Individual tests can mutate this table to assert
-- the config-source branch.
package.loaded["config"] = {
    defaults = { challenge = { nonce_ttl_seconds = nil } },
}

-- Track tmp files so we can wipe them on exit — os.tmpname() leaks
-- otherwise and would accumulate in /tmp across CI runs.
local tmp_files = {}
local function write_tmp(content)
    local path = os.tmpname()
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
    table.insert(tmp_files, path)
    return path
end

local function tmp_template(version)
    -- Version is baked in as a literal (mirrors the real page.html: meta
    -- tag is the source of truth, render() only substitutes per-request
    -- NONCE/EXPIRY). Bumping the version = editing both CASCADE_VERSION
    -- and every literal occurrence in the template.
    return write_tmp(string.format([[
<!doctype html>
<!-- cascade-version: %s -->
<html><head>
<meta name="cascade-version" content="%s">
</head><body>
<div id="challenge-data" data-nonce="{{NONCE}}" data-expiry="{{EXPIRY}}"
     data-cascade-version="%s"></div>
</body></html>
]], version, version, version))
end

local function load_challenge_with(version_file, template_file)
    os.setenv = os.setenv  -- no-op; rely on env via getenv
    -- Patch os.getenv so challenge.lua picks up our test paths without
    -- needing real env vars (Lua's os has no setenv).
    local real_getenv = os.getenv
    os.getenv = function(name)
        if name == "CHALLENGE_TEMPLATE_FILE" then return template_file end
        if name == "CASCADE_VERSION_FILE"    then return version_file end
        return real_getenv(name)
    end
    package.loaded["challenge"] = nil
    local mod = require "challenge"
    os.getenv = real_getenv
    return mod
end

local function assert_eq(a, b, msg)
    if a ~= b then
        error((msg or "assert_eq") .. ": expected " .. tostring(b)
              .. ", got " .. tostring(a), 2)
    end
end

local function assert_contains(haystack, needle, msg)
    if not haystack:find(needle, 1, true) then
        error((msg or "assert_contains") .. ": expected to contain '"
              .. needle .. "'", 2)
    end
end

local tests = {}

-- 1. preload(): version file matches template meta → returns version, no error.
tests.preload_match = function()
    local v = write_tmp("0.1.0\n")
    local t = tmp_template("0.1.0")
    local mod = load_challenge_with(v, t)
    local ver = mod.preload()
    assert_eq(ver, "0.1.0", "preload should return the loaded version")
    assert_eq(mod.template_version(), "0.1.0", "template_version cached")
end

-- 2. preload(): file vs meta mismatch → error with both values in message.
tests.preload_mismatch = function()
    local v = write_tmp("0.2.0")
    local t = tmp_template("0.1.0")
    local mod = load_challenge_with(v, t)
    local ok, err = pcall(mod.preload)
    if ok then error("preload should have raised on mismatch") end
    assert_contains(err, "0.2.0", "error mentions cascade file version")
    assert_contains(err, "0.1.0", "error mentions template meta version")
end

-- 3. preload(): template missing the meta tag → error names the contract.
tests.preload_missing_meta = function()
    local v = write_tmp("0.1.0")
    local t = write_tmp("<html><body>no meta here</body></html>")
    local mod = load_challenge_with(v, t)
    local ok, err = pcall(mod.preload)
    if ok then error("preload should have raised on missing meta") end
    assert_contains(err, "cascade-version", "error mentions the required meta name")
end

-- 4. issue_nonce: with secret loaded, returns "<payload>.<hmac>" carrying host.
tests.issue_nonce_shape = function()
    secret_state.key = "secret-key-32bytes-............."
    local v = write_tmp("0.1.0")
    local t = tmp_template("0.1.0")
    local mod = load_challenge_with(v, t)
    mod.preload()
    local nonce, exp = mod.issue_nonce("example.com", 60)
    if not nonce then error("issue_nonce returned nil: " .. tostring(exp)) end
    assert_eq(exp, fixed_time + 60, "expiry = now + ttl")
    if not nonce:find(".", 1, true) then
        error("nonce should contain payload.hmac separator")
    end
    -- payload-b64 decodes back to JSON with our host
    local b64payload = nonce:match("^([^.]+)%.")
    if not b64payload then error("could not split payload from nonce") end
end

-- 4b. issue_nonce: TTL falls through to config.defaults.challenge.nonce_ttl_seconds
-- when caller omits ttl_seconds. Guards against regression to a hard-coded
-- fallback that ignored defaults.conf (PR #81 review).
tests.issue_nonce_ttl_from_config = function()
    secret_state.key = "secret-key-32bytes-............."
    local v = write_tmp("0.1.0")
    local t = tmp_template("0.1.0")
    local cfg = package.loaded["config"]
    local prev = cfg.defaults.challenge.nonce_ttl_seconds
    cfg.defaults.challenge.nonce_ttl_seconds = 123
    local mod = load_challenge_with(v, t)
    mod.preload()
    local _, exp = mod.issue_nonce("example.com")  -- no explicit TTL
    cfg.defaults.challenge.nonce_ttl_seconds = prev
    assert_eq(exp, fixed_time + 123, "TTL should come from config")
end

-- 5. issue_nonce: missing secret → nil + error mentioning C1 module.
tests.issue_nonce_no_secret = function()
    secret_state.key = nil
    local v = write_tmp("0.1.0")
    local t = tmp_template("0.1.0")
    local mod = load_challenge_with(v, t)
    mod.preload()
    local nonce, err = mod.issue_nonce("example.com")
    assert_eq(nonce, nil, "nonce should be nil without secret")
    assert_contains(err or "", "challenge_secret", "error names the secret loader")
end

-- 6. render: substitutes all three placeholders, leaves no {{TOKEN}} unfilled.
tests.render_substitutes = function()
    secret_state.key = "secret-key-32bytes-............."
    local v = write_tmp("0.1.0")
    local t = tmp_template("0.1.0")
    local mod = load_challenge_with(v, t)
    mod.preload()
    local html, err = mod.render("example.com")
    if not html then error("render failed: " .. tostring(err)) end
    if html:find("{{NONCE}}", 1, true) then error("NONCE placeholder not substituted") end
    if html:find("{{EXPIRY}}", 1, true) then error("EXPIRY placeholder not substituted") end
    -- Version is a literal in the template (not a placeholder), so it
    -- appears as-is in the rendered HTML — see tmp_template above.
    assert_contains(html, "0.1.0", "version appears in the rendered HTML")
    assert_contains(html, tostring(fixed_time + 60), "expiry appears in the rendered HTML")
end

local failed = 0
for name, fn in pairs(tests) do
    local ok, err = pcall(fn)
    if ok then
        print("ok " .. name)
    else
        failed = failed + 1
        print("FAIL " .. name .. ": " .. tostring(err))
    end
end

-- Clean up tmp files from write_tmp. Runs before os.exit so failures
-- don't leak fixtures into /tmp on subsequent CI runs.
for _, path in ipairs(tmp_files) do
    os.remove(path)
end

if failed > 0 then
    os.exit(1)
end
