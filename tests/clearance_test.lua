-- Unit tests for infra/demo-stand/lua/clearance.lua (C3 L2.1 verify).
-- Pure Lua under host luajit: ngx, resty.openssl.hmac, challenge_secret,
-- config stubbed. Covers the six task-acceptance result codes:
--   valid / invalid / expired / missing / wrong_site / malformed
-- plus a couple of guard cases (no_secret, ct_eq same-length differ).

package.path = "infra/demo-stand/lua/?.lua;" .. package.path

-- Track tmp files (none needed for clearance, but keep parity helpers
-- with challenge_test.lua in case future tests grow fixtures).

-- --- ngx stub ------------------------------------------------------------
local function make_shdict()
    local store = {}
    return {
        get    = function(_self, k) return store[k] end,
        set    = function(_self, k, v) store[k] = v; return true end,
        delete = function(_self, k) store[k] = nil; return true end,
    }
end

local cookies = {}    -- mutate per test: cookies["tf_clearance"] = "..."
local fixed_time = 1700000000

_G.ngx = {
    shared = { challenge_secret = make_shdict() },
    log    = function() end,
    ERR    = "ERR",
    WARN   = "WARN",
    INFO   = "INFO",
    time   = function() return fixed_time end,
    var    = setmetatable({}, {
        __index = function(_t, k)
            local name = k:match("^cookie_(.+)$")
            if name then return cookies[name] end
            return nil
        end,
    }),
    -- Standard base64 / decode. Mantissa-safe — bits stays bounded by
    -- masking to the low `n` bits after each extraction. The naive shim
    -- in challenge_test.lua lets `bits` grow unbounded, which breaks
    -- silently past 6-7 input bytes (double-precision rounding); we feed
    -- 32-byte HMAC sigs through here, so the fix is required.
    encode_base64 = function(s)
        local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        local bit = require "bit"
        local out, bits, n = {}, 0, 0
        for i = 1, #s do
            bits = bit.bor(bit.lshift(bits, 8), s:byte(i))
            n = n + 8
            while n >= 6 do
                n = n - 6
                local idx = bit.band(bit.rshift(bits, n), 0x3F)
                out[#out + 1] = b:sub(idx + 1, idx + 1)
            end
        end
        if n > 0 then
            local idx = bit.band(bit.lshift(bits, 6 - n), 0x3F)
            out[#out + 1] = b:sub(idx + 1, idx + 1)
        end
        while #out % 4 ~= 0 do out[#out + 1] = "=" end
        return table.concat(out)
    end,
    decode_base64 = function(s)
        local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        local bit = require "bit"
        local lookup = {}
        for i = 1, #b do lookup[b:sub(i, i)] = i - 1 end
        s = s:gsub("=+$", "")
        local out, bits, n = {}, 0, 0
        for i = 1, #s do
            local c = s:sub(i, i)
            local v = lookup[c]
            if not v then return nil end
            bits = bit.bor(bit.lshift(bits, 6), v)
            n = n + 6
            while n >= 8 do
                n = n - 8
                local byte = bit.band(bit.rshift(bits, n), 0xFF)
                out[#out + 1] = string.char(byte)
            end
        end
        return table.concat(out)
    end,
}

-- --- resty.openssl.hmac stub --------------------------------------------
-- Deterministic 32-byte "signature" derived from key+buffer so tests can
-- forge cookies with the SAME shim that the module uses. Returns 32 bytes
-- so ct_eq length check passes (real HMAC-SHA256 is also 32 bytes).
package.loaded["resty.openssl.hmac"] = {
    new = function(key, _algo)
        local buf = ""
        return {
            update = function(_s, data) buf = buf .. (data or ""); return true end,
            final  = function(_s)
                -- Pad/truncate (key .. ":" .. buf) to 32 bytes — readable
                -- repr so a failing test can eyeball mismatches.
                local raw = "k=" .. key:sub(1, 8) .. ";b=" .. buf
                if #raw < 32 then raw = raw .. string.rep("Z", 32 - #raw) end
                return raw:sub(1, 32)
            end,
        }
    end,
}

-- --- challenge_secret stub -----------------------------------------------
local secret_state = { key = "secret-key-32bytes-AAAAAAAAAAAAA" }
package.loaded["challenge_secret"] = {
    get = function() return secret_state.key end,
}

-- --- config stub ---------------------------------------------------------
package.loaded["config"] = {
    defaults = {
        allow = { cookie_valid = { cookie_name = "tf_clearance" } },
    },
}

-- --- helpers -------------------------------------------------------------
package.loaded["clearance"] = nil
local clearance = require "clearance"

local function b64url(s)
    return (ngx.encode_base64(s):gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

-- Build a cookie via the module's own issue() so the test format always
-- tracks the production format. issue uses the SAME fake hmac as verify,
-- so a roundtrip is genuine — not a mock-vs-mock tautology, since verify
-- recomputes the signature independently.
local function mint(host, ttl, now)
    local raw, exp_or_err = clearance.issue(host, ttl, now)
    if not raw then error("mint failed: " .. tostring(exp_or_err)) end
    return raw, exp_or_err
end

local function set_cookie(raw) cookies["tf_clearance"] = raw end
local function clear_cookie()    cookies["tf_clearance"] = nil end

local function assert_eq(a, b, msg)
    if a ~= b then
        error((msg or "assert_eq") .. ": expected " .. tostring(b)
              .. ", got " .. tostring(a), 2)
    end
end

local tests = {}

-- 1. Valid cookie: HMAC ok + site matches + not expired → "valid".
tests.valid = function()
    set_cookie(mint("example.com", 3600))
    assert_eq(clearance.verify("example.com"), "valid")
end

-- 2. Forged HMAC: take a valid cookie and swap its sig with the sig
--    from a DIFFERENT body. Verify recomputes the expected HMAC for the
--    cookie's body, ct_eq mismatches → "invalid". (Mutating a single
--    last-char of b64 isn't reliable: trailing padding bits may not
--    affect the decoded raw bytes for length=32 sigs.)
tests.invalid_hmac = function()
    local good = mint("example.com", 3600)
    local other = mint("attacker.com", 3600)
    local good_body  = good:match("^(.+)%.")
    local other_sig  = other:match("%.([^.]+)$")
    set_cookie(good_body .. "." .. other_sig)
    assert_eq(clearance.verify("example.com"), "invalid")
end

-- 3. Wrong site: cookie minted for site-a, request comes in on site-b.
--    HMAC still validates (we use the same secret), but payload.site
--    mismatches request host → "wrong_site". Catches cross-tenant leak.
tests.wrong_site = function()
    set_cookie(mint("site-a.example.com", 3600))
    assert_eq(clearance.verify("site-b.example.com"), "wrong_site")
end

-- 4. Expired: TTL=1 sec, mint at fixed_time - 60 → exp is in the past.
--    HMAC still validates (signs whatever expiry was baked in), but
--    exp <= now → "expired".
tests.expired = function()
    -- mint with now=fixed_time-60 and ttl=1 → exp = fixed_time-59
    set_cookie(mint("example.com", 1, fixed_time - 60))
    assert_eq(clearance.verify("example.com"), "expired")
end

-- 5. Missing cookie: no `tf_clearance` header at all → "missing".
tests.missing = function()
    clear_cookie()
    assert_eq(clearance.verify("example.com"), "missing")
end

-- 6. Malformed: cookie present but doesn't fit `<body>.<sig>` shape.
--    Caught before HMAC compute → "malformed". Several flavors:
tests.malformed_no_dot = function()
    set_cookie("just-a-random-string-no-separator")
    assert_eq(clearance.verify("example.com"), "malformed")
end

tests.malformed_bad_body = function()
    -- well-formed `.` split, but body doesn't match `<b64>:<num>:<num>`.
    set_cookie("not-a-valid-body.sig-segment")
    assert_eq(clearance.verify("example.com"), "malformed")
end

-- 7. Guard: challenge_secret unloaded → verify treats cookie as invalid
--    (fail-closed for fastpath; cascade proceeds via normal path).
tests.no_secret_loaded = function()
    -- Mint while secret IS loaded, then unload BEFORE verify.
    set_cookie(mint("example.com", 3600))
    local saved = secret_state.key
    secret_state.key = nil
    local result = clearance.verify("example.com")
    secret_state.key = saved
    assert_eq(result, "invalid")
end

-- 8. Guard: ct_eq doesn't early-exit on first byte. Hard to test for true
--    constant time in pure Lua (no timing primitives), but we can at least
--    assert that a cookie differing only in the LAST sig byte is rejected
--    the same as one differing in the FIRST — both must return "invalid".
--    Already covered by `invalid_hmac` (last byte mutation); add a
--    first-byte mutation for completeness.
tests.invalid_hmac_first_byte = function()
    local raw = mint("example.com", 3600)
    local body, sig = raw:match("^(.+)%.(.+)$")
    local mutated_sig = (sig:sub(1, 1) == "A" and "B" or "A") .. sig:sub(2)
    set_cookie(body .. "." .. mutated_sig)
    assert_eq(clearance.verify("example.com"), "invalid")
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

if failed > 0 then
    os.exit(1)
end
