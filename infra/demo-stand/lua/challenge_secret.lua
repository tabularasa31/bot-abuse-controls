-- The Phase 4 HMAC secret for the clearance cookie (vision §"The HMAC secret for the
-- clearance cookie", §Channel A; config-templates.md §9). One secret shared across
-- the whole edge pool, which L5 uses to sign the cookie (issue) and the self-signed
-- nonce of the challenge page, and which L2.1 uses to verify the cookie on the fastpath. All of it
-- locally, with no call to the backend.
--
-- Delivery. In production it is Puppet (Channel A). On the demo stand Channel A is a
-- file mount (the same principle as kill_switch.local.conf and ./certs/*.pem):
-- the editor puts the file on the VM and the operator runs `openresty -s reload`. No
-- Puppet/Salt/container recreate.
--
-- Rotation = a reload. init_by_lua re-runs on every nginx -s reload and
-- rereads the file, and the secret in the shared_dict is overwritten. Cookies signed with
-- the old secret stop passing the HMAC verify at L2.1 — the client walks the
-- cascade to L5 and solves the challenge again (by design, see vision §"Rotation":
-- "a new version through a PR plus an nginx reload; rotation invalidates every previously
-- issued cookie at once").
--
-- The shared_dict survives a reload (like `meta` / `tls_fp_blocklist` — see the
-- audit note in init.lua). That matters for reader resilience,
-- but it creates a "zombie secret" trap: if the file were deleted accidentally and a
-- reload happened, the old value would stay in memory. So load() in any
-- failure mode explicitly :delete()s both records — fail-closed.

local DICT_NAME = "challenge_secret"
local KEY_SECRET = "secret"
local KEY_FP     = "fp"
-- 32 bytes is the minimum for an HMAC-SHA256 key; a realistic secret arrives
-- through `openssl rand -base64 32` (~44 base64 characters). We reject shorter ones,
-- so as not to accidentally load a "TODO"/"changeme"/test string.
local MIN_BYTES = 32
-- A hard ceiling on the file size — protection from a mis-mount (if
-- CHALLENGE_HMAC_SECRET_FILE accidentally pointed at /dev/urandom or at a
-- large file): f:read('*a') would block the master in init_by_lua and the stand
-- would not come up. A real secret is ~44 bytes; 1024 leaves plenty of room and
-- is guaranteed to finish in one read. If anyone ever needs longer keys,
-- raise this limit deliberately.
local MAX_BYTES = 1024

local _M = {}

-- Trim the trailing newline and whitespace, leaving the base64 body untouched.
local function rstrip(s)
    return (s:gsub("[%s%c]+$", ""))
end

-- The 8-hex prefix of sha256(secret). Used in /__version and /__admin as a
-- safe marker that the reload picked up the file we expected. The secret itself
-- is never exposed.
local function fingerprint(secret)
    local sha256 = require "resty.sha256"
    local h = sha256:new()
    h:update(secret)
    local digest = h:final()
    -- The digest is 32 raw bytes; we turn the first four into 8 hex characters.
    return (digest:sub(1, 4):gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

local function clear(dict)
    dict:delete(KEY_SECRET)
    dict:delete(KEY_FP)
end

-- load(path) — reads the file, validates it and puts it into the shared_dict. Any
-- failure mode (no file / empty / shorter than MIN_BYTES) is logged and
-- clears the previous value in the dict (fail-closed: better that consumers C3/C5
-- see "there is no secret" and skip the cookie verify/issue than work
-- with a stale secret). It is called from init_by_lua, so ngx.log is
-- available. It returns true on success and false otherwise — for the tests.
function _M.load(path)
    if type(path) ~= "string" or path == "" then
        ngx.log(ngx.ERR, "challenge_secret: load(path) needs a non-empty string, got ",
            type(path))
        return false
    end

    local dict = ngx.shared[DICT_NAME]
    if not dict then
        ngx.log(ngx.ERR, "challenge_secret: shared_dict `", DICT_NAME,
            "` not declared in nginx.conf")
        return false
    end

    local f, open_err = io.open(path, "r")
    if not f then
        ngx.log(ngx.WARN, "challenge_secret: file not found at ", path,
            " (", open_err, ") — L2.1 cookie verify and L5 cookie issue ",
            "will be skipped until the file is dropped in and nginx reloaded")
        clear(dict)
        return false
    end
    -- A bounded read: MAX_BYTES + 1, to tell "exactly at the limit" from
    -- "over the limit" (protection from a mis-mount onto /dev/urandom or a large file —
    -- f:read('*a') would block the master in init_by_lua).
    local raw = f:read(MAX_BYTES + 1)
    f:close()
    if not raw then
        ngx.log(ngx.ERR, "challenge_secret: read failed at ", path)
        clear(dict)
        return false
    end
    if #raw > MAX_BYTES then
        ngx.log(ngx.ERR, "challenge_secret: ", path, " is larger than ",
            MAX_BYTES, " bytes — refusing to load (check the mount path; ",
            "a real HMAC secret is ~44 base64 bytes)")
        clear(dict)
        return false
    end

    local secret = rstrip(raw)
    if #secret < MIN_BYTES then
        ngx.log(ngx.ERR, "challenge_secret: ", path, " holds ", #secret,
            " bytes after trim, need >= ", MIN_BYTES,
            " — refusing to load (generate with scripts/generate-challenge-secret.sh)")
        clear(dict)
        return false
    end

    -- Set both keys, treat partial success as failure: a stored secret
    -- without its fp (or vice versa) would let /__admin and /__version
    -- report stale "null" / wrong fingerprint while get() still returns
    -- the secret. clear() wipes both on any failure (fail-closed).
    local fp = fingerprint(secret)
    local ok, set_err = dict:set(KEY_SECRET, secret)
    if ok then
        ok, set_err = dict:set(KEY_FP, fp)
    end
    if not ok then
        ngx.log(ngx.ERR, "challenge_secret: shared_dict set failed: ", set_err)
        clear(dict)
        return false
    end
    ngx.log(ngx.INFO, "challenge_secret: loaded from ", path, " (fp=", fp, ")")
    return true
end

-- get() — for C3 (verify) and C5 (issue). It returns (secret, fp) or nil
-- if the secret is not loaded. Consumers must check for nil and not attempt to
-- sign or verify without one — the cookie fastpath is simply skipped.
function _M.get()
    local dict = ngx.shared[DICT_NAME]
    if not dict then return nil end
    local secret = dict:get(KEY_SECRET)
    if not secret then return nil end
    return secret, dict:get(KEY_FP)
end

-- fingerprint() — the public 8-hex marker for /__version and /__admin.
-- It returns nil if the secret is not loaded. This function never touches
-- the secret itself — it is read-only from the dict.
function _M.fingerprint()
    local dict = ngx.shared[DICT_NAME]
    if not dict then return nil end
    return dict:get(KEY_FP)
end

return _M
