-- The HMAC secret used to sign the clearance cookie and the challenge page's
-- nonce, and to verify the cookie on the fastpath. One secret for the whole
-- edge pool, all of it local, with no call to the backend.
--
-- Delivered as a file mount, so rotation is a reload: init_by_lua re-reads the
-- file and overwrites the value,
-- and every cookie signed with the old secret stops verifying. Clients then
-- walk the cascade and solve one more challenge, which is the point.
--
-- The shared_dict survives a reload, which would otherwise leave a zombie
-- secret in memory if the file were deleted. So every failure path explicitly
-- wipes both keys.
local DICT_NAME = "challenge_secret"
local KEY_SECRET = "secret"
local KEY_FP     = "fp"
-- The HMAC-SHA256 minimum. Shorter means someone loaded a placeholder.
local MIN_BYTES = 32
-- Guards against a mis-mount: reading all of /dev/urandom in init_by_lua would
-- hang the master and the stand would never come up.
local MAX_BYTES = 1024

local _M = {}

local function rstrip(s)
    return (s:gsub("[%s%c]+$", ""))
end

-- A safe marker that a reload picked up the expected file; the secret itself is
-- never exposed.
local function fingerprint(secret)
    local sha256 = require "resty.sha256"
    local h = sha256:new()
    h:update(secret)
    local digest = h:final()
    return (digest:sub(1, 4):gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

local function clear(dict)
    dict:delete(KEY_SECRET)
    dict:delete(KEY_FP)
end

-- Fail-closed: any problem clears the stored value, so consumers see "no
-- secret" rather than working with a stale one.
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
    -- MAX_BYTES + 1 distinguishes "at the limit" from "over" it.
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

    -- Partial success counts as failure: a secret without its fingerprint would
    -- have the observability surface reporting one thing and get() another.
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

-- Returns (secret, fp), or nil when no secret is loaded; callers must skip the
-- cookie path rather than sign without one.
function _M.get()
    local dict = ngx.shared[DICT_NAME]
    if not dict then return nil end
    local secret = dict:get(KEY_SECRET)
    if not secret then return nil end
    return secret, dict:get(KEY_FP)
end

-- The public marker; never touches the secret itself.
function _M.fingerprint()
    local dict = ngx.shared[DICT_NAME]
    if not dict then return nil end
    return dict:get(KEY_FP)
end

return _M
