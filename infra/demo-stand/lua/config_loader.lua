-- Cascade config-file parsers for the demo stand.
--
-- Two on-disk formats, deliberately tiny so init_by_lua can read them
-- without a YAML/JSON dependency (OpenResty ships neither for files):
--
--   * flat list  — one entry per line, used by the IP/UA/ASN/fp lists.
--                  "<value> [k=v ...]  # comment"
--   * sectioned  — INI-like, used by defaults.conf and the tls_fp
--                  catalog/profiles. "[a.b]" opens nested table root.a.b;
--                  "key = value" assigns into the current section.
--
-- docs/product/config-templates.md shows these configs as illustrative
-- YAML; the doc states the concrete syntax is not the point, only the
-- structure/semantics. These parsers reproduce that structure.

local _M = {}

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Drop a "#" comment (full-line or trailing) and surrounding whitespace.
-- A "#" only starts a comment at line start or when preceded by
-- whitespace, so it survives inside a value — e.g. the PR link in
-- "pr=#42" or a "#" in a UA regex.
local function strip_comment(s)
    local hash = s:find("^#") or s:find("%s+#")
    if hash then s = s:sub(1, hash - 1) end
    return trim(s)
end

local function read_lines(path)
    local f, err = io.open(path, "r")
    if not f then return nil, err end
    local lines = {}
    for line in f:lines() do lines[#lines + 1] = line end
    f:close()
    return lines
end

-- Coerce a scalar string into the most useful Lua type: "true"/"false"
-- become booleans (so a consumer's `if cfg.kill_switch.enabled then`
-- isn't fooled by the truthy string "false"), comma-separated values
-- become an array, purely-numeric values become a number, the rest stay
-- strings.
local function coerce(v)
    if v == "true" then return true end
    if v == "false" then return false end
    if v:find(",", 1, true) then
        local list = {}
        for item in v:gmatch("[^,]+") do
            local t = trim(item)
            if t ~= "" then list[#list + 1] = t end
        end
        return list
    end
    local n = tonumber(v)
    if n ~= nil then return n end
    return v
end

-- Parse a flat list file. Returns an array of { value = <str>, attrs = {k=v} }.
-- The first whitespace token is the value; remaining "k=v" tokens are attrs.
function _M.parse_list(path)
    local lines, err = read_lines(path)
    if not lines then return nil, err end

    local out = {}
    for _, raw in ipairs(lines) do
        local line = strip_comment(raw)
        if line ~= "" then
            local fields = {}
            for tok in line:gmatch("%S+") do fields[#fields + 1] = tok end
            local entry = { value = fields[1], attrs = {} }
            for i = 2, #fields do
                local k, v = fields[i]:match("^([%w_]+)=(.+)$")
                if k then entry.attrs[k] = v end
            end
            out[#out + 1] = entry
        end
    end
    return out
end

-- Parse a sectioned file into a nested table. "[a.b]" walks/creates
-- root.a.b and makes it the current section; "key = value" assigns the
-- coerced value into it. Keys before any section land at the root.
function _M.parse_ini(path)
    local lines, err = read_lines(path)
    if not lines then return nil, err end

    local root = {}
    local cur = root
    for _, raw in ipairs(lines) do
        local line = strip_comment(raw)
        if line ~= "" then
            local section = line:match("^%[(.+)%]$")
            if section then
                cur = root
                for part in section:gmatch("[^%.]+") do
                    local key = trim(part)
                    cur[key] = cur[key] or {}
                    cur = cur[key]
                end
            else
                local k, v = line:match("^([^=]+)=(.*)$")
                if k then cur[trim(k)] = coerce(trim(v)) end
            end
        end
    end
    return root
end

return _M
