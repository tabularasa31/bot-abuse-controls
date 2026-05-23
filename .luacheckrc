-- luacheck configuration for the abuse-controls Lua code.
-- See https://luacheck.readthedocs.io/

-- Standard library set: LuaJIT 2.1 = standard Lua 5.1 stdlib + jit/ffi.
-- Inheriting from "luajit" gives us require/pairs/table/string/math etc.
-- so we only need to declare OpenResty-specific globals on top.
std = "luajit"
-- ngx is in `globals` (not `read_globals`) because OpenResty Lua code
-- legitimately assigns to nested ngx fields like `ngx.header.foo` and
-- `ngx.ctx.bar` — those are magic tables that mutate response state.
-- Marking ngx writable suppresses the false-positive read-only warning.
globals = {
    "ngx",
}

-- Vendored third-party library — linted upstream, not to our conventions.
-- resty/ipmatcher.lua (A5) happens to pass clean; resty/maxminddb.lua (A6,
-- anjia0532/lua-resty-maxminddb, Apache-2.0) carries upstream's unused error
-- constants and FFI scaffolding, so skip the vendor copy wholesale rather than
-- patch it.
exclude_files = {
    "infra/demo-stand/lua/resty/maxminddb.lua",
}

-- Suppress these warnings repo-wide.
ignore = {
    "611",  -- "line contains only whitespace" — fights with our doc-comment style
    "612",  -- "line contains trailing whitespace" — same
    "631",  -- "line is too long" — code docs intentionally have long lines
}

-- Test files use loose conventions (assertion globals, etc.).
files["tests/"] = {
    globals = {"_G"},
    ignore = {"211"},  -- unused local in test scaffolding is fine
}

-- Max line length — soft limit, the 631 ignore above handles overruns
-- in long doc comments. Useful when we DO want to fix a real overrun.
max_line_length = 120
max_code_line_length = 100
