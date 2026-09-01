# Runbook — challenge-page version pinning

**Goal.** Guarantee that the HTML+JS challenge page and the Lua cascade agree on
a version: the page cannot drift away from the cascade unnoticed. The page
version (`<meta name="cascade-version">`) must match the
[`CASCADE_VERSION`](../../infra/demo-stand/CASCADE_VERSION) file.

**Mechanism.** [`challenge.lua`](../../infra/demo-stand/lua/challenge.lua)
`preload()` is called from `init_by_lua`. It reads `CASCADE_VERSION` and the
template's meta tag; on a mismatch (or a missing meta tag) it calls `error()`,
which **fails `init_by_lua` and stops nginx from starting or reloading**. That is
the pin: the versions can only diverge deliberately, by bumping both places at
once.

## Normal template version bump

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand

# 1. Edit the template and both versions (page.html meta + CASCADE_VERSION).
$EDITOR challenge/page.html        # challenge copy/JS + <meta name="cascade-version" content="X.Y.Z">
$EDITOR CASCADE_VERSION            # the same X.Y.Z
#    (page.html also carries a human-readable <!-- cascade-version: … --> comment
#     at the top — update it for the reader; only the meta tag is checked by code.)

# 2. Reload — preload compares the versions.
docker compose -f docker-compose.demo.yml exec nginx-demo openresty -s reload

# 3. Verify. cascade_version is a field of the EDGE_STATS log line (a reload
#    emits a fresh one).
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"cascade_version":"[^"]*"'
```

## What the pin catches (negative test)

If you let the versions diverge (bump only `CASCADE_VERSION` and forget the meta
tag), the reload **fails** in `init_by_lua` with a line like:

```
challenge: cascade/template version mismatch — /etc/nginx/CASCADE_VERSION=0.2.0 vs template meta=0.1.0 (bump both sides together; …)
```

Note: when the reload fails, **the old workers keep serving traffic** — nginx
does not apply a broken configuration (the reload is rejected at load time).
`/__health` stays `ok` and `cascade_version` in EDGE_STATS stays where it was.
So the pin catches the drift without taking the stand down.

> `openresty -t` on this build does **not** execute `init_by_lua_file`, so a
> config test will not catch the mismatch — the check happens on
> `openresty -s reload` (a failed reload is safe: it is rejected and the old
> workers live on).

## Rollback

Restore consistency (put the meta tag or `CASCADE_VERSION` back to its previous
value) and run `openresty -t` → a clean reload. Since a broken reload is never
applied, there is no working configuration to roll back.

## Verified on stand

2026-05-28, commit e3a72f7. Diverged the versions (host `CASCADE_VERSION`
0.1.0 → 0.2.0) and ran `openresty -s reload`:

```
[error] 1#1: init_by_lua_file error: /etc/nginx/lua/challenge.lua:114:
challenge: cascade/template version mismatch — /etc/nginx/CASCADE_VERSION=0.2.0
vs template meta=0.1.0 (bump both sides together; see …/challenge/README.md)
```

`/__health` = `ok` and `cascade_version` in EDGE_STATS stayed at `0.1.0` (the old
workers kept serving) — the stand did not go down. Restoring `0.1.0` gave a clean
reload, `cascade_version: 0.1.0`, and a clean `git status`.
