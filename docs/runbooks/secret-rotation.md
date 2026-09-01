# Runbook — HMAC secret rotation

**Goal.** Rotate the shared HMAC secret the cascade uses to sign the clearance
cookie (L5 issue, L2.1 verify) and the self-signed nonce of the challenge page.
Rotation **invalidates every previously issued cookie** — that is by design
(vision §"Rotation"): the client solves a challenge again.

**When.** Scheduled rotation (quarterly) or an emergency one (secret compromise).

**Mechanism.** [`challenge_secret.lua`](../../infra/demo-stand/lua/challenge_secret.lua)
loads the secret from a file into `lua_shared_dict challenge_secret` during
`init_by_lua`. `openresty -s reload` re-runs `init_by_lua`, which rereads the
file and overwrites the dict entry. Cookies signed with the old secret stop
passing the constant-time HMAC verify at L2.1. On the stand, Channel A is a
bind-mount of `infra/demo-stand/certs/challenge_secret.key` (not Puppet).

## Procedure (on the edge VM)

```sh
ssh -i ~/.ssh/gpu-key ubuntu@<EDGE_VM_IP>
cd ~/abuse-controls/infra/demo-stand

# 1. Note the current fingerprint (8 hex chars of sha256 over the secret; the
#    secret itself is never printed). Read it from the EDGE_STATS log line.
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"challenge_secret_fp":"[^"]*"'

# 2. Generate a new secret. The script refuses to overwrite an existing file,
#    so delete it first — that deletion is the rotation.
#    IMPORTANT: the script's default destination is relative to the repo root.
#    From infra/demo-stand, pass the destination explicitly or the key lands in
#    the wrong path.
rm certs/challenge_secret.key
./scripts/generate-challenge-secret.sh certs/challenge_secret.key
# → prints: wrote certs/challenge_secret.key (fp=<new-fp>)

# 3. Reload — init_by_lua rereads the file.
docker compose -f docker-compose.demo.yml exec nginx-demo openresty -s reload

# 4. Confirm the edge picked up the new file. A reload emits a fresh EDGE_STATS
#    line, so take the latest one.
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"challenge_secret_fp":"[^"]*"'
#    The fp must match what step 2 printed and differ from step 1.
```

A second way to cross-check is the private mgmt plane on :9090 (loopback, over
an ssh tunnel): `ssh -L 9090:127.0.0.1:9090 ubuntu@<EDGE_VM_IP>`, then
`curl -s http://localhost:9090/__stats | grep challenge_secret_fp`.

## What to watch

- `challenge_secret_fp` in EDGE_STATS (or `:9090/__stats`) changed to the value
  the script printed.
- `docker logs nginx-demo` carries a `challenge_secret: loaded from … (fp=<new>)`
  line, with no ERR/WARN.
- **Cookie invalidation**: after rotation, a request carrying a `tf_clearance`
  signed with the old secret yields `verdict≠cookie_valid` (the
  `antibot_clearance_verify_total{result="invalid"}` metric increments) and the
  client is sent to a challenge.

To check invalidation without a browser, craft a cookie with the old secret. The
format ([`clearance.lua`](../../infra/demo-stand/lua/clearance.lua)) is
`cookie = body . "." . b64url(sig)`, where `body = b64url(host):iat:exp` and
`sig = HMAC-SHA256(secret, body)` (the signature is **b64url**, not hex):

```sh
SECRET=$(cat certs/challenge_secret.key)        # BEFORE the rotation
HOST=bac.example.com                          # shadow host, no real users
NOW=$(date +%s); EXP=$((NOW+86400))
b64url() { openssl base64 -A | tr -d '\n\r' | tr '+/' '-_' | tr -d '='; }
BODY="$(printf '%s' "$HOST" | b64url):$NOW:$EXP"
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
COOKIE="$BODY.$SIG"
# Before rotation → result=valid; after rotation the same COOKIE → result=invalid.
docker exec nginx-demo curl -ks https://127.0.0.1/ -H "Host: $HOST" \
    -H "Cookie: tf_clearance=$COOKIE" -o /dev/null
# The clearance_verify_* counters live in EDGE_STATS (or :9090/__stats over the tunnel).
docker logs nginx-demo 2>&1 | grep EDGE_STATS | tail -1 | grep -o '"clearance_verify[^,}]*'
```

## Fail-closed (important)

If the file is deleted and a reload happens without regenerating it (or the file
is empty, shorter than 32 bytes, or larger than 1024 bytes),
`challenge_secret.lua` logs WARN/ERR and **explicitly clears** the dict — there is
no zombie secret. `challenge_secret_fp` in EDGE_STATS is then empty, and L2.1/L5
skip cookie verify and issue (the cookie fastpath is off, challenges still work).
The fix is to run steps 2–3.

## Rollback

There is no separate rollback: the new secret is valid immediately. If
regeneration ran but the fp did not change, check that the bind-mount points at
the same file (`docker exec nginx-demo ls -l /etc/nginx/certs/challenge_secret.key`
versus the host file) and that the reload did not fail.

## Verified on stand

2026-05-28, commit e3a72f7 (with a backup and restore of the original secret, so
the real active customer saw a net-zero change):

- Starting EDGE_STATS `challenge_secret_fp: 77b4e803`. A cookie crafted with the
  old secret (host `bac.example.com`) gave `clearance_verify` `result=valid` +1.
- Rotation (`rm` + `generate-challenge-secret.sh certs/challenge_secret.key` +
  reload): the script printed `fp=d520c80e` and EDGE_STATS showed
  `challenge_secret_fp: d520c80e`.
- The same old-secret cookie after rotation gave `clearance_verify`
  `result=invalid` +1 — invalidation confirmed.
- Restoring the original key from backup and reloading brought the fp back to
  `77b4e803` and the same cookie was `valid` again (the real client was
  untouched). `git status` clean.

One bug in the procedure was found and fixed along the way:
`generate-challenge-secret.sh` without an explicit destination writes relative to
the repo root, so running it from `infra/demo-stand` with no argument leaves
`challenge_secret_fp` empty in EDGE_STATS (fail-closed, the secret never loaded).
Pass the destination explicitly, as in step 2.
