# Shadow-mode deployment — abuse-controls antibot

Reverse proxy that runs the full antibot verdict pipeline (fp compute, blocklist lookup, cache) but **logs verdicts instead of enforcing them**. Goal: collect real production fp distribution + would-be-block counts from a low-stakes site before flipping any traffic to active blocking.

> **Risk profile**: near-zero. No request is dropped. The only failure modes are nginx misconfiguration (TLS cert / upstream URL) and proxy latency overhead (sub-millisecond — see [docs/lua-poc-results.md](../../docs/lua-poc-results.md) bench).

## What you'll need

- A VM (1 vCPU, 1 GB RAM is plenty) with Docker installed
- A domain pointing to the VM (or behind a CDN that lets you set origin = VM)
- A TLS cert (Let's Encrypt or any) for that domain
- A backend HTTP service the proxy will forward to (your real site)

## Architecture

```
client ──TLS──▶ nginx-shadow ──HTTP──▶ your backend
                    │
                    ├─ access_by_lua → verdict.lua  (compute fp, lookup blocklist,
                    │                                stash verdict in ngx.ctx;
                    │                                NEVER ngx.exit — pure observation)
                    │
                    └─ log_by_lua    → log_event.lua  (one JSON line per request:
                                                       fp + would-be verdict + timings)
```

The same fp algorithm and verdict pipeline as production ([infra/nginx-lua-poc/lua/ja4_compute.lua](../nginx-lua-poc/lua/ja4_compute.lua)) — bind-mounted from the PoC tree, no copies.

## Deploy

```sh
# 1. Clone the repo on the VM, cd into it.
git clone <repo> abuse-controls && cd abuse-controls

# 2. Customise the nginx config — set server_name + cert paths.
$EDITOR infra/nginx-shadow/nginx.shadow.conf
#   - server_name <yourdomain>;
#   - ssl_certificate / ssl_certificate_key paths
#   - upstream backend_default → server <your-backend-host>:<port>;

# 3. Drop your TLS cert + key into ./infra/nginx-shadow/certs/
#    Files should be named `fullchain.pem` + `privkey.pem`, OR adjust
#    the paths in nginx.shadow.conf to match what you have.
mkdir -p infra/nginx-shadow/certs
cp /your/cert.pem  infra/nginx-shadow/certs/fullchain.pem
cp /your/key.pem   infra/nginx-shadow/certs/privkey.pem

# 4. Bring up.
docker compose -f infra/nginx-shadow/docker-compose.shadow.yml up -d

# 5. Smoke.
curl -k --resolve <yourdomain>:443:127.0.0.1 https://<yourdomain>/__health
#    → ok
curl -k --resolve <yourdomain>:443:127.0.0.1 https://<yourdomain>/__fp
#    → fp=L13d49h2_... + raw $ssl_* dump
```

If your real backend is on the same VM, point `upstream backend_default` to `127.0.0.1:<backend-port>`. If it's elsewhere, use the reachable hostname/IP.

## DNS / CDN setup

Two common topologies:

**A) Direct (VM is internet-facing):**
```
DNS:  yoursite.example   A   <vm-public-ip>
Cert: certbot --nginx -d yoursite.example  (one-time; renew via cron)
```

**B) Behind CDN (CDN operator / cloudflare / etc):**
```
DNS:  yoursite.example   CNAME  <cdn-edge>
CDN origin:               <vm-ip-or-hostname>
Cert: still terminate TLS at the VM (CDN passes through to origin over TLS)
```

In topology B, `$remote_addr` in the log will be the CDN edge IP. Use `X-Forwarded-For` from your CDN's headers to recover the real client IP if you need it — drop a `real_ip_header X-Forwarded-For;` + `set_real_ip_from <cdn-cidr>;` block in the server{} section.

## Read the logs

The shadow handler emits one JSON line per request to nginx error log (NOTICE level), which docker captures via the json-file driver by default.

```sh
# Tail live.
docker logs -f nginx-shadow | grep ANTIBOT_EVENT

# Convert to bare JSON for piping to jq. The sed strips both the prefix
# (nginx timestamp + log header) and the suffix nginx appends to error
# entries emitted from the log_by_lua phase (" while logging request,
# client: ..."). Without that trim, jq chokes on trailing garbage.
ev() { docker logs nginx-shadow 2>&1 | grep ANTIBOT_EVENT \
       | sed -E 's/.*ANTIBOT_EVENT (\{.*\}).*/\1/'; }

# Top 10 fingerprints by request count.
ev | jq -r .fp | sort | uniq -c | sort -rn | head

# Would-be blocks vs allows.
ev | jq -r .would_verdict | sort | uniq -c
```

Or use the canned aggregator:

```sh
./infra/nginx-shadow/scripts/analyze-shadow-log.sh
```

Prints: verdict distribution, cache hit ratio, top fps, top UAs, would-block-by-UA-family, latency percentiles, possible UA↔JA mismatches (the [A5](https://app.clickup.com/t/86exmk00m) signal — "Chrome" UA with non-Chrome cipher count).

## What to look at after the first few days

1. **`would_verdict=block` rate**. Is it ~0.1% (typical), or 10%+ (something else going on)? High block rates against a low-traffic site mean either real bot pressure OR a legit client whose fp happens to match a reference automation entry — investigate by joining on UA / path.

2. **Top 10 fps by volume vs uniqueness.** Production traffic on a low-traffic site might cluster on 5–20 fps that cover 95% of requests (browsers + a few crawlers). If you see 1000+ distinct fps in low-traffic, GREASE is leaking somewhere — file a bug.

3. **Cardinality growth rate.** If `distinct_fp` per hour stays flat, the L-prefix fp is stable enough for blocklist scaling. If it grows linearly with traffic, something's making fps unstable (broken GREASE strip, $ssl_* var quirk on your nginx build, etc.).

4. **UA↔JA mismatches** (the suspicious lines from `analyze-shadow-log.sh`). Each one is a candidate for the [A5 task](https://app.clickup.com/t/86exmk00m). Volume + pattern tells you whether A5 is urgent (push its priority up) or rare (leave at normal).

5. **Latency p99**. Should be roughly upstream-latency + 2–10 ms for the Lua pipeline. If p99 is 100 ms+ above your direct-to-upstream baseline, something else is the problem (DNS, upstream pool, etc.) — not the antibot.

## Convert to ACTIVE blocking later

When shadow data convinces you the blocklist is right:

1. Edit `nginx.shadow.conf`, change the access_by_lua line:
   ```
   - access_by_lua_file  /etc/nginx/lua/verdict.lua          # shadow (logs only)
   + access_by_lua_file  /etc/nginx/lua-common/verdict.lua   # production (ngx.exit on block)
   ```
2. `docker exec nginx-shadow openresty -s reload` (or `docker compose restart`).
3. Monitor `4xx` rates in your access log carefully for the first hour — false-positive blocks show up immediately.
4. Have a rollback ready: revert the conf change + reload = back to shadow mode in seconds.

Or, if you want a softer transition: leave shadow mode running and add a **separate** location block (e.g. `location /api/` ) that uses the active verdict.lua — block only a narrow scope first.

## Operational hygiene

- **Log volume**: each request adds ~500–800 bytes to the error log. 1M requests/day ≈ 500–800 MB/day. Rotate via docker `max-size` + `max-file` log driver options, or ship to a log aggregator and disable file logging.
- **Cert renewal**: nothing in the container manages cert renewal. Run certbot on the host (or in a sidecar) and renew the bind-mounted file; `docker exec nginx-shadow openresty -s reload` picks up the new cert without restart.
- **Backup blocklist.lua before edits.** It's the only file that matters for the verdict distribution; a typo here can flip every request's would-be verdict.
- **Don't expose `/__fp` to the public internet.** It leaks $ssl_* internals. Add an `allow / deny` block or remove the location entirely once you're past initial debugging.

## Caveats specific to shadow mode

- **`would_verdict=block` ≠ "would have hurt the user"**. Many real-world clients hit blocklist entries while being legitimate (RSS readers using `python-requests`, monitoring agents using `curl`, etc.). Treat shadow blocks as candidates for review, not as ground truth.
- **No grey-verdict pipeline.** When [A5](https://app.clickup.com/t/86exmk00m) lands it adds a `would_verdict=challenge` outcome for UA↔JA mismatches — shadow logs today just show `allow` for those.
- **No rate limiting.** [A3](https://app.clickup.com/t/86exmjzxm) is not in this build. If your shadow site gets DDOS'd, OpenResty itself is the only backstop (it's robust to ~30K RPS per worker — see PoC bench — but won't shed load on its own).
