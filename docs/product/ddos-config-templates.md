# DDoS protection — config templates

Illustrative configuration templates for the DDoS layer. The concrete config here is mostly
**connection/protocol level** (nginx directives: timeouts, the `limit_conn` zone, keepalive,
HTTP/2). L7 rate-based is configured through the cascade (rate limits / challenge / policy,
see [vision.md](vision.md)); volumetric L3/L4 is outside the proxy's perimeter. The behaviour
contract is [ddos-spec.md](ddos-spec.md).

**Related material:** [ddos-rules-reference.md](ddos-rules-reference.md),
[ddos-entities-reference.md](ddos-entities-reference.md).

**Format.** Illustrative fragments of nginx config (`http`/`server`) plus YAML for
the policy knob. What matters is the structure and semantics, not the exact values: caps and timeouts are
system constants of the pool, not a customer setting.

**Important.** This is not the config of a cascade stage. The directives below live before the cascade's
decision phase: they tear down or limit a connection before the request reaches analysis. The
observation layer (Lua, the log phase) only records the outcome of the drop. Directives cannot be changed per request
from Lua — hence the coarse nature of the policy knob.

---

## Config hierarchy

```
http { … }                       ← global timeouts + the limit_conn zone declaration + keepalive
server { … }                     ← applying limit_conn, listen http2 on, http2_max_concurrent_streams
build / Dockerfile               ← pinning OpenResty/nginx ≥ 1.25.3 (the Rapid Reset guard)
log phase (observation)          ← $status/$request_time → the slow_client/conn_flood tag
map $… → the policy knob         ← optional, selecting a strict limit_conn zone under attack_mode (per host)
policy[host].attack_mode/strictness ← the per-host knob from the backend (not a local file)
```

---

## 1. Slow attacks: timeouts

The cheapest layer: pure nginx, zero Lua. It cuts the default 60 s to 10–15 s so as to tear down
connections that never finish their headers, body or read. Fully reversible.

```nginx
# http { } — global receive and send timeouts

# Slowloris: the client never finished the request line and headers in the window → 408
client_header_timeout   15s;     # the default is 60s — cut it

# Slow POST: the client finishes the body slowly or never → 408
client_body_timeout     15s;

# Slow read: the client reads the response slowly → the connection is torn down
send_timeout            15s;

# Deliberate header buffers (protection against header abuse)
large_client_header_buffers 4 8k;
```

> **The guarantee for legitimate clients.** A typical request is a few KB; normal traffic
> fits inside 15 s with room to spare. The cut hits slow attacks only.
> `client_max_body_size` is set deliberately on the proxied paths.

---

## 2. Slow attacks: the `limit_conn` zone plus keepalive

A cap on simultaneous connections per IP, plus a limit on how long idle keepalive slots are held.

```nginx
# http { } — declaring the zone and the refusal code

# The zone counts simultaneous connections per IP (the binary form is more compact in shared memory)
limit_conn_zone $binary_remote_addr zone=perip_conn:10m;

# The refusal code when the cap is exceeded — 503 is the target
limit_conn_status 503;

# Limit how long idle keepalive slots are held
keepalive_requests 1000;         # how many requests per connection
keepalive_timeout  30s;          # idle time before closing
```

```nginx
# server { } / location { } — applying the cap

limit_conn perip_conn 20;        # the cap on simultaneous connections per IP (a system constant)
```

> **Semantics.** Exceeding the cap makes nginx refuse the new connection with the code from
> `limit_conn_status` (503). In the log phase that appears as `$status=503` and produces the
> `conn_flood` tag. The cap is a system constant of the pool; the customer does not configure it in the dashboard.

---

## 3. HTTP/2 DoS: the build plus directives

Mostly a property of the patched build plus a couple of directives. An independent layer; it does not
depend on the slow-attack timeouts.

```dockerfile
# Dockerfile / build — pin a version with the Rapid Reset guard
# OpenResty/nginx >= 1.25.3 counts HTTP/2 streams reset before completion
# and tears down the connection when the count is exceeded (CVE-2023-44487 and relatives).
FROM openresty/openresty:1.25.3.1-alpine   # example: a version >= 1.25.3
```

```nginx
# server { } — HTTP/2 settings

listen 443 ssl;
http2 on;

# The limit of concurrent streams per connection (default 128) — tune it to the traffic profile
http2_max_concurrent_streams 128;

# keepalive_requests also applies to h2 multiplexing
keepalive_requests 1000;

# The CONTINUATION/PING/SETTINGS flood thresholds come with the build version (see its changelog);
# they may not be expressible as a separate config directive — this is a build guarantee.
```

> This is HTTP/2 DoS mitigation, not HTTP/2 fingerprinting (client identification).
> The frame level never reaches HTTP semantics; the cascade does not see it at all. Identification
> by h2 fingerprint is a separate detector signal that optionally yields h2 abuse for reputation.

---

## 4. Observation in the log phase

Not a mitigation config — a Lua hook that turns an nginx drop into an observable log event.
It reuses the same log contract as the cascade stages. Illustratively:

```nginx
# server { } / location { } — the observation hook in the log phase
log_by_lua_block {
    local status = tonumber(ngx.var.status)

    -- 408 ← a header or body timeout (client_header_timeout/client_body_timeout);
    -- 503 ← a limit_conn refusal. Slow read (send_timeout) tears the connection down WITHOUT a 408,
    -- so it never lands here (see the observability limitation below).
    if status == 408 or status == 503 then
        local bac_log = require "bac_log"
        -- the access phase does not run for slow attacks → ctx is empty, so initialise it
        if not ngx.ctx.bac then bac_log.init() end

        if status == 408 then
            bac_log.add_tag("slow_client")
            metrics.incr_by_ip_and_subnet("slow_client")   -- counters by IP and /24
        else
            bac_log.add_tag("conn_flood")
            metrics.incr_by_ip_and_subnet("conn_flood")
        end
        bac_log.emit()   -- emit() with no arguments: serialises the accumulated ctx
    end
}
```

> **The observability limitation.** Only what nginx exposes in the log phase is visible
> (`$status`, and the duration `$request_time` → written to the log as `latency_ms`).
> Lua does not see the slow connection being drained in real time. Slow
> read (`send_timeout`) tears the connection down without a 408 — it is observable only as a
> connection close (a teardown, not a `slow_client` tag). The per-IP and per-/24 counters feed the shared
> reputation sink and, through it, the edge-ACL feed.

---

## 5. The policy knob: tightening under `attack_mode` (optional)

Under `policy[host].attack_mode=on` or heightened strictness: a stricter `limit_conn` zone
and/or lower timeouts.

> **The honest limitation.** nginx directives cannot be changed per request from Lua.
> The implementation is a `map`-driven zone selection per host, or a coarse global toggle — not smooth
> per-request tuning. This layer may not be built at all if the timeouts plus
> observation already cover the risk.

```nginx
# http { } — two zones of differing strictness plus a map-based choice by host

limit_conn_zone $binary_remote_addr zone=perip_normal:10m;
limit_conn_zone $binary_remote_addr zone=perip_strict:10m;

# attack_mode is projected into a variable (sourced from policy[host] in the backend)
map $host $conn_zone_for_host {
    default                     perip_normal;
    "under-attack.example.com"  perip_strict;   # illustrative; in reality it comes from the policy merge
}
```

```yaml
# The per-host knob is NOT a local file — it arrives from the backend as part of policy[host].
# The same attack_mode/strictness merge as the cascade uses; here it is read to choose the zone and timeouts.
example.com:
  attack_mode: false        # true → choose perip_strict plus lower timeouts
  strictness: standard      # raising it can tighten the zone the same way
```

> The `attack_mode`/`strictness` → zone selection link is coarse: it switches per host (through
> `map`) or globally, never per request. The cap and timeout values for the strict zone are
> system constants, as in the base layer.

---

## Rollout conventions

1. **Timeouts first, and reversibly.** A cheap layer; roll it out with room to spare: confirm from the
   logs (`$request_time` of legitimate requests) that normal traffic fits, otherwise you get
   false `408`s.
2. **Calibrate the `limit_conn` cap against the real profile.** Too low a cap hits
   NAT and corporate egresses (many legitimate clients behind one IP). Start
   conservatively and watch the `conn_flood` tag on legitimate traffic.
3. **The HTTP/2 audit is independent.** Pinning the build at ≥ 1.25.3 and tuning
   `http2_max_concurrent_streams` do not depend on the slow-attack layers; do them in parallel.
4. **The policy knob is optional and coarse** — not per-request adaptive (nginx cannot do that).
5. **Volumetric L3/L4 is outside these configs.** It is mitigated below the proxy's perimeter;
   the most the layer offers is delivering offenders into the edge-ACL feed.
