# DDoS protection — entity reference

The canonical vocabulary of terms, directives, tags, log fields, enumerations and
contracts of the DDoS layer, across all three sublayers. The behaviour contract is
[ddos-spec.md](ddos-spec.md); the rules are in
[ddos-rules-reference.md](ddos-rules-reference.md).

---

## 1. Sublayers and shared terms

| Term | Definition |
| --- | --- |
| **L7 application layer (rate-based)** | DDoS by HTTP request frequency; the protection is the cascade (rate limits / challenge / attack_mode) plus adaptivity (reputation, the automatic mode, the hot list). |
| **Connection/protocol-level DDoS** | The class of DDoS that does not reduce to request frequency and is therefore invisible to the rate-limit cascade: slow attacks and HTTP/2 DoS. |
| **Slow attack** | An attack at the TCP connection level (slowloris / slow POST / slow read): many connections that finish transmitting slowly or never, eating worker slots. |
| **HTTP/2 DoS** | An attack at the HTTP/2 frame level (Rapid Reset, CVE-2023-44487 and relatives): creating and cancelling streams is cheap for the client and expensive for the server. |
| **Volumetric L3/L4** | SYN/UDP floods and amplification — saturating the link or stack before the handshake. Mitigated outside the proxy's perimeter. |
| **Mitigation** | A real refusal or teardown. At the connection/protocol level this is an nginx directive or a property of the build (not Lua). At L7 it is a rate limit, a challenge or a drop per the policy. |
| **Observation (a log signal)** | A log event a Lua hook writes in the log phase, having seen the result of nginx's drop. This is after-the-fact observation, not a verdict. |
| **The shared reputation sink** | The single artifact that repeat offenders (IP / /24 / ASN) from every sublayer flow into; it raises strictness at L7 and feeds the edge-ACL feed. |

## 2. L7 rate-based — entities

| Entity | Definition |
| --- | --- |
| **GCRA profile** | A per-request rate limit on a key (IP, IP+UA, API path, TLS fingerprint, recon URL) with a sliding window. The L7 base, from the cascade. |
| **attack_mode** | The per-host toggle for heightened strictness (lower thresholds, a more aggressive challenge). It can be set **manually** or **automatically**. |
| **automatic attack mode** | Raising `attack_mode` automatically from "bad" traffic relative to the host's baseline (bots / a solve rate ≈ 0 / origin latency), with hysteresis on lifting. A manual setting takes priority. |
| **host baseline** | The host's normal traffic profile, against which "bad" traffic is measured for the automatic mode. |
| **subnet/IP/ASN reputation** | A global (visible to every tenant) soft artifact: repeat offenders aggregated by IP, /24 subnet and ASN (especially datacenter pools). It raises the score and strictness without blocking by itself. |
| **transient subnet challenge→drop** | A temporary escalation from challenge to drop for a /24 under the host's `attack_mode`, given bad reputation and a solve rate ≈ 0; reactive per-/24 counters, a TTL plus automatic lifting. |
| **cross-tenant hot list** | A short-TTL list of active attackers (fingerprint/subnet) that pre-arms every edge (challenge-first, a lower threshold). Global reputation, per-tenant enforcement. A high promotion bar. |
| **fast / slow tier** | The fast tier is the short-TTL hot list (seconds to react to a botnet pivot); the slow tier is the durable global catalogs delivered by the standard path. |
| **solve_rate** | The share of solved challenges per source or fingerprint. ≈ 0 with many issued is a strong bot signal under a flood. |

## 3. Connection/protocol — nginx directives and zones (the real mitigation)

| Directive / object | What it does | Family | Target value |
| --- | --- | --- | --- |
| `client_header_timeout` | The timeout for receiving the request line and headers; exceeding it tears the connection down with `408` | slow | 10–15 s |
| `client_body_timeout` | The timeout between body reads; exceeding it tears the connection down with `408` | slow | 10–15 s |
| `send_timeout` | The timeout between response writes (slow read); exceeding it tears the connection down | slow | 10–15 s |
| `limit_conn` (plus a zone) | A cap on simultaneous connections by `$binary_remote_addr`; the excess is refused | slow | a zone keyed by IP |
| `limit_conn_status` | The response code for a `limit_conn` refusal | slow | `503` |
| `keepalive_requests` | The limit of requests per keepalive connection; beyond it the connection is closed | slow | limit idle retention |
| `keepalive_timeout` | How long an idle keepalive is held before closing | slow | limit idle retention |
| `large_client_header_buffers` | Buffers for large headers (against header abuse) | slow | set deliberately |
| `client_max_body_size` | The body size limit on proxied paths | slow | deliberate, per path |
| `http2_max_concurrent_streams` | The limit of concurrent HTTP/2 streams per connection | HTTP/2 | tuned |
| Reset-flood guard (build) | Counting streams reset before completion and tearing down the connection (Rapid Reset) | HTTP/2 | build ≥ 1.25.3 |
| Frame-flood guard (build) | The CONTINUATION/PING/SETTINGS flood thresholds | HTTP/2 | per the build version |

## 4. Connection/protocol — tags (informational, on the log event)

| Tag | When it appears | Source |
| --- | --- | --- |
| `slow_client` | A header or body timeout → `$status=408` (slow read via `send_timeout` is torn down without a 408, so no tag is set) | the log phase, `$status` |
| `conn_flood` | A `limit_conn` refusal → `$status` = `limit_conn_status` (`503`) | the log phase, `$status` |
| `h2_abuse` | An anomalous HTTP/2 SETTINGS or stream pattern (optional, where h2 identification is available) | the log phase / reputation |

The tag format is `<namespace>:<short_name>`, as for the cascade's tags. The difference: it
is set in the log phase after the fact, describes an nginx drop that already happened, and
does not decide the request's fate.

## 5. Connection/protocol — log event fields (the log phase)

| Field | Type | Description | Source |
| --- | --- | --- | --- |
| `status` | int | The HTTP code in the log phase. `408` makes it a candidate for `slow_client`; `503` for `conn_flood` | `$status` |
| `latency_ms` | float | The processing duration (ms), from `$request_time`; a high value with a `408` indicates a slow client. The same canonical latency field as the cascade's log contract | `$request_time` |
| `connection_requests` | int | **A new field of this layer**: how many requests a keepalive connection served (keepalive abuse) | `$connection_requests` |
| `tags` | array | The namespaced tags of the connection/protocol signals | the log hook |

## 6. Enumerations

### Refusal HTTP codes (connection/protocol)

| Code | When | Trigger | Tag |
| --- | --- | --- | --- |
| `408` | A timeout receiving the request headers or body | `client_header_timeout` / `client_body_timeout` | `slow_client` |
| (teardown) | Slow read — the client reads the response slowly | `send_timeout` | — (no 408; a connection close, observable only to a limited extent) |
| `503` | A refusal on the simultaneous connection cap | `limit_conn` (via `limit_conn_status`) | `conn_flood` |

### The category of a rule object

| Value | What it is | Who enforces it |
| --- | --- | --- |
| `rate-rule` / `adaptive` | L7 logic on top of the cascade (it can change a request's fate) | the cascade plus analytics |
| `mitigation-directive` | A real refusal or connection teardown | nginx / the build |
| `log-signal` | A log event from the log phase, after a drop | the log hook |
| `tag` | A namespaced marker on an event (it does not decide the request's fate) | the log hook |
| `escalation` | Delivering an offender into reputation or the edge-ACL feed | analytics / the contract |

### attack_mode — the source of the setting

| Value | What it is |
| --- | --- |
| `manual` | Set by an operator; it takes priority over automation |
| `auto` | Raised by automatic detection from "bad" traffic; lifted with hysteresis; it never overrides `manual` |

## 7. The edge-ACL feed contract (escalation into the network layer)

| Property | Value / contract |
| --- | --- |
| Purpose | Escalating confirmed offenders (IP / /24) into the network layer the proxy cannot reach |
| Input | Accumulated per-IP and per-/24 counters and reputation from the L7 and connection/protocol signals |
| Boundary | Volumetric L3/L4 is mitigated outside the proxy's perimeter — the handshake has not even happened by then |
| The proxy's maximum | Supplying candidates into the feed; the network mitigation is performed by an external layer |

## 8. Glossary

- **slowloris / slow POST / slow read** — the three subspecies of slow attack: never
  finishing the headers, never finishing the body, and reading the response slowly,
  respectively.
- **Rapid Reset (CVE-2023-44487)** — an HTTP/2 DoS through mass creation and instant
  cancellation of streams; mitigated by a patched build (≥ 1.25.3).
- **the log phase** — the request-processing phase after the response has been sent, the
  only point where the observation layer sees the result of a connection/protocol drop.
- **hysteresis** — different thresholds for raising and lifting the automatic mode, so that
  it does not chatter at the boundary.
- **edge-ACL feed** — the contract for delivering offenders into the network layer, for the
  cases above the proxy's perimeter (volumetric attacks).
