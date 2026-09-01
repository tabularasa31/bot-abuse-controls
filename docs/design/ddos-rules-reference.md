# DDoS protection — rules and signals reference

The DDoS layer's rules and signals in "if condition → action" form, across all three
sublayers. The behaviour contract is [ddos-spec.md](ddos-spec.md); the entity vocabulary is
[ddos-entities-reference.md](ddos-entities-reference.md).

**The objects here differ in nature** (unlike the cascade, where everything is an
access-phase verdict):

- **rate-rule / adaptive** — L7 logic on top of the cascade (rate limits, the challenge,
  an adaptive `attack_mode`, reputation). It can change a request's fate.
- **mitigation-directive** — a real refusal or connection teardown, performed by nginx or a
  patched build; there is no cascade verdict (there is an HTTP refusal code, or a teardown
  at the frame level).
- **log-signal** — observation in the log phase: Lua sees the result of nginx's drop and
  writes a log event (the request is already gone).
- **tag** — a namespaced marker on a log event; it does not decide the request's fate, it
  feeds reputation.
- **escalation** — delivering an offender into the shared reputation sink or the network
  ACL feed.

---

## A. L7 application layer — the base (the cascade)

| # | If | → action | Category |
| --- | --- | --- | --- |
| A1 | the request rate for a key (IP / IP+UA / API / fingerprint / recon URL) exceeded the GCRA window | a challenge or a refusal, per the host's policy | rate-rule |
| A2 | a client under load does not solve the challenge it was issued | the request does not pass; the source accumulates "unsolved" | rate-rule |
| A3 | `attack_mode=on` was set manually for the host | heightened strictness: lower thresholds, a more aggressive challenge | rate-rule |

## B. L7 application layer — adaptivity (this layer)

| # | If | → action | Category |
| --- | --- | --- | --- |
| B1 | the host's share of "bad" traffic (bots / a solve rate ≈ 0 with many challenges / rising origin latency) exceeded the baseline | `attack_mode` is raised automatically for the host | adaptive |
| B2 | the "bad" traffic fell below the baseline and stayed there | `attack_mode` is lifted automatically, **with hysteresis** | adaptive |
| B3 | `attack_mode` was set manually for the host | the manual setting outranks the automatic one (automation does not override it) | adaptive |
| B4 | an IP / /24 / ASN is a repeat offender across the signals of every layer | +reputation in the **global** subnet/IP/ASN artifact (soft: +score and strictness, not a block) | adaptive |
| B5 | under the host's `attack_mode`, a subnet with bad reputation AND a solve rate ≈ 0 | a temporary escalation from challenge to drop for that /24; a TTL plus automatic lifting once the attack subsides | adaptive |
| B6 | a source (fingerprint/subnet) is actively attacking a tenant and is confirmed | published into the short-TTL **cross-tenant hot list** (a high promotion bar) | escalation |
| B7 | a fingerprint or subnet is in the cross-tenant hot list | every edge is pre-armed: challenge-first, a lower threshold (even with no local attack) | adaptive |

## C. Connection/protocol — slow attacks, mitigation (nginx)

| # | If | → action | Category |
| --- | --- | --- | --- |
| C1 | the client did not finish its headers within `client_header_timeout` (10–15 s) | nginx tears down the connection, `408` | mitigation-directive |
| C2 | the client finishes its body slowly or never, beyond `client_body_timeout` | nginx tears down the connection, `408` | mitigation-directive |
| C3 | the client reads the response more slowly than `send_timeout` (slow read) | nginx tears down the connection | mitigation-directive |
| C4 | the number of simultaneous connections from one `$binary_remote_addr` exceeded the `limit_conn` zone cap | nginx refuses new connections with `limit_conn_status` (`503`) | mitigation-directive |
| C5 | a keepalive connection served more than `keepalive_requests` or idled longer than `keepalive_timeout` | nginx closes the keepalive connection | mitigation-directive |

## D. Connection/protocol — slow attacks, observation (the log phase)

| # | If | → action | Category |
| --- | --- | --- | --- |
| D1 | in the log phase `$status=408` (a header or body timeout; slow read via `send_timeout` is torn down without a 408) | a log event tagged `slow_client`; +counters by IP and /24 | log-signal |
| D2 | in the log phase `$status` = `limit_conn_status` (`503`, a `limit_conn` refusal) | a log event tagged `conn_flood`; +counters by IP and /24 | log-signal |
| D3 | the accumulated `slow_client`/`conn_flood` counter for an IP or /24 indicates a repeat offender | a signal into the shared reputation sink → escalation into the edge-ACL feed when severe | escalation |

## E. Connection/protocol — slow attacks, the policy knob (optional)

| # | If | → action | Category |
| --- | --- | --- | --- |
| E1 | `attack_mode=on` for the host (or heightened strictness) | a `map`-driven selection of a stricter `limit_conn` zone and lower timeouts (per host, not per request) | mitigation-directive |

## F. Connection/protocol — HTTP/2 DoS

| # | If | → action | Category |
| --- | --- | --- | --- |
| F1 | a client cheaply creates and immediately cancels HTTP/2 streams beyond the threshold (Rapid Reset) | a patched build (≥ 1.25.3) counts the reset streams and tears down the connection | mitigation-directive |
| F2 | the number of concurrent HTTP/2 streams exceeded `http2_max_concurrent_streams` | nginx caps the number of parallel streams | mitigation-directive |
| F3 | a CONTINUATION / PING / SETTINGS flood exceeds the build version's thresholds | the patched build applies its protection at those thresholds | mitigation-directive |
| F4 | HTTP/2 client identification sees anomalous SETTINGS/stream patterns (where available) | h2 abuse as a signal into reputation and the score; no verdict is emitted | tag |

## G. Volumetric L3/L4 — the contract

| # | If | → action | Category |
| --- | --- | --- | --- |
| G1 | an IP or /24 is confirmed as an offender (accumulated from the L7 and connection/protocol signals) | delivered into the edge-ACL feed; the network mitigation is performed by an external layer | escalation |
| G2 | a volumetric flood (SYN/UDP/amplification) before the handshake | outside the proxy's perimeter — the proxy is not the point of mitigation | (a boundary) |

---

## Sublayer summary

| Sublayer | Protection | The layer's contribution |
| --- | --- | --- |
| L7 rate-based | the cascade (rate limits / challenge / attack_mode) | adaptivity: automatic attack mode, subnet reputation, the hot list |
| connection/protocol | nginx directives plus the build version | observation (log signals) plus escalation into reputation |
| volumetric L3/L4 | the network layer outside the proxy | supplying candidates into the edge-ACL feed |

## Boundaries (what these rules do NOT do)

- **They do not block at the connection/protocol level from Lua** — the real refusal comes
  from nginx or the build; Lua observes (in the log phase) and feeds reputation.
- **They do not provide adaptive per-request connection limits** — nginx directives are
  static; the policy knob switches zones coarsely (per host or globally).
- **They do not mitigate volumetric L3/L4** — by that point the handshake has not even
  happened; the most on offer is the edge-ACL feed contract.
- **Automatic attack mode does not override a manual one** and lifts with hysteresis.

The entity vocabulary is [ddos-entities-reference.md](ddos-entities-reference.md).
