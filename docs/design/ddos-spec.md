# DDoS protection — specification (post-MVP)

**Version:** v1.0 · Status: a design contract (target behaviour) · a post-MVP layer

This document describes the target behaviour of DDoS protection as a separate layer on
top of the cascade. The cascade decides about each *request*; the DDoS layer deals with
what lies before and around the request: the frequency and shape of the load, the
behaviour of connections and the protocol, and volume at the network level.

**Related material:**

[ddos-rules-reference.md](ddos-rules-reference.md) — the rules and signals in
"if condition → action" form; [ddos-entities-reference.md](ddos-entities-reference.md) —
the entity vocabulary (directives, zones, tags, log fields, enumerations, contracts).

---

## 1. What it is

DDoS splits into three layers of a different nature for this product, each with its own
protection mechanism. These are not three separate subsystems but three fronts of one
task — keeping the origin available under malicious load:

| Layer | What | Where the protection lives |
| --- | --- | --- |
| **L7 application layer (rate-based)** | a flood by HTTP request frequency; an adaptive response to "bad" traffic | the cascade (rate limits + challenge + attack_mode) plus reputation analytics |
| **Connection/protocol level** | slow attacks (slowloris / slow POST / slow read) and HTTP/2 DoS (Rapid Reset) | nginx directives plus the build version; observation in Lua |
| **Volumetric L3/L4** | SYN/UDP floods, amplification — saturating the link or stack before the handshake | the network layer outside the proxy's perimeter; the proxy only supplies candidates |

The thread running through all three is a shared reputation sink: repeat offenders (by IP,
by /24 subnet, by ASN) accumulate in a single reputation artifact that raises strictness at
L7 and, ultimately, escalates into a network ACL feed.

## 2. The principle on one screen

- **The foundation is already in the cascade.** Per-request rate limits (the GCRA
  profiles), the challenge and the per-host `attack_mode` are the baseline L7 protection
  from the vision. The DDoS layer adds **adaptivity and memory** on top: automatic attack
  detection, subnet reputation, cross-tenant signal exchange.
- **Not everything is catchable in the cascade.** A slow client and a reset HTTP/2 stream
  never reach the cascade's decision phase. nginx mitigates them (directives, the build
  version) while the layer only observes and feeds reputation. Protection here is not a new
  cascade stage.
- **Volumetric attacks are outside the proxy.** Link saturation happens before the
  handshake; the proxy is physically not the point of mitigation. The most the layer can do
  is put confirmed offenders into a network ACL feed.
- **Global reputation, local enforcement.** The attacker's reputation
  (fingerprint/subnet/ASN) is shared across all tenants; the enforcement stance
  (challenge/drop) is per tenant and engages during an attack on that specific tenant.
- **Adaptivity with hysteresis and human priority.** Automatic attack mode engages on "bad"
  traffic (not raw volume) and lifts with hysteresis; a manual setting always outranks the
  automatic one.

---

## 3. The L7 application layer (rate-based)

Protection against floods by HTTP request frequency. The base is the cascade; this layer
adds adaptivity.

### 3.1 The base (the cascade)

- **Per-request rate limits (GCRA).** Profiles across different keys (IP, IP+UA, API path,
  TLS fingerprint, recon URLs) with sliding windows. Exceeding one leads to a challenge or a
  refusal, per the policy.
- **The challenge.** Under load the challenge works as a filter: a human passes, a cheap
  flood bot does not.
- **attack_mode (per host).** A toggle for heightened strictness on a specific host: lower
  thresholds, a more aggressive challenge.

### 3.2 Adaptivity (this layer)

- **Automatic attack mode.** An attack is detected not by raw volume but by "bad" traffic
  relative to the host's baseline: the share of bots, the share of unsolved challenges (a
  solve rate ≈ 0 with many issued), rising origin latency. Exceeding the thresholds raises
  `attack_mode` automatically; lifting it uses hysteresis (so it does not chatter). **A
  manual setting outranks** the automatic one. The automatic-mode flag is per host.
- **Subnet/IP reputation.** Repeat offenders are aggregated by /24 subnet and ASN
  (especially datacenter pools). The reputation is a global artifact (not per host): the
  same attacking pool is visible to every tenant. It is a soft signal: it raises the score
  and the strictness without blocking by itself.
- **Transient subnet challenge→drop.** During an attack (the host's `attack_mode`), a
  subnet with bad reputation and a solve rate ≈ 0 may temporarily escalate from a challenge
  to a drop. Reactive per-/24 counters on the edge, a TTL plus automatic lifting once the
  attack subsides, with a prior from the global reputation.
- **A cross-tenant hot list (the fast tier).** An attack on one tenant is reconnaissance
  protecting the rest. Active attackers (fingerprint/subnet) are auto-published to a
  short-TTL hot list that pre-arms every edge: when a botnet pivots from tenant A to B, the
  others react within seconds (challenge-first, a lower threshold). The bar for promotion
  into the hot list is high (a false hot list hits everyone, which raises the requirements
  on anti-poisoning). The slow tier (PR-gated global catalogs) remains for persistent
  offenders.

### 3.3 Solve rate as a bot signal under a flood

The share of solved challenges per fingerprint or source is a near-ground-truth label under
a flood: a source that receives challenges en masse and almost never solves them, with
enough issued, is almost certainly a bot. The signal feeds both the automatic attack mode
(3.2) and the detector's score (see [analytics-spec.md](analytics-spec.md)).

---

## 4. The connection/protocol level

Protection against attacks that do not reduce to HTTP request frequency and are therefore
invisible to the rate-limit layer. Two families:

- **Slow attacks** (slowloris / slow POST / slow read) — an attack at the TCP connection
  level: many connections that finish transmitting slowly or never, eating worker slots.
- **HTTP/2 DoS** (Rapid Reset, CVE-2023-44487 and relatives) — an attack at the HTTP/2
  frame level: creating and cancelling streams is cheap for the client and expensive for
  the server.

### 4.1 Why the cascade does not catch this

The cascade runs in the decision phase, after the server has parsed the request line and
the headers. Attacks of this class live below that point:

| Attack | Why it misses the cascade |
| --- | --- |
| slowloris | the headers were never finished → the decision phase barely starts for that connection |
| slow POST/read | few requests, many idle connections → a frequency counter never sees them |
| Rapid Reset | the stream is reset at the frame level, before HTTP semantics → per-request mechanisms never see it |

On top of that, a challenge against such a client is useless — it never finishes the
request, so the challenge page never reaches it.

### 4.2 The architectural principle: nginx mitigates → Lua observes → reputation escalates

This is not a new cascade stage. A slow client and a reset stream never reach the decision
phase, so there is nothing to add there. The pattern for the whole class:

```
nginx/build  →  MITIGATES (directives, a patched version)      ← the real protection
   Lua       →  OBSERVES (the log phase → a log event)          ← the observation layer
reputation   →  ESCALATES (subnet/IP → enforcement/ACL feed)    ← the shared DDoS sink
```

The layer's contribution here is not blocking (nginx does that) but turning nginx's drops
into an observable signal that feeds reputation, and escalating it into the shared DDoS
mechanism.

### 4.3 Slow attacks — mitigation (directives)

Pure nginx config, zero Lua, delivering most of the effect; fully reversible:

- `client_header_timeout` / `client_body_timeout` — cut them to 10–15 s: they tear down
  connections that never finish their headers or body (a `408` refusal). `send_timeout`
  (slow read) closes the connection when the response is read too slowly (with no `408`).
- `limit_conn` by `$binary_remote_addr` — a cap on simultaneous connections per IP;
  `limit_conn_status` for the refusal code (`503`).
- `keepalive_requests` / `keepalive_timeout` — limit how long idle keepalives are held.
- `large_client_header_buffers`, and a deliberate `client_max_body_size` for proxied paths.

The guarantee: legitimate clients pass with room to spare (a typical request is a few KB).

### 4.4 Slow attacks — observation

A Lua hook in the log phase reads `$status` and the duration `$request_time` (written to
the log as `latency_ms`, the same canonical latency field the cascade uses). A header or
body timeout (`408`) and a `limit_conn` refusal (`503`) → a log event tagged `slow_client`
/ `conn_flood` → the dashboard plus counters by IP and /24. The limitation: only what nginx
exposes in the log phase is visible; slow read (`send_timeout`) closes the connection
without a `408`, so it appears only as a connection close, not as a `slow_client` tag.

### 4.5 Slow attacks — a policy knob (optional)

Under `attack_mode` or heightened strictness: a stricter `limit_conn` zone and lower
timeouts. The honest limitation: nginx directives cannot be changed per request from Lua.
The implementation is a `map`-driven zone selection per host, or a coarse global toggle —
not smooth per-request tuning. It may not be built at all if the base directives plus
observation already cover the risk.

### 4.6 HTTP/2 DoS — mitigation (build plus directives)

- A build version that counts streams reset before completion and tears down the connection
  when the count is exceeded (Rapid Reset): OpenResty/nginx ≥ 1.25.3.
- `http2_max_concurrent_streams` — tune it; the CONTINUATION/PING/SETTINGS flood thresholds
  come with the build version; a deliberate `keepalive_requests` for h2.

### 4.7 HTTP/2 DoS — h2 abuse as a signal (optional)

If HTTP/2 client identification (an HTTP/2 fingerprint) is available, anomalous
SETTINGS/stream patterns can be used as a signal into reputation and the score, even while
frame mitigation stays in nginx. Detection assistance, not mitigation.

> HTTP/2 DoS mitigation (Rapid Reset) and HTTP/2 fingerprinting (client identification,
> anti-fingerprint-rotation) are different tasks; the first belongs to this layer, the
> second is a detector signal (see [analytics-spec.md](analytics-spec.md)).

---

## 5. The volumetric L3/L4 layer

SYN/UDP floods and amplification saturate the link and the network stack before the TLS
handshake — at that moment the proxy is not yet involved and is physically not the point of
mitigation.

- **The boundary.** Mitigating volumetric attacks is the network layer's job (scrubbing,
  anycast, a provider filter), outside the proxy's perimeter.
- **The layer's contribution.** The proxy supplies confirmed offenders (IPs and /24s
  accumulated from the L7 and connection/protocol signals) into an edge-ACL feed — the
  contract for escalating into the network layer. The decision to drop at the network level
  belongs to the network layer.

---

## 6. The shared reputation sink

All three layers feed one reputation artifact:

```
L7 (bad traffic / solve rate) ─┐
connection/protocol (408/503) ─┼─► subnet/IP/ASN reputation ─► enforcement (per tenant)
                               │                             └─► edge-ACL feed (network)
HTTP/2 abuse (optional signal) ┘
```

The reputation is global (the artifact is visible to every tenant) while enforcement is per
tenant (it engages during an attack on that specific tenant). This gives the network effect
(an attack on one protects the rest) without punishing tenants with someone else's
thresholds.

---

## 7. What is reused from the cascade

- **The log contract** — connection/protocol signals are written with the same log event as
  the cascade stages, with no new decision stage.
- **Counters and metrics** — `slow_client` / `conn_flood` increments by IP and /24.
- **`attack_mode` and strictness (the policy)** — for the policy knob and adaptivity.
- **The catalogs and their delivery** — the slow tier of reputation travels the same
  delivery path as the blocklists.

---

## 8. Technical guarantees and boundaries

- **L7 adaptivity comes with hysteresis and human priority.** Automatic attack mode does not
  chatter and always yields to a manual setting.
- **At the connection/protocol level the real protection is nginx's.** Lua does not block,
  only observes; if the observation layer is unavailable, the mitigation itself is
  unaffected.
- **There are no per-request adaptive connection limits.** nginx directives are static per
  config; the policy knob switches zones coarsely (per host or globally), not per request.
- **Volumetric L3/L4 is outside the proxy.** The most the layer offers is the edge-ACL feed
  contract; the network mitigation is performed by an external layer.
- **Global reputation requires anti-poisoning.** A cross-tenant hot list hits everyone when
  it is wrong → a high promotion bar and resistance to poisoning are mandatory (see
  [analytics-spec.md](analytics-spec.md)).

---

## 9. Areas of responsibility

| Who | What they do |
| --- | --- |
| **nginx / the build** | the real mitigation of slow attacks (directives) and HTTP/2 DoS (version plus directives) |
| **The observation layer (Lua, the log phase)** | turns nginx's drops into log signals and feeds reputation |
| **The cascade** | the L7 base: rate limits, the challenge, attack_mode |
| **Reputation analytics** | subnet/IP/ASN reputation, automatic attack mode, the hot list, anti-poisoning |
| **The network layer (outside the proxy)** | mitigating volumetric L3/L4 from the edge-ACL feed |

## 10. What is not included

- Mitigating volumetric L3/L4 on the proxy itself (physically impossible — outside the
  perimeter).
- Smooth per-request connection limits (an nginx directive limitation).
- Client identification by HTTP/2 fingerprint as a task in its own right — that is a
  detector signal, not mitigation (see [analytics-spec.md](analytics-spec.md)).
- Content inspection (SQLi/XSS/…) — the adjacent WAF layer, with its own specification.
