# Roadmap

What is built, and what is planned. The authority on what exists is the code.

## Built

### The edge cascade

The five layers run in `infra/demo-stand/lua/`, entry point `verdict.lua`.

- **L1 hygiene** — method whitelist, User-Agent blacklist, header-anomaly tag.
- **L2 reputation** — clearance cookie (stateless HMAC verify), verified bots from
  reverse DNS, IP allow and block lists, datacenter-ASN tag, per-host geo gating.
- **L3 TLS fingerprint** — JA4-style fingerprint computed in pure Lua from the
  `$ssl_*` variables, with GREASE stripped per RFC 8701. Blocklist plus two soft
  rules: an automation fingerprint behind a browser User-Agent, and a cipher
  count that does not match the claimed browser family.
- **L4 rate limits** — five GCRA profiles keyed on IP, IP+UA, API path, TLS
  fingerprint and unique-URL scanning, each with a 10 s and a 60 s window.
- **L5 verification** — the single point where a challenge is decided. Serves the
  JS challenge, issues the clearance cookie, and routes non-browser and
  protocol-incompatible clients separately.

Supporting behaviour: shadow and active modes per host, Standard and Permissive
strictness, per-host attack mode, staged rollout for catalog entries, kill
switches for the whole cascade and for each stage, and edge self-protection that
rejects a non-tenant TLS handshake before any HTTP is read.

### The control plane

A single Go service, `antibot-backend/`, serving the edges.

- Catalog HTTP API with ETag and conditional requests, delivering blocklists,
  per-host policy and the verified-bot set.
- Policy write API for a dashboard, with idempotent patches and an audit log.
- Log receiver that batches into PostgreSQL with a disk queue, so a database
  outage loses nothing.
- Reverse-DNS worker that verifies crawler claims and publishes the verdicts.
- Two-layer catalog: the slow lists live in git and are reviewed through pull
  requests; the runtime state lives in the database.

### Analytics and tooling

- Daily report over the log stream, with fingerprint scoring and evidence.
- Blocklist promotion workflow: staging observation, promotion, and automatic
  demotion of signatures that go quiet.
- Positive fingerprint catalog of expected browser profiles.
- Integration harness that exercises catalog delivery latency, atomicity and
  fail-stale behaviour.

## Planned

### Detection

- Version-labelled browser fingerprints, so a live browser is never auto-blocked.
- User-Agent version against fingerprint version mismatch.
- Headless-browser fingerprints (Playwright, Puppeteer, patched Chrome drivers).
- Anti-poisoning for the scoring: weighted human share, and a known-good
  invariant on top of the positive catalog.
- Behavioural and temporal signals — inter-request rhythms, navigation graphs.

### Rate-based anti-DDoS

Adaptive deepening of what L4 and attack mode already do: subnet reputation for
datacenter pools, transient subnet challenge under attack, automatic attack
detection from bot rate and solve rate against a host baseline, and a
cross-tenant hot list so an edge is pre-armed when a botnet pivots.

### Connection and protocol DDoS

Attacks below the request layer, which the cascade cannot see: slow-attack
baselines through nginx timeouts and connection limits, HTTP/2 abuse mitigation,
and feeding both into reputation as signals.

### Known gaps

Things the current implementation deliberately does not do, carried over from the
delivery specs:

- No `X-Antibot-*` headers towards the customer's origin — the verdict stays on
  our side of the proxy.
- No external reputation feeds (residential proxy lists, Tor exit nodes,
  commercial known-bad sets).
- The TLS fingerprint uses the handshake fields nginx exposes, not the full
  extension list or the signature algorithms. Reaching those needs a raw
  ClientHello parser.
- The fingerprint catalogs are shared across all resources; a per-customer TLS
  policy would be a separate mechanism.
- Per-fingerprint counters are per proxy. Without shared state, a bot that hops
  between nodes resets its own limits.
- The customer-facing dashboard is a separate product surface; this repo ships
  the policy API it would talk to.

### Research

- Device Bound Session Credentials as an additional bot signal.
- HTTP/2 fingerprinting, to extend the fingerprint beyond TLS.
