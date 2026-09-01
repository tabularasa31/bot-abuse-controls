# API and account protection — specification (post-MVP)

**Version:** v1.0 · Status: a design contract (target behaviour) · a post-MVP layer

This document describes the target behaviour of the API and account protection layer as a
separate layer on top of the cascade ([vision.md](../product/vision.md)): a "pick it up and build it"
specification to implement from. The cascade from the vision rate-limits and checks by
network keys (IP, fingerprint, UA, path); this layer adds the dimension of identity
(account, key, token) and of the API contract (what is permitted at an endpoint), neither
of which the cascade has.

**Related material (as for the vision):**
[api-rules-reference.md](api-rules-reference.md) — the rules in "if condition → verdict"
form; [api-entities-reference.md](api-entities-reference.md) — the entity vocabulary
(stages, keys, profiles, catalogs, tags, log fields, enumerations);
[api-config-templates.md](api-config-templates.md) — the structure of the policy fields,
the schema catalog format, the JWT/mTLS config.

---

## 1. What it is

The layer covers two related but distinct axes of API protection:

- **Axis A — account and API abuse.** Credential stuffing, brute force, mass fake
  registration, scraping, key enumeration and leakage. Control by identity and quotas.
- **Axis B — the contract and governance.** A positive model: what is permitted at an
  endpoint (method, type, schema, token) and cutting off everything else; plus resource
  limits, edge token validation, transport hygiene and endpoint inventory.

The axes are complementary and share one foundation — the endpoint declaration and
identity extraction (see §4).

**The positive model (axis B) versus the WAF's negative model.** Axis B describes what is
**permitted** and cuts the rest; the WAF ([waf-spec.md](waf-spec.md)) looks for signatures
of specific attacks. These are two complementary approaches to one surface.

## 2. Why — what the cascade lacks

The cascade already does rate limits by network keys, reputation and the challenge. That is
not enough:

- **Stuffing spread across a thousand IPs** but aimed at one account — a per-IP limit is
  defeated by rotating proxies or a botnet.
- **Abuse of one API key from many IPs** — a network key cannot see "the key".
- **A targeted brute force of one account** — that needs a per-account counter.
- **The API contract is not checked** — there is no validation of the method, type or
  schema at an endpoint, no size and complexity limits on the body, no edge token
  validation, no security headers, no endpoint inventory.

Control by identity (account/key/token) and by the request's contract is needed, and the
cascade does not have it today.

## 3. The key limitation: the edge is identity-blind

The cascade sees the IP, fingerprint, UA, Host, path and headers — but not "which account"
and not "which key". So the foundation of axis A is an identity-extraction stage that puts
a normalised key into the request context, exactly as the fingerprint rate limit keys on
the fingerprint. Without it axis A cannot be built.

A second cross-cutting principle: the strongest auth-abuse signal is the share of failed
logins, and the edge sees that only from the origin's response (a 401/403 status in the
response phase). That is the same feedback pattern as the challenge solve rate in the
analytics layer.

## 4. Where it sits in the cascade

```
hygiene → [contract] → [schema] → reputation → tls_fp → [identity-extract] →
          rate_limits(+per-key) → [JWT] → verification
   ↑ resource limits (partly nginx before Lua, partly Lua after parsing)
   ↑ mTLS — transport, before the cascade
   ↓ transport hygiene — the response/header phase
   ↓ failed-auth feedback, API inventory — the log/response phase, analytics
```

The exact placement of the stages is pinned down at implementation time; the principle is:
the contract and the schema early (they cut junk cheaply before the expensive layers),
identity extraction before rate_limits, and token validation before proxying to the origin.
The identity and contract stages are active only on paths declared in the endpoint
declaration (§5.1).

---

## 5. Axis A — account and API abuse

### 5.1 The endpoint declaration (a foundation)

A per-host declaration: the login, registration and API paths (glob patterns), plus
optional per-endpoint quotas. It gives the edge a classifier for "which class this path
belongs to". This is a companion foundation: the identity and contract stages run only on
declared paths and skip the rest. It is delivered per host through the policy (the same
path as the rest of the per-host configuration).

### 5.2 Identity extraction (a foundation)

On declared auth and API paths it extracts: an API key or bearer token from the
authorization header / `X-API-Key` / the query; a username from the login form
(form-urlencoded / JSON). It normalises them into a key for the rate profiles and
reputation.

**PII and security (a hard invariant):**

- The username and the token or key are hashed (HMAC) before being used as a key and in the
  logs — never raw.
- The password is never logged, never stored and never inspected — the layer has no need
  for its value.
- Reading the body is enabled only for the login/register classes and endpoints with a
  schema, with a size limit (§6.3) and a bypass for large or upload endpoints.

### 5.3 Per-credential / per-key rate profiles

New GCRA profiles on top of the existing rate-limit engine (the same windows and
shared-memory cells), but keyed on identity rather than a network parameter:

- a profile by hashed username — catches stuffing across many accounts and a brute force of
  one account;
- a profile by hashed key — catches abuse of one key from many IPs, scraping, enumeration
  and key leakage.

There is a graceful skip when no key is present (like the guard on a fingerprint cache
miss). Enforcement is mode-gated: the final action (a challenge or a 429) depends on the
host's mode and strictness, as with the existing rate rules.

### 5.4 Failed-auth feedback

Feedback from the origin's response (the log/response phase): it reads the upstream status
on login paths, classifies success or failure (401/403 = failure) and accumulates the
failure share by hashed account and by /24 subnet. A spike in the failure share means
+score into reputation and an escalation of the challenge or strictness on the source's
subsequent requests.

This is statistics over responses, not a password validity check. It depends on the origin
returning distinguishable statuses for success and failure — an assumption pinned down when
onboarding a specific domain.

### 5.5 Disposable email / breached credentials (optional)

A signal for stuffing and fake registration. The realistic edge scope is a catalog of
disposable email domains (delivered as a slow catalog, PR-only). A full password check
against a breach list is a backend function, not a hot-path one: the edge does not validate
passwords.

---

## 6. Axis B — the contract and governance

### 6.1 A per-endpoint contract (the positive model)

On top of hygiene's global method whitelist, a positive model per endpoint: the permitted
methods, the permitted content types, optional required parameters; everything else is
rejected. On paths with no rules it skips. It is mode-gated (shadow by default) and carries
the `api:contract_violation` tag.

### 6.2 Schema validation

On top of the contract, validation of the body against a JSON schema (a compiled subset of
OpenAPI, not a full engine on the hot path): types, required fields,
`additionalProperties=false` (which cuts the mass-assignment vector on input). Schemas
are a slow catalog, PR-only. It requires reading the body with a limit (§6.3) and a bypass
for uploads. The tag is `api:schema_violation`.

### 6.3 Resource limits

Protection from a single "heavy" request that a count-based rate limit never catches:

- body size — per host and per endpoint (the limit is checked in Lua, with a global cap at
  the nginx level);
- the structural complexity of JSON — maximum depth and array lengths (protection against
  "billion laughs");
- GraphQL (optional) — depth, cost, the number of aliases.

This complements the simultaneous connection limit from the DDoS layer: that one is about
connections, this one about the cost of a single request.

### 6.4 Edge JWT/token validation

Identity extraction pulled the token out as a key; here its validity is checked on API
paths: the signature (JWKS or a secret), `exp`/`nbf`, `iss`/`aud`. A forged or expired token
is cut before proxying to the origin (relieving the backend plus an early block). The keys
and JWKS are delivered as a secret or a catalog. An optional required scope per endpoint
gives coarse authorisation. The tag is `api:token_invalid`.

This is token authentication, not object authorisation: object ownership by ID (BOLA) and
full BFLA belong to the backend. Only stateless checks happen here; revocation and stateful
introspection are also the backend's. The raw token is never logged.

### 6.5 mTLS / client certificates (optional, per tenant)

For APIs with strong client authentication: verifying the client certificate on mTLS hosts.
This is the transport level, before the cascade. Off by default. Compatibility with
on-demand TLS is verified separately. The tag is `api:mtls_fail`.

### 6.6 Transport hygiene

Response-side, cheap and high-ROI, per host: security headers (HSTS,
X-Content-Type-Options, a correct CORS per the policy — not a blind `*`); stripping banner
headers and server versions; masking the origin's verbose 5xx errors.

### 6.7 API inventory / governance

Analytics on top of the log: the edge logs all traffic and knows the declared paths, so a
diff between the endpoints called and those declared gives an inventory almost for free:
undeclared ones (shadow, the tag `api:shadow_endpoint`) and declared-but-unused ones
(zombies). Enforcement of deprecated versions belongs here too (a deprecated path → 410,
mode-gated).

---

## 7. Enforcement: there is no JS challenge for APIs

The JS challenge is browser-based, so on pure API paths it cannot be relied on. Enforcement
here rests on: rate limits by key and account, token or mTLS validation, reputation, and
429/4xx from the contract. For login paths with a browser client, a step-up through the
challenge is appropriate.

## 8. What is reused from the cascade

- **The rate-limit engine** (GCRA plus keying) — for the per-key and per-account profiles.
- **The per-host policy** — for the endpoint declaration, the contract, the JWT/mTLS config
  and the transport flags.
- **Slow-catalog delivery** (PR-only) — for the schemas, the disposable email domains and
  JWKS.
- **Reputation and the challenge** — per key and per account alongside per IP, with a
  step-up on auth.
- **The log and the tags** — for the axes' signals (`account:*`, `api:*`) and the inventory.
- **glob path matching** — for classifying endpoints.

## 9. Technical boundaries (backend, not edge)

These scenarios cannot be solved at the edge — they need context the edge does not have.
The edge supplies a signal, not a decision:

- **ATO** (an anomalous successful login) — it needs the account's history; the edge only
  supplies fingerprint and geo context.
- **Object and function authorisation** (BOLA, full BFLA), semantic mass assignment,
  business logic and control of PII in responses — they need identity plus ownership plus
  business rules.
- **Credential stuffing** at the edge means volume plus the failure share plus a bot score,
  not a password check against a breach list.
- **Breached-password validation** and token revocation or introspection are backend
  functions, not hot-path ones.

## 10. Areas of responsibility

| Who | What they do |
| --- | --- |
| **The edge (the cascade)** | extracts identity, limits by key and account, validates the contract/schema/token/mTLS, response hygiene |
| **Log analytics** | failed-auth feedback, endpoint inventory, draft PRs for declaration candidates |
| **The policy (per host)** | the endpoint declaration, the contract, the JWT/mTLS config, the transport flags |
| **The backend** | ATO, object authorisation and business logic, breached passwords, token revocation |

## 11. Components and rollout order

| Component | Axis | Depends on |
| --- | --- | --- |
| The endpoint declaration | foundation | — |
| Identity extraction | foundation | — |
| Per-key / per-account rate profiles | A | both foundations |
| Failed-auth feedback | A | identity plus the declaration |
| The disposable email signal (optional) | A | identity |
| The per-endpoint contract | B | the declaration |
| Resource limits | B | — |
| Schema validation | B | the contract plus resource limits |
| Edge JWT validation | B | identity |
| Transport hygiene | B | — |
| mTLS (optional) | B | — |
| API inventory | B | the declaration |

The order: the two foundations (the declaration plus identity) in parallel → the per-key
profiles, failed-auth feedback and the contract; the cheap and early pieces (resource
limits, transport hygiene) at any time → schema, JWT, inventory. The rule breakdown is in
[api-rules-reference.md](api-rules-reference.md).

## 12. What is not included

- Object and function authorisation, and business logic (the backend).
- Full password checks against a breach list, and stateful token revocation (the backend).
- Signature-based attack detection (SQLi/XSS/…) — that is the WAF
  ([waf-spec.md](waf-spec.md)), a negative model complementary to axis B's positive one.
