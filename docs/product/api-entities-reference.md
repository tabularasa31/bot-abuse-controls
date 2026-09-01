# API and account protection — entity reference

The canonical vocabulary of the layer's terms, stages, keys, profiles, catalogs, tags, log
fields and enumerations. The behaviour contract is [api-spec.md](api-spec.md); the rules
are in [api-rules-reference.md](api-rules-reference.md).

---

## 1. The axes and shared terms

| Term | Definition |
| --- | --- |
| Axis A (account and API abuse) | Control of credential stuffing, brute force, fake registration, scraping, key abuse and leakage, and enumeration — by identity and quotas. |
| Axis B (the contract and governance) | The positive model: what is permitted at an endpoint (method/type/schema/token), plus resource limits, edge token validation, transport hygiene and inventory. |
| identity-blind | A property of the cascade: it sees the IP, fingerprint, UA, Host, path and headers, but not "which account or key". Hence the need for an identity-extraction stage. |
| the positive model | It describes what is permitted and cuts the rest (axis B). Complementary to the WAF's negative model (attack signatures). |
| mode-gated | Under shadow a hit is counted and logged but the request is not cut; under active it is enforced. |
| the endpoint declaration | A per-host list of login, registration and API paths (globs), plus optional per-endpoint quotas. The identity and contract stages run only on declared paths. |
| endpoint class | The edge's classifier for "which class a path belongs to" (login / register / api / other), taken from the declaration. |

## 2. Identity (the foundation of axis A)

| Entity | Definition |
| --- | --- |
| the identity-extraction stage | A light stage on declared paths: it places a normalised hashed key into the request context (as the fingerprint rate limit keys on the fingerprint). It issues no verdict. |
| hashed username | The username from the login form, hashed with HMAC. The key for the login profile and failed-auth feedback. It is never used or logged raw. |
| hashed key | The API key or bearer token from a header or the query, hashed with HMAC. The key for the key profile and reputation. |
| graceful skip | When identity cannot be extracted, the dependent profiles are skipped and the request continues through the cascade without an error. |
| the PII invariant | The username and token are hashed only; the password is never logged, stored or inspected; the body is read only for the login/register classes and endpoints with a schema, with a limit and a bypass for uploads. |

## 3. Identity rate profiles (axis A)

| Entity | Definition |
| --- | --- |
| the login profile (per account) | A GCRA profile on the hashed username: it catches stuffing across many accounts and a brute force of one. The tag is `account:cred_stuffing`. |
| the key profile (per key) | A GCRA profile on the hashed key: it catches abuse of one key from many IPs, scraping, enumeration and key leakage. The tag is `api:key_abuse`. |
| the rate-limit engine | The same GCRA engine and shared-memory cells as the cascade's network profiles; only the key changes (identity instead of a network parameter). |

## 4. Failed-auth feedback (axis A)

| Entity | Definition |
| --- | --- |
| failed-auth | A request to a login path that the origin answered with 401/403 (the response phase). |
| failed ratio | The share of failed logins per hashed account or /24 subnet over a window. A spike means +score and an escalation. The tag is `account:auth_fail_spike`. |
| the distinguishable-status assumption | The feedback works if the origin returns distinguishable statuses for success and failure; this is pinned down when onboarding a domain. |

## 5. The contract and schema (axis B)

| Entity | Definition |
| --- | --- |
| allowed_methods | The HTTP methods permitted at an endpoint (the positive model). Everything else is rejected. The tag is `api:contract_violation`. |
| allowed_content_types | The content types permitted for an endpoint's body. |
| required_params | The endpoint's required parameters; their absence leads to a reject. |
| the schema catalog | A compiled subset of JSON Schema (types, required, `additionalProperties`), delivered as a slow catalog, PR-only. The tag is `api:schema_violation`. |
| `additionalProperties=false` | Fields outside the schema are forbidden — it cuts the mass-assignment vector on input (but not mass-assignment semantics, which is the backend's). |
| the schema bypass | The list of upload and binary endpoints where the body is not parsed as JSON. |

## 6. Resource limits (axis B)

| Entity | Definition |
| --- | --- |
| the body size limit | Per host and per endpoint; exceeding it gives a 413 (partly at the nginx level, before Lua). |
| JSON structural complexity | Maximum nesting depth and array length; protection against "billion laughs". Exceeding it gives a 422. |
| GraphQL limits (optional) | The query's depth, cost and number of aliases. |

## 7. Edge JWT and mTLS (axis B)

| Entity | Definition |
| --- | --- |
| JWT validation | A stateless token check on API paths: the signature (JWKS/secret), `exp`/`nbf`, `iss`/`aud`. An invalid token is rejected (401). The tag is `api:token_invalid`. |
| JWKS / the secret | The material for verifying a token's signature; delivered as a secret or a catalog. |
| required scope (optional) | A per-endpoint required scope gives coarse authorisation (not full BFLA). |
| mTLS / client certificate | Verification of the client certificate on mTLS hosts (optional, per tenant), at the transport level. The tag is `api:mtls_fail`. |

## 8. Transport hygiene and inventory (axis B)

| Entity | Definition |
| --- | --- |
| security headers | HSTS, X-Content-Type-Options and a correct CORS per the policy (not a blind `*`). Response side. |
| banner stripping | Removing banner headers and server version disclosure. |
| error masking | Hiding the origin's verbose 5xx details in the response to the client. |
| a shadow endpoint | A called path outside those declared. The tag is `api:shadow_endpoint`; optionally a draft PR proposing it for the declaration. |
| a zombie endpoint | Declared but never called during the window (a candidate for removal from the contract). |
| a deprecated version | A path marked as deprecated; a request to it gives a 410 (mode-gated). |

## 9. Tags (accumulating in the log's `tags` field, in the form `account:*` / `api:*`)

| Tag | Where it appears | What it means |
| --- | --- | --- |
| `account:cred_stuffing` | rate_limits (the login profile) | A spike of login attempts across accounts |
| `account:auth_fail_spike` | log/response (failed-auth) | A spike in the share of failed logins |
| `api:key_abuse` | rate_limits (the key profile) | Abuse of one key (scraping/enumeration/leakage) |
| `api:contract_violation` | the per-endpoint contract | A method, type or parameter outside what is permitted |
| `api:schema_violation` | schema validation | The body fails the JSON schema |
| `api:token_invalid` | edge JWT | An invalid or expired token |
| `api:mtls_fail` | mTLS | A missing or invalid client certificate |
| `api:shadow_endpoint` | API inventory | A call to an undeclared path |

## 10. Policy fields and catalogs

| Entity | Where it lives | Purpose |
| --- | --- | --- |
| the path declaration | the per-host policy | login/register/api paths (globs) plus per-endpoint quotas |
| the per-endpoint contract | the per-host policy | allowed_methods / content_types / required_params |
| the JWT config | the per-host policy | JWKS/secret, the expected iss/aud, the required scope |
| the mTLS flag | the per-host policy | Enabling client certificate verification |
| the transport flags | the per-host policy | Security headers, banner stripping, error masking |
| the deprecated version | the per-host policy | Patterns of deprecated paths → 410 |
| the schema catalog | a slow catalog (PR-only) | JSON schemas for endpoint bodies |
| the disposable-email catalog | a slow catalog (PR-only) | Disposable mail domains (a fake-registration signal) |

## 11. Enumerations

| Enumeration | Values |
| --- | --- |
| rule category | `blocking` · `soft` · `tag` · `—` (a foundation) |
| endpoint class | `login` · `register` · `api` · other |
| HTTP on reject | 401 · 403 · 410 · 413 · 415 · 422 · 429 |

## 12. Technical boundaries (backend, not edge)

| Scenario | Why not the edge | Where it is solved |
| --- | --- | --- |
| ATO (an anomalous successful login) | It needs the account's history; the edge only supplies fingerprint and geo context | the backend |
| object and function authorisation (BOLA / full BFLA) | It needs identity plus ownership plus business rules | the backend |
| business-logic abuse (scalping, coupons) | It needs application context | the application / backend |
| breached-password validation | A full password check against a breach list is not a hot-path operation | the backend |
| token revocation / introspection | It requires state | the backend |
