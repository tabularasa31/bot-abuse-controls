# API and account protection — rules reference

The layer's rules in "if condition → verdict/action" form, across both axes. The behaviour
contract is [api-spec.md](api-spec.md); the entity vocabulary is
[api-entities-reference.md](api-entities-reference.md); the config structures are in
[api-config-templates.md](api-config-templates.md).

Categories: `blocking` (issues a reject with an HTTP status), `soft` (accumulates a signal
or has an indirect effect), `tag` (an informational marker that emits no verdict) and `—`
(a foundation: it sets a key or context and emits no verdict). Most blocking rules are
mode-gated: under shadow a hit is counted and logged but the request is not cut; under
active it is enforced.

> The PII invariant (cross-cutting for every rule on axis A). The username and the token or
> key are used as keys and written to the log only in hashed form (HMAC), never raw. The
> password is never logged, stored or inspected. The body is read only for the
> login/register classes and endpoints with a schema, with a size limit and a bypass for
> uploads.

---

## Axis A — account and API abuse

### ID — identity extraction (a foundation, only on declared paths)

| # | If | → action | Category |
| --- | --- | --- | --- |
| ID-1 | a key or bearer token was extracted from the authorization header / `X-API-Key` / the query on an auth or API path | a hashed key is placed in the context; no verdict is emitted | — |
| ID-2 | a username was extracted from the body (form-urlencoded/JSON) on a login or register path | a hashed username is placed in the context; no verdict is emitted | — |
| ID-3 | identity could not be extracted (the field is missing / the body is unreadable / the path is not declared) | a graceful skip — the dependent profiles are skipped and the request continues through the cascade | — |

### RK — per-credential / per-key rate profiles (the rate_limits stage)

| # | If | → action | Category |
| --- | --- | --- | --- |
| RK-1 | the login profile's windows were exceeded for a hashed username (stuffing across many accounts, or a brute force of one) | a challenge or a 429 per the mode and strictness; the tag `account:cred_stuffing` | blocking / soft |
| RK-2 | the key profile's windows were exceeded for a hashed key (key abuse from many IPs / scraping / enumeration / leakage) | a 429 or a challenge per the mode and strictness; the tag `api:key_abuse` | blocking / soft |
| RK-3 | identity from ID is absent | the per-key profiles are skipped; the cascade's network profiles keep working | — |

### FA — failed-auth feedback (the log/response phase)

| # | If | → action | Category |
| --- | --- | --- | --- |
| FA-1 | the origin's response on a login path has status 401/403 | it is classified as a failure and the counters for the hashed account and the /24 are incremented. The current request's verdict is unchanged | — |
| FA-2 | the failed-login share for a hashed account or a /24 exceeds the threshold | +score into reputation plus an escalation of the challenge or strictness on subsequent requests; the tag `account:auth_fail_spike` | soft |

### DE — disposable email / breached credentials (optional)

| # | If | → action | Category |
| --- | --- | --- | --- |
| DE-1 | the email domain from the registration or login form is in the disposable-email domain catalog | a soft fake-registration signal: +score or a flag into reputation; it issues no block itself | soft |

---

## Axis B — the contract and governance

### CT — the per-endpoint contract (the positive model)

| # | If | → action | Category |
| --- | --- | --- | --- |
| CT-1 | the path matched a declared endpoint and the method is not among those permitted for it | reject (403), the tag `api:contract_violation`. Mode-gated | blocking |
| CT-2 | the path matched and the body's content type is not among those permitted | reject (415/422), the tag `api:contract_violation`. Mode-gated | blocking |
| CT-3 | the path matched, required parameters are declared and the request does not carry them | reject (422), the tag `api:contract_violation`. Mode-gated | blocking |
| CT-4 | the path matched no declared endpoint | skip (the contract is not applied); detection of shadow paths lives in IV | — |

### SC — schema validation

| # | If | → action | Category |
| --- | --- | --- | --- |
| SC-1 | the body is unparseable as JSON on an endpoint with a declared schema | reject (422), the tag `api:schema_violation`. Mode-gated | blocking |
| SC-2 | the body parsed but fails the schema (a required field is missing, or a type is wrong) | reject (422), the tag `api:schema_violation`. Mode-gated | blocking |
| SC-3 | the body carries fields outside the schema while `additionalProperties=false` (the mass-assignment vector on input) | reject (422), the tag `api:schema_violation`. Mode-gated | blocking |
| SC-4 | the endpoint is on the bypass list (upload / binary) | skip schema validation | — |

### RL — resource limits

| # | If | → action | Category |
| --- | --- | --- | --- |
| RL-1 | the body size exceeds the per-host or per-endpoint limit | reject (413). Mode-gated | blocking |
| RL-2 | the structural complexity of the JSON exceeds the threshold (depth or array length) | reject (422). Mode-gated | blocking |
| RL-3 | (optional) a GraphQL query exceeds the depth, cost or alias threshold | reject (422). Mode-gated | blocking |

### JW — edge JWT/token validation (API paths)

| # | If | → action | Category |
| --- | --- | --- | --- |
| JW-1 | the token's signature does not verify against the JWKS or secret | reject (401), the tag `api:token_invalid`. Mode-gated | blocking |
| JW-2 | the token has expired or is not yet valid (`exp`/`nbf`) | reject (401), the tag `api:token_invalid`. Mode-gated | blocking |
| JW-3 | `iss`/`aud` do not match those expected for the host or endpoint | reject (401), the tag `api:token_invalid`. Mode-gated | blocking |
| JW-4 | (optional) a required scope is declared for the endpoint and a valid token lacks it (coarse authorisation) | reject (401/403). Mode-gated | blocking |

### MT — mTLS / client certificates (optional, per tenant)

| # | If | → action | Category |
| --- | --- | --- | --- |
| MT-1 | on an mTLS host the client presented no certificate while the check requires one | reject at the transport level, the tag `api:mtls_fail`. Mode-gated | blocking |
| MT-2 | a certificate was presented but is invalid (the wrong CA / expired / unverified) | reject, the tag `api:mtls_fail`. Mode-gated | blocking |

### TH — transport hygiene (response side)

| # | If | → action | Category |
| --- | --- | --- | --- |
| TH-1 | security headers are enabled for the host in the policy | add or normalise HSTS, X-Content-Type-Options and a correct CORS (not a blind `*`) | soft |
| TH-2 | the response discloses banner headers or the server version | strip the banner headers and disable version disclosure | soft |
| TH-3 | the origin returned a verbose 5xx (a stack trace or internal details) | mask the error details in the response to the client | soft |

### IV — API inventory / governance (analytics on top of the log)

| # | If | → action | Category |
| --- | --- | --- | --- |
| IV-1 | a path was called that is not among those declared (undeclared / shadow) | the tag `api:shadow_endpoint`; optionally a draft PR proposing it for the declaration | tag |
| IV-2 | a declared endpoint is not called during the observation window (a zombie) | a signal for analytics (a candidate for removal from the contract) | tag |
| IV-3 | a request to a path marked as a deprecated version | reject (410 Gone). Mode-gated | blocking |

---

## Summary: tags and HTTP statuses

| Group | Category | HTTP on reject |
| --- | --- | --- |
| ID | — (a foundation) | — |
| RK | blocking / soft | 429 (or a challenge) |
| FA | soft | — (the log phase) |
| DE | soft | — |
| CT | blocking | 403 / 415 / 422 |
| SC | blocking | 422 |
| RL | blocking | 413 / 422 |
| JW | blocking | 401 (403 for a scope) |
| MT | blocking | a refusal at the transport level |
| TH | soft | — (response side) |
| IV | tag / blocking | — / 410 (deprecated) |

The layer's tags (accumulating in the log's `tags` field, in the form `account:*` /
`api:*`): `account:cred_stuffing`, `account:auth_fail_spike`, `api:key_abuse`,
`api:contract_violation`, `api:schema_violation`, `api:token_invalid`, `api:mtls_fail`,
`api:shadow_endpoint`.

## The boundary (what these rules do NOT do)

Object and function authorisation (BOLA / full BFLA), business logic, semantic mass
assignment, control of PII in responses, ATO, password checks against a breach list and
token revocation all belong to the backend. The edge supplies a signal, not a decision. The
vocabulary of entities and boundaries is
[api-entities-reference.md](api-entities-reference.md).
