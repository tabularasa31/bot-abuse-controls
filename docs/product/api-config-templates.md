# API and account protection — config templates

Illustrative templates of the layer's policy fields, profiles and catalogs (both axes). The behaviour
contract is [api-spec.md](api-spec.md); the rules are [api-rules-reference.md](api-rules-reference.md);
the vocabulary is [api-entities-reference.md](api-entities-reference.md).

The format is YAML with comments for readability. What matters is the structure and the semantics of the fields,
not the exact syntax. The layer plugs into the existing per-host policy and into the
rate-limit engine; the path declaration extends API path matching; the schemas and
disposable-email list are delivered as slow catalogs (PR-only).

> The PII invariant. The username and the token or key are used as keys and written to the log only
> in hashed form (HMAC). The password is never logged, stored or inspected — it does not and cannot
> appear in the configs.

---

## What is added to a host's policy

The layer extends the `policy[host]` entry with groups of fields: the endpoint declaration and
the per-endpoint contract, the identity profiles, failed-auth feedback, resource limits,
the JWT/mTLS config, the transport flags and disposable email. All of it is mode-gated: under `enforce: false`
everything is counted and logged but never physically enforced.

---

## 1. The endpoint declaration plus the per-endpoint contract

```yaml
example.com:
  # ... the base policy fields (mode/strictness/origin_ip/...) ...

  # The path declaration (a foundation). Globs, as in rate_rules.
  endpoints:
    login:    [ /login, /api/v1/auth/login, /signin* ]
    register: [ /register, /signup* ]
    api:      [ /api/*, /graphql ]

  # The per-endpoint contract (the positive model): what is permitted on a path.
  contract:
    - path: /api/v1/orders
      allowed_methods: [ GET, POST ]
      allowed_content_types: [ application/json ]
      required_params: [ ]
    - path: /api/v1/auth/login
      allowed_methods: [ POST ]
      allowed_content_types: [ application/json, application/x-www-form-urlencoded ]

  enforce: false   # false = observation (shadow), true = active enforcement
```

| Field | Type | What it sets |
| --- | --- | --- |
| `endpoints.login/register/api` | array of glob | The path classes; the identity and contract stages run only here |
| `contract[].allowed_methods` | array | The methods permitted at an endpoint; everything else is rejected (403) |
| `contract[].allowed_content_types` | array | The content types permitted for the body; everything else is rejected (415/422) |
| `contract[].required_params` | array | The required parameters; their absence leads to a reject (422) |
| `enforce` | boolean | The layer's mode gate: observation versus enforcement (default `false`) |

Reading the body is enabled only for the `login`/`register` classes (where the username is needed) and
for endpoints with a schema; upload and binary endpoints are bypassed. The API key and token come from
headers or the query — the body is not needed for the `api` class.

## 2. Identity profiles

GCRA profiles on top of the rate-limit engine; the key is identity, not a network parameter.

```yaml
example.com:
  identity_rate_profiles:
    login_per_account:                 # the key is the hashed username
      key: hashed_username
      windows:
        - { seconds: 60,  limit: 5 }
        - { seconds: 600, limit: 20 }
      action: challenge                # challenge | block — the final action follows strictness/enforce
    per_api_key:                       # the key is the hashed api key
      key: hashed_api_key
      windows:
        - { seconds: 60,   limit: 600 }
        - { seconds: 3600, limit: 10000 }
      action: block                    # for APIs we do not rely on a JS challenge

  # optionally override the windows on a specific path
  per_endpoint_quotas:
    - { path: /api/v1/auth/login, profile: login_per_account, windows: [ { seconds: 60, limit: 3 } ] }
    - { path: /api/bulk-export,   profile: per_api_key,       windows: [ { seconds: 60, limit: 50 } ] }
```

| Field | Type | What it sets |
| --- | --- | --- |
| `key` | enum (`hashed_username` / `hashed_api_key`) | The source of the key; always hashed |
| `windows` | list of `{seconds, limit}` | The GCRA windows; any exceeded window fires |
| `action` | enum (`challenge` / `block`) | The desired action; enforcement is mode-gated by `enforce` and strictness |

For login with a browser client `challenge` is appropriate; for APIs use `block` (429), since we do not
rely on a JS challenge.

## 3. Failed-auth feedback

```yaml
example.com:
  failed_auth_feedback:
    enabled: true
    fail_statuses: [ 401, 403 ]
    keys: [ hashed_account, ip_24 ]
    spike: { min_attempts: 10, fail_ratio: 0.8, window_seconds: 300 }
    on_spike: { reputation_score: increase, escalate: challenge_strictness }
```

This is statistics over responses, not a password check. The assumption is that the origin returns distinguishable
statuses for success and failure — pinned down when onboarding a domain.

## 4. The schema catalog (a slow catalog, PR-only)

Delivered as a slow catalog, separately from the per-host policy. A compiled
subset of JSON schemas per endpoint.

```yaml
# catalog: api_schemas
example.com:
  /api/v1/orders:
    POST:
      type: object
      additionalProperties: false        # fields outside the schema → reject (the mass-assignment vector)
      required: [ item_id, qty ]
      properties:
        item_id: { type: string }
        qty:     { type: integer }
  upload_bypass:                          # endpoints where the body is not parsed as JSON
    - /api/v1/files/upload
```

## 5. Resource limits

```yaml
example.com:
  resource_limits:
    max_body_bytes: 262144               # the body size; exceeding it gives a 413 (partly at the nginx level)
    json:
      max_depth: 32                      # protection against "billion laughs"
      max_array_len: 10000
    graphql:                             # optional
      max_depth: 12
      max_aliases: 50
```

## 6. Edge JWT and mTLS

```yaml
example.com:
  jwt:
    enabled: true
    applies_to: [ api ]                  # the path classes where the token is validated
    jwks_source: jwks_example_com        # JWKS/the secret (delivered as a secret or catalog)
    expected_iss: [ https://auth.example.com ]
    expected_aud: [ api.example.com ]
    required_scope:                      # optional coarse authorisation per endpoint
      - { path: /api/v1/admin/*, scope: admin }

  mtls:                                  # optional, per tenant, off by default
    enabled: false
    verify: optional                     # off | optional | on (nginx always uses optional; under on the check happens in Lua)
```

JWT is a stateless check (signature/exp/nbf/iss/aud); revocation and stateful
introspection belong to the backend. The raw token is never logged. mTLS is the transport level;
compatibility with on-demand TLS is verified separately.

## 7. Transport hygiene and deprecated versions

```yaml
example.com:
  transport:
    hsts: true
    x_content_type_options: nosniff
    cors:
      allow_origins: [ https://app.example.com ]   # not a blind "*"
    strip_server_banner: true
    mask_5xx_details: true

  deprecated_versions:                   # a deprecated version's path → 410 (mode-gated)
    - /api/v0/*
```

## 8. Disposable email (optional)

```yaml
example.com:
  disposable_email:
    enabled: true
    catalog: disposable_email_domains    # a slow catalog (PR-only)
    applies_to: [ register, login ]
    action: soft_signal                  # +score or a flag, never a block on its own
```

---

## Conventions

- Glob path patterns work as in the base rate rules; the endpoint class is derived from
  them.
- Key hashing is always HMAC, in the context and in the log; raw usernames and tokens never
  reach the config.
- The mode gate: the layer's behaviour is governed by `enforce` (per host); under `false` everything
  is counted and logged but not enforced.
- The slow catalogs (schemas, disposable email, JWKS) are delivered PR-only, separately from
  the fast per-host policy.
- parent-domain fallback: a host's entry covers its subdomains, and a more specific one
  overrides the parent.
