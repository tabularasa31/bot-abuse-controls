# The Bot & Abuse Controls cascade — diagrams

Six complementary diagrams describing how the cascade works: the main flow, the L5
decision tree, the mode × Strictness × verdict matrix, the data flow into the log, a
sequence diagram of the runtime interactions, and the state of a verified bot. Each
focuses on its own aspect; together they give the full picture. The source of truth for
the semantics is [vision.md](vision.md) — these diagrams are a visual commentary on it.

The diagrams are Mermaid. They render on GitHub, on GitLab and in IDEs with the right
extensions. For Google Docs or PDF, export them to PNG through mermaid.live or the CLI.

---

## 1. The main flow — a request's path from arrival to response

A high-level overview. It shows every cascade layer, the terminal states (block / allow /
challenge) and where the traffic that passes ends up.

```mermaid
flowchart TD
    Start([HTTP request to a protected domain])
    TLS[TLS handshake<br/>nginx receives the handshake data]
    L1{L1 Hygiene<br/>method whitelist, ua_blacklist}
    L2{L2 Reputation<br/>cookie / bot_verified / ip /<br/>asn / geo + tags}
    L3{L3 TLS fingerprint<br/>fp_blocklist, impersonator,<br/>suspicious_ciphers, dc_browser + tags}
    L4{L4 Rate limits<br/>system + customer rules}
    L5{L5 Active verification<br/>consolidates challenge flags}
    Cache[Serving content:<br/>from cache if present<br/>otherwise from the customer origin]
    Response[Delivering the response to the client]

    Block([verdict=block → 403/429])
    Allow([verdict=allow → fastpath, skip L3-L5])
    Challenge([JS challenge page])
    ChOutcome{Did the client<br/>solve the JS task?}
    GetCookie[Receives a clearance cookie<br/>the browser retries with it]
    Stuck[Stuck on the page:<br/>a bot / no JS execution]
    Retry[A new request with the cookie<br/>re-enters the cascade:<br/>L2.1 skips L3+L5, but goes through L4]

    Start --> TLS
    TLS --> L1
    L1 -->|method not in the whitelist /<br/>UA in the blacklist| Block
    L1 -->|clean| L2
    L2 -->|bot_verified / bot_verified_pending /<br/>ip_whitelist| Allow
    L2 -->|cookie_valid:<br/>skips L3 and L5, but goes through L4| L4
    L2 -->|continue<br/>+ tags into the log| L3
    L2 -->|ip_blocklist / asn_customer /<br/>geo_blocklist| Block
    L3 -->|fingerprint in tls_fp_blocklist| Block
    L3 -->|impersonator / suspicious_ciphers /<br/>dc_browser + challenge flag| L4
    L3 -->|continue<br/>+ tls_fp:* tags into the log| L4
    L4 -->|rate limit exceeded,<br/>action=block| Block
    L4 -->|rate rule with action=challenge<br/>+ challenge flag| L5
    L4 -->|clean| L5
    L5 -->|challenge flags present<br/>+ Standard, browser| Challenge
    L5 -->|Permissive / no flags| Cache
    L5 -->|non-browser + flags present| Block

    Challenge --> ChOutcome
    ChOutcome -->|yes, JS computed the token| GetCookie
    ChOutcome -->|no, JS does not run| Stuck
    GetCookie --> Retry
    %% cookie_valid is not a full fastpath: L3 and L5 are skipped, but L4 (rate limits) applies.
    %% A full skip of L3-L5 (the Allow node) belongs to bot_verified / bot_verified_pending / ip_whitelist only.

    Allow --> Cache
    Cache --> Response
    %% Logging is not drawn here: every terminal outcome (Response / Block / Challenge)
    %% writes exactly one log record — see diagram #4 "Data flow into the log".
    %% Stuck is NOT logged separately: the original request was already logged as verdict=challenge.

    classDef terminalBlock fill:#fee,stroke:#c00,color:#900
    classDef terminalAllow fill:#efe,stroke:#0a0,color:#060
    classDef terminalChallenge fill:#ffe,stroke:#cc0,color:#660
    class Block terminalBlock
    class Stuck terminalBlock
    class Allow terminalAllow
    class GetCookie terminalAllow
    class Retry terminalAllow
    class Challenge terminalChallenge
```

> Logging is not shown on this diagram, to keep the layout readable: every terminal
> outcome (response delivery / `block` / `challenge`) writes exactly one log record. How
> the record is assembled is diagram #4, "Data flow into the log".

---

## 2. The L5 decision tree — what the final layer actually decides

A zoom into the most complex layer: how L5 decides between challenge, pass and block from
the accumulated signals.

```mermaid
flowchart TD
    Start([The request reached L5])
    AM{attack_mode<br/>enabled?}
    Flags{Challenge flags<br/>accumulated?}
    NoFlagsPass[verdict=pass<br/>→ cache/origin]
    Strict{Strictness?}
    Permissive[verdict=permissive<br/>rule=name of the last soft flag<br/>physically → cache/origin]
    Browser{Does the client look<br/>like a browser?<br/>UA + headers}
    BranchA[Branch A:<br/>serve a JS challenge<br/>verdict=challenge]
    BranchB[Branch B:<br/>verdict=block<br/>rule=non_browser_blocked]
    Recovery[The customer sees the block in the dashboard<br/>and can whitelist the IP]

    ChOutcome{Solved the<br/>JS task?}
    GetCookie[Receives a clearance cookie for 24 h<br/>the browser retries the original URL]
    Stuck[Stuck on the challenge page<br/>no JS execution, content unreachable]
    Retry[A new request with the cookie:<br/>L2.1 cookie_valid → fastpath<br/>no challenge until the cookie TTL expires]

    Start --> AM
    AM -->|yes — any request<br/>that reached L5| Browser
    AM -->|no| Flags
    Flags -->|no flags| NoFlagsPass
    Flags -->|flags present| Strict
    Strict -->|Permissive| Permissive
    Strict -->|Standard| Browser
    Browser -->|UA Mozilla/Chrome/etc.| BranchA
    Browser -->|UA curl/python/SDK| BranchB
    BranchB --> Recovery

    BranchA --> ChOutcome
    ChOutcome -->|yes| GetCookie
    ChOutcome -->|no| Stuck
    GetCookie --> Retry

    classDef terminalBlock fill:#fee,stroke:#c00,color:#900
    classDef terminalAllow fill:#efe,stroke:#0a0,color:#060
    classDef terminalChallenge fill:#ffe,stroke:#cc0,color:#660
    class BranchB terminalBlock
    class Stuck terminalBlock
    class NoFlagsPass terminalAllow
    class Permissive terminalAllow
    class Retry terminalAllow
    class BranchA terminalChallenge
    class GetCookie terminalChallenge
```

---

## 3. The "what physically happens" matrix — mode × Strictness × verdict

The same verdict out of the cascade leads to different real actions depending on the
resource's settings.

| Verdict from the cascade | `mode=shadow` *(free)* | `mode=active` + `Strictness=Permissive` | `mode=active` + `Strictness=Standard` |
| --- | --- | --- | --- |
| `block` (a blocking rule fired) | Log only | **403** (or 429 with Retry-After for a rate rule) | **403/429** |
| `allow` (an allow rule fired) | Logged, the cascade continues | **Fastpath** — skip L3-L5 | **Fastpath** |
| **a challenge flag** (soft, accumulated) | Log only (verdict=challenge under Standard / verdict=permissive under Permissive — a dry run) | `verdict=permissive`, → cache/origin | **A JS challenge** (if a browser) / **403 `non_browser_blocked`** (if not) |
| `pass` (nothing fired) | → cache/origin | → cache/origin | → cache/origin |

**A note on the fastpath:** a full fastpath (skipping L3-L5) belongs to `bot_verified` /
`bot_verified_pending` / `ip_whitelist` only. `cookie_valid` is **partial**: it skips L3
and L5 but goes through L4 (rate limits apply to the cookie holder too).
`verdict=allow, rule=cookie_valid` is only set when L4 is clean; otherwise the L4 rule
wins.

**Separately — `attack_mode` (a toggle on top of mode=active):**

- Under `attack_mode=on`, every request that reaches L5 (that is, was not cut earlier and
  not let through by an L2 allow) goes to a challenge, regardless of Strictness and flags.
- Verified search bots and IP whitelist holders take the `allow` path back at L2 and never
  reach L5, so SEO is unaffected during an attack.
- Clearance cookies under attack: those issued before the attack started do not fastpath
  (they go to L5 for a challenge); those issued during the attack skip L3/L5 but still go
  through L4.

---

## 4. Data flow into the log — what accumulates and where

Each cascade stage adds its own fields to a single final JSON log record. The finished
record leaves for the backend asynchronously.

```mermaid
flowchart LR
    L0[TLS handshake] -->|ssl_protocol, ciphers,<br/>curves, alpn, sni| Rec
    L1[L1 Hygiene] -->|rule if matched<br/>request_id, host, ip, ua,<br/>method, path| Rec
    L2[L2 Reputation] -->|rule if matched<br/>asn, geo_country<br/>+ reputation:* tags| Rec
    L3[L3 TLS fp] -->|tls_fp, tls_cipher_count,<br/>tls_alpn, tls_sni_present<br/>+ tls_fp:* tags<br/>+ challenge flags| Rec
    L4[L4 Rate limits] -->|rule if matched<br/>+ challenge flags| Rec
    L5[L5 Verify] -->|final verdict,<br/>final rule| Rec
    Cache[Serving content<br/>from cache or origin] -->|status, latency_ms| Rec

    Rec[The request's JSON log record<br/>request_id, edge_id, timestamp,<br/>host, path, method, status,<br/>ip, asn, geo_country, ua,<br/>tls_*, stage, verdict, rule,<br/>action, mode, tags, flags, staging_match]

    Rec -->|async| Backend[Antibot backend<br/>log receiver]
    Backend -->|batch| Telemetry[Telemetry sink<br/>ClickHouse]
```

**Important properties:**

- Every request produces exactly one final log record, never several.
- `verdict` and `rule` reflect the last (terminal) rule that fired, not all of them.
- `tags` accumulate — everything that fired along the way lands there.
- `flags` accumulate — every challenge flag (from soft rules) along the way lands in this
  field, separately from the terminal `rule`.
- Delivering the log record does not block the request's hot path.

---

## 5. Sequence — runtime interactions over time

Who talks to whom during one request, and what happens in the background. The key point:
the backend is **not on the hot path** — the cascade reads only local catalogs, and the
backend participates only in the background (catalog delivery, log ingestion, rDNS).

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Proxy (nginx+Lua)
    participant B as Backend
    participant O as Origin
    participant Telemetry as Telemetry

    Note over B,P: Background, off the hot path: catalog delivery (pull ≤30 s / ≤15 min)
    B-->>P: policy, blocklists, verified_bot_status, ...
    Note over P: the cascade reads catalogs ONLY from the proxy's local memory

    C->>P: HTTP request (after the TLS handshake)
    Note over P: L1→L2→L3→L4→L5 locally, with no calls to the backend
    alt verdict = allow / pass
        P->>O: proxy_pass (when not in cache)
        O-->>P: response
        P-->>C: 200 (content)
    else verdict = block
        P-->>C: 403 / 429
    else verdict = challenge (a browser)
        P-->>C: challenge page (HTML+JS, self-signed nonce)
        C->>C: solves the JS task
        C->>P: retry with the clearance cookie
        Note over P: L2.1 the cookie is valid → skip L3/L5, but L4 applies
        P->>O: proxy_pass
        O-->>P: response
        P-->>C: 200 + Set-Cookie tf_clearance
    end
    P-)B: the log record (async, it does not block the client's response)
    Note over B: the rDNS worker checks new search engine IPs,<br/>updating verified_bot_status (which reaches the proxy in the background)
    B-)Telemetry: a batch to the telemetry sink
```

---

## 6. State — the verified bot status (`bot_verification_status`)

The state machine of one IP with a search engine UA. Transitions are made by the
background rDNS worker; the TTL returns the record to "no data".

```mermaid
flowchart TD
    Start([An IP with a search engine UA<br/>seen for the first time])
    Absent[<b>Absent</b> — no record<br/>let through on credit, the backend checks rDNS]
    Verified[<b>Verified</b><br/>full L2.2 fastpath — skip L3/L4/L5<br/>TTL 1 h]
    Rejected[<b>Rejected</b><br/>no fastpath, the ordinary cascade<br/>TTL 1 h]

    Start --> Absent
    Absent -->|rDNS matched| Verified
    Absent -->|rDNS did not match| Rejected

    classDef st fill:#eef,stroke:#66a,color:#114
    class Absent,Verified,Rejected st
```

`Absent` is both "the IP's first appearance" and the state after the TTL expires: the
record is deleted and the IP is checked again on its next request. In `Absent` every
request is let through on credit (rule `bot_verified_pending`) — that is, leniently, before
the backend confirms or rejects the bot, so that SEO is not damaged.

---

## What these diagrams do NOT show

For the full picture see [vision.md](vision.md). Left out of the diagrams:

- **Background processes:** catalog delivery, the rDNS worker and log delivery appear in
  outline on the sequence diagram (#5) and the state diagram (#6); the details (the kill
  switch, pull frequencies, log buffering, persistence) are not covered — see vision.md.
- **Staged rollout for PR catalogs:** new patterns are added with `staging` status, match
  and are logged (the `staging_match` field) but do not affect the verdict. After
  calibration they are promoted to `active`.
- **The recovery loop for Branch B:** blocked non-browser requests appear in the customer's
  dashboard in a list of blocks, and the customer can whitelist the IP in one click.
- **Per-request input → output** for specific cases (Googlebot, curl, an impersonator, a
  real user) — those are test scenarios rather than diagrams.
