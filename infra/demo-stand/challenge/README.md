# challenge/ — HTML+JS challenge page asset (C2)

A static asset the edge serves on `verdict=challenge` (Phase 4, Step 5.2,
"Branch A" in [vision.md](../../../docs/product/vision.md)). On the demo it is delivered
by a file mount (Channel A on the demo = bind mount, see
[docker-compose.demo.yml](../docker-compose.demo.yml)); in production this will be
Puppet (`modules/nginx/files/lua/nginx2/`), but the contract — "one file, read
once at init, update = `openresty -s reload`" — is the same.

## The files

- `page.html` — the only template. The edge fills in these placeholders at render time:
  - `{{NONCE}}` — base64url payload + HMAC, issued by `challenge.issue_nonce(host)`
    (see [../lua/challenge.lua](../lua/challenge.lua)). Signed with the same HMAC
    secret as the clearance cookie ([C1](../lua/challenge_secret.lua));
    carries `host` + `expiry` (TTL 60 s). Any proxy in the pool validates it without
    shared state.
  - `{{EXPIRY}}` — the unix timestamp of the nonce expiry (for debugging in DevTools).

  The cascade version in the template is a set of literals (not placeholders): the version the
  template is compatible with is baked into `<meta name="cascade-version">`, an HTML comment
  and `data-cascade-version`.
  `init_by_lua` compares the meta tag against [../CASCADE_VERSION](../CASCADE_VERSION) and
  fails the nginx start on a mismatch.

## The contract with C5 (the verify endpoint)

The JS POSTs this body to `/__challenge/verify`:

```json
{
  "nonce": "<base64url-payload>.<base64url-hmac>",
  "token": "<hex sha256(nonce + JS_SECRET)>",
  "cascade_version": "0.1.0",
  "not_a_robot": false,
  "fp": {
    "ua": "...",
    "languages": ["ru-RU", "en"],
    "screen": {"width": 1920, "height": 1080, "depth": 24},
    "timezone": "Europe/Moscow",
    "hwc": 8,
    "platform": "MacIntel"
  }
}
```

The server (C5) must:
1. Decode the nonce and check the HMAC through `challenge_secret.get()`.
2. Check that `expiry > now` (single use through the TTL — replay protection per vision §5.2).
3. Recompute `sha256(nonce + JS_SECRET)` and compare it with `token`. `JS_SECRET`
   is a constant in [`page.html`](page.html); changing it requires a `CASCADE_VERSION` bump.
4. Compare `cascade_version` with the server-side one and reject mismatches
   (protection against a stale browser cache holding an old page).
5. Write `fp` into BAC_LOG (the challenge-pass event, for analytics) and issue the
   clearance cookie with the same HMAC secret.

## Bump `CASCADE_VERSION`

A bump is mandatory in any PR that changes:
- the nonce payload format (fields, encoding),
- `JS_SECRET`,
- the expected fields of the verify POST,
- the set of fingerprint fields,
- the path of the verify endpoint.

A bump = one line in [../CASCADE_VERSION](../CASCADE_VERSION) plus replacing every
version literal in [`page.html`](page.html) (the HTML comment + `<meta>` +
`data-cascade-version`). `init_by_lua` fails the start if the meta tag and
`CASCADE_VERSION` have drifted apart — that is the safety net for a forgotten bump.
