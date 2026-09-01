# Design specs — layers that are not built

Everything in this directory is a specification for work that does **not exist in
the code**. It is design, not documentation of behaviour.

For what the system actually does, see [`docs/product/`](../product/) and the
rest of `docs/`. For the shape of the plan, see [ROADMAP.md](../../ROADMAP.md).

| Layer | Files | State |
|---|---|---|
| WAF — request inspection, rule sets, virtual patching | `waf-*` | designed, not built |
| DDoS — L7 rate-based, connection and protocol, volumetrics | `ddos-*` | designed, not built |
| API and account protection — credential stuffing, enumeration, scraping | `api-*` | designed, not built |
| Analytics core — scoring, evidence, the blocklist lifecycle | `analytics-*` | partly built: the scoring and promotion tooling exists in `scripts/`, the rest is design |
| Product frame — which adjacent categories are worth taking on | `product-scope.md` | direction, not a commitment |

Each family follows the same four-part shape: the spec itself, a rules
reference, an entities reference, and config templates.
