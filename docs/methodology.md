# Methodology

## Collection

1. **Scope check.** The target must be listed in `scope.yaml` and not expired. Otherwise the run is
   refused before any object that could touch the network exists.
2. **Fan-out.** The async engine calls each plugin once per entity whose kind it consumes, starting
   from the scope root. Newly seen names feed the next round. Every outbound call goes through one
   HTTP client: per-source token bucket (default 1 request/s), SQLite response cache, no redirects followed, no request to the
   target or its subdomains (a `PassiveViolationError` is raised instead).
3. **Privacy filter.** Plugin output is reduced by `privacy.py` (allow-lists for registration data,
   query strings stripped, no names or emails) before it enters the graph or the cache.
4. **Merge.** Plugins return `Observation`s carrying their provenance. `graph/builder.py` merges them
   into one `SurfaceGraph`: domain → IPs → ASN, certificates, archived URLs, technologies. Each
   node and edge keeps which source saw it, so every claim in the report is traceable.

## Analysis

- **Graph metrics** (`graph/metrics.py`, implemented but **not yet shown in the report**), on the
  undirected view: degree (hubs), betweenness (where connections are routed), articulation points
  (removing the node disconnects part of the surface: single points of dependency such as one DNS
  provider or one certificate).
- **Risk rules**: pure functions of the graph and a pinned date, one file each: `certificates`,
  `email-auth` (SPF/DMARC), `exposed-environments`, `hosting-sprawl`, `takeover` (DNS-only). Each
  finding has a severity, a `rationale`, the `evidence` nodes, and a `remediation`. Takeover is a lead
  inferred from a risky CNAME provider plus NXDOMAIN, never confirmed by requesting the host.

## Evaluation

domain-mapper is compared with Amass and Subfinder in passive mode on a domain owned by the author:
per-source counts and Venn, then one timed run per tool with raw output stored untouched.
Recall is **relative to the union** of all tools (no ground truth exists), failed runs are `n/a`
not zero, and scoring is recomputed offline from stored outputs. The one valid run found a single
host, so it does not discriminate between tools: see [evaluation.md](evaluation.md) for the
numbers and why they must not be over-read.

## Reproducibility

Tests run fully offline (respx mocks, recorded fixtures), coverage gate 80 %, rules take a pinned
date. Same graph + same date = same findings.
