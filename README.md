# SurfaceMap

Passive attack-surface mapping of a domain you own or are authorized to assess, rendered as a graph.

> Use only on domains listed in your `scope.yaml` (see [Ethics & legal](#ethics--legal)).

## Quick start

```bash
py -3.11 -m venv .venv                      # Linux/macOS: python3.11 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
cp scope.example.yaml scope.yaml            # list the domains you are authorized to assess
.venv/Scripts/surfacemap scope check example.com
.venv/Scripts/surfacemap scan example.com -o example.com-report.html
```

The report is a single self-contained HTML file (Cytoscape.js inlined): open it offline.

## Architecture

```mermaid
flowchart LR
    scope[("scope.yaml")] --> guard["scope.py<br/>scope guard"]
    guard --> engine["collect/engine<br/>async, rate-limited, cached"]
    engine --> plugins["plugins/<br/>one passive source per module"]
    plugins -->|Observation| priv["privacy.py<br/>personal-data filters"]
    priv --> builder["graph/builder<br/>merge into SurfaceGraph"]
    builder --> metrics["graph/metrics<br/>degree, betweenness,<br/>articulation points"]
    builder --> rules["risk/<br/>one explainable rule per file"]
    metrics --> report["report/<br/>self-contained HTML"]
    rules -->|Finding| report
    builder -.->|optional| neo4j[("Neo4j export")]
```

Plugins never touch the graph: they return `Observation` objects and only `graph/builder.py`
merges them. Every entry point goes through the scope guard first, and everything a plugin emits
passes through `privacy.py` before entering the graph. Details: [docs/architecture.md](docs/architecture.md).

## Sources and their limits

Passive means third-party public data only; nothing is ever sent to the target.

| Source | Gives | Main limit |
|---|---|---|
| crt.sh (Certificate Transparency) | subdomains, certificates | only names with a logged certificate; wildcards hide hosts; frequent 5xx |
| DNS (system resolver) | A/AAAA, CNAME, MX, NS, TXT, DMARC | resolves known names, does not discover |
| RDAP / WHOIS fallback | registered name servers | contacts discarded; WHOIS only when the TLD has no RDAP |
| Team Cymru, iptoasn (local) | ASN, holder, country | country level; a CDN IP says nothing about the origin |
| Wayback CDX | archived paths | only what the Archive crawled; query strings stripped |
| Shodan (optional, key) | ports/banners already scanned | off without a key; data stays Shodan's |
| Google dorks | links to open by hand | never run automatically |

Coverage is a lower bound: hosts with no certificate, archive entry or reachable DNS name are
invisible. Full table and "what passive cannot see": [docs/sources.md](docs/sources.md).

## Methodology

1. **Scope check**: the domain must be in `scope.yaml`, else the run is refused before any network object exists.
2. **Collect**: an async engine fans out over the plugins, behind one HTTP client (per-source rate limit,
   SQLite cache, redirects never followed, never a request to the target).
3. **Filter**: `privacy.py` strips personal data before anything is cached or merged.
4. **Merge**: observations carry their provenance into one graph, so each claim is traceable to a source.
5. **Analyse**: graph metrics (degree, betweenness, articulation points = single points of dependency) and
   explainable risk rules (`rationale`, `evidence`, `remediation`; takeover is a DNS-only lead).
6. **Evaluate**: compared with Amass and Subfinder (passive) with recall relative to the union of tools and
   failed runs reported as `n/a`. On the one tested domain the surface is a single host, so the benchmark
   does not discriminate: see [docs/evaluation.md](docs/evaluation.md).

More: [docs/methodology.md](docs/methodology.md).
