# PRODUCT.md — domain-mapper

## Vision

Map the public attack surface of a domain you own or are authorized to assess,
using only passive public sources, and present it as an explainable graph
(domain → subdomains → IPs → ASN/host → certificates → technologies).

## Target user

The author (engineering-school applicant) and security practitioners auditing
their own infrastructure. Portfolio project: rigor, reproducibility and an
explicit ethical/legal frame (French Penal Code art. 323-1) matter as much as features.

## Current scope

Nothing shipped yet. Planned v0.1: passive collectors (crt.sh, DNS + SPF/DMARC,
RDAP/WHOIS, ASN/geo, Wayback CDX, optional Shodan/Censys, dorks generator),
SQLite cache, NetworkX graph (Neo4j optional), explainable risk rules,
self-contained HTML report, evaluation against Amass/Subfinder (passive) on
`logan-villard.fr`.

## Out of scope (explicitly)

- Any active technique: port scan, bruteforce, HTTP fingerprinting of the
  target (so subdomain takeover detection is DNS-only: risky CNAME provider + NXDOMAIN).
- Automated Google scraping: dorks are generated, run manually.
- Any collection of personal data (names, individual emails).
- Running on a domain not listed in `scope.yaml`.
