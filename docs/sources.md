# Sources and their limits

Every source is third-party and public. SurfaceMap never sends a request to the target or its
subdomains; the only traffic it generates is listed below (each plugin states it in its module docstring).

| Source | Plugin | Traffic | Yields | Key limits |
|---|---|---|---|---|
| crt.sh (Certificate Transparency) | `crtsh` | HTTPS to `crt.sh` | subdomains, certificates | Only names that got a publicly logged certificate. Wildcards hide real hosts. The service is rate-limited and often answers 5xx: a failed query is reported, not read as "nothing found". Co-tenant names outside the queried root are dropped. |
| DNS | `dns_records` | queries to the system resolver | A/AAAA, CNAME chain, MX, NS, TXT, `_dmarc` | Sees only names already known: it resolves, it does not discover. Results depend on the resolver (split-horizon, caching). The only plugin that runs on out-of-scope names, and there it asks A/AAAA only. |
| RDAP | `rdap` | HTTPS to IANA bootstrap + the TLD registry | registered name servers | Registrant data is personal data and is discarded (allow-list). Not every TLD has an RDAP server. |
| WHOIS | `whois` | TCP/43 to third-party servers | name servers (fallback) | Only used when the TLD has no RDAP. Text is never stored, only parsed name servers. Registries discourage automated WHOIS: rare, cached, rate-limited. |
| Team Cymru IP-to-ASN | `asn` | DNS TXT under `asn.cymru.com` | ASN and holder of an IP | In-scope, globally routable addresses only. Heavy users are asked to use the bulk interface. Holder names are organisations, not people. |
| iptoasn `ip2country` | `geoip` | none (local file) | country of an IP | The user downloads the dataset. Country level only; a CDN IP is geolocated to the CDN, not the origin. |
| Wayback Machine CDX | `wayback` | HTTPS to `web.archive.org` | archived paths | Query strings, fragments and session parameters are stripped (tokens, emails). Only what the Archive crawled. The service is sometimes unavailable (503). |
| Shodan (optional) | `shodan` | HTTPS to `api.shodan.io` | open ports/banners already scanned by Shodan | Off without an API key. Data is Shodan's: credit it, stay within your plan's terms. Banners are reduced before caching (they can carry personal data). |
| Google dorks | `dorks` | none | search links for the user | Never executed: Google forbids automated queries. Output does not enter the graph. SPF/DMARC parsing (`mailauth`) is also offline: pure functions over collected TXT. |

## What passive cannot see

- Hosts with no certificate, no archived page and no DNS record reachable from the known names.
- Anything behind a wildcard record or certificate.
- Live service state: a name in DNS or CT may be long dead, and an open port is Shodan's past
  observation, not a fresh check.
- Subdomain takeover is detected from DNS only (risky CNAME provider + NXDOMAIN); it is never
  confirmed by requesting the host. Treat it as a lead.

Coverage is therefore a lower bound, and the [evaluation](evaluation.md) shows how thin that bound
can be on a small domain.
