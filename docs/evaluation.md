# Evaluation

Two questions: how much does each SurfaceMap source contribute, and how does a passive SurfaceMap
scan compare with Amass and Subfinder in passive mode. Target: `logan-villard.fr` (owned by the
author, authorized in `scope.yaml`).

## Method

- **Per-source counts and Venn** (`surfacemap.evaluation.sources`): in-scope subdomains of the
  apex seen by each plugin. The apex and look-alikes (`notexample.com`) are excluded.
- **Benchmark** (`surfacemap.evaluation.benchmark`, driver `evaluation/run_benchmark.py`): each
  tool is run once, timed, and its raw output saved untouched in `evaluation/results/`.
  Amass runs as `amass enum -passive -d <domain>`; Subfinder as `subfinder -d <domain> -silent`
  (passive-only by design). No brute force, no zone transfer.
- **Recall is relative.** No ground truth exists on a real target, so recall is measured against
  the union of what all tools found. It ranks tools; it does not measure the true surface.
- Raw outputs, timings and errors are stored (`results.json`), so scoring changes are recomputed
  offline (`--rescore`), never by querying again. A tool that exits non-zero, times out or is
  missing is reported as failed (recall `n/a`), never as "found nothing".

Versions: Subfinder v2.17.0, Amass v5.1.3, no API keys configured for any tool.

## Results (single valid run, 2026-11-21)

| tool | subdomains | only this tool | recall vs union | time (s) |
|---|---|---|---|---|
| surfacemap | 1 (`www`) | 1 | 100 % | 18.4 |
| subfinder | 0 | 0 | 0 % | 25.9 |
| amass | 0 | 0 | 0 % | 22.2 |

Checked by hand that the two zeros are not failed invocations: both tools exit 0 and Amass
v5.1.3 accepts `-passive` (its stdout is only the session banner). They are still degraded
runs: with no API keys, Subfinder logs source errors even on a normal run (for example driftnet
and reconeer answer 401, digitorus answers 403 behind a Cloudflare challenge). A keyed setup
would likely find more, so these zeros bound what the tools do keyless, not what they can do.

A first run the same day was discarded: crt.sh answered `502` (and Wayback `503`), so every
tool was missing its main source. It is not part of the results.

## Interpretation and limits

- **This benchmark does not discriminate.** crt.sh holds no certificate for the domain and the
  other passive sources add almost nothing, so the whole surface is one host. "1 vs 0" is not
  evidence that SurfaceMap has better coverage.
- **Why SurfaceMap saw `www`.** Which plugin saw it was not recorded in this run (the driver now
  saves `surfacemap-by-source.json` for future runs). A plausible cause is that SurfaceMap
  resolves the domain's own records, which Subfinder and Amass in passive mode do not; that is
  a hypothesis, not a finding. If true, the difference is one of scope, not source quality.
- **Run time is not comparable.** One run each, network-dependent, tools started cold. Treat
  the times as order of magnitude only.
- **What would make it meaningful:** a domain with dozens of subdomains and logged
  certificates, several runs per tool, and a median. Not done: no suitable authorized target.

## Reading the graph metrics

Implemented in `surfacemap.graph.metrics` (a library module: `surfacemap scan` does not show them in the
report yet), on the undirected view of the surface graph (direction of
dependency is irrelevant to "what breaks if this goes away").

- **Degree**: number of neighbours. High degree = a hub (a provider, IP or certificate shared by
  many hosts).
- **Betweenness**: share of shortest paths passing through the node. High = the surface's
  connections are routed through it; it ranks the critical nodes.
- **Articulation point**: removing the node disconnects part of the surface. These are the single
  points of dependency (one DNS provider, one certificate, one IP) and are the ones to list first,
  ordered by betweenness, once the metrics are shown in the report.

On this target the graph is a handful of nodes, so these metrics carry no signal here; they are
only informative on a surface with shared infrastructure across many hosts.
