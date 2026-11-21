# html-report

Phase 6: self-contained HTML report and the end-to-end `surfacemap scan` command.

Branch: `feat/html-report`
Batch: F
Zone: `src/surfacemap/report/`, `src/surfacemap/cli.py`, `tests/`
Depends on: data-model.md, collection-engine.md, passive-plugins.md, risk-rules.md, graph-export.md (phases 1-5)

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [x] feat(report): self-contained Jinja2 template
- [ ] feat(report): interactive graph with Cytoscape.js inlined (MIT, no CDN; keep licence notice)
- [ ] feat(report): findings table by severity
- [ ] feat(cli): `surfacemap scan` command end-to-end (scope.require first)
- [ ] test(report): visual check at desktop + mobile width (human validation; PAUSED/ if needed)
- [ ] Review + merge branch into main
