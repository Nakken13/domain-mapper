# readme-badges

README badges (CI, coverage, licence, python), split from `readme-docs.md`.

External dependency: the GitHub remote is not created yet; the CI and coverage badges need it. Do not start before it exists.

Branch: `docs/readme-badges`
Batch: I
Zone: `README.md`
Depends on: readme-docs.md (closed), GitHub remote created

Rules: Conventional Commits, one atomic commit per action below, passive only, scope first.

## Actions

- [ ] docs(readme): badges (CI via `.github/workflows/ci.yml`, coverage, licence, python)
- [ ] Verify each badge URL resolves once the remote exists (the CI badge must go green)
- [ ] Review + merge branch into main
