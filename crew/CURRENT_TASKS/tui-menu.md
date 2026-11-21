# tui-menu

Interactive numbered-menu TUI for SurfaceMap, modelled on the sibling project `A:/projets_perso/dorkint` (`src/dorkint/tui/`, `visual.py`, `banner.py`): braille banner, Rich rendering, injectable I/O so the flow is testable offline. Not Textual: same stack and spirit as dorkint.

Why: the CLI needs flags; a menu makes the demo and the interview defense easier (scope check, scan, open report) without remembering commands.

Branch: `feat/tui-menu`
Batch: J
Zone: `src/surfacemap/tui/`, `src/surfacemap/banner.py`, `tests/`, `pyproject.toml`, `README.md`
Depends on: none

Rules: Conventional Commits, one atomic commit per action below, passive only, scope first (the TUI must call the same scope check as `scan`; no bypass), TDD.

## Actions

- [ ] Add `rich` dependency and the `surfacemap-tool` entry point (`surfacemap.tui:main`) in `pyproject.toml`
- [ ] `banner.py`: braille banner (the one in the README) + `SurfaceMap` title, version, centered on the terminal (test: width/centering)
- [ ] `tui/prompts.py`: `choose` / `ask` with injectable `input_fn` / `print_fn` (tests: invalid choice, `q`, required value)
- [ ] `tui/render.py`: Rich menu / info / result panels, `color=False` fallback (tests on plain output)
- [ ] `tui/flow.py`: main menu = scope check, scan, open last report, about, quit; scan asks domain + output path, calls the existing scope check first and shows REFUSED for an out-of-scope domain without querying anything (tests with fake scan fn, offline)
- [ ] `tui/__init__.py`: `main()` refusing a non-TTY stdin, ANSI enable on Windows, clean exit on Ctrl-C (test)
- [ ] README: a "Menu (TUI)" section; verify by running `surfacemap-tool` for real (scope check on an in-scope and an out-of-scope domain)
- [ ] Review + merge branch into main
