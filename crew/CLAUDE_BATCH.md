# Batching — parallel workstreams

One batch = one Claude. See § Batching in `crew/CLAUDE_CONTEXT/LIFECYCLE.md` for the rules
(impact zone, disjointness invariant between active batches).

## Unsorted

## Batch D

Zone: `src/surfacemap/risk/`, `tests/`

- ~~`risk-rules.md`~~

## Batch E

Zone: `src/surfacemap/graph/` (except `src/surfacemap/graph/builder.py`), `docker-compose.yml`, `tests/`

- `graph-export.md`

## Batch F

Zone: `src/surfacemap/report/`, `src/surfacemap/cli.py`, `tests/`

- `html-report.md`

## Batch G

Zone: `evaluation/`, `docs/`

- `evaluation.md`

## Batch H

Zone: `README.md`, `docs/`, `media/`

- `readme-docs.md`

Note: phases are sequential (see `Depends on:` in each task); only one batch is active at a time, which is why the shared `tests/` and `docs/` zones do not violate the disjointness invariant. Never start a phase while another is in `CURRENT_TASKS/`.
