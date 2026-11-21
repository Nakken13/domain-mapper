"""Per-source subdomain counts and Venn regions: how much each plugin contributes.

Pure functions over a built graph, no I/O and no plotting dependency. The Venn diagram is
drawn from `venn_regions`, so the numbers shown are the numbers computed here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from xml.sax.saxutils import escape

from domain_mapper.graph.builder import SurfaceGraph
from domain_mapper.models import Domain

SourceSets = Mapping[str, frozenset[str]]


def is_subdomain(fqdn: str, apex: str) -> bool:
    """True for a strict subdomain of `apex`.

    The apex itself and look-alikes such as `notexample.com` are excluded: the suffix test
    includes the leading dot. The one definition shared by the counts and the benchmark.
    """
    return fqdn.endswith(f".{apex}")


def subdomains_by_source(graph: SurfaceGraph, apex: str) -> dict[str, frozenset[str]]:
    """Map each plugin to the in-scope subdomains of `apex` it saw.

    Sources that saw no subdomain are absent from the result.
    """
    found: dict[str, set[str]] = defaultdict(set)
    for node in graph.nodes.values():
        entity = node.entity
        if not isinstance(entity, Domain) or not entity.in_scope:
            continue
        if not is_subdomain(entity.fqdn, apex):
            continue
        for source in node.sources:
            found[source].add(entity.fqdn)
    return {source: frozenset(fqdns) for source, fqdns in found.items()}


def source_counts(sets: SourceSets) -> dict[str, int]:
    """Subdomain count per source, biggest first, ties broken by name (stable output)."""
    ordered = sorted(sets.items(), key=lambda item: (-len(item[1]), item[0]))
    return {source: len(fqdns) for source, fqdns in ordered}


def venn_regions(sets: SourceSets) -> dict[frozenset[str], int]:
    """Count subdomains per exact combination of sources that saw them.

    Regions are exclusive (a subdomain lives in exactly one), so they sum to the union.
    """
    seen_by: dict[str, set[str]] = defaultdict(set)
    for source, fqdns in sets.items():
        for fqdn in fqdns:
            seen_by[fqdn].add(source)
    regions: dict[frozenset[str], int] = defaultdict(int)
    for sources in seen_by.values():
        regions[frozenset(sources)] += 1
    return dict(regions)


# Venn layout: three circles of radius _R, and where each exact region's count is written.
# Region keys are indexes into the (up to three) drawn sources, in count order.
_R = 85
_CENTERS = ((130, 120), (210, 120), (170, 190))
_COLORS = ("#2a6fdb", "#d9822b", "#2e9e6b")
_LABELS: dict[frozenset[int], tuple[int, int]] = {
    frozenset({0}): (95, 100),
    frozenset({1}): (245, 100),
    frozenset({2}): (170, 235),
    frozenset({0, 1}): (170, 90),
    frozenset({0, 2}): (128, 170),
    frozenset({1, 2}): (212, 170),
    frozenset({0, 1, 2}): (170, 140),
}
_MAX_CIRCLES = 3
_WIDTH, _HEIGHT = 340, 340


def render_venn_svg(sets: SourceSets) -> str:
    """Draw a Venn diagram of the (at most) three biggest sources, as a standalone SVG.

    Counts are the exclusive regions of the drawn sources only. Sources beyond the third are
    named in the caption instead of being silently dropped. Every source name is escaped.
    """
    ordered = list(source_counts(sets))
    shown, hidden = ordered[:_MAX_CIRCLES], ordered[_MAX_CIRCLES:]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_WIDTH} {_HEIGHT}" '
        'role="img" aria-label="Subdomains found per source">'
    ]
    for index, source in enumerate(shown):
        cx, cy = _CENTERS[index]
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{_R}" fill="{_COLORS[index]}" '
            f'fill-opacity="0.25" stroke="{_COLORS[index]}" stroke-width="2"/>'
        )
        # Source names sit outside the overlaps, at the outer edge of each circle.
        name_x, name_y = ((20, 20), (320, 20), (170, 300))[index]
        anchor = ("start", "end", "middle")[index]
        parts.append(
            f'<text x="{name_x}" y="{name_y}" text-anchor="{anchor}" font-size="14" '
            f'font-weight="600" fill="{_COLORS[index]}">{escape(source)} '
            f"({len(sets[source])})</text>"
        )
    shown_sets = {source: sets[source] for source in shown}
    by_index = {source: index for index, source in enumerate(shown)}
    for sources, count in venn_regions(shown_sets).items():
        x, y = _LABELS[frozenset(by_index[source] for source in sources)]
        parts.append(
            f'<text x="{x}" y="{y}" text-anchor="middle" font-size="16" '
            f'fill="currentColor">{count}</text>'
        )
    if not shown:
        parts.append(
            f'<text x="{_WIDTH // 2}" y="{_HEIGHT // 2}" text-anchor="middle" '
            'font-size="14" fill="currentColor">no subdomain found</text>'
        )
    if hidden:
        names = ", ".join(escape(source) for source in hidden)
        parts.append(
            f'<text x="{_WIDTH // 2}" y="{_HEIGHT - 4}" text-anchor="middle" font-size="11" '
            f'fill="currentColor">not shown: {names}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)
