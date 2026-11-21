"""Country of an IP address from an offline dataset.

Traffic: none. Lookups run against a local copy of the iptoasn.com `ip2country` dataset
(TSV lines `range_start<TAB>range_end<TAB>country`, IPv4 and IPv6, optionally gzipped),
which the user downloads themselves. Mirrors label that dataset public domain (PDDL);
check iptoasn.com before redistributing it, and credit it in the report anyway. MaxMind
GeoLite2 is deliberately not supported: its EULA needs an account and forbids
redistribution.

The dataset path is given to the constructor, or defaults to `ip2country.tsv` (or
`.tsv.gz`) in the settings' cache directory; without it the plugin is disabled. This
plugin is the only source of `IPAddress.country`.
"""

from __future__ import annotations

import asyncio
import bisect
import gzip
import ipaddress
import logging
from dataclasses import dataclass, field
from pathlib import Path

from surfacemap.config import Settings
from surfacemap.models import Entity, IPAddress, Observation
from surfacemap.plugins._util import country_code
from surfacemap.plugins.base import PluginBase, PluginContext

DATASET_NAMES = ("ip2country.tsv", "ip2country.tsv.gz")
logger = logging.getLogger(__name__)


@dataclass
class _Ranges:
    """Sorted, non-overlapping address ranges of one IP version."""

    starts: list[int] = field(default_factory=list)
    ends: list[int] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)

    def find(self, address: int) -> str | None:
        index = bisect.bisect_right(self.starts, address) - 1
        if index >= 0 and address <= self.ends[index]:
            return self.countries[index]
        return None


def _load(path: Path) -> dict[int, _Ranges]:
    opener = gzip.open if path.suffix == ".gz" else open
    rows: dict[int, list[tuple[int, int, str]]] = {4: [], 6: []}
    with opener(path, "rt", encoding="utf-8") as lines:
        for line in lines:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or country_code(parts[2]) is None:
                continue  # header, unrouted range ("None") or malformed line
            try:
                start, end = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            if start.version == end.version:
                rows[start.version].append((int(start), int(end), parts[2].upper()))
    ranges = {}
    for version, entries in rows.items():
        entries.sort()
        ranges[version] = _Ranges(
            [s for s, _, _ in entries], [e for _, e, _ in entries], [c for _, _, c in entries]
        )
    return ranges


class GeoipPlugin(PluginBase):
    name = "geoip"
    consumes = frozenset({"ip"})
    runs_out_of_scope = False

    def __init__(self, dataset: Path | None = None) -> None:
        self.dataset = dataset
        self._loaded: dict[Path, dict[int, _Ranges]] = {}
        self._load_lock = asyncio.Lock()  # concurrent first runs must parse the file once

    def _path(self, settings: Settings) -> Path | None:
        candidates = (
            [self.dataset] if self.dataset else [settings.cache_dir / n for n in DATASET_NAMES]
        )
        return next((path for path in candidates if path.is_file()), None)

    def enabled(self, settings: Settings) -> bool:
        return self._path(settings) is not None

    async def _ranges(self, settings: Settings) -> dict[int, _Ranges] | None:
        """The parsed dataset, loaded on first use and kept for the run."""
        if self.dataset in self._loaded:  # explicit path: kept even if the file goes away
            return self._loaded[self.dataset]
        path = self._path(settings)
        if path is None:
            return None
        async with self._load_lock:
            if path not in self._loaded:
                self._loaded[path] = await asyncio.to_thread(_load, path)
        return self._loaded[path]

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        if not isinstance(entity, IPAddress):
            return []
        ranges = await self._ranges(ctx.settings)
        if ranges is None:
            return []
        address = ipaddress.ip_address(entity.address)
        country = ranges[address.version].find(int(address))
        if country is None:
            return []
        return [
            Observation(
                provenance=self.provenance(f"ip2country {entity.address}"),
                entities=(IPAddress(address=entity.address, country=country),),
            )
        ]
