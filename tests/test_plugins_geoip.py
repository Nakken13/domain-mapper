from __future__ import annotations

import gzip
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from surfacemap.config import Settings
from surfacemap.models import Domain, IPAddress
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.geoip import DATASET_NAMES, GeoipPlugin

DATASET = Path(__file__).parent / "fixtures" / "ip2country.tsv"


def test_declares_an_offline_ip_plugin(scope_view: ScopeView) -> None:
    plugin = GeoipPlugin(DATASET)
    assert isinstance(plugin, Plugin)
    assert plugin.name == "geoip"
    assert plugin.consumes == frozenset({"ip"})
    assert plugin.runs_out_of_scope is False
    assert plugin.applies_to(IPAddress(address="1.2.3.4"), scope_view)
    assert "geoip" in default_registry()


def test_enabled_only_when_the_dataset_exists(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, cache_dir=tmp_path)
    assert not GeoipPlugin().enabled(settings)
    assert not GeoipPlugin(tmp_path / "missing.tsv").enabled(settings)
    shutil.copy(DATASET, tmp_path / DATASET_NAMES[0])
    assert GeoipPlugin().enabled(settings)
    assert GeoipPlugin(DATASET).enabled(Settings(_env_file=None))


@pytest.mark.parametrize(
    ("address", "country"),
    [
        ("1.2.3.4", "FR"),
        ("1.0.0.0", "AU"),
        ("8.8.8.255", "US"),
        ("2606:4700::1111", "US"),
        ("2a01:cb00::1", "FR"),
    ],
)
async def test_sets_the_country_of_an_address(
    plugin_ctx: PluginContext, address: str, country: str
) -> None:
    [observation] = await GeoipPlugin(DATASET).run(IPAddress(address=address), plugin_ctx)
    assert observation.entities == (IPAddress(address=address, country=country),)
    assert observation.relations == ()
    assert observation.provenance.source == "geoip"
    assert observation.provenance.query == f"ip2country {address}"


@pytest.mark.parametrize("address", ["1.1.1.1", "9.9.9.9", "10.0.0.1", "8.8.9.0", "::1"])
async def test_unknown_or_unrouted_addresses_give_nothing(
    plugin_ctx: PluginContext, address: str
) -> None:
    assert await GeoipPlugin(DATASET).run(IPAddress(address=address), plugin_ctx) == []


async def test_reads_a_gzipped_dataset_from_the_cache_dir(
    plugin_ctx: PluginContext, tmp_path: Path
) -> None:
    with DATASET.open("rb") as src, gzip.open(tmp_path / "ip2country.tsv.gz", "wb") as dst:
        shutil.copyfileobj(src, dst)
    ctx = replace(plugin_ctx, settings=Settings(_env_file=None, cache_dir=tmp_path))
    plugin = GeoipPlugin()
    assert plugin.enabled(ctx.settings)
    [observation] = await plugin.run(IPAddress(address="1.2.3.4"), ctx)
    assert observation.entities == (IPAddress(address="1.2.3.4", country="FR"),)


async def test_the_dataset_is_loaded_once(plugin_ctx: PluginContext, tmp_path: Path) -> None:
    copy = tmp_path / "data.tsv"
    shutil.copy(DATASET, copy)
    plugin = GeoipPlugin(copy)
    await plugin.run(IPAddress(address="1.2.3.4"), plugin_ctx)
    copy.unlink()
    [observation] = await plugin.run(IPAddress(address="8.8.8.8"), plugin_ctx)
    assert observation.entities[0] == IPAddress(address="8.8.8.8", country="US")


async def test_a_missing_dataset_gives_nothing(plugin_ctx: PluginContext, tmp_path: Path) -> None:
    plugin = GeoipPlugin(tmp_path / "missing.tsv")
    assert await plugin.run(IPAddress(address="1.2.3.4"), plugin_ctx) == []


async def test_ignores_entities_that_are_not_ips(plugin_ctx: PluginContext) -> None:
    domain = Domain(fqdn="example.com", in_scope=True)
    assert await GeoipPlugin(DATASET).run(domain, plugin_ctx) == []
