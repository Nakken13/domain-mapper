"""Async HTTP client for third-party sources: the single choke point of outgoing traffic.

Guarantees enforced here rather than trusted to each plugin:

* **Passive only**: a request whose host is the target (any host covered by the scope)
  is refused before anything is sent, and redirects are never followed, so a third
  party cannot bounce us onto the target.
* **Honest identity**: a fixed `SurfaceMap/<version>` User-Agent, no browser spoofing.
* **Rate limits**: every attempt, retries included, spends a token of its source.
* **Cache**: keyed by the plugin's logical query; a hit spends no token and sends nothing.
  Only 2xx bodies are stored.
* **Secrets**: `secret_params` (e.g. an API key the provider wants in the URL) are added
  to the request only. They never reach the cache key, an error message, a chained
  exception or the httpx request log (silenced below INFO level, where it prints URLs).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping

import httpx

from surfacemap import __version__
from surfacemap.collect.cache import ResponseCache
from surfacemap.collect.ratelimit import RateLimiter, Sleep

USER_AGENT = f"SurfaceMap/{__version__} (passive attack-surface mapper; read-only OSINT)"
MAX_RETRY_AFTER = 60.0
_RETRYABLE = frozenset({429, 500, 502, 503, 504})

logger = logging.getLogger(__name__)
# httpx logs every request URL at INFO, query string (and so API keys) included.
for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)


class FetchError(Exception):
    """A source could not be fetched. The message never contains the URL."""


class PassiveViolationError(PermissionError):
    """A request would have reached the assessed target itself."""


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After", "")
    return min(float(raw), MAX_RETRY_AFTER) if raw.isdigit() else None


class HttpClient:
    def __init__(
        self,
        limiter: RateLimiter,
        cache: ResponseCache,
        is_forbidden_host: Callable[[str], bool],
        *,
        max_retries: int = 3,
        backoff: float = 1.0,
        timeout: float = 30.0,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._limiter = limiter
        self._cache = cache
        self._is_forbidden_host = is_forbidden_host
        self._max_retries = max_retries
        self._backoff = backoff
        self._sleep = sleep
        self._client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=timeout
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_text(
        self,
        source: str,
        url: str,
        *,
        query: str,
        params: Mapping[str, str] | None = None,
        secret_params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        """GET `url` for plugin `source`; `query` is the logical cache key (no secret)."""
        # raw_host is the ASCII (punycode) name actually sent, the form scope entries use.
        host = httpx.URL(url).raw_host.decode("ascii").lower().removesuffix(".")
        if self._is_forbidden_host(host):
            raise PassiveViolationError(f"{source}: refused to contact the target host {host}")

        cached = self._cache.get(source, query)
        if cached is not None:
            return cached

        all_params = {**(params or {}), **(secret_params or {})}
        for attempt in range(self._max_retries + 1):
            await self._limiter.acquire(source)
            last_attempt = attempt == self._max_retries
            try:
                response = await self._client.get(url, params=all_params, headers=headers)
            except httpx.TransportError as exc:
                # Message dropped and chain suppressed: httpx errors may embed the URL.
                if last_attempt:
                    raise FetchError(f"{source}: {type(exc).__name__}") from None
                logger.warning("%s: %s, retrying", source, type(exc).__name__)
                await self._sleep(self._backoff * 2**attempt)
                continue

            if response.is_success:
                self._cache.set(source, query, response.text)
                return response.text
            if response.status_code not in _RETRYABLE or last_attempt:
                raise FetchError(f"{source}: HTTP {response.status_code}")
            logger.warning("%s: HTTP %d, retrying", source, response.status_code)
            delay = _retry_after(response)
            await self._sleep(delay if delay is not None else self._backoff * 2**attempt)
        raise AssertionError("unreachable")  # pragma: no cover
