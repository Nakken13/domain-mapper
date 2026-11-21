"""Async HTTP client for third-party sources: the single choke point of outgoing traffic.

Guarantees enforced here rather than trusted to each plugin:

* **Passive only**: a request whose host is the target (any host covered by the scope)
  or an IP literal (every allowed third party is reached by name) is refused before
  anything is sent, and redirects are never followed, so a third party cannot bounce
  us onto the target.
* **Honest identity**: a fixed `SurfaceMap/<version>` User-Agent, no browser spoofing.
* **Rate limits**: every attempt, retries included, spends a token of its source.
* **Cache**: keyed by the logical query + URL + non-secret params; a hit spends no
  token and sends nothing. Only 2xx bodies are stored, after the caller's `redact`
  (personal data in RDAP vCards, certificate emails…) so the raw body never hits disk.
* **Secrets**: `secret_params` (e.g. an API key the provider wants in the URL) are added
  to the request only. They never reach the cache key, an error message, a chained
  exception or the httpx request log (silenced below INFO level, where it prints URLs).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
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
    return min(float(raw), MAX_RETRY_AFTER) if raw.isascii() and raw.isdigit() else None


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
        redact: Callable[[str], str] | None = None,
    ) -> str:
        """GET `url` for plugin `source`.

        `query` is the logical query (as in `Provenance.query`). The cache key is that
        query plus the URL and the non-secret params, so pages of one query never collide.
        `redact` rewrites a 2xx body before it is cached and returned; if it raises, nothing
        is cached.
        """
        try:
            host = _host_of(url)
        except httpx.InvalidURL:
            raise FetchError(f"{source}: InvalidURL") from None
        if _is_ip_literal(host) or self._is_forbidden_host(host):
            raise PassiveViolationError(f"{source}: refused to contact {host} directly")

        cache_key = json.dumps([query, url, sorted((params or {}).items())])
        cached = self._cache.get(source, cache_key)
        if cached is not None:
            return cached

        all_params = {**(params or {}), **(secret_params or {})}
        attempt = 0
        while True:
            await self._limiter.acquire(source)
            delay: float | None = None
            try:
                response = await self._client.get(url, params=all_params, headers=headers)
            except httpx.TransportError as exc:
                failure, retryable = type(exc).__name__, True
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                failure, retryable = type(exc).__name__, False
            else:
                if response.is_success:
                    body = redact(response.text) if redact else response.text
                    self._cache.set(source, cache_key, body)
                    return body
                failure = f"HTTP {response.status_code}"
                retryable = response.status_code in _RETRYABLE
                delay = _retry_after(response)
            if not retryable or attempt == self._max_retries:
                # Raised outside any `except`: no httpx error (and its URL) in __context__.
                raise FetchError(f"{source}: {failure}")
            logger.warning("%s: %s, retrying", source, failure)
            await self._sleep(delay if delay is not None else self._backoff * 2**attempt)
            attempt += 1


def _host_of(url: str) -> str:
    # raw_host is the ASCII (punycode) name actually sent, the form scope entries use.
    return httpx.URL(url).raw_host.decode("ascii").lower().removesuffix(".")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True
