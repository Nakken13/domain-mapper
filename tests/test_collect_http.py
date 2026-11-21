import logging
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import respx

from surfacemap import __version__
from surfacemap.collect.cache import ResponseCache
from surfacemap.collect.http import USER_AGENT, FetchError, HttpClient, PassiveViolationError
from surfacemap.collect.ratelimit import RateLimit, RateLimiter

URL = "https://crt.sh/"
SECRET = "sk-very-secret-123"  # noqa: S105 - fake key, the test checks it never leaks


class Recorder:
    def __init__(self) -> None:
        self.sleeps: list[float] = []
        self.acquired: list[str] = []

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


class CountingLimiter(RateLimiter):
    def __init__(self, rec: Recorder) -> None:
        super().__init__({}, default=RateLimit(rate=1000, burst=1000))
        self._rec = rec

    async def acquire(self, source: str) -> None:
        self._rec.acquired.append(source)
        await super().acquire(source)


@pytest.fixture
def rec() -> Recorder:
    return Recorder()


@pytest.fixture
def cache(tmp_path: Path) -> Iterator[ResponseCache]:
    with ResponseCache(tmp_path / "c.sqlite", ttl=timedelta(hours=1)) as c:
        yield c


@pytest.fixture
def client(rec: Recorder, cache: ResponseCache) -> HttpClient:
    return HttpClient(
        limiter=CountingLimiter(rec),
        cache=cache,
        is_forbidden_host=lambda host: host == "example.com" or host.endswith(".example.com"),
        max_retries=3,
        backoff=1.0,
        sleep=rec.sleep,
    )


@respx.mock
async def test_returns_body_and_sends_honest_user_agent(client: HttpClient) -> None:
    route = respx.get(URL, params={"q": "%.example.com"}).respond(200, text="[]")
    body = await client.get_text("crtsh", URL, query="%.example.com", params={"q": "%.example.com"})
    assert body == "[]"
    sent = route.calls.last.request.headers["user-agent"]
    assert sent == USER_AGENT
    assert sent.startswith(f"SurfaceMap/{__version__}")


@respx.mock
async def test_second_call_is_served_from_cache_without_spending_a_token(
    client: HttpClient, rec: Recorder
) -> None:
    route = respx.get(URL).respond(200, text="body")
    await client.get_text("crtsh", URL, query="q")
    assert await client.get_text("crtsh", URL, query="q") == "body"
    assert route.call_count == 1
    assert rec.acquired == ["crtsh"]


@respx.mock
async def test_retries_server_errors_with_exponential_backoff(
    client: HttpClient, rec: Recorder
) -> None:
    route = respx.get(URL)
    route.side_effect = [httpx.Response(503), httpx.Response(500), httpx.Response(200, text="ok")]
    assert await client.get_text("crtsh", URL, query="q") == "ok"
    assert rec.sleeps == [1.0, 2.0]
    assert rec.acquired == ["crtsh"] * 3  # every attempt spends a token


@respx.mock
async def test_honours_retry_after_on_429(client: HttpClient, rec: Recorder) -> None:
    route = respx.get(URL)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(200, text="ok"),
    ]
    assert await client.get_text("crtsh", URL, query="q") == "ok"
    assert rec.sleeps == [7.0]


@respx.mock
async def test_retry_after_is_capped(client: HttpClient, rec: Recorder) -> None:
    route = respx.get(URL)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "99999"}),
        httpx.Response(200, text="ok"),
    ]
    await client.get_text("crtsh", URL, query="q")
    assert rec.sleeps == [60.0]


@respx.mock
async def test_retries_transport_errors(client: HttpClient) -> None:
    route = respx.get(URL)
    route.side_effect = [httpx.ConnectError("boom"), httpx.Response(200, text="ok")]
    assert await client.get_text("crtsh", URL, query="q") == "ok"


@respx.mock
async def test_gives_up_after_max_retries_and_caches_nothing(
    client: HttpClient, cache: ResponseCache
) -> None:
    route = respx.get(URL).respond(503)
    with pytest.raises(FetchError, match="crtsh: HTTP 503"):
        await client.get_text("crtsh", URL, query="q")
    assert route.call_count == 4  # first try + 3 retries
    assert cache.get("crtsh", "q") is None


@respx.mock
async def test_client_errors_are_not_retried(client: HttpClient) -> None:
    route = respx.get(URL).respond(404)
    with pytest.raises(FetchError, match="HTTP 404"):
        await client.get_text("crtsh", URL, query="q")
    assert route.call_count == 1


@respx.mock
async def test_redirects_are_not_followed(client: HttpClient) -> None:
    respx.get(URL).respond(302, headers={"Location": "https://www.example.com/"})
    target = respx.get("https://www.example.com/").respond(200)
    with pytest.raises(FetchError, match="HTTP 302"):
        await client.get_text("crtsh", URL, query="q")
    assert not target.called


@respx.mock
@pytest.mark.parametrize("url", ["https://example.com/x", "https://WWW.Example.com./"])
async def test_requests_to_the_target_are_refused(client: HttpClient, url: str) -> None:
    route = respx.get(url__regex=r".*").respond(200)
    with pytest.raises(PassiveViolationError):
        await client.get_text("crtsh", url, query="q")
    assert not route.called


@respx.mock
async def test_secret_params_never_leak(
    client: HttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    route = respx.get("https://api.shodan.io/dns/domain/example.org")
    leaky = httpx.ConnectError(f"failed for ?key={SECRET}")
    route.side_effect = [leaky, httpx.Response(500), httpx.Response(503), leaky]
    client_errors = []
    try:
        await client.get_text(
            "shodan",
            "https://api.shodan.io/dns/domain/example.org",
            query="example.org",
            secret_params={"key": SECRET},
        )
    except FetchError as exc:
        client_errors.append(exc)
    assert route.calls[0].request.url.params["key"] == SECRET  # it was really sent
    (error,) = client_errors
    assert SECRET not in repr(error)
    assert error.__cause__ is None
    assert error.__suppress_context__
    assert SECRET not in caplog.text


@respx.mock
async def test_secret_params_are_not_part_of_the_cache_key(
    client: HttpClient, tmp_path: Path
) -> None:
    respx.get("https://api.shodan.io/x").respond(200, text="ok")
    await client.get_text(
        "shodan", "https://api.shodan.io/x", query="example.org", secret_params={"key": SECRET}
    )
    assert SECRET.encode() not in (tmp_path / "c.sqlite").read_bytes()
