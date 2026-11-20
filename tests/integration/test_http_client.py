"""Mocked tests for the safe HTTP client: SSRF guards, retries, rate limiting, size limits, caching."""

import httpx
import pytest
import respx

from siren_threatwatch.connectors.http import (
    DisallowedUrlError,
    HttpFetchError,
    RateLimitedError,
    RequestBudgetExceededError,
    ResponseTooLargeError,
    SafeHttpClient,
    check_url,
)

HOSTS = {"feed.example.com", "mirror.example.com"}
URL = "https://feed.example.com/data.json"


class FakeSleep:
    def __init__(self):
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def sleeper():
    return FakeSleep()


@pytest.fixture
def client_factory(settings, sleeper):
    clients = []

    def make(**kw):
        c = SafeHttpClient(settings, HOSTS, sleep=sleeper, **kw)
        clients.append(c)
        return c

    yield make


@pytest.mark.parametrize(
    "url",
    [
        "http://feed.example.com/x",  # not https
        "https://evil.example.org/x",  # not allowlisted
        "https://169.254.169.254/latest",  # IP literal (cloud metadata)
        "https://[::1]/x",  # IPv6 literal
        "https://user:pw@feed.example.com/x",  # embedded credentials
        "https://feed.example.com:8443/x",  # non-standard port
        "file:///etc/passwd",
    ],
)
def test_check_url_blocks_ssrf_vectors(url):
    with pytest.raises(DisallowedUrlError):
        check_url(url, HOSTS)


@respx.mock
async def test_success(client_factory):
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    async with client_factory(use_cache=False) as c:
        res = await c.get(URL)
    assert res.status == 200 and res.json() == {"ok": True}


@respx.mock
async def test_redirect_to_disallowed_host_is_blocked(client_factory):
    respx.get(URL).mock(
        return_value=httpx.Response(302, headers={"Location": "https://169.254.169.254/meta"})
    )
    async with client_factory(use_cache=False) as c:
        with pytest.raises(DisallowedUrlError):
            await c.get(URL)


@respx.mock
async def test_redirect_within_allowlist_followed(client_factory):
    respx.get(URL).mock(
        return_value=httpx.Response(301, headers={"Location": "https://mirror.example.com/d.json"})
    )
    respx.get("https://mirror.example.com/d.json").mock(return_value=httpx.Response(200, json=[1]))
    async with client_factory(use_cache=False) as c:
        res = await c.get(URL)
    assert res.url == "https://mirror.example.com/d.json" and res.json() == [1]


@respx.mock
async def test_redirect_loop_bounded(client_factory):
    respx.get(URL).mock(return_value=httpx.Response(302, headers={"Location": URL}))
    async with client_factory(use_cache=False) as c:
        with pytest.raises(HttpFetchError, match="too many redirects"):
            await c.get(URL)


@respx.mock
async def test_retries_5xx_then_succeeds(client_factory, sleeper):
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(502), httpx.Response(200, json={})]
    )
    async with client_factory(use_cache=False) as c:
        res = await c.get(URL)
    assert res.status == 200 and route.call_count == 3
    assert len(sleeper.calls) == 2 and sleeper.calls[1] >= sleeper.calls[0] * 0.5  # exponential-ish backoff


@respx.mock
async def test_rate_limit_honours_retry_after_then_gives_up(client_factory, sleeper, settings):
    route = respx.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "7"}))
    async with client_factory(use_cache=False) as c:
        with pytest.raises(RateLimitedError) as exc:
            await c.get(URL)
    assert exc.value.status == 429
    assert route.call_count == settings.http_max_retries + 1
    assert sleeper.calls == [7.0] * settings.http_max_retries


@respx.mock
async def test_retry_after_is_capped(client_factory, sleeper):
    respx.get(URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "99999"}), httpx.Response(200)]
    )
    async with client_factory(use_cache=False) as c:
        await c.get(URL)
    assert sleeper.calls == [120.0]


@respx.mock
async def test_4xx_not_retried(client_factory):
    route = respx.get(URL).mock(return_value=httpx.Response(404))
    async with client_factory(use_cache=False) as c:
        with pytest.raises(HttpFetchError) as exc:
            await c.get(URL)
    assert exc.value.status == 404 and route.call_count == 1


@respx.mock
async def test_network_errors_retried_then_raised(client_factory):
    route = respx.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    async with client_factory(use_cache=False) as c:
        with pytest.raises(HttpFetchError, match="network error"):
            await c.get(URL)
    assert route.call_count == 3


@respx.mock
async def test_response_size_limit(settings, sleeper):
    settings.http_max_response_mb = 1
    respx.get(URL).mock(return_value=httpx.Response(200, content=b"x" * (1024 * 1024 + 10)))
    async with SafeHttpClient(settings, HOSTS, sleep=sleeper, use_cache=False) as c:
        with pytest.raises(ResponseTooLargeError):
            await c.get(URL)


@respx.mock
async def test_conditional_request_uses_cache_on_304(client_factory):
    route = respx.get(URL).mock(
        side_effect=[
            httpx.Response(200, json={"v": 1}, headers={"ETag": '"abc"'}),
            httpx.Response(304),
        ]
    )
    async with client_factory() as c:
        first = await c.get(URL)
        second = await c.get(URL)
    assert first.json() == second.json() == {"v": 1}
    assert second.from_cache and second.status == 304
    assert route.calls[1].request.headers["If-None-Match"] == '"abc"'


@respx.mock
async def test_request_budget(client_factory):
    respx.get(URL).mock(return_value=httpx.Response(200))
    async with client_factory(use_cache=False, max_requests=1) as c:
        await c.get(URL)
        with pytest.raises(RequestBudgetExceededError):
            await c.get(URL)


@respx.mock
async def test_user_agent_sent(client_factory):
    route = respx.get(URL).mock(return_value=httpx.Response(200))
    async with client_factory(use_cache=False) as c:
        await c.get(URL)
    assert route.calls[0].request.headers["User-Agent"].startswith("SirenThreatWatch/")
