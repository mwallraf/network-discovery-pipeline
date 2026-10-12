"""Minimal Nautobot GraphQL client for 'ndp fetch'. The token comes from the environment."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping

# the same queries as the n8n workflow (network-discovery-config/tools/build_workflows.py)
DEVICE_QUERY = "query ($roles: [String]) {\n  devices(role: $roles) {\n    name\n    role { name }\n    primary_ip4 { address }\n  }\n}"
PREFIX_QUERY = "query ($roles: [String]) {\n  prefixes(role: $roles) {\n    prefix\n    role { name }\n  }\n}"

Post = Callable[[str, bytes, dict[str, str]], bytes]


class NautobotError(Exception):
    """Nautobot could not be queried or gave an unusable answer."""


def token_from_env(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    token = env.get("NAUTOBOT_TOKEN", "").strip()
    if not token:
        raise NautobotError("NAUTOBOT_TOKEN is not set or empty")
    return token


def http_post(timeout: float, verify_tls: bool = True, proxy: str | None = None) -> Post:
    """A POST function using urllib.

    verify_tls=False accepts any certificate (locally signed Nautobot).
    proxy=None uses HTTPS_PROXY/HTTP_PROXY/NO_PROXY from the environment.
    """
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    proxies = {"http": proxy, "https": proxy} if proxy else None  # None = environment
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies),
        urllib.request.HTTPSHandler(context=context),
    )

    def post(url: str, body: bytes, headers: dict[str, str]) -> bytes:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read(300).decode("utf-8", "replace").strip()
            raise NautobotError(f"Nautobot returned HTTP {exc.code} for {url}: {detail}") from None
        except (urllib.error.URLError, OSError) as exc:  # DNS, refused, proxy, TLS, timeout
            raise NautobotError(f"cannot reach Nautobot at {url}: {getattr(exc, 'reason', exc)}") from None

    return post


def graphql(url: str, token: str, query: str, variables: dict, post: Post) -> dict:
    endpoint = url.rstrip("/") + "/api/graphql/"
    body = json.dumps({"query": query, "variables": variables}).encode()
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    raw = post(endpoint, body, headers)
    try:
        doc = json.loads(raw)
    except ValueError:
        raise NautobotError(f"Nautobot returned no JSON from {endpoint}: {raw[:200]!r}") from None
    if not isinstance(doc, dict):
        raise NautobotError(f"Nautobot returned no JSON object from {endpoint}")
    if doc.get("errors"):
        raise NautobotError("Nautobot GraphQL: " + json.dumps(doc["errors"])[:500])
    data = doc.get("data")
    if not isinstance(data, dict):
        raise NautobotError(f"Nautobot GraphQL returned no data from {endpoint}")
    return data
