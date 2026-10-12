"""ndp fetch: Nautobot -> inputs/infra-routers.json and inputs/prefixes.json.

The same files n8n writes, so the pipeline also runs without n8n (cron, by hand).
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from ndp.config import Config
from ndp.files import apply_perms, write_text_atomic
from ndp.inputs import InputError, load_infra_routers, load_prefixes
from ndp.nautobot import DEVICE_QUERY, PREFIX_QUERY, NautobotError, Post, graphql, http_post, token_from_env
from ndp.result import StepResult


def _name(value) -> str:
    return str(value.get("name") or "") if isinstance(value, dict) else ""


def _devices(data: dict) -> list[dict]:
    return [
        {"name": d.get("name"), "role": _name(d.get("role")),
         "mgmt_ip": (d.get("primary_ip4") or {}).get("address")}
        for d in data.get("devices") or [] if isinstance(d, dict)
    ]


def _prefixes(data: dict) -> list[dict]:
    return [
        {"prefix": p.get("prefix"), "role": _name(p.get("role"))}
        for p in data.get("prefixes") or [] if isinstance(p, dict)
    ]


def _document(url: str, key: str, roles: list[str], items: list[dict], now: datetime) -> str:
    source = {
        "system": "nautobot",
        "url": url,
        "query": f"{key} with role in [{', '.join(roles)}]",
        "fetched_at": now.isoformat(timespec="seconds"),
        "fetched_by": "ndp fetch",
    }
    return json.dumps({"source": source, key: items}, indent=2) + "\n"


def run_fetch(cfg: Config, now: datetime, env: Mapping[str, str] | None = None, post: Post | None = None) -> StepResult:
    result = StepResult("fetch")
    nb = cfg.nautobot
    if not nb.url:
        result.error = "nautobot.url is not set in ndp.yaml"
        return result
    if not nb.verify_tls:
        result.warnings.append("TLS certificate of Nautobot not checked (nautobot.verify_tls: false)")
    device_roles = list(nb.device_roles)
    prefix_roles = list(nb.prefix_roles)
    files: dict[str, str] = {}  # output name -> file text
    try:
        token = token_from_env(env)
        post = post or http_post(nb.timeout_s, nb.verify_tls, nb.proxy)
        if device_roles:
            devices = _devices(graphql(nb.url, token, DEVICE_QUERY, {"roles": device_roles}, post))
            if not devices:
                raise NautobotError(f"Nautobot returned no devices for roles {', '.join(device_roles)}")
            files["infra_routers"] = _document(nb.url, "devices", device_roles, devices, now)
        else:
            result.warnings.append("nautobot.device_roles is empty; infra-routers.json not fetched")
        prefixes = _prefixes(graphql(nb.url, token, PREFIX_QUERY, {"roles": prefix_roles}, post))
        if not prefixes:
            raise NautobotError(f"Nautobot returned no prefixes for roles {', '.join(prefix_roles)}")
        files["prefixes"] = _document(nb.url, "prefixes", prefix_roles, prefixes, now)
    except NautobotError as exc:
        result.error = str(exc)
        return result

    names = {"infra_routers": "infra-routers.json", "prefixes": "prefixes.json"}
    loaders = {"infra_routers": load_infra_routers, "prefixes": load_prefixes}
    # check both files with the loaders the other steps use before replacing anything
    with tempfile.TemporaryDirectory(prefix="ndp-fetch-") as tmp:
        for key, text in files.items():
            path = Path(tmp) / names[key]
            path.write_text(text)
            try:
                loaded = loaders[key](path)
            except InputError as exc:
                result.error = f"Nautobot data is not valid: {exc}"
                return result
            usable = len(loaded.routers if key == "infra_routers" else loaded.prefixes)
            if usable == 0:
                # e.g. no primary IPs or only IPv6: keep the working files of the previous fetch
                what = "devices (IPv4 mgmt_ip)" if key == "infra_routers" else "prefixes (IPv4)"
                roles = device_roles if key == "infra_routers" else prefix_roles
                result.error = f"Nautobot returned no usable {what} for roles {', '.join(roles)}"
                return result
            result.counts[key] = usable
            result.warnings.extend(f"{key}: {warning}" for warning in loaded.warnings)
    for key, text in files.items():
        target = cfg.paths.inputs / names[key]
        write_text_atomic(target, text)
        result.warnings.extend(apply_perms(target, cfg.housekeeping))
        result.outputs[key] = str(target)
    return result
