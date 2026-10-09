"""Input files generated before a run (by n8n from Nautobot, or by hand)."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path


class InputError(Exception):
    """An input file is missing or invalid."""


@dataclass(frozen=True)
class PrefixEntry:
    network: ipaddress.IPv4Network
    role: str


@dataclass
class PrefixInput:
    source: dict
    prefixes: list[PrefixEntry]
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class InfraRouter:
    name: str
    role: str
    mgmt_ip: str


@dataclass
class InfraInput:
    source: dict
    routers: list[InfraRouter]
    warnings: list[str] = field(default_factory=list)


def _read_json(path: Path) -> dict:
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise InputError(f"{path}: the top level must be an object")
    return data


def load_prefixes(path: Path) -> PrefixInput:
    data = _read_json(path)
    entries = data.get("prefixes")
    if not isinstance(entries, list):
        raise InputError(f"{path}: 'prefixes' must be a list")
    prefixes: list[PrefixEntry] = []
    seen: set[ipaddress.IPv4Network] = set()
    warnings: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or "prefix" not in entry or "role" not in entry:
            raise InputError(f"{path}: prefixes[{index}] needs 'prefix' and 'role'")
        try:
            network = ipaddress.ip_network(str(entry["prefix"]), strict=False)
        except ValueError:
            raise InputError(f"{path}: prefixes[{index}]: invalid prefix {entry['prefix']!r}") from None
        role = str(entry["role"])
        if network.version != 4:
            warnings.append(f"skipped IPv6 prefix {network} (role {role})")
            continue
        if network in seen:
            continue
        seen.add(network)
        prefixes.append(PrefixEntry(network, role))
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    return PrefixInput(source=source, prefixes=prefixes, warnings=warnings)


def load_infra_routers(path: Path) -> InfraInput:
    data = _read_json(path)
    entries = data.get("devices")
    if not isinstance(entries, list):
        raise InputError(f"{path}: 'devices' must be a list")
    routers: list[InfraRouter] = []
    warnings: list[str] = []
    names: set[str] = set()
    ips: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not entry.get("name"):
            raise InputError(f"{path}: devices[{index}] needs 'name'")
        name = str(entry["name"])
        if not entry.get("mgmt_ip"):
            # a device without a primary IP in Nautobot must not block the others
            warnings.append(f"skipped {name}: no mgmt_ip")
            continue
        try:
            ip = ipaddress.ip_interface(str(entry["mgmt_ip"])).ip
        except ValueError:
            raise InputError(f"{path}: devices[{index}]: invalid mgmt_ip {entry['mgmt_ip']!r}") from None
        if ip.version != 4:
            warnings.append(f"skipped {name}: IPv6 mgmt_ip {ip}")
            continue
        if name in names or str(ip) in ips:
            warnings.append(f"skipped duplicate router {name} ({ip})")
            continue
        names.add(name)
        ips.add(str(ip))
        routers.append(InfraRouter(name=name, role=str(entry.get("role") or ""), mgmt_ip=str(ip)))
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    return InfraInput(source=source, routers=routers, warnings=warnings)
