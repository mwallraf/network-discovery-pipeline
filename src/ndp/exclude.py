"""Pass 1 rules: pick one mgmt IP per infrastructure router, exclude its other addresses."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ndp.inputs import PrefixEntry
from ndp.inventory import role_for_ip
from ndp.nmapxml import Interface


@dataclass(frozen=True)
class MgmtChoice:
    ip: str | None
    reason: str  # "interface:<name>", "prefix_role:<role>" or "none"


def normalize_ifname(name: str) -> str:
    return name.replace(" ", "").lower()


def interface_ips(interface: Interface) -> list[str]:
    """IPv4 addresses of an interface, without prefix length."""
    ips: list[str] = []
    for address in interface.addresses:
        try:
            ip = ipaddress.ip_interface(address).ip
        except ValueError:
            continue
        if ip.version == 4 and str(ip) not in ips:
            ips.append(str(ip))
    return ips


def router_ips(interfaces: list[Interface]) -> list[str]:
    ips = {ip for interface in interfaces for ip in interface_ips(interface)}
    return sorted(ips, key=ipaddress.IPv4Address)


def _best(ips: list[str], prefixes: list[PrefixEntry], role_order: list[str]) -> tuple[str, str] | None:
    """Address in the highest-priority role, lowest address on a tie; roles not in the order rank last."""
    ranked = []
    for ip in ips:
        role = role_for_ip(ip, prefixes)
        if role is None:
            continue
        rank = role_order.index(role) if role in role_order else len(role_order)
        ranked.append((rank, ipaddress.IPv4Address(ip), role))
    if not ranked:
        return None
    _, address, role = min(ranked)
    return str(address), role


def choose_mgmt(
    interfaces: list[Interface],
    prefixes: list[PrefixEntry],
    role_order: list[str],
    mgmt_interfaces: list[str],
) -> MgmtChoice:
    by_name: dict[str, Interface] = {}
    for interface in interfaces:
        by_name.setdefault(normalize_ifname(interface.name), interface)
    for wanted in mgmt_interfaces:
        interface = by_name.get(normalize_ifname(wanted))
        if interface is None:
            continue
        best = _best(interface_ips(interface), prefixes, role_order)
        if best:
            return MgmtChoice(best[0], f"interface:{interface.name}")
    best = _best(router_ips(interfaces), prefixes, role_order)
    if best:
        return MgmtChoice(best[0], f"prefix_role:{best[1]}")
    return MgmtChoice(None, "none")


def excluded_ips(interfaces: list[Interface], keep: str) -> list[str]:
    return [ip for ip in router_ips(interfaces) if ip != keep]


def merge_exclude(entries: list[dict], protected: dict[str, str], warnings: list[str]) -> list[str]:
    """Union of every router's excluded addresses; a router's mgmt IP is never excluded."""
    result: set[str] = set()
    for entry in entries:
        for ip in entry["excluded"]:
            owner = protected.get(ip)
            if owner is not None and owner != entry["name"]:
                warnings.append(f"{ip} is an interface address of {entry['name']} and the mgmt IP of {owner}: kept scannable")
                continue
            result.add(ip)
    return sorted(result, key=ipaddress.IPv4Address)
