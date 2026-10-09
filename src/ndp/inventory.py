"""Merge hosts into devices and pick each device's management IP and function."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ndp.config import PrefixRole
from ndp.devices import Device, device_from_host
from ndp.inputs import PrefixEntry
from ndp.nmapxml import HostResult

# taken from the most recent host instead of raising a conflict
ALWAYS_UPDATE = {"sysUpTime"}


@dataclass
class Inventory:
    devices: list[Device]
    warnings: list[str]


def build_inventory(
    hosts: list[HostResult],
    prefixes: list[PrefixEntry],
    prefix_roles: dict[str, PrefixRole],
) -> Inventory:
    warnings: list[str] = []
    by_key: dict[str, Device] = {}
    for host in hosts:
        if host.status != "up":
            continue
        device = device_from_host(host)
        existing = by_key.get(device.key)
        if existing is None:
            by_key[device.key] = device
        else:
            merge_device(existing, device, warnings)
    devices = sorted(by_key.values(), key=lambda d: d.key)
    for device in devices:
        assign_mgmt(device, prefixes, prefix_roles, warnings)
    return Inventory(devices=devices, warnings=warnings)


def _ip_key(ip: str) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(ip)


def _merge_value(key: str, label: str, old: str, new: str, warnings: list[str]) -> str:
    if not new or old == new:
        return old
    if not old:
        return new
    warnings.append(f"{key}: conflicting {label} {old!r} vs {new!r} from another IP; kept the first")
    return old


def merge_device(existing: Device, new: Device, warnings: list[str]) -> None:
    existing.ips = sorted(set(existing.ips) | set(new.ips), key=_ip_key)
    existing.communities = sorted(set(existing.communities) | set(new.communities))
    for name, state in new.ports.items():
        old = existing.ports.get(name, "")
        if state and (not old or (old != state and old != "open")):
            existing.ports[name] = state
    for attr in ("status", "enterprise", "os_slug"):
        setattr(existing, attr, _merge_value(existing.key, attr, getattr(existing, attr), getattr(new, attr), warnings))
    for name, value in new.snmp.items():
        if name in ALWAYS_UPDATE:
            if value:
                existing.snmp[name] = value
        else:
            existing.snmp[name] = _merge_value(existing.key, name, existing.snmp.get(name, ""), value, warnings)
    known = {interface.name for interface in existing.interfaces}
    existing.interfaces.extend(i for i in new.interfaces if i.name not in known)
    existing.updates += 1


def role_for_ip(ip: str, prefixes: list[PrefixEntry]) -> str | None:
    """Role of the most specific prefix that contains the IP."""
    address = _ip_key(ip)
    best: PrefixEntry | None = None
    for entry in prefixes:
        if address in entry.network and (best is None or entry.network.prefixlen > best.network.prefixlen):
            best = entry
    return best.role if best else None


def assign_mgmt(
    device: Device,
    prefixes: list[PrefixEntry],
    prefix_roles: dict[str, PrefixRole],
    warnings: list[str],
) -> None:
    order = list(prefix_roles)
    ranked = []
    for ip in device.ips:
        role = role_for_ip(ip, prefixes)
        if role is not None:
            rank = order.index(role) if role in prefix_roles else len(order)
            ranked.append((rank, _ip_key(ip), role))
    if not ranked:
        device.mgmt_ip = min(device.ips, key=_ip_key)
        device.mgmt_role = ""
        device.function = ""
        device.mgmt_safe = 1 if len(device.ips) == 1 else 0
        warnings.append(f"{device.key}: no IP inside a known prefix, using {device.mgmt_ip}")
        return
    best = min(rank for rank, _, _ in ranked)
    candidates = sorted((item for item in ranked if item[0] == best), key=lambda item: item[1])
    _, address, role = candidates[0]
    device.mgmt_ip = str(address)
    device.mgmt_role = role
    device.function = prefix_roles[role].function if role in prefix_roles else ""
    device.mgmt_safe = 1 if len(candidates) == 1 else 0
