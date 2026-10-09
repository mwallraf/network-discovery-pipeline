"""Read an nmap XML report, including the SNMP NSE script results."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

PORT_NAMES = {
    ("tcp", "22"): "ssh",
    ("tcp", "23"): "telnet",
    ("tcp", "179"): "bgp",
    ("udp", "161"): "snmp",
}


class NmapXmlError(Exception):
    """The scan file is missing, incomplete or not an nmap report."""


@dataclass
class ScanSummary:
    started: int
    started_str: str
    endtime: int
    endtime_str: str
    elapsed: str
    hosts_total: int
    hosts_up: int
    hosts_down: int
    filename: str


@dataclass
class Interface:
    name: str
    if_index: int | None = None
    if_alias: str = ""
    services: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ifIndex": self.if_index,
            "ifAlias": self.if_alias,
            "services": list(self.services),
            "addresses": list(self.addresses),
        }


@dataclass
class HostResult:
    ip: str
    status: str
    ports: dict[str, str] = field(default_factory=dict)
    communities: list[str] = field(default_factory=list)
    enterprise: str = ""
    sysdetails: dict[str, str] = field(default_factory=dict)
    interfaces: list[Interface] = field(default_factory=list)


@dataclass
class ScanReport:
    summary: ScanSummary
    hosts: list[HostResult]


def parse_scan(path: Path) -> ScanReport:
    path = Path(path)
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        raise NmapXmlError(f"scan file not found: {path}") from None
    except ET.ParseError as exc:
        raise NmapXmlError(f"scan file {path} is not valid XML (interrupted scan?): {exc}") from None
    if root.tag != "nmaprun":
        raise NmapXmlError(f"{path} is not an nmap XML report")
    finished = root.find("runstats/finished")
    counts = root.find("runstats/hosts")
    if finished is None or counts is None:
        raise NmapXmlError(f"{path} has no run statistics (interrupted scan?)")
    summary = ScanSummary(
        started=int(root.get("start", "0")),
        started_str=root.get("startstr", ""),
        endtime=int(finished.get("time", "0")),
        endtime_str=finished.get("timestr", ""),
        elapsed=str(float(finished.get("elapsed", "0"))),
        hosts_total=int(counts.get("total", "0")),
        hosts_up=int(counts.get("up", "0")),
        hosts_down=int(counts.get("down", "0")),
        filename=str(path.resolve()),
    )
    hosts = [host for host in (_parse_host(el) for el in root.findall("host")) if host is not None]
    return ScanReport(summary=summary, hosts=hosts)


def _parse_host(el: ET.Element) -> HostResult | None:
    ip = next((a.get("addr") for a in el.findall("address") if a.get("addrtype") == "ipv4"), None)
    if ip is None:
        return None
    status_el = el.find("status")
    host = HostResult(ip=ip, status=status_el.get("state", "") if status_el is not None else "")
    for port in el.findall("ports/port"):
        name = PORT_NAMES.get((port.get("protocol"), port.get("portid")))
        state_el = port.find("state")
        if name and state_el is not None:
            host.ports[name] = state_el.get("state", "")
        for script in port.findall("script"):
            _apply_script(host, script.get("id", ""), _children(script))
    return host


def _children(el: ET.Element):
    """NSE structured output: keyed children -> dict, keyless children -> list."""
    keyed: dict = {}
    items: list = []
    for child in el:
        if child.tag == "elem":
            value = child.text or ""
        elif child.tag == "table":
            value = _children(child)
        else:
            continue
        key = child.get("key")
        if key is None:
            items.append(value)
        else:
            keyed[key] = value
    if keyed and items:
        keyed["_items"] = items
        return keyed
    return keyed if keyed else items


def _apply_script(host: HostResult, script_id: str, data) -> None:
    if script_id == "snmp-brute":
        for community in _valid_communities(data):
            if community not in host.communities:
                host.communities.append(community)
    elif script_id == "snmp-info" and isinstance(data, dict):
        host.enterprise = str(data.get("enterprise", ""))
    elif script_id == "snmp-sysdetails" and isinstance(data, dict):
        host.sysdetails = {key: val for key, val in data.items() if isinstance(val, str)}
    elif script_id == "snmp-ifalias-service" and isinstance(data, dict):
        # the old script version returned plain text only (no structured data)
        host.interfaces = [_interface(name, val) for name, val in data.items() if isinstance(val, dict)]


def _valid_communities(data) -> list[str]:
    found: list[str] = []
    if isinstance(data, dict):
        if "Valid credentials" in str(data.get("state", "")) and data.get("password"):
            found.append(str(data["password"]))
        values = list(data.values())
    elif isinstance(data, list):
        values = data
    else:
        return found
    for value in values:
        if isinstance(value, (dict, list)):
            found.extend(_valid_communities(value))
    return found


def _str_list(value) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _interface(name: str, data: dict) -> Interface:
    index = data.get("ifIndex")
    alias = data.get("ifAlias")
    return Interface(
        name=name,
        if_index=int(index) if isinstance(index, str) and index.isdigit() else None,
        if_alias=alias if isinstance(alias, str) else "",
        services=_str_list(data.get("services")),
        addresses=_str_list(data.get("addresses")),
    )
