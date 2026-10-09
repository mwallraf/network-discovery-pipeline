"""One device record per scanned host, with the legacy normalization rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ndp.nmapxml import HostResult, Interface

SNMP_FIELDS = (
    "sysObjectId", "sysContact", "sysLocation", "sysUpTime", "physSerial",
    "physSoftware", "physDescription", "physName", "physModel", "sysDescr",
)

_CISCO_VERSION = re.compile(r"^Cisco.*Version\s([\da-zA-Z\.\(\)]+),", re.MULTILINE | re.DOTALL)


def normalize_hostname(name: str) -> str:
    """Lowercase, domain stripped: 'PE-01.example.net' -> 'pe-01'."""
    return name.strip().split(".")[0].lower()


def normalize_port_state(state: str) -> str:
    """Any filtered state counts as closed (legacy rule)."""
    return "closed" if "filtered" in state else state


def detect_software(sysdescr: str, enterprise: str, phys_software: str) -> str:
    """Software version, falling back to sysDescr when ENTITY-MIB has none.

    - OneOS: the whole sysDescr is the software string.
    - Cisco: the 'Version x.y.z,' part of sysDescr.
    - Anything after ', ' is dropped (some Cisco devices report extra text).
    """
    software = phys_software
    if not software and len(sysdescr) >= 5:
        if sysdescr[:5].lower().startswith("oneos"):
            software = sysdescr
        if "cisco" in enterprise.lower():
            match = _CISCO_VERSION.match(sysdescr)
            if match:
                software = match.group(1)
    if ", " in software:
        software = software.split(", ")[0]
    return software


def detect_os_slug(enterprise: str, software: str, sysdescr: str) -> str:
    """OS flavor. Rules (same as the legacy parser):

    | enterprise contains | condition                               | slug          |
    |---------------------|-----------------------------------------|---------------|
    | ciena               | software starts with saos-06/05/10      | saos6/5/10    |
    | ciena               | otherwise                               | ciena-generic |
    | oneaccess           | software (upper) contains -V5           | oneos5        |
    | oneaccess           | software contains -6                    | oneos6        |
    | oneaccess           | otherwise                               | oneos-generic |
    | cisco               | sysDescr (upper) contains IOS XR        | ios-xr        |
    | cisco               | sysDescr (upper) has CISCO IOS SOFTWARE | ios-xe        |
    | cisco               | otherwise                               | ios-generic   |
    """
    ent = enterprise.lower()
    slug = ""
    if "ciena" in ent:
        slug = "ciena-generic"
        if software.startswith("saos-06"):
            slug = "saos6"
        elif software.startswith("saos-05"):
            slug = "saos5"
        elif software.startswith("saos-10"):
            slug = "saos10"
    if "oneaccess" in ent:
        slug = "oneos-generic"
        if "-V5" in software.upper():
            slug = "oneos5"
        elif "-6" in software:
            slug = "oneos6"
    if "cisco" in ent:
        slug = "ios-generic"
        if "IOS XR" in sysdescr.upper():
            slug = "ios-xr"
        elif "CISCO IOS SOFTWARE" in sysdescr.upper():
            slug = "ios-xe"
    return slug


@dataclass
class Device:
    key: str
    hostname: str
    status: str
    ips: list[str]
    communities: list[str]
    ports: dict[str, str]
    enterprise: str
    os_slug: str
    snmp: dict[str, str]
    interfaces: list[Interface] = field(default_factory=list)
    updates: int = 0
    mgmt_ip: str = ""
    mgmt_safe: int = 0
    mgmt_role: str = ""
    function: str = ""

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "hostname": self.hostname,
            "status": self.status,
            "mgmt_ip": self.mgmt_ip,
            "mgmt_safe": self.mgmt_safe,
            "mgmt_role": self.mgmt_role,
            "function": self.function,
            "os_slug": self.os_slug,
            "updates": self.updates,
            "ips": list(self.ips),
            "communities": list(self.communities),
            "ports": dict(self.ports),
            "snmp": {**self.snmp, "enterprise": self.enterprise},
            "interfaces": [interface.to_dict() for interface in self.interfaces],
        }


def device_from_host(host: HostResult) -> Device:
    details = host.sysdetails
    snmp = {name: details.get(name, "") for name in SNMP_FIELDS}
    snmp["physSoftware"] = detect_software(snmp["sysDescr"], host.enterprise, snmp["physSoftware"])
    hostname = normalize_hostname(details.get("sysName", ""))
    communities = list(host.communities)
    if not communities and snmp["sysObjectId"]:
        # SNMP answered without a snmp-brute result: the default community worked
        communities = ["public"]
    return Device(
        key=hostname or snmp["physSerial"] or host.ip,
        hostname=hostname,
        status=host.status,
        ips=[host.ip],
        communities=communities,
        ports={name: normalize_port_state(state) for name, state in host.ports.items()},
        enterprise=host.enterprise,
        os_slug=detect_os_slug(host.enterprise, snmp["physSoftware"], snmp["sysDescr"]),
        snmp=snmp,
        interfaces=list(host.interfaces),
    )
