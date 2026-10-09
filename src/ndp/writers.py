"""CSV outputs: legacy device CSV, run summary CSV, services CSV."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ndp.files import write_text_atomic

LEGACY_COLUMNS = [
    "_key", "_updates", "hostname", "status", "telnet", "ssh", "snmp", "bgp", "enterprise",
    "os_slug", "function", "mgmt_ip", "mgmt_safe", "sysObjectId", "sysContact", "sysLocation",
    "sysUpTime", "physSerial", "physSoftware", "physDescription", "physName", "physModel",
    "ip", "communities",
]
SUMMARY_COLUMNS = [
    "id", "started", "started_str", "endtime", "endtime_str", "elapsed",
    "hosts_total", "hosts_up", "hosts_down", "filename",
]
SERVICES_COLUMNS = ["service", "hostname", "mgmt_ip", "interface", "ifAlias", "address"]

_LEGACY_SNMP = [
    "sysObjectId", "sysContact", "sysLocation", "sysUpTime", "physSerial",
    "physSoftware", "physDescription", "physName", "physModel",
]


def clean_text(value) -> str:
    """Legacy CSV cleanup: newlines -> '. ', ',' and '|' -> '_', stripped."""
    return str(value).replace("\n", ". ").replace(",", "_").replace("|", "_").strip()


def legacy_row(device: dict, include_communities: bool = True) -> dict[str, str]:
    snmp = device.get("snmp", {})
    ports = device.get("ports", {})
    row = {
        "_key": device["key"],
        "_updates": device.get("updates", 0),
        "hostname": device.get("hostname", ""),
        "status": device.get("status", ""),
        **{name: ports.get(name, "") for name in ("telnet", "ssh", "snmp", "bgp")},
        "enterprise": snmp.get("enterprise", ""),
        "os_slug": device.get("os_slug", ""),
        "function": device.get("function", ""),
        "mgmt_ip": device.get("mgmt_ip", ""),
        "mgmt_safe": device.get("mgmt_safe", 0),
        **{name: snmp.get(name, "") for name in _LEGACY_SNMP},
    }
    cleaned = {key: clean_text(value) for key, value in row.items()}
    cleaned["ip"] = "|".join(device.get("ips", []))
    cleaned["communities"] = "|".join(device.get("communities", [])) if include_communities else ""
    return cleaned


def _csv_text(columns: list[str], rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def write_legacy_csv(path: Path, devices: list[dict], include_communities: bool) -> None:
    rows = [legacy_row(device, include_communities) for device in devices]
    write_text_atomic(path, _csv_text(LEGACY_COLUMNS, rows))


def append_summary_csv(path: Path, scan: dict) -> None:
    path = Path(path)
    new_file = not path.exists() or path.stat().st_size == 0
    row = {"id": 1, **{name: scan.get(name, "") for name in SUMMARY_COLUMNS[1:]}}
    with open(path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=SUMMARY_COLUMNS, lineterminator="\n")
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def services_rows(devices: list[dict]) -> list[dict[str, str]]:
    rows = []
    for device in devices:
        for interface in device.get("interfaces", []):
            for service in interface.get("services", []):
                for address in interface.get("addresses") or [""]:
                    rows.append({
                        "service": service,
                        "hostname": device.get("hostname") or device["key"],
                        "mgmt_ip": device.get("mgmt_ip", ""),
                        "interface": interface.get("name", ""),
                        "ifAlias": interface.get("ifAlias", ""),
                        "address": address,
                    })
    return rows


def write_services_csv(path: Path, devices: list[dict]) -> int:
    rows = services_rows(devices)
    write_text_atomic(path, _csv_text(SERVICES_COLUMNS, rows))
    return len(rows)
