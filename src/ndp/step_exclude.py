"""ndp exclude: pass 1, SNMP on infrastructure routers -> exclude.txt for pass 2."""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
import tempfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from ndp.config import Config, ConfigError, Scanner, communities_from_env
from ndp.exclude import choose_mgmt, excluded_ips, merge_exclude, router_ips
from ndp.files import apply_perms, atomic_symlink, write_private_file, write_text_atomic
from ndp.inputs import InputError, load_infra_routers, load_prefixes
from ndp.nmapxml import NmapXmlError, parse_scan
from ndp.result import StepResult

log = logging.getLogger(__name__)

EXCLUDE_SCRIPTS = "snmp-brute,snmp-ifalias-service"
# warn when fewer than this fraction of the previous run's excluded IPs remain
MAX_DROP = 0.5


def build_exclude_command(scanner: Scanner, targets_file: Path, communities_file: Path, out_xml: Path) -> list[str]:
    return [
        scanner.nmap_path,
        "-n",
        "-Pn",
        "-sU",
        "-p", "161",
        f"-T{scanner.timing}",
        "--script", EXCLUDE_SCRIPTS,
        "--script-args", f"snmp-brute.communitiesdb={communities_file},snmp.timeout={scanner.snmp_timeout_ms}",
        "-iL", str(targets_file),
        "-oX", str(out_xml),
    ]


def _read_previous(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _age_days(last_seen, now: datetime) -> float | None:
    try:
        seen = datetime.fromisoformat(str(last_seen))
    except ValueError:
        return None
    if seen.tzinfo is None:
        seen = seen.astimezone()
    return (now - seen).total_seconds() / 86400


def _ipv4_list(values) -> list[str]:
    result = []
    for value in values if isinstance(values, list) else []:
        try:
            result.append(str(ipaddress.IPv4Address(str(value))))
        except ValueError:
            continue
    return result


def run_exclude(cfg: Config, now: datetime, env: Mapping[str, str] | None = None, runner=subprocess.run) -> StepResult:
    result = StepResult("exclude")
    try:
        infra = load_infra_routers(cfg.paths.inputs / "infra-routers.json")
        prefix_input = load_prefixes(cfg.paths.inputs / "prefixes.json")
        communities = communities_from_env(env)
    except (InputError, ConfigError) as exc:
        result.error = str(exc)
        return result
    result.warnings.extend(infra.warnings)
    result.warnings.extend(prefix_input.warnings)
    if not infra.routers:
        result.error = "no IPv4 routers in infra-routers.json"
        return result

    cfg.scans_dir.mkdir(parents=True, exist_ok=True)
    xml = cfg.scans_dir / f"exclude-{now:%Y%m%dT%H%M%S}.xml"
    with tempfile.TemporaryDirectory(prefix="ndp-") as tmp:
        communities_file = Path(tmp) / "communities.txt"
        write_private_file(communities_file, "\n".join(communities) + "\n")
        targets_file = Path(tmp) / "targets.txt"
        targets_file.write_text("\n".join(router.mgmt_ip for router in infra.routers) + "\n")
        cmd = build_exclude_command(cfg.scanner, targets_file, communities_file, xml)
        log.info("running: %s", " ".join(cmd))
        try:
            proc = runner(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except OSError as exc:
            result.error = f"cannot run nmap ({cfg.scanner.nmap_path}): {exc}"
            return result
    if proc.returncode != 0:
        result.error = f"nmap exited with {proc.returncode}: {(proc.stderr or '').strip()[-500:]}"
        return result
    try:
        report = parse_scan(xml)
    except NmapXmlError as exc:
        result.error = str(exc)
        return result

    # no interface addresses (no answer, old plain-text script output, or the
    # address walk failed) = no answer, so the previous entry is kept
    interfaces_by_ip = {host.ip: host.interfaces for host in report.hosts if router_ips(host.interfaces)}
    latest = cfg.paths.output / "infra-interfaces-latest.json"
    previous = _read_previous(latest)
    previous_routers = {
        entry.get("name"): entry for entry in previous.get("routers", []) if isinstance(entry, dict)
    }
    role_order = list(cfg.nautobot.prefix_roles)
    stamp = now.isoformat(timespec="seconds")
    entries: list[dict] = []
    protected: dict[str, str] = {}  # IP -> router whose mgmt IP it is
    answered = stale = unseen = 0

    for router in infra.routers:
        interfaces = interfaces_by_ip.get(router.mgmt_ip)
        if interfaces:
            answered += 1
            choice = choose_mgmt(interfaces, prefix_input.prefixes, role_order, cfg.exclude.mgmt_interfaces)
            keep = choice.ip or router.mgmt_ip
            if choice.ip is None:
                result.warnings.append(
                    f"{router.name}: no interface address inside a discovery prefix; "
                    f"only the Nautobot IP {router.mgmt_ip} stays scannable"
                )
            elif choice.ip != router.mgmt_ip:
                result.warnings.append(
                    f"{router.name}: SNMP mgmt IP {choice.ip} ({choice.reason}) differs from "
                    f"Nautobot {router.mgmt_ip}; using {choice.ip}"
                )
            entries.append({
                "name": router.name,
                "role": router.role,
                "nautobot_ip": router.mgmt_ip,
                "mgmt_ip": choice.ip,
                "mgmt_reason": choice.reason,
                "last_seen": stamp,
                "stale": False,
                "interfaces": [interface.to_dict() for interface in interfaces],
                "excluded": excluded_ips(interfaces, keep),
            })
            protected[keep] = router.name
        elif router.name in previous_routers:
            stale += 1
            old = previous_routers[router.name]
            entry = {
                **old,
                "name": router.name,
                "role": router.role,
                "nautobot_ip": router.mgmt_ip,
                "stale": True,
                "excluded": _ipv4_list(old.get("excluded")),
            }
            age = _age_days(old.get("last_seen"), now)
            if age is None or age > cfg.exclude.stale_max_days:
                # its old addresses may have been reused by other devices by now
                entry["excluded"] = []
                result.warnings.append(
                    f"{router.name} ({router.mgmt_ip}): no SNMP answer for more than "
                    f"{cfg.exclude.stale_max_days} days (last seen {old.get('last_seen') or 'unknown'}); "
                    "its old addresses are no longer excluded"
                )
            else:
                result.warnings.append(
                    f"{router.name} ({router.mgmt_ip}): no SNMP answer; kept {len(entry['excluded'])} "
                    f"excluded IPs from {old.get('last_seen') or 'an earlier run'}"
                )
            entries.append(entry)
            protected[entry.get("mgmt_ip") or router.mgmt_ip] = router.name
        else:
            unseen += 1
            protected[router.mgmt_ip] = router.name
            result.warnings.append(
                f"{router.name} ({router.mgmt_ip}): no SNMP answer and no earlier result; "
                "nothing excluded for this router"
            )

    result.counts = {"routers": len(infra.routers), "answered": answered, "stale": stale, "unseen": unseen}
    if answered == 0:
        result.error = f"no infrastructure router answered SNMP in {xml}: keeping the previous exclude list"
        return result

    exclude = merge_exclude(entries, protected, result.warnings)
    previous_count = len(_ipv4_list(previous.get("exclude")))
    if previous_count and len(exclude) < previous_count * MAX_DROP:
        result.warnings.append(
            f"excluded IPs dropped from {previous_count} to {len(exclude)} "
            f"(more than {int((1 - MAX_DROP) * 100)}%): check pass 1 before trusting this exclude list"
        )

    doc_path = cfg.paths.output / f"infra-interfaces-{now:%Y%m%d}.json"
    exclude_path = cfg.paths.inputs / "exclude.txt"
    doc = {
        "generated_at": stamp,
        "source": infra.source,
        "scan_xml": str(xml),
        "warnings": list(result.warnings),
        "routers": entries,
        "exclude": exclude,
    }
    write_text_atomic(doc_path, json.dumps(doc, indent=2) + "\n")
    write_text_atomic(exclude_path, "".join(f"{ip}\n" for ip in exclude))
    atomic_symlink(doc_path.name, latest)
    for path in (xml, doc_path, exclude_path):
        result.warnings.extend(apply_perms(path, cfg.housekeeping))
    result.outputs = {
        "exclude_list": str(exclude_path),
        "infra_interfaces": str(doc_path),
        "infra_interfaces_latest": str(latest),
        "exclude_xml": str(xml),
    }
    result.counts.update(exclude_list=len(exclude), infra_interfaces=len(entries))
    return result
