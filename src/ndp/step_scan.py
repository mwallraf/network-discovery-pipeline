"""ndp scan: pass 2, full discovery of all prefixes minus the exclude list."""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import tempfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from ndp.config import Config, ConfigError, Scanner, communities_from_env
from ndp.files import apply_perms, atomic_symlink, write_private_file
from ndp.inputs import InputError, load_prefixes
from ndp.nmapxml import NmapXmlError, parse_scan
from ndp.result import StepResult

log = logging.getLogger(__name__)

NSE_SCRIPTS = "snmp-brute,snmp-sysdetails,snmp-info,snmp-ifalias-service"


def build_nmap_command(
    scanner: Scanner,
    targets_file: Path,
    communities_file: Path,
    out_base: Path,
    exclude_file: Path | None = None,
) -> list[str]:
    cmd = [
        scanner.nmap_path,
        "-n",
        "-PS" + ",".join(str(p) for p in scanner.host_discovery_ports),
        "-sU",
        "-sS",
        "-p", "T:" + ",".join(str(p) for p in scanner.tcp_ports) + ",U:161",
        f"-T{scanner.timing}",
        "--script", NSE_SCRIPTS,
        "--script-args", f"snmp-brute.communitiesdb={communities_file},snmp.timeout={scanner.snmp_timeout_ms}",
        "-iL", str(targets_file),
    ]
    if exclude_file is not None:
        cmd += ["--excludefile", str(exclude_file)]
    cmd += ["-oX", f"{out_base}.xml", "-oG", f"{out_base}.txt"]
    return cmd


def run_scan(cfg: Config, now: datetime, env: Mapping[str, str] | None = None, runner=subprocess.run) -> StepResult:
    result = StepResult("scan")
    try:
        prefix_input = load_prefixes(cfg.paths.inputs / "prefixes.json")
        communities = communities_from_env(env)
    except (InputError, ConfigError) as exc:
        result.error = str(exc)
        return result
    result.warnings.extend(prefix_input.warnings)
    if not prefix_input.prefixes:
        result.error = "no IPv4 prefixes to scan in prefixes.json"
        return result

    exclude: Path | None = cfg.paths.inputs / "exclude.txt"
    if not exclude.exists():
        result.warnings.append(f"no exclude list at {exclude}: scanning without exclusions")
        exclude = None

    cfg.scans_dir.mkdir(parents=True, exist_ok=True)
    base = cfg.scans_dir / f"scan-{now:%Y%m%dT%H%M%S}"
    with tempfile.TemporaryDirectory(prefix="ndp-") as tmp:
        communities_file = Path(tmp) / "communities.txt"
        write_private_file(communities_file, "\n".join(communities) + "\n")
        targets_file = Path(tmp) / "targets.txt"
        # overlapping prefixes would make nmap scan the same addresses twice
        targets = ipaddress.collapse_addresses(p.network for p in prefix_input.prefixes)
        targets_file.write_text("\n".join(str(net) for net in targets) + "\n")
        cmd = build_nmap_command(cfg.scanner, targets_file, communities_file, base, exclude)
        log.info("running: %s", " ".join(cmd))
        try:
            proc = runner(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except OSError as exc:
            result.error = f"cannot run nmap ({cfg.scanner.nmap_path}): {exc}"
            return result

    if proc.returncode != 0:
        result.error = f"nmap exited with {proc.returncode}: {(proc.stderr or '').strip()[-500:]}"
        return result
    xml = Path(f"{base}.xml")
    try:
        report = parse_scan(xml)
    except NmapXmlError as exc:
        result.error = str(exc)
        return result
    if report.summary.hosts_up == 0:
        result.error = f"no hosts up in {xml}: keeping the previous scan-latest"
        return result

    for suffix in ("xml", "txt"):
        path = Path(f"{base}.{suffix}")
        if path.exists():
            result.warnings.extend(apply_perms(path, cfg.housekeeping))
            atomic_symlink(path.name, cfg.scans_dir / f"scan-latest.{suffix}")
    result.outputs = {"scan_xml": str(xml), "scan_grep": f"{base}.txt"}
    result.counts = {
        "prefixes": len(prefix_input.prefixes),
        "hosts_up": report.summary.hosts_up,
        "hosts_total": report.summary.hosts_total,
    }
    return result
