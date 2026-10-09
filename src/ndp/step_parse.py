"""ndp parse: scan XML + prefixes -> devices-<date>.json."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ndp.config import Config
from ndp.files import apply_perms, write_text_atomic
from ndp.inputs import InputError, load_prefixes
from ndp.inventory import build_inventory
from ndp.nmapxml import NmapXmlError, parse_scan
from ndp.result import StepResult


def run_parse(cfg: Config, now: datetime, xml_path: Path | None = None) -> StepResult:
    result = StepResult("parse")
    xml = Path(xml_path) if xml_path else cfg.scans_dir / "scan-latest.xml"
    try:
        report = parse_scan(xml)
        prefix_input = load_prefixes(cfg.paths.inputs / "prefixes.json")
    except (NmapXmlError, InputError) as exc:
        result.error = str(exc)
        return result

    result.warnings.extend(prefix_input.warnings)
    for role in sorted({p.role for p in prefix_input.prefixes} - set(cfg.nautobot.prefix_roles)):
        result.warnings.append(
            f"prefix role {role} is not in nautobot.prefix_roles: no function, lowest mgmt preference"
        )

    inventory = build_inventory(report.hosts, prefix_input.prefixes, cfg.nautobot.prefix_roles)
    result.warnings.extend(inventory.warnings)
    result.counts = {"hosts_up": report.summary.hosts_up, "devices": len(inventory.devices)}
    if not inventory.devices:
        result.error = f"no devices found in {xml}: not writing an empty inventory"
        return result

    out = cfg.paths.output / f"devices-{now:%Y%m%d}.json"
    doc = {
        "generated_at": now.isoformat(timespec="seconds"),
        "scan": asdict(report.summary),
        "warnings": list(result.warnings),
        "devices": [device.to_dict() for device in inventory.devices],
    }
    write_text_atomic(out, json.dumps(doc, indent=2) + "\n")
    result.warnings.extend(apply_perms(out, cfg.housekeeping))
    result.outputs["devices"] = str(out)
    return result
