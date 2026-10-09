"""ndp publish: devices JSON -> CSV/JSON outputs, run manifest, README, housekeeping."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ndp.config import Config
from ndp.files import apply_perms, atomic_symlink, housekeeping, write_text_atomic
from ndp.inputs import InputError, load_prefixes
from ndp.manifest import build_manifest, render_readme
from ndp.result import StepResult, now_local
from ndp.state import load_step_results
from ndp.writers import append_summary_csv, write_legacy_csv, write_services_csv


def _devices_file(cfg: Config) -> Path | None:
    parse = load_step_results(cfg.state_dir).get("parse")
    if not parse or parse.get("status") == "failed":
        return None
    path = parse.get("outputs", {}).get("devices")
    return Path(path) if path and Path(path).exists() else None


def _sources(cfg: Config) -> dict[str, dict]:
    try:
        prefixes = load_prefixes(cfg.paths.inputs / "prefixes.json")
    except InputError:
        return {}
    return {"prefixes": {**prefixes.source, "items": len(prefixes.prefixes)}}


def run_publish(cfg: Config, now: datetime, config_path: Path) -> StepResult:
    result = StepResult("publish")
    devices_path = _devices_file(cfg)
    if devices_path is None:
        result.error = "no successful parse result found; run 'ndp parse' first"
        return result
    doc = json.loads(devices_path.read_text())
    devices = doc.get("devices", [])
    out = cfg.paths.output
    date = f"{now:%Y%m%d}"
    written: list[Path] = []
    links: list[tuple[str, Path]] = []  # moved only after every file is written

    if cfg.outputs.devices_json:
        link = out / "devices-latest.json"
        links.append((devices_path.name, link))
        result.outputs["devices_latest"] = str(link)
    if cfg.outputs.legacy_csv:
        csv_path = out / f"discovery.csv.{date}"
        write_legacy_csv(csv_path, devices, cfg.outputs.legacy_csv_communities)
        links.append((csv_path.name, out / "discovery-latest.csv"))
        summary = out / "discovery-summary.csv"
        append_summary_csv(summary, doc.get("scan", {}))
        written += [csv_path, summary]
        result.outputs.update(legacy_csv=str(csv_path), summary_csv=str(summary))
        result.counts["legacy_csv"] = len(devices)
    if cfg.outputs.services_csv:
        services = out / f"services-{date}.csv"
        result.counts["services_csv"] = write_services_csv(services, devices)
        links.append((services.name, out / "services-latest.csv"))
        written.append(services)
        result.outputs["services_csv"] = str(services)
    for target, link in links:
        atomic_symlink(target, link)
    for path in written:
        result.warnings.extend(apply_perms(path, cfg.housekeeping))

    result.counts = {"devices": len(devices), **result.counts}
    result.counts["deleted_files"] = len(housekeeping(out, cfg.housekeeping.keep_days, now))

    manifest_path = out / f"run-{now:%Y%m%dT%H%M%S}.json"
    readme_path = out / "README.md"
    result.outputs.update(manifest=str(manifest_path), readme=str(readme_path))
    result.started = now.isoformat(timespec="seconds")
    result.finished = now_local().isoformat(timespec="seconds")
    results = {**load_step_results(cfg.state_dir), "publish": result.to_dict()}
    manifest = build_manifest(now, config_path, results, _sources(cfg))
    write_text_atomic(manifest_path, json.dumps(manifest, indent=2) + "\n")
    write_text_atomic(readme_path, render_readme(manifest, out))
    for path in (manifest_path, readme_path):
        result.warnings.extend(apply_perms(path, cfg.housekeeping))
    return result
