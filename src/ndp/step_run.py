"""ndp run: exclude -> scan -> parse -> publish, for use without n8n (cron, by hand)."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from ndp.config import Config
from ndp.result import StepResult, now_local
from ndp.state import save_step_result
from ndp.step_exclude import run_exclude
from ndp.step_parse import run_parse
from ndp.step_publish import run_publish
from ndp.step_scan import run_scan

# a failed pass 1 keeps the previous exclude.txt, so the scan can still run
OPTIONAL_STEPS = {"exclude"}


def run_all(
    cfg: Config,
    now: datetime,
    config_path: Path,
    env: Mapping[str, str] | None = None,
    runner=subprocess.run,
) -> StepResult:
    result = StepResult("run")
    steps = [
        ("exclude", lambda t: run_exclude(cfg, t, env=env, runner=runner)),
        ("scan", lambda t: run_scan(cfg, t, env=env, runner=runner)),
        ("parse", lambda t: run_parse(cfg, t)),
        ("publish", lambda t: run_publish(cfg, t, config_path)),
    ]
    for name, fn in steps:
        started = now_local()
        try:
            step_result = fn(started)
        except Exception as exc:
            step_result = StepResult(name, error=f"{type(exc).__name__}: {exc}")
        step_result.started = started.isoformat(timespec="seconds")
        step_result.finished = now_local().isoformat(timespec="seconds")
        save_step_result(cfg.state_dir, step_result)
        result.warnings.extend(f"{name}: {warning}" for warning in step_result.warnings)
        result.outputs.update({f"{name}.{key}": value for key, value in step_result.outputs.items()})
        result.counts.update({f"{name}.{key}": value for key, value in step_result.counts.items()})
        if step_result.error:
            if name in OPTIONAL_STEPS:
                result.warnings.append(f"{name}: {step_result.error}; scanning with the previous exclude list")
                continue
            result.error = f"{name}: {step_result.error}"
            break
    return result
