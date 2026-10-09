"""Each step saves its result so later steps (and the run manifest) can read it."""

from __future__ import annotations

import json
from pathlib import Path

from ndp.files import write_text_atomic
from ndp.result import StepResult


def save_step_result(state_dir: Path, result: StepResult) -> None:
    write_text_atomic(Path(state_dir) / f"last-{result.step}.json", result.to_json() + "\n")


def load_step_results(state_dir: Path) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for path in sorted(Path(state_dir).glob("last-*.json")):
        try:
            results[path.stem.removeprefix("last-")] = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
    return results
