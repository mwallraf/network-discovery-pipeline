"""The result every step returns, prints and saves."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

EXIT_CODES = {"ok": 0, "warning": 2, "failed": 1}


def now_local() -> datetime:
    """Current local time, timezone-aware (file names use local time)."""
    return datetime.now().astimezone()


@dataclass
class StepResult:
    step: str
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    started: str = ""
    finished: str = ""

    @property
    def status(self) -> str:
        if self.error:
            return "failed"
        return "warning" if self.warnings else "ok"

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.status]

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "status": self.status,
            "error": self.error,
            "warnings": list(self.warnings),
            "counts": dict(self.counts),
            "outputs": dict(self.outputs),
            "started": self.started,
            "finished": self.finished,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
