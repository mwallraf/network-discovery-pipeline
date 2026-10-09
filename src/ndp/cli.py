"""Command line entry point: ndp [-c CONFIG] STEP."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from ndp import __version__
from ndp.config import Config, ConfigError, load_config
from ndp.result import StepResult, now_local
from ndp.state import save_step_result
from ndp.step_parse import run_parse
from ndp.step_publish import run_publish
from ndp.step_scan import run_scan

DEFAULT_CONFIG = "/etc/ndp/ndp.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ndp",
        description="Network discovery pipeline: scan, parse and publish an SNMP device inventory.",
    )
    parser.add_argument("--version", action="version", version=f"ndp {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        default=os.environ.get("NDP_CONFIG", DEFAULT_CONFIG),
        help="path to ndp.yaml (default: $NDP_CONFIG or /etc/ndp/ndp.yaml)",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="STEP")
    _add_commands(sub)
    return parser


def _add_commands(sub) -> None:
    """Register one subcommand per step."""
    p = sub.add_parser("config", help="validate ndp.yaml and print it as JSON")
    p.add_argument("--json", action="store_true", help="output JSON (the only format)")
    p.set_defaults(handler=_cmd_config)

    p = sub.add_parser("parse", help="turn the scan XML into devices-<date>.json")
    p.add_argument("--xml", type=Path, help="scan XML to parse (default: <output>/nmap/scan-latest.xml)")
    p.set_defaults(handler=lambda args: _run_step(args, "parse", lambda cfg, now: run_parse(cfg, now, args.xml)))

    p = sub.add_parser("scan", help="run the full nmap discovery (pass 2)")
    p.set_defaults(handler=lambda args: _run_step(args, "scan", run_scan))

    p = sub.add_parser("publish", help="write CSV/JSON outputs, the run manifest and README")
    p.set_defaults(
        handler=lambda args: _run_step(args, "publish", lambda cfg, now: run_publish(cfg, now, Path(args.config)))
    )


def _cmd_config(args) -> int:
    try:
        cfg = load_config(Path(args.config))
    except ConfigError as exc:
        return emit(StepResult("config", error=str(exc)))
    print(json.dumps(cfg.model_dump(mode="json"), indent=2))
    return 0


def _run_step(args, step: str, fn: Callable[[Config, datetime], StepResult]) -> int:
    """Load config, run one step, save and print its result."""
    started = now_local()
    try:
        cfg = load_config(Path(args.config))
    except ConfigError as exc:
        return emit(StepResult(step, error=str(exc)))
    result = fn(cfg, started)
    result.started = started.isoformat(timespec="seconds")
    result.finished = now_local().isoformat(timespec="seconds")
    save_step_result(cfg.state_dir, result)
    return emit(result)


def emit(result: StepResult) -> int:
    """Print the step result as JSON on stdout and return its exit code."""
    print(result.to_json())
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    return args.handler(args)
