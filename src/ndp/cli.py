"""Command line entry point: ndp [-c CONFIG] STEP."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from ndp import __version__
from ndp.result import StepResult

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
    """Register one subcommand per step (added by later tasks)."""


def emit(result: StepResult) -> int:
    """Print the step result as JSON on stdout and return its exit code."""
    print(result.to_json())
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    return args.handler(args)
