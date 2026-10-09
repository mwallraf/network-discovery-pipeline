"""Compare a legacy discovery CSV with a new one, row by _key.

Usage: python -m ndp.compare OLD.csv NEW.csv
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path


def _rows(path: Path) -> dict[str, dict[str, str]]:
    with open(path, newline="") as fh:
        return {row["_key"]: row for row in csv.DictReader(fh)}


def compare_csv(old: Path, new: Path) -> dict:
    old_rows, new_rows = _rows(old), _rows(new)
    column_diffs: dict[str, int] = {}
    examples: dict[str, list[tuple[str, str, str]]] = {}
    for key in sorted(old_rows.keys() & new_rows.keys()):
        for column, old_value in old_rows[key].items():
            new_value = new_rows[key].get(column, "")
            if old_value != new_value:
                column_diffs[column] = column_diffs.get(column, 0) + 1
                if len(examples.setdefault(column, [])) < 5:
                    examples[column].append((key, old_value, new_value))
    return {
        "only_old": sorted(old_rows.keys() - new_rows.keys()),
        "only_new": sorted(new_rows.keys() - old_rows.keys()),
        "column_diffs": column_diffs,
        "examples": examples,
    }


def main(argv: list[str] | None = None) -> int:
    old, new = (Path(arg) for arg in (argv if argv is not None else sys.argv[1:]))
    report = compare_csv(old, new)
    print(f"devices only in {old.name}: {len(report['only_old'])}")
    for key in report["only_old"][:20]:
        print(f"  {key}")
    print(f"devices only in {new.name}: {len(report['only_new'])}")
    for key in report["only_new"][:20]:
        print(f"  {key}")
    for column, count in sorted(report["column_diffs"].items()):
        print(f"{column}: {count} rows differ")
        for key, old_value, new_value in report["examples"][column]:
            print(f"  {key}: {old_value!r} -> {new_value!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
