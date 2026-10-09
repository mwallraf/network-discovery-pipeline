import os
import stat
from datetime import datetime, timedelta

from ndp.config import Housekeeping
from ndp.files import apply_perms, atomic_symlink, housekeeping, write_text_atomic

NOW = datetime(2026, 10, 9, 5, 0).astimezone()


def age(path, days):
    t = (NOW - timedelta(days=days)).timestamp()
    os.utime(path, (t, t))


def test_write_text_atomic_creates_parents_and_replaces(tmp_path):
    path = tmp_path / "a" / "b.txt"
    write_text_atomic(path, "one")
    write_text_atomic(path, "two")
    assert path.read_text() == "two"
    assert [p.name for p in path.parent.iterdir()] == ["b.txt"]


def test_atomic_symlink_replaces_existing_link(tmp_path):
    (tmp_path / "x-1.txt").write_text("1")
    (tmp_path / "x-2.txt").write_text("2")
    link = tmp_path / "x-latest.txt"
    atomic_symlink("x-1.txt", link)
    atomic_symlink("x-2.txt", link)
    assert os.readlink(link) == "x-2.txt"
    assert link.read_text() == "2"


def test_apply_perms_sets_mode(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    assert apply_perms(path, Housekeeping(file_mode="0640")) == []
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert apply_perms(tmp_path, Housekeeping(dir_mode="0750")) == []
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o750


def test_apply_perms_unknown_owner_is_a_warning(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    warnings = apply_perms(path, Housekeeping(owner="no-such-user-ndp"))
    assert len(warnings) == 1 and warnings[0].startswith(f"chown {path}")


def test_housekeeping_deletes_old_dated_files_only(tmp_path):
    (tmp_path / "nmap").mkdir()
    old = [tmp_path / "nmap" / "scan-20260801T050000.xml", tmp_path / "discovery.csv.20260801",
           tmp_path / "devices-20260801.json", tmp_path / "services-20260801.csv", tmp_path / "run-20260801T050000.json"]
    recent = tmp_path / "discovery.csv.20261008"
    other = tmp_path / "discovery-summary.csv"
    for path in [*old, recent, other]:
        path.write_text("x")
        age(path, 60)
    age(recent, 1)
    deleted = housekeeping(tmp_path, keep_days=30, now=NOW)
    assert sorted(deleted) == sorted(old)
    assert recent.exists() and other.exists()


def test_housekeeping_keeps_target_of_latest_link(tmp_path):
    target = tmp_path / "discovery.csv.20260801"
    target.write_text("x")
    age(target, 60)
    atomic_symlink(target.name, tmp_path / "discovery-latest.csv")
    assert housekeeping(tmp_path, keep_days=30, now=NOW) == []
    assert target.exists()
