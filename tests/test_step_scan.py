import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from ndp.step_scan import build_nmap_command, run_scan

FIXTURE = Path(__file__).parent / "fixtures" / "scan-basic.xml"
NOW = datetime(2026, 10, 9, 5, 0, 0).astimezone()
ENV = {"SNMP_COMMUNITIES": "public,private"}


class FakeNmap:
    """Records the command and the files nmap would read, writes fixture output."""

    def __init__(self, xml=FIXTURE, returncode=0, stderr=""):
        self.xml, self.returncode, self.stderr = xml, returncode, stderr
        self.cmd = None
        self.communities = None
        self.targets = None
        self.communities_path = None

    def __call__(self, cmd, **kwargs):
        self.cmd = cmd
        script_args = cmd[cmd.index("--script-args") + 1]
        self.communities_path = Path(script_args.split(",")[0].split("=", 1)[1])
        self.communities = self.communities_path.read_text()
        self.mode = self.communities_path.stat().st_mode & 0o777
        self.targets = Path(cmd[cmd.index("-iL") + 1]).read_text()
        if self.xml is not None:
            shutil.copy(self.xml, cmd[cmd.index("-oX") + 1])
            Path(cmd[cmd.index("-oG") + 1]).write_text("# grepable\n")
        return subprocess.CompletedProcess(cmd, self.returncode, "", self.stderr)


def test_build_nmap_command(cfg, tmp_path):
    cmd = build_nmap_command(cfg.scanner, tmp_path / "t.txt", tmp_path / "c.txt", tmp_path / "scan-x", tmp_path / "e.txt")
    assert cmd == [
        "nmap", "-n", "-PS22,23", "-sU", "-sS", "-p", "T:22,23,179,U:161", "-T4",
        "--script", "snmp-brute,snmp-sysdetails,snmp-info,snmp-ifalias-service",
        "--script-args", f"snmp-brute.communitiesdb={tmp_path / 'c.txt'},snmp.timeout=4000",
        "-iL", str(tmp_path / "t.txt"), "--excludefile", str(tmp_path / "e.txt"),
        "-oX", f"{tmp_path / 'scan-x'}.xml", "-oG", f"{tmp_path / 'scan-x'}.txt",
    ]


def test_scan_success(cfg):
    (cfg.paths.inputs / "exclude.txt").write_text("198.51.100.1\n")
    fake = FakeNmap()
    result = run_scan(cfg, NOW, env=ENV, runner=fake)
    assert result.status == "ok", (result.error, result.warnings)
    base = cfg.scans_dir / "scan-20261009T050000"
    assert result.outputs == {"scan_xml": f"{base}.xml", "scan_grep": f"{base}.txt"}
    assert result.counts == {"prefixes": 3, "hosts_up": 4, "hosts_total": 5}
    assert os.readlink(cfg.scans_dir / "scan-latest.xml") == "scan-20261009T050000.xml"
    assert os.readlink(cfg.scans_dir / "scan-latest.txt") == "scan-20261009T050000.txt"
    assert fake.targets == "192.0.2.0/24\n198.51.100.0/24\n203.0.113.0/24\n"
    assert fake.communities == "public\nprivate\n"
    assert fake.mode == 0o600
    assert "--excludefile" in fake.cmd


def test_secrets_never_on_command_line_and_temp_file_removed(cfg):
    fake = FakeNmap()
    run_scan(cfg, NOW, env={"SNMP_COMMUNITIES": "s3cr3t-community"}, runner=fake)
    assert not any("s3cr3t-community" in part for part in fake.cmd)
    assert not fake.communities_path.exists()


def test_no_exclude_file_is_a_warning(cfg):
    result = run_scan(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.status == "warning"
    assert result.warnings[0].startswith("no exclude list at")


def test_ipv6_prefixes_are_not_passed_to_nmap(cfg):
    path = cfg.paths.inputs / "prefixes.json"
    data = json.loads(path.read_text())
    data["prefixes"].append({"prefix": "2001:db8::/32", "role": "MGMT_LAN"})
    path.write_text(json.dumps(data))
    fake = FakeNmap()
    result = run_scan(cfg, NOW, env=ENV, runner=fake)
    assert "2001:db8" not in fake.targets
    assert "skipped IPv6 prefix 2001:db8::/32 (role MGMT_LAN)" in result.warnings


def test_nmap_failure_keeps_previous_latest(cfg):
    cfg.scans_dir.mkdir(parents=True)
    (cfg.scans_dir / "scan-20261008T050000.xml").write_text("old")
    os.symlink("scan-20261008T050000.xml", cfg.scans_dir / "scan-latest.xml")
    result = run_scan(cfg, NOW, env=ENV, runner=FakeNmap(xml=None, returncode=1, stderr="Failed to resolve"))
    assert result.status == "failed"
    assert "nmap exited with 1: Failed to resolve" in result.error
    assert os.readlink(cfg.scans_dir / "scan-latest.xml") == "scan-20261008T050000.xml"


def test_truncated_xml_fails_and_keeps_previous_latest(cfg, tmp_path):
    truncated = tmp_path / "truncated.xml"
    truncated.write_text(FIXTURE.read_text()[:2000])
    result = run_scan(cfg, NOW, env=ENV, runner=FakeNmap(xml=truncated))
    assert result.status == "failed"
    assert "interrupted scan" in result.error
    assert not (cfg.scans_dir / "scan-latest.xml").exists()


@pytest.mark.parametrize("env, message", [
    ({}, "SNMP_COMMUNITIES"),
])
def test_missing_communities(cfg, env, message):
    result = run_scan(cfg, NOW, env=env, runner=FakeNmap())
    assert result.status == "failed" and message in result.error


def test_no_ipv4_prefixes(cfg):
    (cfg.paths.inputs / "prefixes.json").write_text(json.dumps({"prefixes": []}))
    result = run_scan(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.error == "no IPv4 prefixes to scan in prefixes.json"


def test_nmap_not_installed(cfg):
    def missing(cmd, **kwargs):
        raise FileNotFoundError(2, "No such file or directory")
    result = run_scan(cfg, NOW, env=ENV, runner=missing)
    assert result.error.startswith("cannot run nmap (nmap)")


EMPTY_SCAN = """<?xml version="1.0"?>
<nmaprun start="1" startstr="x"><runstats><finished time="2" timestr="y" elapsed="1.0"/>
<hosts up="0" down="3" total="3"/></runstats></nmaprun>
"""


def test_empty_scan_fails_and_keeps_previous_latest(cfg, tmp_path):
    cfg.scans_dir.mkdir(parents=True)
    (cfg.scans_dir / "scan-20261008T050000.xml").write_text("old")
    os.symlink("scan-20261008T050000.xml", cfg.scans_dir / "scan-latest.xml")
    empty = tmp_path / "empty.xml"
    empty.write_text(EMPTY_SCAN)
    result = run_scan(cfg, NOW, env=ENV, runner=FakeNmap(xml=empty))
    assert result.status == "failed"
    assert "no hosts up" in result.error
    assert os.readlink(cfg.scans_dir / "scan-latest.xml") == "scan-20261008T050000.xml"


def test_overlapping_prefixes_are_scanned_once(cfg):
    path = cfg.paths.inputs / "prefixes.json"
    data = json.loads(path.read_text())
    data["prefixes"].append({"prefix": "192.0.2.0/26", "role": "MGMT_LAN"})
    path.write_text(json.dumps(data))
    fake = FakeNmap()
    run_scan(cfg, NOW, env=ENV, runner=fake)
    assert fake.targets == "192.0.2.0/24\n198.51.100.0/24\n203.0.113.0/24\n"
