import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from ndp.step_exclude import build_exclude_command, run_exclude

FIXTURES = Path(__file__).parent / "fixtures"
XML = FIXTURES / "exclude-basic.xml"
NOW = datetime(2026, 10, 9, 4, 30, 0).astimezone()
ENV = {"SNMP_COMMUNITIES": "s3cr3t-a,s3cr3t-b"}
EXPECTED = [
    "10.255.0.1", "192.0.2.3", "192.0.2.50", "198.51.100.1",
    "198.51.100.5", "198.51.100.9", "198.51.100.13", "203.0.113.10",
]
NO_ANSWER = """<?xml version="1.0"?>
<nmaprun start="1" startstr="x"><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
<ports><port protocol="udp" portid="161"><state state="open|filtered"/></port></ports></host>
<runstats><finished time="2" timestr="y" elapsed="1.0"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>
"""
OLD_SCRIPT = NO_ANSWER.replace(
    '<state state="open|filtered"/>',
    '<state state="open"/><script id="snmp-ifalias-service" '
    'output="Gi0/0 = &lt;No services&gt; (IP: 192.0.2.1, Subnet Mask: 255.255.255.255)"/>',
)


class FakeNmap:
    """Records what nmap would get and writes fixture output."""

    def __init__(self, xml=XML, returncode=0, stderr=""):
        self.xml, self.returncode, self.stderr = xml, returncode, stderr

    def __call__(self, cmd, **kwargs):
        self.cmd = cmd
        self.targets = Path(cmd[cmd.index("-iL") + 1]).read_text()
        script_args = cmd[cmd.index("--script-args") + 1]
        self.communities_path = Path(script_args.split(",")[0].split("=", 1)[1])
        self.mode = self.communities_path.stat().st_mode & 0o777
        if self.xml is not None:
            shutil.copy(self.xml, cmd[cmd.index("-oX") + 1])
        return subprocess.CompletedProcess(cmd, self.returncode, "", self.stderr)


@pytest.fixture
def routers(cfg):
    shutil.copy(FIXTURES / "infra-routers.json", cfg.paths.inputs / "infra-routers.json")


def exclude_lines(cfg):
    return (cfg.paths.inputs / "exclude.txt").read_text().splitlines()


def latest_doc(cfg):
    return json.loads((cfg.paths.output / "infra-interfaces-latest.json").read_text())


def write_previous(cfg, doc):
    out = cfg.paths.output
    out.mkdir(parents=True, exist_ok=True)
    (out / "infra-interfaces-20261008.json").write_text(json.dumps(doc))
    os.symlink("infra-interfaces-20261008.json", out / "infra-interfaces-latest.json")


def test_build_exclude_command(cfg, tmp_path):
    cmd = build_exclude_command(cfg.scanner, tmp_path / "t.txt", tmp_path / "c.txt", tmp_path / "exclude-x.xml")
    assert cmd == [
        "nmap", "-n", "-Pn", "-sU", "-p", "161", "-T4",
        "--script", "snmp-brute,snmp-ifalias-service",
        "--script-args", f"snmp-brute.communitiesdb={tmp_path / 'c.txt'},snmp.timeout=4000",
        "-iL", str(tmp_path / "t.txt"), "-oX", str(tmp_path / "exclude-x.xml"),
    ]


def test_exclude_success(cfg, routers):
    fake = FakeNmap()
    result = run_exclude(cfg, NOW, env=ENV, runner=fake)
    assert result.error is None
    assert fake.targets == "192.0.2.1\n192.0.2.2\n192.0.2.3\n192.0.2.4\n"
    assert fake.mode == 0o600 and not fake.communities_path.exists()
    assert not any("s3cr3t" in part for part in fake.cmd)
    assert exclude_lines(cfg) == EXPECTED
    assert result.counts == {
        "routers": 4, "answered": 3, "stale": 0, "unseen": 1, "exclude_list": 8, "infra_interfaces": 3,
    }
    out = cfg.paths.output
    assert os.readlink(out / "infra-interfaces-latest.json") == "infra-interfaces-20261009.json"
    assert result.outputs == {
        "exclude_list": str(cfg.paths.inputs / "exclude.txt"),
        "infra_interfaces": str(out / "infra-interfaces-20261009.json"),
        "infra_interfaces_latest": str(out / "infra-interfaces-latest.json"),
        "exclude_xml": str(cfg.scans_dir / "exclude-20261009T043000.xml"),
    }


def test_mgmt_choice_per_router(cfg, routers):
    run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    doc = latest_doc(cfg)
    got = {r["name"]: (r["mgmt_ip"], r["mgmt_reason"], r["excluded"]) for r in doc["routers"]}
    assert got == {
        "pe-01": ("192.0.2.1", "interface:Loopback0", ["10.255.0.1", "192.0.2.50", "198.51.100.1", "198.51.100.5"]),
        "pe-02": ("192.0.2.2", "prefix_role:INFRA_LOOPBACK", ["198.51.100.9", "203.0.113.10"]),
        "pe-03": ("192.0.2.30", "interface:loopback 64500", ["192.0.2.3", "198.51.100.13"]),
    }
    pe01 = doc["routers"][0]
    assert pe01["nautobot_ip"] == "192.0.2.1" and pe01["role"] == "PE" and pe01["stale"] is False
    assert pe01["last_seen"] == NOW.isoformat(timespec="seconds")
    assert pe01["interfaces"][2]["services"] == ["SVC100001"]
    assert doc["source"]["system"] == "nautobot"
    assert doc["exclude"] == EXPECTED
    text = json.dumps(doc)
    assert '"public"' not in text and '"private"' not in text and "s3cr3t" not in text


def test_mismatch_and_unseen_are_warnings(cfg, routers):
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.status == "warning"
    assert result.warnings == [
        "pe-03: SNMP mgmt IP 192.0.2.30 (interface:loopback 64500) differs from Nautobot 192.0.2.3; using 192.0.2.30",
        "pe-04 (192.0.2.4): no SNMP answer and no earlier result; nothing excluded for this router",
    ]


def test_unanswered_router_keeps_previous_entry(cfg, routers):
    write_previous(cfg, {
        "routers": [{
            "name": "pe-04", "role": "PE", "nautobot_ip": "192.0.2.4", "mgmt_ip": "192.0.2.4",
            "mgmt_reason": "interface:Loopback0", "last_seen": "2026-10-08T04:30:00+02:00",
            "stale": False, "interfaces": [], "excluded": ["198.51.100.17", "not-an-ip"],
        }],
        "exclude": ["198.51.100.17"],
    })
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert "198.51.100.17" in exclude_lines(cfg)
    assert result.counts["stale"] == 1 and result.counts["unseen"] == 0
    assert "pe-04 (192.0.2.4): no SNMP answer; kept 1 excluded IPs from 2026-10-08T04:30:00+02:00" in result.warnings
    entry = next(r for r in latest_doc(cfg)["routers"] if r["name"] == "pe-04")
    assert entry["stale"] is True
    assert entry["last_seen"] == "2026-10-08T04:30:00+02:00"
    assert entry["excluded"] == ["198.51.100.17"]


def test_router_without_address_in_any_prefix(cfg, routers, tmp_path):
    xml = tmp_path / "outside.xml"
    xml.write_text(XML.read_text().replace("192.0.2.1/32", "10.255.9.1/32").replace(
        "192.0.2.50/32", "10.255.9.2/32").replace("198.51.100.1/30", "10.255.9.5/30").replace(
        "198.51.100.5/30", "10.255.9.9/30"))
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=xml))
    pe01 = next(r for r in latest_doc(cfg)["routers"] if r["name"] == "pe-01")
    assert pe01["mgmt_ip"] is None and pe01["mgmt_reason"] == "none"
    assert "pe-01: no interface address inside a discovery prefix; only the Nautobot IP 192.0.2.1 stays scannable" in result.warnings
    assert "192.0.2.1" not in exclude_lines(cfg)
    assert "10.255.9.1" in exclude_lines(cfg)


def test_big_drop_in_excluded_ips_is_a_warning(cfg, routers):
    write_previous(cfg, {"routers": [], "exclude": [f"198.51.100.{i}" for i in range(100, 120)]})
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert any(w.startswith("excluded IPs dropped from 20 to 8") for w in result.warnings)


def test_no_router_answers_fails_and_keeps_previous_exclude(cfg, routers, tmp_path):
    (cfg.paths.inputs / "exclude.txt").write_text("198.51.100.99\n")
    xml = tmp_path / "none.xml"
    xml.write_text(NO_ANSWER)
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=xml))
    assert result.status == "failed"
    assert "no infrastructure router answered SNMP" in result.error
    assert exclude_lines(cfg) == ["198.51.100.99"]
    assert not (cfg.paths.output / "infra-interfaces-latest.json").exists()


def test_plaintext_interface_output_counts_as_no_answer(cfg, routers, tmp_path):
    xml = tmp_path / "old.xml"
    xml.write_text(OLD_SCRIPT)
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=xml))
    assert result.status == "failed"
    assert "no infrastructure router answered SNMP" in result.error


def test_nmap_failure_keeps_previous_exclude(cfg, routers):
    (cfg.paths.inputs / "exclude.txt").write_text("198.51.100.99\n")
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=None, returncode=1, stderr="boom"))
    assert result.error == "nmap exited with 1: boom"
    assert exclude_lines(cfg) == ["198.51.100.99"]


def test_missing_infra_routers(cfg):
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.status == "failed" and "infra-routers.json" in result.error


def test_missing_communities(cfg, routers):
    result = run_exclude(cfg, NOW, env={}, runner=FakeNmap())
    assert result.status == "failed" and "SNMP_COMMUNITIES" in result.error


def test_no_routers(cfg):
    (cfg.paths.inputs / "infra-routers.json").write_text(json.dumps({"devices": []}))
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.error == "no IPv4 routers in infra-routers.json"
