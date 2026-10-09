import json
from datetime import datetime
from pathlib import Path

from ndp.cli import main
from ndp.step_parse import run_parse

FIXTURE = Path(__file__).parent / "fixtures" / "scan-basic.xml"
NOW = datetime(2026, 10, 9, 5, 30).astimezone()

EMPTY_SCAN = """<?xml version="1.0"?>
<nmaprun start="1" startstr="x"><host><status state="down"/><address addr="192.0.2.9" addrtype="ipv4"/></host>
<runstats><finished time="2" timestr="y" elapsed="1.0"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>
"""


def test_parse_writes_devices_file(cfg):
    result = run_parse(cfg, NOW, FIXTURE)
    assert result.status == "ok", result.warnings
    out = cfg.paths.output / "devices-20261009.json"
    assert result.outputs == {"devices": str(out)}
    assert result.counts == {"hosts_up": 4, "devices": 3}
    doc = json.loads(out.read_text())
    assert doc["scan"]["hosts_up"] == 4
    assert [d["key"] for d in doc["devices"]] == ["203.0.113.5", "cpe-01", "pe-01"]
    assert doc["devices"][2]["function"] == "CORE"


def test_default_xml_is_scan_latest(cfg):
    cfg.scans_dir.mkdir(parents=True)
    (cfg.scans_dir / "scan-latest.xml").write_text(FIXTURE.read_text())
    assert run_parse(cfg, NOW).status == "ok"


def test_unknown_prefix_role_is_a_warning(cfg):
    path = cfg.paths.inputs / "prefixes.json"
    data = json.loads(path.read_text())
    data["prefixes"].append({"prefix": "10.0.0.0/8", "role": "NEW_ROLE"})
    path.write_text(json.dumps(data))
    result = run_parse(cfg, NOW, FIXTURE)
    assert result.status == "warning"
    assert "prefix role NEW_ROLE is not in nautobot.prefix_roles" in result.warnings[0]


def test_zero_devices_fails_and_writes_nothing(cfg, tmp_path):
    xml = tmp_path / "empty.xml"
    xml.write_text(EMPTY_SCAN)
    result = run_parse(cfg, NOW, xml)
    assert result.status == "failed"
    assert "no devices found" in result.error
    assert not (cfg.paths.output / "devices-20261009.json").exists()


def test_missing_scan_fails(cfg):
    result = run_parse(cfg, NOW)
    assert result.status == "failed"
    assert "not found" in result.error


def test_cli_parse_saves_state(config_path, capsys):
    assert main(["-c", str(config_path), "parse", "--xml", str(FIXTURE)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["step"] == "parse" and printed["started"] and printed["finished"]
    state = json.loads((config_path.parent / "out" / "state" / "last-parse.json").read_text())
    assert state["outputs"]["devices"].endswith(".json")


def test_cli_bad_config_exit_1(tmp_path, capsys):
    assert main(["-c", str(tmp_path / "nope.yaml"), "parse"]) == 1
    assert json.loads(capsys.readouterr().out)["error"].startswith("cannot read config")
