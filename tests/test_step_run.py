import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from ndp.state import load_step_results
from ndp.step_run import run_all

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "scan-basic.xml"
NOW = datetime(2026, 10, 9, 5, 0).astimezone()
ENV = {"SNMP_COMMUNITIES": "public"}


def fake_nmap(cmd, **kwargs):
    if "-oG" in cmd:  # pass 2
        shutil.copy(FIXTURE, cmd[cmd.index("-oX") + 1])
        Path(cmd[cmd.index("-oG") + 1]).write_text("#\n")
    else:  # pass 1
        shutil.copy(FIXTURES / "exclude-basic.xml", cmd[cmd.index("-oX") + 1])
    return subprocess.CompletedProcess(cmd, 0, "", "")


def failing_nmap(cmd, **kwargs):
    return subprocess.CompletedProcess(cmd, 1, "", "boom")


def two_routers(cfg):
    (cfg.paths.inputs / "infra-routers.json").write_text(json.dumps({"devices": [
        {"name": "pe-01", "role": "PE", "mgmt_ip": "192.0.2.1"},
        {"name": "pe-02", "role": "PE", "mgmt_ip": "192.0.2.2"},
    ]}))


def test_run_all_steps(cfg, config_path):
    two_routers(cfg)
    result = run_all(cfg, NOW, config_path, env=ENV, runner=fake_nmap)
    assert result.status == "ok", (result.error, result.warnings)
    assert set(load_step_results(cfg.state_dir)) == {"exclude", "scan", "parse", "publish"}
    assert "publish.legacy_csv" in result.outputs
    assert result.outputs["exclude.exclude_list"] == str(cfg.paths.inputs / "exclude.txt")
    manifest = json.loads(Path(result.outputs["publish.manifest"]).read_text())
    assert list(manifest["steps"]) == ["exclude", "scan", "parse", "publish"]


def test_run_stops_at_first_failure(cfg, config_path):
    two_routers(cfg)
    result = run_all(cfg, NOW, config_path, env=ENV, runner=failing_nmap)
    assert result.status == "failed"
    assert result.error.startswith("scan: nmap exited with 1")
    assert set(load_step_results(cfg.state_dir)) == {"exclude", "scan"}


def test_exclude_failure_does_not_stop_the_run(cfg, config_path):
    result = run_all(cfg, NOW, config_path, env=ENV, runner=fake_nmap)
    assert result.status == "warning"
    assert result.warnings[0].startswith("exclude: cannot read")
    assert result.warnings[0].endswith("; scanning with the previous exclude list")
    assert result.warnings[1].startswith("scan: no exclude list at")
    assert set(load_step_results(cfg.state_dir)) == {"exclude", "scan", "parse", "publish"}


def test_exception_in_a_step_fails_the_run(cfg, config_path):
    def crash(cmd, **kwargs):
        raise RuntimeError("disk on fire")
    two_routers(cfg)
    result = run_all(cfg, NOW, config_path, env=ENV, runner=crash)
    assert result.status == "failed"
    assert result.error == "scan: RuntimeError: disk on fire"
    assert "exclude: RuntimeError: disk on fire; scanning with the previous exclude list" in result.warnings
    assert load_step_results(cfg.state_dir)["scan"]["status"] == "failed"
