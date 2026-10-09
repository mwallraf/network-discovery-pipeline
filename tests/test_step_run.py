import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from ndp.state import load_step_results
from ndp.step_run import run_all

FIXTURE = Path(__file__).parent / "fixtures" / "scan-basic.xml"
NOW = datetime(2026, 10, 9, 5, 0).astimezone()
ENV = {"SNMP_COMMUNITIES": "public"}


def fake_nmap(cmd, **kwargs):
    shutil.copy(FIXTURE, cmd[cmd.index("-oX") + 1])
    Path(cmd[cmd.index("-oG") + 1]).write_text("#\n")
    return subprocess.CompletedProcess(cmd, 0, "", "")


def failing_nmap(cmd, **kwargs):
    return subprocess.CompletedProcess(cmd, 1, "", "boom")


def test_run_all_steps(cfg, config_path):
    (cfg.paths.inputs / "exclude.txt").write_text("")
    result = run_all(cfg, NOW, config_path, env=ENV, runner=fake_nmap)
    assert result.status == "ok", (result.error, result.warnings)
    assert set(load_step_results(cfg.state_dir)) == {"scan", "parse", "publish"}
    assert "publish.legacy_csv" in result.outputs
    manifest = json.loads(Path(result.outputs["publish.manifest"]).read_text())
    assert list(manifest["steps"]) == ["scan", "parse", "publish"]


def test_run_stops_at_first_failure(cfg, config_path):
    result = run_all(cfg, NOW, config_path, env=ENV, runner=failing_nmap)
    assert result.status == "failed"
    assert result.error.startswith("scan: nmap exited with 1")
    assert set(load_step_results(cfg.state_dir)) == {"scan"}


def test_warnings_are_prefixed(cfg, config_path):
    result = run_all(cfg, NOW, config_path, env=ENV, runner=fake_nmap)
    assert result.status == "warning"
    assert result.warnings[0].startswith("scan: no exclude list at")


def test_exception_in_a_step_fails_the_run(cfg, config_path):
    def crash(cmd, **kwargs):
        raise RuntimeError("disk on fire")
    result = run_all(cfg, NOW, config_path, env=ENV, runner=crash)
    assert result.status == "failed"
    assert result.error == "scan: RuntimeError: disk on fire"
    assert load_step_results(cfg.state_dir)["scan"]["status"] == "failed"
