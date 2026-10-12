import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from ndp.nautobot import DEVICE_QUERY, NautobotError
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


def nautobot_post(url, body, headers):
    query = json.loads(body)["query"]
    if query == DEVICE_QUERY:
        data = {"devices": [
            {"name": "pe-01", "role": {"name": "PE"}, "primary_ip4": {"address": "192.0.2.1/32"}},
            {"name": "pe-02", "role": {"name": "PE"}, "primary_ip4": {"address": "192.0.2.2/32"}},
        ]}
    else:
        # same prefixes as tests/fixtures/prefixes.json, so parse sees what test_run_all_steps sees
        data = {"prefixes": [
            {"prefix": "192.0.2.0/24", "role": {"name": "INFRA_LOOPBACK"}},
            {"prefix": "198.51.100.0/24", "role": {"name": "CPE_P2P"}},
            {"prefix": "203.0.113.0/24", "role": {"name": "MGMT_LAN"}},
        ]}
    return json.dumps({"data": data}).encode()


def with_url(config_path):
    text = config_path.read_text().replace("nautobot:\n", "nautobot:\n  url: https://nautobot.example/\n", 1)
    config_path.write_text(text)
    from ndp.config import load_config
    return load_config(config_path)


def test_run_with_fetch(config_path):
    cfg = with_url(config_path)
    env = {**ENV, "NAUTOBOT_TOKEN": "x"}
    result = run_all(cfg, NOW, config_path, env=env, runner=fake_nmap, fetch=True, post=nautobot_post)
    assert result.status == "ok", (result.error, result.warnings)
    assert result.counts["fetch.infra_routers"] == 2
    assert set(load_step_results(cfg.state_dir)) == {"fetch", "exclude", "scan", "parse", "publish"}
    manifest = json.loads(Path(result.outputs["publish.manifest"]).read_text())
    assert list(manifest["steps"]) == ["fetch", "exclude", "scan", "parse", "publish"]
    assert manifest["sources"]["prefixes"]["fetched_by"] == "ndp fetch"


def test_fetch_failure_does_not_stop_the_run(cfg, config_path):
    two_routers(cfg)

    def down(url, body, headers):
        raise NautobotError(f"cannot reach Nautobot at {url}: timed out")

    cfg = with_url(config_path)
    env = {**ENV, "NAUTOBOT_TOKEN": "x"}
    result = run_all(cfg, NOW, config_path, env=env, runner=fake_nmap, fetch=True, post=down)
    assert result.status == "warning"
    assert result.warnings[0] == (
        "fetch: cannot reach Nautobot at https://nautobot.example/api/graphql/: timed out; "
        "using the previous input files"
    )
    assert "publish.manifest" in result.outputs


def test_run_without_fetch_does_not_call_nautobot(cfg, config_path):
    two_routers(cfg)

    def boom(url, body, headers):
        raise AssertionError("fetch must not run")

    result = run_all(cfg, NOW, config_path, env=ENV, runner=fake_nmap, post=boom)
    assert "fetch" not in load_step_results(cfg.state_dir)
    assert result.status == "ok", (result.error, result.warnings)


def test_failed_fetch_is_in_the_run_readme(cfg, config_path):
    two_routers(cfg)

    def down(url, body, headers):
        raise NautobotError(f"cannot reach Nautobot at {url}: timed out")

    cfg = with_url(config_path)
    result = run_all(cfg, NOW, config_path, env={**ENV, "NAUTOBOT_TOKEN": "x"}, runner=fake_nmap, fetch=True, post=down)
    manifest = json.loads(Path(result.outputs["publish.manifest"]).read_text())
    assert list(manifest["steps"]) == ["fetch", "exclude", "scan", "parse", "publish"]
    assert any(w.startswith("fetch: cannot reach Nautobot") for w in manifest["warnings"])


def test_stale_fetch_is_not_in_a_later_run(config_path):
    cfg = with_url(config_path)
    env = {**ENV, "NAUTOBOT_TOKEN": "x"}
    run_all(cfg, NOW, config_path, env=env, runner=fake_nmap, fetch=True, post=nautobot_post)
    # later, n8n writes newer inputs and runs the steps without ndp fetch
    # (steps are stamped with the real clock, so "later" must be after now)
    for name in ("infra-routers.json", "prefixes.json"):
        path = cfg.paths.inputs / name
        doc = json.loads(path.read_text())
        doc["source"] = {"system": "nautobot", "fetched_at": "2099-01-01T01:00:00.000Z", "fetched_by": "n8n"}
        path.write_text(json.dumps(doc))
    later = datetime(2026, 10, 10, 1, 5).astimezone()
    result = run_all(cfg, later, config_path, env=env, runner=fake_nmap)
    manifest = json.loads(Path(result.outputs["publish.manifest"]).read_text())
    assert list(manifest["steps"]) == ["exclude", "scan", "parse", "publish"]
