import csv
import io
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from ndp.cli import main
from ndp.state import save_step_result
from ndp.step_parse import run_parse
from ndp.step_publish import run_publish

FIXTURE = Path(__file__).parent / "fixtures" / "scan-basic.xml"
NOW = datetime(2026, 10, 9, 5, 40, 0).astimezone()


def parse_first(cfg):
    save_step_result(cfg.state_dir, run_parse(cfg, NOW, FIXTURE))


def test_publish_all_outputs(cfg, config_path):
    parse_first(cfg)
    result = run_publish(cfg, NOW, config_path)
    assert result.status == "ok", (result.error, result.warnings)
    out = cfg.paths.output
    assert os.readlink(out / "devices-latest.json") == "devices-20261009.json"
    assert os.readlink(out / "discovery-latest.csv") == "discovery.csv.20261009"
    assert os.readlink(out / "services-latest.csv") == "services-20261009.csv"
    assert len(list(csv.DictReader(io.StringIO((out / "discovery-latest.csv").read_text())))) == 3
    assert (out / "discovery-summary.csv").read_text().count("\n") == 2
    assert result.counts == {"devices": 3, "legacy_csv": 3, "services_csv": 1, "deleted_files": 0}
    manifest = json.loads(Path(result.outputs["manifest"]).read_text())
    assert manifest["sources"]["prefixes"]["items"] == 3
    assert "publish" in manifest["steps"] and "parse" in manifest["steps"]
    assert (out / "README.md").read_text().startswith("# Network discovery output")


def test_outputs_can_be_switched_off(cfg, config_path):
    cfg.outputs.legacy_csv = False
    cfg.outputs.services_csv = False
    cfg.outputs.devices_json = False
    parse_first(cfg)
    result = run_publish(cfg, NOW, config_path)
    out = cfg.paths.output
    assert not (out / "discovery-latest.csv").exists()
    assert not (out / "services-latest.csv").exists()
    assert not (out / "devices-latest.json").exists()
    assert set(result.outputs) == {"manifest", "readme"}


def test_publish_without_parse_fails(cfg, config_path):
    result = run_publish(cfg, NOW, config_path)
    assert result.status == "failed"
    assert "run 'ndp parse' first" in result.error


def test_publish_after_failed_parse_keeps_latest(cfg, config_path, tmp_path):
    parse_first(cfg)
    run_publish(cfg, NOW, config_path)
    empty = tmp_path / "empty.xml"
    empty.write_text('<nmaprun start="1"><runstats><finished time="2" elapsed="1"/>'
                     '<hosts up="0" down="0" total="0"/></runstats></nmaprun>')
    save_step_result(cfg.state_dir, run_parse(cfg, NOW, empty))
    result = run_publish(cfg, NOW, config_path)
    assert result.status == "failed"
    assert os.readlink(cfg.paths.output / "discovery-latest.csv") == "discovery.csv.20261009"


def test_cli_publish(config_path, capsys):
    assert main(["-c", str(config_path), "parse", "--xml", str(FIXTURE)]) == 0
    capsys.readouterr()
    assert main(["-c", str(config_path), "publish"]) == 0
    assert json.loads(capsys.readouterr().out)["step"] == "publish"


def test_failure_mid_publish_moves_no_latest_link(cfg, config_path, monkeypatch):
    import ndp.step_publish

    parse_first(cfg)

    def boom(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ndp.step_publish, "write_services_csv", boom)
    try:
        run_publish(cfg, NOW, config_path)
    except OSError:
        pass
    out = cfg.paths.output
    assert not (out / "devices-latest.json").exists()
    assert not (out / "discovery-latest.csv").exists()


def test_manifest_lists_infra_routers_source(cfg, config_path):
    shutil.copy(Path(__file__).parent / "fixtures" / "infra-routers.json", cfg.paths.inputs / "infra-routers.json")
    parse_first(cfg)
    result = run_publish(cfg, NOW, config_path)
    manifest = json.loads(Path(result.outputs["manifest"]).read_text())
    assert manifest["sources"]["infra_routers"]["items"] == 4
    assert manifest["sources"]["infra_routers"]["system"] == "nautobot"


def write_previous_devices(cfg, keys):
    out = cfg.paths.output
    out.mkdir(parents=True, exist_ok=True)
    (out / "devices-20261008.json").write_text(json.dumps({"devices": [{"key": k} for k in keys]}))
    os.symlink("devices-20261008.json", out / "devices-latest.json")


def test_new_and_missing_devices_are_counted(cfg, config_path):
    write_previous_devices(cfg, ["pe-01", "gone-01"])
    parse_first(cfg)
    result = run_publish(cfg, NOW, config_path)
    assert result.counts["new_devices"] == 2      # 203.0.113.5, cpe-01
    assert result.counts["missing_devices"] == 1  # gone-01


def test_no_previous_devices_no_change_counts(cfg, config_path):
    parse_first(cfg)
    result = run_publish(cfg, NOW, config_path)
    assert "new_devices" not in result.counts and "missing_devices" not in result.counts


def test_new_missing_counts_skipped_on_same_file(cfg, config_path):
    parse_first(cfg)
    run_publish(cfg, NOW, config_path)
    result = run_publish(cfg, NOW, config_path)
    assert "new_devices" not in result.counts
