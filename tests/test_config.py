import json
from pathlib import Path

import pytest

from ndp.cli import main
from ndp.config import ConfigError, communities_from_env, load_config

EXAMPLE = Path(__file__).parent.parent / "examples" / "ndp.example.yaml"


def test_example_config_loads():
    cfg = load_config(EXAMPLE)
    assert list(cfg.nautobot.prefix_roles) == ["INFRA_LOOPBACK", "CPE_LOOPBACK", "MGMT_LAN", "CPE_P2P"]
    assert cfg.nautobot.prefix_roles["CPE_P2P"].function == "CPE"
    assert cfg.scanner.timing == 5
    assert cfg.exclude.mgmt_interfaces == ["Loopback64500", "Loopback0", "Loopback1"]
    assert cfg.nautobot.url == "https://nautobot.example/"
    assert cfg.nautobot.verify_tls is True and cfg.nautobot.proxy is None


def test_defaults(cfg, tmp_path):
    assert cfg.scanner.snmp_timeout_ms == 4000
    assert cfg.scanner.tcp_ports == [22, 23, 179]
    assert cfg.outputs.legacy_csv is True
    assert cfg.housekeeping.keep_days == 30
    assert cfg.scans_dir == tmp_path / "out" / "nmap"
    assert cfg.state_dir == tmp_path / "out" / "state"


def test_missing_key_is_named(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("paths: {output: /x, inputs: /y}\n")
    with pytest.raises(ConfigError, match="nautobot: Field required"):
        load_config(path)


def test_unknown_key_is_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "paths: {output: /x, inputs: /y}\n"
        "nautobot: {prefix_roles: {A: {function: CORE}}}\n"
        "scanner: {timeing: 4}\n"
    )
    with pytest.raises(ConfigError, match="scanner.timeing"):
        load_config(path)


def test_empty_prefix_roles_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("paths: {output: /x, inputs: /y}\nnautobot: {prefix_roles: {}}\n")
    with pytest.raises(ConfigError, match="nautobot.prefix_roles"):
        load_config(path)


def test_role_without_mapping_is_allowed(tmp_path):
    path = tmp_path / "ok.yaml"
    path.write_text("paths: {output: /x, inputs: /y}\nnautobot:\n  prefix_roles:\n    A:\n")
    assert load_config(path).nautobot.prefix_roles["A"].function == ""


def test_unquoted_mode_is_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "paths: {output: /x, inputs: /y}\n"
        "nautobot: {prefix_roles: {A: {function: CORE}}}\n"
        "housekeeping: {file_mode: 0664}\n"
    )
    with pytest.raises(ConfigError, match="housekeeping.file_mode"):
        load_config(path)


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config"):
        load_config(tmp_path / "nope.yaml")


def test_communities_from_env():
    assert communities_from_env({"SNMP_COMMUNITIES": " public, private ,,"}) == ["public", "private"]


def test_communities_missing():
    with pytest.raises(ConfigError, match="SNMP_COMMUNITIES"):
        communities_from_env({})


def test_cli_config_prints_json(config_path, capsys):
    assert main(["-c", str(config_path), "config", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert list(data["nautobot"]["prefix_roles"]) == ["INFRA_LOOPBACK", "CPE_P2P", "MGMT_LAN"]


def test_cli_config_error_exit_1(tmp_path, capsys):
    assert main(["-c", str(tmp_path / "nope.yaml"), "config"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_exclude_mgmt_interfaces(cfg):
    assert cfg.exclude.mgmt_interfaces == ["Loopback64500", "Loopback0", "Loopback1"]


def test_exclude_section_is_optional(tmp_path):
    path = tmp_path / "ndp.yaml"
    path.write_text("paths: {output: /o, inputs: /i}\nnautobot:\n  prefix_roles: {A: {}}\n")
    assert load_config(path).exclude.mgmt_interfaces == []


def test_exclude_stale_max_days_default(cfg):
    assert cfg.exclude.stale_max_days == 30


def test_nautobot_access_defaults(cfg):
    assert cfg.nautobot.url is None
    assert cfg.nautobot.timeout_s == 60
    assert cfg.nautobot.verify_tls is True
    assert cfg.nautobot.proxy is None


@pytest.mark.parametrize("key", ["url", "proxy"])
def test_nautobot_urls_must_be_http(tmp_path, key):
    path = tmp_path / "bad.yaml"
    path.write_text(f"paths: {{output: /x, inputs: /y}}\nnautobot: {{{key}: host.example, prefix_roles: {{A: {{}}}}}}\n")
    with pytest.raises(ConfigError, match=f"nautobot.{key}: Value error, must start with http"):
        load_config(path)


def test_nautobot_access_keys(tmp_path):
    path = tmp_path / "ok.yaml"
    path.write_text(
        "paths: {output: /x, inputs: /y}\n"
        "nautobot: {url: 'https://nautobot.example/', timeout_s: 10, verify_tls: false,"
        " proxy: 'http://proxy.example:3128', prefix_roles: {A: {}}}\n"
    )
    nb = load_config(path).nautobot
    assert (nb.url, nb.timeout_s, nb.verify_tls, nb.proxy) == (
        "https://nautobot.example/", 10, False, "http://proxy.example:3128",
    )
