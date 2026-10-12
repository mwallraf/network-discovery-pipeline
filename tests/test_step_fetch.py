import json
import os
from datetime import datetime

import pytest

from ndp.config import load_config
from ndp.nautobot import DEVICE_QUERY, NautobotError
from ndp.step_fetch import run_fetch

NOW = datetime(2026, 10, 12, 1, 0).astimezone()
ENV = {"NAUTOBOT_TOKEN": "t0k3n-abc"}
DEVICES = {"data": {"devices": [
    {"name": "pe-01", "role": {"name": "PE"}, "primary_ip4": {"address": "192.0.2.1/32"}},
    {"name": "pe-02", "role": {"name": "PE"}, "primary_ip4": None},
]}}
PREFIXES = {"data": {"prefixes": [
    {"prefix": "192.0.2.0/24", "role": {"name": "INFRA_LOOPBACK"}},
    {"prefix": "198.51.100.0/24", "role": {"name": "CPE_P2P"}},
]}}


def fake_nautobot(devices=DEVICES, prefixes=PREFIXES, calls=None):
    def post(url, body, headers):
        query = json.loads(body)
        if calls is not None:
            calls.append((url, query["variables"]))
        return json.dumps(devices if query["query"] == DEVICE_QUERY else prefixes).encode()
    return post


@pytest.fixture
def ncfg(config_path):
    text = config_path.read_text().replace("nautobot:\n", "nautobot:\n  url: https://nautobot.example/\n", 1)
    config_path.write_text(text)
    return load_config(config_path)


def test_fetch_writes_both_inputs(ncfg):
    calls = []
    result = run_fetch(ncfg, NOW, env=ENV, post=fake_nautobot(calls=calls))
    assert result.status == "warning", result.error
    assert result.warnings == ["infra_routers: skipped pe-02: no mgmt_ip"]
    assert result.counts == {"infra_routers": 1, "prefixes": 2}
    assert calls == [
        ("https://nautobot.example/api/graphql/", {"roles": ["PE"]}),
        ("https://nautobot.example/api/graphql/", {"roles": ["INFRA_LOOPBACK", "CPE_P2P", "MGMT_LAN"]}),
    ]
    routers = json.loads((ncfg.paths.inputs / "infra-routers.json").read_text())
    assert routers["devices"] == [
        {"name": "pe-01", "role": "PE", "mgmt_ip": "192.0.2.1/32"},
        {"name": "pe-02", "role": "PE", "mgmt_ip": None},
    ]
    assert routers["source"] == {
        "system": "nautobot", "url": "https://nautobot.example/", "query": "devices with role in [PE]",
        "fetched_at": NOW.isoformat(timespec="seconds"), "fetched_by": "ndp fetch",
    }
    prefixes = json.loads((ncfg.paths.inputs / "prefixes.json").read_text())
    assert prefixes["prefixes"] == [
        {"prefix": "192.0.2.0/24", "role": "INFRA_LOOPBACK"},
        {"prefix": "198.51.100.0/24", "role": "CPE_P2P"},
    ]
    assert prefixes["source"]["query"] == "prefixes with role in [INFRA_LOOPBACK, CPE_P2P, MGMT_LAN]"
    assert result.outputs == {
        "infra_routers": str(ncfg.paths.inputs / "infra-routers.json"),
        "prefixes": str(ncfg.paths.inputs / "prefixes.json"),
    }


def test_url_required(cfg):
    result = run_fetch(cfg, NOW, env=ENV, post=fake_nautobot())
    assert result.status == "failed" and "nautobot.url" in result.error


def test_token_required(ncfg):
    result = run_fetch(ncfg, NOW, env={}, post=fake_nautobot())
    assert result.status == "failed" and "NAUTOBOT_TOKEN" in result.error


def test_empty_prefixes_fail_and_keep_old_files(ncfg):
    old = (ncfg.paths.inputs / "prefixes.json").read_text()
    result = run_fetch(ncfg, NOW, env=ENV, post=fake_nautobot(prefixes={"data": {"prefixes": []}}))
    assert result.status == "failed"
    assert "no prefixes for roles INFRA_LOOPBACK, CPE_P2P, MGMT_LAN" in result.error
    assert (ncfg.paths.inputs / "prefixes.json").read_text() == old
    assert not (ncfg.paths.inputs / "infra-routers.json").exists()


def test_empty_devices_fail(ncfg):
    result = run_fetch(ncfg, NOW, env=ENV, post=fake_nautobot(devices={"data": {"devices": []}}))
    assert result.status == "failed" and "no devices for roles PE" in result.error


def test_invalid_data_keeps_old_files(ncfg):
    old = (ncfg.paths.inputs / "prefixes.json").read_text()
    bad = {"data": {"devices": [{"name": "pe-01", "role": None, "primary_ip4": {"address": "nope"}}]}}
    result = run_fetch(ncfg, NOW, env=ENV, post=fake_nautobot(devices=bad))
    assert result.status == "failed"
    assert "Nautobot data is not valid" in result.error and "invalid mgmt_ip 'nope'" in result.error
    assert (ncfg.paths.inputs / "prefixes.json").read_text() == old
    assert not (ncfg.paths.inputs / "infra-routers.json").exists()


def test_no_device_roles_skips_infra_routers(ncfg, config_path):
    config_path.write_text(config_path.read_text().replace("  device_roles: [PE]\n", ""))
    cfg = load_config(config_path)
    result = run_fetch(cfg, NOW, env=ENV, post=fake_nautobot())
    assert result.status == "warning"
    assert "nautobot.device_roles is empty; infra-routers.json not fetched" in result.warnings
    assert "infra_routers" not in result.outputs
    assert not (cfg.paths.inputs / "infra-routers.json").exists()


def test_token_never_in_result(ncfg):
    def leaky(url, body, headers):
        raise NautobotError(f"Nautobot returned HTTP 500 for {url}: boom")
    for post in (leaky, fake_nautobot(prefixes={"errors": [{"message": "x"}]})):
        result = run_fetch(ncfg, NOW, env=ENV, post=post)
        assert result.status == "failed"
        assert ENV["NAUTOBOT_TOKEN"] not in result.to_json()


def test_insecure_tls_is_a_warning(ncfg, config_path):
    config_path.write_text(config_path.read_text().replace(
        "  url: https://nautobot.example/\n", "  url: https://nautobot.example/\n  verify_tls: false\n", 1))
    result = run_fetch(load_config(config_path), NOW, env=ENV, post=fake_nautobot())
    assert result.warnings[0] == "TLS certificate of Nautobot not checked (nautobot.verify_tls: false)"


def test_fetch_applies_permissions(ncfg):
    run_fetch(ncfg, NOW, env=ENV, post=fake_nautobot())
    for name in ("infra-routers.json", "prefixes.json"):
        assert os.stat(ncfg.paths.inputs / name).st_mode & 0o777 == 0o664


@pytest.mark.parametrize("devices, prefixes, message", [
    ({"data": {"devices": [{"name": "pe-01", "role": None, "primary_ip4": None}]}}, PREFIXES["data"],
     "no usable devices (IPv4 mgmt_ip) for roles PE"),
    (DEVICES["data"], {"prefixes": [{"prefix": "2001:db8::/32", "role": {"name": "MGMT_LAN"}}]},
     "no usable prefixes (IPv4) for roles INFRA_LOOPBACK, CPE_P2P, MGMT_LAN"),
])
def test_nothing_usable_keeps_old_files(ncfg, devices, prefixes, message):
    old = (ncfg.paths.inputs / "prefixes.json").read_text()
    post = fake_nautobot(devices={"data": devices} if "data" not in devices else devices,
                         prefixes={"data": prefixes} if "data" not in prefixes else prefixes)
    result = run_fetch(ncfg, NOW, env=ENV, post=post)
    assert result.status == "failed" and message in result.error
    assert (ncfg.paths.inputs / "prefixes.json").read_text() == old
    assert not (ncfg.paths.inputs / "infra-routers.json").exists()
