import ipaddress
import json
import re
from pathlib import Path

import pytest

from ndp.inputs import InputError, load_infra_routers, load_prefixes


def write(tmp_path, data):
    path = tmp_path / "prefixes.json"
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return path


def test_loads_fixture(cfg):
    result = load_prefixes(cfg.paths.inputs / "prefixes.json")
    assert result.source["system"] == "nautobot"
    assert [(str(p.network), p.role) for p in result.prefixes] == [
        ("192.0.2.0/24", "INFRA_LOOPBACK"),
        ("198.51.100.0/24", "CPE_P2P"),
        ("203.0.113.0/24", "MGMT_LAN"),
    ]
    assert result.warnings == []


def test_ipv6_prefix_is_skipped_with_warning(tmp_path):
    path = write(tmp_path, {"prefixes": [
        {"prefix": "2001:db8::/32", "role": "MGMT_LAN"},
        {"prefix": "192.0.2.0/24", "role": "MGMT_LAN"},
    ]})
    result = load_prefixes(path)
    assert [str(p.network) for p in result.prefixes] == ["192.0.2.0/24"]
    assert result.warnings == ["skipped IPv6 prefix 2001:db8::/32 (role MGMT_LAN)"]


def test_host_bits_are_accepted(tmp_path):
    path = write(tmp_path, {"prefixes": [{"prefix": "192.0.2.5/24", "role": "A"}]})
    assert load_prefixes(path).prefixes[0].network == ipaddress.ip_network("192.0.2.0/24")


def test_duplicates_are_dropped(tmp_path):
    path = write(tmp_path, {"prefixes": [
        {"prefix": "192.0.2.0/24", "role": "A"},
        {"prefix": "192.0.2.0/24", "role": "B"},
    ]})
    assert [p.role for p in load_prefixes(path).prefixes] == ["A"]


def test_unknown_fields_are_ignored(tmp_path):
    path = write(tmp_path, {"extra": 1, "prefixes": [{"prefix": "192.0.2.0/24", "role": "A", "id": "x"}]})
    assert len(load_prefixes(path).prefixes) == 1


@pytest.mark.parametrize("data, message", [
    ("{not json", "not valid JSON"),
    ({"source": {}}, "'prefixes' must be a list"),
    ({"prefixes": [{"prefix": "192.0.2.0/24"}]}, r"prefixes\[0\] needs 'prefix' and 'role'"),
    ({"prefixes": [{"prefix": "192.0.2.300/24", "role": "A"}]}, r"prefixes\[0\]: invalid prefix"),
])
def test_invalid_input(tmp_path, data, message):
    with pytest.raises(InputError, match=message):
        load_prefixes(write(tmp_path, data))


def test_missing_file(tmp_path):
    with pytest.raises(InputError, match="cannot read"):
        load_prefixes(tmp_path / "nope.json")


FIXTURES = Path(__file__).parent / "fixtures"


def write_infra(tmp_path, data):
    path = tmp_path / "infra-routers.json"
    path.write_text(json.dumps(data))
    return path


def test_load_infra_routers_fixture():
    result = load_infra_routers(FIXTURES / "infra-routers.json")
    assert [(r.name, r.role, r.mgmt_ip) for r in result.routers] == [
        ("pe-01", "PE", "192.0.2.1"),
        ("pe-02", "PE", "192.0.2.2"),
        ("pe-03", "PE", "192.0.2.3"),
        ("pe-04", "PE", "192.0.2.4"),
    ]
    assert result.source["system"] == "nautobot"
    assert result.warnings == []


def test_infra_router_without_mgmt_ip_is_skipped(tmp_path):
    path = write_infra(tmp_path, {"devices": [{"name": "pe-01", "mgmt_ip": None}, {"name": "pe-02", "mgmt_ip": "192.0.2.2"}]})
    result = load_infra_routers(path)
    assert [r.name for r in result.routers] == ["pe-02"]
    assert result.warnings == ["skipped pe-01: no mgmt_ip"]
    assert result.routers[0].role == ""


def test_infra_ipv6_and_duplicates_are_skipped(tmp_path):
    path = write_infra(tmp_path, {"devices": [
        {"name": "a", "mgmt_ip": "2001:db8::1"},
        {"name": "b", "mgmt_ip": "192.0.2.1"},
        {"name": "b", "mgmt_ip": "192.0.2.9"},
        {"name": "c", "mgmt_ip": "192.0.2.1/32"},
    ]})
    result = load_infra_routers(path)
    assert [r.name for r in result.routers] == ["b"]
    assert result.warnings == [
        "skipped a: IPv6 mgmt_ip 2001:db8::1",
        "skipped duplicate router b (192.0.2.9)",
        "skipped duplicate router c (192.0.2.1)",
    ]


@pytest.mark.parametrize("data, message", [
    ({"devices": "x"}, "'devices' must be a list"),
    ({"devices": [{"mgmt_ip": "192.0.2.1"}]}, "devices[0] needs 'name'"),
    ({"devices": [{"name": "a", "mgmt_ip": "nope"}]}, "devices[0]: invalid mgmt_ip 'nope'"),
])
def test_invalid_infra_input(tmp_path, data, message):
    with pytest.raises(InputError, match=re.escape(message)):
        load_infra_routers(write_infra(tmp_path, data))
