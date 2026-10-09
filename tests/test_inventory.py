import ipaddress
from pathlib import Path

from ndp.config import PrefixRole
from ndp.inputs import PrefixEntry
from ndp.inventory import build_inventory, role_for_ip
from ndp.nmapxml import HostResult, parse_scan

FIXTURE = Path(__file__).parent / "fixtures" / "scan-basic.xml"

PREFIXES = [
    PrefixEntry(ipaddress.ip_network("192.0.2.0/24"), "INFRA_LOOPBACK"),
    PrefixEntry(ipaddress.ip_network("198.51.100.0/24"), "CPE_P2P"),
    PrefixEntry(ipaddress.ip_network("203.0.113.0/24"), "MGMT_LAN"),
]
ROLES = {
    "INFRA_LOOPBACK": PrefixRole(function="CORE"),
    "CPE_P2P": PrefixRole(function="CPE"),
    "MGMT_LAN": PrefixRole(function="DCN"),
}


def host(ip, name="", **kw):
    details = {"sysName": name} if name else {}
    details.update(kw.pop("sysdetails", {}))
    return HostResult(ip=ip, status=kw.pop("status", "up"), sysdetails=details, **kw)


def by_key(inventory):
    return {d.key: d for d in inventory.devices}


def test_fixture_inventory():
    inv = build_inventory(parse_scan(FIXTURE).hosts, PREFIXES, ROLES)
    devices = by_key(inv)
    assert list(devices) == ["203.0.113.5", "cpe-01", "pe-01"]
    assert inv.warnings == []

    pe = devices["pe-01"]
    assert pe.ips == ["192.0.2.1", "198.51.100.1"]
    assert (pe.mgmt_ip, pe.mgmt_role, pe.function, pe.mgmt_safe) == ("192.0.2.1", "INFRA_LOOPBACK", "CORE", 1)
    assert pe.updates == 1
    assert pe.ports == {"ssh": "open", "telnet": "closed", "bgp": "open", "snmp": "open"}
    assert pe.snmp["sysUpTime"] == "10d00h00m01.00s (86400100 timeticks)"
    assert [i.name for i in pe.interfaces] == ["Loopback0", "GigabitEthernet0/0/0/2.100"]

    cpe = devices["cpe-01"]
    assert (cpe.mgmt_ip, cpe.function, cpe.os_slug) == ("198.51.100.2", "CPE", "oneos5")
    assert cpe.snmp["physSoftware"] == "ONEOS16-MONO_FT-V5.2R2E7_HA8"

    bare = devices["203.0.113.5"]
    assert (bare.function, bare.communities, bare.ports["snmp"]) == ("DCN", [], "closed")


def test_down_hosts_are_ignored():
    inv = build_inventory([host("192.0.2.9", "x", status="down")], PREFIXES, ROLES)
    assert inv.devices == []


def test_merge_conflict_keeps_first_and_warns():
    hosts = [
        host("192.0.2.1", "dup", sysdetails={"physSerial": "A"}),
        host("192.0.2.2", "dup", sysdetails={"physSerial": "B"}),
    ]
    inv = build_inventory(hosts, PREFIXES, ROLES)
    assert by_key(inv)["dup"].snmp["physSerial"] == "A"
    assert inv.warnings == ["dup: conflicting physSerial 'A' vs 'B' from another IP; kept the first"]


def test_port_goes_from_closed_to_open_but_not_back():
    hosts = [
        host("192.0.2.1", "r", ports={"ssh": "closed", "telnet": "open"}),
        host("192.0.2.2", "r", ports={"ssh": "open", "telnet": "closed"}),
    ]
    device = by_key(build_inventory(hosts, PREFIXES, ROLES))["r"]
    assert device.ports == {"ssh": "open", "telnet": "open"}


def test_mgmt_preference_follows_role_order_then_lowest_ip():
    hosts = [host("198.51.100.7", "r"), host("192.0.2.20", "r"), host("192.0.2.3", "r")]
    device = by_key(build_inventory(hosts, PREFIXES, ROLES))["r"]
    assert (device.mgmt_ip, device.mgmt_role, device.mgmt_safe) == ("192.0.2.3", "INFRA_LOOPBACK", 0)


def test_lowest_ip_is_numeric_not_text():
    hosts = [host("192.0.2.10", "r"), host("192.0.2.9", "r")]
    assert by_key(build_inventory(hosts, PREFIXES, ROLES))["r"].mgmt_ip == "192.0.2.9"


def test_ip_outside_known_prefixes():
    inv = build_inventory([host("10.9.9.9", "x")], PREFIXES, ROLES)
    device = by_key(inv)["x"]
    assert (device.mgmt_ip, device.function, device.mgmt_safe) == ("10.9.9.9", "", 1)
    assert inv.warnings == ["x: no IP inside a known prefix, using 10.9.9.9"]


def test_role_not_in_config_has_no_function_and_lowest_preference():
    prefixes = PREFIXES + [PrefixEntry(ipaddress.ip_network("10.0.0.0/8"), "UNLISTED")]
    hosts = [host("10.1.1.1", "r"), host("198.51.100.9", "r")]
    device = by_key(build_inventory(hosts, prefixes, ROLES))["r"]
    assert device.mgmt_ip == "198.51.100.9"
    only_unlisted = by_key(build_inventory([host("10.1.1.1", "u")], prefixes, ROLES))["u"]
    assert (only_unlisted.mgmt_role, only_unlisted.function) == ("UNLISTED", "")


def test_most_specific_prefix_wins():
    prefixes = [
        PrefixEntry(ipaddress.ip_network("10.0.0.0/16"), "CPE_P2P"),
        PrefixEntry(ipaddress.ip_network("10.0.5.0/24"), "INFRA_LOOPBACK"),
    ]
    assert role_for_ip("10.0.5.1", prefixes) == "INFRA_LOOPBACK"
    assert role_for_ip("10.0.6.1", prefixes) == "CPE_P2P"
    assert role_for_ip("172.16.0.1", prefixes) is None
