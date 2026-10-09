import ipaddress

from ndp.exclude import (
    MgmtChoice,
    choose_mgmt,
    excluded_ips,
    interface_ips,
    merge_exclude,
    normalize_ifname,
)
from ndp.inputs import PrefixEntry
from ndp.nmapxml import Interface

PREFIXES = [
    PrefixEntry(ipaddress.ip_network("192.0.2.0/24"), "INFRA_LOOPBACK"),
    PrefixEntry(ipaddress.ip_network("198.51.100.0/24"), "CPE_P2P"),
    PrefixEntry(ipaddress.ip_network("203.0.113.0/24"), "MGMT_LAN"),
]
ORDER = ["INFRA_LOOPBACK", "CPE_P2P", "MGMT_LAN"]
NAMES = ["Loopback64500", "Loopback0", "Loopback1"]


def intf(name, *addresses):
    return Interface(name=name, addresses=list(addresses))


def test_normalize_ifname():
    assert normalize_ifname("Loopback 64500") == normalize_ifname("LOOPBACK64500") == "loopback64500"


def test_interface_ips_strip_length_and_skip_ipv6_and_garbage():
    assert interface_ips(intf("x", "192.0.2.1/32", "2001:db8::1/64", "junk", "192.0.2.1/24")) == ["192.0.2.1"]


def test_first_named_interface_with_mgmt_address_wins():
    interfaces = [intf("Loopback0", "192.0.2.10/32"), intf("Loopback64500", "192.0.2.20/32")]
    assert choose_mgmt(interfaces, PREFIXES, ORDER, NAMES) == MgmtChoice("192.0.2.20", "interface:Loopback64500")


def test_named_interface_outside_mgmt_prefixes_is_skipped():
    interfaces = [intf("Loopback64500", "10.255.0.1/32"), intf("Loopback1", "203.0.113.7/32"), intf("Gi0", "192.0.2.5/32")]
    assert choose_mgmt(interfaces, PREFIXES, ORDER, NAMES) == MgmtChoice("203.0.113.7", "interface:Loopback1")


def test_name_match_ignores_case_and_spaces():
    assert choose_mgmt([intf("loopback 0", "192.0.2.9/32")], PREFIXES, ORDER, NAMES) == MgmtChoice(
        "192.0.2.9", "interface:loopback 0"
    )


def test_secondary_addresses_on_named_interface_use_role_order_then_lowest_ip():
    interfaces = [intf("Loopback0", "203.0.113.1/32", "192.0.2.40/32", "192.0.2.30/32")]
    assert choose_mgmt(interfaces, PREFIXES, ORDER, NAMES) == MgmtChoice("192.0.2.30", "interface:Loopback0")


def test_fallback_first_prefix_role_then_lowest_ip():
    interfaces = [intf("Gi1", "203.0.113.1/30"), intf("Gi2", "198.51.100.9/30"), intf("Gi3", "198.51.100.5/30")]
    assert choose_mgmt(interfaces, PREFIXES, ORDER, NAMES) == MgmtChoice("198.51.100.5", "prefix_role:CPE_P2P")


def test_role_not_in_config_ranks_last():
    prefixes = PREFIXES + [PrefixEntry(ipaddress.ip_network("10.0.0.0/8"), "OTHER")]
    interfaces = [intf("Gi1", "10.1.1.1/30"), intf("Gi2", "203.0.113.1/30")]
    assert choose_mgmt(interfaces, prefixes, ORDER, NAMES) == MgmtChoice("203.0.113.1", "prefix_role:MGMT_LAN")


def test_no_address_in_any_prefix():
    assert choose_mgmt([intf("Gi1", "10.255.0.1/30")], PREFIXES, ORDER, NAMES) == MgmtChoice(None, "none")


def test_no_mgmt_interface_names_configured_uses_prefix_roles():
    interfaces = [intf("Loopback0", "203.0.113.1/32"), intf("Gi1", "192.0.2.7/30")]
    assert choose_mgmt(interfaces, PREFIXES, ORDER, []) == MgmtChoice("192.0.2.7", "prefix_role:INFRA_LOOPBACK")


def test_excluded_ips_are_all_but_keep_sorted_numerically():
    interfaces = [intf("Gi1", "192.0.2.100/30", "192.0.2.9/30"), intf("Lo0", "192.0.2.1/32")]
    assert excluded_ips(interfaces, "192.0.2.1") == ["192.0.2.9", "192.0.2.100"]


def test_merge_never_excludes_another_routers_mgmt_ip():
    entries = [
        {"name": "pe-01", "excluded": ["192.0.2.2", "198.51.100.1"]},
        {"name": "pe-02", "excluded": ["198.51.100.1", "198.51.100.2"]},
    ]
    warnings = []
    assert merge_exclude(entries, {"192.0.2.1": "pe-01", "192.0.2.2": "pe-02"}, warnings) == [
        "198.51.100.1",
        "198.51.100.2",
    ]
    assert warnings == ["192.0.2.2 is an interface address of pe-01 and the mgmt IP of pe-02: kept scannable"]
