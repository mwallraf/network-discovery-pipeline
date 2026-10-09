import pytest

from ndp.devices import (
    detect_os_slug, detect_software, device_from_host, normalize_hostname, normalize_port_state,
)
from ndp.nmapxml import HostResult, Interface


def test_normalize_hostname():
    assert normalize_hostname(" PE-01.Example.NET ") == "pe-01"
    assert normalize_hostname("") == ""


@pytest.mark.parametrize("state, expected", [
    ("open", "open"), ("closed", "closed"), ("filtered", "closed"), ("open|filtered", "closed"),
])
def test_normalize_port_state(state, expected):
    assert normalize_port_state(state) == expected


@pytest.mark.parametrize("sysdescr, enterprise, phys, expected", [
    ("ONEOS16-MONO_FT-V5.2R2E7_HA8", "oneAccess", "", "ONEOS16-MONO_FT-V5.2R2E7_HA8"),
    ("Cisco IOS Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.9.4, RELEASE SOFTWARE (fc2)",
     "ciscoSystems", "", "16.9.4"),
    ("Cisco IOS XR Software, Version 7.5.2[Default]", "ciscoSystems", "", ""),
    ("anything", "ciscoSystems", "15.1(2)T, RELEASE", "15.1(2)T"),
    ("short", "x", "saos-10-08", "saos-10-08"),
    ("", "x", "", ""),
])
def test_detect_software(sysdescr, enterprise, phys, expected):
    assert detect_software(sysdescr, enterprise, phys) == expected


@pytest.mark.parametrize("enterprise, software, sysdescr, expected", [
    ("ciena", "saos-06-21", "", "saos6"),
    ("ciena", "saos-05-01", "", "saos5"),
    ("ciena", "saos-10-08", "", "saos10"),
    ("ciena", "other", "", "ciena-generic"),
    ("oneAccess", "ONEOS16-MONO_FT-V5.2R2E7_HA8", "", "oneos5"),
    ("oneAccess", "ONEOS-6.4", "", "oneos6"),
    ("oneAccess", "x", "", "oneos-generic"),
    ("ciscoSystems", "", "Cisco IOS XR Software", "ios-xr"),
    ("ciscoSystems", "", "Cisco IOS Software, ISR", "ios-xe"),
    ("ciscoSystems", "", "Cisco NX-OS", "ios-generic"),
    ("other", "", "", ""),
])
def test_detect_os_slug(enterprise, software, sysdescr, expected):
    assert detect_os_slug(enterprise, software, sysdescr) == expected


def test_device_from_snmp_host():
    host = HostResult(
        ip="192.0.2.1", status="up",
        ports={"ssh": "open", "snmp": "open", "telnet": "filtered"},
        communities=["public"], enterprise="ciscoSystems",
        sysdetails={"sysName": "pe-01.example.net", "sysDescr": "Cisco IOS XR Software",
                    "sysObjectId": "1.3.6.1.4.1.9.1.2658", "physSerial": "SERPE01"},
        interfaces=[Interface(name="Loopback0", if_index=1, addresses=["192.0.2.1/32"])],
    )
    device = device_from_host(host)
    assert device.key == "pe-01"
    assert device.hostname == "pe-01"
    assert device.ips == ["192.0.2.1"]
    assert device.ports == {"ssh": "open", "snmp": "open", "telnet": "closed"}
    assert device.os_slug == "ios-xr"
    assert device.snmp["physSerial"] == "SERPE01"
    assert device.snmp["sysContact"] == ""
    assert device.interfaces[0].name == "Loopback0"


def test_key_falls_back_to_serial_then_ip():
    serial_only = HostResult(ip="192.0.2.2", status="up", sysdetails={"physSerial": "S1"})
    assert device_from_host(serial_only).key == "S1"
    nothing = HostResult(ip="192.0.2.3", status="up")
    assert device_from_host(nothing).key == "192.0.2.3"


def test_public_assumed_when_snmp_answered_without_brute_result():
    host = HostResult(ip="192.0.2.4", status="up", sysdetails={"sysObjectId": "1.3.6.1.4.1.6141"})
    assert device_from_host(host).communities == ["public"]
    assert device_from_host(HostResult(ip="192.0.2.5", status="up")).communities == []


def test_to_dict_shape():
    host = HostResult(ip="192.0.2.1", status="up", enterprise="ciena", sysdetails={"sysName": "sw-1"})
    data = device_from_host(host).to_dict()
    assert list(data) == ["key", "hostname", "status", "mgmt_ip", "mgmt_safe", "mgmt_role", "function",
                          "os_slug", "updates", "ips", "communities", "ports", "snmp", "interfaces"]
    assert data["snmp"]["enterprise"] == "ciena"
    assert data["interfaces"] == []
