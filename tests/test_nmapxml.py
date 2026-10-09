from pathlib import Path

import pytest

from ndp.nmapxml import Interface, NmapXmlError, parse_scan

FIXTURE = Path(__file__).parent / "fixtures" / "scan-basic.xml"


@pytest.fixture(scope="module")
def report():
    return parse_scan(FIXTURE)


def test_summary(report):
    s = report.summary
    assert (s.started, s.started_str) == (1791522000, "Fri Oct  9 05:00:00 2026")
    assert (s.endtime, s.endtime_str) == (1791523800, "Fri Oct  9 05:30:00 2026")
    assert s.elapsed == "1800.12"
    assert (s.hosts_total, s.hosts_up, s.hosts_down) == (5, 4, 1)
    assert s.filename == str(FIXTURE.resolve())


def test_hosts_in_file_order(report):
    assert [(h.ip, h.status) for h in report.hosts] == [
        ("192.0.2.1", "up"), ("198.51.100.1", "up"), ("198.51.100.2", "up"),
        ("203.0.113.5", "up"), ("203.0.113.9", "down"),
    ]


def test_ports_keep_raw_state(report):
    assert report.hosts[0].ports == {"ssh": "open", "telnet": "closed", "bgp": "open", "snmp": "open"}
    assert report.hosts[3].ports == {"ssh": "open", "snmp": "open|filtered"}


def test_snmp_scripts(report):
    pe = report.hosts[0]
    assert pe.communities == ["public"]
    assert pe.enterprise == "ciscoSystems"
    assert pe.sysdetails["sysName"] == "pe-01.example.net"
    assert pe.sysdetails["sysDescr"].startswith("Cisco IOS XR Software, Version 7.5.2[Default]\n")


def test_interfaces_new_format(report):
    assert report.hosts[0].interfaces == [
        Interface(name="Loopback0", if_index=1, if_alias="", services=[], addresses=["192.0.2.1/32"]),
        Interface(name="GigabitEthernet0/0/0/2.100", if_index=12, if_alias="SVC123456 customer-a, site 1",
                  services=["SVC123456"], addresses=["198.51.100.1/30"]),
    ]


def test_old_plain_text_ifalias_output_is_ignored(report):
    assert report.hosts[2].interfaces == []


def test_host_without_scripts(report):
    host = report.hosts[3]
    assert (host.communities, host.enterprise, host.sysdetails, host.interfaces) == ([], "", {}, [])


def test_interface_to_dict():
    i = Interface(name="Gi0", if_index=3, if_alias="x", services=["S1"], addresses=["192.0.2.1/30"])
    assert i.to_dict() == {"name": "Gi0", "ifIndex": 3, "ifAlias": "x", "services": ["S1"], "addresses": ["192.0.2.1/30"]}


def test_truncated_xml_from_interrupted_scan(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text(FIXTURE.read_text()[:2000])
    with pytest.raises(NmapXmlError, match="interrupted scan"):
        parse_scan(path)


def test_missing_runstats(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text('<?xml version="1.0"?><nmaprun start="1"></nmaprun>')
    with pytest.raises(NmapXmlError, match="no run statistics"):
        parse_scan(path)


def test_not_nmap(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text("<html></html>")
    with pytest.raises(NmapXmlError, match="not an nmap XML report"):
        parse_scan(path)


def test_missing_file(tmp_path):
    with pytest.raises(NmapXmlError, match="not found"):
        parse_scan(tmp_path / "nope.xml")
