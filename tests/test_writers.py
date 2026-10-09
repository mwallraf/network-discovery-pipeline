import csv
import io
from pathlib import Path

from ndp.config import PrefixRole
from ndp.inputs import load_prefixes
from ndp.inventory import build_inventory
from ndp.nmapxml import parse_scan
from ndp.writers import (
    LEGACY_COLUMNS, append_summary_csv, clean_text, legacy_row, services_rows,
    write_legacy_csv, write_services_csv,
)

FIXTURES = Path(__file__).parent / "fixtures"
ROLES = {"INFRA_LOOPBACK": PrefixRole(function="CORE"), "CPE_P2P": PrefixRole(function="CPE"),
         "MGMT_LAN": PrefixRole(function="DCN")}


def devices():
    prefixes = load_prefixes(FIXTURES / "prefixes.json").prefixes
    inv = build_inventory(parse_scan(FIXTURES / "scan-basic.xml").hosts, prefixes, ROLES)
    return [d.to_dict() for d in inv.devices]


def read_csv(path):
    return list(csv.DictReader(io.StringIO(path.read_text())))


def test_clean_text():
    assert clean_text("a,b|c\nd ") == "a_b_c. d"
    assert clean_text(0) == "0"


def test_legacy_columns_exact(tmp_path):
    path = tmp_path / "discovery.csv"
    write_legacy_csv(path, devices(), include_communities=True)
    assert path.read_text().splitlines()[0] == ",".join(LEGACY_COLUMNS)
    assert len(read_csv(path)) == 3


def test_legacy_row_values():
    pe = next(d for d in devices() if d["key"] == "pe-01")
    row = legacy_row(pe)
    assert row == {
        "_key": "pe-01", "_updates": "1", "hostname": "pe-01", "status": "up",
        "telnet": "closed", "ssh": "open", "snmp": "open", "bgp": "open",
        "enterprise": "ciscoSystems", "os_slug": "ios-xr", "function": "CORE",
        "mgmt_ip": "192.0.2.1", "mgmt_safe": "1",
        "sysObjectId": "1.3.6.1.4.1.9.1.2658", "sysContact": "", "sysLocation": "",
        "sysUpTime": "10d00h00m01.00s (86400100 timeticks)", "physSerial": "SERPE01",
        "physSoftware": "", "physDescription": "", "physName": "", "physModel": "ASR-9901",
        "ip": "192.0.2.1|198.51.100.1", "communities": "public",
    }


def test_communities_can_be_left_out():
    pe = next(d for d in devices() if d["key"] == "pe-01")
    assert legacy_row(pe, include_communities=False)["communities"] == ""


def test_hostile_text_keeps_csv_valid(tmp_path):
    device = devices()[0]
    device["snmp"]["sysLocation"] = 'Room 1, "rack 2"\nrow|3'
    path = tmp_path / "d.csv"
    write_legacy_csv(path, [device], include_communities=True)
    rows = read_csv(path)
    assert len(rows) == 1
    assert rows[0]["sysLocation"] == 'Room 1_ "rack 2". row_3'


def test_summary_appends_with_header_once(tmp_path):
    path = tmp_path / "discovery-summary.csv"
    scan = {"started": 1, "started_str": "a", "endtime": 2, "endtime_str": "b", "elapsed": "1.0",
            "hosts_total": 5, "hosts_up": 4, "hosts_down": 1, "filename": "/x/scan.xml"}
    append_summary_csv(path, scan)
    append_summary_csv(path, scan)
    lines = path.read_text().splitlines()
    assert lines[0] == "id,started,started_str,endtime,endtime_str,elapsed,hosts_total,hosts_up,hosts_down,filename"
    assert lines[1] == "1,1,a,2,b,1.0,5,4,1,/x/scan.xml"
    assert len(lines) == 3


def test_services_rows():
    assert services_rows(devices()) == [{
        "service": "SVC123456", "hostname": "pe-01", "mgmt_ip": "192.0.2.1",
        "interface": "GigabitEthernet0/0/0/2.100", "ifAlias": "SVC123456 customer-a, site 1",
        "address": "198.51.100.1/30",
    }]


def test_service_without_address_gets_one_row():
    device = {"key": "r", "hostname": "", "mgmt_ip": "192.0.2.1",
              "interfaces": [{"name": "Gi0", "ifAlias": "S1 S2", "services": ["S1", "S2"], "addresses": []}]}
    rows = services_rows([device])
    assert [(r["service"], r["hostname"], r["address"]) for r in rows] == [("S1", "r", ""), ("S2", "r", "")]


def test_write_services_csv(tmp_path):
    path = tmp_path / "services.csv"
    assert write_services_csv(path, devices()) == 1
    assert read_csv(path)[0]["ifAlias"] == "SVC123456 customer-a, site 1"
