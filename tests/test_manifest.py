from datetime import datetime
from pathlib import Path

from ndp.manifest import build_manifest, render_readme

NOW = datetime(2026, 10, 9, 5, 40).astimezone()
RESULTS = {
    "publish": {"status": "ok", "started": "s3", "finished": "f3", "error": None, "warnings": [],
                "counts": {"legacy_csv": 3}, "outputs": {"legacy_csv": "/out/discovery.csv.20261009"}},
    "scan": {"status": "warning", "started": "s1", "finished": "f1", "error": None,
             "warnings": ["no exclude list"], "counts": {}, "outputs": {"scan_xml": "/out/nmap/scan-1.xml"}},
    "run": {"status": "ok", "outputs": {}, "warnings": []},
}
SOURCES = {"prefixes": {"system": "nautobot", "url": "https://nautobot.example/", "query": "q",
                        "fetched_at": "t", "items": 3}}


def test_build_manifest(monkeypatch):
    monkeypatch.setenv("NDP_SCANNER_IMAGE", "ghcr.io/example/scanner:1.2.0")
    monkeypatch.delenv("NDP_CONFIG_COMMIT", raising=False)
    m = build_manifest(NOW, Path("/etc/ndp/ndp.yaml"), RESULTS, SOURCES)
    assert list(m["steps"]) == ["scan", "publish"]
    assert m["versions"]["scanner_image"] == "ghcr.io/example/scanner:1.2.0"
    assert m["versions"]["config_commit"] == ""
    assert m["outputs"] == [
        {"name": "scan_xml", "path": "/out/nmap/scan-1.xml", "step": "scan", "rows": None},
        {"name": "legacy_csv", "path": "/out/discovery.csv.20261009", "step": "publish", "rows": 3},
    ]
    assert m["warnings"] == ["scan: no exclude list"]
    assert m["sources"] == SOURCES


def test_manifest_never_contains_communities(monkeypatch):
    monkeypatch.setenv("SNMP_COMMUNITIES", "s3cr3t")
    m = build_manifest(NOW, Path("/c.yaml"), RESULTS, SOURCES)
    assert "s3cr3t" not in str(m)


def test_render_readme():
    m = build_manifest(NOW, Path("/etc/ndp/ndp.yaml"), RESULTS, SOURCES)
    text = render_readme(m, Path("/out"))
    assert text.startswith("# Network discovery output\n")
    assert "## Where the data comes from" in text
    assert "| prefixes | nautobot | https://nautobot.example/ | q | t |  | 3 |" in text
    assert "| `nmap/scan-1.xml` | ndp scan |" in text
    assert "- scan: no exclude list" in text


def test_exclude_outputs_are_described():
    from ndp.manifest import DESCRIPTIONS
    for name in ("exclude_list", "infra_interfaces", "infra_interfaces_latest", "exclude_xml"):
        assert DESCRIPTIONS[name]


def test_fetch_outputs_are_described():
    from ndp.manifest import DESCRIPTIONS
    for name in ("infra_routers", "prefixes"):
        assert DESCRIPTIONS[name]


def test_readme_shows_who_fetched():
    sources = {"prefixes": {**SOURCES["prefixes"], "fetched_by": "ndp fetch"}}
    text = render_readme(build_manifest(NOW, Path("/c.yaml"), RESULTS, sources), Path("/out"))
    assert "| Source | System | URL | Query | Fetched at | Fetched by | Items |" in text
    assert "| prefixes | nautobot | https://nautobot.example/ | q | t | ndp fetch | 3 |" in text
