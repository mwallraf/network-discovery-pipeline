# ndp exclude (pass 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `ndp exclude` step: poll the infrastructure routers over SNMP, pick one mgmt IP per router, and write every other router address to `inputs/exclude.txt` so pass 2 (`ndp scan`) polls each router once.

**Architecture:** Pure selection rules live in `src/ndp/exclude.py` (no I/O). The step `src/ndp/step_exclude.py` reads `inputs/infra-routers.json` and `inputs/prefixes.json`, runs nmap with `snmp-brute,snmp-ifalias-service` on the routers' Nautobot mgmt IPs, applies the rules, keeps the previous entry for routers that do not answer, and writes `exclude.txt` plus `infra-interfaces-<date>.json` / `-latest.json`. `ndp scan` already reads `inputs/exclude.txt`; `ndp run` gains `exclude` as an optional first step.

**Tech Stack:** Python 3.11+, pydantic 2, stdlib (`ipaddress`, `json`, `subprocess`, `tempfile`), pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-09-network-discovery-pipeline-design.md` (section 6 input contract, section 7 step `exclude`).

## Global Constraints

- Public repo: only documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, plus 10.255.0.0/24 as "outside every prefix"), invented names, documentation ASN 64500 (`Loopback64500`). No real roles, prefixes, hosts, paths or communities.
- Secrets: `SNMP_COMMUNITIES` from the environment only; written to a 0600 temp file, never on the command line, never in output files or warnings.
- Every step returns a `StepResult`; exit codes 0 ok / 2 warnings / 1 failed. A failed step never replaces a `*-latest` file or `exclude.txt`.
- Atomic writes (`write_text_atomic`), `*-latest` links via `atomic_symlink`, permissions via `apply_perms`.
- File names use local time: `exclude-<YYYYmmddTHHMMSS>.xml`, `infra-interfaces-<YYYYmmdd>.json`.
- Run tests with `.venv/bin/pytest -q` from the repo root. Commits end with the session attribution trailer.

Deliberate deviation from spec section 6: a router entry whose `mgmt_ip` is missing or null is skipped with a warning instead of failing the step (a Nautobot device without a primary IP must not block pass 1 for all routers). A missing `name` or an invalid IP still fails the step.

Decision taken in this plan (not in the spec): inside `ndp run`, a failed `exclude` becomes a warning and the run continues, because the previous `exclude.txt` stays valid. `ndp exclude` on its own still exits 1.

## Review Focus

1. An address of router A that is the mgmt IP of router B (shared or misconfigured address): must stay scannable, with a warning. Test: `test_merge_never_excludes_another_routers_mgmt_ip` (Task 2).
2. Interface names in other spellings (`loopback 64500`, `LOOPBACK0`): must match the configured names. Tests: `test_name_match_ignores_case_and_spaces` (Task 2), fixture router pe-03 (Task 3).
3. A router that answers SNMP but returns no structured interfaces (old plain-text `snmp-ifalias-service` output, or the walk failed): must count as "no answer" (keep previous / warn), never as "exclude nothing". Test: `test_plaintext_interface_output_counts_as_no_answer` (Task 3).
4. Nautobot mgmt IPs given with a prefix length (`192.0.2.1/32`, the Nautobot primary IP format): must be accepted. Test: `test_load_infra_routers_fixture` (Task 1, fixture uses `/32`).
5. `ndp run` without `infra-routers.json` or with a failing pass 1: the run must continue with the previous exclude list and warn. Test: `test_exclude_failure_does_not_stop_the_run` (Task 4).

---

### Task 1: Config section and infra-routers input

**Files:**
- Modify: `src/ndp/config.py` (add `Exclude` model and `Config.exclude`)
- Modify: `src/ndp/inputs.py` (add `InfraRouter`, `InfraInput`, `load_infra_routers`)
- Create: `tests/fixtures/infra-routers.json`
- Modify: `tests/conftest.py` (add `exclude:` to `CONFIG_TEMPLATE`)
- Test: `tests/test_config.py`, `tests/test_inputs.py`

**Interfaces:**
- Consumes: `inputs._read_json(path) -> dict`, `InputError`.
- Produces:
  - `config.Exclude(mgmt_interfaces: list[str] = [])`, `Config.exclude: Exclude`.
  - `inputs.InfraRouter(name: str, role: str, mgmt_ip: str)` (frozen dataclass; `mgmt_ip` is a bare IPv4 string).
  - `inputs.InfraInput(source: dict, routers: list[InfraRouter], warnings: list[str])`.
  - `inputs.load_infra_routers(path: Path) -> InfraInput`.

- [ ] **Step 1: Write the fixture**

`tests/fixtures/infra-routers.json`:

```json
{
  "source": {
    "system": "nautobot",
    "url": "https://nautobot.example/",
    "query": "devices with role in [PE]",
    "fetched_at": "2026-10-09T04:26:00+02:00"
  },
  "devices": [
    {"name": "pe-01", "role": "PE", "mgmt_ip": "192.0.2.1/32"},
    {"name": "pe-02", "role": "PE", "mgmt_ip": "192.0.2.2"},
    {"name": "pe-03", "role": "PE", "mgmt_ip": "192.0.2.3/32"},
    {"name": "pe-04", "role": "PE", "mgmt_ip": "192.0.2.4"}
  ]
}
```

In `tests/conftest.py`, append to `CONFIG_TEMPLATE` (after the `nautobot:` block, before the closing `"""`):

```
exclude:
  mgmt_interfaces: [Loopback64500, Loopback0, Loopback1]
```

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_config.py`:

```python
def test_exclude_mgmt_interfaces(cfg):
    assert cfg.exclude.mgmt_interfaces == ["Loopback64500", "Loopback0", "Loopback1"]


def test_exclude_section_is_optional(tmp_path):
    path = tmp_path / "ndp.yaml"
    path.write_text("paths: {output: /o, inputs: /i}\nnautobot:\n  prefix_roles: {A: {}}\n")
    assert load_config(path).exclude.mgmt_interfaces == []
```

Append to `tests/test_inputs.py` (add `import re` and `from pathlib import Path` at the top if missing, and extend the import to `from ndp.inputs import InputError, load_infra_routers, load_prefixes`):

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/bin/pytest -q tests/test_config.py tests/test_inputs.py`
Expected: FAIL — `ImportError: cannot import name 'load_infra_routers'` (collection error for test_inputs) and `extra inputs are not permitted` / `AttributeError: 'Config' object has no attribute 'exclude'` for test_config.

- [ ] **Step 4: Implement**

In `src/ndp/config.py`, add after `class Housekeeping`:

```python
class Exclude(_Model):
    # priority order; names are compared case-insensitively, spaces ignored
    mgmt_interfaces: list[str] = Field(default_factory=list)
```

and in `class Config` add after `housekeeping`:

```python
    exclude: Exclude = Field(default_factory=Exclude)
```

In `src/ndp/inputs.py`, add after `PrefixInput`:

```python
@dataclass(frozen=True)
class InfraRouter:
    name: str
    role: str
    mgmt_ip: str


@dataclass
class InfraInput:
    source: dict
    routers: list[InfraRouter]
    warnings: list[str] = field(default_factory=list)
```

and at the end of the file:

```python
def load_infra_routers(path: Path) -> InfraInput:
    data = _read_json(path)
    entries = data.get("devices")
    if not isinstance(entries, list):
        raise InputError(f"{path}: 'devices' must be a list")
    routers: list[InfraRouter] = []
    warnings: list[str] = []
    names: set[str] = set()
    ips: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not entry.get("name"):
            raise InputError(f"{path}: devices[{index}] needs 'name'")
        name = str(entry["name"])
        if not entry.get("mgmt_ip"):
            # a device without a primary IP in Nautobot must not block the others
            warnings.append(f"skipped {name}: no mgmt_ip")
            continue
        try:
            ip = ipaddress.ip_interface(str(entry["mgmt_ip"])).ip
        except ValueError:
            raise InputError(f"{path}: devices[{index}]: invalid mgmt_ip {entry['mgmt_ip']!r}") from None
        if ip.version != 4:
            warnings.append(f"skipped {name}: IPv6 mgmt_ip {ip}")
            continue
        if name in names or str(ip) in ips:
            warnings.append(f"skipped duplicate router {name} ({ip})")
            continue
        names.add(name)
        ips.add(str(ip))
        routers.append(InfraRouter(name=name, role=str(entry.get("role") or ""), mgmt_ip=str(ip)))
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    return InfraInput(source=source, routers=routers, warnings=warnings)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest -q`
Expected: all pass (129 existing + 8 new).

- [ ] **Step 6: Commit**

```bash
git add src/ndp/config.py src/ndp/inputs.py tests/conftest.py tests/fixtures/infra-routers.json tests/test_config.py tests/test_inputs.py
git commit -m "feat: exclude config section and infra-routers input"
```

---

### Task 2: Mgmt-IP selection rules

**Files:**
- Create: `src/ndp/exclude.py`
- Test: `tests/test_exclude.py`

**Interfaces:**
- Consumes: `inventory.role_for_ip(ip: str, prefixes: list[PrefixEntry]) -> str | None` (most specific prefix wins), `inputs.PrefixEntry`, `nmapxml.Interface(name, if_index, if_alias, services, addresses)` where `addresses` are CIDR strings.
- Produces:
  - `MgmtChoice(ip: str | None, reason: str)` frozen dataclass; reason is `interface:<name as reported>`, `prefix_role:<role>` or `none`.
  - `normalize_ifname(name: str) -> str`
  - `interface_ips(interface: Interface) -> list[str]` (IPv4, no prefix length, unique, input order)
  - `router_ips(interfaces: list[Interface]) -> list[str]` (unique, numerically sorted)
  - `choose_mgmt(interfaces, prefixes, role_order: list[str], mgmt_interfaces: list[str]) -> MgmtChoice`
  - `excluded_ips(interfaces, keep: str) -> list[str]` (numerically sorted)
  - `merge_exclude(entries: list[dict], protected: dict[str, str], warnings: list[str]) -> list[str]` — `entries` have `name` and `excluded`; `protected` maps IP → router name whose mgmt IP it is.

- [ ] **Step 1: Write the failing tests**

`tests/test_exclude.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest -q tests/test_exclude.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'ndp.exclude'`.

- [ ] **Step 3: Implement**

`src/ndp/exclude.py`:

```python
"""Pass 1 rules: pick one mgmt IP per infrastructure router, exclude its other addresses."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ndp.inputs import PrefixEntry
from ndp.inventory import role_for_ip
from ndp.nmapxml import Interface


@dataclass(frozen=True)
class MgmtChoice:
    ip: str | None
    reason: str  # "interface:<name>", "prefix_role:<role>" or "none"


def normalize_ifname(name: str) -> str:
    return name.replace(" ", "").lower()


def interface_ips(interface: Interface) -> list[str]:
    """IPv4 addresses of an interface, without prefix length."""
    ips: list[str] = []
    for address in interface.addresses:
        try:
            ip = ipaddress.ip_interface(address).ip
        except ValueError:
            continue
        if ip.version == 4 and str(ip) not in ips:
            ips.append(str(ip))
    return ips


def router_ips(interfaces: list[Interface]) -> list[str]:
    ips = {ip for interface in interfaces for ip in interface_ips(interface)}
    return sorted(ips, key=ipaddress.IPv4Address)


def _best(ips: list[str], prefixes: list[PrefixEntry], role_order: list[str]) -> tuple[str, str] | None:
    """Address in the highest-priority role, lowest address on a tie; roles not in the order rank last."""
    ranked = []
    for ip in ips:
        role = role_for_ip(ip, prefixes)
        if role is None:
            continue
        rank = role_order.index(role) if role in role_order else len(role_order)
        ranked.append((rank, ipaddress.IPv4Address(ip), role))
    if not ranked:
        return None
    _, address, role = min(ranked)
    return str(address), role


def choose_mgmt(
    interfaces: list[Interface],
    prefixes: list[PrefixEntry],
    role_order: list[str],
    mgmt_interfaces: list[str],
) -> MgmtChoice:
    by_name: dict[str, Interface] = {}
    for interface in interfaces:
        by_name.setdefault(normalize_ifname(interface.name), interface)
    for wanted in mgmt_interfaces:
        interface = by_name.get(normalize_ifname(wanted))
        if interface is None:
            continue
        best = _best(interface_ips(interface), prefixes, role_order)
        if best:
            return MgmtChoice(best[0], f"interface:{interface.name}")
    best = _best(router_ips(interfaces), prefixes, role_order)
    if best:
        return MgmtChoice(best[0], f"prefix_role:{best[1]}")
    return MgmtChoice(None, "none")


def excluded_ips(interfaces: list[Interface], keep: str) -> list[str]:
    return [ip for ip in router_ips(interfaces) if ip != keep]


def merge_exclude(entries: list[dict], protected: dict[str, str], warnings: list[str]) -> list[str]:
    """Union of every router's excluded addresses; a router's mgmt IP is never excluded."""
    result: set[str] = set()
    for entry in entries:
        for ip in entry["excluded"]:
            owner = protected.get(ip)
            if owner is not None and owner != entry["name"]:
                warnings.append(f"{ip} is an interface address of {entry['name']} and the mgmt IP of {owner}: kept scannable")
                continue
            result.add(ip)
    return sorted(result, key=ipaddress.IPv4Address)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest -q tests/test_exclude.py`
Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add src/ndp/exclude.py tests/test_exclude.py
git commit -m "feat: mgmt IP selection rules for the exclude list"
```

---

### Task 3: The `exclude` step

**Files:**
- Modify: `src/ndp/files.py` (add `write_private_file`; add dated patterns)
- Modify: `src/ndp/step_scan.py` (use `write_private_file` for the communities file)
- Create: `src/ndp/step_exclude.py`
- Create: `tests/fixtures/exclude-basic.xml`
- Test: `tests/test_files.py`, `tests/test_step_exclude.py`

**Interfaces:**
- Consumes: `load_infra_routers`, `load_prefixes`, `communities_from_env`, `parse_scan` (`HostResult.ip`, `HostResult.interfaces`), `choose_mgmt`, `excluded_ips`, `merge_exclude`, `write_text_atomic`, `atomic_symlink`, `apply_perms`, `Config.exclude.mgmt_interfaces`, `Config.nautobot.prefix_roles`, `Config.scans_dir`.
- Produces:
  - `files.write_private_file(path: Path, text: str) -> None` (mode 0600, fails if the file exists).
  - `step_exclude.build_exclude_command(scanner, targets_file, communities_file, out_xml) -> list[str]`.
  - `step_exclude.run_exclude(cfg, now, env=None, runner=subprocess.run) -> StepResult` with
    `outputs` keys `exclude_list`, `infra_interfaces`, `infra_interfaces_latest`, `exclude_xml` and
    `counts` keys `routers`, `answered`, `stale`, `unseen`, `exclude_list`, `infra_interfaces`.
  - File `infra-interfaces-<date>.json`: `{"generated_at", "source", "scan_xml", "warnings", "routers": [entry], "exclude": [ip]}`; entry = `{"name", "role", "nautobot_ip", "mgmt_ip", "mgmt_reason", "last_seen", "stale", "interfaces", "excluded"}`.

- [ ] **Step 1: Write the failing file tests**

In `tests/test_files.py`, extend the import with `write_private_file`, then append:

```python
def test_write_private_file_is_0600_and_never_overwrites(tmp_path):
    path = tmp_path / "secret.txt"
    write_private_file(path, "a\n")
    assert path.read_text() == "a\n"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_private_file(path, "b\n")


def test_housekeeping_deletes_old_exclude_files(tmp_path):
    (tmp_path / "nmap").mkdir()
    old = [tmp_path / "nmap" / "exclude-20260801T043000.xml", tmp_path / "infra-interfaces-20260801.json"]
    for path in old:
        path.write_text("x")
        age(path, 60)
    assert sorted(housekeeping(tmp_path, keep_days=30, now=NOW)) == sorted(old)
```

(Add `import pytest` at the top of `tests/test_files.py` if it is not there.)

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest -q tests/test_files.py`
Expected: FAIL — `ImportError: cannot import name 'write_private_file'`.

- [ ] **Step 3: Implement the file helpers and use them in scan**

In `src/ndp/files.py`, extend `DATED_PATTERNS`:

```python
DATED_PATTERNS = (
    "nmap/scan-2*.xml",
    "nmap/scan-2*.txt",
    "nmap/exclude-2*.xml",
    "discovery.csv.2*",
    "devices-2*.json",
    "infra-interfaces-2*.json",
    "services-2*.csv",
    "run-2*.json",
)
```

and add after `write_text_atomic`:

```python
def write_private_file(path: Path, text: str) -> None:
    """Create a file only the owner can read (secrets); never overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
```

In `src/ndp/step_scan.py`, change the import to `from ndp.files import apply_perms, atomic_symlink, write_private_file` and replace

```python
        fd = os.open(communities_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(communities) + "\n")
```

with

```python
        write_private_file(communities_file, "\n".join(communities) + "\n")
```

Remove `import os` from `step_scan.py` if nothing else uses it.

Run: `.venv/bin/pytest -q tests/test_files.py tests/test_step_scan.py`
Expected: all pass.

- [ ] **Step 4: Write the XML fixture**

`tests/fixtures/exclude-basic.xml` — pe-01 has a configured mgmt loopback, pe-02 has none (prefix-role fallback), pe-03 spells its loopback `loopback 64500` and its Nautobot IP is on another interface (mismatch), pe-04 does not answer:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -n -Pn -sU -p 161 --script snmp-brute,snmp-ifalias-service" start="1791519960" startstr="Fri Oct  9 04:26:00 2026" version="7.99" xmloutputversion="1.05">
<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.1" addrtype="ipv4"/>
<ports><port protocol="udp" portid="161"><state state="open" reason="udp-response" reason_ttl="0"/>
<script id="snmp-brute" output="public - Valid credentials"><table><elem key="password">public</elem><elem key="state">Valid credentials</elem></table></script>
<script id="snmp-ifalias-service" output="..."><table key="Loopback0"><elem key="ifIndex">1</elem><table key="addresses"><elem>192.0.2.1/32</elem></table></table><table key="Loopback10"><elem key="ifIndex">2</elem><table key="addresses"><elem>192.0.2.50/32</elem></table></table><table key="GigabitEthernet0/0/0/1"><elem key="ifIndex">3</elem><elem key="ifAlias">SVC100001 customer-a</elem><table key="services"><elem>SVC100001</elem></table><table key="addresses"><elem>198.51.100.1/30</elem></table></table><table key="GigabitEthernet0/0/0/2"><elem key="ifIndex">4</elem><table key="addresses"><elem>198.51.100.5/30</elem><elem>10.255.0.1/24</elem></table></table></script>
</port></ports></host>
<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.2" addrtype="ipv4"/>
<ports><port protocol="udp" portid="161"><state state="open" reason="udp-response" reason_ttl="0"/>
<script id="snmp-brute" output="public - Valid credentials"><table><elem key="password">public</elem><elem key="state">Valid credentials</elem></table></script>
<script id="snmp-ifalias-service" output="..."><table key="MgmtEth0/RP0/CPU0/0"><elem key="ifIndex">1</elem><table key="addresses"><elem>192.0.2.2/24</elem></table></table><table key="Bundle-Ether1"><elem key="ifIndex">2</elem><table key="addresses"><elem>198.51.100.9/30</elem></table></table><table key="Loopback20"><elem key="ifIndex">3</elem><table key="addresses"><elem>203.0.113.10/32</elem></table></table></script>
</port></ports></host>
<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.3" addrtype="ipv4"/>
<ports><port protocol="udp" portid="161"><state state="open" reason="udp-response" reason_ttl="0"/>
<script id="snmp-brute" output="private - Valid credentials"><table><elem key="password">private</elem><elem key="state">Valid credentials</elem></table></script>
<script id="snmp-ifalias-service" output="..."><table key="loopback 64500"><elem key="ifIndex">1</elem><table key="addresses"><elem>192.0.2.30/32</elem></table></table><table key="Loopback1"><elem key="ifIndex">2</elem><table key="addresses"><elem>192.0.2.3/32</elem></table></table><table key="TenGigE0/0/0/0"><elem key="ifIndex">3</elem><table key="addresses"><elem>198.51.100.13/30</elem></table></table></script>
</port></ports></host>
<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.4" addrtype="ipv4"/>
<ports><port protocol="udp" portid="161"><state state="open|filtered" reason="no-response" reason_ttl="0"/></port></ports></host>
<runstats><finished time="1791520060" timestr="Fri Oct  9 04:27:40 2026" summary="4 IP addresses (4 hosts up) scanned in 100.00 seconds" elapsed="100.00" exit="success"/><hosts up="4" down="0" total="4"/></runstats>
</nmaprun>
```

- [ ] **Step 5: Write the failing step tests**

`tests/test_step_exclude.py`:

```python
import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from ndp.step_exclude import build_exclude_command, run_exclude

FIXTURES = Path(__file__).parent / "fixtures"
XML = FIXTURES / "exclude-basic.xml"
NOW = datetime(2026, 10, 9, 4, 30, 0).astimezone()
ENV = {"SNMP_COMMUNITIES": "public,private"}
EXPECTED = [
    "10.255.0.1", "192.0.2.3", "192.0.2.50", "198.51.100.1",
    "198.51.100.5", "198.51.100.9", "198.51.100.13", "203.0.113.10",
]
NO_ANSWER = """<?xml version="1.0"?>
<nmaprun start="1" startstr="x"><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
<ports><port protocol="udp" portid="161"><state state="open|filtered"/></port></ports></host>
<runstats><finished time="2" timestr="y" elapsed="1.0"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>
"""
OLD_SCRIPT = NO_ANSWER.replace(
    '<state state="open|filtered"/>',
    '<state state="open"/><script id="snmp-ifalias-service" '
    'output="Gi0/0 = &lt;No services&gt; (IP: 192.0.2.1, Subnet Mask: 255.255.255.255)"/>',
)


class FakeNmap:
    """Records what nmap would get and writes fixture output."""

    def __init__(self, xml=XML, returncode=0, stderr=""):
        self.xml, self.returncode, self.stderr = xml, returncode, stderr

    def __call__(self, cmd, **kwargs):
        self.cmd = cmd
        self.targets = Path(cmd[cmd.index("-iL") + 1]).read_text()
        script_args = cmd[cmd.index("--script-args") + 1]
        self.communities_path = Path(script_args.split(",")[0].split("=", 1)[1])
        self.mode = self.communities_path.stat().st_mode & 0o777
        if self.xml is not None:
            shutil.copy(self.xml, cmd[cmd.index("-oX") + 1])
        return subprocess.CompletedProcess(cmd, self.returncode, "", self.stderr)


@pytest.fixture
def routers(cfg):
    shutil.copy(FIXTURES / "infra-routers.json", cfg.paths.inputs / "infra-routers.json")


def exclude_lines(cfg):
    return (cfg.paths.inputs / "exclude.txt").read_text().splitlines()


def latest_doc(cfg):
    return json.loads((cfg.paths.output / "infra-interfaces-latest.json").read_text())


def write_previous(cfg, doc):
    out = cfg.paths.output
    out.mkdir(parents=True, exist_ok=True)
    (out / "infra-interfaces-20261008.json").write_text(json.dumps(doc))
    os.symlink("infra-interfaces-20261008.json", out / "infra-interfaces-latest.json")


def test_build_exclude_command(cfg, tmp_path):
    cmd = build_exclude_command(cfg.scanner, tmp_path / "t.txt", tmp_path / "c.txt", tmp_path / "exclude-x.xml")
    assert cmd == [
        "nmap", "-n", "-Pn", "-sU", "-p", "161", "-T4",
        "--script", "snmp-brute,snmp-ifalias-service",
        "--script-args", f"snmp-brute.communitiesdb={tmp_path / 'c.txt'},snmp.timeout=4000",
        "-iL", str(tmp_path / "t.txt"), "-oX", str(tmp_path / "exclude-x.xml"),
    ]


def test_exclude_success(cfg, routers):
    fake = FakeNmap()
    result = run_exclude(cfg, NOW, env=ENV, runner=fake)
    assert result.error is None
    assert fake.targets == "192.0.2.1\n192.0.2.2\n192.0.2.3\n192.0.2.4\n"
    assert fake.mode == 0o600 and not fake.communities_path.exists()
    assert not any("private" in part for part in fake.cmd)
    assert exclude_lines(cfg) == EXPECTED
    assert result.counts == {
        "routers": 4, "answered": 3, "stale": 0, "unseen": 1, "exclude_list": 8, "infra_interfaces": 3,
    }
    out = cfg.paths.output
    assert os.readlink(out / "infra-interfaces-latest.json") == "infra-interfaces-20261009.json"
    assert result.outputs == {
        "exclude_list": str(cfg.paths.inputs / "exclude.txt"),
        "infra_interfaces": str(out / "infra-interfaces-20261009.json"),
        "infra_interfaces_latest": str(out / "infra-interfaces-latest.json"),
        "exclude_xml": str(cfg.scans_dir / "exclude-20261009T043000.xml"),
    }


def test_mgmt_choice_per_router(cfg, routers):
    run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    doc = latest_doc(cfg)
    got = {r["name"]: (r["mgmt_ip"], r["mgmt_reason"], r["excluded"]) for r in doc["routers"]}
    assert got == {
        "pe-01": ("192.0.2.1", "interface:Loopback0", ["10.255.0.1", "192.0.2.50", "198.51.100.1", "198.51.100.5"]),
        "pe-02": ("192.0.2.2", "prefix_role:INFRA_LOOPBACK", ["198.51.100.9", "203.0.113.10"]),
        "pe-03": ("192.0.2.30", "interface:loopback 64500", ["192.0.2.3", "198.51.100.13"]),
    }
    pe01 = doc["routers"][0]
    assert pe01["nautobot_ip"] == "192.0.2.1" and pe01["role"] == "PE" and pe01["stale"] is False
    assert pe01["last_seen"] == NOW.isoformat(timespec="seconds")
    assert pe01["interfaces"][2]["services"] == ["SVC100001"]
    assert doc["source"]["system"] == "nautobot"
    assert doc["exclude"] == EXPECTED
    assert "public" not in json.dumps(doc) and "private" not in json.dumps(doc)


def test_mismatch_and_unseen_are_warnings(cfg, routers):
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.status == "warning"
    assert result.warnings == [
        "pe-03: SNMP mgmt IP 192.0.2.30 (interface:loopback 64500) differs from Nautobot 192.0.2.3; using 192.0.2.30",
        "pe-04 (192.0.2.4): no SNMP answer and no earlier result; nothing excluded for this router",
    ]


def test_unanswered_router_keeps_previous_entry(cfg, routers):
    write_previous(cfg, {
        "routers": [{
            "name": "pe-04", "role": "PE", "nautobot_ip": "192.0.2.4", "mgmt_ip": "192.0.2.4",
            "mgmt_reason": "interface:Loopback0", "last_seen": "2026-10-08T04:30:00+02:00",
            "stale": False, "interfaces": [], "excluded": ["198.51.100.17", "not-an-ip"],
        }],
        "exclude": ["198.51.100.17"],
    })
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert "198.51.100.17" in exclude_lines(cfg)
    assert result.counts["stale"] == 1 and result.counts["unseen"] == 0
    assert "pe-04 (192.0.2.4): no SNMP answer; kept 1 excluded IPs from 2026-10-08T04:30:00+02:00" in result.warnings
    entry = next(r for r in latest_doc(cfg)["routers"] if r["name"] == "pe-04")
    assert entry["stale"] is True
    assert entry["last_seen"] == "2026-10-08T04:30:00+02:00"
    assert entry["excluded"] == ["198.51.100.17"]


def test_router_without_address_in_any_prefix(cfg, routers, tmp_path):
    xml = tmp_path / "outside.xml"
    xml.write_text(XML.read_text().replace("192.0.2.1/32", "10.255.9.1/32").replace(
        "192.0.2.50/32", "10.255.9.2/32").replace("198.51.100.1/30", "10.255.9.5/30").replace(
        "198.51.100.5/30", "10.255.9.9/30"))
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=xml))
    pe01 = next(r for r in latest_doc(cfg)["routers"] if r["name"] == "pe-01")
    assert pe01["mgmt_ip"] is None and pe01["mgmt_reason"] == "none"
    assert "pe-01: no interface address inside a discovery prefix; only the Nautobot IP 192.0.2.1 stays scannable" in result.warnings
    assert "192.0.2.1" not in exclude_lines(cfg)
    assert "10.255.9.1" in exclude_lines(cfg)


def test_big_drop_in_excluded_ips_is_a_warning(cfg, routers):
    write_previous(cfg, {"routers": [], "exclude": [f"198.51.100.{i}" for i in range(100, 120)]})
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert any(w.startswith("excluded IPs dropped from 20 to 8") for w in result.warnings)


def test_no_router_answers_fails_and_keeps_previous_exclude(cfg, routers, tmp_path):
    (cfg.paths.inputs / "exclude.txt").write_text("198.51.100.99\n")
    xml = tmp_path / "none.xml"
    xml.write_text(NO_ANSWER)
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=xml))
    assert result.status == "failed"
    assert "no infrastructure router answered SNMP" in result.error
    assert exclude_lines(cfg) == ["198.51.100.99"]
    assert not (cfg.paths.output / "infra-interfaces-latest.json").exists()


def test_plaintext_interface_output_counts_as_no_answer(cfg, routers, tmp_path):
    xml = tmp_path / "old.xml"
    xml.write_text(OLD_SCRIPT)
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=xml))
    assert result.status == "failed"
    assert "no infrastructure router answered SNMP" in result.error


def test_nmap_failure_keeps_previous_exclude(cfg, routers):
    (cfg.paths.inputs / "exclude.txt").write_text("198.51.100.99\n")
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap(xml=None, returncode=1, stderr="boom"))
    assert result.error == "nmap exited with 1: boom"
    assert exclude_lines(cfg) == ["198.51.100.99"]


def test_missing_infra_routers(cfg):
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.status == "failed" and "infra-routers.json" in result.error


def test_missing_communities(cfg, routers):
    result = run_exclude(cfg, NOW, env={}, runner=FakeNmap())
    assert result.status == "failed" and "SNMP_COMMUNITIES" in result.error


def test_no_routers(cfg):
    (cfg.paths.inputs / "infra-routers.json").write_text(json.dumps({"devices": []}))
    result = run_exclude(cfg, NOW, env=ENV, runner=FakeNmap())
    assert result.error == "no IPv4 routers in infra-routers.json"
```

- [ ] **Step 6: Run to verify they fail**

Run: `.venv/bin/pytest -q tests/test_step_exclude.py`
Expected: FAIL — `ModuleNotFoundError: No module named 'ndp.step_exclude'`.

- [ ] **Step 7: Implement the step**

`src/ndp/step_exclude.py`:

```python
"""ndp exclude: pass 1, SNMP on infrastructure routers -> exclude.txt for pass 2."""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
import tempfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from ndp.config import Config, ConfigError, Scanner, communities_from_env
from ndp.exclude import choose_mgmt, excluded_ips, merge_exclude
from ndp.files import apply_perms, atomic_symlink, write_private_file, write_text_atomic
from ndp.inputs import InputError, load_infra_routers, load_prefixes
from ndp.nmapxml import NmapXmlError, parse_scan
from ndp.result import StepResult

log = logging.getLogger(__name__)

EXCLUDE_SCRIPTS = "snmp-brute,snmp-ifalias-service"
# warn when fewer than this fraction of the previous run's excluded IPs remain
MAX_DROP = 0.5


def build_exclude_command(scanner: Scanner, targets_file: Path, communities_file: Path, out_xml: Path) -> list[str]:
    return [
        scanner.nmap_path,
        "-n",
        "-Pn",
        "-sU",
        "-p", "161",
        f"-T{scanner.timing}",
        "--script", EXCLUDE_SCRIPTS,
        "--script-args", f"snmp-brute.communitiesdb={communities_file},snmp.timeout={scanner.snmp_timeout_ms}",
        "-iL", str(targets_file),
        "-oX", str(out_xml),
    ]


def _read_previous(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _ipv4_list(values) -> list[str]:
    result = []
    for value in values if isinstance(values, list) else []:
        try:
            result.append(str(ipaddress.IPv4Address(str(value))))
        except ValueError:
            continue
    return result


def run_exclude(cfg: Config, now: datetime, env: Mapping[str, str] | None = None, runner=subprocess.run) -> StepResult:
    result = StepResult("exclude")
    try:
        infra = load_infra_routers(cfg.paths.inputs / "infra-routers.json")
        prefix_input = load_prefixes(cfg.paths.inputs / "prefixes.json")
        communities = communities_from_env(env)
    except (InputError, ConfigError) as exc:
        result.error = str(exc)
        return result
    result.warnings.extend(infra.warnings)
    result.warnings.extend(prefix_input.warnings)
    if not infra.routers:
        result.error = "no IPv4 routers in infra-routers.json"
        return result

    cfg.scans_dir.mkdir(parents=True, exist_ok=True)
    xml = cfg.scans_dir / f"exclude-{now:%Y%m%dT%H%M%S}.xml"
    with tempfile.TemporaryDirectory(prefix="ndp-") as tmp:
        communities_file = Path(tmp) / "communities.txt"
        write_private_file(communities_file, "\n".join(communities) + "\n")
        targets_file = Path(tmp) / "targets.txt"
        targets_file.write_text("\n".join(router.mgmt_ip for router in infra.routers) + "\n")
        cmd = build_exclude_command(cfg.scanner, targets_file, communities_file, xml)
        log.info("running: %s", " ".join(cmd))
        try:
            proc = runner(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except OSError as exc:
            result.error = f"cannot run nmap ({cfg.scanner.nmap_path}): {exc}"
            return result
    if proc.returncode != 0:
        result.error = f"nmap exited with {proc.returncode}: {(proc.stderr or '').strip()[-500:]}"
        return result
    try:
        report = parse_scan(xml)
    except NmapXmlError as exc:
        result.error = str(exc)
        return result

    # no structured interfaces (no answer, or old plain-text script output) = no answer
    interfaces_by_ip = {host.ip: host.interfaces for host in report.hosts if host.interfaces}
    latest = cfg.paths.output / "infra-interfaces-latest.json"
    previous = _read_previous(latest)
    previous_routers = {
        entry.get("name"): entry for entry in previous.get("routers", []) if isinstance(entry, dict)
    }
    role_order = list(cfg.nautobot.prefix_roles)
    stamp = now.isoformat(timespec="seconds")
    entries: list[dict] = []
    protected: dict[str, str] = {}  # IP -> router whose mgmt IP it is
    answered = stale = unseen = 0

    for router in infra.routers:
        interfaces = interfaces_by_ip.get(router.mgmt_ip)
        if interfaces:
            answered += 1
            choice = choose_mgmt(interfaces, prefix_input.prefixes, role_order, cfg.exclude.mgmt_interfaces)
            keep = choice.ip or router.mgmt_ip
            if choice.ip is None:
                result.warnings.append(
                    f"{router.name}: no interface address inside a discovery prefix; "
                    f"only the Nautobot IP {router.mgmt_ip} stays scannable"
                )
            elif choice.ip != router.mgmt_ip:
                result.warnings.append(
                    f"{router.name}: SNMP mgmt IP {choice.ip} ({choice.reason}) differs from "
                    f"Nautobot {router.mgmt_ip}; using {choice.ip}"
                )
            entries.append({
                "name": router.name,
                "role": router.role,
                "nautobot_ip": router.mgmt_ip,
                "mgmt_ip": choice.ip,
                "mgmt_reason": choice.reason,
                "last_seen": stamp,
                "stale": False,
                "interfaces": [interface.to_dict() for interface in interfaces],
                "excluded": excluded_ips(interfaces, keep),
            })
            protected[keep] = router.name
        elif router.name in previous_routers:
            stale += 1
            old = previous_routers[router.name]
            entry = {
                **old,
                "name": router.name,
                "role": router.role,
                "nautobot_ip": router.mgmt_ip,
                "stale": True,
                "excluded": _ipv4_list(old.get("excluded")),
            }
            entries.append(entry)
            protected[entry.get("mgmt_ip") or router.mgmt_ip] = router.name
            result.warnings.append(
                f"{router.name} ({router.mgmt_ip}): no SNMP answer; kept {len(entry['excluded'])} "
                f"excluded IPs from {old.get('last_seen') or 'an earlier run'}"
            )
        else:
            unseen += 1
            protected[router.mgmt_ip] = router.name
            result.warnings.append(
                f"{router.name} ({router.mgmt_ip}): no SNMP answer and no earlier result; "
                "nothing excluded for this router"
            )

    result.counts = {"routers": len(infra.routers), "answered": answered, "stale": stale, "unseen": unseen}
    if answered == 0:
        result.error = f"no infrastructure router answered SNMP in {xml}: keeping the previous exclude list"
        return result

    exclude = merge_exclude(entries, protected, result.warnings)
    previous_count = len(_ipv4_list(previous.get("exclude")))
    if previous_count and len(exclude) < previous_count * MAX_DROP:
        result.warnings.append(
            f"excluded IPs dropped from {previous_count} to {len(exclude)} "
            f"(more than {int((1 - MAX_DROP) * 100)}%): check pass 1 before trusting this exclude list"
        )

    doc_path = cfg.paths.output / f"infra-interfaces-{now:%Y%m%d}.json"
    exclude_path = cfg.paths.inputs / "exclude.txt"
    doc = {
        "generated_at": stamp,
        "source": infra.source,
        "scan_xml": str(xml),
        "warnings": list(result.warnings),
        "routers": entries,
        "exclude": exclude,
    }
    write_text_atomic(doc_path, json.dumps(doc, indent=2) + "\n")
    write_text_atomic(exclude_path, "".join(f"{ip}\n" for ip in exclude))
    atomic_symlink(doc_path.name, latest)
    for path in (xml, doc_path, exclude_path):
        result.warnings.extend(apply_perms(path, cfg.housekeeping))
    result.outputs = {
        "exclude_list": str(exclude_path),
        "infra_interfaces": str(doc_path),
        "infra_interfaces_latest": str(latest),
        "exclude_xml": str(xml),
    }
    result.counts.update(exclude_list=len(exclude), infra_interfaces=len(entries))
    return result
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add src/ndp/files.py src/ndp/step_scan.py src/ndp/step_exclude.py tests/fixtures/exclude-basic.xml tests/test_files.py tests/test_step_exclude.py
git commit -m "feat: ndp exclude step writes exclude.txt and infra-interfaces JSON"
```

---

### Task 4: Wire `exclude` into the CLI, `ndp run`, the manifest and publish sources

**Files:**
- Modify: `src/ndp/cli.py`
- Modify: `src/ndp/step_run.py`
- Modify: `src/ndp/manifest.py` (`DESCRIPTIONS`)
- Modify: `src/ndp/step_publish.py` (`_sources`)
- Test: `tests/test_cli.py`, `tests/test_step_run.py`, `tests/test_manifest.py`, `tests/test_step_publish.py`

**Interfaces:**
- Consumes: `run_exclude(cfg, now, env=None, runner=subprocess.run)`, `load_infra_routers`.
- Produces: CLI subcommand `exclude`; `run_all` runs `exclude` first and treats its failure as a warning `"exclude: <error>; scanning with the previous exclude list"`; manifest source `infra_routers`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
import json


def test_exclude_without_inputs_fails_as_json(config_path, capsys):
    assert main(["-c", str(config_path), "exclude"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["step"] == "exclude" and "infra-routers.json" in out["error"]
```

Replace the top part of `tests/test_step_run.py` (imports, constants, `fake_nmap`) and the four tests with:

```python
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from ndp.state import load_step_results
from ndp.step_run import run_all

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "scan-basic.xml"
NOW = datetime(2026, 10, 9, 5, 0).astimezone()
ENV = {"SNMP_COMMUNITIES": "public"}


def fake_nmap(cmd, **kwargs):
    if "-oG" in cmd:  # pass 2
        shutil.copy(FIXTURE, cmd[cmd.index("-oX") + 1])
        Path(cmd[cmd.index("-oG") + 1]).write_text("#\n")
    else:  # pass 1
        shutil.copy(FIXTURES / "exclude-basic.xml", cmd[cmd.index("-oX") + 1])
    return subprocess.CompletedProcess(cmd, 0, "", "")


def failing_nmap(cmd, **kwargs):
    return subprocess.CompletedProcess(cmd, 1, "", "boom")


def two_routers(cfg):
    (cfg.paths.inputs / "infra-routers.json").write_text(json.dumps({"devices": [
        {"name": "pe-01", "role": "PE", "mgmt_ip": "192.0.2.1"},
        {"name": "pe-02", "role": "PE", "mgmt_ip": "192.0.2.2"},
    ]}))


def test_run_all_steps(cfg, config_path):
    two_routers(cfg)
    result = run_all(cfg, NOW, config_path, env=ENV, runner=fake_nmap)
    assert result.status == "ok", (result.error, result.warnings)
    assert set(load_step_results(cfg.state_dir)) == {"exclude", "scan", "parse", "publish"}
    assert "publish.legacy_csv" in result.outputs
    assert result.outputs["exclude.exclude_list"] == str(cfg.paths.inputs / "exclude.txt")
    manifest = json.loads(Path(result.outputs["publish.manifest"]).read_text())
    assert list(manifest["steps"]) == ["exclude", "scan", "parse", "publish"]


def test_run_stops_at_first_failure(cfg, config_path):
    two_routers(cfg)
    result = run_all(cfg, NOW, config_path, env=ENV, runner=failing_nmap)
    assert result.status == "failed"
    assert result.error.startswith("scan: nmap exited with 1")
    assert set(load_step_results(cfg.state_dir)) == {"exclude", "scan"}


def test_exclude_failure_does_not_stop_the_run(cfg, config_path):
    result = run_all(cfg, NOW, config_path, env=ENV, runner=fake_nmap)
    assert result.status == "warning"
    assert result.warnings[0].startswith("exclude: cannot read")
    assert result.warnings[0].endswith("; scanning with the previous exclude list")
    assert result.warnings[1].startswith("scan: no exclude list at")
    assert set(load_step_results(cfg.state_dir)) == {"exclude", "scan", "parse", "publish"}


def test_exception_in_a_step_fails_the_run(cfg, config_path):
    def crash(cmd, **kwargs):
        raise RuntimeError("disk on fire")
    two_routers(cfg)
    result = run_all(cfg, NOW, config_path, env=ENV, runner=crash)
    assert result.status == "failed"
    assert result.error == "scan: RuntimeError: disk on fire"
    assert "exclude: RuntimeError: disk on fire; scanning with the previous exclude list" in result.warnings
    assert load_step_results(cfg.state_dir)["scan"]["status"] == "failed"
```

Append to `tests/test_manifest.py`:

```python
def test_exclude_outputs_are_described():
    from ndp.manifest import DESCRIPTIONS
    for name in ("exclude_list", "infra_interfaces", "infra_interfaces_latest", "exclude_xml"):
        assert DESCRIPTIONS[name]
```

Append to `tests/test_step_publish.py` (add `import shutil` at the top):

```python
def test_manifest_lists_infra_routers_source(cfg, config_path):
    shutil.copy(Path(__file__).parent / "fixtures" / "infra-routers.json", cfg.paths.inputs / "infra-routers.json")
    parse_first(cfg)
    result = run_publish(cfg, NOW, config_path)
    manifest = json.loads(Path(result.outputs["manifest"]).read_text())
    assert manifest["sources"]["infra_routers"]["items"] == 4
    assert manifest["sources"]["infra_routers"]["system"] == "nautobot"
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest -q tests/test_cli.py tests/test_step_run.py tests/test_manifest.py tests/test_step_publish.py`
Expected: FAIL — `invalid choice: 'exclude'` (SystemExit 2) in test_cli, step-set mismatches in test_step_run, `KeyError: 'exclude_list'` in test_manifest, `KeyError: 'infra_routers'` in test_step_publish.

- [ ] **Step 3: Implement**

`src/ndp/cli.py`: add `from ndp.step_exclude import run_exclude`; in `_add_commands`, register before `parse`:

```python
    p = sub.add_parser("exclude", help="poll infrastructure routers and write exclude.txt (pass 1)")
    p.set_defaults(handler=lambda args: _run_step(args, "exclude", run_exclude))
```

and change the `run` help text to `"run exclude, scan, parse and publish in order"`. Change the parser description to `"Network discovery pipeline: exclude, scan, parse and publish an SNMP device inventory."`.

`src/ndp/step_run.py`: update the module docstring to `"""ndp run: exclude -> scan -> parse -> publish, for use without n8n (cron, by hand)."""`, add `from ndp.step_exclude import run_exclude`, then:

```python
# a failed pass 1 keeps the previous exclude.txt, so the scan can still run
OPTIONAL_STEPS = {"exclude"}
```

In `run_all`, put `("exclude", lambda t: run_exclude(cfg, t, env=env, runner=runner)),` first in `steps`, and replace

```python
        if step_result.error:
            result.error = f"{name}: {step_result.error}"
            break
```

with

```python
        if step_result.error:
            if name in OPTIONAL_STEPS:
                result.warnings.append(f"{name}: {step_result.error}; scanning with the previous exclude list")
                continue
            result.error = f"{name}: {step_result.error}"
            break
```

`src/ndp/manifest.py`: add to `DESCRIPTIONS` (first entries):

```python
    "exclude_list": "IPs skipped by the full discovery: infrastructure router addresses other than their mgmt IP",
    "infra_interfaces": "Pass 1: infrastructure routers, their interfaces, chosen mgmt IP and excluded IPs (JSON)",
    "infra_interfaces_latest": "Link to the newest infrastructure interfaces JSON",
    "exclude_xml": "Raw nmap XML report of pass 1 (SNMP on infrastructure routers)",
```

`src/ndp/step_publish.py`: change the import to `from ndp.inputs import InputError, load_infra_routers, load_prefixes` and replace `_sources` with:

```python
def _sources(cfg: Config) -> dict[str, dict]:
    sources: dict[str, dict] = {}
    try:
        routers = load_infra_routers(cfg.paths.inputs / "infra-routers.json")
        sources["infra_routers"] = {**routers.source, "items": len(routers.routers)}
    except InputError:
        pass
    try:
        prefixes = load_prefixes(cfg.paths.inputs / "prefixes.json")
        sources["prefixes"] = {**prefixes.source, "items": len(prefixes.prefixes)}
    except InputError:
        pass
    return sources
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/ndp/cli.py src/ndp/step_run.py src/ndp/manifest.py src/ndp/step_publish.py tests/test_cli.py tests/test_step_run.py tests/test_manifest.py tests/test_step_publish.py
git commit -m "feat: ndp exclude in CLI, run, manifest and README sources"
```

---

### Task 5: Documentation and example config

**Files:**
- Modify: `examples/ndp.example.yaml`
- Modify: `README.md`
- Test: `tests/test_config.py` (`test_example_config_loads`)

**Interfaces:**
- Consumes: `Config.exclude.mgmt_interfaces`.
- Produces: nothing used by code.

- [ ] **Step 1: Write the failing test**

In `tests/test_config.py`, add to `test_example_config_loads`:

```python
    assert cfg.exclude.mgmt_interfaces == ["Loopback64500", "Loopback0", "Loopback1"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest -q tests/test_config.py::test_example_config_loads`
Expected: FAIL — `assert [] == ['Loopback64500', 'Loopback0', 'Loopback1']`.

- [ ] **Step 3: Update the example config**

In `examples/ndp.example.yaml`, replace the `device_roles` comment line `# Pass 1 (plan 2): devices whose interface IPs go into the exclude list.` with:

```yaml
  # Pass 1 (ndp exclude): devices whose interface IPs go into the exclude list.
  # n8n fetches these from Nautobot into <inputs>/infra-routers.json.
```

and add before `scanner:`:

```yaml
exclude:
  # Pass 1 keeps ONE address per router scannable. First choice: the first of
  # these interfaces (in this order) with an address inside a discovery prefix.
  # Otherwise: the router address in the highest prefix role above.
  # Names are compared case-insensitively, spaces ignored.
  mgmt_interfaces: [Loopback64500, Loopback0, Loopback1]

```

- [ ] **Step 4: Update the README**

In `README.md`, replace the data-flow row

```
| Exclude list (`exclude.txt`, later: `ndp exclude`) | n8n / `ndp exclude` | `ndp scan` | (input only) | `<inputs>/` |
```

with

```
| Infrastructure routers with role in `device_roles` (Nautobot) | n8n, before the run | `ndp exclude` | `exclude.txt`; `infra-interfaces-<date>.json`, `infra-interfaces-latest.json`; `exclude-<ts>.xml` | `<inputs>/`; `<output>/`; `<output>/nmap/` |
| Exclude list (`exclude.txt`) | `ndp exclude` (or by hand) | `ndp scan` | (input only) | `<inputs>/` |
```

Replace the line ``<inputs>/exclude.txt` (optional): one IP per line, not scanned.`` with:

````markdown
`<inputs>/infra-routers.json`, normally written by n8n from Nautobot (devices
with a role in `nautobot.device_roles`; `mgmt_ip` may include `/32`):

```json
{
  "source": {"system": "nautobot", "url": "https://nautobot.example/", "query": "...", "fetched_at": "..."},
  "devices": [{"name": "pe-01", "role": "PE", "mgmt_ip": "192.0.2.1/32"}]
}
```

`<inputs>/exclude.txt`: one IP per line, not scanned by `ndp scan`. Written by
`ndp exclude`: it polls every router on its mgmt IP over SNMP, keeps one
address per router scannable (see `exclude.mgmt_interfaces` in the example
config) and lists all its other addresses. A router that does not answer keeps
its addresses from the previous run. Each router's choice and reason are in
`infra-interfaces-latest.json`.
````

Replace the steps sentence with:

```
Steps: `ndp config`, `ndp exclude`, `ndp scan`, `ndp parse [--xml FILE]`,
`ndp publish`, `ndp run`. Each prints a JSON summary on stdout; exit code `0` = ok, `2` = ok
with warnings, `1` = failed. A failed step never replaces a `*-latest` file.
In `ndp run`, a failed `ndp exclude` is a warning: the scan uses the previous
`exclude.txt`.
```

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add examples/ndp.example.yaml README.md tests/test_config.py
git commit -m "docs: ndp exclude inputs, outputs and config"
```
