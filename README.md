# network-discovery-pipeline

Daily network discovery: find every device in a set of prefixes, read its
identity over SNMP and publish an inventory as JSON and CSV.

`ndp` runs the [nmap-network-discovery](https://github.com/mwallraf/nmap-network-discovery)
scanner, merges hosts that are the same device, picks one management IP per
device based on prefix roles, and writes outputs that other scripts can use.
Scheduling (n8n, cron) and site configuration live elsewhere: this repository
holds only the tool and generic examples.

## Data flow

| Source | Fetched by | Step | Output | Location |
|---|---|---|---|---|
| Prefixes with a discovery role (Nautobot) | n8n, before the run | `ndp scan` | `scan-<ts>.xml`, `scan-latest.xml` | `<output>/nmap/` |
| Infrastructure routers with role in `device_roles` (Nautobot) | n8n, before the run | `ndp exclude` | `exclude.txt`; `infra-interfaces-<date>.json`, `infra-interfaces-latest.json`; `exclude-<ts>.xml` | `<inputs>/`; `<output>/`; `<output>/nmap/` |
| Exclude list (`exclude.txt`) | `ndp exclude` (or by hand) | `ndp scan` | (input only) | `<inputs>/` |
| Scan XML + prefixes | | `ndp parse` | `devices-<date>.json` | `<output>/` |
| Devices JSON | | `ndp publish` | `devices-latest.json`, `discovery.csv.<date>`, `discovery-latest.csv`, `discovery-summary.csv`, `services-latest.csv`, `run-<ts>.json`, `README.md` | `<output>/` |

Every run writes `run-<ts>.json` (sources, steps, versions, warnings, files)
and regenerates `README.md` in the output folder, so the output explains
itself.

## Inputs

`<inputs>/prefixes.json`, normally written by n8n from Nautobot:

```json
{
  "source": {"system": "nautobot", "url": "https://nautobot.example/", "query": "...", "fetched_at": "..."},
  "prefixes": [{"prefix": "192.0.2.0/24", "role": "INFRA_LOOPBACK"}]
}
```

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

SNMP communities: environment variable `SNMP_COMMUNITIES` (comma-separated),
for example from a `.env` file with mode 0600. Never pass them as arguments.

## Configuration

See [`examples/ndp.example.yaml`](examples/ndp.example.yaml). The order of
`nautobot.prefix_roles` is the preference when a device has IPs in several
roles; the device's function comes from the role of its management IP.

## Running

```bash
docker run --rm --env-file .env -e TZ=UTC \
  -v /path/ndp.yaml:/etc/ndp/ndp.yaml:ro \
  -v /data/network-discovery:/data/network-discovery \
  ghcr.io/mwallraf/network-discovery-pipeline:latest run
```

Steps: `ndp config`, `ndp exclude`, `ndp scan`, `ndp parse [--xml FILE]`,
`ndp publish`, `ndp run`. Each prints a JSON summary on stdout; exit code `0` = ok, `2` = ok
with warnings, `1` = failed. A failed step never replaces a `*-latest` file.
In `ndp run`, a failed `ndp exclude` is a warning: the scan uses the previous
`exclude.txt`.
File names use the container's local time: pass `TZ` to get your time zone.

Compare with a legacy CSV: `python -m ndp.compare old.csv new.csv`.

n8n setup: see [`deploy/n8n/`](deploy/n8n/README.md).

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

Test data uses documentation IP ranges and invented names only. Do not add
real prefixes, hostnames or community strings to this repository.

## License

[MIT](LICENSE)
