# network-discovery-pipeline: design

Date: 2026-10-09
Status: draft, awaiting review

## 1. Purpose

Daily network discovery: find every device in a set of prefixes, read its
identity over SNMP (hostname, model, serial, software, interfaces, service IDs),
pick one management IP per device and publish an inventory.

It replaces an Ansible-based setup (Ansible + Semaphore + cron) in which the
scope, the management-IP rules and the device-function rules were hardcoded in
playbooks, variables and Python filter plugins.

Goals:

- **Configurable without code.** Scope comes from the source of truth
  (Nautobot) and one YAML file. Rules are data, not code.
- **Transparent.** Anyone can see where the data comes from, which step
  produced which file and where to find it, without reading code.
- **More outputs.** A complete JSON inventory that new consumers can use, next
  to the CSV files existing scripts depend on.
- **Less to maintain.** One tool, one container image, one workflow.

## 2. Scope

In scope (first version):

- CLI `ndp` with the steps `config`, `exclude`, `scan`, `parse`, `publish`,
  `run`.
- Container image built on top of the scanner image
  `ghcr.io/mwallraf/nmap-network-discovery`.
- n8n workflow that fetches scope from Nautobot, runs the steps and notifies.
- Outputs that keep the existing CSV format, plus JSON, services CSV, a run
  manifest and a generated README.

Not in scope (first version):

- Writing results back to Nautobot (later; it becomes one more publisher).
- SSH-based interface collection (only if SNMP turns out to miss addresses).
- VRF names per interface (scanner backlog item, needs MIB support checks).
- A UI of its own. n8n is the UI.

## 3. Repositories

| Repo | Visibility | Contents |
|---|---|---|
| `network-discovery-pipeline` (this repo) | public, GitHub | Code, Dockerfile, CI, docs, `examples/ndp.example.yaml`, sanitized test fixtures |
| site config repo | private, internal GitLab | The real `ndp.yaml`, n8n workflow export, server wrapper, `.env.example`, site docs |

Rule for this repo: no real prefixes, hostnames, community strings, paths or
customer data. Examples use documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) and invented role names.

## 4. Architecture

```
n8n (schedule, Nautobot fetch, retries, notifications)
  │ SSH (dedicated key + user)
  ▼
script server: bin/ndp → docker run --rm ghcr.io/mwallraf/network-discovery-pipeline:<tag> <step>
  │   mounts: ndp.yaml (ro), .env (ro), inputs/, output folder
  ▼
ndp steps
  config  → prints the effective config as JSON (n8n reads the role lists)
  fetch   → Nautobot → inputs/infra-routers.json, inputs/prefixes.json (n8n can do this instead)
  exclude → pass 1: SNMP on infrastructure routers → exclude.txt, infra-interfaces-<date>.json
  scan    → pass 2: full scan of all discovery prefixes minus exclude.txt → scan-<ts>.xml
  parse   → devices-<date>.json
  publish → CSV/JSON/services outputs, run-<ts>.json, README.md, housekeeping
  run     → [fetch,] exclude, scan, parse, publish, for use without n8n
```

Division of responsibility: **n8n decides when steps run and moves data;
`ndp` decides what the data means.** n8n holds no parsing or selection logic,
so it can be replaced by cron without losing behavior.

The image is built `FROM` the scanner image, so `ndp scan` calls `nmap`
directly: no Docker socket, no container-in-container. The scanner version is
pinned through the base image tag.

## 5. Configuration (`ndp.yaml`)

Static rules, versioned in git, edited by people. Nothing generates this file.
Dynamic inputs (prefixes, routers, exclude list) are files in `inputs/`,
regenerated each run. Secrets come from the environment only.

```yaml
paths:
  output: /data/network-discovery        # all outputs
  inputs: /data/network-discovery/inputs # generated inputs

nautobot:
  # for 'ndp fetch'; the token is NAUTOBOT_TOKEN in the environment
  url: https://nautobot.example/
  timeout_s: 60
  verify_tls: true             # false = accept a locally signed certificate (warns)
  proxy: null                  # null = HTTPS_PROXY/HTTP_PROXY/NO_PROXY from the environment
  # pass 1: devices whose interface IPs go into the exclude list
  device_roles: [PE, P, AGGREGATION]
  # pass 2: prefixes to discover; order = preference when picking a mgmt IP
  prefix_roles:
    INFRA_LOOPBACK:    {function: CORE, note: PE/P loopbacks}
    CPE_LOOPBACK:      {function: CPE,  note: CPE loopbacks}
    MGMT_LAN:          {function: DCN,  note: management LAN, private IPs}
    CPE_P2P:           {function: CPE,  note: CPE-PE links, older CPEs have no loopback}

scanner:
  snmp_timeout_ms: 4000
  timing: 5                    # nmap -T5
  tcp_ports: [22, 23, 179]
  host_discovery_ports: [22, 23]
  docker_network: null         # optional, set by the wrapper; see section 13

outputs:
  json: true
  legacy_csv: true
  legacy_csv_communities: true # include the communities column (compatibility)
  services_csv: true

housekeeping:
  keep_days: 30
  owner: null                  # null = leave as is
  group: null
  file_mode: "0664"
  dir_mode: "0775"
```

`ndp config --json` prints this config after validation and defaults. A
config error stops every step with exit code 1 and a clear message naming the
key.

Secrets: `SNMP_COMMUNITIES` (comma-separated) and `NAUTOBOT_TOKEN` (only for
`ndp fetch`) from the environment, normally
a `.env` file with mode 0600 on the server. Never a command-line argument
(visible in the process list) and never written to logs or the run manifest.

## 6. Input files (contract between the Nautobot fetch and ndp)

`ndp fetch` or n8n converts Nautobot responses into these files, so the other
steps do not depend on the Nautobot API shape. Each file carries its own
provenance; `fetched_by` is `ndp fetch` or `n8n`.

`inputs/infra-routers.json`

```json
{
  "source": {"system": "nautobot", "url": "https://nautobot.example/", "query": "devices role in [PE,P]", "fetched_at": "2026-10-09T05:00:12Z", "fetched_by": "ndp fetch"},
  "devices": [
    {"name": "pe-01", "role": "PE", "mgmt_ip": "192.0.2.1"}
  ]
}
```

`inputs/prefixes.json`

```json
{
  "source": {"system": "nautobot", "url": "https://nautobot.example/", "query": "prefixes role in [INFRA_LOOPBACK,...]", "fetched_at": "2026-10-09T05:00:14Z", "fetched_by": "ndp fetch"},
  "prefixes": [
    {"prefix": "192.0.2.0/24", "role": "INFRA_LOOPBACK"}
  ]
}
```

Validation: unknown fields are ignored; a missing required field or an invalid
IP/prefix fails the step. A prefix role not listed in `ndp.yaml` is scanned but
gets no function, and produces a warning.

## 7. Step: `exclude` (pass 1)

Why: some CPEs have no loopback and are managed on their WAN point-to-point
address, so the P2P prefixes must be scanned. That also hits the router side
of every P2P link, and a single PE would be polled on hundreds of addresses.
The exclude list removes those router-side addresses from pass 2.

1. Read `inputs/infra-routers.json`.
2. Run nmap with `snmp-brute,snmp-ifalias-service` (UDP 161 only) against the
   routers' mgmt IPs.
3. Choose one mgmt IP per router that answered, from its SNMP interfaces.
   "Mgmt prefixes" are the prefixes of the `prefix_roles` in
   `inputs/prefixes.json`; the role order in `ndp.yaml` is the priority.
   1. Walk `exclude.mgmt_interfaces` in order (names compared
      case-insensitively, spaces ignored). The first of those interfaces
      that has an address inside a mgmt prefix gives the mgmt IP.
   2. Otherwise, walk the prefix roles in priority order; the first role
      that contains any of the router's addresses gives the mgmt IP (the
      numerically lowest address if several fall in that role).
   3. If the chosen IP differs from the Nautobot mgmt IP, the chosen IP
      wins and the step warns (router, Nautobot IP, chosen IP), so Nautobot
      can be corrected.
   4. If no address falls in any mgmt prefix, nothing is chosen: the
      Nautobot mgmt IP stays scannable and the step warns.
4. Every other address of the router goes into the exclude list.
5. A router that does not answer SNMP keeps its entry (and so its excluded
   addresses) from the previous `infra-interfaces-latest.json`, and gets a
   warning, for at most `exclude.stale_max_days` (default 30) since it last
   answered; after that its old addresses are no longer excluded (they may
   have been reused). A router that returns interfaces without addresses
   counts as not answering. A router never seen before that does not answer
   gets a warning only.
6. Write `inputs/exclude.txt` (sorted, unique, one IP per line, atomic) and
   `infra-interfaces-<date>.json` + `infra-interfaces-latest.json` in the
   output folder: per router name, role, Nautobot IP, chosen mgmt IP, the
   reason (`interface:<name>` or `prefix_role:<role>`), `last_seen`,
   interfaces (ifAlias, services, addresses) and the excluded IPs. The raw
   pass-1 XML is `nmap/exclude-<ts>.xml`.
7. Safety: if no router answers, the step fails and the previous
   `exclude.txt` stays. If the number of excluded IPs drops by more than
   50% compared with the previous run, the step warns.

Config:

```yaml
exclude:
  mgmt_interfaces: [Loopback<ASN>, Loopback0, Loopback1]  # priority order
  stale_max_days: 30
```

Tested: on IOS-XR, interfaces in a VRF and their addresses are returned (the VRF
name is not).

## 8. Step: `scan` (pass 2)

1. Targets: all prefixes from `inputs/prefixes.json`.
2. nmap: `-n -PS<host_discovery_ports> -sU -sS -p T:<tcp_ports>,U:161
   -T<timing> --script snmp-brute,snmp-sysdetails,snmp-info,snmp-ifalias-service
   --script-args snmp-brute.communitiesdb=<tmp file>,snmp.timeout=<ms>
   -iL <targets> --excludefile exclude.txt -oX scan-<ts>.xml -oG scan-<ts>.txt`.
   The communities file is a temp file inside the container, deleted after the
   run.
3. Prefixes of infrastructure ranges are not excluded: routers are discovered
   once, on their mgmt IP.
4. On success, the `scan-latest.xml` / `scan-latest.txt` symlinks are replaced
   atomically. A failed or empty scan never moves the symlinks.

## 9. Step: `parse`

Input: `scan-latest.xml` (or a given file) and `inputs/prefixes.json`.
Output: `devices-<date>.json`.

Per host that is up, read the `snmp-brute` (valid communities), `snmp-info`
(enterprise), `snmp-sysdetails` (system/physical fields) and
`snmp-ifalias-service` (interfaces) results.

- **Merging:** hosts are merged into one device by key: hostname (lowercase,
  domain stripped), else serial, else IP. The key is computed after
  normalization (fixes a legacy bug where `host.domain` and `host` did not
  merge). Ports only go from closed to open. Conflicting values are kept from
  the first host and reported as warnings.
- **Mgmt IP:** among the device's IPs, take those inside the prefix role that
  comes first in `prefix_roles`; the lowest IP wins a tie. `mgmt_safe` = 1 when
  that role holds exactly one IP of the device, else 0. If no IP is inside a
  known prefix: lowest IP, no function, warning; `mgmt_safe` = 1 only when
  the device has a single IP (legacy behavior).
- **Function:** the `function` of the mgmt IP's prefix role.
- **OS slug** (`ios-xe`, `ios-xr`, `ios-generic`, `saos5`, `saos6`, `saos10`,
  `ciena-generic`, `oneos5`, `oneos6`, `oneos-generic`): same rules as the
  legacy parser, kept in code as one documented table. Software version
  fallbacks from `sysDescr` (OneOS, Cisco) also kept.
- Text cleanup as legacy: newlines → `. `; `,` and `|` → `_` in CSV fields.

Device record (JSON):

```json
{
  "key": "pe-01", "hostname": "pe-01", "mgmt_ip": "192.0.2.1", "mgmt_safe": 1,
  "mgmt_role": "INFRA_LOOPBACK", "function": "CORE", "os_slug": "ios-xr",
  "ips": ["192.0.2.1"], "communities": ["<redacted in examples>"],
  "ports": {"ssh": "open", "telnet": "closed", "snmp": "open", "bgp": "open"},
  "snmp": {"sysDescr": "...", "sysObjectId": "...", "sysUpTime": "...", "sysContact": "...", "sysLocation": "...",
           "physSerial": "...", "physSoftware": "...", "physModel": "...", "physDescription": "...", "physName": "...",
           "enterprise": "..."},
  "interfaces": [
    {"name": "Gi0/0/0.100", "ifIndex": 12, "ifAlias": "SVC123456 customer", "services": ["SVC123456"], "addresses": ["198.51.100.1/30"]}
  ]
}
```

## 10. Step: `publish`

| File | Content | Notes |
|---|---|---|
| `infra-interfaces-<date>.json`, `infra-interfaces-latest.json` | Pass 1: per infrastructure router its interfaces, chosen mgmt IP and excluded IPs, section 7 | |
| `devices-<date>.json`, `devices-latest.json` | All device records | |
| `discovery.csv.<date>`, `discovery-latest.csv` | One row per device | Columns identical to legacy, see below |
| `discovery-summary.csv` | One row appended per run | Legacy columns: `id,started,started_str,endtime,endtime_str,elapsed,hosts_total,hosts_up,hosts_down,filename` |
| `services-<date>.csv`, `services-latest.csv` | One row per (service ID, device, interface, address) | Columns: `service,hostname,mgmt_ip,interface,ifAlias,address` |
| `run-<ts>.json` | Run manifest, section 11 | |
| `README.md` | Regenerated each run, section 11 | |

Legacy CSV columns, in order:
`_key,_updates,hostname,status,telnet,ssh,snmp,bgp,enterprise,os_slug,function,mgmt_ip,mgmt_safe,sysObjectId,sysContact,sysLocation,sysUpTime,physSerial,physSoftware,physDescription,physName,physModel,ip,communities`
(lists joined with `|`; `communities` empty when
`legacy_csv_communities: false`).

`*-latest.*` symlinks are replaced atomically and only after the dated file is
complete.

Housekeeping: files matching the dated patterns older than `keep_days` are
deleted; owner/group/mode applied to new files and folders.

## 11. Transparency

- **n8n canvas:** each source is a named node (for example "Nautobot: prefixes
  by role"), sticky notes say what each step produces and where. The workflow
  export lives in the private config repo.
- **Run manifest `run-<ts>.json`:** per run: sources (system, URL, query,
  fetched_at, item counts, from the input files), steps (start, end, status,
  exit code, warnings), versions (ndp, scanner image, config git commit if
  available), outputs (path, rows), and the warnings list. Never secrets.
- **`README.md` in the output folder:** generated from the manifest: where the
  data comes from, which step produced each file, column meanings, link to
  this repo and to the config repo.
- **This repo's README:** a data-flow table (source → fetched by → step →
  output → location) and how to run each step by hand.

## 12. Errors and exit codes

Every step prints a JSON summary on stdout (status, counts, warnings, output
paths) and logs on stderr.

| Exit code | Meaning | n8n action |
|---|---|---|
| 0 | Success | continue |
| 2 | Success with warnings | continue, include warnings in the notification |
| 1 | Failure (bad config/input, nmap failed, no output) | stop, notify |

A failed step never replaces a `*-latest` file. `run` stops at the first
failure, except that a failed `fetch` or `exclude` is a warning: the previous
files are used.

## 13. Deployment

- Image `ghcr.io/mwallraf/network-discovery-pipeline`, built by GitHub Actions
  like the scanner (PR: build + tests; `main`: `:main`, `:sha-*`; tag `vX.Y.Z`:
  `:X.Y.Z`, `:X.Y`, `:latest`). Production pins an exact version tag.
- Runs as root inside the container (nmap needs raw sockets for `-sS`/`-sU`).
- Server layout (from the private config repo):

  ```
  /opt/ndp/ndp.yaml
  /opt/ndp/.env          # SNMP_COMMUNITIES, mode 0600
  /opt/ndp/bin/ndp       # wrapper: docker run --rm --env-file .env -v ... <image> "$@"
  ```

- Docker network: the wrapper can attach the container to a dedicated network
  with a chosen subnet, so Docker's default range does not overlap internal
  networks (the legacy setup used a custom network for this).

- Why the image is built on the scanner image (decided 2026-10-09): `ndp scan`
  needs nmap and the custom NSE scripts in its own container. Building on the
  scanner image gives one image, a pinned scanner version and no Docker
  socket. Rejected: `ndp` starting the scanner container (needs the Docker
  socket, root-equivalent), separate containers glued by the wrapper (more
  steps, secrets passed between containers). Possible later: own slim image
  with Debian nmap and the NSE scripts copied in (multi-stage), if image size
  or the Kali base becomes a problem.

### n8n deployment

`deploy/n8n/docker-compose.yml` in this repo (generic), with site values in a
`.env` from the private config repo:

- `n8n` container (official image, version pinned via `.env`), SQLite database
  in a named volume (`/home/node/.n8n`). Not published on a host port.
- `caddy` container in front of it, the only one with published ports (80,
  443), terminating HTTPS: either Caddy's internal CA (`tls internal`) or a
  certificate and key provided by the site.
- Required settings in `.env`: n8n hostname, n8n version, timezone,
  `N8N_ENCRYPTION_KEY` (generated once and kept; without it stored
  credentials cannot be decrypted), TLS mode.
- n8n's own user management protects the UI. It stores the Nautobot token and
  the SSH key to the script server as n8n credentials.

## 14. n8n workflow

```
Schedule (daily)
 → SSH: ndp config --json
 → Nautobot GraphQL: devices with device_roles → Code: shape → SSH upload inputs/infra-routers.json
 → Nautobot GraphQL: prefixes with prefix_roles → Code: shape → SSH upload inputs/prefixes.json
 → SSH: ndp exclude
 → SSH: ndp scan
 → SSH: ndp parse
 → SSH: ndp publish
 → Notify on failure or warnings; daily summary (devices found, new, missing)
```

The Nautobot token is stored in n8n credentials. The "Code" nodes only reshape
JSON into the input contract of section 6.

## 15. Testing

- pytest unit tests: config validation, input validation, merging, mgmt IP and
  function selection, exclude list (including the keep-previous-addresses
  rule), legacy CSV columns, services CSV, symlink and housekeeping behavior.
- Fixtures: scan XMLs with realistic structure, documentation IP ranges,
  invented hostnames, no real communities.
- Comparison test (run privately, not in CI): legacy parser and `ndp parse` on
  the same real XML; CSV diff may only differ in `function`/`mgmt_ip`/`_key`
  where the new rules or the merge-key fix explain it.

## 16. Rollout

1. Production stays on the Ansible `legacy` branch.
2. Run the new pipeline daily in parallel, writing to a separate output folder.
3. Compare outputs daily for 1–2 weeks; explain every difference.
4. Switch the output folder to the production path, disable the Semaphore job.
5. Keep the `legacy` branch as fallback.

## 17. Open questions

- Notification channel (email, Teams, ...), chosen when building the n8n
  workflow.
