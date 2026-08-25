# Defender XDR → Check Point IOC Management Sync

A Python toolkit that exports threat indicators (IOCs) from **Microsoft
Defender XDR** and synchronizes them into a **Check Point IOC Management**
feed via the Custom IOC Management API (v1.0.3).

The primary script pulls indicators, filters and transforms them, upserts
them into Check Point in batches, optionally removes stale entries, and
writes a full set of audit and reporting files for every run.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Command-Line Options](#command-line-options)
- [Process Overview](#process-overview)
- [IOC Type Support](#ioc-type-support)
- [Expiration / TTL Handling](#expiration--ttl-handling)
- [Shadow Filter](#shadow-filter)
- [State Tracking & Cleanup](#state-tracking--cleanup)
- [Output Files](#output-files)
- [Run Summary & Reconciliation](#run-summary--reconciliation)
- [Companion Scripts](#companion-scripts)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## What It Does

At a high level, each run performs the following pipeline:

1. **Acquire indicators** — either live from the Defender XDR API, or from
   a local JSON/CSV file (offline/test mode).
2. **Export** the raw pull to timestamped JSON, CSV, and TXT files.
3. **Filter & validate** — map Defender indicator types to Check Point
   types, validate each value, and drop anything unsupported.
4. **Shadow-filter** — skip `www.` subdomains whose parent domain is also
   being sent (Check Point absorbs these into the parent record).
5. **Transform** — convert each indicator to the Check Point
   `AddIndicatorRequest` schema, including converting Defender's absolute
   expiration date into Check Point's relative `ttl_in_days`.
6. **Upsert** — send indicators to Check Point in batches via `PUT`.
7. **Track state** — record every successfully-created IOC in a local
   state file (the API has no "list all" endpoint, so this is how we know
   what's in the feed).
8. **Cleanup (optional)** — delete IOCs from Check Point that are no
   longer present in Defender.
9. **Report** — write a run summary, an "uncreated" audit report, and log
   a reconciliation check.

---

## Requirements

- **Python 3.8+**
- Packages (see `requirements.txt`):
  - `requests >= 2.32`
  - `PyYAML >= 6.0`
- **Microsoft Defender XDR** app registration (Entra ID) with the
  `Ti.ReadWrite.All` application permission (under the **WindowsDefenderATP**
  API family), granted admin consent.
- **Check Point Infinity Portal** API key with **Service = Centralized IOC
  Management** (Client ID + Secret Key + regional auth URL).
- A **manual feed** pre-created in the Check Point IOC Management portal
  (Inputs → Custom Manual Feeds → Add feed).

---

## Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy and edit the configuration
cp config.yaml config.yaml.local   # or edit config.yaml directly
chmod 600 config.yaml              # protect inline secrets

# 3. First run — dry run to validate everything
python defender_ioc_export.py --test
```

---

## Configuration

All configuration lives in `config.yaml`. Key sections:

### `azure` — Defender XDR credentials
```yaml
azure:
  tenant_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  client_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  client_secret: "your-defender-client-secret"
```
> The client secret can be overridden at runtime via the
> `DEFENDER_CLIENT_SECRET` environment variable (takes precedence over the
> config file — useful for containers/CI).

### `api` — Defender endpoints & rate limiting
```yaml
api:
  scope: "https://api.securitycenter.microsoft.com/.default"
  indicator_url: "https://api.securitycenter.microsoft.com/api/indicators"
  request_timeout_seconds: 60
  rate_limit_delay_seconds: 1.2   # Check Point limit is 50 req/min
```

### `checkpoint` — Check Point IOC Management
```yaml
checkpoint:
  enabled: true
  # Regional auth/API base URLs:
  #   EU:  https://cloudinfra-gw.portal.checkpoint.com
  #   AU:  https://cloudinfra-gw.ap.portal.checkpoint.com
  #   CA:  https://cloudinfra-gw.ca.portal.checkpoint.com
  #   US:  https://cloudinfra-gw.us.portal.checkpoint.com
  auth_url: "https://cloudinfra-gw.portal.checkpoint.com"
  api_base_url: "https://cloudinfra-gw.portal.checkpoint.com/app/ioc-management"
  client_id: "your-checkpoint-client-id"
  access_key: "your-checkpoint-access-key"

  feed_name: "MSDefender_Autofeed"
  batch_size: 100

  default_severity: "High"          # or integer 0..100
  default_confidence: "High"        # or integer 0..100

  preserve_defender_expiration: true
  expiration_days: 30               # fallback / used when preserve=false

  supported_types:                  # toggle any type on/off
    ipv4:   true
    domain: true
    url:    true
    md5:    true
    sha1:   true
    sha256: true

  shadowing:
    enabled: true
    prefixes: ["www."]

  cleanup:
    enabled: false                  # opt-in
    max_delete_per_run: 500         # safety cap
```

### `output` — file locations & prefixes
```yaml
output:
  directory: "./exports"
  state_file: "cp_ioc_state.json"
  raw_json_prefix: "defender_threat_indicators_raw"
  csv_prefix: "defender_threat_indicators"
  txt_prefix: "defender_threat_indicators"
  summary_prefix: "run_summary"
  uncreated_prefix: "uncreated_indicators"
```

### `logging`
```yaml
logging:
  level: "INFO"        # DEBUG | INFO | WARNING | ERROR
  debug_http: true     # include full HTTP error bodies in logs
```

---

## Command-Line Options

```
python defender_ioc_export.py [OPTIONS]
```

| Option | Argument | Description |
|--------|----------|-------------|
| `--test` | — | **Dry run.** Performs all reads, filtering, and transformation, and writes preview files, but makes **no changes** to Check Point (no PUT, no DELETE). |
| `--config` | `PATH` | Path to the configuration file. Default: `config.yaml`. |
| `-i`, `--input-file` | `PATH` | Load indicators from a local **JSON or CSV** file instead of calling the Defender API. Skips Defender authentication entirely. Format is auto-detected by extension and content. |
| `--skip-checkpoint` | — | Perform the Defender export and file outputs only; skip all Check Point operations (injection **and** cleanup). |
| `--cleanup` | — | **Force-enable** stale-IOC cleanup for this run, overriding `checkpoint.cleanup.enabled` in config. |
| `--no-cleanup` | — | **Force-disable** cleanup for this run, overriding config. |

### Common invocations

```bash
# Standard run — export + upsert (no cleanup unless enabled in config)
python defender_ioc_export.py

# Dry run — see exactly what would happen, change nothing
python defender_ioc_export.py --test

# Full sync — upsert new/changed AND remove stale IOCs
python defender_ioc_export.py --cleanup

# Dry run of a full sync (inspect both injection and cleanup previews)
python defender_ioc_export.py --test --cleanup

# Export only — pull from Defender, write files, touch nothing in CP
python defender_ioc_export.py --skip-checkpoint

# Offline iteration — replay a previous raw pull without hitting Defender
python defender_ioc_export.py -i ./exports/defender_threat_indicators_raw_20260709T000017Z.json

# Offline from a hand-built CSV
python defender_ioc_export.py -i ./test_iocs.csv --test

# Alternate config file
python defender_ioc_export.py --config /etc/defender-sync/prod.yaml
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime error (HTTP, network, or unexpected exception) |
| `2` | Configuration error (bad/missing config or secret) |

---

## Process Overview

```
 ┌─────────────────────────────────────────────────────────────────┐
 │ 1. ACQUIRE                                                        │
 │    Defender API  ──OR──  --input-file (JSON/CSV)                  │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │  raw indicators
 ┌────────────────────────────────▼────────────────────────────────┐
 │ 2. EXPORT                                                         │
 │    raw JSON  +  CSV  +  TXT   (timestamped, in ./exports/)        │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼────────────────────────────────┐
 │ 3. FILTER & VALIDATE                                              │
 │    • Map Defender type → CP type                                  │
 │    • Drop unmapped types (e.g. CertificateThumbprint)             │
 │    • Drop types disabled in config                                │
 │    • Validate value per type (IPv4/domain/url/hash)               │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │  supported indicators
 ┌────────────────────────────────▼────────────────────────────────┐
 │ 4. SHADOW FILTER                                                  │
 │    Skip www.<domain> when <domain> is also being sent             │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼────────────────────────────────┐
 │ 5. TRANSFORM                                                      │
 │    → CP AddIndicatorRequest schema                                │
 │    → severity/confidence 0..100                                   │
 │    → expirationTime → ttl_in_days                                 │
 │    → canonicalize value (lowercase, strip trailing dot, etc.)     │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼────────────────────────────────┐
 │ 6. UPSERT  (PUT /feeds/{id}/indicators, batched)                  │
 │    • Positional response matching                                 │
 │    • Record successes in local state file                         │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼────────────────────────────────┐
 │ 7. CLEANUP  (optional; POST /indicators/delete, batched)          │
 │    Remove IOCs in state that are no longer in Defender            │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼────────────────────────────────┐
 │ 8. REPORT                                                         │
 │    run_summary + uncreated_indicators + reconciliation check      │
 └───────────────────────────────────────────────────────────────────┘
```

---

## IOC Type Support

Defender indicator types are mapped to Check Point types as follows:

| Defender `indicatorType` | Check Point `indicator_type` | Notes |
|--------------------------|------------------------------|-------|
| `IpAddress`              | `ipv4`                       | IPv4 only; IPv6 and private/reserved ranges are skipped |
| `DomainName`             | `domain`                     | Lowercased; trailing dot stripped |
| `Url`                    | `url`                        | Scheme + host lowercased |
| `FileMd5`                | `md5`                        | 32 hex chars; lowercased |
| `FileSha1`               | `sha1`                       | 40 hex chars; lowercased |
| `FileSha256`             | `sha256`                     | 64 hex chars; lowercased |
| `CertificateThumbprint`  | *(none)*                     | No CP equivalent — skipped and logged |

Any type can be individually disabled via `checkpoint.supported_types`.

---

## Expiration / TTL Handling

Defender provides an **absolute** expiration timestamp (`expirationTime`);
Check Point expects a **relative** `ttl_in_days` (integer, 1–100000).

When `preserve_defender_expiration: true` (default), the script computes:

```
ttl_in_days = ceil( (expirationTime − now) / 1 day )
```

so the IOC expires in Check Point on the same date Defender intends.

Indicators are selected when `expirationTime` is either **in the future** or
**not set**. Expired indicators are excluded by the Defender API filter.

When Defender provides no expiration, the Check Point payload omits
`ttl_in_days`, so the synchronized IOC also has no expiration.

**Fallback to `expiration_days`** occurs only when expiration preservation is
disabled, or an explicitly supplied expiration is unparseable/already expired
(for example, in an offline input file).

> **Because `ttl_in_days` is relative to creation time, it is re-anchored
> on every sync.** As long as the job runs regularly, Check Point's
> expiration continuously tracks Defender's actual date. If the job stops,
> IOCs age out based on the last-sent TTL (fail-closed).

The run summary reports how many TTLs came from each source
(`from_defender_expiration`, `from_config_default`,
`from_expired_fallback`).

---

## Shadow Filter

Check Point treats a parent-domain indicator as covering certain
subdomains. In practice, pushing `www.example.com` when `example.com`
already exists results in the subdomain being **silently absorbed** into
the parent.

The shadow filter skips a subdomain when **both** are true:
1. Its value starts with a configured prefix (default: only `www.`)
2. The parent domain (prefix stripped) is also being sent this run, or is
   already tracked in state.

All other subdomains (e.g. `mail.`, `api.`) are sent normally. Skipped
subdomains are recorded in the uncreated report with reason
`filter_shadowed_by_parent`.

Configure via:
```yaml
checkpoint:
  shadowing:
    enabled: true
    prefixes: ["www."]   # add more if needed, e.g. ["www.", "m."]
```

---

## State Tracking & Cleanup

The Check Point Custom IOC Management API (v1.0.3) has **no endpoint to
list all indicators in a feed**. To know what's actually in the feed, the
script maintains a local state file (`exports/cp_ioc_state.json`) recording
every `(indicator_type, indicator_value)` pair it has successfully sent,
keyed per feed.

- **Injection** adds/updates entries in state as IOCs are confirmed by CP.
- **Cleanup** (`--cleanup` or `cleanup.enabled: true`) compares the current
  Defender set against state; anything in state but no longer in Defender
  is deleted from Check Point and removed from state.
- `max_delete_per_run` caps how many deletions a single run may perform
  (guards against a bad Defender pull wiping the feed).

> **Note:** State only reflects what *this tool* has sent. IOCs added
> manually via the Check Point portal are not tracked and will not be
> touched by cleanup.

---

## Output Files

All files are written to `output.directory` (default `./exports/`) and are
UTC-timestamped so runs never overwrite each other.

| File | Description |
|------|-------------|
| `defender_threat_indicators_raw_<TS>.json` | Raw indicator pull (source of truth for offline replay via `-i`) |
| `defender_threat_indicators_<TS>.csv`       | Flattened CSV of all pulled indicators |
| `defender_threat_indicators_<TS>.txt`       | Plain list of indicator values |
| `run_summary_<TS>.json`                     | Full machine-readable run statistics |
| `uncreated_indicators_<TS>.json`            | Every IOC that did **not** land in CP, with raw JSON and a reason code |
| `checkpoint_test_preview_<TS>.json`         | (`--test` only) Exact payloads that *would* be PUT |
| `checkpoint_cleanup_preview_<TS>.json`      | (`--test --cleanup` only) IOCs that *would* be deleted |
| `cp_ioc_state.json`                         | Persistent state of what's been sent per feed (not timestamped) |

### Uncreated reason codes

| Reason | Meaning |
|--------|---------|
| `filter_unmapped_type` | Defender type has no CP equivalent |
| `filter_type_disabled` | CP type disabled in config |
| `filter_bad_value` | Value failed per-type validation |
| `filter_shadowed_by_parent` | `www.` subdomain absorbed by its parent |
| `injection_partial_failed` | CP returned a non-2xx status for this item |
| `injection_silently_dropped` | Sent but not echoed in the CP response |
| `injection_batch_failed` | The entire batch threw an HTTP/network error |

---

## Run Summary & Reconciliation

Every run logs and saves a summary. The injection section enforces an
accounting invariant:

```
sent == confirmed + partial_failed + silently_dropped + batch_failed
```

The log prints either:

```
Reconciliation:           OK (977 = 977 + 0 + 0 + 0)
```

or a `MISMATCH` warning if the numbers don't add up (which would indicate a
CP API behavior worth investigating). Per-item success is determined by
**positional matching** against the CP response, so server-side value
normalization (case, trailing dots, etc.) does not corrupt state tracking.

---

## Companion Scripts

These optional utilities share the same `config.yaml`:

| Script | Purpose |
|--------|---------|
| `extract_cp_iocs.py` | Extract IOCs currently in the CP feed (via search, using the state file as the enumeration list) to a CSV for comparison against the source data. |
| `find_state_duplicates.py` | Analyze the state file for near-duplicate entries (case, trailing dot, URL normalization, etc.) that Check Point would collapse. |
| `find_cp_collisions.py` | Post-process an extract CSV to find state entries that mapped to the same underlying CP record. |
| `find_domain_shadowing.py` | Detect (and optionally prune with `--apply`) subdomains in state that are shadowed by a parent domain. |
| `config_migrate.py` | Back up an existing `config.yaml`, copy `config.yaml.example`, carry over prior values, and prompt for anything missing. |

Run any of them with `-h` / `--help` for their specific options.

---

## Troubleshooting

**Defender auth returns a token with no `roles` claim**
Ensure `Ti.ReadWrite.All` is granted under **WindowsDefenderATP** (not
Microsoft Threat Protection) and that the scope is
`https://api.securitycenter.microsoft.com/.default`.

**Check Point 400 `limit: must be greater than 0`**
Not applicable to the current version (there is no GET-list call); ensure
you are on the latest script.

**Check Point 403 on writes**
Confirm the API key's Service is **Centralized IOC Management** and the
target feed is **MANUAL** and enabled.

**State count < confirmed count**
Fixed in the current version via positional response matching. Re-run once
(PUT is idempotent) to heal a state file created by an older version.

**Turn on verbose diagnostics**
```yaml
logging:
  level: "DEBUG"
  debug_http: true
```

---

## Security Notes

This configuration stores secrets inline for POC convenience. Before
production use:

- `chmod 600 config.yaml` and add it to `.gitignore`.
- Prefer the `DEFENDER_CLIENT_SECRET` environment variable, or migrate
  secrets to **Azure Key Vault** / a secrets manager.
- Consider **certificate-based auth** or **Managed Identity** where the
  workload runs in Azure.
- Rotate API keys/secrets on a schedule.

---

*Aligned to Check Point Custom IOC Management API v1.0.3.*
