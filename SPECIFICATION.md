# Defender XDR → Check Point IOC Sync — Technical Specification

**Version:** 1.0
**Target API:** Check Point Custom IOC Management API v1.0.3
**Status:** POC / active development

---

## 1. Purpose & Scope

This package synchronizes threat indicators (IOCs) from **Microsoft
Defender XDR** into a **Check Point IOC Management** feed. It is designed to
run repeatedly (e.g. on a schedule) as an idempotent one-way sync:
Defender is the source of truth; the Check Point feed is the replica.

### 1.1 Goals
- Pull all indicators from Defender XDR (or replay from a saved file).
- Transform them to the Check Point schema (types, severity, TTL).
- Upsert them into a single named Check Point feed.
- Optionally remove IOCs from Check Point that no longer exist in Defender.
- Produce complete, reconcilable audit output on every run.

### 1.2 Non-Goals
- Bidirectional sync (Check Point → Defender).
- Managing multiple Check Point feeds in one run.
- Real-time / streaming updates (this is a batch tool).

---

## 2. Package Contents

| File | Role |
|------|------|
| `defender_ioc_export.py` | **Primary** sync engine (export → filter → upsert → cleanup → report). |
| `config.yaml` | Runtime configuration (secrets inline for POC). |
| `config.yaml.example` | Schema template used by the migrator. |
| `config_migrate.py` | Upgrade an existing config to the latest schema. |
| `extract_cp_iocs.py` | Dump current feed contents to CSV for comparison. |
| `find_state_duplicates.py` | Detect near-duplicate entries in the state file. |
| `find_cp_collisions.py` | Detect state entries that collapsed to one CP record. |
| `find_domain_shadowing.py` | Detect/prune subdomains shadowed by a parent. |
| `requirements.txt` | Python dependencies (`requests`, `PyYAML`). |
| `README.md` | User-facing usage guide. |
| `SPECIFICATION.md` | This document. |

---

## 3. External Interfaces

### 3.1 Microsoft Defender XDR
- **Auth:** OAuth2 client-credentials against Entra ID.
  - Token URL: `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
  - Scope: `https://api.securitycenter.microsoft.com/.default`
  - Required app permission: `Ti.ReadWrite.All` (WindowsDefenderATP family).
- **Read indicators:** `GET https://api.securitycenter.microsoft.com/api/indicators`
  - OData pagination via `@odata.nextLink`.
  - Optional server-side filter `$filter=expirationTime gt {now}`.

### 3.2 Check Point Custom IOC Management (v1.0.3)
Base URL is regional, e.g. `https://cloudinfra-gw.{region}.portal.checkpoint.com/app/ioc-management`.

| Operation | Method | Path | Notes |
|-----------|--------|------|-------|
| Authenticate | POST | `{auth_url}/auth/external` | Body `{clientId, accessKey}` → JWT (30-min TTL). **Auth URL is the portal root, NOT under `/app/ioc-management`.** |
| List feeds | GET | `/feeds?verbose=true` | Returns `{feeds:[VerboseFeedResponse]}`. |
| Upsert indicators | PUT | `/feeds/{feed_id}/indicators` | Body = array of `AddIndicatorRequest`. Create-or-update. |
| Delete indicators | POST | `/feeds/{feed_id}/indicators/delete` | Body = array of `{indicator_type, indicator_value}`. Batch delete. |
| (single delete) | DELETE | `/feeds/{feed_id}/indicators/{type}/{b64value}` | base64-encode value for domain/url/ipv4. Fallback only. |

**Critical constraints discovered during development:**
- There is **NO** `GET /feeds/{id}/indicators` (no "list all"). ⇒ local
  state file required to know feed contents.
- Rate limit: **50 requests/minute** ⇒ ≥1.2 s between calls.
- Batch responses return one result per submitted item **in order** ⇒
  positional matching is authoritative (values may be normalized in echo).
- Check Point absorbs certain subdomains (`www.`) into their parent domain.

### 3.3 `AddIndicatorRequest` schema
```
indicator_type   : enum [domain, url, md5, sha1, sha256, ipv4]   (required)
indicator_value  : string                                        (required)
severity         : int 0..100
confidence       : int 0..100
ttl_in_days      : int 1..100000
name             : string, pattern [A-Za-z0-9 _-]*
enabled          : bool
description      : string, forbidden chars [\x00-\x1F \x60 \x7B-\x7F]
info             : string
```

---

## 4. Configuration Schema

```yaml
azure:
  tenant_id: <guid>
  client_id: <guid>
  client_secret: <string>          # override via env DEFENDER_CLIENT_SECRET

api:
  token_url_template: <url with {tenant_id}>
  indicator_url: <url>
  scope: <url>
  request_timeout_seconds: <int>
  rate_limit_delay_seconds: <float>   # 1.2 for CP's 50/min

checkpoint:
  enabled: <bool>
  auth_url: <portal root url>
  api_base_url: <.../app/ioc-management>
  client_id: <string>
  access_key: <string>
  feed_name: <string>                 # must be a MANUAL feed
  batch_size: <int>                   # ≤ ~100 recommended
  default_severity: <"Low"|"Medium"|"High"|"Critical"|0..100>
  default_confidence: <"Low"|"Medium"|"High"|0..100>
  preserve_defender_expiration: <bool>
  expiration_days: <int>              # fallback TTL
  verbose_feeds: <bool>
  supported_types:                    # per-type on/off
    ipv4|domain|url|md5|sha1|sha256: <bool>
  shadowing:
    enabled: <bool>
    prefixes: [<string>, ...]         # e.g. ["www."]
  cleanup:
    enabled: <bool>
    max_delete_per_run: <int>         # safety cap

filters:
  exclude_expired: <bool>

output:
  directory: <path>
  state_file: <filename>
  *_prefix: <string>                  # raw_json/csv/txt/summary/uncreated

logging:
  level: <DEBUG|INFO|WARNING|ERROR>
  debug_http: <bool>
```

---

## 5. Data Model

### 5.1 Internal indicator (post-filter)
A Defender indicator dict annotated with two derived fields:
```
_cp_type   : mapped Check Point type
_cp_value  : canonicalized value (lowercased, trailing dot stripped, etc.)
```

### 5.2 State file (`cp_ioc_state.json`)
```
{
  "version": 2,
  "feeds": {
    "<feed_id>": {
      "indicators": {
        "<type>:<value>": {
          "indicator_type":  <str>,
          "indicator_value": <str>,
          "first_sent":      <iso8601>,
          "last_seen":       <iso8601>
        }
      }
    }
  }
}
```
Composite key `"<type>:<value>"` prevents cross-type collisions.

### 5.3 Uncreated audit entry
```
{
  "_uncreated_reason": <reason code>,
  "_uncreated_detail": <human explanation>,
  "_cp_type_attempted": <str|null>,
  "raw": { ...original Defender indicator JSON... }
}
```
Reason codes: `filter_unmapped_type`, `filter_type_disabled`,
`filter_bad_value`, `filter_shadowed_by_parent`,
`injection_partial_failed`, `injection_silently_dropped`,
`injection_batch_failed`.

---

## 6. Type Mapping & Validation

```
DEFENDER_TO_CP_TYPE = {
  IpAddress   -> ipv4    (IPv4 only; IPv6 & private/reserved rejected)
  DomainName  -> domain
  Url         -> url
  FileMd5     -> md5
  FileSha1    -> sha1
  FileSha256  -> sha256
  CertificateThumbprint -> (none, skipped)
}

validate(cp_type, value):
  ipv4   -> parses as public IPv4 host (not CIDR, not private/loopback/etc.)
  domain -> RFC-ish regex, ≤253 chars, valid TLD; trailing dot tolerated
  url    -> starts with http:// or https://
  md5    -> 32 hex chars
  sha1   -> 40 hex chars
  sha256 -> 64 hex chars

canonicalize(cp_type, value):
  domain -> lowercase, strip trailing '.'
  md5/sha1/sha256 -> lowercase
  ipv4   -> strip leading zeros per octet
  url    -> lowercase scheme + host (path/query preserved)
```

---

## 7. Primary Script — Pseudocode

### 7.1 Top-level flow
```
function main(args):
    cfg = load_config(args.config)            # env var overrides secret
    configure_logging(cfg.logging.level)

    apply_cli_overrides(cfg, args)            # --cleanup / --no-cleanup
    summary   = new RunSummary(test_mode=args.test)
    session   = build_session_with_retries()  # 429/5xx backoff
    uncreated = []                             # audit accumulator

    try:
        # ---- 1. ACQUIRE ----
        if args.input_file:
            indicators, raw_pages = load_from_file(args.input_file)
            summary.source = "file"
        else:
            token_mgr = TokenManager(session, cfg)
            indicators, raw_pages = get_all_indicators(session, token_mgr, cfg)

        # ---- 2. EXPORT ----
        paths = build_output_paths(cfg)
        write raw_pages  -> paths.raw
        write values     -> paths.txt
        write flattened  -> paths.csv
        record defender totals in summary

        # ---- 3. FILTER & VALIDATE ----
        supported = filter_supported_indicators(indicators, cfg, summary, uncreated)

        # ---- 4-7. CHECK POINT OPS ----
        if args.skip_checkpoint or not cfg.checkpoint.enabled:
            skip
        else:
            cp = CheckPointIOCClient(session, cfg)
            feed_id = cp.find_feed_id(cfg.checkpoint.feed_name)
            assert feed_id else raise
            state, state_path = load_state(cfg)          # migrate if legacy
            feed_state = get_feed_state(state, feed_id)

            supported = detect_shadowed_domains(          # 4. SHADOW FILTER
                            supported, feed_state, cfg, summary, uncreated)

            inject_into_checkpoint(                       # 5-6. TRANSFORM+UPSERT
                            cfg, supported, summary, cp,
                            state, state_path, uncreated)

            cleanup_stale_from_checkpoint(                # 7. CLEANUP (opt-in)
                            cfg, supported, summary, cp,
                            state, state_path)
    finally:
        # ---- 8. REPORT ----
        summarize uncreated by reason -> summary
        write_uncreated_report(uncreated, summary, cfg)
        summary.finalize()
        summary.log_report()          # includes reconciliation check
        write_summary_report(summary, cfg)

    return exit_code   # 0 ok, 1 runtime error, 2 config error
```

### 7.2 Defender retrieval
```
function get_all_indicators(session, token_mgr, cfg):
    url = cfg.api.indicator_url
    params = {$filter: expirationTime gt NOW} if cfg.filters.exclude_expired
    indicators = [], raw_pages = []
    page = 1
    while url:
        headers = {Authorization: Bearer token_mgr.get()}
        resp = session.GET(url, headers, params if page==1 else none)
        raw  = resp.json()
        raw_pages.append(raw)
        indicators.extend(raw.value)
        url = raw["@odata.nextLink"]         # pagination
        page += 1
        if url: sleep(rate_limit_delay)
    return indicators, raw_pages
```

### 7.3 Offline file loader
```
function load_from_file(path):
    fmt = detect_by_extension_then_content(path)   # json | csv
    if fmt == csv:
        rows = parse_csv(path)                      # header-mapped or bare list
        return rows, [{value: rows, _source: file}]
    else:
        data = json.load(path)
        if data has "pages":  extract from raw-export envelope
        elif data has "value": single-page envelope
        elif data is list:     plain array
        elif data has indicatorValue: single object
        else: raise
        validate each item has indicatorValue (+ default type)
        return indicators, raw_pages
```

### 7.4 Filtering
```
function filter_supported_indicators(indicators, cfg, summary, uncreated):
    supported = []
    for i in indicators:
        cp_type = DEFENDER_TO_CP_TYPE[i.indicatorType]
        if cp_type is none:
            uncreated += entry(i, "filter_unmapped_type"); continue
        if cfg.supported_types[cp_type] is false:
            uncreated += entry(i, "filter_type_disabled"); continue
        value = canonicalize(cp_type, i.indicatorValue)
        if not validate(cp_type, value):
            uncreated += entry(i, "filter_bad_value"); continue
        i._cp_type = cp_type; i._cp_value = value
        supported.append(i)
    record per-type counts in summary
    return supported
```

### 7.5 Shadow filter
```
function detect_shadowed_domains(supported, feed_state, cfg, summary, uncreated):
    if not cfg.shadowing.enabled: return supported
    prefixes = normalize(cfg.shadowing.prefixes)   # ensure trailing dot

    parents = { d._cp_value for d in supported if d._cp_type == "domain" }
             ∪ { value from state keys "domain:<value>" }

    kept = []
    for d in supported:
        if d._cp_type != "domain":
            kept.append(d); continue
        matched = false
        for p in prefixes:
            if d._cp_value startswith p:
                parent = d._cp_value without prefix p
                if parent in parents:
                    uncreated += entry(d, "filter_shadowed_by_parent")
                    matched = true; break
        if not matched: kept.append(d)
    record skipped count in summary
    return kept
```

### 7.6 TTL computation (expiration propagation)
```
function compute_ttl_in_days(indicator, cfg, now):
    default = clamp(cfg.expiration_days, 1, 100000)
    if not cfg.preserve_defender_expiration:
        return default, "default"

    exp = parse_iso(indicator.expirationTime)      # strip sub-seconds, 'Z'->+00:00
    if exp is none:
        return default, "default"

    delta_seconds = (exp - now)                    # both truncated to whole sec
    if delta_seconds <= 0:
        return default, "expired-fallback"

    ttl = ceil(delta_seconds / 86400)              # round UP to whole days
    return clamp(ttl, 1, 100000), "defender"
```

### 7.7 Transform
```
function defender_to_cp_indicator(d, cfg, summary, now):
    severity   = map_severity(d.severity or cfg.default_severity)      # ->0..100
    confidence = map_confidence(cfg.default_confidence)                # ->0..100
    ttl, src   = compute_ttl_in_days(d, cfg, now)
    summary.increment_ttl_source(src)
    return {
        indicator_type:  d._cp_type,
        indicator_value: d._cp_value,
        severity, confidence, ttl_in_days: ttl,
        name: sanitize_name("MSDefender_" + type + "_" + value),
        enabled: true,
        description: sanitize_desc(d.description or d.title or default),
        info: "source=Microsoft Defender XDR",
    }
```

### 7.8 Injection (upsert) — **with positional matching**
```
function inject_into_checkpoint(cfg, supported, summary, cp, state, state_path, uncreated):
    if not supported: return
    run_now = utcnow()

    # global dedup by (type,value), preserve order
    ordered_payloads = []; raw_by_pair = {}; seen = set()
    for d in supported:
        p = defender_to_cp_indicator(d, cfg, summary, run_now)
        pair = (p.indicator_type, p.indicator_value)
        if pair in seen: continue
        seen.add(pair); ordered_payloads.append(p); raw_by_pair[pair] = d

    if test_mode:
        write preview file; return

    for each batch of batch_size in ordered_payloads:
        ordered_pairs = [(p.type, p.value) for p in batch]
        sent = len(ordered_pairs)
        summary.cp_sent += sent
        try:
            resp   = cp.put_indicators(feed_id, batch)
            parsed = parse_indicators_response(resp)   # ordered_items, ok/failed counts

            if not parsed.parseable:
                summary.cp_added += sent
                successful = set(ordered_pairs)
            else:
                # AGGREGATE counts are authoritative
                dropped = max(0, sent - parsed.total_items)
                summary.cp_added            += parsed.ok_count
                summary.cp_partial_failed   += parsed.failed_count
                summary.cp_silently_dropped += dropped

                # PER-ITEM classification by POSITION (not by echoed value)
                successful = set()
                for idx, pair in enumerate(ordered_pairs):
                    if idx < len(parsed.ordered_items):
                        item = parsed.ordered_items[idx]
                        if item.status in 2xx: successful.add(pair)
                        else: uncreated += entry(raw_by_pair[pair],
                                                 "injection_partial_failed")
                    else:  # tail beyond response length = dropped
                        uncreated += entry(raw_by_pair[pair],
                                           "injection_silently_dropped")

            # STATE update for confirmed pairs
            for pair in ordered_pairs if pair in successful:
                state[feed].indicators["<type>:<value>"] = {
                    first_sent: (keep existing or run_now),
                    last_seen:  run_now, type, value }
            save_state(state, state_path)

        except HTTP/network error:
            summary.cp_failed_add += sent
            for pair in ordered_pairs:
                uncreated += entry(raw_by_pair[pair], "injection_batch_failed")

        sleep(rate_limit_delay)

    assert reconciliation:
        cp_sent == cp_added + cp_partial_failed + cp_silently_dropped + cp_failed_add
```

### 7.9 Response parser
```
function parse_indicators_response(resp):
    if resp not dict or resp.indicators not list:
        return {parseable: false}
    ordered = []; ok = 0; failed = 0
    for it in resp.indicators:               # ORDER PRESERVED
        status = int(it.status default 200)
        ordered.append({status, type: it.indicator.indicator_type,
                                value: it.indicator.indicator_value})
        if status in 2xx: ok += 1 else failed += 1
    return {parseable: true, ordered_items: ordered,
            total_items: len(ordered), ok_count: ok, failed_count: failed}
```

### 7.10 Cleanup
```
function cleanup_stale_from_checkpoint(cfg, supported, summary, cp, state, state_path):
    if not cfg.cleanup.enabled: return
    prev = state[feed].indicators
    if empty: return

    defender_keys = { "<type>:<value>" for d in supported }
    stale = [ decode(key) for key in prev if key not in defender_keys ]

    if len(stale) > cfg.cleanup.max_delete_per_run:
        abort with error (safety cap)

    if test_mode: write cleanup preview; return

    for each batch of batch_size in stale:
        resp   = cp.delete_indicators_batch(feed_id, batch)
        parsed = parse_indicators_response(resp)
        # positional match to find which pairs were deleted (2xx or absent)
        for idx, pair in enumerate(ordered_pairs):
            if idx >= len(items) or items[idx].status in 2xx:
                deleted.add(pair)
            else: record delete failure
        for pair in deleted: prev.pop("<type>:<value>")
        save_state(state, state_path)
        sleep(rate_limit_delay)
```

### 7.11 Check Point client — auth & token lifecycle
```
class CheckPointIOCClient:
    _authenticate():
        POST {auth_url}/auth/external {clientId, accessKey}
        token = first present of: data.token, token, accessToken,
                access_token, jwt, JWT_TOKEN, data.accessToken, data.jwt
        expires_at = now + 25min          # refresh before 30-min server TTL

    _headers(include_content_type):
        ensure token present
        return {Authorization: Bearer token, Accept: json,
                [Content-Type: json if body]}

    _handle_401_retry(fn):
        try fn()
        except HTTP 401:
            force re-auth; retry fn() once

    every request wrapped in _handle_401_retry; GET/DELETE omit Content-Type
```

---

## 8. Companion Scripts — Pseudocode

### 8.1 `extract_cp_iocs.py`
```
load cfg; load state
resolve feed_id by name
for each (type,value) in state[feed].indicators:      # state = enumeration list
    result = cp.search(feed_id, type, base64(value))  # GET /indicators/search
    write CSV row: {type, value, found_in_cp, state timestamps,
                    cp severity/confidence/ttl/liveness/dates/name/desc/info}
    sleep(rate_limit_delay)                            # 50/min
report found / missing / errors
```

### 8.2 `find_state_duplicates.py`
```
load cfg; load state
for each feed:
    group entries by (type, normalized_value)          # case/dot/url/hash norms
    also group by normalized_value across types         # cross-type
    emit groups with size>1, classify kind, estimate CP collapse count
write JSON report
```

### 8.3 `find_cp_collisions.py`
```
load newest cp_feed_extract_*.csv
group rows by CP-fingerprint (creation_date+name+desc+...)
any group size>1 => that many state entries collapsed to one CP record
classify likely cause (case/trailing_dot/leading_zeros/punycode/...)
write JSON report + reconciliation (state rows vs distinct CP records)
```

### 8.4 `find_domain_shadowing.py`
```
load cfg; load state
for each feed:
    domains = { normalized(value): entry for domain entries }
    for each domain, walk parent labels; if a parent is also present ->
        record shadow group (parent + shadowed child)
report; if --apply: prune shadowed children from state (backup first)
```

### 8.5 `config_migrate.py`
```
load template (new schema) and existing config (old values)
merge: for each leaf in template ->
    if old has real (non-placeholder) value: carry it over
    elif template value is placeholder:      mark missing
    else:                                     keep template default (new key)
if dry_run: print plan; exit
backup existing config -> .bak-YYYYMMDD-HHMM
copy template -> config; re-merge; prompt for missing (secrets hidden)
save; chmod 600
```

---

## 9. Output Artifacts

| File | Written when | Contents |
|------|-------------|----------|
| `defender_threat_indicators_raw_<TS>.json` | always | Raw pull (replayable via `-i`). |
| `defender_threat_indicators_<TS>.csv` | always | Flattened indicators. |
| `defender_threat_indicators_<TS>.txt` | always | Values only. |
| `run_summary_<TS>.json` | always | Full run stats + reconciliation flag. |
| `uncreated_indicators_<TS>.json` | always | Every IOC not created, with reason + raw JSON. |
| `checkpoint_test_preview_<TS>.json` | `--test` | Exact PUT payloads. |
| `checkpoint_cleanup_preview_<TS>.json` | `--test --cleanup` | Would-delete list. |
| `cp_ioc_state.json` | on CP writes | Persistent per-feed sent-state. |

---

## 10. Reconciliation Invariant

The single most important correctness guarantee:

```
cp_sent == cp_added + cp_partial_failed + cp_silently_dropped + cp_failed_add
```

The run summary logs `Reconciliation: OK` or `MISMATCH`. Because per-item
classification uses **positional** response matching (§7.8), server-side
value normalization cannot inflate counts or corrupt the state file — the
bug that caused `977 confirmed + 56 dropped = 1033` in an earlier revision.

---

## 11. Error Handling & Resilience

| Condition | Behavior |
|-----------|----------|
| 429 / 5xx | Automatic retry with exponential backoff (session adapter). |
| 401 mid-run | Force token refresh, retry the request once. |
| Batch PUT throws | Whole batch counted `batch_failed`; items logged to uncreated. |
| CP returns fewer items than sent | Tail items counted `silently_dropped`. |
| CP returns non-2xx per item | Counted `partial_failed`; item logged to uncreated. |
| Cleanup exceeds `max_delete_per_run` | Aborted, logged, no deletions. |
| Bad/missing config | Exit code 2 before any network call. |
| State file corrupt/unreadable | Warn, start with empty state. |
| State written | Atomic (temp file + rename) after every batch. |

---

## 12. Security Considerations

- Secrets inline in `config.yaml` for POC; production should use
  `DEFENDER_CLIENT_SECRET` env var, Azure Key Vault, or Managed Identity.
- `config.yaml` should be `chmod 600` and git-ignored.
- Auth responses are redacted in debug logs (token/secret/jwt fields masked).
- No secret values are ever written to output files.

---

## 13. Performance

- Bounded by Check Point's 50 req/min rate limit ⇒ ~1.2 s per batch call.
- PUT is batched (default 100/req) ⇒ ~10 calls for 1,000 IOCs (~12 s).
- Batch delete is likewise batched.
- Extraction (`extract_cp_iocs.py`) is 1 search/IOC ⇒ ~20 min per 1,000.

---

## 14. Known Limitations

- State reflects only what *this tool* sent; portal-added IOCs are invisible
  and untouched by cleanup.
- No `GET`-list endpoint means feed contents cannot be independently
  re-derived; the state file is authoritative and should be backed up.
- Positional matching assumes CP preserves request order in responses
  (holds for v1.0.3; a reorder would surface as a reconciliation mismatch).
- IPv6 and `CertificateThumbprint` indicators are intentionally unsupported.

---

## 15. Future Enhancements (candidates)

- CSV bulk-import endpoint (`POST /feeds/{id}/import`) for very large feeds.
- Certificate-based auth / Managed Identity.
- Direct Sentinel `ThreatIntelligenceIndicator` ingestion path.
- Containerization (Dockerfile) + scheduled execution.
- Incremental Defender pulls via `lastUpdateTime` watermark.
```
