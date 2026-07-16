#!/usr/bin/env python3
"""
Defender XDR → Check Point IOC Management
------------------------------------------
Exports threat indicators from Microsoft Defender XDR (or loads them from
a local JSON/CSV file), upserts supported IOC types into a Check Point IOC
Management feed via PUT (batched), and optionally deletes stale IOCs via
POST /feeds/{feed_id}/indicators/delete (batched).

Aligned to Check Point Custom IOC Management API v1.0.3.

Any Defender IOC that does NOT successfully land in Check Point (filtered
out, rejected, batch-failed, partial-failed, or silently dropped by the CP
API) is captured to an audit report with the raw Defender JSON so nothing
disappears silently.

Usage:
    python defender_ioc_export.py                    # normal run
    python defender_ioc_export.py --test             # dry run
    python defender_ioc_export.py --cleanup          # inject + cleanup
    python defender_ioc_export.py --no-cleanup       # force cleanup off
    python defender_ioc_export.py --skip-checkpoint  # export files only
    python defender_ioc_export.py -i input.json      # load from JSON file
    python defender_ioc_export.py -i input.csv       # load from CSV file
"""

import argparse
import base64
import csv
import ipaddress
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ============================================================
# LOGGING
# ============================================================

def configure_logging(level: str) -> logging.Logger:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    return logging.getLogger("defender-export")


log = logging.getLogger("defender-export")


# ============================================================
# HTTP ERROR LOGGING HELPER
# ============================================================

def log_http_error(context, response, debug_http=True,
                   sensitive_body_keys=("client_secret", "access_token",
                                        "refresh_token", "id_token",
                                        "accessKey", "token", "jwt",
                                        "access_key")):
    log.error("=" * 60)
    log.error("HTTP ERROR CONTEXT: %s", context)
    if response is not None:
        log.error("Status Code:        %s %s",
                  response.status_code, response.reason)
        log.error("Request URL:        %s", response.url)
        log.error("Request Method:     %s", response.request.method)
        for h in ("x-ms-request-id", "x-ms-correlation-request-id",
                  "request-id", "client-request-id",
                  "x-chkp-request-id", "x-request-id"):
            if h in response.headers:
                log.error("Header %-30s = %s", h, response.headers[h])
        if not debug_http:
            log.error("Response body suppressed")
            log.error("=" * 60)
            return
        try:
            body_json = response.json()
            if isinstance(body_json, dict):
                for k in sensitive_body_keys:
                    if k in body_json:
                        body_json[k] = "***REDACTED***"
            log.error("Response Body (JSON):\n%s",
                      json.dumps(body_json, indent=2, ensure_ascii=False))
        except ValueError:
            body_text = response.text or ""
            truncated = body_text[:2000]
            if len(body_text) > 2000:
                truncated += f"\n... (truncated, {len(body_text)} bytes)"
            log.error("Response Body (raw):\n%s", truncated)
    else:
        log.error("No response object available")
    log.error("=" * 60)


# ============================================================
# CONFIG
# ============================================================

def load_config(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    env_secret = os.environ.get("DEFENDER_CLIENT_SECRET")
    if env_secret:
        cfg["azure"]["client_secret"] = env_secret
    elif not cfg.get("azure", {}).get("client_secret"):
        raise RuntimeError(
            "Missing client secret. Set azure.client_secret in config.yaml "
            "or DEFENDER_CLIENT_SECRET env var."
        )
    return cfg


# ============================================================
# UNCREATED IOC TRACKING
# ============================================================
# Any Defender IOC that does NOT successfully land in Check Point ends up
# here, with its raw JSON preserved plus a reason/detail annotation.
# Reasons used:
#   filter_unmapped_type      - Defender type has no CP equivalent
#   filter_type_disabled      - CP type is disabled in config
#   filter_bad_value          - Value failed per-type validation
#   injection_batch_failed    - Entire PUT batch threw an exception
#   injection_partial_failed  - CP returned non-2xx status for this item
#   injection_silently_dropped- Sent to CP but not present in response

_UNCREATED_REASONS = (
    "filter_unmapped_type",
    "filter_type_disabled",
    "filter_bad_value",
    "injection_batch_failed",
    "injection_partial_failed",
    "injection_silently_dropped",
)


def _make_uncreated_entry(raw, reason, detail, cp_type=None):
    """Wrap a raw Defender indicator with audit metadata."""
    return {
        "_uncreated_reason": reason,
        "_uncreated_detail": detail,
        "_cp_type_attempted": cp_type,
        "raw": raw,
    }


# ============================================================
# RUN SUMMARY TRACKER
# ============================================================

class RunSummary:
    def __init__(self, test_mode: bool = False):
        self.started_at = datetime.now(timezone.utc)
        self.finished_at = None
        self.test_mode = test_mode
        self.source = "defender_api"
        self.source_path = None

        self.defender_total = 0
        self.defender_by_type = {}
        self.defender_by_severity = {}

        # Multi-type filter results
        self.total_supported = 0
        self.by_type_valid = {}
        self.by_type_bad_value = {}
        self.by_type_disabled = {}
        self.by_type_unmapped = {}

        self.cp_feed_name = None
        self.cp_feed_id = None
        self.cp_state_count = 0
        self.cp_added = 0
        self.cp_partial_failed = 0
        self.cp_silently_dropped = 0
        self.cp_failed_add = 0
        self.cp_add_errors = []

        # Uncreated IOC tracking
        self.uncreated_total = 0
        self.uncreated_by_reason = {r: 0 for r in _UNCREATED_REASONS}
        self.uncreated_report_path = None

        self.cleanup_enabled = False
        self.cp_stale_identified = 0
        self.cp_deleted = 0
        self.cp_failed_delete = 0
        self.cp_delete_errors = []

    def finalize(self):
        self.finished_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict:
        return {
            "run": {
                "started_at":       self.started_at.isoformat(),
                "finished_at":      (self.finished_at.isoformat()
                                     if self.finished_at else None),
                "duration_seconds": round(self.duration_seconds, 2),
                "test_mode":        self.test_mode,
                "source":           self.source,
                "source_path":      self.source_path,
            },
            "defender": {
                "total_indicators": self.defender_total,
                "by_type":          self.defender_by_type,
                "by_severity":      self.defender_by_severity,
            },
            "filter": {
                "total_supported":   self.total_supported,
                "by_type_valid":     self.by_type_valid,
                "by_type_bad_value": self.by_type_bad_value,
                "by_type_disabled":  self.by_type_disabled,
                "by_type_unmapped":  self.by_type_unmapped,
            },
            "checkpoint_injection": {
                "feed_name":         self.cp_feed_name,
                "feed_id":           self.cp_feed_id,
                "state_tracked":     self.cp_state_count,
                "added":             self.cp_added,
                "partial_failed":    self.cp_partial_failed,
                "silently_dropped":  self.cp_silently_dropped,
                "failed":            self.cp_failed_add,
                "errors":            self.cp_add_errors[:20],
            },
            "uncreated": {
                "total":              self.uncreated_total,
                "by_reason":          self.uncreated_by_reason,
                "report_path":        (str(self.uncreated_report_path)
                                       if self.uncreated_report_path else None),
            },
            "checkpoint_cleanup": {
                "enabled":          self.cleanup_enabled,
                "stale_identified": self.cp_stale_identified,
                "deleted":          self.cp_deleted,
                "failed":           self.cp_failed_delete,
                "errors":           self.cp_delete_errors[:20],
            },
        }

    def log_report(self):
        d = self.to_dict()
        log.info("=" * 60)
        log.info("RUN SUMMARY REPORT" +
                 (" (TEST MODE)" if self.test_mode else ""))
        log.info("=" * 60)
        log.info("Duration:                 %.2fs",
                 d["run"]["duration_seconds"])
        log.info("Source:                   %s%s",
                 self.source,
                 f" ({self.source_path})" if self.source_path else "")
        log.info("")
        log.info("--- Defender XDR ---")
        log.info("Total indicators pulled:  %d", self.defender_total)
        log.info("By type:                  %s", self.defender_by_type)
        log.info("By severity:              %s", self.defender_by_severity)
        log.info("")
        log.info("--- Filter ---")
        log.info("Total supported:          %d", self.total_supported)
        log.info("Accepted by type:         %s", self.by_type_valid)
        if self.by_type_bad_value:
            log.info("Rejected (bad value):     %s", self.by_type_bad_value)
        if self.by_type_disabled:
            log.info("Disabled by config:       %s", self.by_type_disabled)
        if self.by_type_unmapped:
            log.info("Unmapped Defender types:  %s", self.by_type_unmapped)
        log.info("")
        log.info("--- Check Point Injection ---")
        log.info("Feed:                     %s (id=%s)",
                 self.cp_feed_name, self.cp_feed_id)
        log.info("Tracked in state:         %d", self.cp_state_count)
        log.info("Upserted:                 %d", self.cp_added)
        log.info("Partial failures:         %d", self.cp_partial_failed)
        log.info("Silently dropped:         %d", self.cp_silently_dropped)
        log.info("Batch failures:           %d", self.cp_failed_add)
        log.info("")
        log.info("--- Uncreated (Defender IOCs NOT in Check Point) ---")
        log.info("Total uncreated:          %d", self.uncreated_total)
        log.info("By reason:                %s",
                 {k: v for k, v in self.uncreated_by_reason.items() if v})
        if self.uncreated_report_path:
            log.info("Audit report:             %s", self.uncreated_report_path)
        log.info("")
        log.info("--- Check Point Cleanup ---")
        log.info("Cleanup enabled:          %s", self.cleanup_enabled)
        log.info("Stale identified:         %d", self.cp_stale_identified)
        log.info("Deleted:                  %d", self.cp_deleted)
        log.info("Failed deletions:         %d", self.cp_failed_delete)
        log.info("=" * 60)


def write_summary_report(summary: RunSummary, cfg: dict) -> Path:
    out_dir = Path(cfg["output"]["directory"])
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = summary.started_at.strftime("%Y%m%dT%H%M%SZ")
    prefix = cfg["output"].get("summary_prefix", "run_summary")
    path = out_dir / f"{prefix}_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary.to_dict(), f, indent=2, ensure_ascii=False)
    log.info("Summary report written: %s", path)
    return path


def write_uncreated_report(uncreated, summary, cfg) -> Path:
    """
    Persist the audit list of IOCs pulled from Defender but not created
    in Check Point. Always written (even if empty) so downstream jobs can
    depend on the file existing.
    """
    out_dir = Path(cfg["output"]["directory"])
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = summary.started_at.strftime("%Y%m%dT%H%M%SZ")
    prefix = cfg["output"].get("uncreated_prefix", "uncreated_indicators")
    path = out_dir / f"{prefix}_{ts}.json"

    # Recompute counts by reason from the actual list (source of truth)
    by_reason = {r: 0 for r in _UNCREATED_REASONS}
    for item in uncreated:
        r = item.get("_uncreated_reason", "unknown")
        by_reason[r] = by_reason.get(r, 0) + 1

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_started_at": summary.started_at.isoformat(),
        "test_mode": summary.test_mode,
        "source": summary.source,
        "source_path": summary.source_path,
        "feed_name": summary.cp_feed_name,
        "feed_id": summary.cp_feed_id,
        "totals": {
            "defender_total": summary.defender_total,
            "cp_created": summary.cp_added,
            "uncreated": len(uncreated),
        },
        "by_reason": by_reason,
        "reason_glossary": {
            "filter_unmapped_type":
                "Defender indicatorType has no Check Point equivalent",
            "filter_type_disabled":
                "The mapped Check Point type is disabled in config.yaml",
            "filter_bad_value":
                "Value failed per-type validation (e.g. bad domain, non-hex hash)",
            "injection_batch_failed":
                "The PUT batch containing this IOC threw an HTTP/network error",
            "injection_partial_failed":
                "Check Point returned a non-2xx status for this specific IOC",
            "injection_silently_dropped":
                "Sent to Check Point in a batch, but not present in the response "
                "(likely deduped server-side)",
        },
        "indicators": uncreated,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    log.info("Uncreated indicators report written: %s (%d items)",
             path, len(uncreated))
    return path


# ============================================================
# LOCAL STATE (tracks IOCs we've sent to Check Point)
# ============================================================

def _state_key(cp_type, value):
    return f"{cp_type}:{value}"


def _migrate_state_if_needed(state):
    """Convert legacy state (bare value → entry) to composite key format."""
    known_types = {"ipv4", "domain", "url", "md5", "sha1", "sha256"}
    total_migrated = 0

    for feed_id, feed_data in state.get("feeds", {}).items():
        old = feed_data.get("indicators", {})
        if not isinstance(old, dict):
            continue

        new = {}
        migrated_this_feed = 0
        for key, entry in old.items():
            head = key.split(":", 1)[0] if ":" in key else None
            if head in known_types:
                new[key] = entry
                continue
            itype = (entry or {}).get("indicator_type", "ipv4")
            new_key = _state_key(itype, key)
            new[new_key] = entry
            migrated_this_feed += 1

        if migrated_this_feed:
            log.info("State migration: converted %d legacy entries in feed %s",
                     migrated_this_feed, feed_id)
            feed_data["indicators"] = new
            total_migrated += migrated_this_feed

    if total_migrated:
        log.info("State migration complete: %d total entries upgraded",
                 total_migrated)
    return state


def load_state(cfg):
    filename = cfg["output"].get("state_file", "cp_ioc_state.json")
    path = Path(cfg["output"]["directory"]) / filename
    if not path.exists():
        return {"version": 2, "feeds": {}}, path
    try:
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
    except Exception as e:
        log.warning("Could not read state file %s: %s. Starting fresh.",
                    path, e)
        return {"version": 2, "feeds": {}}, path
    if not isinstance(state, dict) or "feeds" not in state:
        log.warning("State file %s is malformed. Starting fresh.", path)
        return {"version": 2, "feeds": {}}, path

    state = _migrate_state_if_needed(state)
    state["version"] = 2
    return state, path


def save_state(state, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    tmp.replace(path)
    log.debug("State written: %s", path)


def get_feed_state(state, feed_id):
    return state.setdefault("feeds", {}).setdefault(
        feed_id, {"indicators": {}}
    )


# ============================================================
# HTTP SESSION WITH RETRIES
# ============================================================

def build_session():
    session = requests.Session()
    retries = Retry(
        total=5, backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE"],
        respect_retry_after_header=True
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


# ============================================================
# DEFENDER TOKEN MANAGER
# ============================================================

class TokenManager:
    def __init__(self, session, cfg):
        self.session = session
        self.cfg = cfg
        self.token = None
        self.expires_at = 0

    def _fetch(self):
        azure = self.cfg["azure"]
        api = self.cfg["api"]
        debug_http = self.cfg.get("logging", {}).get("debug_http", True)

        token_url = api["token_url_template"].format(
            tenant_id=azure["tenant_id"])
        payload = {
            "client_id": azure["client_id"],
            "client_secret": azure["client_secret"],
            "scope": api["scope"],
            "grant_type": "client_credentials"
        }
        response = None
        try:
            response = self.session.post(
                token_url, data=payload,
                timeout=api["request_timeout_seconds"])
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            log_http_error("Defender token acquisition",
                           response, debug_http)
            raise
        data = response.json()
        return data["access_token"], int(data.get("expires_in", 3600))

    def get(self):
        if not self.token or time.time() > self.expires_at - 60:
            log.info("Acquiring Defender access token")
            self.token, expires_in = self._fetch()
            self.expires_at = time.time() + expires_in
            log.info("Defender token acquired, expires in %ds", expires_in)
        return self.token


# ============================================================
# DEFENDER INDICATORS RETRIEVAL (API)
# ============================================================

def get_all_indicators(session, token_manager, cfg):
    api = cfg["api"]
    filters = cfg.get("filters", {})
    debug_http = cfg.get("logging", {}).get("debug_http", True)

    indicators = []
    raw_pages = []
    url = api["indicator_url"]

    params = None
    if filters.get("exclude_expired"):
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        params = {"$filter": f"expirationTime gt {now_iso}"}
        log.info("Filtering: excluding indicators expired before %s", now_iso)

    page_number = 1
    while url:
        log.info("Fetching Defender indicators page %d", page_number)
        headers = {
            "Authorization": f"Bearer {token_manager.get()}",
            "Accept": "application/json"
        }
        response = None
        try:
            response = session.get(
                url, headers=headers,
                params=params if page_number == 1 else None,
                timeout=api["request_timeout_seconds"]
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            log_http_error(f"Defender Indicators API (page {page_number})",
                           response, debug_http)
            raise
        raw = response.json()
        raw_pages.append(raw)
        page_values = raw.get("value", [])
        indicators.extend(page_values)
        log.info("Page %d returned %d indicators",
                 page_number, len(page_values))
        url = raw.get("@odata.nextLink")
        page_number += 1
        if url:
            time.sleep(api["rate_limit_delay_seconds"])

    return indicators, raw_pages


# ============================================================
# LOAD INDICATORS FROM FILE (test / offline mode)
# ============================================================

CSV_COLUMN_ALIASES = {
    "indicatorValue": (
        "indicatorvalue", "value", "ioc", "ioc_value", "indicator",
        "ip", "ipaddress", "ip_address", "address", "host",
        "domain", "url", "hash", "md5", "sha1", "sha256"
    ),
    "indicatorType": (
        "indicatortype", "type", "ioc_type", "indicator_type"
    ),
    "severity": ("severity", "sev", "level"),
    "title": ("title", "name", "label"),
    "description": ("description", "desc", "comment", "notes", "info"),
    "expirationTime": (
        "expirationtime", "expiration", "expiry", "expires", "ttl",
        "expiration_time"
    ),
}


def _normalize_csv_headers(fieldnames):
    mapping = {}
    for raw in fieldnames or []:
        key = raw.strip().lower().replace(" ", "").replace("-", "_")
        canonical = None
        for canon, aliases in CSV_COLUMN_ALIASES.items():
            if key == canon.lower() or key in aliases:
                canonical = canon
                break
        mapping[raw] = canonical
    return mapping


def _sniff_csv_dialect(sample_text):
    try:
        dialect = csv.Sniffer().sniff(sample_text, delimiters=",;\t|")
        has_header = csv.Sniffer().has_header(sample_text)
        return dialect, has_header
    except csv.Error:
        return csv.excel, True


def _load_csv_indicators(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096)
        f.seek(0)

        if not sample.strip():
            log.warning("CSV file is empty: %s", path)
            return []

        dialect, has_header = _sniff_csv_dialect(sample)
        log.debug("CSV dialect: delimiter=%r, has_header=%s",
                  getattr(dialect, "delimiter", ","), has_header)

        if not has_header:
            log.info("CSV appears to have no header — treating each row "
                     "as a single indicator value")
            reader = csv.reader(f, dialect=dialect)
            indicators = []
            for row_num, row in enumerate(reader, start=1):
                if not row:
                    continue
                value = row[0].strip()
                if not value or value.startswith("#"):
                    continue
                indicators.append({
                    "indicatorValue": value,
                    "indicatorType": "IpAddress",
                    "title": f"CSV row {row_num}",
                })
            return indicators

        reader = csv.DictReader(f, dialect=dialect)
        header_map = _normalize_csv_headers(reader.fieldnames)
        recognized = {k: v for k, v in header_map.items() if v}
        unrecognized = [k for k, v in header_map.items() if not v]

        log.info("CSV headers detected: recognized=%s%s",
                 list(recognized.values()),
                 f", ignored={unrecognized}" if unrecognized else "")

        if "indicatorValue" not in recognized.values():
            raise ValueError(
                f"CSV has no recognizable value column. "
                f"Headers found: {reader.fieldnames}. "
                f"Rename one to one of: "
                f"{CSV_COLUMN_ALIASES['indicatorValue']}"
            )

        indicators = []
        for row_num, row in enumerate(reader, start=2):
            item = {}
            for raw_key, canonical in header_map.items():
                if not canonical:
                    continue
                val = (row.get(raw_key) or "").strip()
                if val:
                    item[canonical] = val
            if not item:
                continue
            if not item.get("indicatorValue"):
                log.debug("CSV row %d has empty indicatorValue — skipping",
                          row_num)
                continue
            if not item.get("indicatorType"):
                item["indicatorType"] = "IpAddress"
            if item.get("severity"):
                item["severity"] = item["severity"].strip().capitalize()
            indicators.append(item)
        return indicators


def load_indicators_from_file(path):
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if not file_path.is_file():
        raise ValueError(f"Input path is not a file: {path}")

    log.info("Loading Defender indicators from file: %s", path)
    suffix = file_path.suffix.lower()

    if suffix == ".csv":
        source_format = "csv"
    elif suffix in (".json", ".jsonl"):
        source_format = "json"
    else:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            head = f.read(2048).lstrip()
        source_format = "json" if head.startswith(("{", "[")) else "csv"
        log.debug("Unknown extension %r — treating as %s",
                  suffix, source_format)

    if source_format == "csv":
        indicators = _load_csv_indicators(file_path)
        raw_pages = [{
            "value": indicators, "_source": "file",
            "_path": str(path), "_format": "csv",
        }]
        log.info("Loaded %d indicators from CSV", len(indicators))
    else:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Input file is not valid JSON: {path} ({e})"
                ) from e

        indicators = []
        raw_pages = []

        if isinstance(data, dict) and isinstance(data.get("pages"), list):
            raw_pages = data["pages"]
            for page in raw_pages:
                if isinstance(page, dict):
                    page_values = page.get("value", [])
                    if isinstance(page_values, list):
                        indicators.extend(page_values)
            log.info("Detected raw export format (%d pages, %d indicators)",
                     len(raw_pages), len(indicators))
        elif isinstance(data, dict) and isinstance(data.get("value"), list):
            raw_pages = [data]
            indicators = data["value"]
            log.info("Detected single-page envelope format (%d indicators)",
                     len(indicators))
        elif isinstance(data, list):
            indicators = data
            raw_pages = [{"value": indicators, "_source": "file",
                          "_path": str(path)}]
            log.info("Detected plain JSON array format (%d indicators)",
                     len(indicators))
        elif isinstance(data, dict) and "indicatorValue" in data:
            indicators = [data]
            raw_pages = [{"value": indicators, "_source": "file",
                          "_path": str(path)}]
            log.info("Detected single-indicator object")
        else:
            raise ValueError(
                f"Unrecognized JSON structure in {path}"
            )

    valid_indicators = []
    dropped = 0
    for i, item in enumerate(indicators):
        if not isinstance(item, dict):
            log.warning("Item %d is not a dict — dropping", i)
            dropped += 1
            continue
        if not item.get("indicatorValue"):
            log.warning("Item %d missing 'indicatorValue' — dropping", i)
            dropped += 1
            continue
        if not item.get("indicatorType"):
            log.warning("Item %d missing 'indicatorType' — assuming IpAddress",
                        i)
            item["indicatorType"] = "IpAddress"
        valid_indicators.append(item)

    if dropped:
        log.warning("Dropped %d malformed items from input file", dropped)

    log.info("Loaded %d valid indicators from %s",
             len(valid_indicators), path)
    return valid_indicators, raw_pages


# ============================================================
# INDICATOR TYPE MAPPING & VALIDATION
# ============================================================

DEFENDER_TO_CP_TYPE = {
    "IpAddress":  "ipv4",
    "DomainName": "domain",
    "Url":        "url",
    "FileMd5":    "md5",
    "FileSha1":   "sha1",
    "FileSha256": "sha256",
}

_HEX_MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
_HEX_SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
_HEX_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9]?\.)+"
    r"[A-Za-z]{2,63}$"
)

_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)


def is_valid_ipv4(value: str) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    if ip.is_private or ip.is_loopback or ip.is_multicast \
       or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
        return False
    return True


def is_valid_domain(v):
    v = (v or "").strip().lower()
    if not v:
        return False
    return bool(_DOMAIN_RE.match(v))


def is_valid_url(v):
    v = (v or "").strip()
    if not v:
        return False
    return bool(_URL_RE.match(v))


def is_valid_hash(v, kind):
    v = (v or "").strip()
    if not v:
        return False
    if kind == "md5":
        return bool(_HEX_MD5_RE.match(v))
    if kind == "sha1":
        return bool(_HEX_SHA1_RE.match(v))
    if kind == "sha256":
        return bool(_HEX_SHA256_RE.match(v))
    return False


def validate_indicator_value(cp_type, value):
    if cp_type == "ipv4":
        return is_valid_ipv4(value)
    if cp_type == "domain":
        return is_valid_domain(value)
    if cp_type == "url":
        return is_valid_url(value)
    if cp_type in ("md5", "sha1", "sha256"):
        return is_valid_hash(value, cp_type)
    return False


def _canonicalize_value(cp_type, value):
    v = (value or "").strip()
    if cp_type == "domain":
        return v.lower()
    if cp_type in ("md5", "sha1", "sha256"):
        return v.lower()
    return v


# ============================================================
# FILTERING (all supported IOC types)
# ============================================================

def filter_supported_indicators(indicators, cp_cfg, summary,
                                 uncreated_collection=None):
    """
    Filter Defender indicators. Also collects rejected raw JSON into
    `uncreated_collection` if provided.
    """
    supported_cfg = cp_cfg.get("supported_types", {}) or {}
    supported = []

    counts_ok        = {}
    counts_bad_value = {}
    counts_disabled  = {}
    counts_unmapped  = {}

    for i in indicators:
        d_type = i.get("indicatorType", "Unknown")
        value  = (i.get("indicatorValue") or "").strip()

        cp_type = DEFENDER_TO_CP_TYPE.get(d_type)
        if not cp_type:
            counts_unmapped[d_type] = counts_unmapped.get(d_type, 0) + 1
            if uncreated_collection is not None:
                uncreated_collection.append(_make_uncreated_entry(
                    i, "filter_unmapped_type",
                    f"Defender indicatorType {d_type!r} has no Check Point equivalent"
                ))
            continue

        if supported_cfg.get(cp_type, True) is False:
            counts_disabled[cp_type] = counts_disabled.get(cp_type, 0) + 1
            if uncreated_collection is not None:
                uncreated_collection.append(_make_uncreated_entry(
                    i, "filter_type_disabled",
                    f"Check Point type {cp_type!r} is disabled in config.yaml "
                    "(checkpoint.supported_types)",
                    cp_type=cp_type
                ))
            continue

        canon_value = _canonicalize_value(cp_type, value)
        if not validate_indicator_value(cp_type, canon_value):
            counts_bad_value[cp_type] = counts_bad_value.get(cp_type, 0) + 1
            log.debug("Rejected invalid %s value: %r", cp_type, value)
            if uncreated_collection is not None:
                uncreated_collection.append(_make_uncreated_entry(
                    i, "filter_bad_value",
                    f"Value {value!r} failed validation for Check Point type "
                    f"{cp_type!r}",
                    cp_type=cp_type
                ))
            continue

        enriched = dict(i)
        enriched["_cp_type"]  = cp_type
        enriched["_cp_value"] = canon_value
        supported.append(enriched)
        counts_ok[cp_type] = counts_ok.get(cp_type, 0) + 1

    summary.by_type_valid     = counts_ok
    summary.by_type_bad_value = counts_bad_value
    summary.by_type_disabled  = counts_disabled
    summary.by_type_unmapped  = counts_unmapped
    summary.total_supported   = len(supported)

    log.info("Filter result: %d supported IOCs across %d types",
             len(supported), len(counts_ok))
    if counts_ok:
        log.info("  Accepted by type: %s", counts_ok)
    if counts_bad_value:
        log.info("  Rejected (bad value): %s", counts_bad_value)
    if counts_disabled:
        log.info("  Skipped (disabled in config): %s", counts_disabled)
    if counts_unmapped:
        log.info("  Skipped (unmapped Defender types): %s", counts_unmapped)

    return supported


# ============================================================
# CHECK POINT IOC MANAGEMENT CLIENT
# Aligned to Custom IOC Management API v1.0.3
# ============================================================

class CheckPointIOCClient:
    _TOKEN_FIELD_PATHS = (
        ("data", "token"),
        ("token",),
        ("accessToken",),
        ("access_token",),
        ("jwt",),
        ("JWT_TOKEN",),
        ("data", "accessToken"),
        ("data", "jwt"),
    )

    def __init__(self, session, cfg):
        self.session = session
        self.cp_cfg = cfg["checkpoint"]
        self.debug_http = cfg.get("logging", {}).get("debug_http", True)
        self.timeout = cfg["api"]["request_timeout_seconds"]
        self.token = None
        self.expires_at = 0

    @staticmethod
    def _walk(d, path):
        cur = d
        for k in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(k)
            if cur is None:
                return None
        return cur

    @staticmethod
    def _redact_dict(d):
        if not isinstance(d, dict):
            return
        for k, v in list(d.items()):
            if any(s in k.lower()
                   for s in ("token", "secret", "key", "password", "jwt")):
                d[k] = "***REDACTED***"
            elif isinstance(v, dict):
                CheckPointIOCClient._redact_dict(v)

    def _authenticate(self):
        auth_endpoint = f"{self.cp_cfg['auth_url'].rstrip('/')}/auth/external"
        payload = {
            "clientId": self.cp_cfg["client_id"],
            "accessKey": self.cp_cfg["access_key"]
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        log.info("Authenticating to Check Point IOC Management API")
        log.debug("Auth endpoint: %s", auth_endpoint)

        response = None
        try:
            response = self.session.post(
                auth_endpoint, json=payload,
                headers=headers, timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            log_http_error("Check Point auth/external",
                           response, self.debug_http)
            raise

        try:
            data = response.json()
        except ValueError:
            log.error("Auth response was not JSON. Body: %s",
                      response.text[:1000])
            raise RuntimeError("Check Point auth response was not JSON")

        token = None
        for path in self._TOKEN_FIELD_PATHS:
            token = self._walk(data, path)
            if isinstance(token, str) and token:
                log.debug("Found token at path: %s", ".".join(path))
                break

        if not token:
            log.error("Could not locate a token in the auth response.")
            if self.debug_http:
                safe = json.loads(json.dumps(data))
                self._redact_dict(safe)
                log.error("Auth response (redacted):\n%s",
                          json.dumps(safe, indent=2, ensure_ascii=False))
            raise RuntimeError(
                "Check Point auth response did not contain a token field."
            )

        if token.count(".") != 2:
            log.warning("Token does not look like a JWT. Length=%d.",
                        len(token))

        self.token = token.strip()
        self.expires_at = time.time() + (25 * 60)
        log.info("Check Point authentication successful "
                 "(token length=%d, expires in ~25 min)",
                 len(self.token))

    def _ensure_token(self):
        if not self.token or time.time() > self.expires_at:
            self._authenticate()

    def _headers(self, include_content_type=True):
        if not self.token:
            self._authenticate()
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        if include_content_type:
            headers["Content-Type"] = "application/json"
        return headers

    def _handle_401_retry(self, request_fn):
        try:
            return request_fn()
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                log.warning("Received 401 — forcing token refresh and retrying")
                self.token = None
                self.expires_at = 0
                self._authenticate()
                return request_fn()
            raise

    # ---------- feed discovery ----------

    def list_feeds(self, verbose=None):
        self._ensure_token()

        if verbose is None:
            verbose = bool(self.cp_cfg.get("verbose_feeds", True))

        url = f"{self.cp_cfg['api_base_url'].rstrip('/')}/feeds"
        params = {"verbose": "true"} if verbose else None
        log.info("GET %s%s", url, " (verbose)" if verbose else "")

        response_holder = {}
        def _do():
            r = self.session.get(
                url,
                headers=self._headers(include_content_type=False),
                params=params, timeout=self.timeout
            )
            response_holder["r"] = r
            r.raise_for_status()
            return r

        try:
            response = self._handle_401_retry(_do)
        except requests.exceptions.HTTPError:
            log_http_error("Check Point list feeds",
                           response_holder.get("r"), self.debug_http)
            raise

        try:
            data = response.json()
        except ValueError:
            log.error("GET /feeds did not return JSON.")
            raise

        feeds = data.get("feeds", []) if isinstance(data, dict) else []
        return feeds

    def find_feed_id(self, feed_name):
        feeds = self.list_feeds()
        if not feeds:
            log.error("Check Point returned zero feeds")
            return None

        log.info("Retrieved %d feeds from Check Point:", len(feeds))
        for f in feeds:
            log.info(
                "  - name=%r  id=%s  type=%s  enabled=%s  indicators=%s",
                f.get("feed_name"), f.get("feed_id"),
                f.get("feed_type"), f.get("enabled"),
                f.get("total_indicators"),
            )

        target = (feed_name or "").strip().lower()
        for f in feeds:
            name = (f.get("feed_name") or "").strip().lower()
            if name == target:
                fid = f.get("feed_id")
                if not f.get("enabled"):
                    log.warning("Feed %r is DISABLED", feed_name)
                if f.get("feed_type") != "MANUAL":
                    log.warning("Feed %r has feed_type=%s (expected MANUAL).",
                                feed_name, f.get("feed_type"))
                log.info("Matched feed %r -> feed_id=%s", feed_name, fid)
                return fid

        log.error("Feed %r not found. Available feeds: %s",
                  feed_name, [f.get("feed_name") for f in feeds])
        return None

    # ---------- response parsing ----------

    @staticmethod
    def _parse_indicators_response(resp_json):
        """
        Parse an IndicatorsResponse into a structured breakdown.
        Returns dict with:
          - ok_pairs:      set of (type, value) that returned 2xx
          - failed_items:  list of {status, indicator_type, indicator_value}
          - ack_pairs:     set of ALL (type, value) present in the response
          - parseable:     True if response had the expected shape
        """
        result = {
            "ok_pairs": set(),
            "failed_items": [],
            "ack_pairs": set(),
            "parseable": False,
        }
        if not isinstance(resp_json, dict):
            return result
        items = resp_json.get("indicators")
        if not isinstance(items, list):
            return result

        result["parseable"] = True
        for it in items:
            if not isinstance(it, dict):
                continue
            ind = it.get("indicator") if isinstance(it.get("indicator"), dict) else {}
            itype = ind.get("indicator_type")
            ivalue = ind.get("indicator_value")
            status = it.get("status", 200)
            pair = (itype, ivalue)

            if itype is not None and ivalue is not None:
                result["ack_pairs"].add(pair)

            if 200 <= int(status) < 300:
                result["ok_pairs"].add(pair)
            else:
                result["failed_items"].append({
                    "status": status,
                    "indicator_type": itype,
                    "indicator_value": ivalue,
                })
        return result

    # ---------- indicator upsert ----------

    def put_indicators(self, feed_id, indicators):
        self._ensure_token()
        url = (f"{self.cp_cfg['api_base_url'].rstrip('/')}"
               f"/feeds/{feed_id}/indicators")

        response_holder = {}
        def _do():
            r = self.session.put(
                url, headers=self._headers(),
                json=indicators, timeout=self.timeout
            )
            response_holder["r"] = r
            r.raise_for_status()
            return r

        try:
            response = self._handle_401_retry(_do)
        except requests.exceptions.HTTPError:
            log_http_error(
                f"Check Point PUT to feed {feed_id} "
                f"(batch of {len(indicators)})",
                response_holder.get("r"), self.debug_http
            )
            raise

        return response.json() if response.content else {}

    # ---------- indicator batch deletion ----------

    def delete_indicators_batch(self, feed_id, indicator_pairs):
        self._ensure_token()
        url = (f"{self.cp_cfg['api_base_url'].rstrip('/')}"
               f"/feeds/{feed_id}/indicators/delete")

        payload = [
            {"indicator_type": p["indicator_type"],
             "indicator_value": p["indicator_value"]}
            for p in indicator_pairs
        ]

        response_holder = {}
        def _do():
            r = self.session.post(
                url, headers=self._headers(),
                json=payload, timeout=self.timeout
            )
            response_holder["r"] = r
            r.raise_for_status()
            return r

        try:
            response = self._handle_401_retry(_do)
        except requests.exceptions.HTTPError:
            log_http_error(
                f"Check Point batch DELETE from feed {feed_id} "
                f"(batch of {len(indicator_pairs)})",
                response_holder.get("r"), self.debug_http
            )
            raise

        return response.json() if response.content else {}

    # ---------- single indicator deletion (kept as fallback) ----------

    @staticmethod
    def _encode_indicator_value(indicator_type, indicator_value):
        needs_encoding = indicator_type in ("domain", "url", "ipv4")
        if not needs_encoding:
            return indicator_value
        raw = indicator_value.encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def delete_indicator(self, feed_id, indicator_type, indicator_value):
        self._ensure_token()
        encoded_value = self._encode_indicator_value(
            indicator_type, indicator_value)
        url = (f"{self.cp_cfg['api_base_url'].rstrip('/')}"
               f"/feeds/{feed_id}/indicators/{indicator_type}/{encoded_value}")

        response_holder = {}
        def _do():
            r = self.session.delete(
                url,
                headers=self._headers(include_content_type=False),
                timeout=self.timeout
            )
            response_holder["r"] = r
            if r.status_code == 404:
                return r
            r.raise_for_status()
            return r

        try:
            response = self._handle_401_retry(_do)
        except requests.exceptions.HTTPError:
            log_http_error(
                f"Check Point DELETE (single) from feed {feed_id}",
                response_holder.get("r"), self.debug_http
            )
            raise

        if response.status_code == 404:
            return {"status": "not_found", "value": indicator_value}
        return {"status": "deleted", "value": indicator_value}


# ============================================================
# INDICATOR TRANSFORMATION (Defender -> Check Point)
# ============================================================

SEVERITY_MAP = {
    "Informational": 25,
    "Low":           40,
    "Medium":        60,
    "High":          80,
    "Critical":      95,
}

SEVERITY_STR_TO_INT = {
    "Low":      40,
    "Medium":   60,
    "High":     80,
    "Critical": 95,
}

CONFIDENCE_MAP = {
    "Low":    33,
    "Medium": 66,
    "High":   90,
}

INFO_MARKER = "source=Microsoft Defender XDR"

_DESC_STRIP_RE = re.compile(r"[\x00-\x1F\x60\x7B-\x7F]")
_NAME_ALLOW_RE = re.compile(r"[^A-Za-z0-9 _\-]")


def _clamp(n, low, high):
    return max(low, min(high, n))


def _to_int_score(value, mapping, default):
    if isinstance(value, int):
        return _clamp(value, 0, 100)
    if isinstance(value, str) and value in mapping:
        return _clamp(mapping[value], 0, 100)
    return _clamp(default, 0, 100)


def sanitize_description(text: str) -> str:
    if not text:
        return ""
    cleaned = _DESC_STRIP_RE.sub(" ", text)
    return " ".join(cleaned.split())[:512]


def sanitize_name(text: str) -> str:
    if not text:
        return ""
    cleaned = _NAME_ALLOW_RE.sub("_", text)
    return cleaned[:64]


def _make_cp_indicator_name(cp_type, value):
    safe = re.sub(r"[^A-Za-z0-9]", "_", value)
    return sanitize_name(f"MSDefender_{cp_type}_{safe}")


def defender_to_cp_indicator(d, cp_cfg):
    cp_type = d.get("_cp_type")
    value   = d.get("_cp_value") or d.get("indicatorValue")
    if not cp_type:
        raise ValueError(
            f"Indicator missing _cp_type annotation: {d.get('indicatorValue')}"
        )

    severity = _to_int_score(
        SEVERITY_MAP.get(d.get("severity"))
            or cp_cfg.get("default_severity"),
        SEVERITY_STR_TO_INT,
        default=80
    )
    confidence = _to_int_score(
        cp_cfg.get("default_confidence"),
        CONFIDENCE_MAP,
        default=90
    )
    ttl = _clamp(int(cp_cfg.get("expiration_days", 30)), 1, 100000)

    description = sanitize_description(
        d.get("description") or d.get("title")
        or f"Imported from Microsoft Defender XDR ({d.get('indicatorType')})"
    )
    name = _make_cp_indicator_name(cp_type, value)

    return {
        "indicator_type":  cp_type,
        "indicator_value": value,
        "severity":        severity,
        "confidence":      confidence,
        "ttl_in_days":     ttl,
        "name":            name,
        "enabled":         True,
        "description":     description,
        "info":            INFO_MARKER,
    }


# ============================================================
# CHECK POINT INJECTION (via PUT batch upsert)
# ============================================================

def inject_into_checkpoint(session, cfg, supported_indicators, summary,
                            test_mode=False, cp_client=None,
                            state=None, state_path=None,
                            uncreated_collection=None):
    """
    Upsert supported indicators to Check Point.

    Detects and reports (via uncreated_collection):
      - Batch-level failures (entire PUT threw)
      - Partial failures (CP returned non-2xx for individual items)
      - Silent drops (sent to CP but not in the response)
    """
    cp_cfg = cfg["checkpoint"]

    if not cp_cfg.get("enabled"):
        log.info("Check Point injection disabled in config.yaml")
        return
    if not supported_indicators:
        log.warning("No supported indicators to inject into Check Point.")
        return

    feed_name = cp_cfg["feed_name"]
    feed_id = summary.cp_feed_id
    batch_size = int(cp_cfg.get("batch_size", 100))

    # Build parallel lists so we can map (type, value) back to the raw Defender IOC
    cp_payloads = []
    raw_by_pair = {}
    for d in supported_indicators:
        payload = defender_to_cp_indicator(d, cp_cfg)
        cp_payloads.append(payload)
        raw_by_pair[(payload["indicator_type"],
                     payload["indicator_value"])] = d

    total = len(cp_payloads)
    num_batches = (total + batch_size - 1) // batch_size

    feed_state = get_feed_state(state, feed_id) if state else {"indicators": {}}
    summary.cp_state_count = len(feed_state["indicators"])

    log.info("Injection plan: %d indicators to upsert (state tracks %d "
             "previously-sent for this feed)",
             total, summary.cp_state_count)

    # ---------- TEST MODE ----------
    if test_mode:
        est_seconds = num_batches * float(
            cfg["api"].get("rate_limit_delay_seconds", 1.2))
        log.info("=" * 60)
        log.info("*** TEST MODE — no changes will be made ***")
        log.info("=" * 60)
        log.info("Would PUT to:          %s/feeds/%s/indicators",
                 cp_cfg['api_base_url'].rstrip('/'), feed_id)
        log.info("Would target feed:     %s", feed_name)
        log.info("Would upsert:          %d indicators", total)
        log.info("Batch size:            %d (=> %d batch(es))",
                 batch_size, num_batches)
        log.info("Estimated runtime:    ~%.1fs at 50 rpm", est_seconds)

        by_type = {}
        for p in cp_payloads:
            by_type.setdefault(p["indicator_type"], p)
            if len(by_type) >= 6:
                break
        preview = list(by_type.values()) or cp_payloads[:5]
        log.info("Sample payload (%d of %d):\n%s",
                 len(preview), total,
                 json.dumps(preview, indent=2))

        out_dir = Path(cfg["output"]["directory"])
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        preview_path = out_dir / f"checkpoint_test_preview_{ts}.json"
        with open(preview_path, "w", encoding="utf-8") as f:
            json.dump({
                "http_method": "PUT",
                "feed_name": feed_name,
                "feed_id": feed_id,
                "total_indicators": total,
                "batch_size": batch_size,
                "batch_count": num_batches,
                "indicators": cp_payloads
            }, f, indent=2)
        log.info("Full preview written to: %s", preview_path)
        log.info("=" * 60)
        return

    # ---------- REAL RUN ----------
    log.info("Upserting %d indicators in %d batch(es) of up to %d",
             total, num_batches, batch_size)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for start in range(0, total, batch_size):
        batch = cp_payloads[start:start + batch_size]
        batch_num = (start // batch_size) + 1
        all_pairs = {(p["indicator_type"], p["indicator_value"])
                     for p in batch}

        log.info("PUT batch %d/%d (%d indicators, %d unique pairs)",
                 batch_num, num_batches, len(batch), len(all_pairs))

        # Detect intra-batch duplicates up front (info only)
        if len(batch) != len(all_pairs):
            dupes_in_batch = len(batch) - len(all_pairs)
            log.warning("Batch %d contains %d intra-batch duplicate (type,value) pairs — "
                        "Check Point will dedupe these",
                        batch_num, dupes_in_batch)

        try:
            resp = cp_client.put_indicators(feed_id, batch)
            parsed = CheckPointIOCClient._parse_indicators_response(resp)

            if not parsed["parseable"]:
                # Non-standard response — best-effort assume success
                summary.cp_added += len(all_pairs)
                successful_pairs = all_pairs
                log.warning("Batch %d: response shape unrecognized — "
                            "assuming all %d succeeded",
                            batch_num, len(all_pairs))
            else:
                ok_pairs      = parsed["ok_pairs"]
                failed_items  = parsed["failed_items"]
                ack_pairs     = parsed["ack_pairs"]

                # Silent drops = sent (unique) but not present in response
                silently_dropped = all_pairs - ack_pairs

                summary.cp_added          += len(ok_pairs)
                summary.cp_partial_failed += len(failed_items)
                summary.cp_silently_dropped += len(silently_dropped)

                successful_pairs = ok_pairs

                # Partial failures
                for fi in failed_items[:5]:
                    log.warning("Batch %d partial failure: %s [%s] status=%s",
                                batch_num, fi.get("indicator_value"),
                                fi.get("indicator_type"), fi.get("status"))
                for fi in failed_items:
                    summary.cp_add_errors.append(
                        f"Batch {batch_num} status={fi.get('status')} "
                        f"type={fi.get('indicator_type')} "
                        f"value={fi.get('indicator_value')}"
                    )
                    if uncreated_collection is not None:
                        pair = (fi.get("indicator_type"),
                                fi.get("indicator_value"))
                        raw = raw_by_pair.get(pair)
                        if raw is not None:
                            uncreated_collection.append(_make_uncreated_entry(
                                _strip_annotations(raw),
                                "injection_partial_failed",
                                f"Check Point returned status "
                                f"{fi.get('status')} for this indicator",
                                cp_type=fi.get("indicator_type"),
                            ))

                # Silent drops
                if silently_dropped:
                    log.warning("Batch %d: %d indicators sent but not "
                                "acknowledged in CP response (silently dropped)",
                                batch_num, len(silently_dropped))
                for pair in silently_dropped:
                    log.debug("  silently_dropped: %s [%s]", pair[1], pair[0])
                    if uncreated_collection is not None:
                        raw = raw_by_pair.get(pair)
                        if raw is not None:
                            uncreated_collection.append(_make_uncreated_entry(
                                _strip_annotations(raw),
                                "injection_silently_dropped",
                                "Sent to Check Point in this batch but not "
                                "present in the response (likely deduped or "
                                "dropped server-side)",
                                cp_type=pair[0],
                            ))

            # Update state for successful (type, value) pairs
            for ind in batch:
                pair = (ind["indicator_type"], ind["indicator_value"])
                if pair not in successful_pairs:
                    continue
                key = _state_key(*pair)
                entry = feed_state["indicators"].get(key, {})
                entry.setdefault("first_sent", now_iso)
                entry["last_seen"]       = now_iso
                entry["indicator_type"]  = ind["indicator_type"]
                entry["indicator_value"] = ind["indicator_value"]
                feed_state["indicators"][key] = entry

            if state_path:
                save_state(state, state_path)

        except Exception as e:
            summary.cp_failed_add += len(batch)
            err = f"Batch {batch_num}: {type(e).__name__}: {e}"
            summary.cp_add_errors.append(err)
            log.error(err)

            # Mark every pair in this batch as batch-failed
            if uncreated_collection is not None:
                for pair in all_pairs:
                    raw = raw_by_pair.get(pair)
                    if raw is not None:
                        uncreated_collection.append(_make_uncreated_entry(
                            _strip_annotations(raw),
                            "injection_batch_failed",
                            f"Batch {batch_num} failed: {type(e).__name__}: {e}",
                            cp_type=pair[0],
                        ))

        time.sleep(cfg["api"]["rate_limit_delay_seconds"])

    log.info("Injection complete: %d upserted, %d partial-failed, "
             "%d silently-dropped, %d batch-failed",
             summary.cp_added, summary.cp_partial_failed,
             summary.cp_silently_dropped, summary.cp_failed_add)


def _strip_annotations(raw):
    """Return a copy of a Defender indicator with our internal _cp_* fields removed."""
    if not isinstance(raw, dict):
        return raw
    return {k: v for k, v in raw.items() if not k.startswith("_cp_")}


# ============================================================
# CHECK POINT CLEANUP (via POST /indicators/delete batch)
# ============================================================

def cleanup_stale_from_checkpoint(cfg, supported_indicators, summary,
                                   test_mode=False, cp_client=None,
                                   state=None, state_path=None):
    cp_cfg = cfg["checkpoint"]
    cleanup_cfg = cp_cfg.get("cleanup", {})

    if not cleanup_cfg.get("enabled"):
        log.info("Cleanup disabled in config.yaml")
        return

    summary.cleanup_enabled = True

    if state is None:
        log.warning("No state loaded; cannot compute cleanup set")
        return

    feed_id = summary.cp_feed_id
    feed_state = get_feed_state(state, feed_id)
    previously_sent = feed_state["indicators"]

    if not previously_sent:
        log.info("No previously-sent indicators recorded in state — "
                 "nothing to clean up.")
        return

    defender_keys = set()
    for d in supported_indicators:
        v = d.get("_cp_value") or d.get("indicatorValue")
        t = d.get("_cp_type")
        if v and t:
            defender_keys.add(_state_key(t, v))

    stale = []
    for key, entry in previously_sent.items():
        if key in defender_keys:
            continue
        if ":" in key:
            itype, ivalue = key.split(":", 1)
        else:
            itype  = entry.get("indicator_type", "ipv4")
            ivalue = entry.get("indicator_value", key)
        stale.append({
            "indicator_value": ivalue,
            "indicator_type":  itype,
            "first_sent":      entry.get("first_sent"),
            "last_seen":       entry.get("last_seen"),
        })

    summary.cp_stale_identified = len(stale)
    log.info("Cleanup: %d stale indicators identified "
             "(state has %d total for this feed)",
             len(stale), len(previously_sent))

    if not stale:
        return

    max_delete = int(cleanup_cfg.get("max_delete_per_run", 500))
    if len(stale) > max_delete:
        log.error("Cleanup aborted: %d stale > max_delete_per_run=%d.",
                  len(stale), max_delete)
        summary.cp_delete_errors.append(
            f"Aborted — {len(stale)} exceeds max_delete_per_run={max_delete}"
        )
        return

    batch_size = int(cp_cfg.get("batch_size", 100))
    num_batches = (len(stale) + batch_size - 1) // batch_size

    # ---------- TEST MODE ----------
    if test_mode:
        est_seconds = num_batches * float(
            cfg["api"].get("rate_limit_delay_seconds", 1.2))
        log.info("=" * 60)
        log.info("*** TEST MODE — no deletions will be performed ***")
        log.info("=" * 60)
        log.info("Would POST to:         %s/feeds/%s/indicators/delete",
                 cp_cfg['api_base_url'].rstrip('/'), feed_id)
        log.info("Would delete %d stale indicators from feed '%s' "
                 "in %d batch(es) (~%.1fs at 50 rpm)",
                 len(stale), summary.cp_feed_name, num_batches, est_seconds)

        by_type = {}
        for s in stale:
            by_type[s["indicator_type"]] = by_type.get(s["indicator_type"], 0) + 1
        log.info("Stale by type: %s", by_type)

        preview = stale[:10]
        log.info("Sample stale indicators (first %d of %d):\n%s",
                 len(preview), len(stale),
                 json.dumps(preview, indent=2))

        out_dir = Path(cfg["output"]["directory"])
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stale_path = out_dir / f"checkpoint_cleanup_preview_{ts}.json"
        with open(stale_path, "w", encoding="utf-8") as f:
            json.dump({
                "http_method": "POST /indicators/delete",
                "feed_name": summary.cp_feed_name,
                "feed_id": feed_id,
                "batch_size": batch_size,
                "batch_count": num_batches,
                "total_stale": len(stale),
                "stale_by_type": by_type,
                "stale_indicators": stale
            }, f, indent=2)
        log.info("Full cleanup preview written to: %s", stale_path)
        log.info("=" * 60)
        return

    # ---------- REAL DELETE (batched) ----------
    log.info("Deleting %d stale indicators in %d batch(es) of up to %d",
             len(stale), num_batches, batch_size)

    for start in range(0, len(stale), batch_size):
        batch = stale[start:start + batch_size]
        batch_num = (start // batch_size) + 1
        log.info("POST delete batch %d/%d (%d indicators)",
                 batch_num, num_batches, len(batch))

        try:
            resp = cp_client.delete_indicators_batch(feed_id, batch)
            parsed = CheckPointIOCClient._parse_indicators_response(resp)

            all_pairs = {(b["indicator_type"], b["indicator_value"])
                         for b in batch}

            if not parsed["parseable"]:
                summary.cp_deleted += len(batch)
                deleted_pairs = all_pairs
            else:
                summary.cp_deleted        += len(parsed["ok_pairs"])
                summary.cp_failed_delete  += len(parsed["failed_items"])
                deleted_pairs = parsed["ok_pairs"]
                for fi in parsed["failed_items"][:5]:
                    log.warning("Delete batch %d partial failure: %s [%s] status=%s",
                                batch_num, fi.get("indicator_value"),
                                fi.get("indicator_type"), fi.get("status"))
                for fi in parsed["failed_items"]:
                    summary.cp_delete_errors.append(
                        f"Batch {batch_num} status={fi.get('status')} "
                        f"type={fi.get('indicator_type')} "
                        f"value={fi.get('indicator_value')}"
                    )

            for (itype, ivalue) in deleted_pairs:
                key = _state_key(itype, ivalue)
                previously_sent.pop(key, None)
            if state_path:
                save_state(state, state_path)

        except Exception as e:
            summary.cp_failed_delete += len(batch)
            err = f"Delete batch {batch_num}: {type(e).__name__}: {e}"
            summary.cp_delete_errors.append(err)
            log.error(err)

        time.sleep(cfg["api"]["rate_limit_delay_seconds"])

    log.info("Cleanup complete: %d deleted, %d failed",
             summary.cp_deleted, summary.cp_failed_delete)


# ============================================================
# EXPORT FUNCTIONS
# ============================================================

def build_output_paths(cfg):
    out_dir = Path(cfg["output"]["directory"])
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return {
        "raw": out_dir / f"{cfg['output']['raw_json_prefix']}_{ts}.json",
        "csv": out_dir / f"{cfg['output']['csv_prefix']}_{ts}.csv",
        "txt": out_dir / f"{cfg['output']['txt_prefix']}_{ts}.txt",
        "timestamp": ts
    }


def export_raw_json(raw_pages, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"pageCount": len(raw_pages), "pages": raw_pages},
                  f, indent=2, ensure_ascii=False)
    log.info("Raw JSON exported: %s", path)


def export_txt(indicators, path):
    with open(path, "w", encoding="utf-8") as f:
        for i in indicators:
            v = i.get("indicatorValue")
            if v:
                f.write(f"{v}\n")
    log.info("Indicator values exported: %s", path)


def export_csv(indicators, path):
    headers = [
        "id", "indicatorValue", "indicatorType", "action", "severity",
        "title", "description", "recommendedActions",
        "expirationTime", "creationTimeDateTimeUtc", "lastUpdateTime",
        "createdBy", "createdByDisplayName", "lastUpdatedBy",
        "source", "sourceType", "application", "generateAlert"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for i in indicators:
            writer.writerow(i)
    log.info("CSV report exported: %s", path)


def log_summary(indicators, summary):
    by_type, by_sev = {}, {}
    for i in indicators:
        t = i.get("indicatorType", "Unknown")
        s = i.get("severity", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1
        by_sev[s] = by_sev.get(s, 0) + 1
    summary.defender_total = len(indicators)
    summary.defender_by_type = by_type
    summary.defender_by_severity = by_sev
    log.info("Total Defender indicators: %d", len(indicators))
    log.info("Breakdown by type:     %s", by_type)
    log.info("Breakdown by severity: %s", by_sev)


# ============================================================
# CLI
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Export Defender XDR indicators, inject supported IOC "
                    "types into Check Point IOC Management, and optionally "
                    "clean up stale IOCs."
    )
    parser.add_argument("--test", action="store_true",
                        help="Dry run — no changes.")
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config file (default: config.yaml)")
    parser.add_argument("-i", "--input-file",
                        help="Load indicators from JSON or CSV file instead "
                             "of calling the Defender API.")
    parser.add_argument("--skip-checkpoint", action="store_true",
                        help="Skip Check Point injection and cleanup.")
    parser.add_argument("--cleanup", action="store_true",
                        help="Force-enable cleanup (overrides config).")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Force-disable cleanup (overrides config).")
    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main():
    args = parse_args()

    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(f"[FATAL] Failed to load configuration: {e}", file=sys.stderr)
        return 2

    global log
    log = configure_logging(cfg.get("logging", {}).get("level", "INFO"))

    if args.cleanup:
        cfg["checkpoint"].setdefault("cleanup", {})["enabled"] = True
    if args.no_cleanup:
        cfg["checkpoint"].setdefault("cleanup", {})["enabled"] = False

    if args.test:
        log.info("Running in TEST mode — no changes will be made")

    summary = RunSummary(test_mode=args.test)
    session = build_session()

    token_manager = None
    if not args.input_file:
        token_manager = TokenManager(session, cfg)

    # Global accumulator for IOCs that don't make it into CP.
    # Populated by the filter (rejects) and by inject_into_checkpoint()
    # (batch/partial/silent failures).
    uncreated = []

    exit_code = 0
    try:
        if args.input_file:
            log.info("=" * 60)
            log.info("OFFLINE MODE: loading indicators from file")
            log.info("Source file: %s", args.input_file)
            log.info("=" * 60)
            summary.source = "file"
            summary.source_path = args.input_file
            indicators, raw_pages = load_indicators_from_file(args.input_file)
        else:
            log.info("Loading indicators from Defender XDR API")
            indicators, raw_pages = get_all_indicators(
                session, token_manager, cfg)

        paths = build_output_paths(cfg)
        export_raw_json(raw_pages, paths["raw"])
        export_txt(indicators, paths["txt"])
        export_csv(indicators, paths["csv"])
        log_summary(indicators, summary)

        supported_indicators = filter_supported_indicators(
            indicators, cfg["checkpoint"], summary,
            uncreated_collection=uncreated,
        )

        if args.skip_checkpoint:
            log.info("--skip-checkpoint specified; skipping CP operations")
        elif not cfg["checkpoint"].get("enabled"):
            log.info("Check Point disabled in config; skipping CP operations")
        else:
            cp_client = CheckPointIOCClient(session, cfg)

            summary.cp_feed_name = cfg["checkpoint"]["feed_name"]
            log.info("Looking up CP feed '%s'", summary.cp_feed_name)
            feed_id = cp_client.find_feed_id(summary.cp_feed_name)
            if not feed_id:
                raise RuntimeError(
                    f"Check Point feed '{summary.cp_feed_name}' not found."
                )
            summary.cp_feed_id = feed_id
            log.info("Resolved feed id=%s", feed_id)

            state, state_path = load_state(cfg)
            log.info("Local state loaded: %s "
                     "(tracked indicators for this feed: %d)",
                     state_path,
                     len(get_feed_state(state, feed_id)["indicators"]))

            inject_into_checkpoint(
                session, cfg, supported_indicators, summary,
                test_mode=args.test, cp_client=cp_client,
                state=state, state_path=state_path,
                uncreated_collection=uncreated,
            )

            cleanup_stale_from_checkpoint(
                cfg, supported_indicators, summary,
                test_mode=args.test, cp_client=cp_client,
                state=state, state_path=state_path
            )

    except requests.exceptions.HTTPError:
        log.error("Aborting due to HTTP error")
        exit_code = 1
    except requests.exceptions.RequestException:
        log.error("Aborting due to network error")
        exit_code = 1
    except Exception as e:
        log.exception("Unexpected fatal error: %s", type(e).__name__)
        exit_code = 1
    finally:
        # Finalize uncreated stats (authoritative from the list itself)
        by_reason = {r: 0 for r in _UNCREATED_REASONS}
        for item in uncreated:
            r = item.get("_uncreated_reason", "unknown")
            by_reason[r] = by_reason.get(r, 0) + 1
        summary.uncreated_total = len(uncreated)
        summary.uncreated_by_reason = by_reason

        # Always write the uncreated report (even in test mode / even if empty)
        try:
            uncreated_path = write_uncreated_report(uncreated, summary, cfg)
            summary.uncreated_report_path = uncreated_path
        except Exception as e:
            log.error("Failed to write uncreated report: %s", e)

        summary.finalize()
        summary.log_report()
        try:
            write_summary_report(summary, cfg)
        except Exception as e:
            log.error("Failed to write summary report: %s", e)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
