#!/usr/bin/env python3
"""
Defender XDR → Check Point IOC Management
------------------------------------------
Exports threat indicators from Microsoft Defender XDR (or loads them from
a local file), upserts valid public IPv4 indicators into a Check Point IOC
Management feed via PUT (batched), and optionally deletes stale IOCs via
DELETE (per-item, base64-encoded value).

Usage:
    python defender_ioc_export.py                    # normal run
    python defender_ioc_export.py --test             # dry run, no changes
    python defender_ioc_export.py --cleanup          # inject + cleanup stale
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

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie",
                     "x-ms-cookie", "x-ms-request-id"}


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
            log.error("Response body suppressed "
                      "(set logging.debug_http: true)")
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
                truncated += f"\n... (truncated, {len(body_text)} bytes total)"
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

    # Env var override (useful for containers/CI)
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
# RUN SUMMARY TRACKER
# ============================================================

class RunSummary:
    """Tracks per-run statistics for reporting."""

    def __init__(self, test_mode: bool = False):
        self.started_at = datetime.now(timezone.utc)
        self.finished_at = None
        self.test_mode = test_mode

        self.source = "defender_api"
        self.source_path = None

        self.defender_total = 0
        self.defender_by_type = {}
        self.defender_by_severity = {}

        self.ipv4_valid = 0
        self.ipv4_skipped_type = 0
        self.ipv4_skipped_invalid = 0

        self.cp_feed_name = None
        self.cp_feed_id = None
        self.cp_existing_count = 0
        self.cp_added = 0
        self.cp_skipped_duplicate = 0
        self.cp_failed_add = 0
        self.cp_add_errors = []

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
            "ipv4_filter": {
                "valid":           self.ipv4_valid,
                "skipped_by_type": self.ipv4_skipped_type,
                "skipped_invalid": self.ipv4_skipped_invalid,
            },
            "checkpoint_injection": {
                "feed_name":         self.cp_feed_name,
                "feed_id":           self.cp_feed_id,
                "existing_in_feed":  self.cp_existing_count,
                "added":             self.cp_added,
                "skipped_duplicate": self.cp_skipped_duplicate,
                "failed":            self.cp_failed_add,
                "errors":            self.cp_add_errors[:20],
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
        log.info("--- IPv4 Filter ---")
        log.info("Valid public IPv4:         %d", self.ipv4_valid)
        log.info("Skipped (not IpAddress):   %d", self.ipv4_skipped_type)
        log.info("Skipped (private/invalid): %d", self.ipv4_skipped_invalid)
        log.info("")
        log.info("--- Check Point Injection ---")
        log.info("Feed:                     %s (id=%s)",
                 self.cp_feed_name, self.cp_feed_id)
        log.info("Existing indicators:      %d", self.cp_existing_count)
        log.info("Upserted:                 %d", self.cp_added)
        log.info("Skipped (unchanged):      %d", self.cp_skipped_duplicate)
        log.info("Failed:                   %d", self.cp_failed_add)
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

# CSV column-name variants we accept for each canonical field.
# All matching is case-insensitive, whitespace-tolerant.
CSV_COLUMN_ALIASES = {
    "indicatorValue": (
        "indicatorvalue", "value", "ioc", "ioc_value", "indicator",
        "ip", "ipaddress", "ip_address", "address", "host"
    ),
    "indicatorType": (
        "indicatortype", "type", "ioc_type", "indicator_type"
    ),
    "severity": (
        "severity", "sev", "level"
    ),
    "title": (
        "title", "name", "label"
    ),
    "description": (
        "description", "desc", "comment", "notes", "info"
    ),
    "expirationTime": (
        "expirationtime", "expiration", "expiry", "expires", "ttl",
        "expiration_time"
    ),
}


def _normalize_csv_headers(fieldnames):
    """Map raw CSV headers to canonical Defender field names."""
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
    """Auto-detect CSV dialect (delimiter, quoting) from a sample."""
    try:
        dialect = csv.Sniffer().sniff(sample_text, delimiters=",;\t|")
        has_header = csv.Sniffer().has_header(sample_text)
        return dialect, has_header
    except csv.Error:
        return csv.excel, True


def _load_csv_indicators(path):
    """Load indicators from a CSV or plain IP-list file."""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096)
        f.seek(0)

        if not sample.strip():
            log.warning("CSV file is empty: %s", path)
            return []

        dialect, has_header = _sniff_csv_dialect(sample)
        log.debug("CSV dialect: delimiter=%r, has_header=%s",
                  getattr(dialect, "delimiter", ","), has_header)

        # Header-less files → treat each row as a single indicator value
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

        # Header-based parsing
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
    """
    Load Defender-format indicators from a local file, bypassing the
    Defender API.

    Supported file types (auto-detected by extension, then content):
      - .json → JSON (multiple structures accepted, see below)
      - .csv  → CSV with header row (columns auto-mapped)
      - Other → sniffed as JSON if starts with '{' or '[', else CSV

    Accepted JSON structures:
      A) Raw export from this script:
         {"pageCount": N, "pages": [{"value": [{...}, ...]}, ...]}
      B) Single-page envelope: {"value": [{...}, ...]}
      C) Plain array: [{...}, {...}, ...]
      D) Single indicator object

    Returns: (indicators_list, raw_pages_list)
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if not file_path.is_file():
        raise ValueError(f"Input path is not a file: {path}")

    log.info("Loading Defender indicators from file: %s", path)

    # Decide by extension first
    suffix = file_path.suffix.lower()

    if suffix == ".csv":
        source_format = "csv"
    elif suffix in (".json", ".jsonl"):
        source_format = "json"
    else:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            head = f.read(2048).lstrip()
        if head.startswith(("{", "[")):
            source_format = "json"
            log.debug("Unknown extension %r — content looks like JSON", suffix)
        else:
            source_format = "csv"
            log.debug("Unknown extension %r — falling back to CSV", suffix)

    # ---------- CSV path ----------
    if source_format == "csv":
        indicators = _load_csv_indicators(file_path)
        raw_pages = [{
            "value": indicators,
            "_source": "file",
            "_path": str(path),
            "_format": "csv",
        }]
        log.info("Loaded %d indicators from CSV", len(indicators))

    # ---------- JSON path ----------
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
                f"Unrecognized JSON structure in {path}. Expected one of:\n"
                "  - {'pages': [...]} (raw export)\n"
                "  - {'value': [...]} (single-page envelope)\n"
                "  - [ {...}, {...} ] (indicator array)\n"
                "  - {'indicatorValue': '...', ...} (single indicator)"
            )

    # ---------- Common validation ----------
    valid_indicators = []
    dropped = 0
    for i, item in enumerate(indicators):
        if not isinstance(item, dict):
            log.warning("Item %d is not a dict (%s) — dropping",
                        i, type(item).__name__)
            dropped += 1
            continue
        if not item.get("indicatorValue"):
            log.warning("Item %d missing 'indicatorValue' — dropping "
                        "(keys: %s)", i, list(item.keys()))
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
# IPv4 FILTERING / VALIDATION
# ============================================================

def is_valid_ipv4(value: str) -> bool:
    """Return True if value is a valid public IPv4 (single host, not CIDR)."""
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


def filter_ipv4_indicators(indicators, summary):
    ipv4_indicators = []
    skipped_types = {}
    skipped_invalid = 0

    for i in indicators:
        itype = i.get("indicatorType", "Unknown")
        value = i.get("indicatorValue", "")

        if itype != "IpAddress":
            skipped_types[itype] = skipped_types.get(itype, 0) + 1
            continue

        if not is_valid_ipv4(value):
            skipped_invalid += 1
            continue

        ipv4_indicators.append(i)

    summary.ipv4_valid = len(ipv4_indicators)
    summary.ipv4_skipped_type = sum(skipped_types.values())
    summary.ipv4_skipped_invalid = skipped_invalid

    log.info("IPv4 filter: %d valid public IPv4 indicators",
             len(ipv4_indicators))
    if skipped_types:
        log.info("Skipped by type: %s", skipped_types)
    if skipped_invalid:
        log.info("Skipped invalid/private IPs: %d", skipped_invalid)

    return ipv4_indicators


# ============================================================
# CHECK POINT IOC MANAGEMENT CLIENT
# ============================================================

class CheckPointIOCClient:
    """
    Client for the Check Point Custom IOC Management API.
    Auth: POST {auth_url}/auth/external → JWT valid ~30 minutes.

    Endpoints used:
      GET    /feeds
      GET    /feeds/{feed_id}/indicators
      PUT    /feeds/{feed_id}/indicators                          (batch upsert)
      DELETE /feeds/{feed_id}/indicators/{type}/{base64_value}    (single)
    """

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

    # ---------- authentication ----------

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
            log.error(
                "Could not locate a token in the auth response. "
                "Top-level keys: %s",
                list(data.keys()) if isinstance(data, dict)
                else type(data).__name__
            )
            if self.debug_http:
                safe = json.loads(json.dumps(data))
                self._redact_dict(safe)
                log.error("Auth response (redacted):\n%s",
                          json.dumps(safe, indent=2, ensure_ascii=False))
            raise RuntimeError(
                "Check Point auth response did not contain a recognizable "
                "token field. Set logging.debug_http: true to inspect."
            )

        if token.count(".") != 2:
            log.warning("Token does not look like a JWT (missing dot "
                        "segments). Length=%d. Proceeding anyway.",
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

    def list_feeds(self):
        self._ensure_token()
        url = f"{self.cp_cfg['api_base_url'].rstrip('/')}/feeds"
        log.info("GET %s", url)

        response_holder = {}

        def _do():
            r = self.session.get(
                url,
                headers=self._headers(include_content_type=False),
                timeout=self.timeout
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
            log.error("GET /feeds did not return JSON. Body: %s",
                      response.text[:2000])
            raise

        feeds = data.get("feeds", []) if isinstance(data, dict) else []
        log.debug("GET /feeds returned %d feeds", len(feeds))
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
                f.get("feed_name"),
                f.get("feed_id"),
                f.get("feed_type"),
                f.get("enabled"),
                f.get("total_indicators"),
            )

        target = (feed_name or "").strip().lower()
        for f in feeds:
            name = (f.get("feed_name") or "").strip().lower()
            if name == target:
                fid = f.get("feed_id")
                if not f.get("enabled"):
                    log.warning("Feed %r is DISABLED — indicators may be "
                                "ingested but not enforced", feed_name)
                if f.get("feed_type") != "MANUAL":
                    log.warning("Feed %r has feed_type=%s (expected MANUAL). "
                                "The API may reject writes.",
                                feed_name, f.get("feed_type"))
                log.info("Matched feed %r -> feed_id=%s", feed_name, fid)
                return fid

        log.error(
            "Feed %r not found. Available feeds: %s",
            feed_name,
            [f.get("feed_name") for f in feeds]
        )
        return None

    # ---------- indicator listing ----------

def list_indicators(self, feed_id, page_size=500):
        """
        GET /feeds/{feed_id}/indicators (paginated).

        The API uses `limit` (max items per page) and `offset` (skip count)
        for pagination — NOT page/pageSize. Response envelope varies, so
        we tolerate several common shapes.
        """
        self._ensure_token()
        base_url = (f"{self.cp_cfg['api_base_url'].rstrip('/')}"
                    f"/feeds/{feed_id}/indicators")

        all_items = []
        offset = 0
        limit = max(1, int(page_size))    # API rejects limit <= 0

        while True:
            params = {"limit": limit, "offset": offset}
            response_holder = {}

            def _do():
                r = self.session.get(
                    base_url,
                    headers=self._headers(include_content_type=False),
                    params=params, timeout=self.timeout
                )
                response_holder["r"] = r
                r.raise_for_status()
                return r

            try:
                response = self._handle_401_retry(_do)
            except requests.exceptions.HTTPError:
                log_http_error(
                    f"Check Point list indicators "
                    f"(feed {feed_id}, offset {offset}, limit {limit})",
                    response_holder.get("r"), self.debug_http
                )
                raise

            data = response.json()

            # Multiple response envelopes seen in Infinity Portal APIs
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = (data.get("indicators")
                         or data.get("items")
                         or data.get("data")
                         or data.get("results")
                         or [])
            else:
                items = []

            if not isinstance(items, list):
                log.warning("Unexpected page structure at offset %d — "
                            "stopping pagination", offset)
                break

            all_items.extend(items)
            log.debug("Feed %s offset=%d returned %d indicators "
                      "(cumulative %d)",
                      feed_id, offset, len(items), len(all_items))

            # Continue while we're getting full pages back
            if len(items) < limit:
                break

            offset += len(items)
            time.sleep(0.3)

        log.info("Total indicators loaded from feed %s: %d",
                 feed_id, len(all_items))
        return all_items

    # ---------- indicator upsert ----------

    def put_indicators(self, feed_id, indicators):
        self._ensure_token()
        url = (f"{self.cp_cfg['api_base_url'].rstrip('/')}"
               f"/feeds/{feed_id}/indicators")

        response_holder = {}

        def _do():
            r = self.session.put(
                url,
                headers=self._headers(),
                json=indicators,
                timeout=self.timeout
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

    # ---------- indicator deletion ----------

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
            indicator_type, indicator_value
        )
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
                f"Check Point DELETE from feed {feed_id} "
                f"(type={indicator_type}, value={indicator_value})",
                response_holder.get("r"), self.debug_http
            )
            raise

        if response.status_code == 404:
            log.debug("DELETE returned 404 (already absent): %s [%s]",
                      indicator_value, indicator_type)
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


def defender_to_cp_indicator(d, cp_cfg):
    """
    Convert a Defender indicator to a Check Point AddIndicatorRequest.
    Schema (Swagger):
      indicator_type*  : enum [domain, url, md5, sha1, sha256, ipv4]
      indicator_value* : string
      severity         : int 0..100
      confidence       : int 0..100
      ttl_in_days      : int 1..100000
      name             : string [A-Za-z0-9 _-]*
      enabled          : bool
      description      : string (control chars, `, {|}~DEL forbidden)
      info             : string
    """
    value = d["indicatorValue"]

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
        or "Imported from Microsoft Defender XDR"
    )
    name = sanitize_name(f"MSDefender_{value.replace('.', '_')}")

    return {
        "indicator_type":  "ipv4",
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
# CHECK POINT INJECTION
# ============================================================

def inject_into_checkpoint(session, cfg, ipv4_indicators, summary,
                            test_mode=False, cp_client=None,
                            existing_indicators=None):
    cp_cfg = cfg["checkpoint"]

    if not cp_cfg.get("enabled"):
        log.info("Check Point injection disabled in config.yaml")
        return

    if not ipv4_indicators:
        log.warning("No IPv4 indicators to inject into Check Point.")
        return

    feed_name = cp_cfg["feed_name"]
    batch_size = int(cp_cfg.get("batch_size", 100))

    cp_payloads = [defender_to_cp_indicator(d, cp_cfg)
                   for d in ipv4_indicators]

    existing_values = set()
    if existing_indicators is not None:
        for e in existing_indicators:
            v = (e.get("indicator_value")
                 or e.get("value")
                 or e.get("indicatorValue"))
            if v:
                existing_values.add(v)
        summary.cp_existing_count = len(existing_values)

    to_upload = []
    for p in cp_payloads:
        if p["indicator_value"] in existing_values:
            summary.cp_skipped_duplicate += 1
        else:
            to_upload.append(p)

    log.info("Injection plan: %d to upsert, %d unchanged (skipped)",
             len(to_upload), summary.cp_skipped_duplicate)

    # ---------- TEST MODE ----------
    if test_mode:
        num_batches = (len(to_upload) + batch_size - 1) // batch_size
        est_seconds = num_batches * float(
            cfg["api"].get("rate_limit_delay_seconds", 0.6))

        log.info("=" * 60)
        log.info("*** TEST MODE — no changes will be made ***")
        log.info("=" * 60)
        log.info("Would PUT to:          %s/feeds/<feed_id>/indicators",
                 cp_cfg['api_base_url'].rstrip('/'))
        log.info("Would target feed:     %s", feed_name)
        log.info("Would upload:          %d NEW indicators", len(to_upload))
        log.info("Would skip:            %d duplicates",
                 summary.cp_skipped_duplicate)
        log.info("Batch size:            %d (=> %d batch(es))",
                 batch_size, num_batches)
        log.info("Estimated runtime:    ~%.1fs", est_seconds)

        preview = to_upload[:5]
        if preview:
            log.info("Sample payload (first %d of %d):\n%s",
                     len(preview), len(to_upload),
                     json.dumps(preview, indent=2))

        out_dir = Path(cfg["output"]["directory"])
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        preview_path = out_dir / f"checkpoint_test_preview_{ts}.json"
        with open(preview_path, "w", encoding="utf-8") as f:
            json.dump({
                "http_method": "PUT",
                "feed_name": feed_name,
                "total_new_indicators": len(to_upload),
                "duplicates_skipped": summary.cp_skipped_duplicate,
                "batch_size": batch_size,
                "batch_count": num_batches,
                "indicators": to_upload
            }, f, indent=2)
        log.info("Full preview written to: %s", preview_path)
        log.info("=" * 60)
        return

    # ---------- REAL RUN ----------
    total = len(to_upload)
    num_batches = (total + batch_size - 1) // batch_size

    log.info("Uploading %d indicators in %d batch(es) of up to %d",
             total, num_batches, batch_size)

    for start in range(0, total, batch_size):
        batch = to_upload[start:start + batch_size]
        batch_num = (start // batch_size) + 1
        log.info("PUT batch %d/%d (%d indicators)",
                 batch_num, num_batches, len(batch))

        try:
            cp_client.put_indicators(summary.cp_feed_id, batch)
            summary.cp_added += len(batch)
        except Exception as e:
            summary.cp_failed_add += len(batch)
            err = f"Batch {batch_num}: {type(e).__name__}: {e}"
            summary.cp_add_errors.append(err)
            log.error(err)

        time.sleep(cfg["api"]["rate_limit_delay_seconds"])

    log.info("Injection complete: %d upserted, %d failed",
             summary.cp_added, summary.cp_failed_add)


# ============================================================
# CHECK POINT CLEANUP
# ============================================================

def cleanup_stale_from_checkpoint(cfg, ipv4_indicators, summary,
                                   test_mode=False, cp_client=None,
                                   existing_indicators=None):
    cp_cfg = cfg["checkpoint"]
    cleanup_cfg = cp_cfg.get("cleanup", {})

    if not cleanup_cfg.get("enabled"):
        log.info("Cleanup disabled in config.yaml")
        return

    summary.cleanup_enabled = True

    if existing_indicators is None:
        log.warning("No existing indicators loaded; cannot compute cleanup set")
        return

    defender_values = {
        d["indicatorValue"] for d in ipv4_indicators
        if d.get("indicatorValue")
    }

    stale = []
    require_source = cleanup_cfg.get("require_source_match", True)

    for e in existing_indicators:
        value = (e.get("indicator_value")
                 or e.get("value")
                 or e.get("indicatorValue"))
        info = e.get("info", "") or ""
        indicator_id = (e.get("indicator_id")
                        or e.get("id")
                        or e.get("_id")
                        or e.get("indicatorId"))
        itype = e.get("indicator_type", "ipv4")

        if not value:
            continue
        if value in defender_values:
            continue

        if require_source and INFO_MARKER not in info:
            log.debug("Preserving IOC %s — info=%r doesn't match our marker",
                      value, info)
            continue

        stale.append({
            "id": indicator_id,
            "value": value,
            "info": info,
            "indicator_type": itype,
        })

    summary.cp_stale_identified = len(stale)
    log.info("Cleanup: %d stale indicators identified", len(stale))

    if not stale:
        return

    max_delete = int(cleanup_cfg.get("max_delete_per_run", 500))
    if len(stale) > max_delete:
        log.error(
            "Cleanup aborted: %d stale > max_delete_per_run=%d.",
            len(stale), max_delete
        )
        summary.cp_delete_errors.append(
            f"Aborted — {len(stale)} exceeds max_delete_per_run={max_delete}"
        )
        return

    # ---------- TEST MODE ----------
    if test_mode:
        est_seconds = len(stale) * float(
            cfg["api"].get("rate_limit_delay_seconds", 0.6))
        log.info("=" * 60)
        log.info("*** TEST MODE — no deletions will be performed ***")
        log.info("=" * 60)
        log.info("Would delete %d stale indicators from feed '%s' "
                 "(1 API call each, ~%.1fs estimated)",
                 len(stale), summary.cp_feed_name, est_seconds)
        preview = stale[:10]
        log.info("Sample stale indicators (first %d of %d):\n%s",
                 len(preview), len(stale),
                 json.dumps(preview, indent=2))

        out_dir = Path(cfg["output"]["directory"])
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stale_path = out_dir / f"checkpoint_cleanup_preview_{ts}.json"
        with open(stale_path, "w", encoding="utf-8") as f:
            json.dump({
                "feed_name": summary.cp_feed_name,
                "total_stale": len(stale),
                "stale_indicators": stale
            }, f, indent=2)
        log.info("Full cleanup preview written to: %s", stale_path)
        log.info("=" * 60)
        return

    # ---------- REAL DELETE ----------
    per_call_delay = float(cfg["api"].get("rate_limit_delay_seconds", 0.6))
    total = len(stale)

    log.info("Deleting %d stale indicators one at a time "
             "(API supports single-indicator delete only)", total)

    for idx, item in enumerate(stale, start=1):
        value = item["value"]
        indicator_type = item.get("indicator_type", "ipv4")

        try:
            cp_client.delete_indicator(
                summary.cp_feed_id, indicator_type, value
            )
            summary.cp_deleted += 1

            if idx % 25 == 0 or idx == total:
                log.info("Progress: %d/%d deleted (%d ok, %d failed)",
                         idx, total, summary.cp_deleted,
                         summary.cp_failed_delete)
        except Exception as e:
            summary.cp_failed_delete += 1
            err = (f"Delete {idx}/{total} ({value}): "
                   f"{type(e).__name__}: {e}")
            summary.cp_delete_errors.append(err)
            log.error(err)

        time.sleep(per_call_delay)

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


# ============================================================
# DEFENDER SUMMARY STATS
# ============================================================

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
        description="Export Defender XDR indicators, inject IPv4 IOCs "
                    "into Check Point IOC Management, and (optionally) "
                    "clean up stale IOCs."
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Dry run — show what would be done but make no changes."
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    parser.add_argument(
        "-i", "--input-file",
        help="Load Defender indicators from a local JSON or CSV file "
             "instead of calling the Defender API. Supports raw export "
             "format, single-page envelope, plain array, single object, "
             "or CSV with header row (columns auto-mapped)."
    )
    parser.add_argument(
        "--skip-checkpoint", action="store_true",
        help="Skip Check Point injection and cleanup entirely."
    )
    parser.add_argument(
        "--cleanup", action="store_true",
        help="Force-enable cleanup for this run (overrides config)."
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="Force-disable cleanup for this run (overrides config)."
    )
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

    # Only build a Defender token manager if we're going to hit the API
    token_manager = None
    if not args.input_file:
        token_manager = TokenManager(session, cfg)

    exit_code = 0
    try:
        # 1. Load indicators — either from Defender API or from an input file
        if args.input_file:
            log.info("=" * 60)
            log.info("OFFLINE MODE: loading indicators from file "
                     "(Defender API will NOT be called)")
            log.info("Source file: %s", args.input_file)
            log.info("=" * 60)
            summary.source = "file"
            summary.source_path = args.input_file
            indicators, raw_pages = load_indicators_from_file(args.input_file)
        else:
            log.info("Loading indicators from Defender XDR API")
            indicators, raw_pages = get_all_indicators(
                session, token_manager, cfg
            )

        # 2. Export files
        paths = build_output_paths(cfg)
        export_raw_json(raw_pages, paths["raw"])
        export_txt(indicators, paths["txt"])
        export_csv(indicators, paths["csv"])
        log_summary(indicators, summary)

        # 3. Filter to public IPv4
        ipv4_indicators = filter_ipv4_indicators(indicators, summary)

        # 4. Check Point ops
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
                    f"Check Point feed '{summary.cp_feed_name}' not found. "
                    f"Create it in the IOC Management portal first."
                )
            summary.cp_feed_id = feed_id
            log.info("Resolved feed id=%s", feed_id)

            log.info("Loading existing indicators from feed for comparison")
            existing = cp_client.list_indicators(feed_id)
            log.info("Feed currently contains %d indicators", len(existing))

            inject_into_checkpoint(
                session, cfg, ipv4_indicators, summary,
                test_mode=args.test,
                cp_client=cp_client,
                existing_indicators=existing
            )

            cleanup_stale_from_checkpoint(
                cfg, ipv4_indicators, summary,
                test_mode=args.test,
                cp_client=cp_client,
                existing_indicators=existing
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
        summary.finalize()
        summary.log_report()
        try:
            write_summary_report(summary, cfg)
        except Exception as e:
            log.error("Failed to write summary report: %s", e)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())