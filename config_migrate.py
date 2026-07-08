#!/usr/bin/env python3
"""
config_migrate.py
------------------
Migrate config.yaml to the latest schema:
  1. If config.yaml exists, back it up as config.yaml.bak-YYYYMMDD-HHMM
  2. Copy config.yaml.example -> config.yaml
  3. Merge values from the backup into the new config.yaml
  4. Prompt the user for any values still missing / placeholder

Usage:
    python config_migrate.py
    python config_migrate.py --example config.yaml.example --target config.yaml
    python config_migrate.py --non-interactive   # fail if anything is missing
"""

import argparse
import getpass
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[FATAL] PyYAML is required. Install with:  pip install pyyaml",
          file=sys.stderr)
    sys.exit(2)


# ============================================================
# HEURISTICS
# ============================================================

# Field-name substrings that should be treated as secrets (hidden input)
SECRET_KEY_HINTS = (
    "secret", "password", "passwd", "access_key", "accesskey",
    "api_key", "apikey", "client_secret", "token"
)

# Values that count as "not really set" — need to prompt the user
PLACEHOLDER_PATTERNS = (
    re.compile(r"^your[-_].*", re.IGNORECASE),
    re.compile(r"^x{4,}[-x]*$", re.IGNORECASE),               # xxxxx or xxxx-xxxx
    re.compile(r"^xxxxxxxx-xxxx-.*", re.IGNORECASE),
    re.compile(r"^<.*>$"),                                     # <put value here>
    re.compile(r"^replace[-_ ]?me$", re.IGNORECASE),
    re.compile(r"^change[-_ ]?me$", re.IGNORECASE),
    re.compile(r"^todo$", re.IGNORECASE),
    re.compile(r"^tbd$", re.IGNORECASE),
    re.compile(r"^example[-_ ].*", re.IGNORECASE),
)


def is_placeholder(value) -> bool:
    """Return True if value looks like an unset placeholder."""
    if value is None:
        return True
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return True
        return any(p.match(s) for p in PLACEHOLDER_PATTERNS)
    return False


def is_secret_key(key_path: str) -> bool:
    """
    Decide if a config key should be treated as sensitive based on
    substring match anywhere in the dotted key path.
    """
    key_lower = key_path.lower()
    return any(hint in key_lower for hint in SECRET_KEY_HINTS)


# ============================================================
# FILE IO
# ============================================================

def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_yaml(data, path: Path):
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False,
                       allow_unicode=True)


def backup_existing(target: Path) -> Path:
    """
    Rename existing target to target.bak-YYYYMMDD-HHMM.
    Returns the backup path. If target does not exist, returns None.
    """
    if not target.exists():
        return None

    ts = datetime.now().strftime("%Y%m%d-%H%M")
    backup_name = f"{target.name}.bak-{ts}"
    backup_path = target.parent / backup_name

    # If we somehow ran twice in the same minute, append seconds
    if backup_path.exists():
        backup_name = f"{target.name}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        backup_path = target.parent / backup_name

    shutil.move(str(target), str(backup_path))
    return backup_path


# ============================================================
# MERGE
# ============================================================

def merge_from_backup(new_cfg, old_cfg, prefix=""):
    """
    Recursively walk the NEW config structure.
    For each leaf whose new value is a placeholder, copy the value from
    the OLD config if it exists there and is not itself a placeholder.

    Returns a list of "still missing" dotted key paths.
    """
    missing = []

    if isinstance(new_cfg, dict):
        for key, new_val in new_cfg.items():
            path = f"{prefix}.{key}" if prefix else key
            old_val = old_cfg.get(key) if isinstance(old_cfg, dict) else None

            if isinstance(new_val, dict):
                sub_missing = merge_from_backup(
                    new_val,
                    old_val if isinstance(old_val, dict) else {},
                    prefix=path
                )
                missing.extend(sub_missing)

            elif isinstance(new_val, list):
                # If the old config has a list, prefer it wholesale
                if isinstance(old_val, list):
                    new_cfg[key] = old_val
                # No placeholder detection inside lists — user must edit if needed

            else:
                # Scalar leaf
                if is_placeholder(new_val):
                    if old_val is not None and not is_placeholder(old_val):
                        new_cfg[key] = old_val
                    else:
                        missing.append(path)
                # else: template already provides a real default — keep it

    return missing


# ============================================================
# PROMPTING
# ============================================================

def get_by_path(data, dotted_path):
    parts = dotted_path.split(".")
    cur = data
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def set_by_path(data, dotted_path, value):
    parts = dotted_path.split(".")
    cur = data
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def coerce_value(raw: str, hint):
    """
    Try to convert the user's typed string to match the type of `hint`
    (the placeholder value from the example). Falls back to string.
    """
    raw = raw.strip()
    if isinstance(hint, bool):
        return raw.lower() in ("1", "true", "yes", "y", "on")
    if isinstance(hint, int) and not isinstance(hint, bool):
        try:
            return int(raw)
        except ValueError:
            return raw
    if isinstance(hint, float):
        try:
            return float(raw)
        except ValueError:
            return raw
    return raw


def prompt_for_missing(new_cfg, missing_paths, non_interactive=False):
    """Prompt the user for each missing dotted-path value."""
    if not missing_paths:
        return

    if non_interactive:
        print("\n[ERROR] --non-interactive was set, but these values are "
              "still missing:", file=sys.stderr)
        for p in missing_paths:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(3)

    print()
    print("=" * 60)
    print(f"  {len(missing_paths)} value(s) need input")
    print("=" * 60)
    print("Press ENTER to skip a value (it will remain as the placeholder).")
    print("Secret fields are hidden as you type.\n")

    for path in missing_paths:
        current = get_by_path(new_cfg, path)
        secret = is_secret_key(path)

        # Show default/placeholder from the example (unless it's a secret)
        default_hint = ""
        if not secret and current not in (None, ""):
            default_hint = f"  [current: {current!r}]"

        label = f"{path}{default_hint}"

        try:
            if secret:
                value = getpass.getpass(f"  {label} (hidden): ")
            else:
                value = input(f"  {label}: ")
        except (KeyboardInterrupt, EOFError):
            print("\n\nAborted by user.")
            sys.exit(130)

        if value.strip():
            set_by_path(new_cfg, path, coerce_value(value, current))
        else:
            print(f"    -> left as-is ({current!r})")


# ============================================================
# MAIN
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Migrate config.yaml to the latest schema, "
                    "preserving values from a previous config."
    )
    parser.add_argument("--example", default="config.yaml.example",
                        help="Path to the template file "
                             "(default: config.yaml.example)")
    parser.add_argument("--target", default="config.yaml",
                        help="Path to the target config "
                             "(default: config.yaml)")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Fail (exit 3) if any values are still missing "
                             "instead of prompting.")
    return parser.parse_args()


def main():
    args = parse_args()

    example_path = Path(args.example)
    target_path = Path(args.target)

    if not example_path.exists():
        print(f"[FATAL] Template not found: {example_path}", file=sys.stderr)
        return 2

    print(f"Template : {example_path}")
    print(f"Target   : {target_path}")

    # Step 1 — Back up existing target
    backup_path = backup_existing(target_path)
    if backup_path:
        print(f"Backup   : {backup_path}")
    else:
        print("Backup   : (no existing config.yaml found)")

    # Step 2 — Copy example to target
    shutil.copy2(str(example_path), str(target_path))
    print(f"Copied   : {example_path} -> {target_path}")

    # Load the new (from example) and old (backup) configs
    new_cfg = load_yaml(target_path)

    old_cfg = {}
    if backup_path:
        try:
            old_cfg = load_yaml(backup_path)
        except Exception as e:
            print(f"[WARN] Could not parse backup {backup_path}: {e}")
            print("       Continuing with the template values only.")

    # Step 3 — Merge values from backup into new
    print()
    print("Merging values from backup...")
    missing = merge_from_backup(new_cfg, old_cfg)

    filled_from_backup = _count_leaves(new_cfg) - len(missing) \
        - _count_untouched_defaults(new_cfg, old_cfg)
    # (best-effort report; not critical if inexact)
    if backup_path:
        print(f"  Restored values from backup where available.")
    if not missing:
        print("  All required fields have values. No prompting needed.")

    # Step 4 — Prompt for anything still missing
    prompt_for_missing(new_cfg, missing,
                       non_interactive=args.non_interactive)

    # Save the merged config
    save_yaml(new_cfg, target_path)

    # Best practice: tighten permissions on the new config
    try:
        target_path.chmod(0o600)
        print(f"\nPermissions set to 600 on {target_path}")
    except Exception as e:
        print(f"\n[WARN] Could not chmod 600 {target_path}: {e}")

    print()
    print("=" * 60)
    print("Migration complete.")
    print("=" * 60)
    print(f"  New config : {target_path}")
    if backup_path:
        print(f"  Backup     : {backup_path}")
    print()
    return 0


# ---------- small helpers used only for the pretty summary ----------

def _count_leaves(d):
    if isinstance(d, dict):
        return sum(_count_leaves(v) for v in d.values())
    if isinstance(d, list):
        return 1
    return 1


def _count_untouched_defaults(new_cfg, old_cfg):
    return 0  # placeholder for a nicer stat later


if __name__ == "__main__":
    sys.exit(main())
