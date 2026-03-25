"""
parser.py

Responsible for reading raw log files and extracting structured scan records.
Groups all log lines by scan ID so downstream modules receive coherent bundles.

Supported scan ID formats (per PRD section 3):
    - scan ID XXXX          e.g. "Scan ID 4500 timer started"
    - scanId = XXXX         e.g. "Scanning buffer via OEX with scanId = 4500"
    - [scan-id:XXXX]        e.g. "[SFS] [scan-id:4500] Start scanning: ..."
"""

import re
from pathlib import Path
from typing import Generator, Optional

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Matches:  scan ID 4500  /  Scan ID 4500  /  SCAN ID 4500
_RE_SCAN_ID_WORDS = re.compile(r"\bscan\s+ID\s+(\d+)", re.IGNORECASE)

# Matches:  scanId = 4500  (with optional whitespace around '=')
_RE_SCAN_ID_CAMEL = re.compile(r"\bscanId\s*=\s*(\d+)")

# Matches:  [scan-id:4500]
_RE_SCAN_ID_BRACKET = re.compile(r"\[scan-id:(\d+)\]")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def iter_log_files(logs_dir: str) -> Generator[Path, None, None]:
    """
    Yield Path objects for every .log or .txt file directly inside logs_dir.

    Skips subdirectories and files with any other extension.
    Does not recurse into subdirectories.
    """
    base = Path(logs_dir)
    if not base.is_dir():
        return

    for entry in sorted(base.iterdir()):
        if entry.is_file() and entry.suffix.lower() in {".log", ".txt"}:
            yield entry


def extract_scan_id(line: str) -> Optional[str]:
    """
    Return the scan ID found in line, or None if no known pattern matches.

    Tries all three supported formats and returns the first match.
    The ID is always returned as a string (the raw numeric value).
    """
    for pattern in (_RE_SCAN_ID_BRACKET, _RE_SCAN_ID_CAMEL, _RE_SCAN_ID_WORDS):
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


def _detect_encoding(path: Path) -> str:
    """Return 'utf-16' if the file starts with a UTF-16 BOM, else 'utf-8'."""
    try:
        with path.open("rb") as f:
            bom = f.read(2)
        if bom in (b"\xff\xfe", b"\xfe\xff"):
            return "utf-16"
    except OSError:
        pass
    return "utf-8"


def parse_log_file(log_path: Path) -> dict[str, list[str]]:
    """
    Parse a single log file and return a mapping of scan_id -> list of lines.

    Lines that contain no recognisable scan ID are silently ignored.
    Malformed / unreadable lines are skipped without raising an exception.
    Handles both UTF-8 and UTF-16 encoded files.

    Returns:
        {
            "4500": ["line containing 4500", ...],
            "4501": [...],
            ...
        }
    """
    scans: dict[str, list[str]] = {}
    encoding = _detect_encoding(log_path)

    try:
        with log_path.open(encoding=encoding, errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                scan_id = extract_scan_id(line)
                if scan_id is None:
                    continue
                scans.setdefault(scan_id, []).append(line)
    except OSError as exc:
        # Log file unreadable — skip gracefully
        print(f"[parser] Warning: could not read {log_path}: {exc}")

    return scans


def parse_logs(logs_dir: str) -> dict[str, dict]:
    """
    Parse all log files in logs_dir and return a unified scan registry.

    If the same scan ID appears in multiple files, its lines are merged
    under a single entry and the first source file name is preserved.

    Returns:
        {
            "4500": {
                "lines": ["line1", "line2", ...],
                "source_log_file": "security_scan_001.log",
            },
            ...
        }
    """
    registry: dict[str, dict] = {}

    for log_path in iter_log_files(logs_dir):
        file_scans = parse_log_file(log_path)

        for scan_id, lines in file_scans.items():
            if scan_id not in registry:
                registry[scan_id] = {
                    "lines": [],
                    "source_log_file": log_path.name,
                }
            registry[scan_id]["lines"].extend(lines)

    return registry
