"""
evaluator.py

Applies detection rules to a bundle of log lines for a given scan ID.
Returns a detection dict if the scan is suspicious, None otherwise.

Detection rules (any one triggers suspicion):
  R1 — Machine Learning    : Score > 0.75  OR  probability > 75%
  R2 — Static File Scanner : threat name present, non-NULL, non-empty
  R3 — Behavioral Engine   : `threat =` present (from behavioral engine lines)

Detection type priority (highest wins):
  Behavioral Engine  >  Static File Scanner  >  Machine Learning
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

ML_SCORE_THRESHOLD = 0.75

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# R1 — ML score:  "Score: 0.89"
_RE_ML_SCORE = re.compile(r"\bScore:\s*([\d.]+)", re.IGNORECASE)

# R1 — Probability:  "probability = 92%"
_RE_ML_PROBABILITY = re.compile(r"\bprobability\s*=\s*(\d+(?:\.\d+)?)%", re.IGNORECASE)

# R2 — Threat name (colon form):  "Threat name: Trojan:Win32.Emotet. Silent:"
# Stops at a dot followed by whitespace (the separator before the next field).
# Dots within the threat name (e.g. Win32.Emotet) are included because they
# are followed by a non-whitespace character.
_RE_THREAT_NAME_COLON = re.compile(
    r"\bThreat name:\s*((?:[^.\n]|\.(?!\s))+)",
    re.IGNORECASE,
)

# R2 — Threat name (quoted form):  "threat name = 'Trojan:Win32.CrackedApp'"
_RE_THREAT_NAME_QUOTED = re.compile(
    r"\bthreat name\s*=\s*'([^']+)'",
    re.IGNORECASE,
)

# R3 — Behavioral threat:  "threat = Trojan:Win32.Dropper"
# Uses word boundary to avoid matching "threat name = ..." (letters follow, not '=')
_RE_BEHAVIORAL_THREAT = re.compile(r"\bthreat\s*=\s*([^,\n]+)")

# File path (quoted):  path = "C:\...\file.exe"
_RE_FILE_PATH_QUOTED = re.compile(r'\bpath\s*=\s*"([^"]+)"')

# File path (scan start):  "[SFS] [scan-id:X] Start scanning: C:\...\file.exe"
# Greedy to end-of-line — paths may contain spaces (e.g. Program Files)
_RE_FILE_PATH_SCANNING = re.compile(
    r"\bStart scanning:\s*(.+)",
    re.IGNORECASE,
)

# Final verdict (short form):  "final verdict: malware"
_RE_VERDICT_SHORT = re.compile(r"\bfinal verdict:\s*(\w+)", re.IGNORECASE)

# Final verdict (long form):  "Final verdict for scan ID X, ..., Verdict: malware"
_RE_VERDICT_LONG = re.compile(r"\bVerdict:\s*(\w+)")

# Signature:  "Signature verified: ValidVendor, signed = VALID"
_RE_SIGNATURE = re.compile(
    r"Signature verified:\s*([^,\n]+),\s*signed\s*=\s*(\w+)",
    re.IGNORECASE,
)

# NULL-like values that must NOT count as a real threat name (R2)
_NULL_THREAT_VALUES = {"null", "none", ""}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _is_null_threat(value: str) -> bool:
    return value.strip().lower() in _NULL_THREAT_VALUES


def _extract_threat_name(line: str) -> Optional[str]:
    """
    Return the threat name from a line, or None if absent / NULL.

    Tries the single-quoted form first (more specific), then the colon form.
    """
    # quoted form:  threat name = 'Trojan:Win32.Emotet'
    m = _RE_THREAT_NAME_QUOTED.search(line)
    if m:
        value = m.group(1).strip()
        return None if _is_null_threat(value) else value

    # colon form:  Threat name: Trojan:Win32.Emotet. Silent: 0
    m = _RE_THREAT_NAME_COLON.search(line)
    if m:
        value = m.group(1).strip().rstrip(".")
        return None if _is_null_threat(value) else value

    return None


def _extract_ml_score(line: str) -> Optional[float]:
    """
    Return the ML confidence score as a float if found, else None.

    Handles both "Score: 0.89" and "probability = 92%" formats.
    Probability is converted to a 0–1 scale.
    """
    m = _RE_ML_SCORE.search(line)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass

    m = _RE_ML_PROBABILITY.search(line)
    if m:
        try:
            return float(m.group(1)) / 100.0
        except ValueError:
            pass

    return None


def _extract_final_verdict(line: str) -> Optional[str]:
    """Return a normalised verdict string if found in line, else None."""
    known_verdicts = {"malware", "clean", "unknown", "pua", "adware"}

    m = _RE_VERDICT_SHORT.search(line)
    if not m:
        m = _RE_VERDICT_LONG.search(line)
    if m:
        verdict = m.group(1).lower()
        if verdict in known_verdicts:
            return verdict

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_scan(scan_id: str, lines: list[str]) -> Optional[dict]:
    """
    Evaluate a scan bundle against all detection rules.

    Iterates through all lines, extracts relevant fields, then applies
    the three detection rules.  If at least one rule fires, returns a
    detection dict; otherwise returns None.

    Returns:
        {
            "scan_id": str,
            "detection_type": str,        # "Machine Learning" / "Static File Scanner" / "Behavioral Engine"
            "suspicious_file": str | None,
            "threat_name": str | None,
            "ml_score": str | None,       # raw string, e.g. "0.89"
            "extra_details": {
                "finalVerdict":    str | None,
                "mlProbability":   str | None,  # e.g. "92%"
                "signature":       str | None,  # e.g. "ValidVendor, signed = VALID"
                "behavioralThreat":str | None,
            },
        }
    """
    suspicious_file: Optional[str] = None
    threat_name: Optional[str] = None
    ml_score_value: Optional[float] = None
    ml_probability_str: Optional[str] = None
    final_verdict: Optional[str] = None
    signature_info: Optional[str] = None
    behavioral_threat: Optional[str] = None

    for line in lines:
        # ── File path ────────────────────────────────────────────────────
        if suspicious_file is None:
            m = _RE_FILE_PATH_QUOTED.search(line)
            if m:
                suspicious_file = m.group(1)
            else:
                m = _RE_FILE_PATH_SCANNING.search(line)
                if m:
                    suspicious_file = m.group(1)

        # ── Threat name (R2) ─────────────────────────────────────────────
        if threat_name is None:
            threat_name = _extract_threat_name(line)

        # ── ML score (R1) ────────────────────────────────────────────────
        score = _extract_ml_score(line)
        if score is not None:
            # Keep the highest score seen across all lines for this scan
            if ml_score_value is None or score > ml_score_value:
                ml_score_value = score
            # Capture the probability string for extra_details (display)
            m = _RE_ML_PROBABILITY.search(line)
            if m and ml_probability_str is None:
                ml_probability_str = m.group(1) + "%"

        # ── Behavioral threat (R3) ───────────────────────────────────────
        if behavioral_threat is None:
            m = _RE_BEHAVIORAL_THREAT.search(line)
            if m:
                behavioral_threat = m.group(1).strip()

        # ── Final verdict ────────────────────────────────────────────────
        if final_verdict is None:
            final_verdict = _extract_final_verdict(line)

        # ── Signature ────────────────────────────────────────────────────
        if signature_info is None:
            m = _RE_SIGNATURE.search(line)
            if m:
                signature_info = f"{m.group(1).strip()}, signed = {m.group(2).upper()}"

    # ── Apply detection rules ────────────────────────────────────────────
    r1_triggered = ml_score_value is not None and ml_score_value > ML_SCORE_THRESHOLD
    r2_triggered = threat_name is not None
    r3_triggered = behavioral_threat is not None

    if not (r1_triggered or r2_triggered or r3_triggered):
        return None  # clean — no detection rules fired

    # Assign detection type by priority: Behavioral > Static > ML
    if r3_triggered:
        detection_type = "Behavioral Engine"
    elif r2_triggered:
        detection_type = "Static File Scanner"
    else:
        detection_type = "Machine Learning"

    return {
        "scan_id": scan_id,
        "detection_type": detection_type,
        "suspicious_file": suspicious_file,
        "threat_name": threat_name,
        "ml_score": str(round(ml_score_value, 4)) if ml_score_value is not None else None,
        "extra_details": {
            "finalVerdict": final_verdict,
            "mlProbability": ml_probability_str,
            "signature": signature_info,
            "behavioralThreat": behavioral_threat,
        },
    }


def evaluate_scans(scan_records: dict) -> list[dict]:
    """
    Run evaluate_scan over every entry in scan_records.

    Attaches source_log_file from the registry to each detection dict.
    Returns only suspicious scans (None results are filtered out).

    Args:
        scan_records: dict returned by parse_logs()

    Returns:
        List of detection dicts, one per suspicious scan.
    """
    results = []
    for scan_id, record in scan_records.items():
        detection = evaluate_scan(scan_id, record["lines"])
        if detection:
            detection["source_log_file"] = record["source_log_file"]
            results.append(detection)
    return results
