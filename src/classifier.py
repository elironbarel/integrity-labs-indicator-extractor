"""
classifier.py

Classifies each suspicious indicator as true_positive, false_positive, or uncertain.

Classification logic (signal-based, rule-driven):
  false_positive  — trusted system path OR valid digital signature (no strong TP signals)
  true_positive   — strong malware indicators (threat name, behavioral, malware verdict, suspicious path)
  uncertain       — weak/ambiguous signals (PUA, Packed, ML-only, or mixed TP+FP signals)

Each indicator receives a 'classification' label and a 'classification_reason' string.
"""

from typing import Optional

# ---------------------------------------------------------------------------
# Reference lists
# ---------------------------------------------------------------------------

# Path segments that suggest legitimate installed or OS software
_TRUSTED_PATH_SEGMENTS = (
    r"\windows\system32",
    r"\windows\syswow64",
    r"\program files",
    r"\program files (x86)",
)

# Path segments that suggest higher risk (user-controlled locations)
_SUSPICIOUS_PATH_SEGMENTS = (
    r"\users",
    r"\downloads",
    r"\desktop",
    r"\appdata",
    r"\temp",
    r"\roaming",
)

# Threat name keywords that indicate a clearly malicious family
_STRONG_THREAT_KEYWORDS = (
    "trojan",
    "backdoor",
    "ransomware",
    "coinminer",
    "dropper",
    "remoteaccess",
    "worm",
    "spyware",
)

# Threat name prefixes / keywords that are lower-confidence or ambiguous
_UNCERTAIN_THREAT_KEYWORDS = (
    "pua",
    "packed",
    "bundler",
    "generic",
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def normalize_text(value: Optional[str]) -> str:
    """Return a lowercase, stripped string. Returns empty string for None."""
    if value is None:
        return ""
    return value.strip().lower()


def is_trusted_path(file_path: Optional[str]) -> bool:
    """
    Return True if the file path suggests a known system or installed-software location.

    Trusted locations: Windows System32, SysWOW64, Program Files.
    """
    text = normalize_text(file_path)
    return any(segment in text for segment in _TRUSTED_PATH_SEGMENTS)


def is_suspicious_path(file_path: Optional[str]) -> bool:
    """
    Return True if the file path suggests a higher-risk, user-controlled location.

    Suspicious locations: Users folder, Downloads, Desktop, AppData, Temp, Roaming.
    """
    text = normalize_text(file_path)
    return any(segment in text for segment in _SUSPICIOUS_PATH_SEGMENTS)


def is_strong_threat_name(threat_name: Optional[str]) -> bool:
    """
    Return True if the threat name contains a keyword associated with clearly malicious families.

    Examples: Trojan, Backdoor, Ransomware, CoinMiner, Dropper, RemoteAccess, Worm, Spyware.
    """
    text = normalize_text(threat_name)
    return any(kw in text for kw in _STRONG_THREAT_KEYWORDS)


def is_uncertain_threat_name(threat_name: Optional[str]) -> bool:
    """
    Return True if the threat name suggests a weaker or ambiguous classification.

    Examples: PUA (Potentially Unwanted Application), Packed, Bundler, Generic.
    """
    text = normalize_text(threat_name)
    return any(kw in text for kw in _UNCERTAIN_THREAT_KEYWORDS)


def is_valid_signature(signature_info: Optional[str]) -> bool:
    """
    Return True if the signature information suggests the file is legitimately signed.

    Looks for: 'signed = valid', 'microsoft', 'verified'.
    """
    text = normalize_text(signature_info)
    return any(kw in text for kw in ("signed = valid", "microsoft", "verified"))


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def classify_indicator(indicator: dict) -> dict:
    """
    Add 'classification' and 'classification_reason' fields to the indicator dict.

    Collects TP (true-positive) signals and FP (false-positive) signals separately,
    then decides:
      - Both TP and FP signals present  →  uncertain  (mixed signals)
      - Only FP signals                 →  false_positive
      - Only TP signals                 →  true_positive
      - Only uncertain signals          →  uncertain
      - No strong signals               →  uncertain

    The original dict is mutated in place and also returned.
    """
    file_path      = indicator.get("suspicious_file")
    threat_name    = indicator.get("threat_name")
    detection_type = indicator.get("detection_type", "")
    extra          = indicator.get("extra_details") or {}
    final_verdict  = extra.get("finalVerdict")
    signature      = extra.get("signature")
    behavioral     = extra.get("behavioralThreat")

    # ── Collect signals ──────────────────────────────────────────────────

    tp_signals: list[str] = []   # evidence of a real threat
    fp_signals: list[str] = []   # evidence of a benign / trusted file
    unc_signals: list[str] = []  # ambiguous evidence

    # FP signals
    if is_trusted_path(file_path):
        fp_signals.append("trusted system path")
    if is_valid_signature(signature):
        fp_signals.append("valid digital signature")

    # TP signals
    if is_strong_threat_name(threat_name):
        tp_signals.append(f"strong threat name ({threat_name})")
    if detection_type == "Behavioral Engine" or behavioral:
        tp_signals.append(f"behavioral detection ({behavioral or 'present'})")
    if normalize_text(final_verdict) == "malware":
        tp_signals.append("malware verdict")
    if is_suspicious_path(file_path):
        tp_signals.append("suspicious file location")

    # Uncertain signals (only relevant if no strong TP signals exist)
    if is_uncertain_threat_name(threat_name) and not tp_signals:
        unc_signals.append(f"ambiguous threat type ({threat_name})")

    # ── Decide ───────────────────────────────────────────────────────────

    if tp_signals and fp_signals:
        # Mixed signals: cannot reliably classify
        classification = "uncertain"
        reason = (
            f"Mixed signals — suspicious: {'; '.join(tp_signals)} | "
            f"benign: {'; '.join(fp_signals)}"
        )
    elif fp_signals:
        classification = "false_positive"
        reason = f"Benign indicators: {'; '.join(fp_signals)}"
    elif tp_signals:
        classification = "true_positive"
        reason = f"Malicious indicators: {'; '.join(tp_signals)}"
    elif unc_signals:
        classification = "uncertain"
        reason = f"Low-confidence detection: {'; '.join(unc_signals)}"
    else:
        classification = "uncertain"
        reason = "Insufficient context to determine classification"

    indicator["classification"] = classification
    indicator["classification_reason"] = reason
    return indicator


def classify_indicators(indicators: list[dict]) -> list[dict]:
    """
    Classify every suspicious indicator in the list.

    Calls classify_indicator() on each item and returns the updated list.
    """
    for indicator in indicators:
        classify_indicator(indicator)
    return indicators
