"""
report_builder.py

Assembles the final JSON report from classified indicators and processing stats.

Internal snake_case field names are mapped to the camelCase output schema
defined in the PRD.  None values are excluded from extraDetails to keep
the output clean.
"""

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Internal → output field mapping
# ---------------------------------------------------------------------------

def _build_extra_details(indicator: dict) -> dict:
    """
    Build the extraDetails block from the internal extra_details dict.

    Rules:
    - Only include fields that have a non-None value.
    - Add a triggeredRules list that records which detection rules fired.
    """
    raw = indicator.get("extra_details") or {}

    # Determine which detection rules were triggered by this scan
    triggered: list[str] = []
    if indicator.get("threat_name") is not None:
        triggered.append("Threat name detected")
    if raw.get("behavioralThreat") is not None:
        triggered.append("Behavioral threat detected")
    try:
        if indicator.get("ml_score") is not None and float(indicator["ml_score"]) > 0.75:
            triggered.append("ML score > 0.75")
    except (ValueError, TypeError):
        pass

    # Build the dict, skipping None values
    extra: dict = {}
    if raw.get("finalVerdict") is not None:
        extra["finalVerdict"] = raw["finalVerdict"]
    if raw.get("mlProbability") is not None:
        extra["mlProbability"] = raw["mlProbability"]
    if raw.get("behavioralThreat") is not None:
        extra["behavioralThreat"] = raw["behavioralThreat"]
    if raw.get("signature") is not None:
        extra["signature"] = raw["signature"]
    if triggered:
        extra["triggeredRules"] = triggered

    return extra


def build_indicator_object(indicator: dict) -> dict:
    """
    Convert an internal classified indicator into the final output format.

    Maps snake_case internal keys to camelCase JSON output keys as required
    by the PRD output schema.

    Args:
        indicator: dict produced by evaluator + classifier pipeline

    Returns:
        Dict with camelCase keys ready for JSON serialisation.
    """
    return {
        "scanId":               indicator.get("scan_id"),
        "detectionType":        indicator.get("detection_type"),
        "suspiciousFile":       indicator.get("suspicious_file"),
        "threatName":           indicator.get("threat_name"),
        "mlScore":              indicator.get("ml_score"),
        "sourceLogFile":        indicator.get("source_log_file"),
        "extraDetails":         _build_extra_details(indicator),
        "classification":       indicator.get("classification"),
        "classificationReason": indicator.get("classification_reason"),
    }


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report(indicators: list[dict], stats: dict) -> dict:
    """
    Assemble the full report dict from classified indicators and run statistics.

    Args:
        indicators: list of classified indicator dicts (internal format)
        stats: dict with totalLogsProcessed and totalScansAnalyzed

    Returns:
        {
            "summary": {
                "totalLogsProcessed":      int,
                "totalScansAnalyzed":      int,
                "suspiciousIndicatorsFound": int,
            },
            "indicators": [ <camelCase indicator objects> ],
        }
    """
    output_indicators = [build_indicator_object(ind) for ind in indicators]

    return {
        "summary": {
            "totalLogsProcessed":       stats.get("totalLogsProcessed", 0),
            "totalScansAnalyzed":       stats.get("totalScansAnalyzed", 0),
            "suspiciousIndicatorsFound": len(output_indicators),
        },
        "indicators": output_indicators,
    }


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------

def write_report(report: dict, output_path: str) -> None:
    """
    Serialise report to JSON and write to output_path.

    Uses indent=2 for human-readable output.
    Prints a warning and continues if the file cannot be written.
    """
    try:
        Path(output_path).write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"[report_builder] Warning: could not write report to {output_path}: {exc}")
