"""
indicator_extractor.py

Entry point for the Suspicious Indicator Extractor.

Usage:
    python indicator_extractor.py --logs-dir ./logs --output report.json
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from src.parser import iter_log_files, parse_logs
from src.evaluator import evaluate_scans
from src.classifier import classify_indicators
from src.report_builder import build_report, write_report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract suspicious indicators from security scan logs."
    )
    parser.add_argument(
        "--logs-dir",
        default="./logs",
        help="Directory containing .log / .txt files (default: ./logs)",
    )
    parser.add_argument(
        "--output",
        default="report.json",
        help="Output JSON report path (default: report.json)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

def print_sample_scans(scan_records: dict, n: int = 3) -> None:
    """Print a short parsing summary for the first n scan IDs."""
    for scan_id in list(scan_records.keys())[:n]:
        record = scan_records[scan_id]
        print(
            f"  scan_id={scan_id}, "
            f"lines={len(record['lines'])}, "
            f"source={record['source_log_file']}"
        )


def print_sample_indicators(indicators: list[dict], n: int = 3) -> None:
    """Print a short classified-indicator summary for the first n items."""
    for ind in indicators[:n]:
        file_short = ind["suspicious_file"] or "unknown"
        if len(file_short) > 55:
            file_short = "..." + file_short[-52:]
        print(
            f"  scan_id={ind['scan_id']}, "
            f"type={ind['detection_type']}, "
            f"classification={ind['classification']}\n"
            f"    file={file_short}\n"
            f"    threat={ind['threat_name']}, ml_score={ind['ml_score']}\n"
            f"    reason={ind['classification_reason']}"
        )


def print_first_report_indicator(report: dict) -> None:
    """Print the first indicator from the finished report as a JSON preview."""
    indicators = report.get("indicators", [])
    if not indicators:
        return
    print("\nFirst indicator (report format):")
    print(json.dumps(indicators[0], indent=4, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # ── Step 1: Parse ────────────────────────────────────────────────────
    logs_path = Path(args.logs_dir)
    if not logs_path.is_dir():
        print(f"Error: logs directory not found: {args.logs_dir}", file=sys.stderr)
        sys.exit(1)

    log_files = list(iter_log_files(args.logs_dir))
    total_logs = len(log_files)

    if total_logs == 0:
        print(f"Warning: no .log or .txt files found in {args.logs_dir}", file=sys.stderr)

    scan_records = parse_logs(args.logs_dir)
    total_scans = len(scan_records)

    print(f"Found {total_logs} log file(s)")
    print(f"Extracted {total_scans} scan IDs")

    if scan_records:
        print("\nParsing sample:")
        print_sample_scans(scan_records, n=3)

    # ── Step 2: Evaluate ─────────────────────────────────────────────────
    indicators = evaluate_scans(scan_records)
    print(f"\nSuspicious scans found: {len(indicators)}")

    # ── Step 3: Classify ─────────────────────────────────────────────────
    classify_indicators(indicators)

    counts = Counter(ind["classification"] for ind in indicators)
    print("\nClassification breakdown:")
    print(f"  true_positive  : {counts.get('true_positive', 0)}")
    print(f"  false_positive : {counts.get('false_positive', 0)}")
    print(f"  uncertain      : {counts.get('uncertain', 0)}")

    if indicators:
        print("\nSample indicators:")
        print_sample_indicators(indicators, n=3)

    # ── Step 4: Build and write report ───────────────────────────────────
    stats = {
        "totalLogsProcessed": total_logs,
        "totalScansAnalyzed": total_scans,
    }
    report = build_report(indicators, stats)
    write_report(report, args.output)

    print(f"\nReport written to {args.output}")

    # ── Step 5: Validation preview ───────────────────────────────────────
    print_first_report_indicator(report)


if __name__ == "__main__":
    main()
