# Product Requirements Document (PRD)

## Project: Indicator Extractor (Integrity Labs Home Assignment)

**Status:** Scaffold complete — implementation pending
**Last updated:** 2026-03-23

---

## 1. Objective

Build a standalone Python script that reads security software log files, identifies suspicious scan events using defined detection rules, classifies each finding as true_positive / false_positive / uncertain, and outputs a structured JSON report.

---

## 2. Assignment Summary

| Task | Description |
|------|-------------|
| Task 1 | Parse logs, extract suspicious indicators, produce JSON report |
| Task 2 | Classify each indicator (true_positive / false_positive / uncertain) |
| Task 3 | Document architecture, regex patterns, edge cases, and classification reasoning |

---

## 3. Input Expectations

- **Source:** one or more `.log` files in a directory (default `./logs`)
- **Format:** line-based, timestamped, free-text with embedded key-value pairs
- **Line structure:** `[TIMESTAMP][LEVEL][COMPONENT] message ... key = value ...`
- **Log levels:** `[T]` Trace · `[E]` Error · `[W]` Warning
- Same scan may appear across multiple lines and multiple files

### Key field patterns

| Field | Known patterns |
|-------|----------------|
| Scan ID | `scan ID XXXX` · `scanId = XXXX` · `[scan-id:XXXX]` |
| ML score | `Score: X.XX` · `probability = XX%` |
| Threat name | `threat name = 'ThreatName'` · `threatName: 'ThreatName'` |
| Behavioral threat | `threat = THREAT_TYPE` |
| File path | `path = "filepath"` · `scanning: filepath` |
| Final verdict | `final verdict: clean/unknown/malware/pua/adware` |
| Digital signature | `Signature verified: VENDOR, signed = VALID/INVALID` |

---

## 4. Output Expectations

### Per-indicator required fields

| Field | Type | Description |
|-------|------|-------------|
| `scanId` | string | Unique scan identifier |
| `detectionType` | string | `"Machine Learning"` / `"Static File Scanner"` / `"Behavioral Engine"` |
| `suspiciousFile` | string \| null | Path to the scanned file |
| `threatName` | string \| null | Detected threat name |
| `mlScore` | string \| null | ML confidence score |
| `sourceLogFile` | string | Filename of the originating log |
| `extraDetails` | object | Additional context (finalVerdict, mlProbability, signature, etc.) |
| `classification` | string | `true_positive` / `false_positive` / `uncertain` |
| `classificationReason` | string | Human-readable explanation of the classification decision |

### Summary fields

| Field | Type | Description |
|-------|------|-------------|
| `totalLogsProcessed` | int | Number of log files read |
| `totalScansAnalyzed` | int | Total distinct scan IDs encountered |
| `suspiciousIndicatorsFound` | int | Count of indicators emitted |

### Report skeleton

```json
{
  "suspiciousIndicators": [
    {
      "scanId": "4521",
      "detectionType": "Machine Learning",
      "suspiciousFile": "C:\\Users\\test\\malware.exe",
      "threatName": "Trojan:Win32.Generic",
      "mlScore": "0.89",
      "sourceLogFile": "security_scan_001.log",
      "extraDetails": { "finalVerdict": "malware", "mlProbability": "89%" },
      "classification": "true_positive",
      "classificationReason": "Malware verdict, no trusted signature, suspicious path"
    }
  ],
  "summary": {
    "totalLogsProcessed": 3,
    "totalScansAnalyzed": 1250,
    "suspiciousIndicatorsFound": 12
  }
}
```

---

## 5. Suspicious Detection Rules

A scan is **suspicious** if it satisfies at least one of:

| Rule | Label | Trigger condition |
|------|-------|-------------------|
| R1 | Machine Learning | `Score:` > **0.75** OR `probability` > **75%** |
| R2 | Static File Scanner | `threat name` / `threatName` is present, non-empty, and **not** `NULL` / `"NULL"` / `null` |
| R3 | Behavioral Engine | `threat =` is present in a behavioral log line |

> **Critical:** `"Threat name: NULL"` and `threat name = 'NULL'` must **not** trigger R2.

---

## 6. Detection Type Priority

When a single scan triggers multiple rules, assign the **highest-priority** detection type:

```
Behavioral Engine  >  Static File Scanner  >  Machine Learning
```

---

## 7. Classification Strategy

| Classification | Criteria |
|----------------|----------|
| `false_positive` | File signed by a known trusted vendor (Microsoft, Google, Intel, Nvidia, Adobe, …) **or** file resides in a trusted system path (`C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Program Files`, `C:\Program Files (x86)`) |
| `uncertain` | Threat type prefix is `Packed:`, `PUA:`, or `Adware:` without additional corroborating signals; or mixed / inconclusive signals |
| `true_positive` | Malware verdict, strong threat name (Trojan, Backdoor, CoinMiner, Ransomware, …), behavioral detection, and/or suspicious file location (Downloads, AppData, Temp, Desktop) — no FP signals present |

Every indicator **must** include a `classificationReason` string explaining the decision.

---

## 8. Architecture

```
indicator_extractor.py      ← CLI entry point; orchestrates the pipeline
src/
  parser.py                 ← File I/O; groups raw log lines by scan ID
  evaluator.py              ← Applies detection rules; returns detection dict or None
  classifier.py             ← Adds classification + classificationReason
  report_builder.py         ← Assembles and serialises the final JSON report
```

### Data flow

```
log files
   │
   ▼
parser.py  ──► {scan_id: [lines]}
   │
   ▼
evaluator.py  ──► detection dict (or None if clean)
   │
   ▼
classifier.py  ──► detection dict + classification fields
   │
   ▼
report_builder.py  ──► report.json
```

---

## 9. Design Principles

- **Modular:** each module has a single, clear responsibility
- **Readable:** short functions, descriptive names, minimal nesting
- **Robust to missing data:** missing fields default to `null`; no crash on malformed lines
- **No overengineering:** no ORM, no config files, no abstract base classes unless truly needed
- **Regex documented:** all patterns named and explained inline

---

## 10. Edge Cases to Handle

| Scenario | Expected behaviour |
|----------|--------------------|
| Missing field (e.g. no `Score:` line) | Field is `null` in output; scan still evaluated on other rules |
| `threat name = NULL` / `threat name = 'NULL'` | Must **not** trigger R2 |
| Multiple formats for the same field | All known patterns captured by regex alternatives |
| Duplicate scan IDs across log files | Treated as same scan; lines merged |
| Single scan triggers multiple rules | Use priority order to assign `detectionType` |
| Out-of-order log lines | Grouping by scan ID is order-agnostic |
| Noisy / unrelated lines | Lines with no recognisable scan ID ignored or logged at debug level |
| Empty log file | Handled gracefully; contributes 0 to `totalScansAnalyzed` |

---

## 11. Non-Goals

- No external APIs or network calls
- No real-time malware validation
- No UI or web interface

---

## 12. Success Criteria

- Correct identification of all suspicious scans in the provided log files
- Clean, valid JSON output matching the required schema
- Clear, reproducible classification logic with reasoning
- Easy-to-read, maintainable, and well-documented code

---

## 13. Run Command

```bash
python indicator_extractor.py --logs-dir ./logs --output report.json
```

---

## 14. Submission Checklist

- [ ] `indicator_extractor.py` — working script
- [ ] `README.md` — documentation (patterns, FP logic, edge cases, improvements)
- [ ] `report.json` — sample output generated against the provided logs
- [ ] All helper modules under `src/`
