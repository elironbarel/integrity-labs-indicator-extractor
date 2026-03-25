# Suspicious Indicator Extractor

A standalone Python tool that reads endpoint security software logs, identifies suspicious scan events using defined detection rules, classifies each finding as a true/false positive or uncertain, and writes a structured JSON report.

**Assignment:** QA Analyst Home Assignment — Integrity Labs
**Status:** Complete
**Name:** Eliron Barel

---

## Quick Start

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS / Linux

# 2. Run
python indicator_extractor.py --logs-dir ./logs --output report.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--logs-dir` | `./logs` | Directory containing `.log` or `.txt` files |
| `--output` | `report.json` | Path for the JSON output report |

No third-party libraries are required.

---

## Project Structure

```
integrity-labs-indicator-extractor/
├── logs/                      # Input log files
├── src/
│   ├── parser.py              # File I/O — reads and groups lines by scan ID
│   ├── evaluator.py           # Detection rules — flags suspicious scans
│   ├── classifier.py          # Classification — TP / FP / uncertain
│   └── report_builder.py      # Output — assembles and writes report.json
├── indicator_extractor.py     # CLI entry point — orchestrates the pipeline
├── PRD.md                     # Product Requirements Document (source of truth)
└── QA_Analyst_Home_Assignment.md
```

---

## Architecture

The tool is a single linear pipeline. Each module has one responsibility and hands off a well-defined data structure to the next.

```
log files
    │
    ▼
parser.py        reads files, groups all lines by scan ID
    │            → {scan_id: {lines: [...], source_log_file: "..."}}
    ▼
evaluator.py     applies 3 detection rules per scan bundle
    │            → list of detection dicts (suspicious scans only)
    ▼
classifier.py    adds classification + reason to each detection
    │            → same list, enriched with classification fields
    ▼
report_builder   maps internal snake_case → camelCase JSON schema
                 → report.json
```

---

## Parsing Strategy

### Scan ID extraction

Log files use three different formats for scan identifiers. The parser recognises all three:

| Format | Example line |
|--------|-------------|
| `scan ID XXXX` | `Scan ID 4500 timer started for 5 seconds` |
| `scanId = XXXX` | `Scanning buffer via OEX with scanId = 4500` |
| `[scan-id:XXXX]` | `[SFS] [scan-id:4500] Start scanning: C:\...\file.exe` |

Each line is tested against all three patterns. Lines with no recognisable scan ID are silently ignored — this is the primary mechanism for filtering noise.

All lines sharing the same scan ID (across the entire file) are grouped into a single bundle. The bundle is then handed to the evaluator as a unit.

### Multi-file handling

If the same scan ID appears in more than one log file, its lines are merged into a single entry. The source filename recorded is the first file where that ID appeared.

### Encoding

One of the three provided log files is encoded in **UTF-16** (identified by a BOM at the start of the file). The parser detects this automatically by peeking at the first two bytes (`\xff\xfe` or `\xfe\xff`) and opens the file with the correct encoding. All other files are treated as UTF-8 with `errors="replace"` so that individual corrupt bytes never crash the run.

---

## Detection Logic

A scan is flagged as **suspicious** if at least one of the three rules fires. All rules are evaluated independently; the one with the highest priority determines the `detectionType` in the report.

### Rule 1 — Machine Learning (`detectionType: "Machine Learning"`)

Triggered when the ML confidence score exceeds **0.75**.

Two log formats are handled:

```
Score: 0.89                   → parsed as float directly
probability = 92%             → divided by 100 → 0.92
```

If both appear for the same scan, the higher value is used. The threshold is `> 0.75` (strict).

### Rule 2 — Static File Scanner (`detectionType: "Static File Scanner"`)

Triggered when a threat name is present and is **not** a NULL placeholder.

Two log formats are handled:

```
Threat name: Trojan:Win32.Emotet. Silent: 0    ← colon form
threat name = 'Trojan:Win32.CrackedApp'         ← quoted form
```

The quoted form is checked first (it is more specific). Values that equal `NULL`, `null`, `None`, or empty string are explicitly rejected — `Threat name: NULL` does **not** trigger this rule.

The threat name regex allows dots within the name (`Win32.Emotet`) by only stopping at a dot followed by whitespace (the field separator).

### Rule 3 — Behavioral Engine (`detectionType: "Behavioral Engine"`)

Triggered by behavioral detection lines:

```
[BehavioralEngine] [RMS][YARA] threat = Trojan:Win32.Dropper, scanId = 4599
```

Pattern: `\bthreat\s*=\s*([^,\n]+)`. The word boundary before `threat` ensures this does not match `threat name = 'something'`, which has letters (not `=`) immediately after `threat`.

### Priority

When multiple rules fire for the same scan, the reported `detectionType` is assigned by priority:

```
Behavioral Engine  >  Static File Scanner  >  Machine Learning
```

---

## Classification Logic

Each suspicious scan is classified using a **signal-based** approach. The classifier collects separate lists of true-positive (TP) and false-positive (FP) signals, then decides:

| Signals present | Classification |
|----------------|----------------|
| TP signals only | `true_positive` |
| FP signals only | `false_positive` |
| Both TP and FP | `uncertain` — mixed, needs review |
| Only PUA/Packed signals | `uncertain` — low confidence |
| Nothing conclusive | `uncertain` — insufficient context |

### True-positive signals

- Threat name contains a known malware family keyword: `Trojan`, `Backdoor`, `Ransomware`, `CoinMiner`, `Dropper`, `RemoteAccess`, `Worm`, `Spyware`
- Detection type is Behavioral Engine
- Final verdict is `malware`
- File path is in a user-controlled location: `\Users\`, `\Downloads\`, `\Desktop\`, `\AppData\`, `\Temp\`, `\Roaming\`

### False-positive signals

- File path is in a trusted system location: `\Windows\System32\`, `\Windows\SysWOW64\`, `\Program Files\`, `\Program Files (x86)\`
- Digital signature is valid: line contains `signed = VALID` or vendor is `Microsoft`

### Examples

```
scan 4502 — true_positive
  threat=Trojan:Win32.Emotet, verdict=malware, path=C:\Users\testuser\Downloads\free_antivirus_setup.exe
  reason: "Malicious indicators: strong threat name (Trojan:Win32.Emotet); malware verdict; suspicious file location"

scan 4550 — false_positive
  threat=HackTool:Win32.SecurityTool, path=C:\Program Files\CustomApp\legitimate_tool.exe, signed=VALID
  reason: "Benign indicators: trusted system path; valid digital signature"

scan 4551 — uncertain
  threat=HackTool:Win32.DebugTool, path=C:\Users\testuser\Development\debug_helper.exe, signed=VALID
  reason: "Mixed signals — suspicious: suspicious file location | benign: valid digital signature"
```

---

## Edge Cases Handled

| Scenario | Behaviour |
|----------|-----------|
| `Threat name: NULL` | Rejected by `_is_null_threat()` — Rule 2 does not fire |
| `threat name = 'NULL'` | Same rejection in both regex paths |
| Paths with spaces (`Program Files`) | `Start scanning:` pattern uses greedy `(.+)` to end of line |
| UTF-16 encoded log file | Detected via BOM bytes; opened with `encoding="utf-16"` |
| Same scan ID across multiple files | Lines merged into one bundle; first source file name preserved |
| One scan triggers multiple rules | Priority order selects the detection type; all data collected |
| Lines with no scan ID | Silently skipped — noise lines do not affect results |
| Unreadable / corrupt file | `OSError` caught; warning printed; pipeline continues |
| Empty logs directory | Detected early; warning printed; empty report written |
| Missing field in a scan | Field is `null` in output; scan still evaluated on other rules |
| Mixed TP + FP signals | Classified as `uncertain` with both sides explained in the reason |

---

## Example Output

```json
{
  "summary": {
    "totalLogsProcessed": 3,
    "totalScansAnalyzed": 46,
    "suspiciousIndicatorsFound": 16
  },
  "indicators": [
    {
      "scanId": "4521",
      "detectionType": "Static File Scanner",
      "suspiciousFile": "C:\\Users\\testuser\\Downloads\\cracked_software.exe",
      "threatName": "Trojan:Win32.CrackedApp",
      "mlScore": "0.92",
      "sourceLogFile": "security_scan_002.log",
      "extraDetails": {
        "finalVerdict": "malware",
        "mlProbability": "92%",
        "triggeredRules": [
          "Threat name detected",
          "ML score > 0.75"
        ]
      },
      "classification": "true_positive",
      "classificationReason": "Malicious indicators: strong threat name (Trojan:Win32.CrackedApp); malware verdict; suspicious file location"
    }
  ]
}
```

---

## Regex Patterns Reference

| Field | Pattern | Example match |
|-------|---------|---------------|
| Scan ID (bracket) | `\[scan-id:(\d+)\]` | `[scan-id:4500]` |
| Scan ID (camelCase) | `\bscanId\s*=\s*(\d+)` | `scanId = 4500` |
| Scan ID (words) | `\bscan\s+ID\s+(\d+)` | `Scan ID 4500` |
| ML score | `\bScore:\s*([\d.]+)` | `Score: 0.89` |
| ML probability | `\bprobability\s*=\s*(\d+(?:\.\d+)?)%` | `probability = 92%` |
| Threat name (colon) | `\bThreat name:\s*((?:[^.\n]\|\.(?!\s))+)` | `Threat name: Trojan:Win32.Emotet.` |
| Threat name (quoted) | `\bthreat name\s*=\s*'([^']+)'` | `threat name = 'Trojan:Win32.CrackedApp'` |
| Behavioral threat | `\bthreat\s*=\s*([^,\n]+)` | `threat = Trojan:Win32.Dropper` |
| File path (quoted) | `\bpath\s*=\s*"([^"]+)"` | `path = "C:\...\file.exe"` |
| File path (scanning) | `\bStart scanning:\s*(.+)` | `Start scanning: C:\...\file.exe` |
| Final verdict | `\bfinal verdict:\s*(\w+)` | `final verdict: malware` |
| Signature | `Signature verified:\s*([^,\n]+),\s*signed\s*=\s*(\w+)` | `Signature verified: Vendor, signed = VALID` |

---

## Design Decisions

**Modular pipeline over a monolithic script.**
Each layer (parse / evaluate / classify / report) is isolated in its own module. This makes each step independently testable, replaceable, and readable without understanding the whole system.

**Two-pass approach: collect all lines first, then evaluate.**
Rather than evaluating each line as it is read, the parser first groups all lines per scan ID into a bundle. The evaluator then sees the complete picture for each scan. This is important because a single scan spans many lines — the threat name, ML score, file path, verdict, and signature may all appear on different lines in different orders.

**Rule-based classification over ML or heuristic scoring.**
A rule-based classifier with explicit, named signals produces decisions that are easy to explain and audit. Every classification comes with a `classificationReason` string that describes exactly which signals drove the decision — this is more useful for a reviewer than a confidence score.

**Regex patterns compiled at module load time.**
All patterns are compiled once at the top of `evaluator.py` with descriptive names and inline comments. This avoids recompilation on every line and makes the patterns easy to find, read, and adjust.

**None values excluded from `extraDetails`.**
`extraDetails` only contains fields that were actually found in the logs. Empty objects are cleaner than objects full of `null` values, and make it easier to spot what evidence was available for a given scan.

---

## Potential Improvements

- **Confidence scoring.** Instead of a binary suspicious/clean verdict, compute a weighted confidence score from multiple signals and use it to rank indicators by risk.

- **Unit tests.** Add `pytest` tests for each module with synthetic log lines covering all regex patterns and classification branches. The modular design makes this straightforward.

- **Signature vendor enrichment.** Cross-reference the signing vendor name against a known-good list (Microsoft, Google, Apple, Adobe, etc.) to increase confidence in false-positive classifications.

- **Streaming large logs.** The current implementation loads all matched lines into memory. For very large log files, a streaming approach (processing and discarding lines as they are read) would reduce memory usage.

- **Configurable thresholds.** Expose `ML_SCORE_THRESHOLD` and the trusted-path / threat-keyword lists as CLI arguments or a config file so they can be tuned without editing source code.

- **Duplicate scan deduplication.** If the same scan ID appears in multiple log files with conflicting data, a merge strategy (e.g. prefer the file with more lines, or the higher score) could produce more reliable results.
