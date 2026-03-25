# QA Analyst - Home Assignment
## Suspicious Indicator Extraction from Security Software Logs

---

### Background

As part of our security testing infrastructure, we analyze logs from endpoint security software to detect **suspicious indicators** - signs of potential malware detection that occur during file scanning.

The logs contain scan events with various verdicts and scores. A **suspicious indicator** is identified when:
- A Machine Learning (ML) score exceeds a certain threshold
- A threat is detected (threat name is present)
- A behavioral detection rule is triggered

Your task is to build a standalone Python script that analyzes security logs and extracts potential suspicious indicators.

---

### Task 1: Suspicious Indicator Extractor

#### Requirements

Build a Python script (`indicator_extractor.py`) that:

1. **Reads all log files** from a specified directory (default: `./logs`)
2. **Identifies suspicious scans** based on these rules:
   - Rule 1 (ML Score): Extract scans where `Score:` value is **greater than 0.75**
   - Rule 2 (Threat Detection): Extract scans where `threat name =` or `threatName` contains a value
   - Rule 3 (Behavioral): Extract scans where `threat =` is present in behavioral logs
3. **For each suspicious scan ID found**, collect ALL related log lines containing that scan ID
4. **Output a structured report** (JSON format) containing:
   - `scanId`: The unique scan identifier
   - `detectionType`: "Machine Learning" / "Static File Scanner" / "Behavioral Engine"
   - `suspiciousFile`: Path to the scanned file
   - `threatName`: Name of the threat (if detected)
   - `mlScore`: The ML score (if applicable)
   - `sourceLogFile`: Name of the log file where this was found
   - `extraDetails`: Any additional relevant information

#### Example Output
```json
{
  "suspiciousIndicators": [
    {
      "scanId": "4521",
      "detectionType": "Machine Learning",
      "suspiciousFile": "C:\\Users\\test\\malware.exe",
      "threatName": "Trojan:Win32.Generic",
      "mlScore": "0.89",
      "sourceLogFile": "cps-20260101-120000-123.0.log",
      "extraDetails": {
        "finalVerdict": "malware",
        "mlProbability": "89%"
      }
    }
  ],
  "summary": {
    "totalLogsProcessed": 5,
    "totalScansAnalyzed": 1250,
    "suspiciousIndicatorsFound": 3
  }
}
```

---

### Task 2: False Positive Analysis

Not all detections are real threats. Some are **False Positives** - legitimate files incorrectly flagged as suspicious.

**Your task:**
1. Review the suspicious indicators you found in Task 1
2. Identify which ones are likely **False Positives**
3. Add a classification to each indicator in your report:
   - `"classification": "true_positive"` - Real threat
   - `"classification": "false_positive"` - Legitimate file, incorrect detection
   - `"classification": "uncertain"` - Need more information

**Hints for identifying False Positives:**
- **Digital Signature:** Look for `Signature verified: VENDOR, signed = VALID` in the logs. Files signed by Microsoft, known software vendors, etc. are usually legitimate.
- **File Location:** Files in `C:\Windows\System32\`, `C:\Program Files\` are usually system/installed software.
- **Threat Type:** Some detections like "Packed:*" or "PUA:*" indicate the file is packed or potentially unwanted, but not necessarily malware.
- **Research:** If unsure, search online for the file name + "legitimate" or "malware" to understand what it is.

**Example:** If you see a detection for `C:\Windows\System32\svchost.exe` with `Signature verified: Microsoft`, this is likely a False Positive - svchost.exe is a core Windows service.

---

### Task 3: Documentation

Write a brief technical document (README.md or similar) that includes:

1. **How to run the script** - clear instructions with example commands
2. **Architecture decisions** - explain your design choices
3. **Regex patterns used** - document the patterns you used and why
4. **False Positive logic** - explain how you identify FPs
5. **Classification reasoning** - for each indicator you classified as false_positive or uncertain, briefly explain why (e.g., "known system file", "located in Program Files", "digitally signed")
6. **Edge cases handled** - what scenarios did you consider?
7. **Potential improvements** - what would you add if you had more time?

---

### Log File Structure

The log files in the `./logs` directory follow this general structure:

```
[TIMESTAMP][LEVEL][COMPONENT] Message content with scanId = XXXX and other details
```

#### Key patterns to look for:
- `scan ID XXXX` or `scanId = XXXX` or `[scan-id:XXXX]` - unique identifier for each scan
- `Score: X.XX` - ML confidence score (0.0 to 1.0)
- `probability = XX%` - alternative probability format
- `threat name = 'ThreatName'` or `threatName: 'ThreatName'` - detected threat
- `final verdict: VERDICT` - can be: clean, unknown, malware, pua, adware
- `path = "filepath"` or `scanning: filepath` - the file being scanned
- `threat = THREAT_TYPE` - behavioral detection
- `Signature verified: VENDOR, signed = VALID/INVALID` - digital signature info

#### Log Levels:
- `[T]` - Trace (detailed info)
- `[E]` - Error
- `[W]` - Warning

---

### Provided Files

- `./logs/` - Directory containing sample security software log files
- `./QA_Analyst_Home_Assignment.md` - This document

---

### Submission Guidelines

1. Submit your solution as a ZIP file containing:
   - `indicator_extractor.py` - Your main script
   - `README.md` - Your documentation
   - `report.json` - Sample output from running against provided logs
   - Any additional helper files/modules

2. Ensure your script can be run with:
   ```
   python indicator_extractor.py --logs-dir ./logs --output report.json
   ```

---

### Tips

- Start simple - first make it work, then optimize
- Think about maintainability - your code will be reviewed by others
- You may use external Python libraries. If you do, explain what purpose you used them for
- You are welcome to use AI assistants - we're interested in how you work with them
- When in doubt about a classification, explain your reasoning

---

### Questions?

If you have any questions about the assignment, please don't hesitate to reach out.

Good luck!
