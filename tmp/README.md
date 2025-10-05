# tmp/ - Temporary Test Results

This folder contains temporary analysis results and test outputs.

## What's Stored Here

- **VirusTotal analysis results** (`virustotal_analysis_*.json`)
- **Batch analysis results** (`batch_analysis_*.json`)
- **Test outputs** from various forensic analysis scripts

## Purpose

This folder keeps all test results organized and separate from the main codebase. All files in this folder (except this README) are ignored by Git.

## Cleanup

You can safely delete all JSON files in this folder at any time:

```bash
# Windows PowerShell
Remove-Item tmp\*.json

# Linux/Mac
rm tmp/*.json
```

## File Naming Convention

- `virustotal_analysis_<url>.json` - Single URL analysis results
- `batch_analysis_<timestamp>.json` - Batch analysis results
- `forensic_analysis_<timestamp>.json` - Full forensic analysis results

---

**Note:** This folder is automatically created by the analysis scripts. All contents (except this README) are gitignored.
