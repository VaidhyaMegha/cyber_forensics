# 📁 Cyber Forensics Toolkit - Folder Structure

## 🗂️ **Directory Organization**

```
cyber_forensics-main/
│
├── 📂 analyzers/              # Analysis modules
│   ├── network_analyzer.py         ✅ Network intelligence
│   ├── security_analyzer.py        ✅ Security checks
│   ├── content_analyzer.py         ✅ Content analysis
│   ├── attribution_analyzer.py     ✅ WHOIS/domain info
│   └── threat_intel.py             ✅ VirusTotal integration
│
├── 📂 detectors/              # Threat detection
│   ├── phishing_detector.py        ✅ Phishing detection
│   ├── malware_detector.py         ✅ Malware detection
│   ├── brand_detector.py           ✅ Brand impersonation
│   └── kit_detector.py             ✅ Phishing kit detection
│
├── 📂 collectors/             # Evidence collection
│   ├── screenshot_collector.py     ✅ Screenshots
│   ├── resource_collector.py       ✅ Resource download
│   ├── dns_collector.py            ✅ DNS records
│   └── cert_collector.py           ✅ SSL certificates
│
├── 📂 reporters/              # Report generation
│   ├── pdf_reporter.py             ✅ PDF reports
│   ├── html_reporter.py            ✅ HTML dashboards
│   ├── json_exporter.py            ✅ JSON export
│   └── ioc_extractor.py            ✅ IOC extraction
│
├── 📂 config/                 # Configuration files
│   ├── api_keys.json               🔑 Your API keys (gitignored)
│   └── api_keys.json.example       📋 Template file
│
├── 📂 tmp/                    # Temporary test results (gitignored)
│   ├── README.md                   📖 Folder documentation
│   ├── virustotal_analysis_*.json  📊 Test results
│   └── batch_analysis_*.json       📊 Batch results
│
├── 📂 reports/                # Generated reports (gitignored)
│   ├── *.pdf                       📄 PDF reports
│   ├── *.html                      🌐 HTML dashboards
│   └── *.json                      📊 JSON exports
│
├── 📂 screenshots/            # Website screenshots (gitignored)
│   └── *.png                       📸 Screenshot files
│
├── 📂 todo/                   # Project management
│   └── gaps.md                     📝 Implementation gaps
│
├── 📄 main_analyzer.py        # Main orchestrator
├── 📄 demo.py                 # Demo script
├── 📄 test_implementation.py  # Module tests
├── 📄 test_virustotal.py      # VirusTotal test
├── 📄 batch_analysis.py       # Batch URL analysis
│
├── 📚 Documentation
│   ├── README.md                   📖 Project overview
│   ├── QUICK_START.md              🚀 Quick start guide
│   ├── IMPLEMENTATION_GUIDE.md     📘 Complete guide
│   ├── IMPLEMENTATION_SUMMARY.md   📊 Technical summary
│   ├── COMPLETION_REPORT.md        ✅ Final report
│   └── FOLDER_STRUCTURE.md         📁 This file
│
├── ⚙️ Configuration
│   ├── .gitignore                  🚫 Git ignore rules
│   ├── requirements.txt            📦 Dependencies
│   └── LICENSE                     ⚖️ License file
│
└── 📝 forensics.log           # Application logs (gitignored)
```

---

## 🚫 **What's Gitignored**

The following files/folders are **NOT tracked** by Git (kept local only):

```
__pycache__/              # Python cache files
tmp/*                     # All test results (except README.md)
*.json                    # All JSON files (except examples)
reports/                  # Generated reports
screenshots/              # Website screenshots
forensics.log             # Application logs
config/api_keys.json      # Your API keys (IMPORTANT!)
```

---

## 📊 **Where Results Are Saved**

### **Test Results** → `tmp/`
- Single URL analysis: `tmp/virustotal_analysis_<url>.json`
- Batch analysis: `tmp/batch_analysis_<timestamp>.json`
- Test outputs: `tmp/forensic_analysis_<timestamp>.json`

### **Reports** → `reports/`
- PDF reports: `reports/forensic_report.pdf`
- HTML dashboards: `reports/forensic_report.html`
- JSON exports: `reports/forensic_analysis_<timestamp>.json`

### **Screenshots** → `screenshots/`
- Website screenshots: `screenshots/screenshot_<hash>_<timestamp>.png`

### **Logs** → Root directory
- Application logs: `forensics.log`

---

## 🔑 **Important Files**

### **Configuration**
- `config/api_keys.json` - **Your API keys** (keep this secure!)
- `config/api_keys.json.example` - Template for API keys

### **Main Scripts**
- `main_analyzer.py` - Full forensic analysis
- `demo.py` - Demo with test URLs
- `test_virustotal.py` - Single URL VirusTotal test
- `batch_analysis.py` - Multiple URL analysis

### **Testing**
- `test_implementation.py` - Verify all modules work

---

## 🧹 **Cleanup Commands**

### **Clean test results:**
```bash
# Windows PowerShell
Remove-Item tmp\*.json

# Linux/Mac
rm tmp/*.json
```

### **Clean all generated files:**
```bash
# Windows PowerShell
Remove-Item tmp\*.json, reports\*, screenshots\*, forensics.log

# Linux/Mac
rm tmp/*.json reports/* screenshots/* forensics.log
```

### **Clean Python cache:**
```bash
# Windows PowerShell
Remove-Item -Recurse -Force __pycache__

# Linux/Mac
find . -type d -name __pycache__ -exec rm -r {} +
```

---

## 📝 **File Naming Conventions**

### **Analysis Results**
- Pattern: `<type>_analysis_<identifier>_<timestamp>.json`
- Examples:
  - `virustotal_analysis_https_www.google.com.json`
  - `batch_analysis_20251004_213545.json`
  - `forensic_analysis_20251004_214530.json`

### **Reports**
- Pattern: `forensic_report[_<name>].<format>`
- Examples:
  - `forensic_report.pdf`
  - `forensic_report_google.html`
  - `forensic_analysis_20251004_214530.json`

### **Screenshots**
- Pattern: `screenshot_<hash>_<timestamp>.png`
- Example: `screenshot_a3f2b1c8_20251004_214530.png`

---

## 🔒 **Security Notes**

### **Files to NEVER commit to Git:**
- ✅ `config/api_keys.json` - Contains your API keys
- ✅ `tmp/*.json` - May contain sensitive URLs
- ✅ `reports/*` - May contain investigation data
- ✅ `screenshots/*` - May contain sensitive content
- ✅ `forensics.log` - Contains analysis logs

### **Safe to commit:**
- ✅ All Python source files (`*.py`)
- ✅ Documentation files (`*.md`)
- ✅ Configuration templates (`*.example`)
- ✅ `tmp/README.md` (folder documentation)

---

## 💡 **Usage Tips**

1. **Keep tmp/ clean** - Delete old test results regularly
2. **Backup reports/** - Save important reports elsewhere
3. **Monitor forensics.log** - Check for errors and warnings
4. **Secure api_keys.json** - Never share or commit this file
5. **Use batch_analysis.py** - For analyzing multiple URLs efficiently

---

## 📞 **Need Help?**

- **Quick Start:** See `QUICK_START.md`
- **Full Guide:** See `IMPLEMENTATION_GUIDE.md`
- **Contact:** madhulatha@samyama.ai

---

**Last Updated:** October 4, 2025  
**Version:** 1.0.0
