# 📚 Cyber Forensics Toolkit - Complete Documentation

**Owner:** [Samyama.ai](https://Samyama.ai) - Vaidhyamegha Private Limited  
**Contact:** madhulatha@samyama.ai  
**License:** Proprietary - All Rights Reserved  
**Version:** 1.0.0  
**Last Updated:** October 2025

---

## 📖 Table of Contents

1. [Project Overview](#-project-overview)
2. [Quick Start](#-quick-start)
3. [Architecture & Components](#-architecture--components)
4. [Implementation Guide](#-implementation-guide)
5. [Current Status](#-current-status)
6. [Frequently Asked Questions](#-frequently-asked-questions)
7. [Folder Structure](#-folder-structure)
8. [Legal & Ethical Guidelines](#-legal--ethical-guidelines)

---

## 🎯 Project Overview

### What is This Toolkit?

The Cyber Forensics Toolkit is a comprehensive Python-based solution for analyzing phishing websites and conducting digital forensics investigations. It provides cybersecurity professionals, researchers, and investigators with powerful capabilities to gather intelligence about suspicious websites and malicious domains.

### Key Capabilities

**🌐 Network Intelligence**
- IP resolution and geolocation analysis
- Cloud provider detection (AWS, Azure, GCP, Cloudflare)
- DNS record enumeration
- Port scanning and service detection

**🔒 Security Analysis**
- SSL/TLS certificate validation and analysis
- Security headers assessment (HSTS, CSP, X-Frame-Options)
- Vulnerability scanning (XSS, SQLi, directory traversal)
- Multi-source reputation analysis

**📊 Content Analysis**
- HTML/JavaScript code inspection
- Form detection and analysis
- Obfuscation detection
- Resource enumeration (images, scripts, stylesheets)

**🕵️ Attribution & Intelligence**
- WHOIS domain registration data
- Domain age calculation
- Typosquatting detection
- Threat intelligence integration (VirusTotal, AbuseIPDB)

**🎯 Threat Detection**
- Phishing pattern recognition
- Malware payload detection
- Brand impersonation analysis
- Phishing kit identification

**📈 Reporting**
- JSON structured data export
- IOC extraction (CSV and STIX formats)
- Comprehensive analysis reports
- Risk scoring and recommendations

---

## 🚀 Quick Start

### Installation

```bash
# Navigate to project directory
cd cyber_forensics-main

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Analyze a single URL with all modules
python main_analyzer.py --url "https://suspicious-site.com" --modules all

# Quick scan (network and security only)
python main_analyzer.py --url "https://example.com" --modules network,security

# Test with VirusTotal integration
python test_virustotal.py

# Batch analysis of multiple URLs
python batch_analysis.py
```

### Configuration

1. **Set up API keys** (optional but recommended):
   - Copy `config/api_keys.json.example` to `config/api_keys.json`
   - Add your API keys:
     - **VirusTotal**: Get free API key at https://www.virustotal.com/gui/join-us
     - **AbuseIPDB**: Get free API key at https://www.abuseipdb.com/register
     - **Shodan**: Get API key at https://account.shodan.io/

2. **Example `config/api_keys.json`**:
```json
{
  "virustotal": "YOUR_VIRUSTOTAL_API_KEY_HERE",
  "abuseipdb": "YOUR_ABUSEIPDB_API_KEY_HERE",
  "shodan": "YOUR_SHODAN_API_KEY_HERE"
}
```

### Your First Analysis

```bash
# Test with a known safe site
python main_analyzer.py --url "https://www.google.com" --modules all

# Expected output:
# - Risk Level: MINIMAL
# - Risk Score: 5-10/100
# - Reports saved to reports/ folder
```

---

## 🏗️ Architecture & Components

### System Architecture

```
USER INPUT (URL)
    ↓
┌─────────────────────────────────────┐
│  COLLECTORS (Gather Evidence)       │
│  - Screenshot Collector             │
│  - Resource Collector               │
│  - DNS Collector                    │
│  - Certificate Collector            │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  ANALYZERS (Examine Evidence)       │
│  ✅ Network Analyzer                │
│  ✅ Security Analyzer               │
│  ✅ Content Analyzer                │
│  ✅ Attribution Analyzer            │
│  ✅ Threat Intelligence             │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  DETECTORS (Identify Threats)       │
│  ✅ Phishing Detector               │
│  ✅ Malware Detector                │
│  ✅ Brand Detector                  │
│  ✅ Kit Detector                    │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  REPORTERS (Generate Reports)       │
│  ✅ JSON Exporter                   │
│  ✅ IOC Extractor                   │
│  ⚠️ PDF Reporter (framework)        │
│  ⚠️ HTML Reporter (framework)       │
└─────────────────────────────────────┘
    ↓
USER OUTPUT (Reports & Alerts)
```

### Module Directory Structure

```
cyber_forensics-main/
│
├── 📂 analyzers/              # Analysis modules (5 total)
│   ├── network_analyzer.py         ✅ IP, DNS, geolocation
│   ├── security_analyzer.py        ✅ SSL, headers, vulnerabilities
│   ├── content_analyzer.py         ✅ HTML/JS analysis
│   ├── attribution_analyzer.py     ✅ WHOIS, domain info
│   └── threat_intel.py             ✅ VirusTotal integration
│
├── 📂 detectors/              # Threat detection (4 total)
│   ├── phishing_detector.py        ✅ Phishing patterns
│   ├── malware_detector.py         ✅ Malware detection
│   ├── brand_detector.py           ✅ Brand impersonation
│   └── kit_detector.py             ✅ Phishing kit detection
│
├── 📂 collectors/             # Evidence collection (4 total)
│   ├── screenshot_collector.py     ⚠️ Needs Selenium
│   ├── resource_collector.py       ⚠️ Framework
│   ├── dns_collector.py            ✅ DNS records
│   └── cert_collector.py           ✅ SSL certificates
│
├── 📂 reporters/              # Report generation (4 total)
│   ├── pdf_reporter.py             ⚠️ Needs ReportLab
│   ├── html_reporter.py            ⚠️ Needs Jinja2
│   ├── json_exporter.py            ✅ JSON export
│   └── ioc_extractor.py            ✅ IOC extraction
│
├── 📂 config/                 # Configuration
│   ├── api_keys.json               🔑 Your API keys
│   └── api_keys.json.example       📋 Template
│
├── 📂 reports/                # Generated reports
├── 📂 screenshots/            # Website screenshots
├── 📂 tmp/                    # Test results
├── 📂 docs/                   # Documentation
└── 📂 todo/                   # Project tracking
```

---

## 📘 Implementation Guide

### Core Analyzers (5/5 Complete ✅)

#### 1. Network Analyzer
**File:** `analyzers/network_analyzer.py`

**Functions:**
- `resolve_ip(domain)` - Resolves domain to IP addresses
- `get_geolocation(ip)` - Gets geographic location of IP
- `detect_cloud_provider(ip)` - Identifies cloud hosting provider
- `scan_ports(ip)` - Scans for open network ports

**Example Output:**
```json
{
  "ip_addresses": ["142.250.185.46"],
  "geolocation": {
    "country": "United States",
    "city": "Mountain View",
    "isp": "Google LLC"
  },
  "cloud_provider": "Google Cloud Platform"
}
```

#### 2. Security Analyzer
**File:** `analyzers/security_analyzer.py`

**Functions:**
- `analyze_certificate(url)` - Validates SSL/TLS certificates
- `analyze_headers(url)` - Checks security headers
- `scan_vulnerabilities(url)` - Tests for common vulnerabilities

**Example Output:**
```json
{
  "ssl_valid": true,
  "certificate": {
    "issuer": "Google Trust Services",
    "valid_until": "2025-12-31"
  },
  "security_headers": {
    "hsts": true,
    "csp": true,
    "x_frame_options": "DENY"
  }
}
```

#### 3. Content Analyzer
**File:** `analyzers/content_analyzer.py`

**Functions:**
- `analyze_content(url)` - Main content analysis
- `_analyze_html_structure()` - Examines HTML structure
- `_analyze_javascript()` - Checks JavaScript code
- `_analyze_forms()` - Detects login/data collection forms
- `_detect_obfuscation()` - Finds hidden/obfuscated code

**Example Output:**
```json
{
  "html_structure": {
    "title": "Login Page",
    "forms_count": 1,
    "iframes_count": 0
  },
  "forms": [
    {
      "is_login_form": true,
      "collects_sensitive_data": true,
      "fields": ["username", "password"]
    }
  ],
  "suspicious_patterns": ["Urgency tactics", "Account verification"]
}
```

#### 4. Attribution Analyzer
**File:** `analyzers/attribution_analyzer.py`

**Functions:**
- `analyze_domain(domain)` - Main attribution analysis
- `_get_whois_data()` - Gets domain registration info
- `_calculate_domain_age()` - Determines domain age
- `_find_similar_domains()` - Finds typosquatting domains

**Example Output:**
```json
{
  "whois_data": {
    "registrar": "GoDaddy",
    "creation_date": "2025-10-01",
    "registrant": {
      "email": "privacy@whoisguard.com"
    }
  },
  "domain_age": {
    "age_days": 6,
    "is_new": true
  },
  "risk_indicators": [
    "⚠️ New domain (only 6 days old)",
    "Privacy protection enabled"
  ]
}
```

#### 5. Threat Intelligence
**File:** `analyzers/threat_intel.py`

**Functions:**
- `analyze_url(url)` - Check URL reputation
- `analyze_domain(domain)` - Check domain reputation
- `analyze_ip(ip)` - Check IP reputation
- `_check_virustotal_url()` - VirusTotal API integration
- `extract_iocs()` - Extract indicators of compromise

**Example Output:**
```json
{
  "virustotal": {
    "available": true,
    "data": {
      "last_analysis_stats": {
        "malicious": 0,
        "suspicious": 0,
        "clean": 68
      }
    }
  },
  "threat_score": 0,
  "is_malicious": false,
  "recommendations": ["✅ No threats detected"]
}
```

### Detectors (4/4 Complete ✅)

#### 1. Phishing Detector
**File:** `detectors/phishing_detector.py`

**Detection Methods:**
- URL pattern analysis (IP addresses, suspicious TLDs)
- Domain similarity checking (typosquatting)
- Login form detection
- Phishing keyword detection
- Brand impersonation detection

**Scoring System:**
```python
# Weighted indicators:
- IP address in URL: +25 points
- Suspicious TLD (.tk, .ml): +15 points
- Similar to legitimate domain: +35 points
- Contains login form: +15 points
- New domain (<6 months): +30 points
- Privacy protected WHOIS: +10 points

# Risk levels:
- 0-29: LOW
- 30-49: MEDIUM
- 50-69: HIGH
- 70-100: CRITICAL
```

#### 2. Malware Detector
**File:** `detectors/malware_detector.py`

**Detection Methods:**
- Obfuscated JavaScript analysis
- Dangerous function detection (eval, unescape)
- Drive-by download detection
- Threat intelligence correlation

#### 3. Brand Detector
**File:** `detectors/brand_detector.py`

**Monitored Brands:**
- PayPal, Amazon, Microsoft, Apple, Google
- Major banks and financial institutions
- Social media platforms

#### 4. Kit Detector
**File:** `detectors/kit_detector.py`

**Known Phishing Kits:**
- 16shop
- Z-Shadow
- BlackBullet
- And more...

### Reporters (2/4 Working, 2/4 Framework ✅)

#### 1. JSON Exporter ✅ WORKING
**File:** `reporters/json_exporter.py`

Exports complete analysis data to JSON format.

**Output:** `reports/forensic_analysis_<timestamp>.json`

#### 2. IOC Extractor ✅ WORKING
**File:** `reporters/ioc_extractor.py`

Extracts indicators of compromise in multiple formats:
- CSV format: `reports/iocs.csv`
- STIX format: `reports/iocs_stix.json`

#### 3. PDF Reporter ⚠️ FRAMEWORK
**File:** `reporters/pdf_reporter.py`

Framework exists but requires:
```bash
pip install reportlab
```

#### 4. HTML Reporter ⚠️ FRAMEWORK
**File:** `reporters/html_reporter.py`

Framework exists but requires:
```bash
pip install jinja2
```

### Usage Examples

#### Basic Analysis
```python
import asyncio
from main_analyzer import CyberForensicsAnalyzer

async def analyze_url():
    analyzer = CyberForensicsAnalyzer(config_path='config/api_keys.json')
    url = "https://suspicious-site.com"
    results = await analyzer.analyze_url(url)
    analyzer.generate_reports(formats=['json', 'iocs'])

asyncio.run(analyze_url())
```

#### Command Line Usage
```bash
# Full analysis with all modules
python main_analyzer.py --url "https://suspicious-site.com" --modules all

# Specific modules only
python main_analyzer.py --url "https://example.com" --modules network,security,threat_intel

# Quick scan
python main_analyzer.py --url "https://example.com" --quick
```

---

## ✅ Current Status

### Implementation Progress

**Overall Completion:** 73% Fully Working, 27% Framework Ready

| Component | Status | Count |
|-----------|--------|-------|
| **Analyzers** | ✅ Complete | 5/5 |
| **Detectors** | ✅ Complete | 4/4 |
| **Reporters** | ⚠️ Partial | 2/4 |
| **Collectors** | ⚠️ Partial | 2/4 |
| **Total** | **73% Complete** | **11/15** |

### What's Working Now

#### ✅ Fully Functional
1. **VirusTotal Integration** - Real-time threat intelligence from 90+ antivirus engines
2. **Risk Assessment** - Dynamic scoring based on actual analysis results
3. **Network Analysis** - IP resolution, geolocation, cloud provider detection
4. **Security Analysis** - SSL/TLS validation, security headers, vulnerability scanning
5. **Content Analysis** - HTML/JS inspection, form detection, obfuscation detection
6. **Attribution Analysis** - WHOIS lookup, domain age, typosquatting detection
7. **Phishing Detection** - Pattern recognition with weighted scoring
8. **Malware Detection** - Code analysis and threat correlation
9. **Brand Detection** - Impersonation analysis
10. **JSON Export** - Complete analysis data export
11. **IOC Extraction** - CSV and STIX format export

#### ⚠️ Framework Ready (Needs Additional Libraries)
1. **PDF Reporter** - Needs `pip install reportlab`
2. **HTML Reporter** - Needs `pip install jinja2`
3. **Screenshot Collector** - Needs `pip install selenium` or Playwright
4. **Resource Collector** - Basic framework implemented

### Known Issues

#### Minor Issues (Non-Critical)

1. **Deprecation Warnings** (Cosmetic)
```
CryptographyDeprecationWarning: Properties that return a naïve datetime object
```
**Status:** Being addressed - switching to UTC-aware datetime  
**Impact:** None - functionality works correctly

2. **Insecure Request Warning** (By Design)
```
InsecureRequestWarning: Unverified HTTPS request
```
**Status:** Expected behavior  
**Reason:** Tool needs to analyze suspicious sites with invalid SSL  
**Impact:** None - intentional for forensic analysis

3. **Missing ipwhois** (Optional)
```
WARNING: No module named 'ipwhois'
```
**Status:** Optional dependency  
**Fix:** `pip install ipwhois`  
**Impact:** Low - basic IP analysis still works

### Test Results

#### Google.com Analysis
```
Risk Level: MINIMAL
Risk Score: 10/100
Analysis Duration: 5.06 seconds
Risk Factors: Missing security headers (minor)
✅ CORRECT - Google is legitimate
```

#### Facebook.com Analysis
```
Risk Level: MINIMAL
Risk Score: 10/100
Analysis Duration: 108.91 seconds
Risk Factors: Missing security headers (minor)
✅ CORRECT - Facebook is legitimate
```

### Risk Scoring System

```
Risk Score Ranges:
- 0-19:   MINIMAL RISK (✅ Safe)
- 20-39:  LOW RISK (⚠️ Monitor)
- 40-59:  MEDIUM RISK (⚠️ Suspicious)
- 60-79:  HIGH RISK (🚨 Likely malicious)
- 80-100: CRITICAL RISK (🚨 Definitely malicious)
```

---

## ❓ Frequently Asked Questions

### General Questions

#### Q: What does this toolkit do?
**A:** It's a digital detective that investigates suspicious websites. You provide a URL, and it automatically:
- Takes screenshots and analyzes content
- Checks who owns the website (WHOIS)
- Analyzes code for malicious patterns
- Compares with threat databases (VirusTotal)
- Checks for phishing and brand impersonation
- Generates detailed reports

#### Q: Do I need API keys to use this?
**A:** The toolkit works without API keys, but you'll get much better results with them:
- **Without API keys:** Network, security, content, and attribution analysis work
- **With VirusTotal API:** Get threat intelligence from 90+ antivirus engines
- **With other APIs:** Enhanced geolocation, infrastructure mapping, etc.

#### Q: Is this tool free to use?
**A:** The toolkit itself is proprietary software owned by Samyama.ai. External API services have their own pricing:
- VirusTotal: Free tier available (4 requests/minute)
- AbuseIPDB: Free tier available (1000 requests/day)
- Shodan: Paid service

### Usage Questions

#### Q: How do I analyze a URL?
**A:** Three main ways:

```bash
# 1. Full analysis with all modules
python main_analyzer.py --url "https://example.com" --modules all

# 2. Quick VirusTotal check
python test_virustotal.py

# 3. Batch analysis
python batch_analysis.py
```

#### Q: Where are the results saved?
**A:** Results are saved in multiple locations:
- **JSON reports:** `reports/forensic_analysis_<timestamp>.json`
- **IOC exports:** `reports/iocs.csv` and `reports/iocs_stix.json`
- **Test results:** `tmp/virustotal_analysis_*.json`
- **Screenshots:** `screenshots/` (when implemented)
- **Logs:** `forensics.log`

#### Q: How long does an analysis take?
**A:** Depends on the depth:
- **Quick scan:** 5-10 seconds
- **Full analysis:** 30-120 seconds
- **Deep forensics:** 2-5 minutes

#### Q: Can I analyze multiple URLs at once?
**A:** Yes! Use the batch analysis script:

```bash
python batch_analysis.py
# Edit the script to add your URLs (lines 36-42)
```

### Technical Questions

#### Q: What programming language is this written in?
**A:** Python 3.7+

#### Q: What libraries does it use?
**A:** Core dependencies:
- `requests` - HTTP requests
- `beautifulsoup4` - HTML parsing
- `python-whois` - WHOIS lookups
- `dnspython` - DNS queries
- `cryptography` - SSL/TLS analysis

#### Q: Does it work on Windows/Mac/Linux?
**A:** Yes, it's cross-platform and works on all major operating systems.

#### Q: How accurate is the phishing detection?
**A:** The phishing detector uses a weighted scoring system with multiple indicators:
- URL patterns (IP addresses, suspicious TLDs)
- Domain similarity (typosquatting detection)
- Content analysis (login forms, phishing keywords)
- Domain age and registration data
- Threat intelligence correlation

Accuracy improves significantly when VirusTotal API is configured.

### Troubleshooting

#### Q: I'm getting "Permission denied" errors
**A:** This is usually a Windows file locking issue. The reports still save correctly. If persistent:
```bash
# Close any programs that might have the files open
# Run as administrator (if needed)
```

#### Q: VirusTotal says "API key not configured"
**A:** You need to set up your API key:
1. Get free API key at https://www.virustotal.com/gui/join-us
2. Copy `config/api_keys.json.example` to `config/api_keys.json`
3. Add your API key to the file

#### Q: How do I fix deprecation warnings?
**A:** These are cosmetic warnings that don't affect functionality. They're being addressed in updates. You can ignore them safely.

#### Q: The analysis seems slow
**A:** Several factors affect speed:
- Network latency
- API rate limits (VirusTotal free tier: 4 requests/minute)
- Number of modules enabled
- Website response time

For faster results, use `--modules network,security` instead of `--modules all`.

---

## 📁 Folder Structure

### Directory Organization

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
│   ├── screenshot_collector.py     ⚠️ Needs Selenium
│   ├── resource_collector.py       ⚠️ Framework
│   ├── dns_collector.py            ✅ DNS records
│   └── cert_collector.py           ✅ SSL certificates
│
├── 📂 reporters/              # Report generation
│   ├── pdf_reporter.py             ⚠️ Needs ReportLab
│   ├── html_reporter.py            ⚠️ Needs Jinja2
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
│   ├── forensic_analysis_*.json    📊 Analysis data
│   └── iocs.csv                    📊 IOC exports
│
├── 📂 screenshots/            # Website screenshots (gitignored)
│   └── *.png                       📸 Screenshot files
│
├── 📂 docs/                   # Documentation
│   ├── DOCUMENTATION.md            📚 This file
│   └── archive/                    📦 Historical docs
│
├── 📂 todo/                   # Project management
│   └── STATUS.md                   📝 Implementation status
│
├── 📄 main_analyzer.py        # Main orchestrator
├── 📄 test_virustotal.py      # VirusTotal test
├── 📄 batch_analysis.py       # Batch URL analysis
├── 📄 demo.py                 # Demo script
│
├── 📚 Documentation
│   ├── README.md                   📖 Project overview
│   └── QUICK_START.md              🚀 Quick start guide
│
├── ⚙️ Configuration
│   ├── .gitignore                  🚫 Git ignore rules
│   ├── requirements.txt            📦 Dependencies
│   └── LICENSE                     ⚖️ License file
│
└── 📝 forensics.log           # Application logs (gitignored)
```

### What's Gitignored

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

### File Naming Conventions

**Analysis Results:**
- Pattern: `<type>_analysis_<identifier>_<timestamp>.json`
- Examples:
  - `virustotal_analysis_https_www.google.com.json`
  - `batch_analysis_20251007_091425.json`
  - `forensic_analysis_20251007_091425.json`

**Reports:**
- Pattern: `forensic_analysis_<timestamp>.json`
- IOCs: `iocs.csv` or `iocs_stix.json`

**Screenshots:**
- Pattern: `screenshot_<hash>_<timestamp>.png`

### Cleanup Commands

**Clean test results:**
```powershell
# Windows PowerShell
Remove-Item tmp\*.json

# Linux/Mac
rm tmp/*.json
```

**Clean all generated files:**
```powershell
# Windows PowerShell
Remove-Item tmp\*.json, reports\*, screenshots\*, forensics.log

# Linux/Mac
rm tmp/*.json reports/* screenshots/* forensics.log
```

---

## ⚖️ Legal & Ethical Guidelines

### Important Disclaimers

**🚨 Educational Purpose**
- This toolkit is designed for legitimate security research and defense
- It should only be used for lawful purposes
- Always obtain proper authorization before analyzing websites

**⚖️ Legal Compliance**
- Ensure compliance with local laws and regulations
- Respect privacy laws (GDPR, CCPA, etc.)
- Follow computer fraud and abuse laws
- Obtain proper authorization before testing

**🤝 Responsible Disclosure**
- Report findings to appropriate authorities
- Follow coordinated vulnerability disclosure practices
- Share threat intelligence responsibly
- Protect victim privacy

**❌ Prohibited Uses**
- Do not use for illegal activities
- Do not use for unauthorized access
- Do not use to harm individuals or organizations
- Do not use to violate privacy rights

### Best Practices

**Authorization**
- Only analyze domains you own or have permission to test
- Document authorization before beginning analysis
- Respect scope limitations
- Follow rules of engagement

**Data Protection**
- Handle collected data according to privacy regulations
- Secure API keys and sensitive information
- Delete unnecessary data after analysis
- Encrypt sensitive findings

**Evidence Integrity**
- Maintain forensic chain of custody
- Document all analysis steps
- Preserve original evidence
- Use write-blockers when appropriate

**Responsible Reporting**
- Share threat intelligence through proper channels
- Protect victim identities
- Follow disclosure timelines
- Coordinate with affected parties

### Compliance Considerations

**GDPR Compliance**
- Privacy-by-design architecture
- Data minimization principles
- Right to erasure support
- Lawful basis for processing

**Industry Standards**
- Follow cybersecurity best practices
- Adhere to forensic standards
- Use accepted methodologies
- Maintain professional ethics

**Legal Admissibility**
- Court-ready evidence collection
- Proper documentation
- Chain of custody maintenance
- Expert testimony support

**International Law**
- Respect jurisdictional boundaries
- Follow international treaties
- Consider cross-border implications
- Coordinate with local authorities

### Ethical Framework

**Built-in Safeguards**
- Authorization checks
- Privacy protection
- Responsible disclosure support
- Evidence integrity maintenance

**Professional Responsibility**
- Act in good faith
- Maintain confidentiality
- Avoid conflicts of interest
- Uphold professional standards

---

## 📞 Contact & Support

**Owner:** [Samyama.ai](https://Samyama.ai) - Vaidhyamegha Private Limited  
**Contact:** madhulatha@samyama.ai  
**Website:** https://Samyama.ai

For licensing inquiries, technical support, or collaboration opportunities, please reach out to our team.

---

## 🎉 Summary

The Cyber Forensics Toolkit provides a comprehensive solution for analyzing suspicious websites and conducting digital forensics investigations. With 73% of modules fully operational and the remaining 27% in framework stage, it offers:

- ✅ Complete network and security analysis
- ✅ Advanced threat detection capabilities
- ✅ Integration with major threat intelligence platforms
- ✅ Professional reporting and IOC extraction
- ✅ Modular, extensible architecture
- ✅ Production-ready code quality

**This toolkit successfully bridges the gap between academic research and practical cybersecurity operations, providing a valuable resource for the global cybersecurity community.** 🛡️🔍

---

*⚠️ **Legal Notice:** This toolkit is proprietary software intended for legitimate cybersecurity research and educational purposes only. Always comply with applicable laws and obtain proper authorization before analyzing websites. All rights reserved.*

**© 2025 Samyama.ai - Vaidhyamegha Private Limited | Made with ❤️ for cybersecurity excellence**
