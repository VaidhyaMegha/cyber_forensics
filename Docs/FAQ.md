# ❓ Frequently Asked Questions (FAQ)

## **1. What details do collectors want? URL or user input?**

### **Answer: Collectors take data FROM the URL automatically - NO user input needed!**

**All collectors work automatically:**

```python
# You only provide the URL
url = "https://www.google.com"

# Everything else is automatic!
screenshot = await screenshot_collector.capture_screenshot(url)
# → Automatically opens the URL and takes screenshot

dns_records = await dns_collector.collect_dns_records("google.com")
# → Automatically queries DNS servers

certificate = await cert_collector.collect_certificate("google.com")
# → Automatically downloads SSL certificate
```

**What collectors do:**
- **Screenshot Collector** → Opens URL in browser, takes screenshot
- **Resource Collector** → Downloads images, scripts, CSS from the URL
- **DNS Collector** → Performs DNS queries for the domain
- **Certificate Collector** → Downloads SSL certificate from the server

**NO manual input required!** Just provide the URL and everything is automated.

---

## **2. Do reporters save data to files?**

### **Answer: YES! All reporters save data to files.**

**Files Created:**

```
reports/
├── forensic_analysis_20251005_003623.json  ✅ WORKING
│   → Complete analysis data in JSON format
│
├── iocs_20251005_003623.csv                ✅ WORKING
│   → Indicators of Compromise in CSV format
│
├── iocs_stix_20251005_003623.json          ✅ WORKING
│   → IOCs in STIX format (threat intelligence standard)
│
├── forensic_report.pdf                     ⚠️ Framework only
│   → Needs: pip install reportlab
│
└── forensic_report.html                    ⚠️ Framework only
    → Needs: pip install jinja2
```

**How to access saved data:**

```bash
# View JSON report
cat reports/forensic_analysis_20251005_003623.json

# View IOCs
cat reports/iocs_20251005_003623.csv

# Open in Excel/Notepad
start reports/iocs_20251005_003623.csv
```

**What's saved:**
- ✅ **All analysis results** (network, security, content, attribution, threat intel)
- ✅ **Detection results** (phishing score, malware detection, brand impersonation)
- ✅ **Risk assessment** (risk score, risk level, recommendations)
- ✅ **IOCs** (URLs, domains, IPs, hashes extracted from analysis)

---

## **3. Does code only do threat intelligence? What about other analyzers?**

### **Answer: NO! It does MUCH more than just threat intelligence.**

**All 5 Analyzers Work:**

```python
# 1. Network Analyzer ✅
- Resolves IP addresses
- Gets geolocation (country, city, ISP)
- Detects cloud provider (AWS, Azure, GCP, Cloudflare)
- Scans ports
- Detects CDN

# 2. Security Analyzer ✅
- Validates SSL/TLS certificates
- Checks security headers (HSTS, CSP, X-Frame-Options)
- Scans for vulnerabilities (XSS, SQLi)

# 3. Content Analyzer ✅
- Parses HTML structure
- Analyzes JavaScript code
- Detects login forms
- Finds obfuscated code
- Identifies suspicious patterns

# 4. Attribution Analyzer ✅
- Performs WHOIS lookup
- Calculates domain age
- Generates typosquatting variations
- Checks registrant info

# 5. Threat Intelligence ✅
- Queries VirusTotal API (90+ antivirus engines)
- Checks AbuseIPDB
- Calculates threat score
- Provides recommendations
```

**How to use specific analyzers:**

```bash
# Only threat intelligence
python main_analyzer.py --url "https://example.com" --modules threat_intel

# Network + Security only
python main_analyzer.py --url "https://example.com" --modules network,security

# Content + Attribution only
python main_analyzer.py --url "https://example.com" --modules content,attribution

# ALL analyzers
python main_analyzer.py --url "https://example.com" --modules all
```

---

## **4. What tools are used and how do detectors work?**

### **Tools & Libraries Used:**

```python
# HTTP & Web
import requests              # Make HTTP requests
from bs4 import BeautifulSoup  # Parse HTML

# Network
import socket               # Network operations
import ssl                  # SSL/TLS operations
import dns.resolver         # DNS queries

# Data Processing
import json                 # JSON handling
import asyncio              # Async operations
import whois                # WHOIS lookups

# VirusTotal API
requests.post("https://www.virustotal.com/api/v3/urls")
requests.get("https://www.virustotal.com/api/v3/urls/{id}")
```

### **How Detectors Work:**

#### **Phishing Detector - Weighted Scoring System:**

```python
def detect_phishing(url, content, attribution):
    score = 0
    
    # URL Pattern Checks
    if "192.168.1.1" in url:           # IP address
        score += 25
    
    if url.endswith(".tk") or url.endswith(".ml"):  # Suspicious TLD
        score += 15
    
    if url.count(".") > 3:             # Too many subdomains
        score += 10
    
    # Domain Similarity (Typosquatting)
    if similar("paypa1.com", "paypal.com") > 0.85:
        score += 35  # Very similar = typosquatting!
    
    # Content Checks
    if has_login_form(content):
        score += 15
    
    if has_password_field(content):
        score += 20
    
    if "verify your account" in content:
        score += 20  # Phishing keyword
    
    # Attribution Checks
    if domain_age < 180:               # Less than 6 months
        score += 30
    
    if privacy_protected:
        score += 10
    
    # Calculate Risk Level
    if score >= 70:
        return "CRITICAL - Definitely phishing"
    elif score >= 50:
        return "HIGH - Likely phishing"
    elif score >= 30:
        return "MEDIUM - Suspicious"
    else:
        return "LOW - Probably safe"
```

#### **Malware Detector:**

```python
def detect_malware(content, threat_intel):
    score = 0
    
    # Check for obfuscated JavaScript
    if "eval(unescape(" in javascript:
        score += 25
    
    # Check for dangerous functions
    if "document.write(unescape(" in javascript:
        score += 20
    
    # Check VirusTotal results
    if threat_intel['is_malicious']:
        score += 50
    
    return score
```

#### **Brand Detector:**

```python
def detect_brand(url, content):
    # Check if page mentions a brand
    if "PayPal" in page_title:
        # But domain is NOT paypal.com
        if "paypal.com" not in domain:
            return "⚠️ Brand impersonation detected!"
```

---

## **5. Does main_analyzer store data or just show it?**

### **Answer: BOTH! It shows AND stores data.**

**What Happens:**

```
1. Analysis runs
   → Collects data from all modules
   
2. Display to screen (real-time)
   → Shows progress: "🔍 Analyzing..."
   → Shows results: "Risk Score: 85/100"
   
3. Save to files (automatic)
   → reports/forensic_analysis_*.json
   → reports/iocs_*.csv
   
4. Return file paths
   → "Reports saved to: reports/..."
```

**Example Output:**

```bash
$ python main_analyzer.py --url "https://example.com" --modules all

🔍 Starting forensic analysis...
📡 Network Analysis... ✅
🔒 Security Analysis... ✅
📄 Content Analysis... ✅
🔍 Attribution Analysis... ✅
🛡️ Threat Intelligence... ✅
🎯 Detection Analysis... ✅

🎯 ANALYSIS SUMMARY
====================
Risk Level: HIGH
Risk Score: 75/100
Analysis Duration: 12.34 seconds

Reports Generated:
  ✅ reports/forensic_analysis_20251005_003623.json
  ✅ reports/iocs_20251005_003623.csv

⚠️ Risk Factors:
  • Phishing patterns detected
  • New domain (only 5 days old)
  • Login form detected
  • Similar to paypal.com (typosquatting)

💡 Recommendation: HIGH RISK - Avoid this site
```

**Files Created:**
- `reports/forensic_analysis_20251005_003623.json` - Complete data
- `reports/iocs_20251005_003623.csv` - Extracted IOCs

---

## **6. Errors Fixed! ✅**

### **All errors have been fixed in main_analyzer.py:**

**Fixed:**
1. ✅ `'DNSCollector' object has no attribute 'collect_dns_info'`
   - Now uses: `network_analyzer.resolve_ip(domain)`

2. ✅ `'CertificateCollector' object has no attribute 'analyze_certificate'`
   - Now uses: `security_analyzer.analyze_certificate(url)`

3. ✅ `'ContentAnalyzer' object has no attribute 'analyze_html'`
   - Now uses: `content_analyzer.analyze_content(url)`

4. ✅ `'AttributionAnalyzer' object has no attribute 'get_whois_info'`
   - Now uses: `attribution_analyzer.analyze_domain(domain)`

5. ✅ `'PhishingDetector' object has no attribute 'analyze'`
   - Now uses: `phishing_detector.detect_phishing(url, content, attribution)`

6. ✅ `[Errno 13] Permission denied: 'reports'`
   - Fixed: `output_path.mkdir(parents=True, exist_ok=True)`

7. ⚠️ `No module named 'ipwhois'`
   - Optional dependency, not critical
   - Install with: `pip install ipwhois`

**Test the fixes:**

```bash
# Full analysis should now work!
python main_analyzer.py --url "https://www.google.com" --modules all
```

---

## **7. Where do collectors store collected details?**

### **Answer: In memory during analysis, then saved to reports/**

**Data Flow:**

```
Collectors gather data
    ↓
Store in memory (Python dictionaries)
    ↓
Pass to analyzers
    ↓
Analyzers process data
    ↓
Results stored in self.results dictionary
    ↓
Reporters save to files
    ↓
Files saved to reports/ folder
```

**Example:**

```python
# Collector gathers data
screenshot_data = await screenshot_collector.capture_screenshot(url)
# → Returns: {'screenshot_path': 'screenshots/screenshot_abc123.png'}

# Stored in results
self.results['evidence']['screenshot'] = screenshot_data

# Reporter saves everything
json_exporter.export_data(self.results)
# → Saves to: reports/forensic_analysis_20251005_003623.json
```

**Where data is stored:**

1. **During analysis:** In memory (RAM)
   - `self.results` dictionary in main_analyzer.py

2. **After analysis:** In files
   - `reports/forensic_analysis_*.json` - All data
   - `reports/iocs_*.csv` - Extracted IOCs
   - `screenshots/screenshot_*.png` - Screenshots (if captured)

**View stored data:**

```bash
# View JSON report
cat reports/forensic_analysis_20251005_003623.json

# Or open in text editor
notepad reports/forensic_analysis_20251005_003623.json
```

---

## **8. Does PDF get generated in reporters?**

### **Answer: Framework exists, but needs ReportLab library.**

**Current Status:**

```python
# PDF Reporter - ⚠️ Framework only
pdf_reporter.generate_report(results)
    → Framework exists in reporters/pdf_reporter.py
    → Needs: pip install reportlab
    → Status: Not fully implemented yet
```

**To enable PDF generation:**

```bash
# Install ReportLab
pip install reportlab

# Then implement the PDF generation logic
# in reporters/pdf_reporter.py
```

**What's working now:**

```python
# JSON Export - ✅ FULLY WORKING
json_exporter.export_data(results)
    → Saves to: reports/forensic_analysis_*.json

# IOC Export - ✅ FULLY WORKING
ioc_extractor.export_csv_format(iocs)
    → Saves to: reports/iocs_*.csv

ioc_extractor.export_stix_format(iocs)
    → Saves to: reports/iocs_stix_*.json
```

**Workaround for PDF:**

You can convert JSON to PDF manually:
1. Generate JSON report
2. Open in browser
3. Print to PDF

Or use online JSON to PDF converters.

---

## **Quick Reference**

### **Run Analysis:**

```bash
# Single URL with VirusTotal
python test_virustotal.py

# Batch analysis
python batch_analysis.py

# Full forensic analysis
python main_analyzer.py --url "https://example.com" --modules all
```

### **View Results:**

```bash
# Test results
ls tmp/

# Full reports
ls reports/

# Screenshots
ls screenshots/
```

### **Clean Up:**

```bash
# Clean test results
Remove-Item tmp\*.json

# Clean reports
Remove-Item reports\*

# Clean screenshots
Remove-Item screenshots\*
```

---

**Last Updated:** October 5, 2025  
**Version:** 1.0.0
