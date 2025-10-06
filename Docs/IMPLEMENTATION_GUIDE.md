# 🚀 Cyber Forensics Toolkit - Implementation Guide

## 📋 **What We've Built**

This guide explains the complete implementation of the Cyber Forensics Toolkit, designed for both technical and non-technical users.

---

## 🎯 **For Beginners: What Does This Tool Do?**

Think of this toolkit as a **digital detective** that investigates suspicious websites. Here's how it works:

### **The Investigation Process**

1. **You provide a suspicious URL** (like a link from a suspicious email)
2. **The tool automatically:**
   - Takes a "photo" of the website (screenshot)
   - Checks who owns the website (WHOIS lookup)
   - Analyzes the website's code for malicious patterns
   - Compares it with known threat databases (VirusTotal)
   - Checks if it's impersonating a real company (phishing)
   - Generates a detailed report

3. **You get a clear answer:**
   - ✅ **SAFE** - No threats detected
   - ⚠️ **SUSPICIOUS** - Some warning signs found
   - 🚨 **DANGEROUS** - High probability of phishing/malware

---

## 🏗️ **Architecture Overview**

### **Data Flow**

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
│  ✅ Content Analyzer (NEW)          │
│  ✅ Attribution Analyzer (NEW)      │
│  ✅ Threat Intelligence (NEW)       │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  DETECTORS (Identify Threats)       │
│  ✅ Phishing Detector (NEW)         │
│  ✅ Malware Detector (NEW)          │
│  ✅ Brand Detector (NEW)            │
│  ✅ Kit Detector (NEW)              │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  REPORTERS (Generate Reports)       │
│  ✅ PDF Reporter (NEW)              │
│  ✅ HTML Reporter (NEW)             │
│  ✅ JSON Exporter (NEW)             │
│  ✅ IOC Extractor (NEW)             │
└─────────────────────────────────────┘
    ↓
USER OUTPUT (Reports & Alerts)
```

---

## 📦 **Modules Implemented**

### **✅ ANALYZERS (5 Total)**

#### **1. Network Analyzer** (Already Existed)
- **File:** `analyzers/network_analyzer.py`
- **What it does:** Investigates the network infrastructure
- **Key Functions:**
  - `resolve_ip()` - Finds the server's IP address
  - `get_geolocation()` - Determines server location
  - `detect_cloud_provider()` - Identifies hosting (AWS, Azure, GCP)
  - `scan_ports()` - Checks for open network ports

#### **2. Security Analyzer** (Already Existed)
- **File:** `analyzers/security_analyzer.py`
- **What it does:** Checks security configurations
- **Key Functions:**
  - `analyze_certificate()` - Validates SSL/TLS certificates
  - `analyze_headers()` - Checks security headers
  - `scan_vulnerabilities()` - Tests for common vulnerabilities

#### **3. Content Analyzer** ⭐ (NEW)
- **File:** `analyzers/content_analyzer.py`
- **What it does:** Analyzes website content and structure
- **Key Functions:**
  - `analyze_content()` - Main content analysis
  - `_analyze_html_structure()` - Examines HTML structure
  - `_analyze_javascript()` - Checks JavaScript code
  - `_analyze_forms()` - Detects login/data collection forms
  - `_extract_resources()` - Lists all images, scripts, stylesheets
  - `_detect_obfuscation()` - Finds hidden/obfuscated code
  - `calculate_content_similarity()` - Compares with legitimate sites

**Example Output:**
```json
{
  "html_structure": {
    "title": "PayPal Login",
    "forms_count": 1,
    "iframes_count": 2
  },
  "forms": [
    {
      "is_login_form": true,
      "collects_sensitive_data": true
    }
  ],
  "suspicious_patterns": [
    "Account verification request",
    "Urgency tactics"
  ]
}
```

#### **4. Attribution Analyzer** ⭐ (NEW)
- **File:** `analyzers/attribution_analyzer.py`
- **What it does:** Investigates domain ownership and history
- **Key Functions:**
  - `analyze_domain()` - Main attribution analysis
  - `_get_whois_data()` - Gets domain registration info
  - `_calculate_domain_age()` - Determines how old the domain is
  - `_find_similar_domains()` - Finds typosquatting domains
  - `_analyze_registrant()` - Checks who registered the domain

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
    "age_days": 3,
    "is_new": true
  },
  "risk_indicators": [
    "⚠️ New domain (only 3 days old)",
    "Privacy protection enabled"
  ]
}
```

#### **5. Threat Intelligence** ⭐ (NEW)
- **File:** `analyzers/threat_intel.py`
- **What it does:** Checks threat databases (VirusTotal, AbuseIPDB)
- **Key Functions:**
  - `analyze_url()` - Check URL reputation
  - `analyze_domain()` - Check domain reputation
  - `analyze_ip()` - Check IP reputation
  - `_check_virustotal_url()` - VirusTotal API integration
  - `_check_abuseipdb()` - AbuseIPDB API integration
  - `extract_iocs()` - Extract indicators of compromise

**Example Output:**
```json
{
  "virustotal": {
    "available": true,
    "data": {
      "last_analysis_stats": {
        "malicious": 15,
        "suspicious": 3,
        "clean": 50
      }
    }
  },
  "threat_score": 85,
  "is_malicious": true,
  "recommendations": [
    "⚠️ HIGH RISK: Multiple threat intelligence sources flag this as malicious"
  ]
}
```

---

### **✅ DETECTORS (4 Total)**

#### **1. Phishing Detector** ⭐ (NEW)
- **File:** `detectors/phishing_detector.py`
- **What it does:** Identifies phishing attempts
- **Detection Methods:**
  - URL pattern analysis (IP addresses, suspicious TLDs)
  - Domain similarity checking (typosquatting)
  - Login form detection
  - Phishing keyword detection
  - Brand impersonation detection

**Phishing Indicators:**
- IP address instead of domain name (weight: 25)
- Suspicious TLD like `.tk`, `.ml` (weight: 15)
- Similar to legitimate domain (weight: 35)
- Contains login form (weight: 15)
- New domain < 6 months (weight: 30)

**Example Output:**
```json
{
  "is_phishing": true,
  "phishing_score": 75,
  "confidence": 0.9,
  "risk_level": "critical",
  "indicators": [
    {
      "type": "domain_similarity",
      "severity": "high",
      "description": "Domain similar to paypal.com (similarity: 85%)"
    },
    {
      "type": "content",
      "severity": "high",
      "description": "Login form detected"
    }
  ]
}
```

#### **2. Malware Detector** ⭐ (NEW)
- **File:** `detectors/malware_detector.py`
- **What it does:** Detects malicious code
- **Detection Methods:**
  - Obfuscated JavaScript analysis
  - Dangerous function detection (eval, unescape)
  - Drive-by download detection
  - Threat intelligence correlation

#### **3. Brand Detector** ⭐ (NEW)
- **File:** `detectors/brand_detector.py`
- **What it does:** Detects brand impersonation
- **Checks for:** PayPal, Amazon, Microsoft, Apple, Google, Banks, etc.

#### **4. Kit Detector** ⭐ (NEW)
- **File:** `detectors/kit_detector.py`
- **What it does:** Identifies known phishing kits
- **Known Kits:** 16shop, Z-Shadow, BlackBullet

---

### **✅ COLLECTORS (4 Total)**

#### **1. Screenshot Collector** ⭐ (NEW)
- **File:** `collectors/screenshot_collector.py`
- **What it does:** Captures visual evidence
- **Functions:**
  - `capture_screenshot()` - Single screenshot
  - `capture_full_page()` - Full page screenshot
  - `capture_multiple_viewports()` - Desktop, tablet, mobile views

#### **2. Resource Collector** ⭐ (NEW)
- **File:** `collectors/resource_collector.py`
- **What it does:** Downloads and analyzes resources

#### **3. DNS Collector** ⭐ (NEW)
- **File:** `collectors/dns_collector.py`
- **What it does:** Collects DNS records (uses NetworkAnalyzer)

#### **4. Certificate Collector** ⭐ (NEW)
- **File:** `collectors/cert_collector.py`
- **What it does:** Collects SSL certificates (uses SecurityAnalyzer)

---

### **✅ REPORTERS (4 Total)**

#### **1. PDF Reporter** ⭐ (NEW)
- **File:** `reporters/pdf_reporter.py`
- **What it does:** Generates professional PDF reports

#### **2. HTML Reporter** ⭐ (NEW)
- **File:** `reporters/html_reporter.py`
- **What it does:** Creates interactive HTML dashboards

#### **3. JSON Exporter** ⭐ (NEW)
- **File:** `reporters/json_exporter.py`
- **What it does:** Exports structured JSON data
- **Function:** `export_data()` - Saves analysis to JSON file

#### **4. IOC Extractor** ⭐ (NEW)
- **File:** `reporters/ioc_extractor.py`
- **What it does:** Extracts indicators of compromise
- **Functions:**
  - `extract_iocs()` - Extract IPs, domains, URLs, hashes
  - `export_stix_format()` - STIX format export
  - `export_csv_format()` - CSV format export

---

## 🔧 **Configuration Setup**

### **1. API Keys Configuration**

Create `config/api_keys.json` from the example:

```json
{
  "virustotal": "YOUR_VIRUSTOTAL_API_KEY_HERE",
  "abuseipdb": "YOUR_ABUSEIPDB_API_KEY_HERE",
  "shodan": "YOUR_SHODAN_API_KEY_HERE"
}
```

**How to get API keys:**

1. **VirusTotal** (FREE tier available)
   - Visit: https://www.virustotal.com/gui/join-us
   - Sign up for free account
   - Go to your profile → API Key
   - Copy the key to `api_keys.json`

2. **AbuseIPDB** (Optional)
   - Visit: https://www.abuseipdb.com/register
   - Free tier: 1000 requests/day

### **2. Install Dependencies**

```bash
pip install -r requirements.txt
```

**Core Dependencies:**
- `requests` - HTTP requests
- `beautifulsoup4` - HTML parsing
- `python-whois` - WHOIS lookups
- `dnspython` - DNS queries
- `cryptography` - SSL/TLS analysis

---

## 🚀 **Usage Examples**

### **Basic Usage**

```python
import asyncio
from main_analyzer import CyberForensicsAnalyzer

async def analyze_url():
    # Initialize analyzer
    analyzer = CyberForensicsAnalyzer(config_path='config/api_keys.json')
    
    # Analyze a URL
    url = "https://suspicious-site.com"
    results = await analyzer.analyze_url(url)
    
    # Generate reports
    analyzer.generate_reports(formats=['json', 'pdf', 'html'])

# Run analysis
asyncio.run(analyze_url())
```

### **Command Line Usage**

```bash
# Full analysis
python main_analyzer.py --url "https://suspicious-site.com" --full-analysis

# Quick scan
python main_analyzer.py --url "https://suspicious-site.com" --quick

# Specific modules
python main_analyzer.py --url "https://suspicious-site.com" --modules network,security,threat_intel
```

---

## 📊 **Understanding the Results**

### **Risk Levels**

- **🟢 LOW (0-29):** No significant threats detected
- **🟡 MEDIUM (30-49):** Some suspicious indicators
- **🟠 HIGH (50-69):** Strong threat indicators
- **🔴 CRITICAL (70-100):** High probability of malicious intent

### **Sample Analysis Output**

```json
{
  "target_url": "http://paypa1-login.tk",
  "analysis_summary": {
    "risk_level": "CRITICAL",
    "risk_score": 85,
    "is_phishing": true,
    "is_malicious": true
  },
  "findings": {
    "network_analysis": {
      "ip": "192.168.1.1",
      "location": "Unknown",
      "cloud_provider": "None"
    },
    "threat_intelligence": {
      "virustotal": {
        "malicious": 15,
        "suspicious": 3
      },
      "threat_score": 85
    },
    "phishing_detection": {
      "is_phishing": true,
      "phishing_score": 75,
      "indicators": [
        "Domain similar to paypal.com",
        "New domain (3 days old)",
        "Login form detected",
        "Suspicious TLD (.tk)"
      ]
    }
  },
  "recommendations": [
    "🚨 CRITICAL: Do not interact with this site",
    "⚠️ HIGH RISK: Multiple threat sources confirm malicious intent",
    "Block this URL in your firewall/proxy"
  ]
}
```

---

## 🧪 **Testing the Implementation**

### **Test with Known URLs**

```python
# Test URLs
test_urls = {
    'legitimate': 'https://www.google.com',
    'phishing': 'http://neverssl.com',  # Test site
    'suspicious': 'https://badssl.com'   # SSL test site
}

# Run tests
for category, url in test_urls.items():
    print(f"\nTesting {category}: {url}")
    results = await analyzer.analyze_url(url)
    print(f"Risk Level: {results['risk_level']}")
```

---

## 🔍 **Module Integration Flow**

### **How Modules Work Together**

1. **User provides URL** → `main_analyzer.py`

2. **Collectors gather data:**
   - Screenshot Collector → Takes website screenshot
   - DNS Collector → Gets DNS records (via NetworkAnalyzer)
   - Certificate Collector → Gets SSL cert (via SecurityAnalyzer)

3. **Analyzers process data:**
   - Network Analyzer → IP, geolocation, cloud provider
   - Security Analyzer → SSL, headers, vulnerabilities
   - Content Analyzer → HTML, JavaScript, forms
   - Attribution Analyzer → WHOIS, domain age
   - Threat Intelligence → VirusTotal, AbuseIPDB

4. **Detectors identify threats:**
   - Phishing Detector → Uses content + attribution data
   - Malware Detector → Uses content + threat intel data
   - Brand Detector → Uses content data
   - Kit Detector → Uses content data

5. **Reporters generate output:**
   - JSON Exporter → Structured data
   - PDF Reporter → Professional report
   - HTML Reporter → Interactive dashboard
   - IOC Extractor → Threat indicators

---

## 📝 **Common Functions Pattern**

All modules follow this pattern:

```python
class ModuleName:
    def __init__(self, config: Dict[str, Any]):
        """Initialize with configuration"""
        self.config = config
        self.timeout = config.get('timeouts', {}).get('module', 30)
    
    async def main_function(self, input: str) -> Dict[str, Any]:
        """Main analysis function"""
        result = {
            'input': input,
            'status': 'success',
            'data': {}
        }
        
        try:
            # Analysis logic here
            pass
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            result['error'] = str(e)
        
        return result
```

---

## 🎓 **For Developers**

### **Adding New Analyzers**

1. Create file in `analyzers/` directory
2. Follow the pattern from existing analyzers
3. Implement async methods
4. Return consistent dictionary structure
5. Add to `main_analyzer.py` imports

### **Adding New Detectors**

1. Create file in `detectors/` directory
2. Accept analyzer data as input
3. Return threat indicators with weights
4. Calculate risk scores

---

## ✅ **Implementation Status**

| Component | Status | Files Created |
|-----------|--------|---------------|
| **Analyzers** | ✅ Complete | 5/5 |
| **Detectors** | ✅ Complete | 4/4 |
| **Collectors** | ✅ Complete | 4/4 |
| **Reporters** | ✅ Complete | 4/4 |
| **Total** | **✅ 17 modules** | **17/17** |

---

## 🎯 **Next Steps**

1. **Test with your VirusTotal API key**
2. **Run demo analysis on test URLs**
3. **Review generated reports**
4. **Customize detection rules as needed**
5. **Integrate with your security workflow**

---

## 📞 **Support**

For questions or issues:
- **Email:** madhulatha@samyama.ai
- **Website:** https://Samyama.ai

---

**Last Updated:** October 2025  
**Version:** 1.0.0  
**License:** Proprietary - All Rights Reserved
