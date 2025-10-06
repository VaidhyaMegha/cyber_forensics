# 🚀 Quick Start Guide - Cyber Forensics Toolkit

## ⚡ **Get Started in 5 Minutes**

### **Step 1: Setup API Keys** (2 minutes)

1. Copy the example config:
```bash
copy config\api_keys.json.example config\api_keys.json
```

2. Edit `config/api_keys.json` and add your VirusTotal API key:
```json
{
  "virustotal": "YOUR_API_KEY_HERE"
}
```

**Get FREE VirusTotal API Key:**
- Visit: https://www.virustotal.com/gui/join-us
- Sign up → Profile → API Key

---

### **Step 2: Install Dependencies** (1 minute)

```bash
pip install requests beautifulsoup4 python-whois dnspython cryptography
```

---

### **Step 3: Run Your First Analysis** (2 minutes)

```bash
python demo.py
```

This will analyze test URLs and show you how the tool works!

---

## 📋 **Quick Test Commands**

### **Test 1: Analyze a Legitimate Site**
```bash
python demo.py
# Analyzes: http://httpbin.org
```

### **Test 2: Check Your Own URL**

Create a simple test script `test_url.py`:

```python
import asyncio
from analyzers.network_analyzer import NetworkAnalyzer
from analyzers.security_analyzer import SecurityAnalyzer
from analyzers.threat_intel import ThreatIntelligence
import json

async def quick_test():
    # Configuration
    config = {
        'timeouts': {'network': 30, 'security': 60, 'threat_intel': 60},
        'api_keys': json.load(open('config/api_keys.json'))
    }
    
    # Your URL to test
    url = "https://www.google.com"
    
    print(f"🔍 Analyzing: {url}\n")
    
    # Network Analysis
    print("📡 Network Analysis...")
    network = NetworkAnalyzer(config)
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    ip_info = await network.resolve_ip(domain)
    print(f"   IPs: {ip_info['ipv4_addresses']}")
    
    # Security Analysis
    print("\n🔒 Security Analysis...")
    security = SecurityAnalyzer(config)
    cert_info = await security.analyze_certificate(url)
    print(f"   SSL: {'✅ Valid' if cert_info['certificate_valid'] else '❌ Invalid'}")
    
    # Threat Intelligence
    print("\n🛡️ Threat Intelligence...")
    threat = ThreatIntelligence(config)
    threat_info = await threat.analyze_url(url)
    print(f"   Threat Score: {threat_info['threat_score']}/100")
    print(f"   Status: {threat_info['recommendations'][0]}")
    
    print("\n✅ Analysis Complete!")

# Run
asyncio.run(quick_test())
```

Run it:
```bash
python test_url.py
```

---

## 🎯 **What Each Module Does (Simple)**

| Module | What It Checks | Example Output |
|--------|----------------|----------------|
| **Network Analyzer** | Where is the server? | "IP: 142.250.185.46, Location: USA" |
| **Security Analyzer** | Is it secure? | "SSL: ✅ Valid, Headers: 70/100" |
| **Content Analyzer** | What's on the page? | "Login form: Yes, Suspicious code: No" |
| **Attribution Analyzer** | Who owns it? | "Domain age: 3 days, Owner: Hidden" |
| **Threat Intelligence** | Is it known bad? | "VirusTotal: 15 engines flagged it" |
| **Phishing Detector** | Is it phishing? | "Phishing Score: 75/100 - HIGH RISK" |

---

## 📊 **Understanding Results**

### **Risk Scores**

```
0-29   = 🟢 LOW RISK      → Probably safe
30-49  = 🟡 MEDIUM RISK   → Be cautious
50-69  = 🟠 HIGH RISK     → Likely malicious
70-100 = 🔴 CRITICAL RISK → Definitely malicious
```

### **Example Good Site**
```
URL: https://www.google.com
Risk Score: 5/100
Status: ✅ LOW RISK - No threats detected
```

### **Example Bad Site**
```
URL: http://paypa1-verify.tk
Risk Score: 85/100
Status: 🚨 CRITICAL - High probability of phishing
Indicators:
  - Similar to paypal.com (typosquatting)
  - Domain only 2 days old
  - Login form detected
  - Flagged by 15 antivirus engines
```

---

## 🔧 **Troubleshooting**

### **Error: "VirusTotal API key not configured"**
**Solution:** Add your API key to `config/api_keys.json`

### **Error: "Module not found"**
**Solution:** Install dependencies:
```bash
pip install -r requirements.txt
```

### **Error: "WHOIS lookup failed"**
**Solution:** Install python-whois:
```bash
pip install python-whois
```

---

## 📁 **File Structure**

```
cyber_forensics/
├── analyzers/              # Analysis modules
│   ├── network_analyzer.py      ✅ Network intelligence
│   ├── security_analyzer.py     ✅ Security checks
│   ├── content_analyzer.py      ✅ Content analysis
│   ├── attribution_analyzer.py  ✅ WHOIS/domain info
│   └── threat_intel.py          ✅ VirusTotal integration
│
├── detectors/              # Threat detection
│   ├── phishing_detector.py     ✅ Phishing detection
│   ├── malware_detector.py      ✅ Malware detection
│   ├── brand_detector.py        ✅ Brand impersonation
│   └── kit_detector.py          ✅ Phishing kit detection
│
├── collectors/             # Evidence collection
│   ├── screenshot_collector.py  ✅ Screenshots
│   ├── resource_collector.py    ✅ Resource download
│   ├── dns_collector.py         ✅ DNS records
│   └── cert_collector.py        ✅ SSL certificates
│
├── reporters/              # Report generation
│   ├── pdf_reporter.py          ✅ PDF reports
│   ├── html_reporter.py         ✅ HTML dashboards
│   ├── json_exporter.py         ✅ JSON export
│   └── ioc_extractor.py         ✅ IOC extraction
│
├── config/
│   └── api_keys.json            ⚙️ Your API keys
│
├── demo.py                      🎮 Demo script
├── main_analyzer.py             🎯 Main orchestrator
└── requirements.txt             📦 Dependencies
```

---

## 🎮 **Try These Test URLs**

```python
test_urls = {
    'safe': 'https://www.google.com',
    'test_ssl': 'https://badssl.com',
    'test_no_ssl': 'http://neverssl.com',
    'test_http': 'http://httpbin.org'
}
```

---

## 💡 **Pro Tips**

1. **Start with demo.py** to see how it works
2. **Test with known-good URLs first** (like google.com)
3. **Check the JSON output** for detailed information
4. **Use VirusTotal API** for best threat detection
5. **Review logs** in `forensics.log` for debugging

---

## 📞 **Need Help?**

- **Documentation:** See `IMPLEMENTATION_GUIDE.md`
- **Email:** madhulatha@samyama.ai
- **Website:** https://Samyama.ai

---

## ✅ **You're Ready!**

You now have a fully functional cyber forensics toolkit. Start analyzing suspicious URLs and stay safe online! 🛡️

**Happy Investigating! 🔍**
