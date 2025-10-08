# Cyber Forensics Toolkit 🔍🛡️

> **A comprehensive toolkit for analyzing phishing websites and conducting digital forensics investigations**

---

## 📋 **Project Information**

**Owner:** [Samyama.ai](https://Samyama.ai) - Vaidhyamegha Private Limited  
**Contact:** madhulatha@samyama.ai  
**License:** Proprietary - All Rights Reserved  
**Version:** 1.0.0  
**Last Updated:** October 2025

---

A powerful Python-based toolkit for conducting thorough forensic analysis of phishing websites and malicious domains. This tool helps cybersecurity professionals, researchers, and investigators gather comprehensive intelligence about suspicious websites.

---

## 🎯 **Key Features**

### **🌐 Network Intelligence**
- **IP Address Resolution**: Primary and secondary IPs
- **Geolocation Analysis**: Country, region, city, ISP details
- **Cloud Provider Detection**: AWS, Azure, GCP, Cloudflare identification
- **DNS Analysis**: Complete DNS record enumeration
- **Subdomain Discovery**: Find related subdomains and infrastructure

### **🔒 Security Analysis**
- **SSL/TLS Certificate Analysis**: Validity, issuer, chain verification
- **Security Headers**: HSTS, CSP, X-Frame-Options analysis
- **Vulnerability Scanning**: Common web vulnerabilities
- **Malware Detection**: Integration with threat intelligence feeds
- **Reputation Scoring**: Multi-source reputation analysis

### **🕵️ Attribution & Intelligence**
- **WHOIS Analysis**: Domain registration details
- **Historical Data**: Domain age, registration changes
- **Contact Information**: Registrant, admin, technical contacts
- **Infrastructure Mapping**: Related domains and IPs
- **Threat Actor Profiling**: Pattern analysis and attribution

### **📊 Content Analysis**
- **Website Screenshots**: Visual evidence capture
- **HTML/JavaScript Analysis**: Code inspection and obfuscation detection
- **Resource Enumeration**: Images, scripts, external resources
- **Phishing Kit Detection**: Common phishing framework identification
- **Brand Impersonation**: Logo and content similarity analysis

### **📈 Reporting & Visualization**
- **Comprehensive Reports**: PDF and HTML forensic reports
- **Interactive Dashboards**: Real-time analysis visualization
- **Timeline Analysis**: Attack progression and infrastructure changes
- **Threat Intelligence**: IOC extraction and sharing
- **Evidence Chain**: Forensically sound documentation

---

## 🛠️ **Toolkit Components**

### **Core Modules**
```
cyber_forensics/
├── 🔍 analyzers/
│   ├── network_analyzer.py      # IP, DNS, geolocation analysis
│   ├── security_analyzer.py     # SSL, headers, vulnerabilities
│   ├── content_analyzer.py      # Website content and structure
│   ├── attribution_analyzer.py  # WHOIS, historical data
│   └── threat_intel.py          # Threat intelligence integration
├── 🛡️ detectors/
│   ├── phishing_detector.py     # Phishing pattern detection
│   ├── malware_detector.py      # Malware and payload analysis
│   ├── brand_detector.py        # Brand impersonation detection
│   └── kit_detector.py          # Phishing kit identification
├── 📊 reporters/
│   ├── pdf_reporter.py          # PDF forensic reports
│   ├── html_reporter.py         # Interactive HTML reports
│   ├── json_exporter.py         # Structured data export
│   └── ioc_extractor.py         # IOC extraction and formatting
├── 🌐 collectors/
│   ├── screenshot_collector.py  # Website screenshots
│   ├── resource_collector.py    # Download and analyze resources
│   ├── dns_collector.py         # Comprehensive DNS enumeration
│   └── cert_collector.py        # SSL certificate chain analysis
└── 🎯 main_analyzer.py          # Orchestration and main interface
```

### **External Integrations**
- **VirusTotal API**: Malware and reputation analysis
- **Shodan API**: Infrastructure and service discovery
- **URLVoid API**: Multi-engine URL reputation
- **AbuseIPDB**: IP reputation and abuse reports
- **Censys API**: Internet-wide scanning data
- **Netlas.io API**: Domain, DNS, and internet-wide scan intelligence

---

## 🚀 **Quick Start**

### **Installation**
```bash
cd cyber_forensics
pip install -r requirements.txt
```

### **Basic Analysis**
```bash
# Analyze a suspicious URL
python main_analyzer.py --url "https://suspicious-site.com" --full-analysis

# Quick scan mode
python main_analyzer.py --url "https://phishing-site.com" --quick

# Batch analysis
python main_analyzer.py --file urls.txt --output-dir results/
```

### **Advanced Usage**
```bash
# Deep forensics with all modules
python main_analyzer.py \
    --url "https://target.com" \
    --deep-scan \
    --screenshot \
    --download-resources \
    --threat-intel \
    --report-format pdf,html,json

# Focus on specific analysis
python main_analyzer.py \
    --url "https://target.com" \
    --modules network,security,attribution \
    --api-keys config/api_keys.json
```

---

## 📋 **Analysis Capabilities**

### **🌐 Network Forensics**
| Feature | Description | Data Sources |
|---------|-------------|--------------|
| **IP Resolution** | Primary/secondary IPs, CDN detection | DNS queries, multiple resolvers |
| **Geolocation** | Country, region, city, coordinates | MaxMind, IP2Location, IPinfo |
| **ISP/Hosting** | Internet service provider, hosting company | WHOIS, BGP data, Shodan |
| **Cloud Detection** | AWS, Azure, GCP, Cloudflare identification | IP ranges, reverse DNS |
| **Port Scanning** | Open ports and running services | Nmap, Shodan API |

### **🔒 Security Assessment**
| Feature | Description | Detection Method |
|---------|-------------|------------------|
| **SSL Analysis** | Certificate validity, chain, encryption | OpenSSL, certificate transparency |
| **Security Headers** | HSTS, CSP, CORS, X-Frame-Options | HTTP response analysis |
| **Vulnerabilities** | XSS, SQLi, CSRF, directory traversal | Automated scanning, signatures |
| **Malware Detection** | Malicious payloads, drive-by downloads | VirusTotal, YARA rules |
| **Reputation** | Domain/IP reputation across databases | Multiple threat intel sources |

### **🕵️ Attribution Intelligence**
| Feature | Description | Information Gathered |
|---------|-------------|---------------------|
| **WHOIS Data** | Domain registration information | Registrant, dates, contacts |
| **Historical Analysis** | Domain age, ownership changes | Archive.org, DNS history |
| **Infrastructure Mapping** | Related domains and IP addresses | Passive DNS, certificate analysis |
| **Contact Tracing** | Email addresses, phone numbers | Registration data, social media |
| **Pattern Analysis** | Similar domains, naming conventions | Fuzzy matching, Levenshtein distance |

### **📊 Content Forensics**
| Feature | Description | Analysis Method |
|---------|-------------|-----------------|
| **Visual Analysis** | Screenshots, layout comparison | Selenium, image processing |
| **Code Analysis** | HTML, JavaScript, obfuscation | Static analysis, beautification |
| **Resource Mapping** | External resources, CDNs | Link extraction, dependency analysis |
| **Phishing Kit Detection** | Common frameworks, templates | Signature matching, hash analysis |
| **Brand Analysis** | Logo similarity, content matching | Computer vision, NLP |

---

## 🎯 **Use Cases**

### **🚨 Incident Response**
- **Rapid Triage**: Quick assessment of reported phishing sites
- **Evidence Collection**: Forensically sound data gathering
- **Impact Assessment**: Determine scope and potential damage
- **Attribution**: Identify threat actors and infrastructure

### **🔍 Threat Hunting**
- **Infrastructure Discovery**: Map attacker infrastructure
- **Campaign Tracking**: Follow phishing campaigns over time
- **IOC Generation**: Extract indicators for defensive measures
- **Pattern Recognition**: Identify recurring attack methods

### **🛡️ Proactive Defense**
- **Brand Monitoring**: Detect impersonation attempts
- **Domain Monitoring**: Track suspicious domain registrations
- **Threat Intelligence**: Enrich security tools with IOCs
- **Security Awareness**: Generate training materials

### **📚 Research & Education**
- **Academic Research**: Study phishing trends and techniques
- **Training Materials**: Create realistic scenarios for education
- **Methodology Development**: Improve forensic techniques
- **Tool Validation**: Test and compare analysis methods

---

## 🔧 **Configuration**

### **API Keys Setup**
```json
{
  "virustotal": "your_vt_api_key",
  "shodan": "your_shodan_api_key",
  "urlvoid": "your_urlvoid_api_key",
  "abuseipdb": "your_abuseipdb_key",
  "censys": {
    "api_id": "your_censys_id",
    "api_secret": "your_censys_secret"
  },
  "netlas": "your_netlas_api_key"
}
```

### **Analysis Profiles**
```yaml
# Quick scan profile
quick_scan:
  modules: [network, security]
  screenshot: false
  deep_scan: false
  timeout: 30

# Full forensics profile
full_forensics:
  modules: [network, security, content, attribution, threat_intel]
  screenshot: true
  deep_scan: true
  download_resources: true
  timeout: 300
```

---

## 📊 **Sample Output**

### **Executive Summary**
```
🎯 FORENSIC ANALYSIS REPORT
==========================
Target: https://fake-bank-login.com
Analysis Date: 2024-08-03 11:58:06
Risk Level: HIGH ⚠️

🔍 Key Findings:
• Phishing site impersonating major bank
• Hosted on compromised WordPress site
• SSL certificate from Let's Encrypt (suspicious for banking)
• IP geolocation: Russia (high-risk jurisdiction)
• Domain registered 2 days ago with privacy protection
• Multiple security vulnerabilities detected
```

### **Technical Details**
```
🌐 NETWORK INTELLIGENCE
IP Address: 185.220.101.42
Geolocation: Moscow, Russia (55.7558, 37.6176)
ISP: Selectel Ltd
Cloud Provider: None detected
Open Ports: 80, 443, 22 (SSH - concerning)

🔒 SECURITY ANALYSIS
SSL Certificate: Let's Encrypt (DV) - Expires in 89 days
Security Headers: Missing HSTS, CSP, X-Frame-Options
Vulnerabilities: XSS, Outdated WordPress, Weak passwords
Reputation: Flagged by 8/12 security vendors

🕵️ ATTRIBUTION
Domain Age: 2 days
Registrar: Namecheap (privacy protected)
Similar Domains: 15 variants detected
Infrastructure: Part of larger phishing campaign
```

---

## ⚖️ **Legal & Ethical Considerations**

### **🚨 Important Disclaimers**
- **Educational Purpose**: This toolkit is for legitimate security research and defense
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report findings to appropriate authorities
- **No Malicious Use**: Do not use for illegal activities or unauthorized access

### **📋 Best Practices**
- **Authorization**: Only analyze domains you own or have permission to test
- **Data Protection**: Handle collected data according to privacy regulations
- **Evidence Integrity**: Maintain forensic chain of custody
- **Responsible Reporting**: Share threat intelligence responsibly

---

## 🤝 **Contributing**

We welcome contributions from the cybersecurity community:

- **Bug Reports**: Report issues and false positives
- **Feature Requests**: Suggest new analysis capabilities
- **Code Contributions**: Submit pull requests with improvements
- **Threat Intelligence**: Share IOCs and attack patterns
- **Documentation**: Improve guides and examples

---

## 📚 **Documentation**

### **📖 Complete Documentation**
- **[📚 Complete Documentation](docs/DOCUMENTATION.md)** - **All-in-one comprehensive guide**
  - Project overview and architecture
  - Quick start and installation
  - Implementation details for all modules
  - Current status and working features
  - FAQ and troubleshooting
  - Folder structure and organization
  - Legal and ethical guidelines

### **🚀 Quick References**
- [Quick Start Guide](QUICK_START.md) - Get started in 5 minutes
- [Implementation Status](todo/STATUS.md) - Detailed module completion status

### **📂 Additional Documentation**
For those who prefer separate documents, individual guides are available in the `docs/` folder:
- [Project Summary](docs/PROJECT_SUMMARY.md) - Technical overview
- [Implementation Guide](docs/IMPLEMENTATION_GUIDE.md) - Complete technical guide
- [FAQ](docs/FAQ.md) - Frequently asked questions
- [Current Status](docs/CURRENT_STATUS.md) - What's working now
- [Folder Structure](docs/FOLDER_STRUCTURE.md) - Directory organization

---

## 🎉 **Getting Started**

Ready to start your forensic analysis? Follow these steps:

1. **Install Dependencies**: `pip install -r requirements.txt`
2. **Configure API Keys**: Edit `config/api_keys.json`
3. **Run First Analysis**: `python main_analyzer.py --url "https://example.com"`
4. **Review Results**: Check the generated reports
5. **Explore Advanced Features**: Try different analysis modules

**Happy hunting! 🕵️‍♂️🔍**

---

*⚠️ This toolkit is for legitimate cybersecurity purposes only. Always comply with applicable laws and obtain proper authorization before analyzing websites.*
