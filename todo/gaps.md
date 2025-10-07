# 📝 Cyber Forensics Toolkit - Implementation Gaps & TODO

This document outlines the current implementation gaps and a prioritized roadmap for future development to make the toolkit fully functional.

---

## 🔴 Priority 1: Critical Fixes & Core Functionality

*These items are essential for the toolkit to be considered complete and usable.*

### 1. **Fix [requirements.txt](cci:7://file:///d:/Github/cyber_forensics-main/requirements.txt:0:0-0:0)**
- **Issue:** The file contains Python standard libraries (`socket`, `ipaddress`, `asyncio`, etc.) which cause installation errors.
- **Action:** Remove the following lines from [requirements.txt](cci:7://file:///d:/Github/cyber_forensics-main/requirements.txt:0:0-0:0):
  - `socket`
  - `ipaddress`
  - `sqlite3`
  - `asyncio`
  - `concurrent.futures`

### 2. **Implement Screenshot Collector**
- **Issue:** [collectors/screenshot_collector.py](cci:7://file:///d:/Github/cyber_forensics-main/collectors/screenshot_collector.py:0:0-0:0) is a placeholder and does not capture screenshots.
- **Action:** Integrate `Selenium` or `Playwright` to:
  - Launch a headless browser.
  - Navigate to the target URL.
  - Capture a full-page screenshot.
  - Save the image to the [screenshots/](cci:7://file:///d:/Github/cyber_forensics-main/screenshots:0:0-0:0) directory.

### 3. **Implement PDF & HTML Reporters**
- **Issue:** [reporters/pdf_reporter.py](cci:7://file:///d:/Github/cyber_forensics-main/reporters/pdf_reporter.py:0:0-0:0) and `reporters/html_reporter.py` are placeholders.
- **Action:**
  - **HTML:** Use `Jinja2` to create an HTML template. Pass the final analysis dictionary to the template to generate a readable, well-formatted HTML report.
  - **PDF:** Use a library like `WeasyPrint` (which converts HTML to PDF) or `ReportLab` to generate a professional PDF report from the analysis data.

---

## 🟠 Priority 2: High-Impact Improvements

*These items will significantly enhance the accuracy and reliability of the analysis.*

### 1. **Flesh out Detector Logic**
- **Issue:** The detector modules (`phishing`, `malware`, `brand`) have very basic, keyword-based logic.
- **Action:**
  - **Phishing:** Improve the scoring algorithm. Add checks for URL shorteners, non-standard ports, and IP-based URLs.
  - **Malware:** Implement static analysis of downloaded JavaScript files for obfuscation patterns (`eval`, `unescape`, etc.).
  - **Brand:** Use a more robust method for brand detection, such as checking for favicons or comparing logos using image similarity (e.g., with `Pillow` or `OpenCV`).

### 2. **Improve WHOIS Reliability**
- **Issue:** The `python-whois` library can be unreliable. It may fail for certain TLDs or get rate-limited.
- **Action:**
  - Implement a try-except block with a fallback mechanism.
  - Consider switching to a more actively maintained fork of the library or using a WHOIS API (some have free tiers) as a secondary data source.

### 3. **Integrate Additional Threat Intelligence APIs**
- **Issue:** [analyzers/threat_intel.py](cci:7://file:///d:/Github/cyber_forensics-main/analyzers/threat_intel.py:0:0-0:0) is written to support URLVoid and AbuseIPDB, but only the VirusTotal function is actually called in the code.
- **Action:**
  - Implement the `_check_urlvoid()` and [_check_abuseipdb()](cci:1://file:///d:/Github/cyber_forensics-main/analyzers/threat_intel.py:292:4-333:21) methods.
  - Update the [analyze_url](cci:1://file:///d:/Github/cyber_forensics-main/analyzers/threat_intel.py:58:4-84:21) method to run these checks concurrently with the VirusTotal check.
  - Combine the scores from all three services for a more robust `threat_score`.

---

## 🟡 Priority 3: Medium-Impact Enhancements

*These items will improve the tool's robustness, performance, and analytical depth.*

### 1. **Enhance the Risk Assessment Algorithm**
- **Issue:** The current algorithm is simple and linear. It doesn't handle complex scenarios well (e.g., a clean VirusTotal report but a brand new domain with a login form).
- **Action:** Refactor the [_perform_risk_assessment](cci:1://file:///d:/Github/cyber_forensics-main/main_analyzer.py:419:4-523:9) function to use a more nuanced, weighted scoring system. Give more weight to high-confidence indicators like `is_phishing: True`.

### 2. **Add Caching for API Calls**
- **Issue:** The tool re-analyzes the same URL from scratch every time, wasting API credits and time.
- **Action:** Implement a simple caching mechanism:
  - Before calling an API, check if a recent result for that URL exists in a local cache (e.g., a [tmp/](cci:7://file:///d:/Github/cyber_forensics-main/tmp:0:0-0:0) file or a simple `sqlite` database).
  - If a fresh result exists, use it instead of making a new API call.

### 3. **Implement Standalone Collector Modules**
- **Issue:** [DNSCollector](cci:2://file:///d:/Github/cyber_forensics-main/collectors/dns_collector.py:15:0-37:21), `ResourceCollector`, and `CertificateCollector` are currently placeholders that defer to other analyzers.
- **Action:** Give these modules their own logic to make them independent and more powerful. For example, `ResourceCollector` could be responsible for downloading and hashing all JS/CSS files.

---

## 🟢 Priority 4: Low-Priority & Future Work

*Advanced features to be considered once the core functionality is stable.*

### 1. **Implement Advanced Analysis (YARA, PE)**
- **Issue:** The optional dependencies `yara-python` and `pefile` are listed but not used.
- **Action:** Implement functionality to scan downloaded resources with YARA rules or analyze executable files if any are found.

### 2. **Integrate Machine Learning Models**
- **Issue:** The optional ML dependencies (`transformers`, `torch`) are listed but not used.
- **Action:** Implement a feature to use a pre-trained language model to analyze text content for phishing cues, providing a more advanced detection method.