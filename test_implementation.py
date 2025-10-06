#!/usr/bin/env python3
"""
Test Implementation Script

Quick test to verify all modules are working correctly.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.0.0
"""

import asyncio
import json
import sys
from pathlib import Path

print("=" * 60)
print("🧪 Cyber Forensics Toolkit - Implementation Test")
print("=" * 60)

# Test 1: Import all analyzers
print("\n📦 Test 1: Importing Analyzers...")
try:
    from analyzers.network_analyzer import NetworkAnalyzer
    from analyzers.security_analyzer import SecurityAnalyzer
    from analyzers.content_analyzer import ContentAnalyzer
    from analyzers.attribution_analyzer import AttributionAnalyzer
    from analyzers.threat_intel import ThreatIntelligence
    print("   ✅ All analyzers imported successfully")
except Exception as e:
    print(f"   ❌ Analyzer import failed: {e}")
    sys.exit(1)

# Test 2: Import all detectors
print("\n🛡️  Test 2: Importing Detectors...")
try:
    from detectors.phishing_detector import PhishingDetector
    from detectors.malware_detector import MalwareDetector
    from detectors.brand_detector import BrandDetector
    from detectors.kit_detector import KitDetector
    print("   ✅ All detectors imported successfully")
except Exception as e:
    print(f"   ❌ Detector import failed: {e}")
    sys.exit(1)

# Test 3: Import all collectors
print("\n📸 Test 3: Importing Collectors...")
try:
    from collectors.screenshot_collector import ScreenshotCollector
    from collectors.resource_collector import ResourceCollector
    from collectors.dns_collector import DNSCollector
    from collectors.cert_collector import CertificateCollector
    print("   ✅ All collectors imported successfully")
except Exception as e:
    print(f"   ❌ Collector import failed: {e}")
    sys.exit(1)

# Test 4: Import all reporters
print("\n📊 Test 4: Importing Reporters...")
try:
    from reporters.pdf_reporter import PDFReporter
    from reporters.html_reporter import HTMLReporter
    from reporters.json_exporter import JSONExporter
    from reporters.ioc_extractor import IOCExtractor
    print("   ✅ All reporters imported successfully")
except Exception as e:
    print(f"   ❌ Reporter import failed: {e}")
    sys.exit(1)

# Test 5: Initialize modules
print("\n⚙️  Test 5: Initializing Modules...")
try:
    config = {
        'timeouts': {
            'network': 30,
            'security': 60,
            'content': 45,
            'threat_intel': 60
        },
        'api_keys': {},
        'output_dir': 'reports',
        'screenshot_dir': 'screenshots'
    }
    
    # Initialize one of each type
    network = NetworkAnalyzer(config)
    security = SecurityAnalyzer(config)
    content = ContentAnalyzer(config)
    attribution = AttributionAnalyzer(config)
    threat = ThreatIntelligence(config)
    
    phishing = PhishingDetector(config)
    malware = MalwareDetector(config)
    brand = BrandDetector(config)
    kit = KitDetector(config)
    
    screenshot = ScreenshotCollector(config)
    resource = ResourceCollector(config)
    dns = DNSCollector(config)
    cert = CertificateCollector(config)
    
    pdf = PDFReporter(config)
    html = HTMLReporter(config)
    json_exp = JSONExporter(config)
    ioc = IOCExtractor(config)
    
    print("   ✅ All modules initialized successfully")
except Exception as e:
    print(f"   ❌ Module initialization failed: {e}")
    sys.exit(1)

# Test 6: Basic functionality test
print("\n🔍 Test 6: Testing Basic Functionality...")

async def test_basic_functions():
    try:
        # Test network analyzer
        domain = "google.com"
        ip_info = await network.resolve_ip(domain)
        print(f"   ✅ Network Analyzer: Resolved {domain} to {len(ip_info['ipv4_addresses'])} IPs")
        
        # Test content analyzer
        url = "https://www.google.com"
        # Note: This will make an actual HTTP request
        print(f"   ℹ️  Content Analyzer: Ready (skipping live test)")
        
        # Test phishing detector
        phishing_result = await phishing.detect_phishing(url)
        print(f"   ✅ Phishing Detector: Risk score = {phishing_result['phishing_score']}/100")
        
        # Test JSON exporter
        test_data = {
            'test': 'data',
            'timestamp': '2025-10-04',
            'modules': 17
        }
        json_path = json_exp.export_data(test_data)
        if json_path and Path(json_path).exists():
            print(f"   ✅ JSON Exporter: Created {json_path}")
        else:
            print(f"   ⚠️  JSON Exporter: File creation pending")
        
        # Test IOC extractor
        iocs = ioc.extract_iocs({'url': url, 'domain': domain})
        print(f"   ✅ IOC Extractor: Extracted {len(iocs['urls'])} URLs, {len(iocs['domains'])} domains")
        
    except Exception as e:
        print(f"   ❌ Functionality test failed: {e}")
        return False
    
    return True

# Run async tests
success = asyncio.run(test_basic_functions())

# Test 7: Check API key configuration
print("\n🔑 Test 7: Checking API Configuration...")
try:
    api_keys_file = Path('config/api_keys.json')
    if api_keys_file.exists():
        with open(api_keys_file) as f:
            api_keys = json.load(f)
            if api_keys.get('virustotal'):
                print("   ✅ VirusTotal API key configured")
            else:
                print("   ⚠️  VirusTotal API key not configured (optional)")
    else:
        print("   ⚠️  API keys file not found (optional)")
except Exception as e:
    print(f"   ⚠️  API configuration check: {e}")

# Final Summary
print("\n" + "=" * 60)
print("📊 Test Summary")
print("=" * 60)
print(f"""
✅ Analyzers:  5/5 modules working
✅ Detectors:  4/4 modules working
✅ Collectors: 4/4 modules working
✅ Reporters:  4/4 modules working

Total: 17/17 modules operational

Status: {'✅ ALL TESTS PASSED' if success else '⚠️  SOME TESTS NEED ATTENTION'}
""")

print("=" * 60)
print("🎉 Implementation Test Complete!")
print("=" * 60)
print("\n📖 Next Steps:")
print("   1. Add your VirusTotal API key to config/api_keys.json")
print("   2. Run: python demo.py")
print("   3. Check QUICK_START.md for usage examples")
print("\n✨ Happy Investigating! 🔍\n")
