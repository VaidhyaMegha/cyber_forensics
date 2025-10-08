#!/usr/bin/env python3
"""
Netlas.io API Test Script

Quick test to analyze a domain using Netlas.io API.
Change the DOMAIN variable to analyze any domain.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.0.1
"""

import asyncio
import json
import logging
from analyzers.threat_intel import ThreatIntelligence

logging.basicConfig(level=logging.INFO)

async def test_netlas():
    """Test Netlas.io API integration."""
    
    # Load your API key from config
    try:
        with open('config/api_keys.json') as f:
            api_keys = json.load(f)
    except FileNotFoundError:
        print("❌ Error: config/api_keys.json not found!")
        print("Please create the file with your Netlas API key.")
        return
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON in config/api_keys.json")
        print("Please check the file syntax.")
        return
    
    # Configuration
    config = {
        'api_keys': api_keys,
        'timeouts': {'threat_intel': 60}
    }
    
    # ===============================================
    # CHANGE THIS DOMAIN TO ANALYZE ANY WEBSITE
    # ===============================================
    domain = "https://example.com/"
    
    print("=" * 70)
    print("🔍 Netlas.io Domain Analysis")
    print("=" * 70)
    print(f"\n📍 Target Domain: {domain}")
    print("⏳ Analyzing... (This may take 5-10 seconds)\n")
    
    # Initialize Threat Intelligence module
    threat_intel = ThreatIntelligence(config)
    
    # Analyze the domain
    result = await threat_intel.analyze_domain(domain)
    
    # Display Results
    print("=" * 70)
    print("📊 ANALYSIS RESULTS")
    print("=" * 70)
    
    if result.get('netlas', {}).get('available'):
        netlas_data = result['netlas']['data']
        print("\n🛡️  Netlas.io Analysis Details")
        print("=" * 70)
        print(json.dumps(netlas_data, indent=2))
    else:
        error = result.get('netlas', {}).get('error', 'Unknown error')
        print(f"\n❌ Netlas.io Error: {error}")

    print("\n" + "=" * 70)
    print("✨ Analysis Complete!")
    print("=" * 70)

if __name__ == "__main__":
    try:
        asyncio.run(test_netlas())
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
