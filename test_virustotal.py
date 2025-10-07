#!/usr/bin/env python3
"""
VirusTotal API Test Script

Quick test to analyze a URL using VirusTotal API.
Change the URL variable to analyze any website.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.0.0
"""

import asyncio
import json
from analyzers.threat_intel import ThreatIntelligence

async def test_virustotal():
    """Test VirusTotal API integration."""
    
    # Load your API key from config
    try:
        with open('config/api_keys.json') as f:
            api_keys = json.load(f)
    except FileNotFoundError:
        print("❌ Error: config/api_keys.json not found!")
        print("Please create the file with your VirusTotal API key.")
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
    
    # ============================================
    # CHANGE THIS URL TO ANALYZE ANY WEBSITE
    # ============================================
    url = "https://www.google.com/"
    
    # You can also test with these:
    # url = "http://neverssl.com"
    # url = "https://badssl.com"
    # url = "https://www.paypal.com"
    
    print("=" * 70)
    print("🔍 VirusTotal URL Analysis")
    print("=" * 70)
    print(f"\n📍 Target URL: {url}")
    print("⏳ Analyzing... (This may take 5-10 seconds)\n")
    
    # Initialize Threat Intelligence module
    threat_intel = ThreatIntelligence(config)
    
    # Analyze the URL
    result = await threat_intel.analyze_url(url)
    
    # Display Results
    print("=" * 70)
    print("📊 ANALYSIS RESULTS")
    print("=" * 70)
    
    print(f"\n🌐 URL: {result['url']}")
    print(f"📈 Threat Score: {result['threat_score']}/100")
    print(f"⚠️  Is Malicious: {'YES ⚠️' if result['is_malicious'] else 'NO ✅'}")
    
    if result['threat_categories']:
        print(f"🏷️  Threat Categories: {', '.join(result['threat_categories'])}")
    
    print(f"\n💡 Recommendations:")
    for rec in result['recommendations']:
        print(f"   {rec}")
    
    # VirusTotal Detailed Results
    print("\n" + "=" * 70)
    print("🛡️  VirusTotal Analysis Details")
    print("=" * 70)
    
    vt_result = result['virustotal']
    
    if vt_result.get('available'):
        vt_data = vt_result.get('data', {})
        
        if 'data' in vt_data:
            attributes = vt_data['data'].get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            print(f"\n📊 Detection Statistics:")
            print(f"   🔴 Malicious:   {stats.get('malicious', 0)} engines")
            print(f"   🟡 Suspicious:  {stats.get('suspicious', 0)} engines")
            print(f"   🟢 Clean:       {stats.get('harmless', 0)} engines")
            print(f"   ⚪ Undetected:  {stats.get('undetected', 0)} engines")
            
            total = sum(stats.values())
            print(f"   📝 Total:       {total} engines scanned")
            
            # Categories
            categories = attributes.get('categories', {})
            if categories:
                print(f"\n🏷️  Categories: {categories}")
            
            # Reputation
            reputation = attributes.get('reputation', 0)
            print(f"\n⭐ Reputation Score: {reputation}")
            
            # Last analysis date
            last_analysis = attributes.get('last_analysis_date')
            if last_analysis:
                from datetime import datetime
                date = datetime.fromtimestamp(last_analysis)
                print(f"📅 Last Analyzed: {date.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print("\n⏳ Analysis in progress or data not yet available.")
            print("   Try running the script again in a few seconds.")
    else:
        error = vt_result.get('error', 'Unknown error')
        print(f"\n❌ VirusTotal Error: {error}")
        
        if 'API key not configured' in error:
            print("\n💡 Solution:")
            print("   1. Make sure config/api_keys.json exists")
            print("   2. Add your VirusTotal API key to the file")
            print("   3. Get a free key at: https://www.virustotal.com/gui/join-us")
    
    # Save results to file
    print("\n" + "=" * 70)
    print("💾 Saving Results")
    print("=" * 70)
    
    # Create tmp directory if it doesn't exist
    import os
    os.makedirs('tmp', exist_ok=True)
    
    # Generate safe filename
    safe_url = url.replace('://', '_').replace('/', '_').replace('?', '_').replace('&', '_')
    if len(safe_url) > 100:  # Limit filename length
        safe_url = safe_url[:100]
    
    output_file = f"tmp/virustotal_analysis_{safe_url}.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"✅ Results saved to: {output_file}")
    except Exception as e:
        print(f"⚠️  Could not save results: {e}")
    
    print("\n" + "=" * 70)
    print("✨ Analysis Complete!")
    print("=" * 70)
    print("\n💡 Tips:")
    print("   - Change the 'url' variable in this script to analyze different sites")
    print("   - Check the JSON file for detailed results")
    print("   - Run 'python demo.py' for full forensic analysis\n")


if __name__ == "__main__":
    try:
        asyncio.run(test_virustotal())
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nPlease check:")
        print("  1. config/api_keys.json exists and has valid JSON")
        print("  2. Your VirusTotal API key is correct")
        print("  3. You have internet connection")
