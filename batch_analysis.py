#!/usr/bin/env python3
"""
Batch URL Analysis Script

Analyze multiple URLs at once using VirusTotal API.
Add your URLs to the list below and run the script.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.0.0
"""

import asyncio
import json
from datetime import datetime
from analyzers.threat_intel import ThreatIntelligence

async def batch_analyze_urls():
    """Analyze multiple URLs in batch."""
    
    # Load your API key
    try:
        with open('config/api_keys.json') as f:
            api_keys = json.load(f)
    except FileNotFoundError:
        print("❌ Error: config/api_keys.json not found!")
        return
    
    # Configuration
    config = {
        'api_keys': api_keys,
        'timeouts': {'threat_intel': 60}
    }
    
    # ============================================
    # ADD YOUR URLs HERE (one per line)
    # ============================================
    urls_to_analyze = [
        "https://www.google.com",
        "https://www.facebook.com",
        "https://temp-mail.org/en/",
        "http://neverssl.com",
        "https://www.paypal.com",
        # Add more URLs here...
    ]
    
    print("=" * 80)
    print("🔍 BATCH URL ANALYSIS WITH VIRUSTOTAL")
    print("=" * 80)
    print(f"\n📊 Total URLs to analyze: {len(urls_to_analyze)}")
    print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Initialize Threat Intelligence
    threat_intel = ThreatIntelligence(config)
    
    # Store all results
    all_results = []
    
    # Analyze each URL
    for index, url in enumerate(urls_to_analyze, 1):
        print("=" * 80)
        print(f"🔍 Analyzing URL {index}/{len(urls_to_analyze)}")
        print("=" * 80)
        print(f"📍 URL: {url}")
        print("⏳ Analyzing...\n")
        
        try:
            # Analyze the URL
            result = await threat_intel.analyze_url(url)
            
            # Display quick summary
            print(f"✅ Analysis Complete!")
            print(f"   Threat Score: {result['threat_score']}/100")
            print(f"   Is Malicious: {'YES ⚠️' if result['is_malicious'] else 'NO ✅'}")
            print(f"   Status: {result['recommendations'][0] if result['recommendations'] else 'N/A'}")
            
            # Show VirusTotal stats if available
            if result['virustotal'].get('available'):
                vt_data = result['virustotal'].get('data', {})
                if 'data' in vt_data:
                    stats = vt_data['data'].get('attributes', {}).get('last_analysis_stats', {})
                    print(f"   VirusTotal: 🔴 {stats.get('malicious', 0)} malicious, "
                          f"🟡 {stats.get('suspicious', 0)} suspicious, "
                          f"🟢 {stats.get('harmless', 0)} clean")
            
            # Add to results
            all_results.append({
                'url': url,
                'threat_score': result['threat_score'],
                'is_malicious': result['is_malicious'],
                'analysis': result
            })
            
            print()
            
            # Add delay between requests to respect API rate limits
            if index < len(urls_to_analyze):
                print("⏸️  Waiting 15 seconds before next request (API rate limit)...\n")
                await asyncio.sleep(15)  # VirusTotal free tier: 4 requests/minute
        
        except Exception as e:
            print(f"❌ Error analyzing {url}: {e}\n")
            all_results.append({
                'url': url,
                'error': str(e)
            })
    
    # Generate Summary Report
    print("\n" + "=" * 80)
    print("📊 BATCH ANALYSIS SUMMARY")
    print("=" * 80)
    
    total = len(urls_to_analyze)
    analyzed = len([r for r in all_results if 'threat_score' in r])
    malicious = len([r for r in all_results if r.get('is_malicious')])
    clean = analyzed - malicious
    errors = len([r for r in all_results if 'error' in r])
    
    print(f"\n📈 Statistics:")
    print(f"   Total URLs:     {total}")
    print(f"   Analyzed:       {analyzed}")
    print(f"   🔴 Malicious:   {malicious}")
    print(f"   🟢 Clean:       {clean}")
    print(f"   ❌ Errors:      {errors}")
    
    # Show detailed results table
    print(f"\n📋 Detailed Results:")
    print("-" * 80)
    print(f"{'URL':<50} {'Score':<10} {'Status':<15}")
    print("-" * 80)
    
    for result in all_results:
        url = result['url'][:47] + '...' if len(result['url']) > 50 else result['url']
        
        if 'error' in result:
            print(f"{url:<50} {'ERROR':<10} {'Failed':<15}")
        else:
            score = f"{result['threat_score']}/100"
            status = "MALICIOUS ⚠️" if result['is_malicious'] else "CLEAN ✅"
            print(f"{url:<50} {score:<10} {status:<15}")
    
    print("-" * 80)
    
    # Save results to JSON file
    import os
    os.makedirs('tmp', exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"tmp/batch_analysis_{timestamp}.json"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'analysis_date': datetime.now().isoformat(),
                'total_urls': total,
                'statistics': {
                    'analyzed': analyzed,
                    'malicious': malicious,
                    'clean': clean,
                    'errors': errors
                },
                'results': all_results
            }, f, indent=2, default=str)
        
        print(f"\n💾 Full results saved to: {output_file}")
    except Exception as e:
        print(f"\n⚠️  Could not save results: {e}")
    
    print("\n" + "=" * 80)
    print("✨ Batch Analysis Complete!")
    print("=" * 80)
    print(f"\n⏰ Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n💡 Tips:")
    print("   - Edit the 'urls_to_analyze' list in this script to add more URLs")
    print("   - Free VirusTotal API: 4 requests/minute (script adds 15s delay)")
    print("   - Check the JSON file for complete analysis data\n")


if __name__ == "__main__":
    try:
        asyncio.run(batch_analyze_urls())
    except KeyboardInterrupt:
        print("\n\n⚠️  Batch analysis interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
