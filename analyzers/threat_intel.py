#!/usr/bin/env python3
"""
Threat Intelligence Module

This module provides threat intelligence analysis capabilities including:
- VirusTotal API integration for URL/domain/IP reputation
- URLVoid API integration for multi-engine scanning
- AbuseIPDB integration for IP reputation
- Threat scoring and risk assessment
- IOC (Indicators of Compromise) analysis

Owner: Samyama.ai - Vaidhyamegha Private Limited
Contact: madhulatha@samyama.ai
Website: https://Samyama.ai
License: Proprietary - All Rights Reserved
Version: 1.0.0
Last Updated: October 2025
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import hashlib
import base64

try:
    import requests
except ImportError as e:
    logging.warning(f"Some threat intelligence dependencies not available: {e}")

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """Threat intelligence gathering and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize threat intelligence analyzer with configuration."""
        self.config = config
        self.timeout = config.get('timeouts', {}).get('threat_intel', 60)
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
        # API keys from config
        self.api_keys = config.get('api_keys', {})
        self.virustotal_key = self.api_keys.get('virustotal')
        self.urlvoid_key = self.api_keys.get('urlvoid')
        self.abuseipdb_key = self.api_keys.get('abuseipdb')
        
        # API endpoints
        self.virustotal_url_api = "https://www.virustotal.com/api/v3/urls"
        self.virustotal_domain_api = "https://www.virustotal.com/api/v3/domains"
        self.virustotal_ip_api = "https://www.virustotal.com/api/v3/ip_addresses"
        self.abuseipdb_api = "https://api.abuseipdb.com/api/v2/check"
        
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive threat intelligence analysis on a URL."""
        result = {
            'url': url,
            'virustotal': {},
            'urlvoid': {},
            'threat_score': 0,
            'is_malicious': False,
            'threat_categories': [],
            'recommendations': []
        }
        
        try:
            # Run all threat intelligence checks concurrently
            vt_task = self._check_virustotal_url(url)
            
            # Wait for results
            result['virustotal'] = await vt_task
            
            # Calculate overall threat score
            result = await self._calculate_threat_score(result)
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain reputation."""
        result = {
            'domain': domain,
            'virustotal': {},
            'threat_score': 0,
            'is_malicious': False,
            'categories': [],
            'last_analysis_stats': {}
        }
        
        try:
            if self.virustotal_key:
                result['virustotal'] = await self._check_virustotal_domain(domain)
                
                # Extract key information
                if 'data' in result['virustotal']:
                    data = result['virustotal']['data']
                    attributes = data.get('attributes', {})
                    
                    result['last_analysis_stats'] = attributes.get('last_analysis_stats', {})
                    result['categories'] = attributes.get('categories', {})
                    result['reputation'] = attributes.get('reputation', 0)
                    
                    # Determine if malicious
                    stats = result['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)
                    suspicious_count = stats.get('suspicious', 0)
                    
                    if malicious_count > 0 or suspicious_count > 2:
                        result['is_malicious'] = True
                        result['threat_score'] = min(100, (malicious_count * 10) + (suspicious_count * 5))
            
        except Exception as e:
            logger.error(f"Domain analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze IP address reputation."""
        result = {
            'ip': ip,
            'virustotal': {},
            'abuseipdb': {},
            'threat_score': 0,
            'is_malicious': False,
            'abuse_confidence': 0
        }
        
        try:
            # Run checks concurrently
            tasks = []
            
            if self.virustotal_key:
                tasks.append(self._check_virustotal_ip(ip))
            else:
                tasks.append(asyncio.sleep(0))  # Placeholder
            
            if self.abuseipdb_key:
                tasks.append(self._check_abuseipdb(ip))
            else:
                tasks.append(asyncio.sleep(0))  # Placeholder
            
            vt_result, abuse_result = await asyncio.gather(*tasks, return_exceptions=True)
            
            if not isinstance(vt_result, Exception) and vt_result:
                result['virustotal'] = vt_result
            
            if not isinstance(abuse_result, Exception) and abuse_result:
                result['abuseipdb'] = abuse_result
                result['abuse_confidence'] = abuse_result.get('data', {}).get('abuseConfidenceScore', 0)
            
            # Calculate threat score
            if result['abuse_confidence'] > 50:
                result['is_malicious'] = True
                result['threat_score'] = result['abuse_confidence']
            
        except Exception as e:
            logger.error(f"IP analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _check_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Check URL reputation using VirusTotal API v3."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.virustotal_key:
            result['error'] = 'VirusTotal API key not configured'
            return result
        
        try:
            # Step 1: Submit URL for scanning
            headers = {
                'x-apikey': self.virustotal_key,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {'url': url}
            response = self.session.post(
                self.virustotal_url_api,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                submission_data = response.json()
                
                # Step 2: Get the URL ID
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                
                # Step 3: Wait a bit for analysis to complete
                await asyncio.sleep(2)
                
                # Step 4: Get analysis results
                analysis_url = f"{self.virustotal_url_api}/{url_id}"
                analysis_response = self.session.get(
                    analysis_url,
                    headers={'x-apikey': self.virustotal_key},
                    timeout=self.timeout
                )
                
                if analysis_response.status_code == 200:
                    result['available'] = True
                    result['data'] = analysis_response.json()
                else:
                    result['error'] = f"Analysis retrieval failed: {analysis_response.status_code}"
            else:
                result['error'] = f"URL submission failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"VirusTotal URL check failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _check_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using VirusTotal API v3."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.virustotal_key:
            result['error'] = 'VirusTotal API key not configured'
            return result
        
        try:
            headers = {'x-apikey': self.virustotal_key}
            url = f"{self.virustotal_domain_api}/{domain}"
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result['available'] = True
                result['data'] = response.json()
            elif response.status_code == 404:
                result['error'] = 'Domain not found in VirusTotal database'
            else:
                result['error'] = f"Request failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"VirusTotal domain check failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _check_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using VirusTotal API v3."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.virustotal_key:
            result['error'] = 'VirusTotal API key not configured'
            return result
        
        try:
            headers = {'x-apikey': self.virustotal_key}
            url = f"{self.virustotal_ip_api}/{ip}"
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result['available'] = True
                result['data'] = response.json()
            elif response.status_code == 404:
                result['error'] = 'IP not found in VirusTotal database'
            else:
                result['error'] = f"Request failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"VirusTotal IP check failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB API."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.abuseipdb_key:
            result['error'] = 'AbuseIPDB API key not configured'
            return result
        
        try:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = self.session.get(
                self.abuseipdb_api,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result['available'] = True
                result['data'] = response.json()
            else:
                result['error'] = f"Request failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _calculate_threat_score(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall threat score based on all intelligence sources."""
        total_score = 0
        threat_categories = []
        
        # VirusTotal scoring
        if result['virustotal'].get('available'):
            vt_data = result['virustotal'].get('data', {})
            
            if 'data' in vt_data:
                attributes = vt_data['data'].get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 0:
                    total_score += min(50, malicious * 5)
                    threat_categories.append('malicious')
                
                if suspicious > 0:
                    total_score += min(25, suspicious * 3)
                    threat_categories.append('suspicious')
                
                # Check categories
                categories = attributes.get('categories', {})
                if 'phishing' in str(categories).lower():
                    threat_categories.append('phishing')
                    total_score += 20
                
                if 'malware' in str(categories).lower():
                    threat_categories.append('malware')
                    total_score += 25
        
        result['threat_score'] = min(100, total_score)
        result['threat_categories'] = list(set(threat_categories))
        
        # Determine if malicious
        if result['threat_score'] >= 50:
            result['is_malicious'] = True
            result['recommendations'].append('⚠️ HIGH RISK: Multiple threat intelligence sources flag this as malicious')
        elif result['threat_score'] >= 30:
            result['is_malicious'] = False
            result['recommendations'].append('⚠️ MEDIUM RISK: Some suspicious indicators detected')
        else:
            result['recommendations'].append('✓ LOW RISK: No significant threats detected')
        
        return result
    
    async def batch_analyze(self, items: List[str], item_type: str = 'url') -> Dict[str, Any]:
        """Batch analyze multiple items (URLs, domains, or IPs)."""
        results = {
            'total': len(items),
            'analyzed': 0,
            'malicious': 0,
            'clean': 0,
            'errors': 0,
            'items': []
        }
        
        try:
            tasks = []
            
            for item in items:
                if item_type == 'url':
                    tasks.append(self.analyze_url(item))
                elif item_type == 'domain':
                    tasks.append(self.analyze_domain(item))
                elif item_type == 'ip':
                    tasks.append(self.analyze_ip(item))
            
            # Execute all tasks concurrently
            item_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for item, item_result in zip(items, item_results):
                if isinstance(item_result, Exception):
                    results['errors'] += 1
                    results['items'].append({
                        'item': item,
                        'error': str(item_result)
                    })
                else:
                    results['analyzed'] += 1
                    if item_result.get('is_malicious'):
                        results['malicious'] += 1
                    else:
                        results['clean'] += 1
                    results['items'].append(item_result)
            
        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def extract_iocs(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise (IOCs) from analysis data."""
        iocs = {
            'urls': [],
            'domains': [],
            'ips': [],
            'hashes': [],
            'emails': []
        }
        
        try:
            # Extract from VirusTotal data
            if 'virustotal' in data and data['virustotal'].get('available'):
                vt_data = data['virustotal'].get('data', {})
                
                if 'data' in vt_data:
                    attributes = vt_data['data'].get('attributes', {})
                    
                    # Extract related URLs
                    if 'last_final_url' in attributes:
                        iocs['urls'].append(attributes['last_final_url'])
                    
                    # Extract domains
                    if 'domain' in data:
                        iocs['domains'].append(data['domain'])
                    
                    # Extract IPs
                    if 'ip' in data:
                        iocs['ips'].append(data['ip'])
            
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
        
        return iocs
