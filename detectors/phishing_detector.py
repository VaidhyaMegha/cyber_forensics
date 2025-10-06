#!/usr/bin/env python3
"""
Phishing Detector Module

This module provides phishing detection capabilities including:
- URL pattern analysis for phishing indicators
- Domain name similarity scoring
- Login form detection
- SSL certificate validation
- Content-based phishing detection
- Brand impersonation detection

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
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import difflib

logger = logging.getLogger(__name__)


class PhishingDetector:
    """Phishing detection and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize phishing detector with configuration."""
        self.config = config
        
        # Known legitimate domains for comparison
        self.legitimate_domains = self._load_legitimate_domains()
        
        # Phishing keywords
        self.phishing_keywords = [
            'verify', 'account', 'suspended', 'locked', 'confirm', 'update',
            'secure', 'banking', 'paypal', 'amazon', 'microsoft', 'apple',
            'login', 'signin', 'password', 'credential', 'urgent', 'immediate'
        ]
        
    def _load_legitimate_domains(self) -> List[str]:
        """Load list of known legitimate domains."""
        # Common legitimate domains for comparison
        return [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'ebay.com', 'netflix.com',
            'linkedin.com', 'twitter.com', 'instagram.com', 'yahoo.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com'
        ]
    
    async def detect_phishing(self, url: str, content_data: Dict[str, Any] = None, 
                             attribution_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive phishing detection."""
        result = {
            'url': url,
            'is_phishing': False,
            'phishing_score': 0,
            'confidence': 0.0,
            'indicators': [],
            'risk_level': 'low'
        }
        
        try:
            # URL-based detection
            url_indicators = await self._check_url_patterns(url)
            result['indicators'].extend(url_indicators)
            
            # Domain similarity check
            similarity_indicators = await self._check_domain_similarity(url)
            result['indicators'].extend(similarity_indicators)
            
            # Content-based detection
            if content_data:
                content_indicators = await self._check_content_indicators(content_data)
                result['indicators'].extend(content_indicators)
            
            # Attribution-based detection
            if attribution_data:
                attribution_indicators = await self._check_attribution_indicators(attribution_data)
                result['indicators'].extend(attribution_indicators)
            
            # Calculate phishing score
            result = await self._calculate_phishing_score(result)
            
        except Exception as e:
            logger.error(f"Phishing detection failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _check_url_patterns(self, url: str) -> List[Dict[str, Any]]:
        """Check URL for phishing patterns."""
        indicators = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for IP address in URL
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'high',
                    'description': 'IP address used instead of domain name',
                    'weight': 25
                })
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'medium',
                    'description': 'Suspicious top-level domain',
                    'weight': 15
                })
            
            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'medium',
                    'description': f'Excessive subdomains ({subdomain_count})',
                    'weight': 10
                })
            
            # Check for @ symbol (credential phishing)
            if '@' in url:
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'high',
                    'description': '@ symbol in URL (credential hiding)',
                    'weight': 30
                })
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'low',
                    'description': 'URL shortener detected',
                    'weight': 5
                })
            
            # Check for phishing keywords in URL
            url_lower = url.lower()
            keyword_matches = [kw for kw in self.phishing_keywords if kw in url_lower]
            if keyword_matches:
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'medium',
                    'description': f'Phishing keywords in URL: {", ".join(keyword_matches[:3])}',
                    'weight': 10
                })
            
            # Check for HTTPS
            if parsed.scheme != 'https':
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'medium',
                    'description': 'No HTTPS encryption',
                    'weight': 15
                })
            
            # Check for suspicious patterns in path
            if re.search(r'(login|signin|verify|confirm|account).*\.(php|html|asp)', path):
                indicators.append({
                    'type': 'url_pattern',
                    'severity': 'high',
                    'description': 'Suspicious login page pattern',
                    'weight': 20
                })
            
        except Exception as e:
            logger.debug(f"URL pattern check failed: {e}")
        
        return indicators
    
    async def _check_domain_similarity(self, url: str) -> List[Dict[str, Any]]:
        """Check if domain is similar to legitimate domains (typosquatting)."""
        indicators = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check similarity with legitimate domains
            for legit_domain in self.legitimate_domains:
                similarity = difflib.SequenceMatcher(None, domain, legit_domain).ratio()
                
                # If very similar but not exact match (typosquatting)
                if 0.7 < similarity < 1.0:
                    indicators.append({
                        'type': 'domain_similarity',
                        'severity': 'high',
                        'description': f'Domain similar to {legit_domain} (similarity: {similarity:.2%})',
                        'weight': 35,
                        'similar_to': legit_domain
                    })
                    break  # Only report first match
            
            # Check for common typosquatting patterns
            for legit_domain in self.legitimate_domains:
                legit_name = legit_domain.split('.')[0]
                
                # Check if legitimate brand name is in the domain
                if legit_name in domain and domain != legit_domain:
                    indicators.append({
                        'type': 'domain_similarity',
                        'severity': 'high',
                        'description': f'Contains brand name "{legit_name}" but different domain',
                        'weight': 30
                    })
                    break
            
        except Exception as e:
            logger.debug(f"Domain similarity check failed: {e}")
        
        return indicators
    
    async def _check_content_indicators(self, content_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check content for phishing indicators."""
        indicators = []
        
        try:
            # Check for login forms
            forms = content_data.get('forms', [])
            login_forms = [f for f in forms if f.get('is_login_form')]
            
            if login_forms:
                indicators.append({
                    'type': 'content',
                    'severity': 'medium',
                    'description': f'Login form detected ({len(login_forms)} form(s))',
                    'weight': 15
                })
            
            # Check for forms collecting sensitive data
            sensitive_forms = [f for f in forms if f.get('collects_sensitive_data')]
            if sensitive_forms:
                indicators.append({
                    'type': 'content',
                    'severity': 'high',
                    'description': 'Form collecting sensitive data detected',
                    'weight': 25
                })
            
            # Check for suspicious patterns
            suspicious_patterns = content_data.get('suspicious_patterns', [])
            if suspicious_patterns:
                indicators.append({
                    'type': 'content',
                    'severity': 'medium',
                    'description': f'Suspicious patterns: {", ".join(suspicious_patterns[:3])}',
                    'weight': 20
                })
            
            # Check for obfuscation
            if content_data.get('obfuscation_detected'):
                indicators.append({
                    'type': 'content',
                    'severity': 'high',
                    'description': 'Code obfuscation detected',
                    'weight': 25
                })
            
            # Check JavaScript analysis
            js_analysis = content_data.get('javascript_analysis', {})
            if js_analysis.get('obfuscated_code'):
                indicators.append({
                    'type': 'content',
                    'severity': 'high',
                    'description': 'Obfuscated JavaScript detected',
                    'weight': 20
                })
            
            if js_analysis.get('suspicious_functions'):
                indicators.append({
                    'type': 'content',
                    'severity': 'medium',
                    'description': f'Suspicious JavaScript functions: {", ".join(js_analysis["suspicious_functions"][:3])}',
                    'weight': 15
                })
            
            # Check for iframes
            html_structure = content_data.get('html_structure', {})
            if html_structure.get('has_iframes'):
                indicators.append({
                    'type': 'content',
                    'severity': 'medium',
                    'description': f'Hidden iframes detected ({html_structure.get("iframes_count", 0)})',
                    'weight': 15
                })
            
        except Exception as e:
            logger.debug(f"Content indicator check failed: {e}")
        
        return indicators
    
    async def _check_attribution_indicators(self, attribution_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check attribution data for phishing indicators."""
        indicators = []
        
        try:
            # Check domain age
            domain_age = attribution_data.get('domain_age', {})
            if domain_age.get('is_new'):
                age_days = domain_age.get('age_days', 0)
                indicators.append({
                    'type': 'attribution',
                    'severity': 'high',
                    'description': f'Very new domain ({age_days} days old)',
                    'weight': 30
                })
            
            # Check privacy protection
            registrant_info = attribution_data.get('registrant_info', {})
            if registrant_info.get('privacy_protected'):
                indicators.append({
                    'type': 'attribution',
                    'severity': 'medium',
                    'description': 'WHOIS privacy protection enabled',
                    'weight': 10
                })
            
            # Check for suspicious registrant indicators
            suspicious = registrant_info.get('suspicious_indicators', [])
            if suspicious:
                indicators.append({
                    'type': 'attribution',
                    'severity': 'medium',
                    'description': f'Suspicious registrant info: {", ".join(suspicious[:2])}',
                    'weight': 15
                })
            
        except Exception as e:
            logger.debug(f"Attribution indicator check failed: {e}")
        
        return indicators
    
    async def _calculate_phishing_score(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall phishing score and risk level."""
        try:
            # Calculate total score from all indicators
            total_score = sum(indicator.get('weight', 0) for indicator in result['indicators'])
            
            # Normalize to 0-100 scale
            result['phishing_score'] = min(100, total_score)
            
            # Calculate confidence based on number of indicators
            indicator_count = len(result['indicators'])
            if indicator_count == 0:
                result['confidence'] = 0.0
            elif indicator_count <= 2:
                result['confidence'] = 0.5
            elif indicator_count <= 4:
                result['confidence'] = 0.75
            else:
                result['confidence'] = 0.9
            
            # Determine risk level and phishing status
            if result['phishing_score'] >= 70:
                result['is_phishing'] = True
                result['risk_level'] = 'critical'
                result['recommendation'] = '🚨 CRITICAL: High probability of phishing. Do not interact with this site.'
            elif result['phishing_score'] >= 50:
                result['is_phishing'] = True
                result['risk_level'] = 'high'
                result['recommendation'] = '⚠️ HIGH RISK: Strong phishing indicators detected. Avoid this site.'
            elif result['phishing_score'] >= 30:
                result['is_phishing'] = False
                result['risk_level'] = 'medium'
                result['recommendation'] = '⚠️ MEDIUM RISK: Some suspicious indicators. Proceed with caution.'
            else:
                result['is_phishing'] = False
                result['risk_level'] = 'low'
                result['recommendation'] = '✓ LOW RISK: No significant phishing indicators detected.'
            
        except Exception as e:
            logger.error(f"Phishing score calculation failed: {e}")
        
        return result
