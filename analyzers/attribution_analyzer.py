#!/usr/bin/env python3
"""
Attribution Analyzer Module

This module provides attribution analysis capabilities including:
- WHOIS data collection and analysis
- Domain age and history analysis
- Similar domain detection
- Contact information extraction
- Infrastructure mapping
- Threat actor profiling

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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import re

try:
    import requests
    import whois
except ImportError as e:
    logging.warning(f"Some attribution analysis dependencies not available: {e}")

logger = logging.getLogger(__name__)


class AttributionAnalyzer:
    """Attribution and intelligence analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize attribution analyzer with configuration."""
        self.config = config
        self.timeout = config.get('timeouts', {}).get('attribution', 45)
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive attribution analysis on a domain."""
        result = {
            'domain': domain,
            'whois_data': {},
            'domain_age': {},
            'similar_domains': [],
            'registrant_info': {},
            'risk_indicators': []
        }
        
        try:
            # Run attribution analysis
            result['whois_data'] = await self._get_whois_data(domain)
            result['domain_age'] = await self._calculate_domain_age(result['whois_data'])
            result['similar_domains'] = await self._find_similar_domains(domain)
            result['registrant_info'] = await self._analyze_registrant(result['whois_data'])
            result['risk_indicators'] = await self._assess_risk_indicators(result)
            
        except Exception as e:
            logger.error(f"Attribution analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _get_whois_data(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS data for domain."""
        whois_result = {
            'available': False,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant': {},
            'admin': {},
            'tech': {},
            'status': []
        }
        
        try:
            w = whois.whois(domain)
            
            if w:
                whois_result['available'] = True
                whois_result['registrar'] = w.registrar
                
                # Handle dates (can be list or single value)
                if w.creation_date:
                    creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    whois_result['creation_date'] = creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date)
                
                if w.expiration_date:
                    expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                    whois_result['expiration_date'] = expiration_date.isoformat() if hasattr(expiration_date, 'isoformat') else str(expiration_date)
                
                if w.updated_date:
                    updated_date = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date
                    whois_result['updated_date'] = updated_date.isoformat() if hasattr(updated_date, 'isoformat') else str(updated_date)
                
                # Name servers
                if w.name_servers:
                    whois_result['name_servers'] = list(w.name_servers) if isinstance(w.name_servers, (list, tuple)) else [w.name_servers]
                
                # Status
                if w.status:
                    whois_result['status'] = list(w.status) if isinstance(w.status, (list, tuple)) else [w.status]
                
                # Contact information
                if hasattr(w, 'emails') and w.emails:
                    emails = list(w.emails) if isinstance(w.emails, (list, tuple)) else [w.emails]
                    whois_result['registrant']['email'] = emails[0] if emails else None
                
                if hasattr(w, 'org') and w.org:
                    whois_result['registrant']['organization'] = w.org
                
                if hasattr(w, 'country') and w.country:
                    whois_result['registrant']['country'] = w.country
                
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            whois_result['error'] = str(e)
        
        return whois_result
    
    async def _calculate_domain_age(self, whois_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate domain age and related metrics."""
        age_info = {
            'age_days': None,
            'age_years': None,
            'is_new': False,
            'is_recently_updated': False,
            'days_until_expiration': None
        }
        
        try:
            if whois_data.get('creation_date'):
                creation_date_str = whois_data['creation_date']
                creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                
                now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.now()
                age = now - creation_date
                
                age_info['age_days'] = age.days
                age_info['age_years'] = round(age.days / 365.25, 2)
                
                # Domain is considered new if less than 6 months old
                age_info['is_new'] = age.days < 180
            
            if whois_data.get('updated_date'):
                updated_date_str = whois_data['updated_date']
                updated_date = datetime.fromisoformat(updated_date_str.replace('Z', '+00:00'))
                
                now = datetime.now(updated_date.tzinfo) if updated_date.tzinfo else datetime.now()
                days_since_update = (now - updated_date).days
                
                # Recently updated if within last 30 days
                age_info['is_recently_updated'] = days_since_update < 30
            
            if whois_data.get('expiration_date'):
                expiration_date_str = whois_data['expiration_date']
                expiration_date = datetime.fromisoformat(expiration_date_str.replace('Z', '+00:00'))
                
                now = datetime.now(expiration_date.tzinfo) if expiration_date.tzinfo else datetime.now()
                days_until_expiration = (expiration_date - now).days
                
                age_info['days_until_expiration'] = days_until_expiration
                age_info['expiring_soon'] = days_until_expiration < 30
            
        except Exception as e:
            logger.debug(f"Domain age calculation failed: {e}")
        
        return age_info
    
    async def _find_similar_domains(self, domain: str) -> List[str]:
        """Find similar domains (typosquatting, homograph attacks)."""
        similar_domains = []
        
        try:
            # Extract domain parts
            parts = domain.split('.')
            if len(parts) < 2:
                return similar_domains
            
            domain_name = parts[0]
            tld = '.'.join(parts[1:])
            
            # Common typosquatting patterns
            typo_patterns = []
            
            # Character omission
            for i in range(len(domain_name)):
                typo = domain_name[:i] + domain_name[i+1:]
                if len(typo) > 2:
                    typo_patterns.append(f"{typo}.{tld}")
            
            # Character repetition
            for i in range(len(domain_name)):
                typo = domain_name[:i] + domain_name[i] + domain_name[i:]
                typo_patterns.append(f"{typo}.{tld}")
            
            # Common character substitutions
            substitutions = {
                'a': ['@', '4'],
                'e': ['3'],
                'i': ['1', 'l'],
                'o': ['0'],
                's': ['5', '$'],
                'l': ['1', 'i']
            }
            
            for char, replacements in substitutions.items():
                if char in domain_name:
                    for replacement in replacements:
                        typo = domain_name.replace(char, replacement, 1)
                        typo_patterns.append(f"{typo}.{tld}")
            
            # Common TLD variations
            common_tlds = ['com', 'net', 'org', 'info', 'biz', 'co']
            for alt_tld in common_tlds:
                if alt_tld != tld:
                    typo_patterns.append(f"{domain_name}.{alt_tld}")
            
            # Limit to first 20 patterns
            similar_domains = list(set(typo_patterns))[:20]
            
        except Exception as e:
            logger.debug(f"Similar domain detection failed: {e}")
        
        return similar_domains
    
    async def _analyze_registrant(self, whois_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze registrant information."""
        registrant_analysis = {
            'privacy_protected': False,
            'suspicious_indicators': [],
            'contact_info_available': False
        }
        
        try:
            registrant = whois_data.get('registrant', {})
            
            # Check for privacy protection
            if whois_data.get('registrar'):
                registrar = whois_data['registrar'].lower()
                privacy_keywords = ['privacy', 'protected', 'proxy', 'whoisguard', 'domains by proxy']
                registrant_analysis['privacy_protected'] = any(keyword in registrar for keyword in privacy_keywords)
            
            # Check if contact info is available
            if registrant.get('email') or registrant.get('organization'):
                registrant_analysis['contact_info_available'] = True
            
            # Suspicious indicators
            if registrant.get('email'):
                email = registrant['email'].lower()
                
                # Check for suspicious email patterns
                if any(keyword in email for keyword in ['temp', 'disposable', 'fake', 'test']):
                    registrant_analysis['suspicious_indicators'].append('Suspicious email address')
                
                # Check for free email providers
                free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
                if any(provider in email for provider in free_providers):
                    registrant_analysis['suspicious_indicators'].append('Free email provider used')
            
            # Check organization
            if registrant.get('organization'):
                org = registrant['organization'].lower()
                if any(keyword in org for keyword in ['private', 'redacted', 'n/a', 'none']):
                    registrant_analysis['suspicious_indicators'].append('Redacted organization info')
            
        except Exception as e:
            logger.debug(f"Registrant analysis failed: {e}")
        
        return registrant_analysis
    
    async def _assess_risk_indicators(self, attribution_data: Dict[str, Any]) -> List[str]:
        """Assess risk indicators based on attribution data."""
        risk_indicators = []
        
        try:
            # Check domain age
            domain_age = attribution_data.get('domain_age', {})
            if domain_age.get('is_new'):
                risk_indicators.append(f"⚠️ New domain (only {domain_age.get('age_days', 0)} days old)")
            
            # Check for privacy protection
            registrant_info = attribution_data.get('registrant_info', {})
            if registrant_info.get('privacy_protected'):
                risk_indicators.append("Privacy protection enabled (common in phishing)")
            
            # Check for suspicious registrant indicators
            suspicious = registrant_info.get('suspicious_indicators', [])
            risk_indicators.extend(suspicious)
            
            # Check expiration
            if domain_age.get('expiring_soon'):
                risk_indicators.append("Domain expiring soon")
            
            # Check WHOIS availability
            whois_data = attribution_data.get('whois_data', {})
            if not whois_data.get('available'):
                risk_indicators.append("WHOIS data not available")
            
        except Exception as e:
            logger.debug(f"Risk assessment failed: {e}")
        
        return risk_indicators
    
    async def get_domain_history(self, domain: str) -> Dict[str, Any]:
        """Get historical information about domain."""
        history = {
            'domain': domain,
            'historical_ips': [],
            'dns_history': [],
            'archive_snapshots': 0
        }
        
        try:
            # This would integrate with services like SecurityTrails, PassiveTotal, etc.
            # For now, return basic structure
            logger.info(f"Domain history lookup for {domain} - requires external API integration")
            
        except Exception as e:
            logger.error(f"Domain history lookup failed: {e}")
            history['error'] = str(e)
        
        return history
