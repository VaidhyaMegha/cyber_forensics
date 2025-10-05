#!/usr/bin/env python3
"""
Content Analyzer Module

This module provides content analysis capabilities including:
- HTML structure analysis
- JavaScript behavior analysis
- Resource enumeration (images, scripts, stylesheets)
- Content similarity scoring
- Obfuscation detection
- Form analysis (login forms, data collection points)

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
from urllib.parse import urlparse, urljoin
import hashlib

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    logging.warning(f"Some content analysis dependencies not available: {e}")

logger = logging.getLogger(__name__)


class ContentAnalyzer:
    """Content analysis and structure examination."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize content analyzer with configuration."""
        self.config = config
        self.timeout = config.get('timeouts', {}).get('content', 45)
        self.session = requests.Session()
        self.session.timeout = self.timeout
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        })
        
    async def analyze_content(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive content analysis."""
        result = {
            'url': url,
            'html_structure': {},
            'javascript_analysis': {},
            'forms': [],
            'resources': {},
            'obfuscation_detected': False,
            'suspicious_patterns': []
        }
        
        try:
            # Fetch page content
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            html_content = response.text
            
            # Parse HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Run analysis tasks
            result['html_structure'] = await self._analyze_html_structure(soup, html_content)
            result['javascript_analysis'] = await self._analyze_javascript(soup, url)
            result['forms'] = await self._analyze_forms(soup)
            result['resources'] = await self._extract_resources(soup, url)
            result['obfuscation_detected'] = await self._detect_obfuscation(html_content)
            result['suspicious_patterns'] = await self._detect_suspicious_patterns(html_content)
            
        except Exception as e:
            logger.error(f"Content analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _analyze_html_structure(self, soup: BeautifulSoup, html: str) -> Dict[str, Any]:
        """Analyze HTML structure and metadata."""
        structure = {
            'title': None,
            'meta_tags': [],
            'links_count': 0,
            'images_count': 0,
            'scripts_count': 0,
            'forms_count': 0,
            'iframes_count': 0,
            'total_size': len(html),
            'encoding': None
        }
        
        try:
            # Title
            if soup.title:
                structure['title'] = soup.title.string
            
            # Meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                meta_info = {}
                if meta.get('name'):
                    meta_info['name'] = meta.get('name')
                if meta.get('content'):
                    meta_info['content'] = meta.get('content')
                if meta.get('property'):
                    meta_info['property'] = meta.get('property')
                if meta_info:
                    structure['meta_tags'].append(meta_info)
            
            # Count elements
            structure['links_count'] = len(soup.find_all('a'))
            structure['images_count'] = len(soup.find_all('img'))
            structure['scripts_count'] = len(soup.find_all('script'))
            structure['forms_count'] = len(soup.find_all('form'))
            structure['iframes_count'] = len(soup.find_all('iframe'))
            
            # Check for suspicious iframes
            if structure['iframes_count'] > 0:
                structure['has_iframes'] = True
                structure['iframe_sources'] = [iframe.get('src') for iframe in soup.find_all('iframe') if iframe.get('src')]
            
        except Exception as e:
            logger.debug(f"HTML structure analysis failed: {e}")
        
        return structure
    
    async def _analyze_javascript(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """Analyze JavaScript code."""
        js_analysis = {
            'inline_scripts': 0,
            'external_scripts': 0,
            'script_sources': [],
            'suspicious_functions': [],
            'obfuscated_code': False
        }
        
        try:
            scripts = soup.find_all('script')
            
            for script in scripts:
                if script.get('src'):
                    # External script
                    js_analysis['external_scripts'] += 1
                    src = urljoin(base_url, script.get('src'))
                    js_analysis['script_sources'].append(src)
                elif script.string:
                    # Inline script
                    js_analysis['inline_scripts'] += 1
                    
                    # Check for suspicious functions
                    suspicious_funcs = ['eval', 'unescape', 'fromCharCode', 'atob', 'btoa']
                    for func in suspicious_funcs:
                        if func in script.string:
                            js_analysis['suspicious_functions'].append(func)
                    
                    # Check for obfuscation
                    if await self._is_obfuscated(script.string):
                        js_analysis['obfuscated_code'] = True
            
        except Exception as e:
            logger.debug(f"JavaScript analysis failed: {e}")
        
        return js_analysis
    
    async def _is_obfuscated(self, code: str) -> bool:
        """Detect if code is obfuscated."""
        try:
            # Simple heuristics for obfuscation detection
            obfuscation_indicators = [
                len(code) > 1000 and code.count(';') > 50,  # Very dense code
                'eval(' in code and 'unescape(' in code,  # Common obfuscation pattern
                code.count('\\x') > 10,  # Hex encoding
                re.search(r'_0x[a-f0-9]{4}', code) is not None,  # Hex variable names
                len(re.findall(r'\w{30,}', code)) > 5  # Very long variable names
            ]
            
            return sum(obfuscation_indicators) >= 2
            
        except Exception as e:
            logger.debug(f"Obfuscation detection failed: {e}")
            return False
    
    async def _analyze_forms(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Analyze forms on the page."""
        forms = []
        
        try:
            form_elements = soup.find_all('form')
            
            for form in form_elements:
                form_data = {
                    'action': form.get('action'),
                    'method': form.get('method', 'get').upper(),
                    'inputs': [],
                    'is_login_form': False,
                    'collects_sensitive_data': False
                }
                
                # Analyze input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    input_data = {
                        'type': inp.get('type', 'text'),
                        'name': inp.get('name'),
                        'id': inp.get('id')
                    }
                    form_data['inputs'].append(input_data)
                    
                    # Check for login form indicators
                    if inp.get('type') == 'password':
                        form_data['is_login_form'] = True
                    
                    # Check for sensitive data collection
                    sensitive_fields = ['password', 'credit', 'card', 'cvv', 'ssn', 'social']
                    field_name = (inp.get('name') or '').lower()
                    if any(sensitive in field_name for sensitive in sensitive_fields):
                        form_data['collects_sensitive_data'] = True
                
                forms.append(form_data)
            
        except Exception as e:
            logger.debug(f"Form analysis failed: {e}")
        
        return forms
    
    async def _extract_resources(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """Extract and categorize resources."""
        resources = {
            'images': [],
            'stylesheets': [],
            'scripts': [],
            'external_domains': set(),
            'total_resources': 0
        }
        
        try:
            # Extract images
            for img in soup.find_all('img'):
                src = img.get('src')
                if src:
                    full_url = urljoin(base_url, src)
                    resources['images'].append(full_url)
                    domain = urlparse(full_url).netloc
                    if domain and domain != urlparse(base_url).netloc:
                        resources['external_domains'].add(domain)
            
            # Extract stylesheets
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href')
                if href:
                    full_url = urljoin(base_url, href)
                    resources['stylesheets'].append(full_url)
                    domain = urlparse(full_url).netloc
                    if domain and domain != urlparse(base_url).netloc:
                        resources['external_domains'].add(domain)
            
            # Extract scripts
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    full_url = urljoin(base_url, src)
                    resources['scripts'].append(full_url)
                    domain = urlparse(full_url).netloc
                    if domain and domain != urlparse(base_url).netloc:
                        resources['external_domains'].add(domain)
            
            resources['external_domains'] = list(resources['external_domains'])
            resources['total_resources'] = (
                len(resources['images']) + 
                len(resources['stylesheets']) + 
                len(resources['scripts'])
            )
            
        except Exception as e:
            logger.debug(f"Resource extraction failed: {e}")
        
        return resources
    
    async def _detect_obfuscation(self, html: str) -> bool:
        """Detect obfuscation in HTML content."""
        try:
            obfuscation_patterns = [
                r'eval\s*\(',  # eval function
                r'unescape\s*\(',  # unescape function
                r'String\.fromCharCode',  # Character code conversion
                r'\\x[0-9a-fA-F]{2}',  # Hex encoding
                r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
                r'atob\s*\(',  # Base64 decode
                r'document\.write\s*\(\s*unescape'  # Common obfuscation
            ]
            
            matches = sum(1 for pattern in obfuscation_patterns if re.search(pattern, html))
            return matches >= 2
            
        except Exception as e:
            logger.debug(f"Obfuscation detection failed: {e}")
            return False
    
    async def _detect_suspicious_patterns(self, html: str) -> List[str]:
        """Detect suspicious patterns in content."""
        patterns = []
        
        try:
            # Check for common phishing indicators
            if re.search(r'verify\s+your\s+account', html, re.IGNORECASE):
                patterns.append('Account verification request')
            
            if re.search(r'suspended|locked|unusual\s+activity', html, re.IGNORECASE):
                patterns.append('Account suspension warning')
            
            if re.search(r'click\s+here\s+immediately|urgent|act\s+now', html, re.IGNORECASE):
                patterns.append('Urgency tactics')
            
            if re.search(r'confirm\s+your\s+identity', html, re.IGNORECASE):
                patterns.append('Identity confirmation request')
            
            # Check for hidden elements
            if re.search(r'display:\s*none|visibility:\s*hidden', html):
                patterns.append('Hidden elements detected')
            
            # Check for auto-submit forms
            if re.search(r'onload\s*=\s*["\'].*submit', html, re.IGNORECASE):
                patterns.append('Auto-submit form detected')
            
        except Exception as e:
            logger.debug(f"Suspicious pattern detection failed: {e}")
        
        return patterns
    
    async def calculate_content_similarity(self, url1: str, url2: str) -> Dict[str, Any]:
        """Calculate similarity between two URLs' content."""
        result = {
            'url1': url1,
            'url2': url2,
            'similarity_score': 0.0,
            'common_elements': {}
        }
        
        try:
            # Fetch both pages
            response1 = self.session.get(url1, timeout=self.timeout)
            response2 = self.session.get(url2, timeout=self.timeout)
            
            soup1 = BeautifulSoup(response1.text, 'html.parser')
            soup2 = BeautifulSoup(response2.text, 'html.parser')
            
            # Compare titles
            title1 = soup1.title.string if soup1.title else ''
            title2 = soup2.title.string if soup2.title else ''
            title_similarity = self._calculate_string_similarity(title1, title2)
            
            # Compare structure
            structure1 = {
                'forms': len(soup1.find_all('form')),
                'inputs': len(soup1.find_all('input')),
                'images': len(soup1.find_all('img')),
                'links': len(soup1.find_all('a'))
            }
            
            structure2 = {
                'forms': len(soup2.find_all('form')),
                'inputs': len(soup2.find_all('input')),
                'images': len(soup2.find_all('img')),
                'links': len(soup2.find_all('a'))
            }
            
            # Calculate structural similarity
            structure_similarity = self._calculate_structure_similarity(structure1, structure2)
            
            # Overall similarity
            result['similarity_score'] = (title_similarity + structure_similarity) / 2
            result['common_elements'] = {
                'title_similarity': title_similarity,
                'structure_similarity': structure_similarity
            }
            
        except Exception as e:
            logger.error(f"Content similarity calculation failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings."""
        if not str1 or not str2:
            return 0.0
        
        # Simple Jaccard similarity
        set1 = set(str1.lower().split())
        set2 = set(str2.lower().split())
        
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_structure_similarity(self, struct1: Dict, struct2: Dict) -> float:
        """Calculate similarity between two page structures."""
        total_diff = 0
        max_diff = 0
        
        for key in struct1:
            val1 = struct1[key]
            val2 = struct2.get(key, 0)
            max_val = max(val1, val2)
            
            if max_val > 0:
                diff = abs(val1 - val2) / max_val
                total_diff += (1 - diff)
                max_diff += 1
        
        return total_diff / max_diff if max_diff > 0 else 0.0
