#!/usr/bin/env python3
"""
Security Analyzer Module

This module provides security-focused analysis capabilities including:
- SSL/TLS certificate analysis
- Security headers assessment
- Basic vulnerability scanning
- Web application security testing
- Malware detection

Owner: Samyama.ai - Vaidhyamegha Private Limited
Contact: madhulatha@samyama.ai
Website: https://Samyama.ai
License: Proprietary - All Rights Reserved
Version: 1.0.0
Last Updated: August 2025
"""

import asyncio
import json
import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

try:
    import requests
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import OpenSSL
except ImportError as e:
    logging.warning(f"Some security analysis dependencies not available: {e}")

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Security analysis and vulnerability assessment."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize security analyzer with configuration."""
        self.config = config
        self.timeout = config.get('timeouts', {}).get('security', 60)
        self.session = requests.Session()
        self.session.timeout = self.timeout
        self.session.verify = config.get('verify_ssl', False)
        
        # Security headers to check
        self.security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
            'expect-ct': 'Expect-CT'
        }
    
    async def analyze_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate."""
        result = {
            'url': url,
            'has_ssl': False,
            'certificate_valid': False,
            'certificate_expired': False,
            'certificate_details': {},
            'certificate_chain': [],
            'vulnerabilities': [],
            'trust_issues': []
        }
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            port = 443 if parsed_url.scheme == 'https' else 80
            
            if parsed_url.scheme != 'https':
                result['has_ssl'] = False
                result['trust_issues'].append('No SSL/TLS encryption')
                return result
            
            result['has_ssl'] = True
            
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
                    
                    # Parse certificate
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Basic certificate information
                    try:
                        subject_dict = {}
                        for attr in cert.subject:
                            try:
                                key = attr.oid._name
                            except:
                                key = attr.oid.dotted_string
                            subject_dict[key] = attr.value
                        
                        issuer_dict = {}
                        for attr in cert.issuer:
                            try:
                                key = attr.oid._name
                            except:
                                key = attr.oid.dotted_string
                    except Exception as e:
                        logger.debug(f"Certificate attribute parsing failed: {e}")
                        subject_dict = {'error': 'Could not parse subject'}
                        issuer_dict = {'error': 'Could not parse issuer'}
                    
                    # Use UTC-aware datetime methods
                    try:
                        not_valid_before = cert.not_valid_before.astimezone()
                        not_valid_after = cert.not_valid_after.astimezone()
                    except AttributeError:
                        # Fallback for older cryptography versions
                        not_valid_before = cert.not_valid_before
                        not_valid_after = cert.not_valid_after
                    
                    result['certificate_details'] = {
                        'subject': subject_dict,
                        'issuer': issuer_dict,
                        'serial_number': str(cert.serial_number),
                        'version': cert.version.name,
                        'not_valid_before': not_valid_before.isoformat(),
                        'not_valid_after': not_valid_after.isoformat(),
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'public_key_algorithm': cert.public_key().__class__.__name__
                    }
                    
                    # Check certificate validity
                    now = datetime.now(timezone.utc)
                    if not_valid_after < now:
                        result['is_expired'] = True
                        result['certificate_valid'] = False
                    elif not_valid_before > now:
                        result['is_expired'] = False
                        result['certificate_valid'] = False  # Not yet valid')
                    else:
                        result['certificate_valid'] = True
                    
                    # Check certificate chain
                    result['certificate_chain'] = await self._analyze_certificate_chain(hostname, port)
                    
                    # Check for common vulnerabilities
                    result['vulnerabilities'] = await self._check_ssl_vulnerabilities(hostname, port)
                    
                    # Analyze certificate trust
                    await self._analyze_certificate_trust(cert, result)
        
        except Exception as e:
            logger.error(f"Certificate analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _analyze_certificate_chain(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Analyze the certificate chain."""
        chain = []
        
        try:
            # Use OpenSSL to get full certificate chain
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    peer_cert_chain = ssock.getpeercert_chain()
                    
                    if peer_cert_chain:
                        for i, cert in enumerate(peer_cert_chain):
                            cert_info = {
                                'position': i,
                                'subject': cert.get_subject().get_components(),
                                'issuer': cert.get_issuer().get_components(),
                                'serial_number': str(cert.get_serial_number()),
                                'not_before': cert.get_notBefore().decode('utf-8'),
                                'not_after': cert.get_notAfter().decode('utf-8'),
                                'signature_algorithm': cert.get_signature_algorithm().decode('utf-8')
                            }
                            chain.append(cert_info)
        
        except Exception as e:
            logger.debug(f"Certificate chain analysis failed: {e}")
        
        return chain
    
    async def _check_ssl_vulnerabilities(self, hostname: str, port: int) -> List[str]:
        """Check for SSL/TLS vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for weak protocols
            weak_protocols = [ssl.PROTOCOL_SSLv2, ssl.PROTOCOL_SSLv3, ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1]
            
            for protocol in weak_protocols:
                try:
                    context = ssl.SSLContext(protocol)
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            protocol_name = {
                                ssl.PROTOCOL_SSLv2: 'SSLv2',
                                ssl.PROTOCOL_SSLv3: 'SSLv3',
                                ssl.PROTOCOL_TLSv1: 'TLSv1.0',
                                ssl.PROTOCOL_TLSv1_1: 'TLSv1.1'
                            }.get(protocol, 'Unknown')
                            vulnerabilities.append(f'Weak protocol supported: {protocol_name}')
                except Exception:
                    pass  # Protocol not supported (good)
            
            # Check for weak ciphers
            try:
                context = ssl.create_default_context()
                context.set_ciphers('LOW:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cipher = ssock.cipher()
                        if cipher and any(weak in cipher[0] for weak in ['RC4', 'DES', 'MD5']):
                            vulnerabilities.append(f'Weak cipher supported: {cipher[0]}')
            except Exception:
                pass
        
        except Exception as e:
            logger.debug(f"SSL vulnerability check failed: {e}")
        
        return vulnerabilities
    
    async def _analyze_certificate_trust(self, cert, result: Dict[str, Any]):
        """Analyze certificate trust and legitimacy."""
        try:
            # Check issuer
            issuer_cn = None
            try:
                for attr in cert.issuer:
                    try:
                        if attr.oid._name == 'commonName':
                            issuer_cn = attr.value
                            break
                    except:
                        if 'commonName' in str(attr.oid):
                            issuer_cn = attr.value
                            break
            except Exception as e:
                logger.debug(f"Issuer CN extraction failed: {e}")
            
            if issuer_cn:
                result['certificate_details']['issuer_cn'] = issuer_cn
                
                # Check for suspicious issuers
                suspicious_issuers = [
                    'self-signed', 'localhost', 'test', 'example',
                    'untrusted', 'invalid', 'fake'
                ]
                
                if any(suspicious in issuer_cn.lower() for suspicious in suspicious_issuers):
                    result['trust_issues'].append(f'Suspicious issuer: {issuer_cn}')
                
                # Check for free certificate authorities (not necessarily bad, but worth noting)
                free_cas = ['Let\'s Encrypt', 'ZeroSSL', 'Buypass']
                if any(ca in issuer_cn for ca in free_cas):
                    result['certificate_details']['free_ca'] = True
            
            # Check subject alternative names
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_names = [name.value for name in san_ext.value]
                result['certificate_details']['san'] = san_names
                
                # Check for wildcard certificates
                if any(name.startswith('*.') for name in san_names):
                    result['certificate_details']['wildcard'] = True
            except Exception:
                pass
        
        except Exception as e:
            logger.debug(f"Certificate trust analysis failed: {e}")
    
    async def analyze_headers(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP security headers."""
        result = {
            'url': url,
            'security_headers': {},
            'missing_headers': [],
            'security_score': 0,
            'recommendations': []
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            # Check each security header
            for header_name, header_description in self.security_headers.items():
                if header_name in headers:
                    result['security_headers'][header_name] = {
                        'present': True,
                        'value': headers[header_name],
                        'description': header_description
                    }
                    result['security_score'] += 10
                else:
                    result['missing_headers'].append(header_name)
                    result['recommendations'].append(f'Add {header_description} header')
            
            # Analyze specific headers
            await self._analyze_hsts(headers, result)
            await self._analyze_csp(headers, result)
            await self._analyze_frame_options(headers, result)
            
            # Check for information disclosure headers
            info_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
            for header in info_headers:
                if header in headers:
                    result['security_headers'][header] = {
                        'present': True,
                        'value': headers[header],
                        'risk': 'Information disclosure'
                    }
                    result['recommendations'].append(f'Remove or obfuscate {header} header')
            
            # Calculate final security score
            max_score = len(self.security_headers) * 10
            result['security_score_percentage'] = (result['security_score'] / max_score) * 100
        
        except Exception as e:
            logger.error(f"Header analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _analyze_hsts(self, headers: Dict[str, str], result: Dict[str, Any]):
        """Analyze HSTS header."""
        hsts_header = headers.get('strict-transport-security')
        if hsts_header:
            hsts_analysis = {
                'max_age': None,
                'include_subdomains': False,
                'preload': False
            }
            
            # Parse HSTS directives
            directives = [d.strip() for d in hsts_header.split(';')]
            for directive in directives:
                if directive.startswith('max-age='):
                    try:
                        hsts_analysis['max_age'] = int(directive.split('=')[1])
                    except ValueError:
                        pass
                elif directive == 'includeSubDomains':
                    hsts_analysis['include_subdomains'] = True
                elif directive == 'preload':
                    hsts_analysis['preload'] = True
            
            result['security_headers']['strict-transport-security']['analysis'] = hsts_analysis
            
            # Recommendations
            if hsts_analysis['max_age'] and hsts_analysis['max_age'] < 31536000:  # 1 year
                result['recommendations'].append('HSTS max-age should be at least 1 year (31536000 seconds)')
    
    async def _analyze_csp(self, headers: Dict[str, str], result: Dict[str, Any]):
        """Analyze Content Security Policy header."""
        csp_header = headers.get('content-security-policy')
        if csp_header:
            csp_analysis = {
                'directives': {},
                'unsafe_inline': False,
                'unsafe_eval': False,
                'allows_data_uris': False
            }
            
            # Parse CSP directives
            directives = [d.strip() for d in csp_header.split(';')]
            for directive in directives:
                if ' ' in directive:
                    name, values = directive.split(' ', 1)
                    csp_analysis['directives'][name] = values.split()
                    
                    # Check for unsafe practices
                    if "'unsafe-inline'" in values:
                        csp_analysis['unsafe_inline'] = True
                    if "'unsafe-eval'" in values:
                        csp_analysis['unsafe_eval'] = True
                    if 'data:' in values:
                        csp_analysis['allows_data_uris'] = True
            
            result['security_headers']['content-security-policy']['analysis'] = csp_analysis
            
            # Recommendations
            if csp_analysis['unsafe_inline']:
                result['recommendations'].append('Avoid unsafe-inline in CSP')
            if csp_analysis['unsafe_eval']:
                result['recommendations'].append('Avoid unsafe-eval in CSP')
    
    async def _analyze_frame_options(self, headers: Dict[str, str], result: Dict[str, Any]):
        """Analyze X-Frame-Options header."""
        frame_options = headers.get('x-frame-options')
        if frame_options:
            frame_analysis = {
                'value': frame_options.upper(),
                'protection_level': 'unknown'
            }
            
            if frame_options.upper() == 'DENY':
                frame_analysis['protection_level'] = 'high'
            elif frame_options.upper() == 'SAMEORIGIN':
                frame_analysis['protection_level'] = 'medium'
            elif frame_options.upper().startswith('ALLOW-FROM'):
                frame_analysis['protection_level'] = 'low'
                frame_analysis['allowed_origin'] = frame_options.split(' ', 1)[1]
            
            result['security_headers']['x-frame-options']['analysis'] = frame_analysis
    
    async def scan_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """Scan for common web vulnerabilities."""
        result = {
            'url': url,
            'vulnerabilities': [],
            'scan_results': {
                'xss': await self._test_xss(url),
                'sql_injection': await self._test_sql_injection(url),
                'directory_traversal': await self._test_directory_traversal(url),
                'open_redirect': await self._test_open_redirect(url),
                'information_disclosure': await self._test_information_disclosure(url)
            },
            'risk_level': 'low'
        }
        
        # Aggregate vulnerabilities
        for vuln_type, vuln_result in result['scan_results'].items():
            if vuln_result.get('vulnerable', False):
                result['vulnerabilities'].append({
                    'type': vuln_type,
                    'severity': vuln_result.get('severity', 'medium'),
                    'description': vuln_result.get('description', ''),
                    'evidence': vuln_result.get('evidence', [])
                })
        
        # Determine overall risk level
        if any(v['severity'] == 'high' for v in result['vulnerabilities']):
            result['risk_level'] = 'high'
        elif any(v['severity'] == 'medium' for v in result['vulnerabilities']):
            result['risk_level'] = 'medium'
        
        return result
    
    async def _test_xss(self, url: str) -> Dict[str, Any]:
        """Test for XSS vulnerabilities."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'description': 'Cross-Site Scripting (XSS) vulnerability',
            'evidence': []
        }
        
        try:
            # Simple XSS payloads
            payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "javascript:alert('XSS')",
                '<img src=x onerror=alert("XSS")>'
            ]
            
            parsed_url = urlparse(url)
            
            for payload in payloads:
                # Test in URL parameters
                test_url = f"{url}?test={payload}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    if payload in response.text:
                        result['vulnerable'] = True
                        result['evidence'].append(f'Payload reflected: {payload}')
                        break
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"XSS test failed: {e}")
        
        return result
    
    async def _test_sql_injection(self, url: str) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'description': 'SQL Injection vulnerability',
            'evidence': []
        }
        
        try:
            # SQL injection payloads
            payloads = [
                "'",
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--"
            ]
            
            error_indicators = [
                'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                'sqlite_', 'postgresql', 'warning: pg_'
            ]
            
            for payload in payloads:
                test_url = f"{url}?id={payload}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    response_text = response.text.lower()
                    
                    for indicator in error_indicators:
                        if indicator in response_text:
                            result['vulnerable'] = True
                            result['evidence'].append(f'SQL error detected with payload: {payload}')
                            return result
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"SQL injection test failed: {e}")
        
        return result
    
    async def _test_directory_traversal(self, url: str) -> Dict[str, Any]:
        """Test for directory traversal vulnerabilities."""
        result = {
            'vulnerable': False,
            'severity': 'medium',
            'description': 'Directory Traversal vulnerability',
            'evidence': []
        }
        
        try:
            # Directory traversal payloads
            payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd'
            ]
            
            for payload in payloads:
                test_url = f"{url}?file={payload}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for common file contents
                    if 'root:x:0:0:' in response.text or '# localhost' in response.text:
                        result['vulnerable'] = True
                        result['evidence'].append(f'File disclosure with payload: {payload}')
                        break
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"Directory traversal test failed: {e}")
        
        return result
    
    async def _test_open_redirect(self, url: str) -> Dict[str, Any]:
        """Test for open redirect vulnerabilities."""
        result = {
            'vulnerable': False,
            'severity': 'medium',
            'description': 'Open Redirect vulnerability',
            'evidence': []
        }
        
        try:
            # Open redirect payloads
            payloads = [
                'http://evil.com',
                '//evil.com',
                'https://evil.com'
            ]
            
            redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'continue']
            
            for param in redirect_params:
                for payload in payloads:
                    test_url = f"{url}?{param}={payload}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10, allow_redirects=False)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('location', '')
                            if 'evil.com' in location:
                                result['vulnerable'] = True
                                result['evidence'].append(f'Open redirect to {location}')
                                return result
                    except Exception:
                        continue
        
        except Exception as e:
            logger.debug(f"Open redirect test failed: {e}")
        
        return result
    
    async def _test_information_disclosure(self, url: str) -> Dict[str, Any]:
        """Test for information disclosure."""
        result = {
            'vulnerable': False,
            'severity': 'low',
            'description': 'Information Disclosure',
            'evidence': []
        }
        
        try:
            # Common sensitive files
            sensitive_files = [
                'robots.txt',
                '.htaccess',
                'web.config',
                'phpinfo.php',
                'info.php',
                'test.php',
                'backup.sql',
                '.git/config',
                '.env'
            ]
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for file_path in sensitive_files:
                test_url = f"{base_url}/{file_path}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        # Check for sensitive content
                        content = response.text.lower()
                        if any(keyword in content for keyword in ['password', 'secret', 'key', 'token', 'config']):
                            result['vulnerable'] = True
                            result['evidence'].append(f'Sensitive file accessible: {file_path}')
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"Information disclosure test failed: {e}")
        
        return result
