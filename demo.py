#!/usr/bin/env python3
"""
Cyber Forensics Toolkit - Demo

Simplified demonstration of cyber forensics capabilities.
This demo shows basic network and security analysis without requiring
all external dependencies.

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
import socket
import ssl
import time
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SimpleCyberForensicsDemo:
    """Simplified cyber forensics demonstration."""
    
    def __init__(self):
        """Initialize the demo analyzer."""
        self.results = {}
        self.start_time = None
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Perform basic forensic analysis of a URL."""
        self.start_time = datetime.now()
        logger.info(f"🔍 Starting forensic analysis of: {url}")
        
        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"Invalid URL format: {url}")
        
        # Initialize results
        self.results = {
            'target_url': url,
            'analysis_start': self.start_time.isoformat(),
            'parsed_url': {
                'scheme': parsed_url.scheme,
                'netloc': parsed_url.netloc,
                'path': parsed_url.path,
                'query': parsed_url.query
            },
            'network_analysis': {},
            'security_analysis': {},
            'risk_assessment': {}
        }
        
        try:
            # Network analysis
            logger.info("🌐 Running network analysis...")
            self.results['network_analysis'] = await self._analyze_network(url)
            
            # Security analysis
            logger.info("🔒 Running security analysis...")
            self.results['security_analysis'] = await self._analyze_security(url)
            
            # Risk assessment
            logger.info("⚖️ Performing risk assessment...")
            self.results['risk_assessment'] = self._assess_risk()
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.results['error'] = str(e)
        
        finally:
            end_time = datetime.now()
            self.results['analysis_end'] = end_time.isoformat()
            self.results['analysis_duration'] = (end_time - self.start_time).total_seconds()
            
            logger.info(f"✅ Analysis completed in {self.results['analysis_duration']:.2f} seconds")
        
        return self.results
    
    async def _analyze_network(self, url: str) -> Dict[str, Any]:
        """Basic network analysis."""
        network_info = {
            'ip_addresses': [],
            'geolocation': {},
            'dns_info': {},
            'cloud_provider': None
        }
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            
            # Resolve IP addresses
            try:
                ip_addresses = socket.gethostbyname_ex(hostname)[2]
                network_info['ip_addresses'] = ip_addresses
                
                if ip_addresses:
                    primary_ip = ip_addresses[0]
                    
                    # Basic geolocation (simplified)
                    network_info['geolocation'] = await self._get_basic_geolocation(primary_ip)
                    
                    # Cloud provider detection (simplified)
                    network_info['cloud_provider'] = self._detect_cloud_provider(primary_ip)
                    
            except socket.gaierror as e:
                network_info['dns_error'] = str(e)
            
            # Basic DNS info
            try:
                network_info['dns_info'] = {
                    'hostname': hostname,
                    'fqdn': socket.getfqdn(hostname)
                }
            except Exception as e:
                network_info['dns_info']['error'] = str(e)
        
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            network_info['error'] = str(e)
        
        return network_info
    
    async def _get_basic_geolocation(self, ip: str) -> Dict[str, Any]:
        """Basic IP geolocation (simplified)."""
        geo_info = {
            'ip': ip,
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }
        
        try:
            # This is a simplified version - in production, use proper geolocation APIs
            import requests
            
            # Using a free geolocation service (limited requests)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_info.update({
                        'country': data.get('country', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon')
                    })
        
        except Exception as e:
            logger.debug(f"Geolocation lookup failed: {e}")
            geo_info['error'] = str(e)
        
        return geo_info
    
    def _detect_cloud_provider(self, ip: str) -> str:
        """Basic cloud provider detection."""
        try:
            # Reverse DNS lookup
            hostname = socket.gethostbyaddr(ip)[0].lower()
            
            if 'amazonaws' in hostname:
                return 'Amazon AWS'
            elif 'azure' in hostname or 'microsoft' in hostname:
                return 'Microsoft Azure'
            elif 'googleusercontent' in hostname or 'google' in hostname:
                return 'Google Cloud Platform'
            elif 'cloudflare' in hostname:
                return 'Cloudflare'
            elif 'digitalocean' in hostname:
                return 'DigitalOcean'
            else:
                return 'Unknown/Traditional Hosting'
        
        except Exception:
            return 'Unknown'
    
    async def _analyze_security(self, url: str) -> Dict[str, Any]:
        """Basic security analysis."""
        security_info = {
            'ssl_analysis': {},
            'security_headers': {},
            'vulnerabilities': []
        }
        
        try:
            parsed_url = urlparse(url)
            
            # SSL analysis
            if parsed_url.scheme == 'https':
                security_info['ssl_analysis'] = await self._analyze_ssl(parsed_url.netloc)
            else:
                security_info['ssl_analysis'] = {
                    'has_ssl': False,
                    'risk': 'No SSL/TLS encryption - data transmitted in plain text'
                }
            
            # Basic security headers check
            security_info['security_headers'] = await self._check_security_headers(url)
            
            # Basic vulnerability indicators
            security_info['vulnerabilities'] = await self._check_basic_vulnerabilities(url)
        
        except Exception as e:
            logger.error(f"Security analysis failed: {e}")
            security_info['error'] = str(e)
        
        return security_info
    
    async def _analyze_ssl(self, hostname: str) -> Dict[str, Any]:
        """Basic SSL certificate analysis."""
        ssl_info = {
            'has_ssl': True,
            'certificate_valid': False,
            'certificate_expired': False,
            'issuer': 'Unknown',
            'subject': 'Unknown',
            'expires': 'Unknown'
        }
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                        ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        ssl_info['expires'] = cert.get('notAfter', 'Unknown')
                        
                        # Check if certificate is expired
                        try:
                            expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            if expire_date < datetime.now():
                                ssl_info['certificate_expired'] = True
                            else:
                                ssl_info['certificate_valid'] = True
                        except Exception:
                            pass
        
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    async def _check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check for basic security headers."""
        headers_info = {
            'security_score': 0,
            'present_headers': [],
            'missing_headers': [],
            'recommendations': []
        }
        
        try:
            import requests
            
            response = requests.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            # Important security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    headers_info['present_headers'].append({
                        'header': header,
                        'description': description,
                        'value': headers[header]
                    })
                    headers_info['security_score'] += 20
                else:
                    headers_info['missing_headers'].append(header)
                    headers_info['recommendations'].append(f'Add {description} ({header})')
            
            # Check for information disclosure
            info_headers = ['Server', 'X-Powered-By']
            for header in info_headers:
                if header in headers:
                    headers_info['recommendations'].append(f'Consider hiding {header} header')
        
        except Exception as e:
            headers_info['error'] = str(e)
        
        return headers_info
    
    async def _check_basic_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Check for basic vulnerability indicators."""
        vulnerabilities = []
        
        try:
            import requests
            
            # Check for common sensitive files
            sensitive_paths = [
                '/robots.txt',
                '/.git/config',
                '/admin',
                '/login',
                '/wp-admin',
                '/.env'
            ]
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for path in sensitive_paths:
                try:
                    test_url = base_url + path
                    response = requests.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'severity': 'Low' if path == '/robots.txt' else 'Medium',
                            'description': f'Accessible path: {path}',
                            'url': test_url
                        })
                except Exception:
                    continue
            
            # Basic XSS test
            try:
                xss_payload = '<script>alert("XSS")</script>'
                test_url = f"{url}?test={xss_payload}"
                response = requests.get(test_url, timeout=5)
                
                if xss_payload in response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': 'Potential XSS vulnerability detected',
                        'evidence': 'Payload reflected in response'
                    })
            except Exception:
                pass
        
        except Exception as e:
            logger.debug(f"Vulnerability check failed: {e}")
        
        return vulnerabilities
    
    def _assess_risk(self) -> Dict[str, Any]:
        """Perform basic risk assessment."""
        risk_factors = []
        risk_score = 0
        
        # Check SSL
        ssl_analysis = self.results.get('security_analysis', {}).get('ssl_analysis', {})
        if not ssl_analysis.get('has_ssl', False):
            risk_factors.append("No SSL/TLS encryption")
            risk_score += 30
        elif ssl_analysis.get('certificate_expired', False):
            risk_factors.append("Expired SSL certificate")
            risk_score += 20
        
        # Check security headers
        headers = self.results.get('security_analysis', {}).get('security_headers', {})
        security_score = headers.get('security_score', 0)
        if security_score < 60:
            risk_factors.append("Poor security headers implementation")
            risk_score += 15
        
        # Check vulnerabilities
        vulnerabilities = self.results.get('security_analysis', {}).get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if vuln.get('severity') == 'High':
                risk_factors.append(f"High severity vulnerability: {vuln.get('type')}")
                risk_score += 25
            elif vuln.get('severity') == 'Medium':
                risk_factors.append(f"Medium severity vulnerability: {vuln.get('type')}")
                risk_score += 15
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            'HIGH': "⚠️ HIGH RISK: Multiple security issues detected. Avoid accessing this site and consider blocking.",
            'MEDIUM': "⚠️ MODERATE RISK: Some security concerns detected. Exercise caution when accessing.",
            'LOW': "ℹ️ LOW RISK: Minor security issues detected. Generally safe but monitor for changes.",
            'MINIMAL': "✅ MINIMAL RISK: No significant security issues detected."
        }
        return recommendations.get(risk_level, "Unable to determine recommendation")
    
    def print_summary(self):
        """Print a formatted summary of the analysis."""
        print("\n" + "="*60)
        print("🎯 CYBER FORENSICS ANALYSIS SUMMARY")
        print("="*60)
        
        print(f"🌐 Target URL: {self.results['target_url']}")
        print(f"⏱️ Analysis Duration: {self.results.get('analysis_duration', 0):.2f} seconds")
        print()
        
        # Network Information
        network = self.results.get('network_analysis', {})
        if network.get('ip_addresses'):
            print("🌐 NETWORK INFORMATION:")
            print(f"   IP Addresses: {', '.join(network['ip_addresses'])}")
            
            geo = network.get('geolocation', {})
            if geo.get('country') != 'Unknown':
                print(f"   Location: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}")
                print(f"   ISP: {geo.get('isp', 'Unknown')}")
            
            if network.get('cloud_provider'):
                print(f"   Cloud Provider: {network['cloud_provider']}")
            print()
        
        # Security Information
        security = self.results.get('security_analysis', {})
        ssl_info = security.get('ssl_analysis', {})
        
        print("🔒 SECURITY ANALYSIS:")
        if ssl_info.get('has_ssl'):
            print(f"   SSL/TLS: ✅ Enabled")
            if ssl_info.get('certificate_expired'):
                print(f"   Certificate: ❌ EXPIRED")
            elif ssl_info.get('certificate_valid'):
                print(f"   Certificate: ✅ Valid")
            
            if ssl_info.get('issuer', {}).get('organizationName'):
                print(f"   Issuer: {ssl_info['issuer']['organizationName']}")
        else:
            print(f"   SSL/TLS: ❌ Not enabled")
        
        headers_info = security.get('security_headers', {})
        if 'security_score' in headers_info:
            print(f"   Security Headers Score: {headers_info['security_score']}/100")
        
        vulnerabilities = security.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"   Vulnerabilities Found: {len(vulnerabilities)}")
            for vuln in vulnerabilities:
                severity_icon = "🔴" if vuln['severity'] == 'High' else "🟡" if vuln['severity'] == 'Medium' else "🟢"
                print(f"     {severity_icon} {vuln['type']} ({vuln['severity']})")
        else:
            print(f"   Vulnerabilities: ✅ None detected")
        print()
        
        # Risk Assessment
        risk = self.results.get('risk_assessment', {})
        risk_level = risk.get('risk_level', 'UNKNOWN')
        risk_score = risk.get('risk_score', 0)
        
        risk_icon = {
            'HIGH': '🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'MINIMAL': '✅'
        }.get(risk_level, '❓')
        
        print("⚖️ RISK ASSESSMENT:")
        print(f"   Risk Level: {risk_icon} {risk_level}")
        print(f"   Risk Score: {risk_score}/100")
        
        if risk.get('risk_factors'):
            print("   Risk Factors:")
            for factor in risk['risk_factors']:
                print(f"     • {factor}")
        
        print(f"\n💡 {risk.get('recommendation', 'No recommendation available')}")
        print("\n" + "="*60)


async def main():
    """Main demo function."""
    print("🔍 Cyber Forensics Toolkit - Demo")
    print("="*40)
    print("This demo shows basic forensic analysis capabilities.")
    print("For full functionality, install all dependencies and use main_analyzer.py")
    print()
    
    # Demo URLs (use safe, legitimate sites for testing)
    demo_urls = [
        "https://httpbin.org",  # Safe testing site
        "http://neverssl.com",  # Intentionally no SSL
        "https://badssl.com",   # SSL testing site
    ]
    
    analyzer = SimpleCyberForensicsDemo()
    
    for i, url in enumerate(demo_urls, 1):
        print(f"\n🎯 Demo {i}/{len(demo_urls)}: Analyzing {url}")
        print("-" * 50)
        
        try:
            results = await analyzer.analyze_url(url)
            analyzer.print_summary()
            
            # Save results to file
            filename = f"demo_results_{i}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"📄 Detailed results saved to: {filename}")
            
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
        
        if i < len(demo_urls):
            print("\nPress Enter to continue to next demo...")
            input()
    
    print("\n🎉 Demo completed!")
    print("\nNext steps:")
    print("• Install full dependencies: pip install -r requirements.txt")
    print("• Use main analyzer: python main_analyzer.py --url <target_url>")
    print("• Check the generated JSON files for detailed results")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user. Goodbye! 👋")
    except Exception as e:
        print(f"\nDemo failed: {e}")
        print("Make sure you have basic dependencies installed: pip install requests")
