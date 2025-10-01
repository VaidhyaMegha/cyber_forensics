#!/usr/bin/env python3
"""
Network Analyzer Module

This module provides network-level analysis capabilities including:
- IP address resolution and geolocation
- Cloud provider detection
- CDN identification
- Port scanning and service detection
- Network path analysis

Owner: Samyama.ai - Vaidhyamegha Private Limited
Contact: madhulatha@samyama.ai
Website: https://Samyama.ai
License: Proprietary - All Rights Reserved
Version: 1.0.0
Last Updated: August 2025
"""

import asyncio
import ipaddress
import json
import logging
import socket
import subprocess
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

try:
    import requests
    import dns.resolver
    import geoip2.database
    import geoip2.errors
    from ipwhois import IPWhois
except ImportError as e:
    logging.warning(f"Some network analysis dependencies not available: {e}")

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """Network analysis and intelligence gathering."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize network analyzer with configuration."""
        self.config = config
        self.timeout = config.get('timeouts', {}).get('network', 30)
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
        # Cloud provider IP ranges (simplified - in production, use comprehensive lists)
        self.cloud_providers = {
            'aws': [
                '3.0.0.0/8', '13.0.0.0/8', '15.0.0.0/8', '18.0.0.0/8',
                '34.0.0.0/8', '35.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8'
            ],
            'azure': [
                '13.64.0.0/11', '13.96.0.0/13', '13.104.0.0/14', '20.0.0.0/8',
                '40.0.0.0/8', '51.0.0.0/8', '52.0.0.0/8', '104.0.0.0/8'
            ],
            'gcp': [
                '8.8.8.0/24', '8.8.4.0/24', '8.34.208.0/20', '8.35.192.0/20',
                '23.236.48.0/20', '23.251.128.0/19', '34.0.0.0/8', '35.0.0.0/8'
            ],
            'cloudflare': [
                '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
                '104.16.0.0/12', '108.162.192.0/18', '131.0.72.0/22',
                '141.101.64.0/18', '162.158.0.0/15', '172.64.0.0/13',
                '173.245.48.0/20', '188.114.96.0/20', '190.93.240.0/20',
                '197.234.240.0/22', '198.41.128.0/17'
            ]
        }
    
    async def resolve_ip(self, domain: str) -> Dict[str, Any]:
        """Resolve domain to IP addresses."""
        result = {
            'domain': domain,
            'ipv4_addresses': [],
            'ipv6_addresses': [],
            'cname_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'resolution_time': 0
        }
        
        try:
            import time
            start_time = time.time()
            
            # A records (IPv4)
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                result['ipv4_addresses'] = [str(record) for record in a_records]
            except Exception as e:
                logger.debug(f"No A records for {domain}: {e}")
            
            # AAAA records (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                result['ipv6_addresses'] = [str(record) for record in aaaa_records]
            except Exception as e:
                logger.debug(f"No AAAA records for {domain}: {e}")
            
            # CNAME records
            try:
                cname_records = dns.resolver.resolve(domain, 'CNAME')
                result['cname_records'] = [str(record) for record in cname_records]
            except Exception as e:
                logger.debug(f"No CNAME records for {domain}: {e}")
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                result['mx_records'] = [{'priority': record.preference, 'exchange': str(record.exchange)} 
                                      for record in mx_records]
            except Exception as e:
                logger.debug(f"No MX records for {domain}: {e}")
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                result['txt_records'] = [str(record) for record in txt_records]
            except Exception as e:
                logger.debug(f"No TXT records for {domain}: {e}")
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                result['ns_records'] = [str(record) for record in ns_records]
            except Exception as e:
                logger.debug(f"No NS records for {domain}: {e}")
            
            result['resolution_time'] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
            result['error'] = str(e)
        
        return result
    
    async def get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for an IP address."""
        result = {
            'ip': ip,
            'country': None,
            'country_code': None,
            'region': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None,
            'organization': None,
            'asn': None,
            'as_name': None
        }
        
        try:
            # Try multiple geolocation services
            await self._get_ipinfo_data(ip, result)
            await self._get_whois_data(ip, result)
            
        except Exception as e:
            logger.error(f"Geolocation lookup failed for {ip}: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _get_ipinfo_data(self, ip: str, result: Dict[str, Any]):
        """Get geolocation data from ipinfo.io (free tier)."""
        try:
            response = self.session.get(f"http://ipinfo.io/{ip}/json", timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                
                result['country'] = data.get('country')
                result['region'] = data.get('region')
                result['city'] = data.get('city')
                result['timezone'] = data.get('timezone')
                result['organization'] = data.get('org')
                
                # Parse location coordinates
                if 'loc' in data:
                    lat, lon = data['loc'].split(',')
                    result['latitude'] = float(lat)
                    result['longitude'] = float(lon)
                
        except Exception as e:
            logger.debug(f"IPInfo lookup failed: {e}")
    
    async def _get_whois_data(self, ip: str, result: Dict[str, Any]):
        """Get WHOIS data for IP address."""
        try:
            whois = IPWhois(ip)
            whois_data = whois.lookup_rdap(depth=1)
            
            if 'asn' in whois_data:
                result['asn'] = whois_data['asn']
            
            if 'asn_description' in whois_data:
                result['as_name'] = whois_data['asn_description']
            
            # Extract network information
            if 'network' in whois_data:
                network = whois_data['network']
                if 'name' in network:
                    result['network_name'] = network['name']
                if 'country' in network and not result['country']:
                    result['country'] = network['country']
            
        except Exception as e:
            logger.debug(f"WHOIS lookup failed: {e}")
    
    async def detect_cloud_provider(self, ip: str) -> Dict[str, Any]:
        """Detect if IP belongs to a major cloud provider."""
        result = {
            'ip': ip,
            'is_cloud': False,
            'provider': None,
            'service': None,
            'region': None
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for provider, ranges in self.cloud_providers.items():
                for cidr in ranges:
                    try:
                        network = ipaddress.ip_network(cidr)
                        if ip_obj in network:
                            result['is_cloud'] = True
                            result['provider'] = provider
                            
                            # Try to get more specific information
                            if provider == 'aws':
                                result.update(await self._get_aws_details(ip))
                            elif provider == 'azure':
                                result.update(await self._get_azure_details(ip))
                            elif provider == 'gcp':
                                result.update(await self._get_gcp_details(ip))
                            elif provider == 'cloudflare':
                                result['service'] = 'CDN/Security'
                            
                            return result
                    except Exception as e:
                        logger.debug(f"Error checking {cidr}: {e}")
            
            # If not in known ranges, try reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0].lower()
                if any(cloud in hostname for cloud in ['amazonaws', 'azure', 'googleusercontent', 'cloudflare']):
                    result['is_cloud'] = True
                    if 'amazonaws' in hostname:
                        result['provider'] = 'aws'
                    elif 'azure' in hostname:
                        result['provider'] = 'azure'
                    elif 'googleusercontent' in hostname:
                        result['provider'] = 'gcp'
                    elif 'cloudflare' in hostname:
                        result['provider'] = 'cloudflare'
            except Exception as e:
                logger.debug(f"Reverse DNS lookup failed: {e}")
        
        except Exception as e:
            logger.error(f"Cloud provider detection failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _get_aws_details(self, ip: str) -> Dict[str, Any]:
        """Get AWS-specific details."""
        details = {}
        try:
            # Try reverse DNS for AWS region info
            hostname = socket.gethostbyaddr(ip)[0]
            if 'amazonaws.com' in hostname:
                parts = hostname.split('.')
                for part in parts:
                    if part.startswith('ec2-'):
                        details['service'] = 'EC2'
                    elif 'elb' in part:
                        details['service'] = 'ELB'
                    elif 's3' in part:
                        details['service'] = 'S3'
                    elif any(region in part for region in ['us-east', 'us-west', 'eu-', 'ap-']):
                        details['region'] = part
        except Exception as e:
            logger.debug(f"AWS details lookup failed: {e}")
        
        return details
    
    async def _get_azure_details(self, ip: str) -> Dict[str, Any]:
        """Get Azure-specific details."""
        details = {}
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if 'azure' in hostname.lower():
                details['service'] = 'Azure'
                # Extract region if possible
                if 'eastus' in hostname:
                    details['region'] = 'East US'
                elif 'westus' in hostname:
                    details['region'] = 'West US'
                elif 'northeurope' in hostname:
                    details['region'] = 'North Europe'
        except Exception as e:
            logger.debug(f"Azure details lookup failed: {e}")
        
        return details
    
    async def _get_gcp_details(self, ip: str) -> Dict[str, Any]:
        """Get GCP-specific details."""
        details = {}
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if 'googleusercontent.com' in hostname:
                details['service'] = 'Compute Engine'
        except Exception as e:
            logger.debug(f"GCP details lookup failed: {e}")
        
        return details
    
    async def detect_cdn(self, url: str) -> Dict[str, Any]:
        """Detect CDN usage."""
        result = {
            'uses_cdn': False,
            'cdn_provider': None,
            'cdn_headers': {},
            'edge_locations': []
        }
        
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            # Check for CDN-specific headers
            cdn_indicators = {
                'cloudflare': ['cf-ray', 'cf-cache-status', 'server'],
                'fastly': ['fastly-debug-digest', 'x-served-by'],
                'akamai': ['akamai-origin-hop', 'x-akamai-transformed'],
                'amazon_cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'maxcdn': ['x-maxcdn-forward'],
                'keycdn': ['x-keycdn-forward'],
                'incapsula': ['x-iinfo']
            }
            
            for cdn, header_keys in cdn_indicators.items():
                for header_key in header_keys:
                    if header_key in headers:
                        result['uses_cdn'] = True
                        result['cdn_provider'] = cdn
                        result['cdn_headers'][header_key] = headers[header_key]
                        
                        # Extract edge location if available
                        if header_key == 'x-served-by':
                            result['edge_locations'].append(headers[header_key])
                        elif header_key == 'cf-ray':
                            # Cloudflare ray ID contains edge location
                            ray_id = headers[header_key]
                            if '-' in ray_id:
                                edge_code = ray_id.split('-')[-1]
                                result['edge_locations'].append(edge_code)
            
            # Check server header for CDN indicators
            server_header = headers.get('server', '').lower()
            if 'cloudflare' in server_header:
                result['uses_cdn'] = True
                result['cdn_provider'] = 'cloudflare'
            elif 'nginx' in server_header and 'cloudfront' in str(headers):
                result['uses_cdn'] = True
                result['cdn_provider'] = 'amazon_cloudfront'
        
        except Exception as e:
            logger.error(f"CDN detection failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def scan_ports(self, ip: str, ports: List[int] = None) -> Dict[str, Any]:
        """Scan common ports on target IP."""
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        result = {
            'ip': ip,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_duration': 0
        }
        
        try:
            import time
            start_time = time.time()
            
            # Use asyncio for concurrent port scanning
            tasks = []
            for port in ports:
                task = asyncio.create_task(self._scan_single_port(ip, port))
                tasks.append(task)
            
            port_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for port, status in zip(ports, port_results):
                if isinstance(status, Exception):
                    result['filtered_ports'].append(port)
                elif status:
                    result['open_ports'].append(port)
                else:
                    result['closed_ports'].append(port)
            
            result['scan_duration'] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _scan_single_port(self, ip: str, port: int, timeout: int = 3) -> bool:
        """Scan a single port."""
        try:
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def traceroute(self, target: str) -> Dict[str, Any]:
        """Perform traceroute to target."""
        result = {
            'target': target,
            'hops': [],
            'total_hops': 0,
            'success': False
        }
        
        try:
            # Use system traceroute command
            cmd = ['traceroute', '-n', '-m', '15', target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                lines = stdout.decode().strip().split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            hop_num = parts[0]
                            ip = parts[1] if parts[1] != '*' else None
                            rtt = parts[2] if len(parts) > 2 and 'ms' in parts[2] else None
                            
                            result['hops'].append({
                                'hop': int(hop_num),
                                'ip': ip,
                                'rtt': rtt
                            })
                
                result['total_hops'] = len(result['hops'])
                result['success'] = True
            else:
                result['error'] = stderr.decode()
        
        except Exception as e:
            logger.error(f"Traceroute failed: {e}")
            result['error'] = str(e)
        
        return result
