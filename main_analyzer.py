#!/usr/bin/env python3
"""
Cyber Forensics Toolkit - Main Analyzer

A comprehensive toolkit for analyzing phishing websites and conducting
digital forensics investigations.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Contact: madhulatha@samyama.ai
Website: https://Samyama.ai
License: Proprietary - All Rights Reserved
Version: 1.0.0
Last Updated: August 2025

This module orchestrates the entire forensic analysis workflow.


"""

import argparse
import asyncio
import json
import logging
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensics.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Import analysis modules
try:
    from analyzers.network_analyzer import NetworkAnalyzer
    from analyzers.security_analyzer import SecurityAnalyzer
    from analyzers.content_analyzer import ContentAnalyzer
    from analyzers.attribution_analyzer import AttributionAnalyzer
    from analyzers.threat_intel import ThreatIntelligence
    
    from detectors.phishing_detector import PhishingDetector
    from detectors.malware_detector import MalwareDetector
    from detectors.brand_detector import BrandDetector
    from detectors.kit_detector import KitDetector
    
    from reporters.pdf_reporter import PDFReporter
    from reporters.html_reporter import HTMLReporter
    from reporters.json_exporter import JSONExporter
    from reporters.ioc_extractor import IOCExtractor
    
    from collectors.screenshot_collector import ScreenshotCollector
    from collectors.resource_collector import ResourceCollector
    from collectors.dns_collector import DNSCollector
    from collectors.cert_collector import CertificateCollector
    
except ImportError as e:
    logger.warning(f"Some modules not available: {e}")
    logger.info("Running in basic mode with available modules only")


class CyberForensicsAnalyzer:
    """Main orchestrator for cyber forensics analysis."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the forensics analyzer."""
        self.config = self._load_config(config_path)
        self.results = {}
        self.start_time = None
        self.end_time = None
        
        # Initialize analyzers
        self.network_analyzer = NetworkAnalyzer(self.config)
        self.security_analyzer = SecurityAnalyzer(self.config)
        self.content_analyzer = ContentAnalyzer(self.config)
        self.attribution_analyzer = AttributionAnalyzer(self.config)
        self.threat_intel = ThreatIntelligence(self.config)
        
        # Initialize detectors
        self.phishing_detector = PhishingDetector(self.config)
        self.malware_detector = MalwareDetector(self.config)
        self.brand_detector = BrandDetector(self.config)
        self.kit_detector = KitDetector(self.config)
        
        # Initialize collectors
        self.screenshot_collector = ScreenshotCollector(self.config)
        self.resource_collector = ResourceCollector(self.config)
        self.dns_collector = DNSCollector(self.config)
        self.cert_collector = CertificateCollector(self.config)
        
        # Initialize reporters
        self.pdf_reporter = PDFReporter(self.config)
        self.html_reporter = HTMLReporter(self.config)
        self.json_exporter = JSONExporter(self.config)
        self.ioc_extractor = IOCExtractor(self.config)
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        default_config = {
            'api_keys': {},
            'timeouts': {
                'network': 30,
                'security': 60,
                'content': 120,
                'screenshot': 30
            },
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'max_redirects': 10,
            'verify_ssl': False,
            'screenshot_resolution': (1920, 1080),
            'deep_scan': False
        }
        
        # Automatically load config/api_keys.json if it exists and no specific config is provided
        if not config_path:
            config_path = 'config/api_keys.json'

        if Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    # Deep merge api_keys
                    if 'api_keys' in user_config:
                        default_config['api_keys'].update(user_config['api_keys'])
                        del user_config['api_keys']
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    async def analyze_url(self, url: str, modules: List[str] = None, 
                         deep_scan: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a URL.
        
        Args:
            url: Target URL to analyze
            modules: List of analysis modules to run
            deep_scan: Whether to perform deep analysis
            
        Returns:
            Dictionary containing all analysis results
        """
        self.start_time = datetime.now()
        logger.info(f"🔍 Starting forensic analysis of: {url}")
        
        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"Invalid URL format: {url}")
        
        # Initialize results structure
        self.results = {
            'target_url': url,
            'analysis_start': self.start_time.isoformat(),
            'parsed_url': {
                'scheme': parsed_url.scheme,
                'netloc': parsed_url.netloc,
                'path': parsed_url.path,
                'params': parsed_url.params,
                'query': parsed_url.query,
                'fragment': parsed_url.fragment
            },
            'analysis_config': {
                'modules': modules or ['all'],
                'deep_scan': deep_scan
            },
            'network': {},
            'security': {},
            'content': {},
            'attribution': {},
            'threat_intelligence': {},
            'detections': {},
            'evidence': {},
            'risk_assessment': {}
        }
        
        # Determine which modules to run
        if not modules or 'all' in modules:
            modules = ['network', 'security', 'content', 'attribution', 'threat_intel', 'detections']
        
        try:
            # Run analysis modules
            if 'network' in modules:
                logger.info("🌐 Running network analysis...")
                self.results['network'] = await self._run_network_analysis(url)
            
            if 'security' in modules:
                logger.info("🔒 Running security analysis...")
                self.results['security'] = await self._run_security_analysis(url)
            
            if 'content' in modules:
                logger.info("📄 Running content analysis...")
                self.results['content'] = await self._run_content_analysis(url)
            
            if 'attribution' in modules:
                logger.info("🕵️ Running attribution analysis...")
                self.results['attribution'] = await self._run_attribution_analysis(url)
            
            if 'threat_intel' in modules:
                logger.info("🛡️ Running threat intelligence analysis...")
                self.results['threat_intelligence'] = await self._run_threat_intel_analysis(url)
            
            if 'detections' in modules:
                logger.info("🎯 Running detection analysis...")
                self.results['detections'] = await self._run_detection_analysis(url)
            
            # Collect evidence
            logger.info("📸 Collecting evidence...")
            self.results['evidence'] = await self._collect_evidence(url)
            
            # Perform risk assessment
            logger.info("⚖️ Performing risk assessment...")
            self.results['risk_assessment'] = self._perform_risk_assessment()
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.results['error'] = str(e)
        
        finally:
            self.end_time = datetime.now()
            self.results['analysis_end'] = self.end_time.isoformat()
            self.results['analysis_duration'] = (self.end_time - self.start_time).total_seconds()
            
            logger.info(f"✅ Analysis completed in {self.results['analysis_duration']:.2f} seconds")
        
        return self.results
    
    async def _run_network_analysis(self, url: str) -> Dict[str, Any]:
        """Run comprehensive network analysis."""
        network_results = {}
        
        try:
            # DNS analysis
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            dns_info = await self.network_analyzer.resolve_ip(domain)
            network_results['dns'] = dns_info
            
            # IP geolocation
            if dns_info.get('a_records'):
                ip = dns_info['a_records'][0]
                geo_info = await self.network_analyzer.get_geolocation(ip)
                network_results['geolocation'] = geo_info
                
                # Cloud provider detection
                cloud_info = await self.network_analyzer.detect_cloud_provider(ip)
                network_results['cloud_provider'] = cloud_info
                
                # Port scanning (if enabled)
                if self.config.get('deep_scan'):
                    port_info = await self.network_analyzer.scan_ports(ip)
                    network_results['ports'] = port_info
            
            # CDN detection
            cdn_info = await self.network_analyzer.detect_cdn(url)
            network_results['cdn'] = cdn_info
            
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            network_results['error'] = str(e)
        
        return network_results
    
    async def _run_security_analysis(self, url: str) -> Dict[str, Any]:
        """Run comprehensive security analysis."""
        security_results = {}
        
        try:
            # SSL/TLS analysis
            cert_info = await self.security_analyzer.analyze_certificate(url)
            security_results['certificate'] = cert_info
            
            # Security headers analysis
            headers_info = await self.security_analyzer.analyze_headers(url)
            security_results['headers'] = headers_info
            
            # Vulnerability scanning
            if self.config.get('deep_scan'):
                vuln_info = await self.security_analyzer.scan_vulnerabilities(url)
                security_results['vulnerabilities'] = vuln_info
            
        except Exception as e:
            logger.error(f"Security analysis failed: {e}")
            security_results['error'] = str(e)
        
        return security_results
    
    async def _run_content_analysis(self, url: str) -> Dict[str, Any]:
        """Run comprehensive content analysis."""
        content_results = {}
        
        try:
            # HTML analysis
            html_info = await self.content_analyzer.analyze_content(url)
            content_results['html'] = html_info
            
            # Resource analysis (already included in analyze_content)
            # resources = await self.resource_collector.collect_resources(url)
            # content_results['resources'] = resources
            
            # JavaScript analysis (already included in analyze_content)
            # js_info = await self.content_analyzer.analyze_javascript(url)
            # content_results['javascript'] = js_info
            
        except Exception as e:
            logger.error(f"Content analysis failed: {e}")
            content_results['error'] = str(e)
        
        return content_results
    
    async def _run_attribution_analysis(self, url: str) -> Dict[str, Any]:
        """Run attribution and intelligence analysis."""
        attribution_results = {}
        
        try:
            # WHOIS analysis
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            whois_info = await self.attribution_analyzer.analyze_domain(domain)
            attribution_results['whois'] = whois_info
            
            # Historical analysis
            if self.config.get('deep_scan'):
                history_info = await self.attribution_analyzer.get_domain_history(domain)
                attribution_results['history'] = history_info
            
            # Similar domains (already included in analyze_domain)
            # similar_domains = await self.attribution_analyzer._find_similar_domains(domain)
            # attribution_results['similar_domains'] = similar_domains
            
        except Exception as e:
            logger.error(f"Attribution analysis failed: {e}")
            attribution_results['error'] = str(e)
        
        return attribution_results
    
    async def _run_threat_intel_analysis(self, url: str) -> Dict[str, Any]:
        """Run threat intelligence analysis."""
        threat_results = {}
        
        try:
            # Run all threat intel analyses concurrently
            tasks = {}

            if self.config.get('api_keys', {}).get('virustotal'):
                tasks['url_analysis'] = self.threat_intel.analyze_url(url)

            if self.config.get('api_keys', {}).get('netlas'):
                tasks['domain_analysis'] = self.threat_intel.analyze_domain(url)

            # You can add IP analysis here if an IP is available
            # For now, we focus on URL and Domain

            results = await asyncio.gather(*tasks.values(), return_exceptions=True)

            # Process results
            task_keys = list(tasks.keys())
            for i, result in enumerate(results):
                if not isinstance(result, Exception):
                    if task_keys[i] == 'url_analysis':
                        # Merge URL analysis results (contains virustotal data)
                        threat_results.update(result)
                    elif task_keys[i] == 'domain_analysis':
                        # Merge domain analysis results (contains netlas data)
                        threat_results.update(result)
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed: {e}")
            threat_results['error'] = str(e)
        
        return threat_results
    
    async def _run_detection_analysis(self, url: str) -> Dict[str, Any]:
        """Run detection analysis."""
        detection_results = {}
        
        try:
            # Get content and attribution data for detection
            content_data = self.results.get('content', {})
            attribution_data = self.results.get('attribution', {})
            threat_intel = self.results.get('threat_intelligence', {})
            
            # Phishing detection
            phishing_score = await self.phishing_detector.detect_phishing(url, content_data, attribution_data)
            detection_results['phishing'] = phishing_score
            
            # Malware detection
            malware_score = await self.malware_detector.detect_malware(url, content_data, threat_intel)
            detection_results['malware'] = malware_score
            
            # Brand impersonation detection
            brand_analysis = await self.brand_detector.detect_brand(url, content_data)
            detection_results['brand_impersonation'] = brand_analysis
            
            # Phishing kit detection
            kit_analysis = await self.kit_detector.detect_phishing_kit(url, content_data)
            detection_results['phishing_kit'] = kit_analysis
            
        except Exception as e:
            logger.error(f"Detection analysis failed: {e}")
            detection_results['error'] = str(e)
        
        return detection_results
    
    async def _collect_evidence(self, url: str) -> Dict[str, Any]:
        """Collect forensic evidence."""
        evidence = {}
        
        try:
            # Screenshot
            screenshot_path = await self.screenshot_collector.capture_screenshot(url)
            evidence['screenshot'] = screenshot_path
            
            # Page source - skip for now (requires additional implementation)
            # page_source = await self.content_analyzer.get_page_source(url)
            # evidence['page_source'] = page_source
            
            # HTTP headers - skip for now (requires additional implementation)
            # headers = await self.content_analyzer.get_response_headers(url)
            # evidence['http_headers'] = headers
            
        except Exception as e:
            logger.error(f"Evidence collection failed: {e}")
            evidence['error'] = str(e)
        
        return evidence
    
    def _perform_risk_assessment(self) -> Dict[str, Any]:
        """Perform comprehensive risk assessment."""
        risk_factors = []
        risk_score = 0
        
        # Analyze threat intelligence (MOST IMPORTANT)
        threat_intel = self.results.get('threat_intelligence', {})
        if threat_intel:
            threat_score = threat_intel.get('threat_score', 0)
            is_malicious = threat_intel.get('is_malicious', False)
            
            if is_malicious:
                risk_factors.append(f"⚠️ VirusTotal flagged as malicious (score: {threat_score}/100)")
                risk_score += threat_score  # Use actual VirusTotal score
            elif threat_score > 30:
                risk_factors.append(f"⚠️ Suspicious threat intelligence score: {threat_score}/100")
                risk_score += threat_score // 2  # Half weight for suspicious
        
        # Analyze detection results
        detections = self.results.get('detections', {})
        
        # Phishing detection
        phishing = detections.get('phishing', {})
        if phishing:
            phishing_score = phishing.get('phishing_score', 0)
            if phishing.get('is_phishing'):
                risk_factors.append(f"🎣 Phishing detected (score: {phishing_score}/100)")
                risk_score += phishing_score // 2  # Add half of phishing score
            elif phishing_score > 30:
                risk_factors.append(f"⚠️ Suspicious phishing indicators (score: {phishing_score}/100)")
                risk_score += phishing_score // 3
        
        # Malware detection
        malware = detections.get('malware', {})
        if malware and malware.get('is_malicious'):
            risk_factors.append("🦠 Malware detected")
            risk_score += 50
        
        # Brand impersonation
        brand = detections.get('brand_impersonation', {})
        if brand and brand.get('is_impersonation'):
            brand_name = brand.get('brand_detected', 'unknown')
            risk_factors.append(f"🏢 Brand impersonation: {brand_name}")
            risk_score += 30
        
        # Analyze security issues
        security = self.results.get('security', {})
        
        if security:
            cert = security.get('certificate', {})
            if cert.get('is_expired'):
                risk_factors.append("🔒 Expired SSL certificate")
                risk_score += 20
            elif not cert.get('certificate_valid'):
                risk_factors.append("🔒 Invalid SSL certificate")
                risk_score += 15
            
            headers = security.get('headers', {})
            if headers and not headers.get('has_security_headers'):
                risk_factors.append("📋 Missing security headers")
                risk_score += 10
        
        # Analyze attribution
        attribution = self.results.get('attribution', {})
        
        if attribution:
            whois_data = attribution.get('whois', {})
            
            # Check domain age
            domain_age_info = whois_data.get('domain_age', {})
            if domain_age_info:
                age_days = domain_age_info.get('age_days', 999)
                is_new = domain_age_info.get('is_new', False)
                
                if is_new or age_days < 30:
                    risk_factors.append(f"🆕 Very new domain ({age_days} days old)")
                    risk_score += 25
                elif age_days < 180:
                    risk_factors.append(f"📅 Recently registered domain ({age_days} days old)")
                    risk_score += 15
            
            # Check privacy protection
            registrant = whois_data.get('registrant_info', {})
            if registrant and registrant.get('privacy_protected'):
                risk_factors.append("🔐 Domain privacy protection enabled")
                risk_score += 10
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
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
            'CRITICAL': "IMMEDIATE ACTION REQUIRED: Block this URL and investigate further. High likelihood of malicious activity.",
            'HIGH': "CAUTION ADVISED: This URL shows multiple suspicious indicators. Avoid accessing and consider blocking.",
            'MEDIUM': "MODERATE RISK: Some concerning indicators detected. Exercise caution and additional verification recommended.",
            'LOW': "LOW RISK: Minor concerns detected. Monitor for changes and verify legitimacy if needed.",
            'MINIMAL': "MINIMAL RISK: No significant threats detected, but continue monitoring as part of routine security."
        }
        return recommendations.get(risk_level, "Unable to determine recommendation")
    
    async def generate_reports(self, output_dir: str = "reports", 
                             formats: List[str] = None) -> Dict[str, str]:
        """Generate forensic reports in specified formats."""
        if not formats:
            formats = ['html', 'json']
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        report_files = {}
        
        try:
            if 'html' in formats:
                html_file = self.html_reporter.generate_report(self.results)
                report_files['html'] = html_file
            
            if 'pdf' in formats:
                pdf_file = self.pdf_reporter.generate_report(self.results, output_path)
                report_files['pdf'] = pdf_file
            
            if 'json' in formats:
                json_file = self.json_exporter.export_data(self.results, output_path)
                report_files['json'] = json_file
            
            # Always generate IOCs
            iocs = self.ioc_extractor.extract_iocs(self.results)
            ioc_file = self.ioc_extractor.export_csv_format(iocs, output_path / 'iocs.csv')
            report_files['iocs'] = ioc_file
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
        
        return report_files


def main():
    """Main entry point for the cyber forensics analyzer."""
    parser = argparse.ArgumentParser(
        description="Cyber Forensics Toolkit - Comprehensive phishing site analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url "https://suspicious-site.com" --full-analysis
  %(prog)s --url "https://phishing-site.com" --modules network,security
  %(prog)s --file urls.txt --output-dir results/ --format html,pdf,json
        """
    )
    
    parser.add_argument('--url', type=str, help='Target URL to analyze')
    parser.add_argument('--file', type=str, help='File containing URLs to analyze (one per line)')
    parser.add_argument('--modules', type=str, default='all',
                       help='Comma-separated list of modules to run (network,security,content,attribution,threat_intel,detections)')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    parser.add_argument('--output-dir', type=str, default='reports', help='Output directory for reports')
    parser.add_argument('--format', type=str, default='html,json',
                       help='Report formats (html,pdf,json)')
    parser.add_argument('--deep-scan', action='store_true', help='Enable deep scanning (slower but more thorough)')
    parser.add_argument('--quick', action='store_true', help='Quick scan mode (faster but less comprehensive)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.url and not args.file:
        parser.error("Either --url or --file must be specified")
    
    # Parse modules
    if args.quick:
        modules = ['network', 'security']
    elif args.modules == 'all':
        modules = ['all']
    else:
        modules = [m.strip() for m in args.modules.split(',')]
    
    # Parse formats
    formats = [f.strip() for f in args.format.split(',')]
    
    async def run_analysis():
        """Run the analysis asynchronously."""
        analyzer = CyberForensicsAnalyzer(args.config)
        
        urls_to_analyze = []
        
        if args.url:
            urls_to_analyze.append(args.url)
        
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    urls_to_analyze.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                logger.error(f"Failed to read URLs from file: {e}")
                return
        
        for i, url in enumerate(urls_to_analyze, 1):
            logger.info(f"🎯 Analyzing URL {i}/{len(urls_to_analyze)}: {url}")
            
            try:
                # Run analysis
                results = await analyzer.analyze_url(url, modules, args.deep_scan)
                
                # Generate reports
                report_files = await analyzer.generate_reports(args.output_dir, formats)
                
                # Print summary
                risk_assessment = results.get('risk_assessment', {})
                print(f"\n🎯 ANALYSIS SUMMARY for {url}")
                print("=" * 50)
                print(f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
                print(f"Risk Score: {risk_assessment.get('risk_score', 0)}/100")
                print(f"Analysis Duration: {results.get('analysis_duration', 0):.2f} seconds")
                print(f"Reports Generated: {', '.join(report_files.keys())}")
                
                if risk_assessment.get('risk_factors'):
                    print("\n⚠️ Risk Factors:")
                    for factor in risk_assessment['risk_factors']:
                        print(f"  • {factor}")
                
                print(f"\n💡 Recommendation: {risk_assessment.get('recommendation', 'N/A')}")
                print()

                # Automatically open the HTML report if it was generated
                if 'html' in report_files and report_files['html']:
                    try:
                        webbrowser.open(f"file://{Path(report_files['html']).resolve()}")
                        logger.info(f"Opened HTML report in browser: {report_files['html']}")
                    except Exception as e:
                        logger.warning(f"Could not open HTML report in browser: {e}")
                
            except Exception as e:
                logger.error(f"Analysis failed for {url}: {e}")
    
    # Run the analysis
    try:
        asyncio.run(run_analysis())
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
    except Exception as e:
        logger.error(f"Analysis failed: {e}")


if __name__ == "__main__":
    main()
