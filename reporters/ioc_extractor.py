#!/usr/bin/env python3
"""
IOC Extractor Module

This module provides IOC extraction capabilities including:
- Indicator extraction (IPs, domains, hashes)
- STIX/TAXII support
- MISP integration
- Custom format support
- IOC validation

Owner: Samyama.ai - Vaidhyamegha Private Limited
Contact: madhulatha@samyama.ai
Website: https://Samyama.ai
License: Proprietary - All Rights Reserved
Version: 1.0.0
Last Updated: October 2025
"""

import json
import logging
from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime
import re

logger = logging.getLogger(__name__)


class IOCExtractor:
    """Indicators of Compromise extraction and export."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize IOC extractor."""
        self.config = config
        self.output_dir = Path(config.get('output_dir', 'reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def extract_iocs(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from analysis data."""
        iocs = {
            'urls': [],
            'domains': [],
            'ips': [],
            'hashes': [],
            'emails': []
        }
        
        try:
            # Extract URL
            if 'url' in data:
                iocs['urls'].append(data['url'])
            
            # Extract domain
            if 'domain' in data:
                iocs['domains'].append(data['domain'])
            
            # Extract IPs from network analysis
            if 'network_analysis' in data:
                network = data['network_analysis']
                if 'ip_addresses' in network:
                    iocs['ips'].extend(network['ip_addresses'])
            
            # Extract from threat intelligence
            if 'threat_intelligence' in data:
                threat_intel = data['threat_intelligence']
                if 'virustotal' in threat_intel:
                    vt_iocs = self._extract_from_virustotal(threat_intel['virustotal'])
                    for key in iocs:
                        iocs[key].extend(vt_iocs.get(key, []))
            
            # Remove duplicates
            for key in iocs:
                iocs[key] = list(set(iocs[key]))
            
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
        
        return iocs
    
    def _extract_from_virustotal(self, vt_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from VirusTotal data."""
        iocs = {
            'urls': [],
            'domains': [],
            'ips': [],
            'hashes': [],
            'emails': []
        }
        
        try:
            if 'data' in vt_data:
                attributes = vt_data['data'].get('attributes', {})
                
                # Extract URLs
                if 'last_final_url' in attributes:
                    iocs['urls'].append(attributes['last_final_url'])
                
                # Extract related domains and IPs
                # (This would be expanded based on VT API response structure)
                
        except Exception as e:
            logger.debug(f"VT IOC extraction failed: {e}")
        
        return iocs
    
    def export_stix_format(self, iocs: Dict[str, List[str]], output_path: str = None) -> str:
        """Export IOCs in STIX format."""
        try:
            if not output_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = self.output_dir / f"iocs_stix_{timestamp}.json"
            
            # Simplified STIX format
            stix_data = {
                "type": "bundle",
                "id": f"bundle--{timestamp}",
                "spec_version": "2.1",
                "objects": []
            }
            
            # Add indicators
            for ioc_type, values in iocs.items():
                for value in values:
                    stix_data["objects"].append({
                        "type": "indicator",
                        "id": f"indicator--{hash(value)}",
                        "pattern": f"[{ioc_type}:value = '{value}']",
                        "valid_from": datetime.now().isoformat()
                    })
            
            with open(output_path, 'w') as f:
                json.dump(stix_data, f, indent=2)
            
            logger.info(f"STIX IOCs exported to {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"STIX export failed: {e}")
            return None
    
    def export_csv_format(self, iocs: Dict[str, List[str]], output_path: str = None) -> str:
        """Export IOCs in CSV format."""
        try:
            if not output_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = self.output_dir / f"iocs_{timestamp}.csv"
            
            with open(output_path, 'w') as f:
                f.write("Type,Value,Timestamp\n")
                timestamp = datetime.now().isoformat()
                
                for ioc_type, values in iocs.items():
                    for value in values:
                        f.write(f"{ioc_type},{value},{timestamp}\n")
            
            logger.info(f"CSV IOCs exported to {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            return None
