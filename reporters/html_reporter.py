#!/usr/bin/env python3
"""
HTML Reporter Module

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.0.0
"""

import logging
from typing import Dict, Any
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class HTMLReporter:
    """HTML report generation."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize HTML reporter."""
        self.config = config
        self.output_dir = Path(config.get('output_dir', 'reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Setup Jinja2 environment
        template_dir = Path(__file__).parent.parent / 'templates'
        self.env = Environment(loader=FileSystemLoader(template_dir))
        
    def generate_report(self, data: Dict[str, Any], output_path: str = None) -> str:
        """Generate HTML forensic report."""
        try:
            template = self.env.get_template('report_template.html')
            html_content = template.render(**data)

            if not output_path:
                safe_url = data.get('target_url', 'unknown').replace('://', '_').replace('/', '_')
                filename = f"forensic_report_{safe_url}.html"
                output_path = self.output_dir / filename
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"HTML generation failed: {e}", exc_info=True)
            return None
