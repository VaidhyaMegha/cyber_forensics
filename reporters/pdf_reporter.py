#!/usr/bin/env python3
"""
PDF Reporter Module

This module converts HTML content to a PDF report using WeasyPrint.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.1.0
"""

import logging
from typing import Dict, Any
from pathlib import Path
import weasyprint

logger = logging.getLogger(__name__)


class PDFReporter:
    """PDF report generation from HTML content."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize PDF reporter."""
        self.config = config
        self.output_dir = Path(config.get('output_dir', 'reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, html_content: str, output_filename: str) -> str:
        """Generate PDF forensic report from HTML content."""
        output_path = self.output_dir / output_filename

        try:
            pdf = weasyprint.HTML(string=html_content)
            pdf.write_pdf(output_path)
            logger.info(f"Successfully generated PDF report: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"PDF generation failed: {e}", exc_info=True)
            return None
