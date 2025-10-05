#!/usr/bin/env python3
"""
JSON Exporter Module

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.0.0
"""

import json
import logging
from typing import Dict, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class JSONExporter:
    """JSON data export."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize JSON exporter."""
        self.config = config
        self.output_dir = Path(config.get('output_dir', 'reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def export_data(self, data: Dict[str, Any], output_path = None) -> str:
        """Export analysis data to JSON."""
        try:
            # Ensure output directory exists
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            if not output_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = self.output_dir / f"forensic_analysis_{timestamp}.json"
            elif isinstance(output_path, str):
                output_path = Path(output_path)
            elif isinstance(output_path, Path):
                # If it's a directory path, add filename
                if output_path.is_dir():
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_path = output_path / f"forensic_analysis_{timestamp}.json"
            
            # Convert to Path if string
            if isinstance(output_path, str):
                output_path = Path(output_path)
            
            # Ensure parent directory exists
            if output_path.parent.exists() or output_path.parent == Path('.'):
                output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the file
            with open(str(output_path), 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"JSON export saved to {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
