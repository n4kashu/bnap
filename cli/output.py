#!/usr/bin/env python3
"""
Output Formatting Module for BNAP CLI

Provides flexible output formatting for CLI results including tables,
JSON, CSV, YAML, and custom templates.
"""

import json
import csv
import io
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pathlib import Path
import sys

# Try to import optional dependencies
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False


class OutputFormatter:
    """Universal output formatter for CLI results."""
    
    def __init__(self, format_type: str = 'table', 
                 color_output: bool = True,
                 max_width: Optional[int] = None):
        """
        Initialize output formatter.
        
        Args:
            format_type: Output format (table, json, yaml, csv, template)
            color_output: Enable colored output
            max_width: Maximum width for table output
        """
        self.format_type = format_type
        self.color_output = color_output and sys.stdout.isatty()
        self.max_width = max_width or 120
    
    def format(self, data: Any, template: Optional[str] = None, 
               headers: Optional[List[str]] = None) -> str:
        """
        Format data according to specified format type.
        
        Args:
            data: Data to format
            template: Optional template string for template format
            headers: Optional headers for table/csv formats
            
        Returns:
            Formatted string output
        """
        if self.format_type == 'json':
            return self.format_json(data)
        elif self.format_type == 'yaml':
            return self.format_yaml(data)
        elif self.format_type == 'csv':
            return self.format_csv(data, headers)
        elif self.format_type == 'template' and template:
            return self.format_template(data, template)
        else:
            return self.format_table(data, headers)
    
    def format_json(self, data: Any) -> str:
        """Format data as JSON."""
        return json.dumps(data, indent=2, default=self._json_encoder)
    
    def format_yaml(self, data: Any) -> str:
        """Format data as YAML."""
        if HAS_YAML:
            return yaml.dump(data, default_flow_style=False, sort_keys=False)
        else:
            # Fallback to JSON if YAML not available
            return self.format_json(data)
    
    def format_csv(self, data: Any, headers: Optional[List[str]] = None) -> str:
        """Format data as CSV."""
        if isinstance(data, dict):
            # Convert single dict to list
            data = [data]
        
        if not isinstance(data, list) or not data:
            return ""
        
        output = io.StringIO()
        
        # Flatten nested data for CSV
        flattened_data = []
        for item in data:
            if isinstance(item, dict):
                flat_item = self._flatten_dict(item)
                flattened_data.append(flat_item)
            else:
                flattened_data.append({'value': str(item)})
        
        if flattened_data:
            fieldnames = headers or list(flattened_data[0].keys())
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_data)
        
        return output.getvalue().strip()
    
    def format_table(self, data: Any, headers: Optional[List[str]] = None) -> str:
        """Format data as a table."""
        if isinstance(data, dict):
            return self._format_dict_table(data)
        elif isinstance(data, list):
            return self._format_list_table(data, headers)
        else:
            return str(data)
    
    def format_template(self, data: Any, template: str) -> str:
        """Format data using a custom template."""
        if HAS_JINJA2:
            tmpl = Template(template)
            return tmpl.render(data=data)
        else:
            # Simple string formatting fallback
            try:
                return template.format(**data) if isinstance(data, dict) else template.format(data)
            except:
                return str(data)
    
    def _format_dict_table(self, data: Dict[str, Any]) -> str:
        """Format dictionary as a key-value table."""
        if HAS_TABULATE:
            table_data = [[self._colorize(k, 'key'), self._format_value(v)] 
                         for k, v in data.items()]
            return tabulate(table_data, tablefmt='plain')
        else:
            # Simple formatting without tabulate
            lines = []
            max_key_len = max(len(str(k)) for k in data.keys()) if data else 0
            for key, value in data.items():
                formatted_value = self._format_value(value)
                lines.append(f"{str(key):<{max_key_len}}  {formatted_value}")
            return '\n'.join(lines)
    
    def _format_list_table(self, data: List[Any], headers: Optional[List[str]] = None) -> str:
        """Format list as a table."""
        if not data:
            return "No data available"
        
        # Handle list of dictionaries
        if isinstance(data[0], dict):
            if HAS_TABULATE:
                # Use tabulate for nice formatting
                if headers is None:
                    headers = list(data[0].keys())
                
                table_data = []
                for item in data:
                    row = [self._format_value(item.get(h, '')) for h in headers]
                    table_data.append(row)
                
                colored_headers = [self._colorize(h, 'header') for h in headers]
                return tabulate(table_data, headers=colored_headers, tablefmt='grid')
            else:
                # Simple table formatting
                if headers is None:
                    headers = list(data[0].keys())
                
                # Calculate column widths
                col_widths = {}
                for h in headers:
                    max_width = len(h)
                    for item in data:
                        val_len = len(str(item.get(h, '')))
                        max_width = max(max_width, val_len)
                    col_widths[h] = min(max_width, 30)  # Cap at 30 chars
                
                # Build table
                lines = []
                
                # Header
                header_line = ' | '.join(f"{h:<{col_widths[h]}}" for h in headers)
                lines.append(header_line)
                lines.append('-' * len(header_line))
                
                # Data rows
                for item in data:
                    row = []
                    for h in headers:
                        val = str(item.get(h, ''))
                        if len(val) > col_widths[h]:
                            val = val[:col_widths[h]-3] + '...'
                        row.append(f"{val:<{col_widths[h]}}")
                    lines.append(' | '.join(row))
                
                return '\n'.join(lines)
        else:
            # Simple list
            return '\n'.join(str(item) for item in data)
    
    def _format_value(self, value: Any) -> str:
        """Format individual value for display."""
        if value is None:
            return self._colorize('null', 'null')
        elif isinstance(value, bool):
            return self._colorize('true' if value else 'false', 'bool')
        elif isinstance(value, (int, float)):
            return self._colorize(str(value), 'number')
        elif isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(value, dict):
            return f"<{len(value)} items>"
        elif isinstance(value, list):
            return f"[{len(value)} items]"
        else:
            val_str = str(value)
            if len(val_str) > 50:
                val_str = val_str[:47] + '...'
            return val_str
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
        """Flatten nested dictionary for CSV output."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _colorize(self, text: str, color_type: str) -> str:
        """Add color to text if color output is enabled."""
        if not self.color_output:
            return text
        
        # ANSI color codes
        colors = {
            'header': '\033[1;34m',  # Bold blue
            'key': '\033[1;36m',     # Bold cyan
            'number': '\033[33m',     # Yellow
            'bool': '\033[35m',       # Magenta
            'null': '\033[90m',       # Gray
            'error': '\033[1;31m',    # Bold red
            'success': '\033[1;32m',  # Bold green
            'warning': '\033[1;33m',  # Bold yellow
            'reset': '\033[0m'
        }
        
        color = colors.get(color_type, '')
        reset = colors['reset']
        
        return f"{color}{text}{reset}" if color else text
    
    def _json_encoder(self, obj):
        """Custom JSON encoder for special types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Path):
            return str(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)


class ProgressBar:
    """Simple progress bar for long-running operations."""
    
    def __init__(self, total: int, description: str = "Progress", 
                 width: int = 40, show_percentage: bool = True):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items
            description: Description text
            width: Width of progress bar
            show_percentage: Show percentage complete
        """
        self.total = total
        self.description = description
        self.width = width
        self.show_percentage = show_percentage
        self.current = 0
        self.start_time = datetime.now()
    
    def update(self, increment: int = 1, message: Optional[str] = None):
        """Update progress bar."""
        self.current = min(self.current + increment, self.total)
        self.render(message)
    
    def render(self, message: Optional[str] = None):
        """Render progress bar to stdout."""
        if self.total == 0:
            percentage = 100
        else:
            percentage = (self.current / self.total) * 100
        
        filled_width = int(self.width * self.current / self.total) if self.total > 0 else self.width
        bar = '█' * filled_width + '░' * (self.width - filled_width)
        
        # Calculate time elapsed and ETA
        elapsed = datetime.now() - self.start_time
        if self.current > 0 and self.current < self.total:
            eta = elapsed * (self.total - self.current) / self.current
            eta_str = f" ETA: {str(eta).split('.')[0]}"
        else:
            eta_str = ""
        
        # Build output line
        line = f"\r{self.description}: {bar}"
        
        if self.show_percentage:
            line += f" {percentage:5.1f}%"
        
        line += f" ({self.current}/{self.total})"
        
        if message:
            line += f" - {message}"
        
        line += eta_str
        
        # Clear to end of line and print
        sys.stdout.write('\033[K' + line)
        sys.stdout.flush()
        
        if self.current >= self.total:
            sys.stdout.write('\n')
            sys.stdout.flush()
    
    def finish(self, message: str = "Complete"):
        """Finish progress bar."""
        self.current = self.total
        self.render(message)


class StatusIndicator:
    """Status indicators for different states."""
    
    # Status symbols
    SYMBOLS = {
        'success': '✅',
        'error': '❌',
        'warning': '⚠️',
        'info': 'ℹ️',
        'running': '🔄',
        'stopped': '🛑',
        'pending': '⏳',
        'complete': '✓',
        'failed': '✗',
        'bullet': '•',
        'arrow': '→',
    }
    
    # Colored status text
    STATUS_COLORS = {
        'active': '\033[1;32m',    # Green
        'inactive': '\033[90m',     # Gray
        'error': '\033[1;31m',      # Red
        'warning': '\033[1;33m',    # Yellow
        'info': '\033[1;34m',       # Blue
        'reset': '\033[0m'
    }
    
    @classmethod
    def get_symbol(cls, status: str) -> str:
        """Get status symbol."""
        return cls.SYMBOLS.get(status, cls.SYMBOLS['bullet'])
    
    @classmethod
    def format_status(cls, status: str, text: str, color: bool = True) -> str:
        """Format status with symbol and optional color."""
        symbol = cls.get_symbol(status)
        
        if color and sys.stdout.isatty():
            color_code = cls.STATUS_COLORS.get(status, '')
            reset = cls.STATUS_COLORS['reset']
            return f"{symbol} {color_code}{text}{reset}"
        else:
            return f"{symbol} {text}"


def format_tree(data: Dict[str, Any], indent: str = "", is_last: bool = True) -> str:
    """
    Format nested data as a tree structure.
    
    Args:
        data: Nested dictionary data
        indent: Current indentation
        is_last: Whether this is the last item at this level
        
    Returns:
        Formatted tree string
    """
    lines = []
    items = list(data.items())
    
    for i, (key, value) in enumerate(items):
        is_last_item = i == len(items) - 1
        
        # Choose the right symbol
        if indent == "":
            prefix = ""
        elif is_last_item:
            prefix = "└── "
        else:
            prefix = "├── "
        
        lines.append(f"{indent}{prefix}{key}")
        
        # Handle nested structures
        if isinstance(value, dict):
            extension = "    " if is_last_item else "│   "
            nested = format_tree(value, indent + extension, is_last_item)
            lines.append(nested)
        elif isinstance(value, list):
            extension = "    " if is_last_item else "│   "
            for j, item in enumerate(value):
                item_prefix = "└── " if j == len(value) - 1 else "├── "
                if isinstance(item, dict):
                    lines.append(f"{indent}{extension}{item_prefix}[{j}]")
                    nested = format_tree(item, indent + extension + "    ", j == len(value) - 1)
                    lines.append(nested)
                else:
                    lines.append(f"{indent}{extension}{item_prefix}{item}")
        else:
            lines[-1] += f": {value}"
    
    return '\n'.join(lines)


def format_diff(old_data: Dict[str, Any], new_data: Dict[str, Any], color: bool = True) -> str:
    """
    Format difference between two dictionaries.
    
    Args:
        old_data: Original data
        new_data: New data
        color: Enable colored output
        
    Returns:
        Formatted diff string
    """
    lines = []
    all_keys = set(old_data.keys()) | set(new_data.keys())
    
    for key in sorted(all_keys):
        old_val = old_data.get(key)
        new_val = new_data.get(key)
        
        if old_val == new_val:
            # No change
            lines.append(f"  {key}: {old_val}")
        elif key not in old_data:
            # Added
            if color:
                lines.append(f"\033[32m+ {key}: {new_val}\033[0m")
            else:
                lines.append(f"+ {key}: {new_val}")
        elif key not in new_data:
            # Removed
            if color:
                lines.append(f"\033[31m- {key}: {old_val}\033[0m")
            else:
                lines.append(f"- {key}: {old_val}")
        else:
            # Modified
            if color:
                lines.append(f"\033[31m- {key}: {old_val}\033[0m")
                lines.append(f"\033[32m+ {key}: {new_val}\033[0m")
            else:
                lines.append(f"- {key}: {old_val}")
                lines.append(f"+ {key}: {new_val}")
    
    return '\n'.join(lines)


# Export formatter classes and functions
__all__ = [
    'OutputFormatter',
    'ProgressBar',
    'StatusIndicator',
    'format_tree',
    'format_diff',
]