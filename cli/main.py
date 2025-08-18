#!/usr/bin/env python3
"""
Bitcoin Native Asset Protocol - Command Line Interface

A comprehensive CLI for managing Bitcoin assets, performing minting operations,
querying registries, and administering the BNAP system.
"""

import sys
import os
import logging
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import click
from datetime import datetime

# Add the project root to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import configuration management
from cli.config import get_config_manager, load_config

# Import help and output modules
from cli.help import (
    get_command_examples, get_troubleshooting_guide, get_context_help,
    format_examples_help, generate_man_page, generate_completion_script,
    QUICK_START_GUIDE, CHEAT_SHEET
)
from cli.output import OutputFormatter, ProgressBar, StatusIndicator

# Global CLI context
class CLIContext:
    """Global CLI context for sharing state across commands."""
    
    def __init__(self):
        self.config_file: Optional[str] = None
        self.output_format: str = "table"
        self.verbose: int = 0
        self.config: Dict[str, Any] = {}
        self.logger: Optional[logging.Logger] = None
        self.config_manager = None
        self.output_formatter: Optional[OutputFormatter] = None
    
    def setup_logging(self):
        """Configure logging based on verbosity level."""
        log_levels = {
            0: logging.WARNING,
            1: logging.INFO,
            2: logging.DEBUG
        }
        
        level = log_levels.get(min(self.verbose, 2), logging.DEBUG)
        
        # Configure logging format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Configure handler
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        
        # Setup logger
        self.logger = logging.getLogger('bnap-cli')
        self.logger.setLevel(level)
        self.logger.addHandler(handler)
        
        # Suppress verbose third-party logs unless in debug mode
        if self.verbose < 2:
            logging.getLogger('requests').setLevel(logging.WARNING)
            logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    def load_config(self):
        """Load configuration from file and environment."""
        # Use configuration manager for hierarchical config loading
        self.config_manager = get_config_manager(self.config_file)
        self.config = self.config_manager.load()
        
        # Apply CLI-specific settings from config
        if 'cli' in self.config:
            cli_config = self.config['cli']
            # Only override if not set via command line
            if self.output_format == "table" and 'output_format' in cli_config:
                self.output_format = cli_config['output_format']
            if self.verbose == 0 and 'verbose' in cli_config:
                self.verbose = cli_config['verbose']
        
        self.logger.debug(f"Loaded configuration from {len(self.config_manager.get_sources())} sources")
        
        # Initialize output formatter
        self.output_formatter = OutputFormatter(
            format_type=self.output_format,
            color_output=self.config.get('cli', {}).get('color_output', True)
        )
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback to default."""
        return self.config.get(key, default)
    
    def output(self, data: Any, format_override: Optional[str] = None, 
               template: Optional[str] = None, headers: Optional[List[str]] = None):
        """Output data in specified format using the OutputFormatter."""
        try:
            # Update formatter if format override is provided
            if format_override and format_override != self.output_format:
                formatter = OutputFormatter(
                    format_type=format_override,
                    color_output=self.config.get('cli', {}).get('color_output', True)
                )
            else:
                formatter = self.output_formatter
            
            # Format and print the data
            formatted_output = formatter.format(data, template=template, headers=headers)
            print(formatted_output)
            
        except Exception as e:
            self.logger.error(f"Output formatting error: {e}")
            # Fallback to simple string output
            if isinstance(data, (dict, list)):
                print(json.dumps(data, indent=2, default=str))
            else:
                print(str(data))
    
    def success(self, message: str):
        """Display success message with formatting."""
        formatted_msg = StatusIndicator.format_status('success', message, color=True)
        click.echo(formatted_msg)
    
    def error(self, message: str):
        """Display error message with formatting."""
        formatted_msg = StatusIndicator.format_status('error', message, color=True)
        click.echo(formatted_msg, err=True)
    
    def warning(self, message: str):
        """Display warning message with formatting."""
        formatted_msg = StatusIndicator.format_status('warning', message, color=True)
        click.echo(formatted_msg, err=True)
    
    def info(self, message: str):
        """Display info message with formatting."""
        formatted_msg = StatusIndicator.format_status('info', message, color=True)
        click.echo(formatted_msg)


# Global context instance
pass_context = click.make_pass_decorator(CLIContext, ensure=True)


@click.group(context_settings={'help_option_names': ['-h', '--help']})
@click.option('--config-file', '-c', 
              help='Path to configuration file')
@click.option('--output-format', '-o', 
              type=click.Choice(['table', 'json', 'yaml', 'csv', 'template']), 
              default='table',
              help='Output format')
@click.option('--verbose', '-v', 
              count=True, 
              help='Increase verbosity (-v for INFO, -vv for DEBUG)')
@click.option('--version', 
              is_flag=True, 
              help='Show version information')
@click.option('--show-examples', 
              is_flag=True, 
              help='Show usage examples')
@pass_context
def cli(ctx: CLIContext, config_file: Optional[str], output_format: str, 
        verbose: int, version: bool, show_examples: bool):
    """
    Bitcoin Native Asset Protocol (BNAP) Command Line Interface
    
    A comprehensive tool for managing Bitcoin assets, performing minting operations,
    querying registries, and administering the BNAP system.
    
    Examples:
        bnap asset create --name "My Token" --symbol "MTK"
        bnap mint fungible --asset-id abc123 --amount 1000
        bnap registry query --asset-type fungible
        bnap validator start --network testnet
    """
    
    if version:
        try:
            from cli import __version__
            click.echo(f"BNAP CLI v{__version__}")
        except ImportError:
            click.echo("BNAP CLI v1.0.0")
        sys.exit(0)
    
    if show_examples:
        click.echo(QUICK_START_GUIDE)
        sys.exit(0)
    
    # Setup context
    ctx.config_file = config_file
    ctx.output_format = output_format
    ctx.verbose = verbose
    
    # Initialize logging
    ctx.setup_logging()
    
    # Load configuration
    ctx.load_config()
    
    ctx.logger.debug("CLI initialized with context")












# Error handling wrapper
def handle_cli_error(func):
    """Decorator to handle CLI errors gracefully."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            click.echo("\nOperation cancelled by user.", err=True)
            sys.exit(130)
        except Exception as e:
            # Get context if available
            ctx = None
            try:
                ctx = click.get_current_context().find_object(CLIContext)
            except:
                pass
            
            if ctx and ctx.verbose >= 2:
                # Show full traceback in debug mode
                import traceback
                click.echo(f"Error: {e}", err=True)
                click.echo(traceback.format_exc(), err=True)
            else:
                click.echo(f"Error: {e}", err=True)
                click.echo("Use -vv for detailed error information.", err=True)
            
            sys.exit(1)
    
    return wrapper


# Utility functions for commands
def format_datetime(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def confirm_action(message: str, default: bool = False) -> bool:
    """Confirm user action with prompt."""
    return click.confirm(message, default=default)


def prompt_for_value(message: str, required: bool = True, 
                    hide_input: bool = False) -> Optional[str]:
    """Prompt user for input value."""
    return click.prompt(message, default="" if not required else None,
                       hide_input=hide_input, show_default=False)


def validate_bitcoin_address(address: str) -> bool:
    """Basic Bitcoin address validation."""
    # Simplified validation - in production would use proper Bitcoin libraries
    if not address:
        return False
    
    # Basic format checks for different address types
    if address.startswith(('1', '3', 'bc1', 'tb1')):
        return len(address) >= 26 and len(address) <= 62
    
    return False


def validate_hex_string(hex_str: str, expected_length: Optional[int] = None) -> bool:
    """Validate hex string format."""
    try:
        bytes.fromhex(hex_str)
        if expected_length and len(hex_str) != expected_length:
            return False
        return True
    except ValueError:
        return False


def load_json_file(file_path: str) -> Dict[str, Any]:
    """Load and validate JSON file."""
    path = Path(file_path)
    if not path.exists():
        raise click.FileError(f"File not found: {file_path}")
    
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise click.FileError(f"Invalid JSON in {file_path}: {e}")


def save_json_file(data: Dict[str, Any], file_path: str, indent: int = 2):
    """Save data to JSON file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w') as f:
        json.dump(data, f, indent=indent, default=str)


# Status and progress indicators
class ProgressTracker:
    """Simple progress tracking for CLI operations."""
    
    def __init__(self, total_steps: int, description: str = "Progress"):
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.start_time = datetime.now()
    
    def step(self, message: str = ""):
        """Advance progress by one step."""
        self.current_step += 1
        percentage = (self.current_step / self.total_steps) * 100
        
        bar_length = 30
        filled_length = int(bar_length * self.current_step / self.total_steps)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        elapsed = datetime.now() - self.start_time
        
        status = f"\r{self.description}: {bar} {percentage:5.1f}% ({self.current_step}/{self.total_steps})"
        if message:
            status += f" - {message}"
        
        click.echo(status, nl=False)
        
        if self.current_step >= self.total_steps:
            click.echo(f"\nCompleted in {elapsed.total_seconds():.2f}s")
    
    def finish(self, message: str = "Completed"):
        """Finish progress tracking."""
        self.current_step = self.total_steps
        self.step(message)


def show_banner():
    """Display CLI banner."""
    banner = """
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║    Bitcoin Native Asset Protocol (BNAP) CLI         ║
    ║    Professional Asset Management for Bitcoin        ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    """
    click.echo(banner)


# Command registration
def register_commands():
    """Register all command modules with the main CLI."""
    try:
        from cli.commands.asset import asset
        cli.add_command(asset)
    except ImportError as e:
        logging.getLogger('bnap-cli').warning(f"Failed to load asset commands: {e}")
    
    try:
        from cli.commands.mint import mint
        cli.add_command(mint)
    except ImportError as e:
        logging.getLogger('bnap-cli').warning(f"Failed to load mint commands: {e}")
    
    try:
        from cli.commands.registry import registry
        cli.add_command(registry)
    except ImportError as e:
        logging.getLogger('bnap-cli').warning(f"Failed to load registry commands: {e}")
    
    try:
        from cli.commands.validator import validator
        cli.add_command(validator)
    except ImportError as e:
        logging.getLogger('bnap-cli').warning(f"Failed to load validator commands: {e}")
    
    try:
        from cli.commands.config import config
        cli.add_command(config)
    except ImportError as e:
        logging.getLogger('bnap-cli').warning(f"Failed to load config commands: {e}")
    
    try:
        from cli.commands.help import help
        cli.add_command(help)
    except ImportError as e:
        logging.getLogger('bnap-cli').warning(f"Failed to load help commands: {e}")


# Main entry point
if __name__ == '__main__':
    # Register all commands
    register_commands()
    
    # Apply error handling to main CLI
    cli = handle_cli_error(cli)
    cli()