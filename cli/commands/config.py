#!/usr/bin/env python3
"""
Configuration Management Commands for BNAP CLI

Commands for managing CLI configuration, environment profiles, and settings.
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
import click
import json

# Try to import yaml, but make it optional
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Add the project root to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cli.config import (
    ConfigurationManager, get_config_manager, DEFAULT_CONFIG, 
    PROFILES, CONFIG_SEARCH_PATHS, ENV_PREFIX
)

# Import dependencies without circular import
import logging


# Global CLI context (duplicated to avoid circular imports)
class CLIContext:
    """Global CLI context for sharing state across commands."""
    
    def __init__(self):
        self.config_file: Optional[str] = None
        self.output_format: str = "table"
        self.verbose: int = 0
        self.config: Dict[str, Any] = {}
        self.logger: Optional[logging.Logger] = self._setup_logger()
    
    def _setup_logger(self):
        """Setup basic logger."""
        logger = logging.getLogger('bnap-cli')
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def output(self, data: Any, format_override: Optional[str] = None):
        """Output data in specified format."""
        format_type = format_override or self.output_format
        
        try:
            if format_type == "json":
                print(json.dumps(data, indent=2, default=str))
            elif format_type == "table":
                self._output_table(data)
            elif format_type == "yaml":
                if HAS_YAML:
                    print(yaml.dump(data, default_flow_style=False))
                else:
                    self.logger.warning("PyYAML not installed, falling back to JSON")
                    print(json.dumps(data, indent=2, default=str))
            else:
                print(str(data))
        except Exception as e:
            if self.logger:
                self.logger.error(f"Output formatting error: {e}")
            print(str(data))
    
    def _output_table(self, data: Any):
        """Output data in table format."""
        if isinstance(data, dict):
            # Simple key-value table
            for key, value in data.items():
                print(f"{key:20} {value}")
        elif isinstance(data, list) and data:
            # Table with headers
            if isinstance(data[0], dict):
                headers = list(data[0].keys())
                print(" | ".join(f"{h:15}" for h in headers))
                print("-" * (len(headers) * 17))
                for item in data:
                    values = [str(item.get(h, ""))[:15] for h in headers]
                    print(" | ".join(f"{v:15}" for v in values))
            else:
                # Simple list
                for item in data:
                    print(item)
        else:
            print(str(data))


# Global context instance
pass_context = click.make_pass_decorator(CLIContext, ensure=True)


# Error handling wrapper
def handle_cli_error(func):
    """Decorator to handle CLI errors gracefully."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            click.echo("\\nOperation cancelled by user.", err=True)
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


@click.group()
@pass_context
def config(ctx: CLIContext):
    """
    Configuration management commands.
    
    Manage CLI configuration, environment profiles, and settings.
    """
    ctx.logger.debug("Config command group invoked")


@config.command('init')
@click.option('--profile', type=click.Choice(['production', 'testnet', 'development']),
              help='Configuration profile to use as base')
@click.option('--output', type=click.Path(), help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['yaml', 'json']), 
              default='yaml', help='Configuration file format')
@click.option('--force', is_flag=True, help='Overwrite existing configuration')
@click.option('--interactive', is_flag=True, help='Interactive configuration setup')
@pass_context
@handle_cli_error
def init_config(ctx: CLIContext, profile: Optional[str], output: Optional[str],
               output_format: str, force: bool, interactive: bool):
    """
    Generate a default configuration file.
    
    Creates a new configuration file with default settings, optionally
    based on a predefined profile for different environments.
    
    Examples:
        bnap config init
        bnap config init --profile production --output production.yml
        bnap config init --interactive --format json
    """
    
    ctx.logger.info("Initializing configuration file")
    
    # Determine output path
    if not output:
        if output_format == 'yaml':
            output = '.bnap.yml'
        else:
            output = '.bnap.json'
    
    output_path = Path(output)
    
    # Check if file exists
    if output_path.exists() and not force:
        raise click.ClickException(f"Configuration file already exists: {output}. Use --force to overwrite.")
    
    # Start with default configuration
    config_data = DEFAULT_CONFIG.copy()
    
    # Apply profile if specified
    if profile:
        profile_config = PROFILES.get(profile, {})
        config_data = _deep_merge(config_data, profile_config)
        ctx.logger.info(f"Applied profile: {profile}")
    
    # Interactive setup if requested
    if interactive:
        click.echo("\\n🔧 Interactive Configuration Setup")
        click.echo("=" * 40)
        
        # Network configuration
        click.echo("\\n📡 Network Configuration:")
        config_data['network']['type'] = click.prompt(
            "Network type", 
            type=click.Choice(['mainnet', 'testnet', 'regtest']),
            default=config_data['network']['type']
        )
        
        config_data['network']['bitcoin_rpc']['host'] = click.prompt(
            "Bitcoin RPC host",
            default=config_data['network']['bitcoin_rpc']['host']
        )
        
        config_data['network']['bitcoin_rpc']['port'] = click.prompt(
            "Bitcoin RPC port",
            type=int,
            default=config_data['network']['bitcoin_rpc']['port']
        )
        
        config_data['network']['bitcoin_rpc']['username'] = click.prompt(
            "Bitcoin RPC username",
            default=config_data['network']['bitcoin_rpc']['username']
        )
        
        # CLI preferences
        click.echo("\\n🖥️  CLI Preferences:")
        config_data['cli']['output_format'] = click.prompt(
            "Default output format",
            type=click.Choice(['table', 'json', 'yaml', 'csv']),
            default=config_data['cli']['output_format']
        )
        
        config_data['cli']['confirm_destructive'] = click.confirm(
            "Require confirmation for destructive operations?",
            default=config_data['cli']['confirm_destructive']
        )
        
        # Security settings
        click.echo("\\n🔒 Security Settings:")
        config_data['security']['require_confirmations'] = click.prompt(
            "Required confirmations",
            type=int,
            default=config_data['security']['require_confirmations']
        )
        
        config_data['security']['enable_multisig'] = click.confirm(
            "Enable multisignature support?",
            default=config_data['security']['enable_multisig']
        )
    
    # Save configuration
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        if output_format == 'yaml':
            if HAS_YAML:
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
            else:
                click.echo("Warning: YAML support not available. Saving as JSON instead.")
                output_format = 'json'
                json.dump(config_data, f, indent=2)
        else:
            json.dump(config_data, f, indent=2)
    
    click.echo(f"\\n✅ Configuration file created: {output_path}")
    click.echo(f"   Format: {output_format}")
    if profile:
        click.echo(f"   Profile: {profile}")
    
    # Show next steps
    click.echo("\\n📝 Next steps:")
    click.echo(f"   1. Edit {output_path} to customize settings")
    click.echo(f"   2. Set environment variables with {ENV_PREFIX} prefix")
    click.echo(f"   3. Use --config-file {output_path} to use this configuration")


@config.command('show')
@click.option('--key', help='Specific configuration key to show (dot notation)')
@click.option('--sources', is_flag=True, help='Show configuration sources')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']), 
              help='Override output format')
@click.option('--export-env', is_flag=True, help='Export as environment variables')
@pass_context
@handle_cli_error
def show_config(ctx: CLIContext, key: Optional[str], sources: bool, 
               output_format: Optional[str], export_env: bool):
    """
    Display current configuration settings.
    
    Shows the merged configuration from all sources including files,
    environment variables, and defaults.
    
    Examples:
        bnap config show
        bnap config show --key network.bitcoin_rpc
        bnap config show --sources
        bnap config show --export-env > .env
    """
    
    manager = get_config_manager(ctx.config_file)
    
    if export_env:
        # Export as environment variables
        env_vars = manager.export_environment()
        for name, value in env_vars.items():
            click.echo(f"export {name}=\"{value}\"")
        return
    
    if sources:
        # Show configuration sources
        sources_list = manager.get_sources()
        click.echo("📚 Configuration Sources (in order of precedence):")
        click.echo("=" * 50)
        for i, source in enumerate(sources_list, 1):
            click.echo(f"   {i}. {source}")
        return
    
    if key:
        # Show specific key
        value = manager.get(key)
        if value is None:
            click.echo(f"Configuration key not found: {key}")
            sys.exit(1)
        
        if output_format:
            ctx.output({key: value}, output_format)
        else:
            if isinstance(value, dict):
                ctx.output(value, 'yaml')
            else:
                click.echo(f"{key}: {value}")
    else:
        # Show full configuration
        config_data = manager.load()
        ctx.output(config_data, output_format or 'yaml')


@config.command('validate')
@click.option('--fix', is_flag=True, help='Attempt to fix validation issues')
@click.option('--strict', is_flag=True, help='Strict validation mode')
@pass_context
@handle_cli_error
def validate_config(ctx: CLIContext, fix: bool, strict: bool):
    """
    Validate configuration for errors and inconsistencies.
    
    Checks configuration values for validity, required fields,
    and logical consistency.
    
    Examples:
        bnap config validate
        bnap config validate --strict
        bnap config validate --fix
    """
    
    ctx.logger.info("Validating configuration")
    
    manager = get_config_manager(ctx.config_file)
    errors = manager.validate()
    
    # Additional strict validation
    if strict:
        config = manager.load()
        
        # Check for missing passwords
        if not config.get('network', {}).get('bitcoin_rpc', {}).get('password'):
            errors.append("Bitcoin RPC password is not set (required in strict mode)")
        
        # Check for development settings in production
        if config.get('network', {}).get('type') == 'mainnet':
            if config.get('development', {}).get('debug_mode'):
                errors.append("Debug mode enabled on mainnet (not allowed in strict mode)")
            if config.get('development', {}).get('mock_services'):
                errors.append("Mock services enabled on mainnet (not allowed in strict mode)")
    
    if errors:
        click.echo("❌ Configuration validation failed:")
        for error in errors:
            click.echo(f"   • {error}")
        
        if fix:
            click.echo("\\n🔧 Attempting to fix issues...")
            fixed_count = _attempt_config_fixes(manager, errors)
            click.echo(f"   Fixed {fixed_count} issue(s)")
            
            # Re-validate
            remaining_errors = manager.validate()
            if remaining_errors:
                click.echo(f"\\n⚠️  {len(remaining_errors)} issue(s) remain unfixed")
                sys.exit(1)
            else:
                click.echo("\\n✅ All issues fixed successfully")
        else:
            sys.exit(1)
    else:
        click.echo("✅ Configuration is valid")
        
        # Show configuration summary
        config = manager.load()
        click.echo("\\n📊 Configuration Summary:")
        click.echo(f"   Network: {config['network']['type']}")
        click.echo(f"   Bitcoin RPC: {config['network']['bitcoin_rpc']['host']}:{config['network']['bitcoin_rpc']['port']}")
        click.echo(f"   Output Format: {config['cli']['output_format']}")
        click.echo(f"   Confirmations Required: {config['security']['require_confirmations']}")


@config.command('set')
@click.argument('key')
@click.argument('value')
@click.option('--save', is_flag=True, help='Save to configuration file')
@click.option('--global', 'is_global', is_flag=True, help='Save to global config')
@pass_context
@handle_cli_error
def set_config(ctx: CLIContext, key: str, value: str, save: bool, is_global: bool):
    """
    Set a configuration value.
    
    Updates a configuration value using dot notation for nested keys.
    Optionally saves the change to a configuration file.
    
    Examples:
        bnap config set network.type testnet
        bnap config set cli.output_format json --save
        bnap config set security.require_confirmations 3 --global
    """
    
    manager = get_config_manager(ctx.config_file)
    
    # Parse value to appropriate type
    parsed_value = _parse_config_value(value)
    
    # Set the value
    manager.set(key, parsed_value)
    
    click.echo(f"✅ Set {key} = {parsed_value}")
    
    if save:
        if is_global:
            # Save to global config
            global_config_path = Path.home() / '.bnap' / 'config.yml'
            manager.save(str(global_config_path))
            click.echo(f"   Saved to global config: {global_config_path}")
        else:
            # Save to project config
            manager.save()
            click.echo("   Saved to project config")


@config.command('get')
@click.argument('key')
@click.option('--default', help='Default value if key not found')
@pass_context
@handle_cli_error
def get_config(ctx: CLIContext, key: str, default: Optional[str]):
    """
    Get a specific configuration value.
    
    Retrieves a configuration value using dot notation for nested keys.
    
    Examples:
        bnap config get network.type
        bnap config get cli.verbose --default 0
        bnap config get network.bitcoin_rpc.host
    """
    
    manager = get_config_manager(ctx.config_file)
    value = manager.get(key, default)
    
    if value is None:
        click.echo(f"Configuration key not found: {key}")
        sys.exit(1)
    
    if isinstance(value, dict):
        ctx.output(value, 'yaml')
    else:
        click.echo(value)


@config.command('list-profiles')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']), 
              default='table', help='Output format')
@pass_context
@handle_cli_error
def list_profiles(ctx: CLIContext, output_format: str):
    """
    List available configuration profiles.
    
    Shows predefined configuration profiles for different environments.
    
    Examples:
        bnap config list-profiles
        bnap config list-profiles --format yaml
    """
    
    profiles_info = []
    
    for profile_name, profile_config in PROFILES.items():
        info = {
            'profile': profile_name,
            'network': profile_config.get('network', {}).get('type', 'default'),
            'confirmations': profile_config.get('security', {}).get('require_confirmations', 'default'),
            'debug': profile_config.get('development', {}).get('debug_mode', False)
        }
        profiles_info.append(info)
    
    if output_format == 'table':
        click.echo("📋 Available Configuration Profiles:")
        click.echo("=" * 60)
        for info in profiles_info:
            click.echo(f"\\n🔹 {info['profile'].upper()}")
            click.echo(f"   Network: {info['network']}")
            click.echo(f"   Confirmations: {info['confirmations']}")
            click.echo(f"   Debug Mode: {info['debug']}")
    else:
        ctx.output(PROFILES, output_format)


@config.command('search-paths')
@pass_context
@handle_cli_error
def search_paths(ctx: CLIContext):
    """
    Show configuration file search paths.
    
    Lists all paths where the CLI searches for configuration files,
    in order of precedence.
    
    Example:
        bnap config search-paths
    """
    
    click.echo("🔍 Configuration File Search Paths (in order of precedence):")
    click.echo("=" * 60)
    
    for i, path in enumerate(CONFIG_SEARCH_PATHS, 1):
        exists = "✅" if path.exists() else "❌"
        click.echo(f"   {i}. {exists} {path}")
    
    click.echo(f"\\n📝 Environment Variable Prefix: {ENV_PREFIX}")
    
    # Show current environment variables
    env_vars = [k for k in os.environ.keys() if k.startswith(ENV_PREFIX)]
    if env_vars:
        click.echo(f"\\n🌍 Active Environment Variables:")
        for var in sorted(env_vars):
            click.echo(f"   • {var} = {os.environ[var]}")


# Utility functions

def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries."""
    result = base.copy()
    
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result


def _parse_config_value(value: str) -> Any:
    """Parse configuration value string to appropriate type."""
    # Try to parse as JSON first
    try:
        return json.loads(value)
    except:
        pass
    
    # Boolean values
    if value.lower() in ['true', 'yes']:
        return True
    elif value.lower() in ['false', 'no']:
        return False
    
    # Numeric values
    try:
        if '.' in value:
            return float(value)
        else:
            return int(value)
    except ValueError:
        pass
    
    # Default to string
    return value


def _attempt_config_fixes(manager: ConfigurationManager, errors: List[str]) -> int:
    """Attempt to fix configuration errors."""
    fixed_count = 0
    config = manager.load()
    
    for error in errors:
        if "Invalid network type" in error:
            # Fix invalid network type
            manager.set('network.type', 'testnet')
            fixed_count += 1
        
        elif "Bitcoin RPC host is required" in error:
            # Set default RPC host
            manager.set('network.bitcoin_rpc.host', 'localhost')
            fixed_count += 1
        
        elif "Bitcoin RPC port must be a positive integer" in error:
            # Set default port based on network
            network_type = config.get('network', {}).get('type', 'testnet')
            default_ports = {'mainnet': 8332, 'testnet': 18332, 'regtest': 18443}
            manager.set('network.bitcoin_rpc.port', default_ports.get(network_type, 18332))
            fixed_count += 1
        
        elif "Invalid output format" in error:
            # Fix invalid output format
            manager.set('cli.output_format', 'table')
            fixed_count += 1
        
        elif "Min fee rate" in error and "cannot be greater than max fee rate" in error:
            # Fix fee rate mismatch
            manager.set('security.min_fee_rate', 1.0)
            manager.set('security.max_fee_rate', 100.0)
            fixed_count += 1
    
    return fixed_count


# Register commands with main CLI
def register_commands(cli_app):
    """Register config commands with the main CLI application."""
    cli_app.add_command(config)


if __name__ == '__main__':
    config()