#!/usr/bin/env python3
"""
Configuration Management Module for BNAP CLI

Handles hierarchical configuration loading, environment variable mapping,
validation, and management of settings across different environments.
"""

import os
import json
from pathlib import Path

# Try to import yaml, but make it optional
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
from typing import Dict, Any, Optional, List, Union
from collections import ChainMap
import logging

# Configuration file locations in order of precedence (highest to lowest)
CONFIG_SEARCH_PATHS = [
    Path.cwd() / '.bnap.yml',           # Project-specific YAML
    Path.cwd() / '.bnap.json',          # Project-specific JSON
    Path.cwd() / 'bnap.config.yml',     # Alternative project config
    Path.cwd() / 'bnap.config.json',    # Alternative project config
    Path.home() / '.bnap' / 'config.yml',   # User global YAML
    Path.home() / '.bnap' / 'config.json',  # User global JSON
    Path('/etc/bnap/config.yml'),       # System-wide YAML
    Path('/etc/bnap/config.json'),      # System-wide JSON
]

# Environment variable prefix
ENV_PREFIX = 'BNAP_'

# Default configuration values
DEFAULT_CONFIG = {
    # Network settings
    'network': {
        'type': 'testnet',  # mainnet, testnet, regtest
        'bitcoin_rpc': {
            'host': 'localhost',
            'port': 18332,  # Default testnet port
            'username': 'bitcoin',
            'password': None,
            'timeout': 30
        }
    },
    
    # CLI behavior
    'cli': {
        'output_format': 'table',  # table, json, yaml, csv
        'verbose': 0,
        'color_output': True,
        'confirm_destructive': True,
        'pager': 'auto',  # auto, always, never
        'max_display_items': 50,
        'request_timeout': 60
    },
    
    # Asset management
    'assets': {
        'default_fee_rate': 1.0,
        'max_mint_amount': 1000000,
        'require_signatures': True,
        'auto_validate': True
    },
    
    # Registry settings
    'registry': {
        'api_endpoint': 'https://api.bnap.network',
        'cache_enabled': True,
        'cache_ttl': 300,  # seconds
        'max_query_results': 1000,
        'default_sort': 'created_at',
        'default_order': 'desc'
    },
    
    # Validator settings
    'validator': {
        'data_dir': '~/.bnap/validators',
        'log_level': 'INFO',
        'health_check_interval': 30,
        'max_concurrent_operations': 10,
        'psbt_timeout': 300,
        'auto_start': False,
        'enable_monitoring': True
    },
    
    # Security settings
    'security': {
        'require_confirmations': 6,
        'enable_multisig': False,
        'key_derivation': 'bip84',  # bip84, bip86
        'min_fee_rate': 1.0,
        'max_fee_rate': 100.0
    },
    
    # Development settings
    'development': {
        'debug_mode': False,
        'mock_services': False,
        'skip_validation': False,
        'unsafe_operations': False
    }
}

# Configuration profiles
PROFILES = {
    'production': {
        'network': {'type': 'mainnet'},
        'cli': {'confirm_destructive': True, 'verbose': 0},
        'security': {'require_confirmations': 6, 'enable_multisig': True},
        'development': {'debug_mode': False, 'mock_services': False}
    },
    'testnet': {
        'network': {'type': 'testnet'},
        'cli': {'confirm_destructive': True, 'verbose': 1},
        'security': {'require_confirmations': 3},
        'development': {'debug_mode': False}
    },
    'development': {
        'network': {'type': 'regtest'},
        'cli': {'confirm_destructive': False, 'verbose': 2},
        'security': {'require_confirmations': 1},
        'development': {'debug_mode': True, 'mock_services': True}
    }
}


class ConfigurationManager:
    """Manages hierarchical configuration with environment variable support."""
    
    def __init__(self, config_file: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Explicit configuration file path
            profile: Configuration profile to load (production, testnet, development)
        """
        self.logger = logging.getLogger('bnap-cli.config')
        self.config_file = config_file
        self.profile = profile
        self._config_cache = None
        self._config_sources = []
    
    def load(self) -> Dict[str, Any]:
        """
        Load configuration from all sources in hierarchical order.
        
        Returns:
            Merged configuration dictionary
        """
        if self._config_cache is not None:
            return self._config_cache
        
        configs = []
        
        # 1. Start with default configuration
        configs.append(DEFAULT_CONFIG.copy())
        self._config_sources.append("defaults")
        
        # 2. Apply profile if specified
        if self.profile and self.profile in PROFILES:
            profile_config = PROFILES[self.profile]
            configs.append(profile_config)
            self._config_sources.append(f"profile:{self.profile}")
            self.logger.debug(f"Applied profile: {self.profile}")
        
        # 3. Load configuration files
        if self.config_file:
            # Load specific config file
            config_data = self._load_config_file(Path(self.config_file))
            if config_data:
                configs.append(config_data)
                self._config_sources.append(f"file:{self.config_file}")
        else:
            # Search for config files in standard locations
            for config_path in CONFIG_SEARCH_PATHS:
                if config_path.exists():
                    config_data = self._load_config_file(config_path)
                    if config_data:
                        configs.append(config_data)
                        self._config_sources.append(f"file:{config_path}")
                        self.logger.debug(f"Loaded config from {config_path}")
                        break  # Use first found config file
        
        # 4. Apply environment variables
        env_config = self._load_environment_variables()
        if env_config:
            configs.append(env_config)
            self._config_sources.append("environment")
        
        # Merge all configurations (later ones override earlier ones)
        self._config_cache = self._deep_merge(*configs)
        
        # Expand paths
        self._expand_paths(self._config_cache)
        
        return self._config_cache
    
    def _load_config_file(self, path: Path) -> Optional[Dict[str, Any]]:
        """Load configuration from file."""
        try:
            with open(path, 'r') as f:
                if path.suffix in ['.yml', '.yaml']:
                    if HAS_YAML:
                        return yaml.safe_load(f)
                    else:
                        self.logger.warning(f"YAML support not available. Install PyYAML to use YAML configs.")
                        return None
                elif path.suffix == '.json':
                    return json.load(f)
                else:
                    self.logger.warning(f"Unknown config file format: {path}")
                    return None
        except Exception as e:
            self.logger.error(f"Failed to load config from {path}: {e}")
            return None
    
    def _load_environment_variables(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}
        
        for key, value in os.environ.items():
            if key.startswith(ENV_PREFIX):
                # Remove prefix and convert to lowercase
                config_key = key[len(ENV_PREFIX):].lower()
                
                # Convert underscores to nested dictionary structure
                # e.g., BNAP_NETWORK_TYPE -> {'network': {'type': value}}
                parts = config_key.split('_')
                current = env_config
                
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                
                # Convert value types
                current[parts[-1]] = self._parse_env_value(value)
        
        return env_config
    
    def _parse_env_value(self, value: str) -> Union[str, int, float, bool]:
        """Parse environment variable value to appropriate type."""
        # Try to parse as JSON first (for complex types)
        try:
            return json.loads(value)
        except:
            pass
        
        # Boolean values
        if value.lower() in ['true', 'yes', '1']:
            return True
        elif value.lower() in ['false', 'no', '0']:
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
    
    def _deep_merge(self, *dicts: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge multiple dictionaries."""
        result = {}
        
        for dictionary in dicts:
            for key, value in dictionary.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = self._deep_merge(result[key], value)
                else:
                    result[key] = value
        
        return result
    
    def _expand_paths(self, config: Dict[str, Any]):
        """Expand ~ and environment variables in path values."""
        for key, value in config.items():
            if isinstance(value, dict):
                self._expand_paths(value)
            elif isinstance(value, str):
                if '~' in value or '$' in value:
                    config[key] = os.path.expanduser(os.path.expandvars(value))
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation path.
        
        Args:
            key_path: Dot-separated path (e.g., 'network.bitcoin_rpc.host')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        config = self.load()
        
        keys = key_path.split('.')
        current = config
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    def set(self, key_path: str, value: Any):
        """
        Set configuration value by dot-notation path.
        
        Args:
            key_path: Dot-separated path (e.g., 'network.bitcoin_rpc.host')
            value: Value to set
        """
        config = self.load()
        
        keys = key_path.split('.')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
        self._config_cache = config
    
    def save(self, path: Optional[str] = None, format: str = 'yaml'):
        """
        Save current configuration to file.
        
        Args:
            path: File path to save to (default: project config file)
            format: Output format ('yaml' or 'json')
        """
        config = self.load()
        
        if not path:
            if format == 'yaml':
                path = Path.cwd() / '.bnap.yml'
            else:
                path = Path.cwd() / '.bnap.json'
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            if format == 'yaml':
                if HAS_YAML:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                else:
                    self.logger.warning("YAML support not available. Saving as JSON instead.")
                    json.dump(config, f, indent=2)
            else:
                json.dump(config, f, indent=2)
        
        self.logger.info(f"Configuration saved to {path}")
    
    def validate(self) -> List[str]:
        """
        Validate current configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        config = self.load()
        errors = []
        
        # Network validation
        network_type = config.get('network', {}).get('type')
        if network_type not in ['mainnet', 'testnet', 'regtest']:
            errors.append(f"Invalid network type: {network_type}")
        
        # Bitcoin RPC validation
        rpc_config = config.get('network', {}).get('bitcoin_rpc', {})
        if not rpc_config.get('host'):
            errors.append("Bitcoin RPC host is required")
        if not isinstance(rpc_config.get('port'), int) or rpc_config['port'] <= 0:
            errors.append("Bitcoin RPC port must be a positive integer")
        
        # CLI validation
        output_format = config.get('cli', {}).get('output_format')
        if output_format not in ['table', 'json', 'yaml', 'csv']:
            errors.append(f"Invalid output format: {output_format}")
        
        # Security validation
        min_fee = config.get('security', {}).get('min_fee_rate', 0)
        max_fee = config.get('security', {}).get('max_fee_rate', 0)
        if min_fee > max_fee:
            errors.append(f"Min fee rate ({min_fee}) cannot be greater than max fee rate ({max_fee})")
        
        return errors
    
    def get_sources(self) -> List[str]:
        """Get list of configuration sources that were loaded."""
        self.load()  # Ensure config is loaded
        return self._config_sources
    
    def export_environment(self) -> Dict[str, str]:
        """
        Export configuration as environment variables.
        
        Returns:
            Dictionary of environment variable names and values
        """
        config = self.load()
        env_vars = {}
        
        def flatten(obj: Dict[str, Any], prefix: str = ''):
            for key, value in obj.items():
                env_key = f"{prefix}_{key}".upper() if prefix else key.upper()
                
                if isinstance(value, dict):
                    flatten(value, env_key)
                else:
                    env_name = f"{ENV_PREFIX}{env_key}"
                    if isinstance(value, bool):
                        env_vars[env_name] = 'true' if value else 'false'
                    else:
                        env_vars[env_name] = str(value)
        
        flatten(config)
        return env_vars
    
    def reset(self):
        """Reset configuration cache."""
        self._config_cache = None
        self._config_sources = []


# Global configuration manager instance
_global_config_manager = None


def get_config_manager(config_file: Optional[str] = None, 
                       profile: Optional[str] = None) -> ConfigurationManager:
    """
    Get or create global configuration manager.
    
    Args:
        config_file: Optional configuration file path
        profile: Optional configuration profile
        
    Returns:
        Configuration manager instance
    """
    global _global_config_manager
    
    if _global_config_manager is None or config_file or profile:
        _global_config_manager = ConfigurationManager(config_file, profile)
    
    return _global_config_manager


def load_config(config_file: Optional[str] = None, 
                profile: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to load configuration.
    
    Args:
        config_file: Optional configuration file path
        profile: Optional configuration profile
        
    Returns:
        Configuration dictionary
    """
    manager = get_config_manager(config_file, profile)
    return manager.load()


def get_config_value(key_path: str, default: Any = None,
                    config_file: Optional[str] = None,
                    profile: Optional[str] = None) -> Any:
    """
    Convenience function to get a configuration value.
    
    Args:
        key_path: Dot-separated configuration path
        default: Default value if not found
        config_file: Optional configuration file path
        profile: Optional configuration profile
        
    Returns:
        Configuration value
    """
    manager = get_config_manager(config_file, profile)
    return manager.get(key_path, default)


def validate_config(config_file: Optional[str] = None,
                   profile: Optional[str] = None) -> List[str]:
    """
    Convenience function to validate configuration.
    
    Args:
        config_file: Optional configuration file path
        profile: Optional configuration profile
        
    Returns:
        List of validation errors
    """
    manager = get_config_manager(config_file, profile)
    return manager.validate()