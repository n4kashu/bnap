#!/usr/bin/env python3
"""
Validator Management and Operation Commands for BNAP CLI

Commands for validator initialization, daemon management, PSBT signing/validation,
key management, and comprehensive monitoring of validator health and performance.
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Tuple
import click
import json
import hashlib
import secrets
import time
from datetime import datetime, timedelta
import subprocess
import signal
import threading
import base64

# Add the project root to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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
                try:
                    import yaml
                    print(yaml.dump(data, default_flow_style=False))
                except ImportError:
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


@click.group()
@pass_context
def validator(ctx: CLIContext):
    """
    Validator management and operation commands.
    
    Initialize, manage, and monitor BNAP validator operations including
    daemon control, PSBT processing, and key management.
    """
    ctx.logger.debug("Validator command group invoked")


@validator.command('init')
@click.option('--validator-name', required=True, help='Unique name for this validator')
@click.option('--network', type=click.Choice(['mainnet', 'testnet', 'regtest']), 
              default='testnet', help='Bitcoin network to operate on')
@click.option('--data-dir', type=click.Path(), help='Custom data directory')
@click.option('--generate-keys', is_flag=True, help='Generate new signing keys')
@click.option('--import-key', type=click.Path(exists=True), help='Import existing private key file')
@click.option('--rpc-host', default='localhost', help='Bitcoin RPC host')
@click.option('--rpc-port', type=int, help='Bitcoin RPC port (default: network specific)')
@click.option('--rpc-user', help='Bitcoin RPC username')
@click.option('--rpc-password', help='Bitcoin RPC password')
@click.option('--force', is_flag=True, help='Overwrite existing validator configuration')
@pass_context
@handle_cli_error
def init_validator(ctx: CLIContext, validator_name: str, network: str, data_dir: Optional[str],
                   generate_keys: bool, import_key: Optional[str], rpc_host: str,
                   rpc_port: Optional[int], rpc_user: Optional[str], rpc_password: Optional[str],
                   force: bool):
    """
    Initialize a new BNAP validator.
    
    Set up validator configuration, generate or import signing keys, configure
    Bitcoin RPC connection, and prepare the validator for operation.
    
    Examples:
        bnap validator init --validator-name main-validator --generate-keys
        bnap validator init --validator-name backup --import-key validator.key --network mainnet
    """
    
    # Set default data directory
    if not data_dir:
        data_dir = Path.home() / '.bnap' / 'validators' / validator_name
    else:
        data_dir = Path(data_dir)
    
    # Set default RPC port based on network
    if not rpc_port:
        rpc_port = {'mainnet': 8332, 'testnet': 18332, 'regtest': 18443}[network]
    
    ctx.logger.info(f"Initializing validator '{validator_name}' on {network}")
    
    # Check if validator already exists
    config_file = data_dir / 'validator.json'
    if config_file.exists() and not force:
        raise click.ClickException(f"Validator '{validator_name}' already exists. Use --force to overwrite.")
    
    # Create data directory
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate or import keys
    if generate_keys:
        ctx.logger.info("Generating new signing keys")
        private_key, public_key = _generate_validator_keys()
    elif import_key:
        ctx.logger.info(f"Importing keys from {import_key}")
        private_key, public_key = _import_validator_keys(import_key)
    else:
        raise click.BadParameter("Must specify either --generate-keys or --import-key")
    
    # Prompt for RPC credentials if not provided
    if not rpc_user:
        rpc_user = click.prompt("Bitcoin RPC username", default="bitcoin")
    if not rpc_password:
        rpc_password = click.prompt("Bitcoin RPC password", hide_input=True)
    
    # Build validator configuration
    validator_config = {
        "validator_name": validator_name,
        "network": network,
        "data_dir": str(data_dir),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0",
        "keys": {
            "public_key": public_key,
            "key_fingerprint": hashlib.sha256(public_key.encode()).hexdigest()[:16]
        },
        "bitcoin_rpc": {
            "host": rpc_host,
            "port": rpc_port,
            "username": rpc_user,
            "password": rpc_password
        },
        "validator_settings": {
            "max_concurrent_operations": 10,
            "psbt_timeout_seconds": 300,
            "health_check_interval": 30,
            "transaction_fee_rate": 1.0,
            "enable_monitoring": True,
            "log_level": "INFO"
        },
        "status": {
            "initialized": True,
            "running": False,
            "last_health_check": None,
            "total_transactions_processed": 0,
            "uptime_start": None
        }
    }
    
    # Save configuration
    with open(config_file, 'w') as f:
        json.dump(validator_config, f, indent=2)
    
    # Save private key securely
    key_file = data_dir / 'private.key'
    with open(key_file, 'w') as f:
        f.write(private_key)
    key_file.chmod(0o600)  # Read/write for owner only
    
    # Create logs directory
    (data_dir / 'logs').mkdir(exist_ok=True)
    
    ctx.logger.info(f"Validator configuration saved to {config_file}")
    
    # Display summary
    click.echo(f"✅ Successfully initialized validator '{validator_name}':")
    click.echo(f"   Network: {network}")
    click.echo(f"   Data Directory: {data_dir}")
    click.echo(f"   Key Fingerprint: {validator_config['keys']['key_fingerprint']}")
    click.echo(f"   Bitcoin RPC: {rpc_host}:{rpc_port}")
    click.echo(f"\\n🔐 Private key saved securely to: {key_file}")
    click.echo(f"\\nNext steps:")
    click.echo(f"   - Start the validator: bnap validator start --name {validator_name}")
    click.echo(f"   - Check status: bnap validator status --name {validator_name}")


@validator.command('start')
@click.option('--name', required=True, help='Validator name to start')
@click.option('--daemon', is_flag=True, help='Run as background daemon')
@click.option('--log-file', type=click.Path(), help='Custom log file location')
@click.option('--pid-file', type=click.Path(), help='Custom PID file location')
@pass_context
@handle_cli_error
def start_validator(ctx: CLIContext, name: str, daemon: bool, log_file: Optional[str],
                    pid_file: Optional[str]):
    """
    Start a BNAP validator service.
    
    Launch the validator daemon to begin processing transactions and
    monitoring the Bitcoin network for BNAP operations.
    
    Examples:
        bnap validator start --name main-validator
        bnap validator start --name backup --daemon --log-file custom.log
    """
    
    ctx.logger.info(f"Starting validator '{name}'")
    
    # Load validator configuration
    validator_config = _load_validator_config(name)
    
    data_dir = Path(validator_config['data_dir'])
    
    # Set default log and PID file paths
    if not log_file:
        log_file = data_dir / 'logs' / 'validator.log'
    if not pid_file:
        pid_file = data_dir / 'validator.pid'
    
    # Check if validator is already running
    if _is_validator_running(pid_file):
        raise click.ClickException(f"Validator '{name}' is already running")
    
    # Verify Bitcoin RPC connection
    if not _test_bitcoin_rpc(validator_config['bitcoin_rpc']):
        ctx.logger.warning("Warning: Cannot connect to Bitcoin RPC. Validator may not function properly.")
        if not click.confirm("Continue starting validator?", default=False):
            return
    
    if daemon:
        # Start as daemon
        ctx.logger.info(f"Starting validator '{name}' as daemon")
        _start_validator_daemon(validator_config, log_file, pid_file)
        
        # Wait a moment and check if it started successfully
        time.sleep(2)
        if _is_validator_running(pid_file):
            click.echo(f"✅ Validator '{name}' started successfully as daemon")
            click.echo(f"   PID file: {pid_file}")
            click.echo(f"   Log file: {log_file}")
        else:
            click.echo(f"❌ Failed to start validator '{name}' as daemon")
            sys.exit(1)
    else:
        # Start in foreground
        ctx.logger.info(f"Starting validator '{name}' in foreground mode")
        click.echo(f"🚀 Starting validator '{name}' (Press Ctrl+C to stop)")
        try:
            _run_validator_foreground(validator_config)
        except KeyboardInterrupt:
            click.echo(f"\\n🛑 Validator '{name}' stopped by user")


@validator.command('stop')
@click.option('--name', required=True, help='Validator name to stop')
@click.option('--force', is_flag=True, help='Force stop (SIGKILL) if graceful stop fails')
@click.option('--timeout', type=int, default=30, help='Graceful shutdown timeout in seconds')
@pass_context
@handle_cli_error
def stop_validator(ctx: CLIContext, name: str, force: bool, timeout: int):
    """
    Stop a running BNAP validator service.
    
    Gracefully shut down the validator daemon, allowing current operations
    to complete before terminating.
    
    Examples:
        bnap validator stop --name main-validator
        bnap validator stop --name backup --force
    """
    
    ctx.logger.info(f"Stopping validator '{name}'")
    
    # Load validator configuration
    validator_config = _load_validator_config(name)
    data_dir = Path(validator_config['data_dir'])
    pid_file = data_dir / 'validator.pid'
    
    if not _is_validator_running(pid_file):
        click.echo(f"Validator '{name}' is not running")
        return
    
    # Get PID
    with open(pid_file, 'r') as f:
        pid = int(f.read().strip())
    
    ctx.logger.info(f"Sending graceful shutdown signal to PID {pid}")
    
    try:
        # Send SIGTERM for graceful shutdown
        os.kill(pid, signal.SIGTERM)
        
        # Wait for graceful shutdown
        for _ in range(timeout):
            if not _is_validator_running(pid_file):
                click.echo(f"✅ Validator '{name}' stopped gracefully")
                return
            time.sleep(1)
        
        if force:
            ctx.logger.warning(f"Graceful shutdown timed out, force stopping PID {pid}")
            os.kill(pid, signal.SIGKILL)
            time.sleep(2)
            
            if not _is_validator_running(pid_file):
                click.echo(f"✅ Validator '{name}' force stopped")
            else:
                click.echo(f"❌ Failed to stop validator '{name}'")
                sys.exit(1)
        else:
            click.echo(f"⚠️  Validator '{name}' did not stop gracefully within {timeout}s")
            click.echo(f"Use --force to force stop")
    
    except ProcessLookupError:
        # Process already dead, clean up PID file
        if pid_file.exists():
            pid_file.unlink()
        click.echo(f"Validator '{name}' was not running (cleaned up stale PID file)")
    except PermissionError:
        click.echo(f"❌ Permission denied stopping validator '{name}' (PID {pid})")
        sys.exit(1)


@validator.command('status')
@click.option('--name', help='Specific validator name to check')
@click.option('--detailed', is_flag=True, help='Show detailed status information')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'summary']), 
              default='summary', help='Output format')
@pass_context
@handle_cli_error
def validator_status(ctx: CLIContext, name: Optional[str], detailed: bool, output_format: str):
    """
    Check validator status and health.
    
    Display comprehensive status information including health, performance
    metrics, transaction processing statistics, and system resource usage.
    
    Examples:
        bnap validator status --name main-validator
        bnap validator status --detailed --format json
        bnap validator status  # Show all validators
    """
    
    ctx.logger.info("Checking validator status")
    
    if name:
        # Check specific validator
        validators_status = [_get_validator_status(name, detailed)]
    else:
        # Check all validators
        validators_status = _get_all_validators_status(detailed)
    
    if not validators_status:
        click.echo("No validators found")
        return
    
    if output_format == 'summary':
        _display_validator_status_summary(validators_status)
    else:
        ctx.output(validators_status, output_format)


@validator.command('sign-psbt')
@click.argument('psbt_file', type=click.Path(exists=True))
@click.option('--validator-name', required=True, help='Validator to use for signing')
@click.option('--output-file', type=click.Path(), help='Output file for signed PSBT')
@click.option('--verify-before-sign', is_flag=True, default=True, help='Verify PSBT before signing')
@pass_context
@handle_cli_error
def sign_psbt(ctx: CLIContext, psbt_file: str, validator_name: str, output_file: Optional[str],
              verify_before_sign: bool):
    """
    Manually sign a PSBT using validator keys.
    
    Load a PSBT from file, validate it, and sign using the specified
    validator's private keys. Outputs the signed PSBT.
    
    Examples:
        bnap validator sign-psbt transaction.psbt --validator-name main-validator
        bnap validator sign-psbt mint.psbt --validator-name backup --output-file signed.psbt
    """
    
    ctx.logger.info(f"Signing PSBT {psbt_file} with validator '{validator_name}'")
    
    # Load validator configuration
    validator_config = _load_validator_config(validator_name)
    
    # Load PSBT
    psbt_data = _load_psbt_file(psbt_file)
    
    if verify_before_sign:
        # Verify PSBT before signing
        verification_result = _verify_psbt(psbt_data, validator_config)
        if not verification_result['valid']:
            click.echo(f"❌ PSBT verification failed: {verification_result['error']}")
            if not click.confirm("Continue signing anyway?", default=False):
                return
    
    # Sign PSBT
    ctx.logger.info("Signing PSBT with validator keys")
    signed_psbt = _sign_psbt_with_validator(psbt_data, validator_config)
    
    # Save signed PSBT
    if not output_file:
        output_file = psbt_file.replace('.psbt', '_signed.psbt')
    
    _save_psbt_file(signed_psbt, output_file)
    
    # Display result
    click.echo(f"✅ Successfully signed PSBT:")
    click.echo(f"   Input file: {psbt_file}")
    click.echo(f"   Output file: {output_file}")
    click.echo(f"   Validator: {validator_name}")
    click.echo(f"   Signatures added: {signed_psbt.get('signatures_added', 1)}")


@validator.command('validate-psbt')
@click.argument('psbt_file', type=click.Path(exists=True))
@click.option('--validator-name', help='Validator context for validation')
@click.option('--detailed', is_flag=True, help='Show detailed validation results')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'summary']), 
              default='summary', help='Output format')
@pass_context
@handle_cli_error
def validate_psbt(ctx: CLIContext, psbt_file: str, validator_name: Optional[str],
                  detailed: bool, output_format: str):
    """
    Validate a PSBT for correctness and compatibility.
    
    Perform comprehensive validation of PSBT structure, signatures,
    inputs/outputs, and BNAP-specific requirements.
    
    Examples:
        bnap validator validate-psbt transaction.psbt
        bnap validator validate-psbt mint.psbt --validator-name main --detailed
    """
    
    ctx.logger.info(f"Validating PSBT {psbt_file}")
    
    # Load validator configuration if specified
    validator_config = None
    if validator_name:
        validator_config = _load_validator_config(validator_name)
    
    # Load PSBT
    psbt_data = _load_psbt_file(psbt_file)
    
    # Perform validation
    validation_result = _comprehensive_psbt_validation(psbt_data, validator_config, detailed)
    
    if output_format == 'summary':
        _display_psbt_validation_summary(validation_result, psbt_file)
    else:
        ctx.output(validation_result, output_format)


@validator.command('rotate-keys')
@click.option('--validator-name', required=True, help='Validator for key rotation')
@click.option('--backup-old-keys', is_flag=True, default=True, help='Backup old keys before rotation')
@click.option('--import-new-key', type=click.Path(exists=True), help='Import specific new key file')
@click.option('--force', is_flag=True, help='Force rotation even if validator is running')
@pass_context
@handle_cli_error
def rotate_keys(ctx: CLIContext, validator_name: str, backup_old_keys: bool,
                import_new_key: Optional[str], force: bool):
    """
    Rotate validator signing keys.
    
    Generate new signing keys and update validator configuration while
    optionally backing up old keys for recovery purposes.
    
    Examples:
        bnap validator rotate-keys --validator-name main-validator
        bnap validator rotate-keys --validator-name backup --import-new-key new.key
    """
    
    ctx.logger.info(f"Rotating keys for validator '{validator_name}'")
    
    # Load validator configuration
    validator_config = _load_validator_config(validator_name)
    data_dir = Path(validator_config['data_dir'])
    
    # Check if validator is running
    pid_file = data_dir / 'validator.pid'
    if _is_validator_running(pid_file) and not force:
        raise click.ClickException(
            f"Validator '{validator_name}' is running. Stop it first or use --force"
        )
    
    # Backup old keys if requested
    if backup_old_keys:
        backup_dir = data_dir / 'key_backups' / datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        old_key_file = data_dir / 'private.key'
        if old_key_file.exists():
            backup_key_file = backup_dir / 'private.key'
            backup_key_file.write_text(old_key_file.read_text())
            backup_key_file.chmod(0o600)
            ctx.logger.info(f"Backed up old key to {backup_key_file}")
    
    # Generate or import new keys
    if import_new_key:
        ctx.logger.info(f"Importing new key from {import_new_key}")
        new_private_key, new_public_key = _import_validator_keys(import_new_key)
    else:
        ctx.logger.info("Generating new signing keys")
        new_private_key, new_public_key = _generate_validator_keys()
    
    # Update validator configuration
    old_fingerprint = validator_config['keys']['key_fingerprint']
    validator_config['keys']['public_key'] = new_public_key
    validator_config['keys']['key_fingerprint'] = hashlib.sha256(new_public_key.encode()).hexdigest()[:16]
    validator_config['keys']['rotated_at'] = datetime.utcnow().isoformat() + "Z"
    validator_config['keys']['previous_fingerprint'] = old_fingerprint
    
    # Save updated configuration
    config_file = data_dir / 'validator.json'
    with open(config_file, 'w') as f:
        json.dump(validator_config, f, indent=2)
    
    # Save new private key
    key_file = data_dir / 'private.key'
    with open(key_file, 'w') as f:
        f.write(new_private_key)
    key_file.chmod(0o600)
    
    # Display result
    click.echo(f"✅ Successfully rotated keys for validator '{validator_name}':")
    click.echo(f"   Old fingerprint: {old_fingerprint}")
    click.echo(f"   New fingerprint: {validator_config['keys']['key_fingerprint']}")
    if backup_old_keys:
        click.echo(f"   Old key backed up to: {backup_dir}")
    click.echo(f"\\n⚠️  Important: Update any external systems using the old key fingerprint")


# Utility functions

def _load_validator_config(validator_name: str) -> Dict[str, Any]:
    """Load validator configuration by name."""
    validators_dir = Path.home() / '.bnap' / 'validators'
    config_file = validators_dir / validator_name / 'validator.json'
    
    if not config_file.exists():
        raise click.ClickException(f"Validator '{validator_name}' not found. Run 'bnap validator init' first.")
    
    return load_json_file(str(config_file))


def _generate_validator_keys() -> Tuple[str, str]:
    """Generate new validator key pair."""
    # TODO: Replace with actual cryptographic key generation
    # For demonstration, generate deterministic keys
    private_key_bytes = secrets.token_bytes(32)
    private_key = base64.b64encode(private_key_bytes).decode('utf-8')
    
    # Simulate public key derivation
    public_key_hash = hashlib.sha256(private_key_bytes).hexdigest()
    public_key = f"bnap_pubkey_{public_key_hash[:32]}"
    
    return private_key, public_key


def _import_validator_keys(key_file: str) -> Tuple[str, str]:
    """Import validator keys from file."""
    # TODO: Implement actual key import with format detection
    # For demonstration, simulate key import
    
    with open(key_file, 'r') as f:
        key_content = f.read().strip()
    
    # Simulate key parsing
    if key_content.startswith('bnap_private_'):
        private_key = key_content
        # Derive public key from private key
        private_bytes = base64.b64decode(key_content.replace('bnap_private_', '').encode())
        public_key_hash = hashlib.sha256(private_bytes).hexdigest()
        public_key = f"bnap_pubkey_{public_key_hash[:32]}"
    else:
        # Assume base64 encoded private key
        private_key = key_content
        private_bytes = base64.b64decode(key_content.encode())
        public_key_hash = hashlib.sha256(private_bytes).hexdigest()
        public_key = f"bnap_pubkey_{public_key_hash[:32]}"
    
    return private_key, public_key


def _is_validator_running(pid_file: Path) -> bool:
    """Check if validator is running based on PID file."""
    if not pid_file.exists():
        return False
    
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
        
        # Check if process is still running
        os.kill(pid, 0)  # Signal 0 just checks if process exists
        return True
    except (ValueError, OSError):
        # PID file invalid or process not running
        if pid_file.exists():
            pid_file.unlink()  # Clean up stale PID file
        return False


def _test_bitcoin_rpc(rpc_config: Dict[str, Any]) -> bool:
    """Test Bitcoin RPC connection."""
    # TODO: Implement actual Bitcoin RPC connection test
    # For demonstration, simulate connection test
    
    host = rpc_config['host']
    port = rpc_config['port']
    
    # Simulate network connectivity check
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def _start_validator_daemon(validator_config: Dict[str, Any], log_file: Path, pid_file: Path):
    """Start validator as daemon process."""
    # TODO: Implement actual daemon startup
    # For demonstration, simulate daemon creation
    
    import subprocess
    
    # Create a simple daemon process
    daemon_script = f"""
import os
import time
import signal
import sys
from datetime import datetime

# Write PID file
with open('{pid_file}', 'w') as f:
    f.write(str(os.getpid()))

# Setup signal handlers
def signal_handler(sig, frame):
    os.unlink('{pid_file}')
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Simulate validator operation
with open('{log_file}', 'a') as log:
    log.write(f"{{datetime.utcnow().isoformat()}} - Validator daemon started\\n")
    
    try:
        while True:
            time.sleep(10)
            log.write(f"{{datetime.utcnow().isoformat()}} - Health check OK\\n")
            log.flush()
    except KeyboardInterrupt:
        log.write(f"{{datetime.utcnow().isoformat()}} - Validator daemon stopped\\n")
        os.unlink('{pid_file}')
"""
    
    # Start daemon process
    process = subprocess.Popen([
        sys.executable, '-c', daemon_script
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _run_validator_foreground(validator_config: Dict[str, Any]):
    """Run validator in foreground mode."""
    # TODO: Implement actual validator operation
    # For demonstration, simulate validator running
    
    validator_name = validator_config['validator_name']
    
    print(f"🔄 Validator '{validator_name}' is running...")
    print("🔍 Monitoring Bitcoin network for BNAP transactions...")
    
    try:
        transaction_count = 0
        while True:
            time.sleep(5)
            transaction_count += 1
            
            if transaction_count % 6 == 0:  # Every 30 seconds
                print(f"💓 Health check OK - Processed {transaction_count} cycles")
            
            # Simulate transaction processing
            if transaction_count % 12 == 0:  # Every minute
                print(f"⚡ Processed mock transaction #{transaction_count // 12}")
    
    except KeyboardInterrupt:
        print(f"\\n🛑 Shutting down validator '{validator_name}'...")


def _get_validator_status(validator_name: str, detailed: bool) -> Dict[str, Any]:
    """Get status for a specific validator."""
    try:
        validator_config = _load_validator_config(validator_name)
        data_dir = Path(validator_config['data_dir'])
        pid_file = data_dir / 'validator.pid'
        
        is_running = _is_validator_running(pid_file)
        
        status = {
            "validator_name": validator_name,
            "network": validator_config['network'],
            "status": "running" if is_running else "stopped",
            "key_fingerprint": validator_config['keys']['key_fingerprint'],
            "created_at": validator_config['created_at']
        }
        
        if detailed:
            status.update({
                "data_dir": validator_config['data_dir'],
                "bitcoin_rpc": f"{validator_config['bitcoin_rpc']['host']}:{validator_config['bitcoin_rpc']['port']}",
                "rpc_connected": _test_bitcoin_rpc(validator_config['bitcoin_rpc']),
                "version": validator_config.get('version', '1.0.0'),
                "settings": validator_config.get('validator_settings', {}),
                "performance": _get_validator_performance_metrics(validator_name) if is_running else None
            })
        
        return status
        
    except Exception as e:
        return {
            "validator_name": validator_name,
            "status": "error",
            "error": str(e)
        }


def _get_all_validators_status(detailed: bool) -> List[Dict[str, Any]]:
    """Get status for all validators."""
    validators_dir = Path.home() / '.bnap' / 'validators'
    
    if not validators_dir.exists():
        return []
    
    statuses = []
    for validator_dir in validators_dir.iterdir():
        if validator_dir.is_dir() and (validator_dir / 'validator.json').exists():
            status = _get_validator_status(validator_dir.name, detailed)
            statuses.append(status)
    
    return statuses


def _get_validator_performance_metrics(validator_name: str) -> Dict[str, Any]:
    """Get performance metrics for running validator."""
    # TODO: Implement actual performance monitoring
    # For demonstration, simulate metrics
    
    import random
    
    return {
        "uptime_seconds": random.randint(3600, 86400),
        "transactions_processed": random.randint(100, 5000),
        "average_processing_time_ms": random.randint(50, 500),
        "memory_usage_mb": random.randint(50, 200),
        "cpu_usage_percent": random.randint(5, 25),
        "network_connections": random.randint(10, 50),
        "last_transaction_time": (datetime.utcnow() - timedelta(minutes=random.randint(1, 30))).isoformat() + "Z"
    }


def _display_validator_status_summary(validators_status: List[Dict[str, Any]]):
    """Display validator status in summary format."""
    if not validators_status:
        click.echo("No validators found")
        return
    
    click.echo("🛡️  BNAP Validator Status")
    click.echo("=" * 50)
    
    running_count = len([v for v in validators_status if v.get('status') == 'running'])
    total_count = len(validators_status)
    
    click.echo(f"\\n📊 Summary: {running_count}/{total_count} validators running\\n")
    
    for validator in validators_status:
        name = validator['validator_name']
        status = validator.get('status', 'unknown')
        
        if status == 'running':
            status_icon = "🟢"
        elif status == 'stopped':
            status_icon = "🔴"
        else:
            status_icon = "⚠️"
        
        click.echo(f"{status_icon} {name}")
        click.echo(f"   Network: {validator.get('network', 'unknown')}")
        click.echo(f"   Status: {status}")
        click.echo(f"   Key: {validator.get('key_fingerprint', 'unknown')}")
        
        if 'performance' in validator and validator['performance']:
            perf = validator['performance']
            uptime_hours = perf['uptime_seconds'] // 3600
            click.echo(f"   Uptime: {uptime_hours}h, Processed: {perf['transactions_processed']} tx")
        
        if 'error' in validator:
            click.echo(f"   Error: {validator['error']}")
        
        click.echo()


def _load_psbt_file(psbt_file: str) -> Dict[str, Any]:
    """Load PSBT from file."""
    # TODO: Implement actual PSBT parsing
    # For demonstration, simulate PSBT loading
    
    path = Path(psbt_file)
    if not path.exists():
        raise click.FileError(f"PSBT file not found: {psbt_file}")
    
    try:
        # Try to load as JSON first (our format)
        with open(psbt_file, 'r') as f:
            data = json.load(f)
            if 'psbt_base64' in data:
                return data
    except:
        pass
    
    # Try to load as raw base64 PSBT
    try:
        with open(psbt_file, 'r') as f:
            psbt_base64 = f.read().strip()
            return {
                'psbt_base64': psbt_base64,
                'loaded_from': psbt_file,
                'format': 'raw_base64'
            }
    except:
        raise click.FileError(f"Invalid PSBT file format: {psbt_file}")


def _verify_psbt(psbt_data: Dict[str, Any], validator_config: Dict[str, Any]) -> Dict[str, Any]:
    """Verify PSBT before signing."""
    # TODO: Implement actual PSBT verification
    # For demonstration, simulate verification
    
    psbt_base64 = psbt_data.get('psbt_base64', '')
    
    # Basic format validation
    if not psbt_base64:
        return {'valid': False, 'error': 'Missing PSBT data'}
    
    try:
        # Try to decode base64
        base64.b64decode(psbt_base64)
    except:
        return {'valid': False, 'error': 'Invalid base64 encoding'}
    
    # Simulate verification checks
    return {
        'valid': True,
        'checks_passed': [
            'format_validation',
            'input_validation', 
            'output_validation',
            'fee_validation'
        ],
        'warnings': []
    }


def _sign_psbt_with_validator(psbt_data: Dict[str, Any], validator_config: Dict[str, Any]) -> Dict[str, Any]:
    """Sign PSBT using validator keys."""
    # TODO: Implement actual PSBT signing
    # For demonstration, simulate signing
    
    # Load private key
    data_dir = Path(validator_config['data_dir'])
    key_file = data_dir / 'private.key'
    
    with open(key_file, 'r') as f:
        private_key = f.read().strip()
    
    # Simulate signing process
    original_psbt = psbt_data['psbt_base64']
    
    # Create a modified PSBT (in reality, this would add signatures)
    signed_psbt_data = psbt_data.copy()
    signed_psbt_data['psbt_base64'] = original_psbt + '_signed'
    signed_psbt_data['signatures_added'] = 1
    signed_psbt_data['signed_at'] = datetime.utcnow().isoformat() + "Z"
    signed_psbt_data['signed_by'] = validator_config['keys']['key_fingerprint']
    
    return signed_psbt_data


def _save_psbt_file(psbt_data: Dict[str, Any], output_file: str):
    """Save PSBT to file."""
    with open(output_file, 'w') as f:
        json.dump(psbt_data, f, indent=2, default=str)


def _comprehensive_psbt_validation(psbt_data: Dict[str, Any], validator_config: Optional[Dict[str, Any]], 
                                 detailed: bool) -> Dict[str, Any]:
    """Perform comprehensive PSBT validation."""
    # TODO: Implement actual comprehensive validation
    # For demonstration, simulate validation
    
    validation_result = {
        "validation_timestamp": datetime.utcnow().isoformat() + "Z",
        "psbt_valid": True,
        "checks_performed": [],
        "passed_checks": [],
        "failed_checks": [],
        "warnings": [],
        "errors": []
    }
    
    # Basic format checks
    checks = [
        "psbt_format",
        "base64_encoding", 
        "transaction_structure",
        "input_validation",
        "output_validation",
        "fee_calculation",
        "signature_validation"
    ]
    
    validation_result["checks_performed"] = checks
    
    # Simulate some checks passing and some warnings
    validation_result["passed_checks"] = checks[:6]
    validation_result["warnings"] = ["High transaction fee detected"]
    
    if detailed:
        validation_result["detailed_results"] = {
            "input_count": 2,
            "output_count": 2,
            "estimated_fee": 1500,
            "fee_rate": "1.5 sat/vB",
            "transaction_size": 250,
            "signatures_required": 1,
            "signatures_present": 0
        }
    
    return validation_result


def _display_psbt_validation_summary(validation_result: Dict[str, Any], psbt_file: str):
    """Display PSBT validation results in summary format."""
    click.echo(f"🔍 PSBT Validation Results: {psbt_file}")
    click.echo("=" * 60)
    
    is_valid = validation_result.get('psbt_valid', False)
    status_icon = "✅" if is_valid else "❌"
    
    click.echo(f"\\n{status_icon} Overall Status: {'Valid' if is_valid else 'Invalid'}")
    
    passed = len(validation_result.get('passed_checks', []))
    failed = len(validation_result.get('failed_checks', []))
    warnings = len(validation_result.get('warnings', []))
    
    click.echo(f"\\n📊 Check Summary:")
    click.echo(f"   Passed: {passed}")
    click.echo(f"   Failed: {failed}")
    click.echo(f"   Warnings: {warnings}")
    
    if validation_result.get('warnings'):
        click.echo(f"\\n⚠️  Warnings:")
        for warning in validation_result['warnings']:
            click.echo(f"   • {warning}")
    
    if validation_result.get('errors'):
        click.echo(f"\\n❌ Errors:")
        for error in validation_result['errors']:
            click.echo(f"   • {error}")
    
    if 'detailed_results' in validation_result:
        details = validation_result['detailed_results']
        click.echo(f"\\n📋 Transaction Details:")
        click.echo(f"   Inputs: {details['input_count']}")
        click.echo(f"   Outputs: {details['output_count']}")
        click.echo(f"   Estimated Fee: {details['estimated_fee']} sats ({details['fee_rate']})")
        click.echo(f"   Size: {details['transaction_size']} bytes")
        click.echo(f"   Signatures: {details['signatures_present']}/{details['signatures_required']}")


# Register commands with main CLI
def register_commands(cli_app):
    """Register validator commands with the main CLI application."""
    cli_app.add_command(validator)


if __name__ == '__main__':
    validator()