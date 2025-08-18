#!/usr/bin/env python3
"""
Minting Operation Commands for BNAP CLI

Commands for minting fungible tokens and NFTs with PSBT (Partially Signed Bitcoin Transaction)
generation, asset validation, and batch processing capabilities.
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List, Union
import click
import json
import csv
from datetime import datetime
import base64
import hashlib
import secrets
import re

# Add the project root to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import dependencies without circular import
import logging


# Global CLI context from main module (duplicated to avoid circular imports)
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
def mint(ctx: CLIContext):
    """
    Minting operation commands.
    
    Mint fungible tokens and NFTs for registered assets with PSBT generation.
    """
    ctx.logger.debug("Mint command group invoked")


@mint.command('mint-fungible')
@click.option('--asset-id', required=True, help='Asset ID for the fungible token')
@click.option('--amount', type=int, required=True, help='Amount to mint')
@click.option('--recipient', help='Bitcoin address to receive minted tokens')
@click.option('--fee-rate', type=float, default=1.0, help='Transaction fee rate (sat/vB)')
@click.option('--from-file', type=click.Path(exists=True), help='Load minting parameters from JSON file')
@click.option('--output-file', type=click.Path(), help='Save PSBT to file')
@click.option('--dry-run', is_flag=True, help='Validate parameters without generating PSBT')
@click.option('--interactive', is_flag=True, help='Interactive mode with prompts')
@pass_context
@handle_cli_error
def mint_fungible(ctx: CLIContext, asset_id: str, amount: int, recipient: Optional[str],
                  fee_rate: float, from_file: Optional[str], output_file: Optional[str],
                  dry_run: bool, interactive: bool):
    """
    Mint fungible tokens.
    
    Generate a PSBT for minting fungible tokens to a specified recipient address.
    Validates against asset supply limits and minting rules.
    
    Examples:
        bnap mint mint-fungible --asset-id fungible_btk_123 --amount 1000 --recipient bc1q...
        bnap mint mint-fungible --from-file mint_params.json --dry-run
    """
    
    if from_file:
        ctx.logger.info(f"Loading minting parameters from {from_file}")
        params = load_json_file(from_file)
        
        # Override with CLI options if provided
        asset_id = asset_id or params.get('asset_id')
        amount = amount or params.get('amount')
        recipient = recipient or params.get('recipient')
        fee_rate = fee_rate or params.get('fee_rate', 1.0)
    
    # Interactive mode prompts
    if interactive:
        if not asset_id:
            asset_id = click.prompt("Asset ID")
        if not amount:
            amount = click.prompt("Amount to mint", type=int)
        if not recipient:
            recipient = click.prompt("Recipient address")
    
    # Validate inputs
    if not asset_id:
        raise click.BadParameter("Asset ID is required")
    
    if not amount or amount <= 0:
        raise click.BadParameter("Amount must be positive")
    
    if not recipient:
        raise click.BadParameter("Recipient address is required")
    
    if not _validate_bitcoin_address(recipient):
        raise click.BadParameter(f"Invalid Bitcoin address: {recipient}")
    
    if fee_rate <= 0:
        raise click.BadParameter("Fee rate must be positive")
    
    ctx.logger.info(f"Processing fungible token mint: {asset_id}")
    
    # TODO: Fetch actual asset information from registry
    # For now, simulate asset validation
    asset_info = _simulate_asset_lookup(asset_id)
    
    if not asset_info:
        raise click.ClickException(f"Asset not found: {asset_id}")
    
    if asset_info['asset_type'] != 'fungible':
        raise click.ClickException(f"Asset {asset_id} is not a fungible token")
    
    # Validate against asset rules
    _validate_fungible_mint(asset_info, amount)
    
    # Build minting operation
    mint_operation = {
        "operation_type": "mint_fungible",
        "asset_id": asset_id,
        "amount": amount,
        "recipient": recipient,
        "fee_rate": fee_rate,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "operation_id": _generate_operation_id()
    }
    
    if dry_run:
        ctx.logger.info("Dry run mode - validating parameters only")
        ctx.output(mint_operation)
        click.echo("✅ Minting parameters are valid")
        return
    
    # Display operation for confirmation
    ctx.output(mint_operation, "table")
    
    if not click.confirm(f"\\nMint {amount} tokens of {asset_id} to {recipient}?", default=True):
        ctx.logger.info("Minting operation cancelled by user")
        return
    
    # Generate PSBT
    ctx.logger.info("Generating PSBT for minting operation")
    psbt_data = _generate_fungible_mint_psbt(mint_operation, asset_info)
    
    # Save to file if requested
    if output_file:
        _save_psbt_file(psbt_data, output_file)
        ctx.logger.info(f"PSBT saved to {output_file}")
    
    # Display success message
    click.echo(f"\\n✅ Successfully generated minting PSBT:")
    click.echo(f"   Operation ID: {mint_operation['operation_id']}")
    click.echo(f"   Asset: {asset_id}")
    click.echo(f"   Amount: {amount:,} tokens")
    click.echo(f"   Recipient: {recipient}")
    click.echo(f"   Estimated Fee: {psbt_data['estimated_fee']} sats")
    click.echo(f"\\n📋 PSBT (base64):")
    click.echo(psbt_data['psbt_base64'])


@mint.command('mint-nft')
@click.option('--collection-id', required=True, help='Collection ID for the NFT')
@click.option('--token-id', type=int, help='Specific token ID (auto-assigned if not provided)')
@click.option('--metadata', help='NFT metadata JSON string or file path')
@click.option('--recipient', help='Bitcoin address to receive minted NFT')
@click.option('--fee-rate', type=float, default=1.0, help='Transaction fee rate (sat/vB)')
@click.option('--from-file', type=click.Path(exists=True), help='Load minting parameters from JSON file')
@click.option('--output-file', type=click.Path(), help='Save PSBT to file')
@click.option('--dry-run', is_flag=True, help='Validate parameters without generating PSBT')
@click.option('--interactive', is_flag=True, help='Interactive mode with prompts')
@pass_context
@handle_cli_error
def mint_nft(ctx: CLIContext, collection_id: str, token_id: Optional[int], 
             metadata: Optional[str], recipient: Optional[str], fee_rate: float,
             from_file: Optional[str], output_file: Optional[str],
             dry_run: bool, interactive: bool):
    """
    Mint NFTs from a collection.
    
    Generate a PSBT for minting an NFT with specified metadata to a recipient address.
    Validates against collection supply limits and minting phases.
    
    Examples:
        bnap mint mint-nft --collection-id nft_art_123 --metadata '{"name":"Art #1"}' --recipient bc1q...
        bnap mint mint-nft --from-file nft_params.json --token-id 42
    """
    
    if from_file:
        ctx.logger.info(f"Loading NFT minting parameters from {from_file}")
        params = load_json_file(from_file)
        
        # Override with CLI options if provided
        collection_id = collection_id or params.get('collection_id')
        token_id = token_id or params.get('token_id')
        metadata = metadata or params.get('metadata')
        recipient = recipient or params.get('recipient')
        fee_rate = fee_rate or params.get('fee_rate', 1.0)
    
    # Interactive mode prompts
    if interactive:
        if not collection_id:
            collection_id = click.prompt("Collection ID")
        if not token_id:
            token_id = click.prompt("Token ID (leave empty for auto-assignment)", default="", show_default=False)
            token_id = int(token_id) if token_id else None
        if not metadata:
            metadata = click.prompt("Metadata (JSON string or file path)")
        if not recipient:
            recipient = click.prompt("Recipient address")
    
    # Validate inputs
    if not collection_id:
        raise click.BadParameter("Collection ID is required")
    
    if not recipient:
        raise click.BadParameter("Recipient address is required")
    
    if not _validate_bitcoin_address(recipient):
        raise click.BadParameter(f"Invalid Bitcoin address: {recipient}")
    
    if fee_rate <= 0:
        raise click.BadParameter("Fee rate must be positive")
    
    # Parse metadata
    nft_metadata = _parse_nft_metadata(metadata)
    
    ctx.logger.info(f"Processing NFT mint: {collection_id}")
    
    # TODO: Fetch actual collection information from registry
    # For now, simulate collection validation
    collection_info = _simulate_collection_lookup(collection_id)
    
    if not collection_info:
        raise click.ClickException(f"Collection not found: {collection_id}")
    
    # Validate against collection rules
    assigned_token_id = _validate_nft_mint(collection_info, token_id)
    
    # Build minting operation
    mint_operation = {
        "operation_type": "mint_nft",
        "collection_id": collection_id,
        "token_id": assigned_token_id,
        "metadata": nft_metadata,
        "recipient": recipient,
        "fee_rate": fee_rate,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "operation_id": _generate_operation_id()
    }
    
    if dry_run:
        ctx.logger.info("Dry run mode - validating parameters only")
        ctx.output(mint_operation)
        click.echo("✅ NFT minting parameters are valid")
        return
    
    # Display operation for confirmation
    ctx.output(mint_operation, "table")
    
    if not click.confirm(f"\\nMint NFT #{assigned_token_id} from collection {collection_id} to {recipient}?", default=True):
        ctx.logger.info("NFT minting operation cancelled by user")
        return
    
    # Generate PSBT
    ctx.logger.info("Generating PSBT for NFT minting operation")
    psbt_data = _generate_nft_mint_psbt(mint_operation, collection_info)
    
    # Save to file if requested
    if output_file:
        _save_psbt_file(psbt_data, output_file)
        ctx.logger.info(f"PSBT saved to {output_file}")
    
    # Display success message
    click.echo(f"\\n✅ Successfully generated NFT minting PSBT:")
    click.echo(f"   Operation ID: {mint_operation['operation_id']}")
    click.echo(f"   Collection: {collection_id}")
    click.echo(f"   Token ID: {assigned_token_id}")
    click.echo(f"   Recipient: {recipient}")
    click.echo(f"   Estimated Fee: {psbt_data['estimated_fee']} sats")
    click.echo(f"\\n📋 PSBT (base64):")
    click.echo(psbt_data['psbt_base64'])


@mint.command('batch-mint')
@click.option('--batch-file', type=click.Path(exists=True), required=True, 
              help='CSV or JSON file with batch minting operations')
@click.option('--output-dir', type=click.Path(), default="./batch_output", 
              help='Directory to save generated PSBTs')
@click.option('--dry-run', is_flag=True, help='Validate batch without generating PSBTs')
@click.option('--continue-on-error', is_flag=True, help='Continue processing on individual failures')
@click.option('--format', 'batch_format', type=click.Choice(['csv', 'json']), 
              help='Override batch file format detection')
@pass_context
@handle_cli_error
def batch_mint(ctx: CLIContext, batch_file: str, output_dir: str, dry_run: bool,
               continue_on_error: bool, batch_format: Optional[str]):
    """
    Batch mint multiple assets from CSV or JSON file.
    
    Process multiple minting operations from a structured file. Supports both
    fungible token and NFT minting with validation and PSBT generation.
    
    CSV Format:
        operation_type,asset_id,amount,recipient,metadata
        mint_fungible,fungible_btk_123,1000,bc1q...,
        mint_nft,nft_art_456,,bc1q...,'{"name":"Art #1"}'
    
    Examples:
        bnap mint batch-mint --batch-file mints.csv
        bnap mint batch-mint --batch-file mints.json --dry-run
    """
    
    ctx.logger.info(f"Processing batch minting from {batch_file}")
    
    # Determine file format
    file_format = batch_format or _detect_file_format(batch_file)
    
    # Load batch operations
    if file_format == 'csv':
        operations = _load_csv_batch(batch_file)
    elif file_format == 'json':
        operations = _load_json_batch(batch_file)
    else:
        raise click.BadParameter(f"Unsupported file format: {file_format}")
    
    if not operations:
        raise click.ClickException("No valid operations found in batch file")
    
    ctx.logger.info(f"Found {len(operations)} operations to process")
    
    # Validate all operations first
    validation_errors = []
    for i, op in enumerate(operations):
        try:
            _validate_batch_operation(op)
        except Exception as e:
            validation_errors.append(f"Operation {i+1}: {e}")
    
    if validation_errors:
        click.echo("❌ Validation errors found:")
        for error in validation_errors:
            click.echo(f"   {error}")
        
        if not continue_on_error:
            raise click.ClickException("Fix validation errors before proceeding")
    
    if dry_run:
        ctx.logger.info("Dry run mode - showing batch summary only")
        summary = _generate_batch_summary(operations)
        ctx.output(summary, "table")
        click.echo("✅ Batch validation completed")
        return
    
    # Display batch summary
    summary = _generate_batch_summary(operations)
    ctx.output(summary, "table")
    
    if not click.confirm(f"\\nProcess {len(operations)} minting operations?", default=True):
        ctx.logger.info("Batch minting cancelled by user")
        return
    
    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Process operations
    successful_operations = []
    failed_operations = []
    
    with click.progressbar(operations, label='Processing operations') as bar:
        for i, operation in enumerate(bar):
            try:
                psbt_data = _process_batch_operation(operation)
                
                # Save PSBT to file
                output_file = Path(output_dir) / f"operation_{i+1}_{operation.get('operation_id', 'unknown')}.psbt"
                _save_psbt_file(psbt_data, str(output_file))
                
                successful_operations.append({
                    "index": i+1,
                    "operation_id": operation.get('operation_id'),
                    "output_file": str(output_file)
                })
                
            except Exception as e:
                failed_operations.append({
                    "index": i+1,
                    "operation_id": operation.get('operation_id'),
                    "error": str(e)
                })
                
                if not continue_on_error:
                    raise
    
    # Display results
    click.echo(f"\\n✅ Batch processing completed:")
    click.echo(f"   Successful: {len(successful_operations)}")
    click.echo(f"   Failed: {len(failed_operations)}")
    click.echo(f"   Output directory: {output_dir}")
    
    if failed_operations:
        click.echo("\\n❌ Failed operations:")
        for failure in failed_operations:
            click.echo(f"   Operation {failure['index']}: {failure['error']}")


# Utility functions

def _validate_bitcoin_address(address: str) -> bool:
    """Basic Bitcoin address validation."""
    if not address:
        return False
    
    # Basic format checks for different address types
    if address.startswith(('1', '3', 'bc1', 'tb1')):
        return len(address) >= 26 and len(address) <= 62
    
    return False


def _generate_operation_id() -> str:
    """Generate unique operation ID."""
    return f"mint_{int(datetime.utcnow().timestamp())}_{secrets.token_hex(4)}"


def _simulate_asset_lookup(asset_id: str) -> Optional[Dict[str, Any]]:
    """Simulate asset registry lookup."""
    # TODO: Replace with actual registry integration
    if "fungible" in asset_id:
        return {
            "asset_id": asset_id,
            "asset_type": "fungible",
            "name": "Sample Token",
            "symbol": "STK",
            "max_supply": 1000000,
            "current_supply": 250000,
            "per_mint_limit": 10000,
            "minting_enabled": True,
            "public_minting": True
        }
    return None


def _simulate_collection_lookup(collection_id: str) -> Optional[Dict[str, Any]]:
    """Simulate collection registry lookup."""
    # TODO: Replace with actual registry integration
    if "nft" in collection_id:
        return {
            "collection_id": collection_id,
            "asset_type": "nft_collection",
            "name": "Sample NFT Collection",
            "max_supply": 1000,
            "current_supply": 47,
            "next_token_id": 48,
            "minting_enabled": True,
            "public_minting": True
        }
    return None


def _validate_fungible_mint(asset_info: Dict[str, Any], amount: int):
    """Validate fungible token minting parameters."""
    if not asset_info.get('minting_enabled'):
        raise click.ClickException("Minting is disabled for this asset")
    
    max_supply = asset_info.get('max_supply')
    current_supply = asset_info.get('current_supply', 0)
    
    if max_supply and (current_supply + amount) > max_supply:
        raise click.ClickException(f"Minting would exceed max supply ({max_supply})")
    
    per_mint_limit = asset_info.get('per_mint_limit')
    if per_mint_limit and amount > per_mint_limit:
        raise click.ClickException(f"Amount exceeds per-mint limit ({per_mint_limit})")


def _validate_nft_mint(collection_info: Dict[str, Any], token_id: Optional[int]) -> int:
    """Validate NFT minting parameters and return assigned token ID."""
    if not collection_info.get('minting_enabled'):
        raise click.ClickException("Minting is disabled for this collection")
    
    max_supply = collection_info.get('max_supply')
    current_supply = collection_info.get('current_supply', 0)
    
    if max_supply and current_supply >= max_supply:
        raise click.ClickException(f"Collection has reached max supply ({max_supply})")
    
    # Assign token ID if not provided
    if token_id is None:
        token_id = collection_info.get('next_token_id', current_supply + 1)
    
    if token_id <= 0:
        raise click.ClickException("Token ID must be positive")
    
    return token_id


def _parse_nft_metadata(metadata: Optional[str]) -> Dict[str, Any]:
    """Parse NFT metadata from string or file."""
    if not metadata:
        return {}
    
    # Check if it's a file path
    if Path(metadata).exists():
        return load_json_file(metadata)
    
    # Try to parse as JSON string
    try:
        return json.loads(metadata)
    except json.JSONDecodeError:
        raise click.BadParameter("Invalid JSON metadata")


def _generate_fungible_mint_psbt(mint_operation: Dict[str, Any], asset_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate PSBT for fungible token minting."""
    # TODO: Implement actual PSBT generation
    # This is a simulation for demonstration
    
    # Simulate PSBT generation
    psbt_hex = _simulate_psbt_generation(mint_operation, "fungible")
    psbt_base64 = base64.b64encode(bytes.fromhex(psbt_hex)).decode('utf-8')
    
    return {
        "operation_id": mint_operation['operation_id'],
        "psbt_hex": psbt_hex,
        "psbt_base64": psbt_base64,
        "estimated_fee": 1500,  # Simulated fee in sats
        "inputs": 1,
        "outputs": 2
    }


def _generate_nft_mint_psbt(mint_operation: Dict[str, Any], collection_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate PSBT for NFT minting."""
    # TODO: Implement actual PSBT generation
    # This is a simulation for demonstration
    
    # Simulate PSBT generation
    psbt_hex = _simulate_psbt_generation(mint_operation, "nft")
    psbt_base64 = base64.b64encode(bytes.fromhex(psbt_hex)).decode('utf-8')
    
    return {
        "operation_id": mint_operation['operation_id'],
        "psbt_hex": psbt_hex,
        "psbt_base64": psbt_base64,
        "estimated_fee": 2000,  # Simulated fee in sats
        "inputs": 1,
        "outputs": 2
    }


def _simulate_psbt_generation(operation: Dict[str, Any], asset_type: str) -> str:
    """Simulate PSBT generation for demonstration."""
    # Create a deterministic but fake PSBT hex
    operation_hash = hashlib.sha256(json.dumps(operation, sort_keys=True).encode()).hexdigest()
    
    # Simulate PSBT structure (this is not a real PSBT)
    psbt_parts = [
        "70736274ff01",  # PSBT magic + separator
        "0100",  # Global unsigned tx
        operation_hash[:32],  # Simulated transaction data
        "0000",  # End markers
        operation_hash[32:64]  # More simulated data
    ]
    
    return "".join(psbt_parts)


def _save_psbt_file(psbt_data: Dict[str, Any], output_file: str):
    """Save PSBT data to file."""
    psbt_output = {
        "operation_id": psbt_data['operation_id'],
        "psbt_base64": psbt_data['psbt_base64'],
        "estimated_fee": psbt_data['estimated_fee'],
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    
    with open(output_file, 'w') as f:
        json.dump(psbt_output, f, indent=2)


def _detect_file_format(file_path: str) -> str:
    """Detect file format from extension."""
    extension = Path(file_path).suffix.lower()
    if extension == '.csv':
        return 'csv'
    elif extension in ['.json', '.jsonl']:
        return 'json'
    else:
        raise click.BadParameter(f"Unsupported file extension: {extension}")


def _load_csv_batch(file_path: str) -> List[Dict[str, Any]]:
    """Load batch operations from CSV file."""
    operations = []
    
    with open(file_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row_num, row in enumerate(reader, 1):
            try:
                operation = _normalize_batch_operation(row)
                operation['_row_number'] = row_num
                operations.append(operation)
            except Exception as e:
                raise click.ClickException(f"Error in CSV row {row_num}: {e}")
    
    return operations


def _load_json_batch(file_path: str) -> List[Dict[str, Any]]:
    """Load batch operations from JSON file."""
    data = load_json_file(file_path)
    
    if isinstance(data, list):
        operations = data
    elif isinstance(data, dict) and 'operations' in data:
        operations = data['operations']
    else:
        raise click.BadParameter("JSON file must contain array of operations or object with 'operations' key")
    
    for i, operation in enumerate(operations):
        operation['_row_number'] = i + 1
    
    return operations


def _normalize_batch_operation(row: Dict[str, str]) -> Dict[str, Any]:
    """Normalize batch operation from CSV row."""
    operation = {
        "operation_type": row.get('operation_type'),
        "operation_id": _generate_operation_id()
    }
    
    if operation['operation_type'] == 'mint_fungible':
        operation.update({
            "asset_id": row.get('asset_id'),
            "amount": int(row.get('amount', 0)),
            "recipient": row.get('recipient')
        })
    elif operation['operation_type'] == 'mint_nft':
        operation.update({
            "collection_id": row.get('asset_id'),  # Using asset_id column for collection_id
            "token_id": int(row.get('token_id')) if row.get('token_id') else None,
            "recipient": row.get('recipient'),
            "metadata": json.loads(row.get('metadata', '{}')) if row.get('metadata') else {}
        })
    
    return operation


def _validate_batch_operation(operation: Dict[str, Any]):
    """Validate individual batch operation."""
    op_type = operation.get('operation_type')
    
    if op_type not in ['mint_fungible', 'mint_nft']:
        raise ValueError(f"Invalid operation type: {op_type}")
    
    if not operation.get('recipient'):
        raise ValueError("Recipient address is required")
    
    if not _validate_bitcoin_address(operation['recipient']):
        raise ValueError(f"Invalid recipient address: {operation['recipient']}")
    
    if op_type == 'mint_fungible':
        if not operation.get('asset_id'):
            raise ValueError("Asset ID is required for fungible minting")
        
        amount = operation.get('amount')
        if not amount or amount <= 0:
            raise ValueError("Amount must be positive for fungible minting")
    
    elif op_type == 'mint_nft':
        if not operation.get('collection_id'):
            raise ValueError("Collection ID is required for NFT minting")


def _generate_batch_summary(operations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate batch processing summary."""
    summary = {
        "total_operations": len(operations),
        "fungible_mints": len([op for op in operations if op.get('operation_type') == 'mint_fungible']),
        "nft_mints": len([op for op in operations if op.get('operation_type') == 'mint_nft']),
        "unique_assets": len(set(op.get('asset_id') or op.get('collection_id') for op in operations)),
        "unique_recipients": len(set(op.get('recipient') for op in operations))
    }
    
    return summary


def _process_batch_operation(operation: Dict[str, Any]) -> Dict[str, Any]:
    """Process individual batch operation."""
    op_type = operation.get('operation_type')
    
    if op_type == 'mint_fungible':
        # Simulate asset lookup and validation
        asset_info = _simulate_asset_lookup(operation['asset_id'])
        if not asset_info:
            raise Exception(f"Asset not found: {operation['asset_id']}")
        
        _validate_fungible_mint(asset_info, operation['amount'])
        return _generate_fungible_mint_psbt(operation, asset_info)
    
    elif op_type == 'mint_nft':
        # Simulate collection lookup and validation
        collection_info = _simulate_collection_lookup(operation['collection_id'])
        if not collection_info:
            raise Exception(f"Collection not found: {operation['collection_id']}")
        
        operation['token_id'] = _validate_nft_mint(collection_info, operation.get('token_id'))
        return _generate_nft_mint_psbt(operation, collection_info)
    
    else:
        raise Exception(f"Unsupported operation type: {op_type}")


# Register commands with main CLI
def register_commands(cli_app):
    """Register mint commands with the main CLI application."""
    cli_app.add_command(mint)


if __name__ == '__main__':
    mint()