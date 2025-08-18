#!/usr/bin/env python3
"""
Asset Management Commands for BNAP CLI

Commands for creating, registering, and managing both fungible tokens and NFT collections.
Includes asset lifecycle operations, metadata management, and registry interactions.
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
import click
import json
from datetime import datetime
import re

# Add the project root to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import dependencies
import logging
from datetime import datetime

# Import main CLI context and help system
from cli.main import pass_context, CLIContext, load_json_file, save_json_file
from cli.help import get_command_examples, format_examples_help


@click.group()
@pass_context
def asset(ctx: CLIContext):
    """
    Asset management commands.
    
    Create, register, and manage both fungible and non-fungible assets.
    """
    ctx.logger.debug("Asset command group invoked")


@asset.command('create-fungible')
@click.option('--name', required=True, help='Token name (e.g., "My Bitcoin Token")')
@click.option('--symbol', required=True, help='Token symbol (e.g., "MBT")')
@click.option('--max-supply', type=int, help='Maximum token supply (optional, 0 for unlimited)')
@click.option('--per-mint-limit', type=int, help='Maximum tokens per mint operation')
@click.option('--description', help='Token description')
@click.option('--icon-uri', help='URI to token icon image')
@click.option('--website', help='Project website URL')
@click.option('--from-file', type=click.Path(exists=True), help='Load token definition from JSON file')
@click.option('--output-file', type=click.Path(), help='Save asset configuration to file')
@click.option('--dry-run', is_flag=True, help='Validate inputs without creating asset')
@click.option('--show-examples', is_flag=True, help='Show usage examples and exit')
@pass_context
def create_fungible(ctx: CLIContext, name: str, symbol: str, max_supply: Optional[int],
                   per_mint_limit: Optional[int], description: Optional[str], 
                   icon_uri: Optional[str], website: Optional[str],
                   from_file: Optional[str], output_file: Optional[str], dry_run: bool, 
                   show_examples: bool):
    """
    Create a new fungible token asset.
    
    Creates a fungible token with specified parameters. The token can have unlimited 
    or capped supply, and supports per-mint limits for controlled issuance.
    
    Examples:
        bnap asset create-fungible --name "MyToken" --symbol "MTK" --max-supply 1000000
        bnap asset create-fungible --from-file token.json --output-file config.json
    """
    
    # Show examples if requested
    if show_examples:
        examples = get_command_examples('asset', 'create-fungible')
        if examples:
            ctx.info("Examples for asset create-fungible:")
            print(format_examples_help(examples))
        else:
            ctx.info("No examples available for this command")
        return
    
    if from_file:
        ctx.logger.info(f"Loading token definition from {from_file}")
        token_data = load_json_file(from_file)
        
        # Override with CLI options if provided
        name = name or token_data.get('name')
        symbol = symbol or token_data.get('symbol')
        max_supply = max_supply or token_data.get('max_supply')
        per_mint_limit = per_mint_limit or token_data.get('per_mint_limit')
        description = description or token_data.get('description')
        icon_uri = icon_uri or token_data.get('icon_uri')
        website = website or token_data.get('website')
    
    # Validate inputs
    if not name or len(name.strip()) == 0:
        raise click.BadParameter("Token name is required")
    
    if not symbol or len(symbol.strip()) == 0:
        raise click.BadParameter("Token symbol is required")
    
    # Validate symbol format (alphanumeric, 2-10 characters)
    if not re.match(r'^[A-Za-z0-9]{2,10}$', symbol):
        raise click.BadParameter("Symbol must be 2-10 alphanumeric characters")
    
    # Validate supply limits
    if max_supply is not None and max_supply < 0:
        raise click.BadParameter("Max supply cannot be negative")
    
    if per_mint_limit is not None and per_mint_limit <= 0:
        raise click.BadParameter("Per-mint limit must be positive")
    
    if max_supply and per_mint_limit and per_mint_limit > max_supply:
        raise click.BadParameter("Per-mint limit cannot exceed max supply")
    
    # Validate URIs if provided
    if icon_uri and not _validate_uri(icon_uri):
        raise click.BadParameter(f"Invalid icon URI: {icon_uri}")
    
    if website and not _validate_uri(website):
        raise click.BadParameter(f"Invalid website URL: {website}")
    
    # Build asset configuration
    asset_config = {
        "asset_type": "fungible",
        "name": name.strip(),
        "symbol": symbol.upper().strip(),
        "max_supply": max_supply,
        "per_mint_limit": per_mint_limit,
        "description": description,
        "icon_uri": icon_uri,
        "website": website,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "draft"
    }
    
    # Remove None values
    asset_config = {k: v for k, v in asset_config.items() if v is not None}
    
    if dry_run:
        ctx.logger.info("Dry run mode - validating configuration only")
        ctx.output(asset_config)
        click.echo("✅ Asset configuration is valid")
        return
    
    # Display configuration for confirmation
    ctx.output(asset_config, "table")
    
    if not click.confirm(f"\nCreate fungible token '{name}' ({symbol})?", default=True):
        ctx.logger.info("Asset creation cancelled by user")
        return
    
    # TODO: Integrate with actual asset registration system
    # For now, simulate registration
    asset_id = f"fungible_{symbol.lower()}_{int(datetime.utcnow().timestamp())}"
    asset_config["asset_id"] = asset_id
    asset_config["status"] = "registered"
    
    ctx.logger.info(f"Creating fungible token: {name} ({symbol})")
    
    # Save to file if requested
    if output_file:
        save_json_file(asset_config, output_file)
        ctx.logger.info(f"Asset configuration saved to {output_file}")
    
    # Display success message
    click.echo(f"\n✅ Successfully created fungible token:")
    click.echo(f"   Asset ID: {asset_id}")
    click.echo(f"   Name: {name}")
    click.echo(f"   Symbol: {symbol}")
    if max_supply:
        click.echo(f"   Max Supply: {max_supply:,}")
    else:
        click.echo(f"   Max Supply: Unlimited")
    
    if per_mint_limit:
        click.echo(f"   Per-Mint Limit: {per_mint_limit:,}")
    
    ctx.logger.debug(f"Asset created with ID: {asset_id}")


@asset.command('create-nft')
@click.option('--collection-name', required=True, help='NFT collection name')
@click.option('--symbol', help='Collection symbol (optional)')
@click.option('--max-supply', type=int, help='Maximum number of NFTs in collection')
@click.option('--description', help='Collection description')
@click.option('--base-uri', help='Base URI for token metadata')
@click.option('--image-uri', help='Collection image URI')
@click.option('--website', help='Project website URL')
@click.option('--royalty-rate', type=float, help='Royalty percentage (0-10)')
@click.option('--royalty-address', help='Bitcoin address for royalty payments')
@click.option('--from-file', type=click.Path(exists=True), help='Load collection definition from JSON file')
@click.option('--output-file', type=click.Path(), help='Save collection configuration to file')
@click.option('--dry-run', is_flag=True, help='Validate inputs without creating collection')
@pass_context
def create_nft(ctx: CLIContext, collection_name: str, symbol: Optional[str],
               max_supply: Optional[int], description: Optional[str],
               base_uri: Optional[str], image_uri: Optional[str], website: Optional[str],
               royalty_rate: Optional[float], royalty_address: Optional[str],
               from_file: Optional[str], output_file: Optional[str], dry_run: bool):
    """
    Create a new NFT collection.
    
    Creates an NFT collection with specified parameters. Collections can have 
    limited or unlimited supply and support royalty configurations.
    
    Examples:
        bnap asset create-nft --collection-name "Art Collection" --max-supply 1000
        bnap asset create-nft --from-file collection.json --dry-run
    """
    
    if from_file:
        ctx.logger.info(f"Loading collection definition from {from_file}")
        collection_data = load_json_file(from_file)
        
        # Override with CLI options if provided
        collection_name = collection_name or collection_data.get('collection_name')
        symbol = symbol or collection_data.get('symbol')
        max_supply = max_supply or collection_data.get('max_supply')
        description = description or collection_data.get('description')
        base_uri = base_uri or collection_data.get('base_uri')
        image_uri = image_uri or collection_data.get('image_uri')
        website = website or collection_data.get('website')
        royalty_rate = royalty_rate or collection_data.get('royalty_rate')
        royalty_address = royalty_address or collection_data.get('royalty_address')
    
    # Validate inputs
    if not collection_name or len(collection_name.strip()) == 0:
        raise click.BadParameter("Collection name is required")
    
    if symbol and not re.match(r'^[A-Za-z0-9]{2,10}$', symbol):
        raise click.BadParameter("Symbol must be 2-10 alphanumeric characters")
    
    if max_supply is not None and max_supply <= 0:
        raise click.BadParameter("Max supply must be positive")
    
    # Validate royalty settings
    if royalty_rate is not None:
        if royalty_rate < 0 or royalty_rate > 10:
            raise click.BadParameter("Royalty rate must be between 0-10%")
        
        if not royalty_address:
            raise click.BadParameter("Royalty address is required when royalty rate is set")
        
        # TODO: Add proper Bitcoin address validation
        if not _validate_bitcoin_address(royalty_address):
            raise click.BadParameter(f"Invalid Bitcoin address: {royalty_address}")
    
    # Validate URIs if provided
    if base_uri and not _validate_uri(base_uri):
        raise click.BadParameter(f"Invalid base URI: {base_uri}")
    
    if image_uri and not _validate_uri(image_uri):
        raise click.BadParameter(f"Invalid image URI: {image_uri}")
    
    if website and not _validate_uri(website):
        raise click.BadParameter(f"Invalid website URL: {website}")
    
    # Build collection configuration
    collection_config = {
        "asset_type": "nft_collection",
        "collection_name": collection_name.strip(),
        "symbol": symbol.upper().strip() if symbol else None,
        "max_supply": max_supply,
        "description": description,
        "base_uri": base_uri,
        "image_uri": image_uri,
        "website": website,
        "royalty_rate": royalty_rate,
        "royalty_address": royalty_address,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "draft"
    }
    
    # Remove None values
    collection_config = {k: v for k, v in collection_config.items() if v is not None}
    
    if dry_run:
        ctx.logger.info("Dry run mode - validating configuration only")
        ctx.output(collection_config)
        click.echo("✅ Collection configuration is valid")
        return
    
    # Display configuration for confirmation
    ctx.output(collection_config, "table")
    
    if not click.confirm(f"\nCreate NFT collection '{collection_name}'?", default=True):
        ctx.logger.info("Collection creation cancelled by user")
        return
    
    # TODO: Integrate with actual asset registration system
    # For now, simulate registration
    collection_id = f"nft_{collection_name.lower().replace(' ', '_')}_{int(datetime.utcnow().timestamp())}"
    collection_config["collection_id"] = collection_id
    collection_config["status"] = "registered"
    
    ctx.logger.info(f"Creating NFT collection: {collection_name}")
    
    # Save to file if requested
    if output_file:
        save_json_file(collection_config, output_file)
        ctx.logger.info(f"Collection configuration saved to {output_file}")
    
    # Display success message
    click.echo(f"\n✅ Successfully created NFT collection:")
    click.echo(f"   Collection ID: {collection_id}")
    click.echo(f"   Name: {collection_name}")
    if symbol:
        click.echo(f"   Symbol: {symbol}")
    if max_supply:
        click.echo(f"   Max Supply: {max_supply:,}")
    else:
        click.echo(f"   Max Supply: Unlimited")
    
    if royalty_rate:
        click.echo(f"   Royalty Rate: {royalty_rate}%")
        click.echo(f"   Royalty Address: {royalty_address}")
    
    ctx.logger.debug(f"Collection created with ID: {collection_id}")


@asset.command('list')
@click.option('--asset-type', type=click.Choice(['fungible', 'nft']), help='Filter by asset type')
@click.option('--status', type=click.Choice(['draft', 'registered', 'active', 'frozen']), 
              help='Filter by asset status')
@click.option('--limit', type=int, default=50, help='Maximum number of assets to display')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), 
              help='Override output format')
@pass_context
def list_assets(ctx: CLIContext, asset_type: Optional[str], status: Optional[str], 
                limit: int, output_format: Optional[str]):
    """
    List all registered assets.
    
    Display a paginated list of assets with optional filtering by type and status.
    
    Examples:
        bnap asset list
        bnap asset list --asset-type fungible --status active
        bnap asset list --format json --limit 10
    """
    
    ctx.logger.info("Fetching asset list")
    
    # TODO: Replace with actual registry query
    # For now, simulate some sample assets
    sample_assets = [
        {
            "asset_id": "fungible_btk_1692345678",
            "asset_type": "fungible",
            "name": "Bitcoin Token",
            "symbol": "BTK",
            "max_supply": 1000000,
            "status": "active",
            "created_at": "2023-08-18T10:30:00Z"
        },
        {
            "asset_id": "nft_art_collection_1692346789",
            "asset_type": "nft",
            "name": "Digital Art Collection",
            "symbol": "DAC",
            "max_supply": 1000,
            "status": "registered", 
            "created_at": "2023-08-18T11:45:00Z"
        },
        {
            "asset_id": "fungible_coin_1692347890",
            "asset_type": "fungible",
            "name": "My Coin",
            "symbol": "MYC",
            "max_supply": None,
            "status": "draft",
            "created_at": "2023-08-18T12:15:00Z"
        }
    ]
    
    # Apply filters
    filtered_assets = sample_assets
    
    if asset_type:
        filtered_assets = [a for a in filtered_assets if a['asset_type'] == asset_type]
    
    if status:
        filtered_assets = [a for a in filtered_assets if a['status'] == status]
    
    # Apply limit
    if limit and len(filtered_assets) > limit:
        filtered_assets = filtered_assets[:limit]
        ctx.logger.info(f"Limiting results to {limit} assets")
    
    if not filtered_assets:
        click.echo("No assets found matching the specified criteria")
        return
    
    # Format output
    if output_format == 'csv':
        _output_csv(filtered_assets)
    else:
        ctx.output(filtered_assets, output_format)
    
    click.echo(f"\nFound {len(filtered_assets)} assets")


@asset.command('info')
@click.argument('asset_id')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']), 
              help='Override output format')
@pass_context
def asset_info(ctx: CLIContext, asset_id: str, output_format: Optional[str]):
    """
    Display detailed information about a specific asset.
    
    Shows comprehensive asset details including metadata, supply information,
    minting rules, and transaction history.
    
    Examples:
        bnap asset info fungible_btk_1692345678
        bnap asset info nft_collection_123 --format json
    """
    
    ctx.logger.info(f"Fetching information for asset: {asset_id}")
    
    # TODO: Replace with actual registry lookup
    # For now, simulate asset data
    if "fungible" in asset_id:
        asset_info_data = {
            "asset_id": asset_id,
            "asset_type": "fungible",
            "name": "Bitcoin Token",
            "symbol": "BTK",
            "description": "A sample Bitcoin-based token",
            "max_supply": 1000000,
            "current_supply": 250000,
            "per_mint_limit": 1000,
            "icon_uri": "ipfs://QmTokenIcon123",
            "website": "https://example.com",
            "status": "active",
            "created_at": "2023-08-18T10:30:00Z",
            "updated_at": "2023-08-18T15:45:00Z",
            "transaction_count": 127,
            "holder_count": 89,
            "minting_rules": {
                "enabled": True,
                "public_minting": True,
                "whitelist_required": False
            }
        }
    elif "nft" in asset_id:
        asset_info_data = {
            "asset_id": asset_id,
            "asset_type": "nft_collection",
            "collection_name": "Digital Art Collection",
            "symbol": "DAC",
            "description": "A premium collection of digital art NFTs",
            "max_supply": 1000,
            "current_supply": 47,
            "base_uri": "ipfs://QmCollection/metadata/",
            "image_uri": "ipfs://QmCollectionImage",
            "website": "https://art-collection.com",
            "royalty_rate": 5.0,
            "royalty_address": "bc1qexampleaddress123",
            "status": "registered",
            "created_at": "2023-08-18T11:45:00Z",
            "updated_at": "2023-08-18T16:20:00Z",
            "transaction_count": 47,
            "holder_count": 41,
            "floor_price": "0.001 BTC"
        }
    else:
        raise click.ClickException(f"Asset not found: {asset_id}")
    
    ctx.output(asset_info_data, output_format)


@asset.command('update-rules')
@click.argument('asset_id')
@click.option('--enable-minting/--disable-minting', default=None, help='Enable or disable minting')
@click.option('--public-minting/--private-minting', default=None, help='Set minting accessibility')
@click.option('--per-mint-limit', type=int, help='Update per-mint limit')
@click.option('--whitelist-required/--no-whitelist', default=None, help='Require whitelist for minting')
@click.option('--from-file', type=click.Path(exists=True), help='Load rules from JSON file')
@click.option('--dry-run', is_flag=True, help='Preview changes without applying')
@pass_context
def update_rules(ctx: CLIContext, asset_id: str, enable_minting: Optional[bool],
                public_minting: Optional[bool], per_mint_limit: Optional[int],
                whitelist_required: Optional[bool], from_file: Optional[str], dry_run: bool):
    """
    Update minting rules for an asset.
    
    Modify asset minting parameters such as enabling/disabling minting,
    setting accessibility, and updating limits.
    
    Examples:
        bnap asset update-rules fungible_btk_123 --enable-minting --per-mint-limit 500
        bnap asset update-rules nft_collection_456 --private-minting --whitelist-required
    """
    
    if from_file:
        ctx.logger.info(f"Loading rules from {from_file}")
        rules_data = load_json_file(from_file)
        
        # Override with CLI options if provided
        enable_minting = enable_minting if enable_minting is not None else rules_data.get('enable_minting')
        public_minting = public_minting if public_minting is not None else rules_data.get('public_minting')
        per_mint_limit = per_mint_limit or rules_data.get('per_mint_limit')
        whitelist_required = whitelist_required if whitelist_required is not None else rules_data.get('whitelist_required')
    
    # Build update data
    updates = {}
    
    if enable_minting is not None:
        updates['minting_enabled'] = enable_minting
    
    if public_minting is not None:
        updates['public_minting'] = public_minting
    
    if per_mint_limit is not None:
        if per_mint_limit <= 0:
            raise click.BadParameter("Per-mint limit must be positive")
        updates['per_mint_limit'] = per_mint_limit
    
    if whitelist_required is not None:
        updates['whitelist_required'] = whitelist_required
    
    if not updates:
        raise click.ClickException("No rule updates specified")
    
    ctx.logger.info(f"Updating rules for asset: {asset_id}")
    
    if dry_run:
        ctx.logger.info("Dry run mode - showing proposed changes only")
        click.echo(f"Proposed rule updates for {asset_id}:")
        ctx.output(updates, "table")
        return
    
    # Display proposed changes
    click.echo(f"Updating rules for asset: {asset_id}")
    ctx.output(updates, "table")
    
    if not click.confirm("\nApply these rule changes?", default=True):
        ctx.logger.info("Rule update cancelled by user")
        return
    
    # TODO: Apply actual rule updates
    ctx.logger.info(f"Applied rule updates to asset {asset_id}")
    click.echo(f"✅ Successfully updated rules for asset: {asset_id}")


# Utility functions
def _validate_uri(uri: str) -> bool:
    """Basic URI validation."""
    if not uri:
        return False
    
    # Support common schemes
    valid_schemes = ['http', 'https', 'ipfs', 'ar', 'data']
    
    try:
        # Simple scheme validation
        if '://' in uri:
            scheme = uri.split('://')[0].lower()
            return scheme in valid_schemes
        return False
    except:
        return False


def _validate_bitcoin_address(address: str) -> bool:
    """Basic Bitcoin address validation."""
    if not address:
        return False
    
    # Basic format checks for different address types
    if address.startswith(('1', '3', 'bc1', 'tb1')):
        return len(address) >= 26 and len(address) <= 62
    
    return False


def _output_csv(data: List[Dict[str, Any]]):
    """Output data in CSV format."""
    if not data:
        return
    
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    
    click.echo(output.getvalue().strip())


# Register commands with main CLI
def register_commands(cli_app):
    """Register asset commands with the main CLI application."""
    cli_app.add_command(asset)


if __name__ == '__main__':
    asset()