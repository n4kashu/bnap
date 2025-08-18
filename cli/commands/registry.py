#!/usr/bin/env python3
"""
Registry Query and Reporting Commands for BNAP CLI

Commands for querying asset registry state, generating reports, and analyzing
the BNAP ecosystem with comprehensive filtering and export capabilities.
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Tuple
import click
import json
import csv
from datetime import datetime, timedelta
import hashlib
import math
from collections import defaultdict
import re

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
def registry(ctx: CLIContext):
    """
    Registry query and reporting commands.
    
    Query asset registries, view statistics, and generate comprehensive reports.
    """
    ctx.logger.debug("Registry command group invoked")


@registry.command('query')
@click.option('--asset-type', type=click.Choice(['fungible', 'nft', 'all']), default='all',
              help='Filter by asset type')
@click.option('--status', type=click.Choice(['draft', 'registered', 'active', 'frozen', 'all']), default='all',
              help='Filter by asset status')
@click.option('--name', help='Search by asset name (supports wildcards)')
@click.option('--symbol', help='Search by symbol (exact match)')
@click.option('--creator', help='Filter by creator address')
@click.option('--created-after', type=click.DateTime(), help='Filter by creation date (after)')
@click.option('--created-before', type=click.DateTime(), help='Filter by creation date (before)')
@click.option('--min-supply', type=int, help='Minimum total supply')
@click.option('--max-supply', type=int, help='Maximum total supply')
@click.option('--has-royalties', is_flag=True, help='Only assets with royalty configuration')
@click.option('--limit', type=int, default=50, help='Maximum results to return')
@click.option('--offset', type=int, default=0, help='Number of results to skip')
@click.option('--sort-by', type=click.Choice(['name', 'created_at', 'supply', 'volume']), 
              default='created_at', help='Sort results by field')
@click.option('--sort-order', type=click.Choice(['asc', 'desc']), default='desc', 
              help='Sort order')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), 
              help='Override output format')
@pass_context
@handle_cli_error
def query_registry(ctx: CLIContext, asset_type: str, status: str, name: Optional[str],
                  symbol: Optional[str], creator: Optional[str], created_after: Optional[datetime],
                  created_before: Optional[datetime], min_supply: Optional[int], 
                  max_supply: Optional[int], has_royalties: bool, limit: int, offset: int,
                  sort_by: str, sort_order: str, output_format: Optional[str]):
    """
    Query asset registry with flexible filtering.
    
    Search and filter assets by various criteria including type, status, creation date,
    supply amounts, and royalty configuration. Supports pagination and sorting.
    
    Examples:
        bnap registry query --asset-type fungible --status active
        bnap registry query --name "*Token*" --min-supply 1000000
        bnap registry query --created-after 2023-01-01 --has-royalties --format json
    """
    
    ctx.logger.info("Querying asset registry")
    
    # Build query filters
    filters = _build_query_filters(
        asset_type, status, name, symbol, creator, created_after, created_before,
        min_supply, max_supply, has_royalties
    )
    
    ctx.logger.debug(f"Query filters: {filters}")
    
    # TODO: Replace with actual registry query
    # For now, simulate registry data
    registry_data = _simulate_registry_data()
    
    # Apply filters
    filtered_results = _apply_filters(registry_data, filters)
    
    # Apply sorting
    sorted_results = _sort_results(filtered_results, sort_by, sort_order)
    
    # Apply pagination
    total_count = len(sorted_results)
    paginated_results = sorted_results[offset:offset + limit]
    
    # Add query metadata
    query_metadata = {
        "total_results": total_count,
        "showing": len(paginated_results),
        "offset": offset,
        "limit": limit,
        "filters_applied": len([f for f in filters.values() if f is not None]),
        "query_timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if not paginated_results:
        click.echo("No assets found matching the specified criteria")
        return
    
    # Format output
    if output_format == 'csv':
        _output_csv(paginated_results)
    else:
        ctx.output(paginated_results, output_format)
    
    # Display query summary
    if output_format != 'csv':
        click.echo(f"\\nQuery Summary:")
        click.echo(f"  Total matching: {total_count}")
        click.echo(f"  Showing: {len(paginated_results)} (offset: {offset})")
        if total_count > offset + limit:
            click.echo(f"  Next page: --offset {offset + limit}")


@registry.command('stats')
@click.option('--asset-type', type=click.Choice(['fungible', 'nft', 'all']), default='all',
              help='Statistics for specific asset type')
@click.option('--timeframe', type=click.Choice(['24h', '7d', '30d', '90d', 'all']), default='all',
              help='Timeframe for statistics')
@click.option('--group-by', type=click.Choice(['type', 'status', 'creator', 'month']), 
              help='Group statistics by field')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'summary']), 
              default='summary', help='Output format')
@pass_context
@handle_cli_error
def registry_stats(ctx: CLIContext, asset_type: str, timeframe: str, group_by: Optional[str],
                   output_format: str):
    """
    Generate registry statistics and analytics.
    
    Display comprehensive statistics about assets, supply, minting activity,
    and ecosystem growth with optional grouping and timeframe filtering.
    
    Examples:
        bnap registry stats --asset-type fungible
        bnap registry stats --timeframe 30d --group-by type
        bnap registry stats --format json
    """
    
    ctx.logger.info(f"Generating registry statistics for {asset_type} assets")
    
    # TODO: Replace with actual registry statistics
    # For now, simulate statistics
    stats_data = _generate_registry_statistics(asset_type, timeframe, group_by)
    
    if output_format == 'summary':
        _display_stats_summary(stats_data)
    else:
        ctx.output(stats_data, output_format)


@registry.command('history')
@click.argument('asset_id')
@click.option('--limit', type=int, default=100, help='Maximum transactions to return')
@click.option('--transaction-type', type=click.Choice(['mint', 'transfer', 'burn', 'all']), 
              default='all', help='Filter by transaction type')
@click.option('--from-date', type=click.DateTime(), help='Start date for history')
@click.option('--to-date', type=click.DateTime(), help='End date for history')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']), 
              help='Override output format')
@pass_context
@handle_cli_error
def asset_history(ctx: CLIContext, asset_id: str, limit: int, transaction_type: str,
                  from_date: Optional[datetime], to_date: Optional[datetime],
                  output_format: Optional[str]):
    """
    Display transaction history for a specific asset.
    
    Show chronological transaction history including mints, transfers, and burns
    with optional filtering by transaction type and date range.
    
    Examples:
        bnap registry history fungible_btk_123
        bnap registry history nft_art_456 --transaction-type mint --limit 50
        bnap registry history fungible_xyz_789 --from-date 2023-01-01 --format csv
    """
    
    ctx.logger.info(f"Fetching transaction history for asset: {asset_id}")
    
    # TODO: Replace with actual transaction history lookup
    # For now, simulate transaction history
    history_data = _simulate_transaction_history(asset_id, transaction_type, from_date, to_date, limit)
    
    if not history_data:
        click.echo(f"No transaction history found for asset: {asset_id}")
        return
    
    # Format output
    if output_format == 'csv':
        _output_csv(history_data)
    else:
        ctx.output(history_data, output_format)
    
    # Display summary
    if output_format != 'csv':
        click.echo(f"\\nShowing {len(history_data)} transactions for {asset_id}")
        if len(history_data) == limit:
            click.echo("(Results may be truncated - use --limit to show more)")


@registry.command('export')
@click.option('--format', 'export_format', type=click.Choice(['json', 'csv', 'jsonl']), 
              default='json', help='Export format')
@click.option('--output-file', type=click.Path(), help='Output file path')
@click.option('--asset-type', type=click.Choice(['fungible', 'nft', 'all']), default='all',
              help='Filter by asset type')
@click.option('--status', type=click.Choice(['draft', 'registered', 'active', 'frozen', 'all']), 
              default='active', help='Filter by asset status')
@click.option('--include-metadata', is_flag=True, help='Include full metadata in export')
@click.option('--include-history', is_flag=True, help='Include transaction history')
@click.option('--compress', is_flag=True, help='Compress output file (gzip)')
@pass_context
@handle_cli_error
def export_registry(ctx: CLIContext, export_format: str, output_file: Optional[str],
                    asset_type: str, status: str, include_metadata: bool, 
                    include_history: bool, compress: bool):
    """
    Export registry data to file.
    
    Export complete registry data or filtered subsets to various formats
    for backup, analysis, or integration with external systems.
    
    Examples:
        bnap registry export --format csv --output-file assets.csv
        bnap registry export --asset-type fungible --include-metadata --compress
        bnap registry export --format jsonl --include-history --output-file full_export.jsonl
    """
    
    ctx.logger.info("Exporting registry data")
    
    # Generate output filename if not provided
    if not output_file:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        extension = export_format
        if compress:
            extension += ".gz"
        output_file = f"bnap_registry_export_{timestamp}.{extension}"
    
    # TODO: Replace with actual registry export
    # For now, simulate export data
    export_data = _generate_export_data(asset_type, status, include_metadata, include_history)
    
    ctx.logger.info(f"Exporting {len(export_data)} assets to {output_file}")
    
    # Export data
    _export_data_to_file(export_data, output_file, export_format, compress)
    
    # Display summary
    click.echo(f"✅ Successfully exported registry data:")
    click.echo(f"   Records: {len(export_data)}")
    click.echo(f"   Format: {export_format}")
    click.echo(f"   File: {output_file}")
    if compress:
        click.echo(f"   Compressed: Yes")


@registry.command('verify')
@click.option('--check-integrity', is_flag=True, help='Verify registry data integrity')
@click.option('--check-signatures', is_flag=True, help='Verify asset signatures')
@click.option('--check-supply', is_flag=True, help='Verify supply calculations')
@click.option('--check-metadata', is_flag=True, help='Verify metadata schemas')
@click.option('--asset-id', help='Verify specific asset only')
@click.option('--fix-issues', is_flag=True, help='Attempt to fix detected issues')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'summary']), 
              default='summary', help='Output format')
@pass_context
@handle_cli_error
def verify_registry(ctx: CLIContext, check_integrity: bool, check_signatures: bool,
                    check_supply: bool, check_metadata: bool, asset_id: Optional[str],
                    fix_issues: bool, output_format: str):
    """
    Verify registry integrity and consistency.
    
    Perform comprehensive verification of registry data including integrity checks,
    signature validation, supply calculations, and metadata schema compliance.
    
    Examples:
        bnap registry verify --check-integrity --check-supply
        bnap registry verify --asset-id fungible_btk_123 --check-signatures
        bnap registry verify --check-metadata --fix-issues --format json
    """
    
    ctx.logger.info("Starting registry verification")
    
    # Default to all checks if none specified
    if not any([check_integrity, check_signatures, check_supply, check_metadata]):
        check_integrity = check_signatures = check_supply = check_metadata = True
    
    # Run verification checks
    verification_results = _run_verification_checks(
        check_integrity, check_signatures, check_supply, check_metadata, asset_id, fix_issues
    )
    
    if output_format == 'summary':
        _display_verification_summary(verification_results)
    else:
        ctx.output(verification_results, output_format)
    
    # Exit with error code if critical issues found
    critical_issues = verification_results.get('critical_issues', 0)
    if critical_issues > 0:
        ctx.logger.error(f"Found {critical_issues} critical issues")
        sys.exit(1)


# Utility functions

def _build_query_filters(asset_type: str, status: str, name: Optional[str], 
                        symbol: Optional[str], creator: Optional[str],
                        created_after: Optional[datetime], created_before: Optional[datetime],
                        min_supply: Optional[int], max_supply: Optional[int], 
                        has_royalties: bool) -> Dict[str, Any]:
    """Build query filters dictionary."""
    filters = {
        'asset_type': asset_type if asset_type != 'all' else None,
        'status': status if status != 'all' else None,
        'name': name,
        'symbol': symbol,
        'creator': creator,
        'created_after': created_after,
        'created_before': created_before,
        'min_supply': min_supply,
        'max_supply': max_supply,
        'has_royalties': has_royalties if has_royalties else None
    }
    
    return filters


def _simulate_registry_data() -> List[Dict[str, Any]]:
    """Simulate registry data for demonstration."""
    base_time = datetime.utcnow() - timedelta(days=365)
    
    assets = []
    
    # Generate sample fungible tokens
    for i in range(50):
        asset = {
            "asset_id": f"fungible_token_{i:03d}",
            "asset_type": "fungible",
            "name": f"Token {i+1}",
            "symbol": f"TK{i+1}",
            "creator": f"bc1q{'a' * (20 + i % 20)}",
            "max_supply": (i + 1) * 1000000 if i % 3 != 0 else None,
            "current_supply": (i + 1) * 250000,
            "status": ["draft", "registered", "active", "frozen"][i % 4],
            "created_at": (base_time + timedelta(days=i * 7)).isoformat() + "Z",
            "volume_24h": (i + 1) * 10000,
            "holders": (i + 1) * 150,
            "royalty_rate": None
        }
        assets.append(asset)
    
    # Generate sample NFT collections
    for i in range(30):
        asset = {
            "asset_id": f"nft_collection_{i:03d}",
            "asset_type": "nft",
            "name": f"NFT Collection {i+1}",
            "symbol": f"NFT{i+1}",
            "creator": f"bc1q{'b' * (20 + i % 20)}",
            "max_supply": (i + 1) * 1000,
            "current_supply": (i + 1) * 100,
            "status": ["draft", "registered", "active"][i % 3],
            "created_at": (base_time + timedelta(days=i * 5 + 100)).isoformat() + "Z",
            "volume_24h": (i + 1) * 5000,
            "holders": (i + 1) * 75,
            "royalty_rate": (i % 3) * 2.5 if i % 2 == 0 else None
        }
        assets.append(asset)
    
    return assets


def _apply_filters(data: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Apply query filters to registry data."""
    filtered_data = data
    
    for key, value in filters.items():
        if value is None:
            continue
            
        if key == 'asset_type':
            filtered_data = [item for item in filtered_data if item.get('asset_type') == value]
        elif key == 'status':
            filtered_data = [item for item in filtered_data if item.get('status') == value]
        elif key == 'name':
            # Support wildcard matching
            pattern = value.replace('*', '.*')
            regex = re.compile(pattern, re.IGNORECASE)
            filtered_data = [item for item in filtered_data if regex.search(item.get('name', ''))]
        elif key == 'symbol':
            filtered_data = [item for item in filtered_data if item.get('symbol', '').lower() == value.lower()]
        elif key == 'creator':
            filtered_data = [item for item in filtered_data if item.get('creator') == value]
        elif key == 'created_after':
            filtered_data = [item for item in filtered_data 
                           if datetime.fromisoformat(item.get('created_at', '').replace('Z', '+00:00')) >= value]
        elif key == 'created_before':
            filtered_data = [item for item in filtered_data 
                           if datetime.fromisoformat(item.get('created_at', '').replace('Z', '+00:00')) <= value]
        elif key == 'min_supply':
            filtered_data = [item for item in filtered_data 
                           if item.get('current_supply', 0) >= value]
        elif key == 'max_supply':
            filtered_data = [item for item in filtered_data 
                           if item.get('current_supply', 0) <= value]
        elif key == 'has_royalties':
            filtered_data = [item for item in filtered_data if item.get('royalty_rate') is not None]
    
    return filtered_data


def _sort_results(data: List[Dict[str, Any]], sort_by: str, sort_order: str) -> List[Dict[str, Any]]:
    """Sort query results."""
    reverse = sort_order == 'desc'
    
    if sort_by == 'name':
        return sorted(data, key=lambda x: x.get('name', ''), reverse=reverse)
    elif sort_by == 'created_at':
        return sorted(data, key=lambda x: x.get('created_at', ''), reverse=reverse)
    elif sort_by == 'supply':
        return sorted(data, key=lambda x: x.get('current_supply', 0), reverse=reverse)
    elif sort_by == 'volume':
        return sorted(data, key=lambda x: x.get('volume_24h', 0), reverse=reverse)
    
    return data


def _generate_registry_statistics(asset_type: str, timeframe: str, group_by: Optional[str]) -> Dict[str, Any]:
    """Generate registry statistics."""
    # TODO: Replace with actual statistics calculation
    # For now, simulate statistics
    
    base_stats = {
        "total_assets": 80,
        "fungible_tokens": 50,
        "nft_collections": 30,
        "total_supply_value": "125,000,000",
        "active_assets": 60,
        "draft_assets": 8,
        "registered_assets": 12,
        "frozen_assets": 0,
        "unique_creators": 65,
        "total_holders": 12500,
        "avg_holders_per_asset": 156,
        "assets_with_royalties": 15,
        "total_volume_24h": "2,450,000",
        "new_assets_24h": 3,
        "mint_transactions_24h": 127,
        "transfer_transactions_24h": 892
    }
    
    if timeframe != 'all':
        # Simulate timeframe filtering
        multiplier = {'24h': 0.1, '7d': 0.3, '30d': 0.7, '90d': 0.9}.get(timeframe, 1.0)
        base_stats.update({
            f"timeframe": timeframe,
            f"filtered_assets": int(base_stats['total_assets'] * multiplier),
            f"period_volume": f"{int(2450000 * multiplier):,}"
        })
    
    if group_by:
        # Add grouping data
        if group_by == 'type':
            base_stats['groups'] = {
                'fungible': {'count': 50, 'volume': '1,800,000'},
                'nft': {'count': 30, 'volume': '650,000'}
            }
        elif group_by == 'status':
            base_stats['groups'] = {
                'active': {'count': 60, 'volume': '2,200,000'},
                'registered': {'count': 12, 'volume': '200,000'},
                'draft': {'count': 8, 'volume': '50,000'}
            }
    
    return base_stats


def _display_stats_summary(stats: Dict[str, Any]):
    """Display statistics in summary format."""
    click.echo("📊 BNAP Registry Statistics")
    click.echo("=" * 50)
    
    click.echo("\\n🏗️  Asset Overview:")
    click.echo(f"   Total Assets: {stats.get('total_assets', 0)}")
    click.echo(f"   Fungible Tokens: {stats.get('fungible_tokens', 0)}")
    click.echo(f"   NFT Collections: {stats.get('nft_collections', 0)}")
    click.echo(f"   Total Supply Value: {stats.get('total_supply_value', '0')}")
    
    click.echo("\\n📈 Status Distribution:")
    click.echo(f"   Active: {stats.get('active_assets', 0)}")
    click.echo(f"   Registered: {stats.get('registered_assets', 0)}")
    click.echo(f"   Draft: {stats.get('draft_assets', 0)}")
    click.echo(f"   Frozen: {stats.get('frozen_assets', 0)}")
    
    click.echo("\\n👥 Community:")
    click.echo(f"   Unique Creators: {stats.get('unique_creators', 0)}")
    click.echo(f"   Total Holders: {stats.get('total_holders', 0):,}")
    click.echo(f"   Avg Holders/Asset: {stats.get('avg_holders_per_asset', 0)}")
    click.echo(f"   Assets with Royalties: {stats.get('assets_with_royalties', 0)}")
    
    click.echo("\\n⚡ 24h Activity:")
    click.echo(f"   Volume: {stats.get('total_volume_24h', '0')}")
    click.echo(f"   New Assets: {stats.get('new_assets_24h', 0)}")
    click.echo(f"   Mint Transactions: {stats.get('mint_transactions_24h', 0)}")
    click.echo(f"   Transfer Transactions: {stats.get('transfer_transactions_24h', 0)}")
    
    if 'groups' in stats:
        click.echo("\\n📊 Grouped Statistics:")
        for group, data in stats['groups'].items():
            click.echo(f"   {group.capitalize()}: {data.get('count', 0)} assets, {data.get('volume', '0')} volume")


def _simulate_transaction_history(asset_id: str, transaction_type: str, from_date: Optional[datetime],
                                 to_date: Optional[datetime], limit: int) -> List[Dict[str, Any]]:
    """Simulate transaction history for an asset."""
    # TODO: Replace with actual transaction history lookup
    
    base_time = datetime.utcnow() - timedelta(days=30)
    transactions = []
    
    for i in range(min(limit, 150)):
        tx_type = ['mint', 'transfer', 'transfer', 'transfer'][i % 4] if transaction_type == 'all' else transaction_type
        
        tx = {
            "transaction_id": f"tx_{hashlib.sha256(f'{asset_id}_{i}'.encode()).hexdigest()[:16]}",
            "asset_id": asset_id,
            "transaction_type": tx_type,
            "amount": (i + 1) * 100 if 'fungible' in asset_id else 1,
            "from_address": f"bc1q{'sender' + str(i).zfill(10)}" if tx_type != 'mint' else None,
            "to_address": f"bc1q{'recipient' + str(i).zfill(10)}",
            "block_height": 800000 + i,
            "transaction_fee": 500 + (i % 100),
            "timestamp": (base_time + timedelta(hours=i * 2)).isoformat() + "Z",
            "confirmation_status": "confirmed" if i < limit - 5 else "pending"
        }
        
        # Apply date filters
        tx_time = datetime.fromisoformat(tx['timestamp'].replace('Z', '+00:00'))
        if from_date and tx_time < from_date:
            continue
        if to_date and tx_time > to_date:
            continue
            
        transactions.append(tx)
    
    return sorted(transactions, key=lambda x: x['timestamp'], reverse=True)


def _generate_export_data(asset_type: str, status: str, include_metadata: bool, 
                         include_history: bool) -> List[Dict[str, Any]]:
    """Generate data for export."""
    # Get base registry data
    registry_data = _simulate_registry_data()
    
    # Apply filters
    if asset_type != 'all':
        registry_data = [item for item in registry_data if item.get('asset_type') == asset_type]
    
    if status != 'all':
        registry_data = [item for item in registry_data if item.get('status') == status]
    
    # Enhance data based on options
    for asset in registry_data:
        if include_metadata:
            asset['metadata'] = {
                "description": f"Description for {asset['name']}",
                "image": f"ipfs://Qm{hashlib.sha256(asset['asset_id'].encode()).hexdigest()[:32]}",
                "external_url": f"https://example.com/asset/{asset['asset_id']}",
                "attributes": [
                    {"trait_type": "Rarity", "value": "Common"},
                    {"trait_type": "Generation", "value": 1}
                ]
            }
        
        if include_history:
            # Add sample transaction history
            asset['transaction_history'] = _simulate_transaction_history(
                asset['asset_id'], 'all', None, None, 10
            )
    
    return registry_data


def _export_data_to_file(data: List[Dict[str, Any]], output_file: str, 
                        export_format: str, compress: bool):
    """Export data to file in specified format."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if compress:
        import gzip
        file_opener = gzip.open
        if not output_file.endswith('.gz'):
            output_file += '.gz'
    else:
        file_opener = open
    
    if export_format == 'json':
        with file_opener(output_file, 'wt') as f:
            json.dump(data, f, indent=2, default=str)
    
    elif export_format == 'jsonl':
        with file_opener(output_file, 'wt') as f:
            for item in data:
                f.write(json.dumps(item, default=str) + '\\n')
    
    elif export_format == 'csv':
        if not data:
            return
        
        # Flatten nested data for CSV
        flattened_data = []
        for item in data:
            flat_item = {}
            for key, value in item.items():
                if isinstance(value, (dict, list)):
                    flat_item[key] = json.dumps(value, default=str)
                else:
                    flat_item[key] = value
            flattened_data.append(flat_item)
        
        with file_opener(output_file, 'wt', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flattened_data[0].keys())
            writer.writeheader()
            writer.writerows(flattened_data)


def _run_verification_checks(check_integrity: bool, check_signatures: bool, 
                           check_supply: bool, check_metadata: bool,
                           asset_id: Optional[str], fix_issues: bool) -> Dict[str, Any]:
    """Run registry verification checks."""
    results = {
        "verification_timestamp": datetime.utcnow().isoformat() + "Z",
        "checks_performed": [],
        "total_assets_checked": 0,
        "issues_found": 0,
        "critical_issues": 0,
        "warnings": 0,
        "fixes_applied": 0,
        "details": []
    }
    
    # TODO: Replace with actual verification logic
    # For now, simulate verification results
    
    registry_data = _simulate_registry_data()
    if asset_id:
        registry_data = [item for item in registry_data if item['asset_id'] == asset_id]
    
    results["total_assets_checked"] = len(registry_data)
    
    if check_integrity:
        results["checks_performed"].append("data_integrity")
        # Simulate finding some integrity issues
        results["issues_found"] += 2
        results["details"].append({
            "check": "data_integrity",
            "status": "completed",
            "issues": 2,
            "description": "Found 2 assets with missing required fields"
        })
    
    if check_signatures:
        results["checks_performed"].append("signature_verification")
        results["issues_found"] += 1
        results["critical_issues"] += 1
        results["details"].append({
            "check": "signature_verification",
            "status": "completed", 
            "issues": 1,
            "description": "Found 1 asset with invalid signature"
        })
    
    if check_supply:
        results["checks_performed"].append("supply_verification")
        results["warnings"] += 3
        results["details"].append({
            "check": "supply_verification",
            "status": "completed",
            "issues": 0,
            "warnings": 3,
            "description": "Found 3 assets with supply inconsistencies (warnings only)"
        })
    
    if check_metadata:
        results["checks_performed"].append("metadata_schema")
        results["issues_found"] += 5
        results["details"].append({
            "check": "metadata_schema",
            "status": "completed",
            "issues": 5,
            "description": "Found 5 assets with invalid metadata schemas"
        })
        
        if fix_issues:
            results["fixes_applied"] = 3
            results["issues_found"] -= 3
    
    return results


def _display_verification_summary(results: Dict[str, Any]):
    """Display verification results in summary format."""
    click.echo("🔍 Registry Verification Results")
    click.echo("=" * 50)
    
    click.echo(f"\\n📊 Summary:")
    click.echo(f"   Assets Checked: {results.get('total_assets_checked', 0)}")
    click.echo(f"   Checks Performed: {len(results.get('checks_performed', []))}")
    click.echo(f"   Issues Found: {results.get('issues_found', 0)}")
    click.echo(f"   Critical Issues: {results.get('critical_issues', 0)}")
    click.echo(f"   Warnings: {results.get('warnings', 0)}")
    if results.get('fixes_applied', 0) > 0:
        click.echo(f"   Fixes Applied: {results.get('fixes_applied', 0)}")
    
    click.echo(f"\\n🔎 Check Details:")
    for detail in results.get('details', []):
        status_icon = "✅" if detail['issues'] == 0 else "❌"
        click.echo(f"   {status_icon} {detail['check']}: {detail['description']}")
    
    # Overall status
    total_issues = results.get('issues_found', 0) + results.get('critical_issues', 0)
    if total_issues == 0:
        click.echo(f"\\n🎉 Registry verification completed successfully!")
    else:
        click.echo(f"\\n⚠️  Registry verification completed with {total_issues} issues")


def _output_csv(data: List[Dict[str, Any]]):
    """Output data in CSV format."""
    if not data:
        return
    
    import io
    
    # Flatten nested data for CSV
    flattened_data = []
    for item in data:
        flat_item = {}
        for key, value in item.items():
            if isinstance(value, (dict, list)):
                flat_item[key] = json.dumps(value, default=str)
            else:
                flat_item[key] = value
        flattened_data.append(flat_item)
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=flattened_data[0].keys())
    writer.writeheader()
    writer.writerows(flattened_data)
    
    click.echo(output.getvalue().strip())


# Register commands with main CLI
def register_commands(cli_app):
    """Register registry commands with the main CLI application."""
    cli_app.add_command(registry)


if __name__ == '__main__':
    registry()