#!/usr/bin/env python3
"""
Help System Module for BNAP CLI

Provides context-aware help, usage examples, troubleshooting guides,
and command documentation for the BNAP CLI.
"""

from typing import Dict, List, Optional
import click
from textwrap import dedent

# Command examples database
COMMAND_EXAMPLES = {
    'asset': {
        'create-fungible': [
            ('Basic fungible token creation',
             'bnap asset create-fungible --name "Bitcoin Token" --symbol "BTK" --max-supply 1000000'),
            ('Token with per-mint limit',
             'bnap asset create-fungible --name "Limited Token" --symbol "LTK" --max-supply 100000 --per-mint-limit 1000'),
            ('Load from configuration file',
             'bnap asset create-fungible --from-file token_config.json --output-file result.json'),
        ],
        'create-nft': [
            ('Basic NFT collection',
             'bnap asset create-nft --collection-name "Art Collection" --max-supply 1000'),
            ('NFT with royalties',
             'bnap asset create-nft --collection-name "Premium Art" --royalty-rate 5 --royalty-address bc1q...'),
            ('Interactive setup',
             'bnap asset create-nft --collection-name "My NFTs" --interactive'),
        ],
        'list': [
            ('List all assets',
             'bnap asset list'),
            ('Filter by type and status',
             'bnap asset list --asset-type fungible --status active'),
            ('Export to JSON with pagination',
             'bnap asset list --format json --limit 100 --offset 0'),
        ],
    },
    'mint': {
        'mint-fungible': [
            ('Basic token minting',
             'bnap mint mint-fungible --asset-id fungible_btk_123 --amount 1000 --recipient bc1q...'),
            ('Dry run validation',
             'bnap mint mint-fungible --asset-id token_456 --amount 500 --recipient bc1q... --dry-run'),
            ('Interactive minting',
             'bnap mint mint-fungible --interactive'),
        ],
        'mint-nft': [
            ('Mint NFT with metadata',
             'bnap mint mint-nft --collection-id nft_art_123 --metadata \'{"name":"Art #1"}\' --recipient bc1q...'),
            ('Mint with specific token ID',
             'bnap mint mint-nft --collection-id collection_456 --token-id 42 --recipient bc1q...'),
            ('Load from file',
             'bnap mint mint-nft --from-file nft_params.json'),
        ],
        'batch-mint': [
            ('Process batch from CSV',
             'bnap mint batch-mint --batch-file operations.csv'),
            ('Batch with custom output directory',
             'bnap mint batch-mint --batch-file mints.json --output-dir ./psbts/ --continue-on-error'),
        ],
    },
    'registry': {
        'query': [
            ('Search by name pattern',
             'bnap registry query --name "*Token*" --asset-type fungible'),
            ('Date range filtering',
             'bnap registry query --created-after 2023-01-01 --created-before 2023-12-31'),
            ('Complex query with sorting',
             'bnap registry query --min-supply 100000 --has-royalties --sort-by volume --sort-order desc'),
        ],
        'stats': [
            ('Overall statistics',
             'bnap registry stats'),
            ('Time-based statistics',
             'bnap registry stats --timeframe 30d --group-by type'),
            ('Export statistics',
             'bnap registry stats --format json > stats.json'),
        ],
        'export': [
            ('Export registry to CSV',
             'bnap registry export --format csv --output-file assets.csv'),
            ('Export with metadata',
             'bnap registry export --include-metadata --include-history --compress'),
        ],
    },
    'validator': {
        'init': [
            ('Initialize validator',
             'bnap validator init --validator-name main-validator --generate-keys --network testnet'),
            ('Import existing keys',
             'bnap validator init --validator-name backup --import-key validator.key'),
        ],
        'start': [
            ('Start validator daemon',
             'bnap validator start --name main-validator --daemon'),
            ('Start in foreground',
             'bnap validator start --name test-validator'),
        ],
        'sign-psbt': [
            ('Sign PSBT',
             'bnap validator sign-psbt transaction.psbt --validator-name main'),
            ('Sign with output file',
             'bnap validator sign-psbt input.psbt --validator-name signer --output-file signed.psbt'),
        ],
    },
    'config': {
        'init': [
            ('Create default config',
             'bnap config init'),
            ('Production profile config',
             'bnap config init --profile production --output prod.yml'),
            ('Interactive setup',
             'bnap config init --interactive'),
        ],
        'show': [
            ('Show all configuration',
             'bnap config show'),
            ('Show specific setting',
             'bnap config show --key network.bitcoin_rpc'),
            ('Export as environment variables',
             'bnap config show --export-env > .env'),
        ],
        'set': [
            ('Set configuration value',
             'bnap config set network.type mainnet'),
            ('Set and save to file',
             'bnap config set cli.output_format json --save'),
        ],
    },
}

# Troubleshooting guides
TROUBLESHOOTING_GUIDES = {
    'connection_errors': {
        'title': 'Connection Issues',
        'description': 'Problems connecting to Bitcoin RPC or registry services',
        'solutions': [
            'Verify Bitcoin Core is running: bitcoind or bitcoin-qt',
            'Check RPC credentials in configuration: bnap config show --key network.bitcoin_rpc',
            'Test network connectivity: telnet localhost 18332',
            'Review firewall settings for blocked ports',
            'Check if correct network is configured (mainnet/testnet/regtest)',
        ]
    },
    'validation_errors': {
        'title': 'Validation Failures',
        'description': 'PSBT validation or asset rule violations',
        'solutions': [
            'Verify PSBT format: bnap validator validate-psbt <file>',
            'Check asset minting rules: bnap asset info <asset-id>',
            'Ensure sufficient balance for fees',
            'Validate recipient addresses are correct format',
            'Review supply limits and per-mint restrictions',
        ]
    },
    'configuration_issues': {
        'title': 'Configuration Problems',
        'description': 'Issues with CLI configuration or environment variables',
        'solutions': [
            'Validate configuration: bnap config validate',
            'Check configuration sources: bnap config show --sources',
            'List search paths: bnap config search-paths',
            'Verify environment variables: env | grep BNAP_',
            'Generate new config: bnap config init --force',
        ]
    },
    'permission_errors': {
        'title': 'Permission Denied',
        'description': 'File access or process management permission issues',
        'solutions': [
            'Check file permissions: ls -la ~/.bnap/',
            'Ensure validator keys are readable: chmod 600 ~/.bnap/validators/*/private.key',
            'Run with appropriate user permissions',
            'Check directory ownership for data directories',
            'Verify write access to output directories',
        ]
    },
}

# Quick start guide
QUICK_START_GUIDE = """
🚀 BNAP CLI Quick Start Guide
==============================

1. Initial Setup
----------------
# Install and configure BNAP CLI
bnap config init --interactive
bnap config validate

# Set up a validator
bnap validator init --validator-name main --generate-keys

2. Create Assets
----------------
# Create a fungible token
bnap asset create-fungible --name "My Token" --symbol "MTK" --max-supply 1000000

# Create an NFT collection
bnap asset create-nft --collection-name "Art Collection" --max-supply 100

3. Mint Assets
--------------
# Mint fungible tokens
bnap mint mint-fungible --asset-id <asset-id> --amount 100 --recipient <address>

# Mint NFT
bnap mint mint-nft --collection-id <collection-id> --recipient <address>

4. Query Registry
-----------------
# List all assets
bnap asset list

# Search assets
bnap registry query --name "*Token*"

# View statistics
bnap registry stats

5. Manage Validators
--------------------
# Start validator
bnap validator start --name main --daemon

# Check status
bnap validator status

# Sign PSBT
bnap validator sign-psbt transaction.psbt --validator-name main

For detailed help on any command, use: bnap <command> --help
"""

# Command cheat sheet
CHEAT_SHEET = """
📋 BNAP CLI Command Cheat Sheet
================================

Asset Management
----------------
asset create-fungible    Create fungible token
asset create-nft        Create NFT collection
asset list              List all assets
asset info <id>         Show asset details
asset update-rules      Modify minting rules

Minting Operations
------------------
mint mint-fungible      Mint fungible tokens
mint mint-nft          Mint NFT
mint batch-mint        Batch minting from file

Registry Operations
-------------------
registry query          Search assets with filters
registry stats          View ecosystem statistics
registry history <id>   Transaction history
registry export         Export registry data
registry verify         Validate registry integrity

Validator Management
--------------------
validator init          Initialize validator
validator start         Start validator service
validator stop          Stop validator service
validator status        Check validator health
validator sign-psbt     Sign transaction
validator validate-psbt Validate PSBT
validator rotate-keys   Rotate signing keys

Configuration
-------------
config init            Generate config file
config show            Display configuration
config validate        Validate settings
config set <key>       Update configuration
config get <key>       Get specific value
config list-profiles   Show available profiles

Global Options
--------------
--config-file <file>   Use specific config
--output-format <fmt>  Output format (table/json/yaml)
--verbose/-v          Increase verbosity
--help/-h             Show help
--version             Show version
"""


def get_command_examples(command_group: str, command: Optional[str] = None) -> List[tuple]:
    """
    Get examples for a specific command or command group.
    
    Args:
        command_group: Main command group (asset, mint, registry, etc.)
        command: Specific command within the group
        
    Returns:
        List of (description, example) tuples
    """
    if command_group not in COMMAND_EXAMPLES:
        return []
    
    if command:
        return COMMAND_EXAMPLES[command_group].get(command, [])
    
    # Return all examples for the command group
    all_examples = []
    for cmd, examples in COMMAND_EXAMPLES[command_group].items():
        all_examples.extend(examples)
    return all_examples


def get_troubleshooting_guide(issue_type: Optional[str] = None) -> str:
    """
    Get troubleshooting guide for specific issue or all issues.
    
    Args:
        issue_type: Specific issue type or None for all
        
    Returns:
        Formatted troubleshooting guide text
    """
    if issue_type and issue_type in TROUBLESHOOTING_GUIDES:
        guide = TROUBLESHOOTING_GUIDES[issue_type]
        text = f"🔧 {guide['title']}\n"
        text += f"{guide['description']}\n\n"
        text += "Solutions:\n"
        for solution in guide['solutions']:
            text += f"  • {solution}\n"
        return text
    
    # Return all troubleshooting guides
    text = "🔧 Troubleshooting Guide\n"
    text += "=" * 40 + "\n\n"
    
    for issue_type, guide in TROUBLESHOOTING_GUIDES.items():
        text += f"{guide['title']}\n"
        text += "-" * len(guide['title']) + "\n"
        text += f"{guide['description']}\n\n"
        text += "Solutions:\n"
        for solution in guide['solutions']:
            text += f"  • {solution}\n"
        text += "\n"
    
    return text


def format_examples_help(examples: List[tuple]) -> str:
    """
    Format examples for display in help text.
    
    Args:
        examples: List of (description, example) tuples
        
    Returns:
        Formatted help text with examples
    """
    if not examples:
        return ""
    
    text = "\nExamples:\n"
    for description, example in examples:
        text += f"\n  # {description}\n"
        text += f"  {example}\n"
    
    return text


def get_context_help(ctx: click.Context) -> str:
    """
    Get context-aware help based on current command.
    
    Args:
        ctx: Click context object
        
    Returns:
        Context-specific help text
    """
    # Get command path
    command_path = ctx.command_path.split()
    
    if len(command_path) == 1:
        # Main command help
        return QUICK_START_GUIDE
    
    if len(command_path) >= 2:
        command_group = command_path[1]
        command = command_path[2] if len(command_path) > 2 else None
        
        examples = get_command_examples(command_group, command)
        if examples:
            return format_examples_help(examples)
    
    return ""


def generate_man_page() -> str:
    """
    Generate man page content for BNAP CLI.
    
    Returns:
        Formatted man page content
    """
    man_page = dedent("""
    .TH BNAP 1 "August 2024" "1.0.0" "BNAP Manual"
    .SH NAME
    bnap \\- Bitcoin Native Asset Protocol Command Line Interface
    
    .SH SYNOPSIS
    .B bnap
    [\\fIOPTIONS\\fR] \\fICOMMAND\\fR [\\fIARGS\\fR]...
    
    .SH DESCRIPTION
    The Bitcoin Native Asset Protocol (BNAP) CLI is a comprehensive tool for managing 
    Bitcoin assets, performing minting operations, querying registries, and administering 
    the BNAP system.
    
    .SH OPTIONS
    .TP
    .BR \\-c ", " \\-\\-config\\-file " " \\fIFILE\\fR
    Path to configuration file
    .TP
    .BR \\-o ", " \\-\\-output\\-format " " \\fIFORMAT\\fR
    Output format (table, json, yaml, csv)
    .TP
    .BR \\-v ", " \\-\\-verbose
    Increase verbosity (use multiple times for more detail)
    .TP
    .BR \\-\\-version
    Show version information
    .TP
    .BR \\-h ", " \\-\\-help
    Show help message and exit
    
    .SH COMMANDS
    .SS Asset Management Commands
    .TP
    .B asset create-fungible
    Create a new fungible token asset
    .TP
    .B asset create-nft
    Create a new NFT collection
    .TP
    .B asset list
    List all registered assets
    .TP
    .B asset info
    Display detailed information about an asset
    
    .SS Minting Commands
    .TP
    .B mint mint-fungible
    Mint fungible tokens
    .TP
    .B mint mint-nft
    Mint NFTs from a collection
    .TP
    .B mint batch-mint
    Process batch minting operations
    
    .SS Registry Commands
    .TP
    .B registry query
    Query asset registry with filters
    .TP
    .B registry stats
    Display registry statistics
    .TP
    .B registry export
    Export registry data
    
    .SS Validator Commands
    .TP
    .B validator init
    Initialize a new validator
    .TP
    .B validator start
    Start validator service
    .TP
    .B validator status
    Check validator status
    
    .SS Configuration Commands
    .TP
    .B config init
    Generate configuration file
    .TP
    .B config show
    Display configuration
    .TP
    .B config validate
    Validate configuration
    
    .SH ENVIRONMENT
    .TP
    .B BNAP_*
    Any environment variable prefixed with BNAP_ will be loaded as configuration
    
    .SH FILES
    .TP
    .I ~/.bnap/config.yml
    User configuration file
    .TP
    .I .bnap.yml
    Project configuration file
    .TP
    .I ~/.bnap/validators/
    Validator data directory
    
    .SH EXAMPLES
    .TP
    Create a fungible token:
    .B bnap asset create-fungible --name "My Token" --symbol "MTK"
    
    .TP
    Mint tokens:
    .B bnap mint mint-fungible --asset-id token_123 --amount 100 --recipient bc1q...
    
    .TP
    Query registry:
    .B bnap registry query --asset-type fungible --status active
    
    .SH SEE ALSO
    Full documentation at: https://github.com/bnap/cli
    
    .SH AUTHOR
    BNAP Development Team
    """).strip()
    
    return man_page


def generate_completion_script(shell: str = 'bash') -> str:
    """
    Generate shell completion script.
    
    Args:
        shell: Shell type (bash, zsh, fish)
        
    Returns:
        Shell completion script content
    """
    if shell == 'bash':
        return dedent("""
        # BNAP CLI Bash Completion
        # Add this to ~/.bashrc or ~/.bash_completion
        
        _bnap_completion() {
            local cur prev opts
            COMPREPLY=()
            cur="${COMP_WORDS[COMP_CWORD]}"
            prev="${COMP_WORDS[COMP_CWORD-1]}"
            
            # Main commands
            local commands="asset mint registry validator config --help --version"
            
            # Asset subcommands
            local asset_commands="create-fungible create-nft list info update-rules"
            
            # Mint subcommands
            local mint_commands="mint-fungible mint-nft batch-mint"
            
            # Registry subcommands
            local registry_commands="query stats history export verify"
            
            # Validator subcommands
            local validator_commands="init start stop status sign-psbt validate-psbt rotate-keys"
            
            # Config subcommands
            local config_commands="init show validate set get list-profiles search-paths"
            
            case "${prev}" in
                bnap)
                    COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
                    return 0
                    ;;
                asset)
                    COMPREPLY=( $(compgen -W "${asset_commands}" -- ${cur}) )
                    return 0
                    ;;
                mint)
                    COMPREPLY=( $(compgen -W "${mint_commands}" -- ${cur}) )
                    return 0
                    ;;
                registry)
                    COMPREPLY=( $(compgen -W "${registry_commands}" -- ${cur}) )
                    return 0
                    ;;
                validator)
                    COMPREPLY=( $(compgen -W "${validator_commands}" -- ${cur}) )
                    return 0
                    ;;
                config)
                    COMPREPLY=( $(compgen -W "${config_commands}" -- ${cur}) )
                    return 0
                    ;;
                *)
                    ;;
            esac
            
            # Handle options
            if [[ ${cur} == -* ]] ; then
                local opts="--help --config-file --output-format --verbose --version"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                return 0
            fi
        }
        
        complete -F _bnap_completion bnap
        """).strip()
    
    elif shell == 'zsh':
        return dedent("""
        # BNAP CLI Zsh Completion
        # Add this to ~/.zshrc or ~/.zsh_completion
        
        #compdef bnap
        
        _bnap() {
            local -a commands
            commands=(
                'asset:Manage assets'
                'mint:Minting operations'
                'registry:Registry queries'
                'validator:Validator management'
                'config:Configuration management'
            )
            
            if (( CURRENT == 2 )); then
                _describe 'command' commands
            elif (( CURRENT == 3 )); then
                case ${words[2]} in
                    asset)
                        local -a asset_commands
                        asset_commands=(
                            'create-fungible:Create fungible token'
                            'create-nft:Create NFT collection'
                            'list:List assets'
                            'info:Asset information'
                            'update-rules:Update minting rules'
                        )
                        _describe 'asset command' asset_commands
                        ;;
                    mint)
                        local -a mint_commands
                        mint_commands=(
                            'mint-fungible:Mint fungible tokens'
                            'mint-nft:Mint NFT'
                            'batch-mint:Batch minting'
                        )
                        _describe 'mint command' mint_commands
                        ;;
                    registry)
                        local -a registry_commands
                        registry_commands=(
                            'query:Query registry'
                            'stats:View statistics'
                            'history:Transaction history'
                            'export:Export data'
                            'verify:Verify integrity'
                        )
                        _describe 'registry command' registry_commands
                        ;;
                    validator)
                        local -a validator_commands
                        validator_commands=(
                            'init:Initialize validator'
                            'start:Start validator'
                            'stop:Stop validator'
                            'status:Check status'
                            'sign-psbt:Sign PSBT'
                            'validate-psbt:Validate PSBT'
                            'rotate-keys:Rotate keys'
                        )
                        _describe 'validator command' validator_commands
                        ;;
                    config)
                        local -a config_commands
                        config_commands=(
                            'init:Initialize config'
                            'show:Show configuration'
                            'validate:Validate config'
                            'set:Set value'
                            'get:Get value'
                            'list-profiles:List profiles'
                        )
                        _describe 'config command' config_commands
                        ;;
                esac
            fi
        }
        
        compdef _bnap bnap
        """).strip()
    
    else:
        return f"# Completion script for {shell} not yet implemented"


# Export help functions for use in CLI
__all__ = [
    'get_command_examples',
    'get_troubleshooting_guide',
    'format_examples_help',
    'get_context_help',
    'generate_man_page',
    'generate_completion_script',
    'QUICK_START_GUIDE',
    'CHEAT_SHEET',
]