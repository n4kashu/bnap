#!/usr/bin/env python3
"""
Help Commands for BNAP CLI

Provides comprehensive help system with examples, troubleshooting guides,
quick start information, and shell completion generation.
"""

import sys
import os
from pathlib import Path
from typing import Optional
import click

# Import help module functions
from cli.help import (
    get_command_examples, get_troubleshooting_guide, get_context_help,
    format_examples_help, generate_man_page, generate_completion_script,
    QUICK_START_GUIDE, CHEAT_SHEET, COMMAND_EXAMPLES, TROUBLESHOOTING_GUIDES
)
from cli.main import pass_context, CLIContext


@click.group()
def help():
    """
    Comprehensive help system for BNAP CLI.
    
    Provides quick start guides, examples, troubleshooting,
    and interactive help for all commands.
    """
    pass


@help.command('quickstart')
@pass_context
def quickstart(ctx: CLIContext):
    """Show quick start guide for BNAP CLI."""
    ctx.info("BNAP CLI Quick Start Guide")
    print(QUICK_START_GUIDE)


@help.command('cheatsheet')
@pass_context
def cheatsheet(ctx: CLIContext):
    """Show command cheat sheet."""
    ctx.info("BNAP CLI Command Cheat Sheet")
    print(CHEAT_SHEET)


@help.command('examples')
@click.option('--command-group', '-g', 
              type=click.Choice(['asset', 'mint', 'registry', 'validator', 'config']),
              help='Show examples for specific command group')
@click.option('--command', '-c',
              help='Show examples for specific command within group')
@pass_context
def examples(ctx: CLIContext, command_group: Optional[str], command: Optional[str]):
    """
    Show command examples.
    
    Examples:
        bnap help examples                           # All examples
        bnap help examples -g asset                  # Asset command examples
        bnap help examples -g mint -c mint-fungible  # Specific command examples
    """
    if command_group:
        examples_list = get_command_examples(command_group, command)
        
        if not examples_list:
            ctx.warning(f"No examples found for {command_group}" + 
                       (f" {command}" if command else ""))
            return
        
        title = f"Examples for {command_group}"
        if command:
            title += f" {command}"
        
        ctx.info(title)
        print(format_examples_help(examples_list))
    else:
        # Show all examples organized by command group
        ctx.info("All BNAP CLI Examples")
        
        for group, commands in COMMAND_EXAMPLES.items():
            print(f"\n{group.upper()} Commands:")
            print("=" * (len(group) + 10))
            
            for cmd, examples in commands.items():
                print(f"\n{cmd}:")
                print("-" * (len(cmd) + 1))
                for description, example in examples:
                    print(f"\n  # {description}")
                    print(f"  {example}")


@help.command('troubleshoot')
@click.option('--issue', '-i',
              type=click.Choice(['connection_errors', 'validation_errors', 
                               'configuration_issues', 'permission_errors']),
              help='Show specific troubleshooting guide')
@pass_context
def troubleshoot(ctx: CLIContext, issue: Optional[str]):
    """
    Show troubleshooting guides.
    
    Examples:
        bnap help troubleshoot                      # All troubleshooting guides
        bnap help troubleshoot -i connection_errors # Specific issue guide
    """
    if issue:
        guide = get_troubleshooting_guide(issue)
        if guide:
            print(guide)
        else:
            ctx.warning(f"No troubleshooting guide found for: {issue}")
    else:
        ctx.info("BNAP CLI Troubleshooting")
        print(get_troubleshooting_guide())


@help.command('completion')
@click.option('--shell', '-s', 
              type=click.Choice(['bash', 'zsh', 'fish']),
              default='bash',
              help='Shell type for completion script')
@click.option('--output-file', '-o',
              help='Output file for completion script')
@pass_context
def completion(ctx: CLIContext, shell: str, output_file: Optional[str]):
    """
    Generate shell completion script.
    
    Examples:
        bnap help completion                        # Print bash completion
        bnap help completion -s zsh                 # Print zsh completion
        bnap help completion -o ~/.bash_completion  # Save to file
    """
    script = generate_completion_script(shell)
    
    if output_file:
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                f.write(script)
            
            ctx.success(f"Completion script saved to: {output_file}")
            
            # Provide installation instructions
            if shell == 'bash':
                ctx.info("To enable completion, add to ~/.bashrc:")
                print(f"source {output_file}")
            elif shell == 'zsh':
                ctx.info("To enable completion, add to ~/.zshrc:")
                print(f"source {output_file}")
                
        except Exception as e:
            ctx.error(f"Failed to save completion script: {e}")
    else:
        print(script)


@help.command('manpage')
@click.option('--output-file', '-o',
              help='Output file for man page')
@pass_context
def manpage(ctx: CLIContext, output_file: Optional[str]):
    """
    Generate man page for BNAP CLI.
    
    Examples:
        bnap help manpage                          # Print man page
        bnap help manpage -o /usr/local/man/man1/bnap.1  # Save to man directory
    """
    man_content = generate_man_page()
    
    if output_file:
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                f.write(man_content)
            
            ctx.success(f"Man page saved to: {output_file}")
            ctx.info("To view: man bnap")
            
        except Exception as e:
            ctx.error(f"Failed to save man page: {e}")
    else:
        print(man_content)


@help.command('interactive')
@pass_context
def interactive(ctx: CLIContext):
    """
    Interactive help mode.
    
    Provides an interactive prompt for exploring BNAP CLI commands and getting help.
    """
    ctx.info("BNAP CLI Interactive Help")
    print("Type a command group (asset, mint, registry, validator, config) or 'quit' to exit.")
    
    while True:
        try:
            user_input = input("\nhelp> ").strip().lower()
            
            if user_input in ['quit', 'exit', 'q']:
                ctx.info("Goodbye!")
                break
            elif user_input == '':
                continue
            elif user_input in ['help', '?']:
                print("Available commands: asset, mint, registry, validator, config")
                print("Or type 'examples', 'troubleshoot', 'quickstart', 'cheatsheet'")
                print("Type 'quit' to exit")
            elif user_input == 'examples':
                print(format_examples_help(get_command_examples('asset')))
            elif user_input == 'troubleshoot':
                print(get_troubleshooting_guide())
            elif user_input == 'quickstart':
                print(QUICK_START_GUIDE)
            elif user_input == 'cheatsheet':
                print(CHEAT_SHEET)
            elif user_input in COMMAND_EXAMPLES:
                examples = get_command_examples(user_input)
                if examples:
                    print(f"\n{user_input.upper()} Examples:")
                    print(format_examples_help(examples))
                else:
                    print(f"No examples found for: {user_input}")
            else:
                print(f"Unknown command: {user_input}")
                print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            ctx.info("\nGoodbye!")
            break
        except EOFError:
            ctx.info("\nGoodbye!")
            break


@help.command('search')
@click.argument('query')
@pass_context
def search(ctx: CLIContext, query: str):
    """
    Search help content for specific terms.
    
    Examples:
        bnap help search "mint token"      # Search for minting help
        bnap help search "validation"      # Search for validation help
    """
    query = query.lower()
    results = []
    
    # Search in command examples
    for group, commands in COMMAND_EXAMPLES.items():
        for command, examples in commands.items():
            for description, example in examples:
                if (query in description.lower() or 
                    query in example.lower() or 
                    query in command.lower()):
                    results.append({
                        'type': 'example',
                        'group': group,
                        'command': command,
                        'description': description,
                        'content': example
                    })
    
    # Search in troubleshooting guides
    for issue_type, guide in TROUBLESHOOTING_GUIDES.items():
        if (query in guide['title'].lower() or 
            query in guide['description'].lower() or
            any(query in solution.lower() for solution in guide['solutions'])):
            results.append({
                'type': 'troubleshoot',
                'issue': issue_type,
                'title': guide['title'],
                'description': guide['description']
            })
    
    # Search in quick start and cheat sheet
    if query in QUICK_START_GUIDE.lower():
        results.append({
            'type': 'guide',
            'title': 'Quick Start Guide',
            'content': 'Contains information about: ' + query
        })
    
    if query in CHEAT_SHEET.lower():
        results.append({
            'type': 'guide',
            'title': 'Command Cheat Sheet',
            'content': 'Contains information about: ' + query
        })
    
    if not results:
        ctx.warning(f"No help content found for: {query}")
        return
    
    ctx.success(f"Found {len(results)} result(s) for '{query}':")
    
    for result in results:
        if result['type'] == 'example':
            print(f"\n📝 Example: {result['group']} {result['command']}")
            print(f"   {result['description']}")
            print(f"   {result['content']}")
        elif result['type'] == 'troubleshoot':
            print(f"\n🔧 Troubleshooting: {result['title']}")
            print(f"   {result['description']}")
            print(f"   Use: bnap help troubleshoot -i {result['issue']}")
        elif result['type'] == 'guide':
            print(f"\n📚 Guide: {result['title']}")
            print(f"   {result['content']}")


# Export the help command group
__all__ = ['help']