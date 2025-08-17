# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Bitcoin Native Asset Protocol (BNAP) - Development Guide

## Project Overview

This repository contains the development of a Bitcoin Native Asset Minting & NFT Issuance Platform for the Retest network. The project enables:

- **Fungible Token Issuance**: Colored coin assets with rule-based controls (supply caps, per-mint limits, allowlists)
- **NFT Creation**: Unique digital collectibles with metadata binding and collection management
- **Dual Covenant Approach**: Support for both Taproot (P2TR) and P2WSH formats
- **Standard Bitcoin Compatibility**: All transactions are valid Bitcoin transactions

## Core Architecture

The platform uses a **colored outputs** approach where assets are represented by Bitcoin UTXOs with embedded metadata. A centralized validator (single signer in MVP, expandable to multi-signature quorum) authorizes mints by signing transactions that meet predefined rules.

### Key Components

- **Registry System**: Centralized tracking of asset rules and issuance state
- **Validator Component**: Single-signer authority that validates and signs mint transactions
- **PSBT-based Workflow**: Uses Partially Signed Bitcoin Transactions for coordination
- **Metadata Management**: Secure binding of content to NFTs via cryptographic hashes

## Technical Stack

- **Blockchain**: Bitcoin Retest network (regtest/testnet compatible)
- **Script Types**: P2WSH (Pay-to-Witness-Script-Hash), P2TR (Pay-to-Taproot)
- **Languages**: Python for validator logic, JavaScript for client libraries
- **Cryptographic Libraries**: bitcoinlib, bitcoinjs-lib, btclib
- **Transaction Format**: PSBT (Partially Signed Bitcoin Transaction)
- **Storage**: JSON-based registry, IPFS for NFT content

## Development Commands

### Registry Management
```bash
# Initialize asset registry
python validator/init_registry.py

# Add new fungible asset
python validator/add_asset.py --type=fungible --name="TestToken" --max-supply=1000000

# Add NFT collection
python validator/add_asset.py --type=nft --name="ArtCollection" --max-supply=100
```

### Transaction Processing
```bash
# Validate PSBT
python validator/validate_psbt.py <psbt_base64>

# Sign valid mint transaction
python validator/sign_mint.py <psbt_base64>

# Broadcast transaction
bitcoin-cli sendrawtransaction <hex>
```

### Testing & Development
```bash
# Start regtest Bitcoin node
bitcoind -regtest -daemon

# Generate test blocks
bitcoin-cli -regtest generatetoaddress 101 <address>

# Run validator tests
python -m pytest tests/

# Validate covenant scripts
python scripts/validate_scripts.py
```

## Key Files & Project Structure

### Core Implementation Files
- `validator/` - Validator logic and signing components
- `scripts/` - Covenant scripts for P2WSH and Taproot implementations  
- `registry/` - Asset registry management and state tracking
- `psbt/` - PSBT construction and parsing utilities
- `tests/` - Comprehensive test suite for all components

### Documentation & Requirements
- `prd.prd` - Complete Product Requirements Document
- `idea_and_research.txt` - Technical architecture documentation
- `idea_and_research2.txt` - Market analysis and tokenomics (ACME protocol)
- `tech.txt` - Detailed technical specifications
- `doc.txt` - Implementation guide and examples

### Configuration Files
- `registry.json` - Asset definitions and validator keys
- `manifests/` - NFT collection metadata (JSON)
- `.env` - API keys and network configuration

## Asset Types & Implementation

### Fungible Tokens
- **Maximum Supply**: Hard cap enforcement
- **Per-Mint Limits**: Transaction-level restrictions  
- **Allowlist Support**: Merkle proof-based distribution
- **Colored Outputs**: Bitcoin UTXOs representing asset quantities

### NFTs (Non-Fungible Tokens)
- **Unique Supply**: One-of-one tokens per ID
- **Content Hash Binding**: SHA-256 integrity verification
- **Collection Management**: Group NFTs with manifests
- **Storage Options**: IPFS, Taproot envelope, or URI pointers

## Covenant Implementations

### Taproot Approach (P2TR)
- **Privacy**: Asset commitments hidden in key tweaks
- **Efficiency**: Key-path spending with validator signature
- **Formula**: `P = P_internal + H(asset_commitment) * G`

### P2WSH Approach  
- **Transparency**: Explicit witness scripts for validation
- **Script**: `<ValidatorPubKey> OP_CHECKSIG`
- **Extensible**: Can add on-chain rule enforcement

## Transaction Structure

### Mint Transaction Inputs
- Funding UTXO (provides Bitcoin for fees)
- Asset control UTXO (validator authority, optional)

### Mint Transaction Outputs
- **Asset Output**: Colored coin carrying newly minted assets
- **Marker Output**: OP_RETURN with protocol metadata
- **Change Output**: Return excess Bitcoin to issuer

## Security & Validation

### Validator Responsibilities
- Verify supply limits and per-mint caps
- Validate allowlist proofs (Merkle verification)
- Check content hash binding for NFTs
- Ensure proper transaction structure
- Sign valid PSBTs with appropriate keys

### Rule Enforcement
- **Supply Caps**: Total issuance ≤ maximum supply
- **Mint Limits**: Per-transaction quantity restrictions
- **Allowlist**: Cryptographic proof of authorized recipients
- **Content Integrity**: Hash verification for NFT metadata

## Testing Strategy

### Development Workflow
1. **Unit Tests**: Individual component validation
2. **Integration Tests**: Validator + registry coordination  
3. **End-to-end Tests**: Complete mint-to-transfer workflows
4. **Regtest Validation**: Live blockchain testing

### Test Categories
- PSBT construction and parsing
- Covenant script validation
- Signature verification (ECDSA/Schnorr)
- Registry state management
- Error handling and edge cases

## Common Development Tasks

### Adding New Asset Types
1. Update registry schema in `registry/schema.py`
2. Implement validation logic in `validator/rules.py` 
3. Add PSBT templates in `psbt/templates.py`
4. Create test cases in `tests/assets/`

### Implementing New Covenant Types
1. Define script logic in `scripts/covenants/`
2. Update key derivation in `crypto/keys.py`
3. Modify validator signing in `validator/signer.py`
4. Add integration tests

### Debugging Transaction Issues
1. Check PSBT structure with `psbt/parser.py`
2. Validate scripts with `scripts/validator.py`
3. Verify signatures with `crypto/verify.py`
4. Inspect registry state in `registry/state.py`

# Task Master AI Integration

This project uses Task Master AI for development workflow management. The task management system helps coordinate complex, multi-step implementation tasks.

## Essential Commands

### Core Workflow Commands

```bash
# Project Setup
task-master init                                    # Initialize Task Master in current project
task-master parse-prd .taskmaster/docs/prd.txt      # Generate tasks from PRD document
task-master models --setup                        # Configure AI models interactively

# Daily Development Workflow
task-master list                                   # Show all tasks with status
task-master next                                   # Get next available task to work on
task-master show <id>                             # View detailed task information (e.g., task-master show 1.2)
task-master set-status --id=<id> --status=done    # Mark task complete

# Task Management
task-master add-task --prompt="description" --research        # Add new task with AI assistance
task-master expand --id=<id> --research --force              # Break task into subtasks
task-master update-task --id=<id> --prompt="changes"         # Update specific task
task-master update --from=<id> --prompt="changes"            # Update multiple tasks from ID onwards
task-master update-subtask --id=<id> --prompt="notes"        # Add implementation notes to subtask

# Analysis & Planning
task-master analyze-complexity --research          # Analyze task complexity
task-master complexity-report                      # View complexity analysis
task-master expand --all --research               # Expand all eligible tasks

# Dependencies & Organization
task-master add-dependency --id=<id> --depends-on=<id>       # Add task dependency
task-master move --from=<id> --to=<id>                       # Reorganize task hierarchy
task-master validate-dependencies                            # Check for dependency issues
task-master generate                                         # Update task markdown files (usually auto-called)
```

## Key Files & Project Structure

### Core Files

- `.taskmaster/tasks/tasks.json` - Main task data file (auto-managed)
- `.taskmaster/config.json` - AI model configuration (use `task-master models` to modify)
- `.taskmaster/docs/prd.txt` - Product Requirements Document for parsing
- `.taskmaster/tasks/*.txt` - Individual task files (auto-generated from tasks.json)
- `.env` - API keys for CLI usage

### Claude Code Integration Files

- `CLAUDE.md` - Auto-loaded context for Claude Code (this file)
- `.claude/settings.json` - Claude Code tool allowlist and preferences
- `.claude/commands/` - Custom slash commands for repeated workflows
- `.mcp.json` - MCP server configuration (project-specific)

### Directory Structure

```
project/
├── .taskmaster/
│   ├── tasks/              # Task files directory
│   │   ├── tasks.json      # Main task database
│   │   ├── task-1.md      # Individual task files
│   │   └── task-2.md
│   ├── docs/              # Documentation directory
│   │   ├── prd.txt        # Product requirements
│   ├── reports/           # Analysis reports directory
│   │   └── task-complexity-report.json
│   ├── templates/         # Template files
│   │   └── example_prd.txt  # Example PRD template
│   └── config.json        # AI models & settings
├── .claude/
│   ├── settings.json      # Claude Code configuration
│   └── commands/         # Custom slash commands
├── .env                  # API keys
├── .mcp.json            # MCP configuration
└── CLAUDE.md            # This file - auto-loaded by Claude Code
```

## MCP Integration

Task Master provides an MCP server that Claude Code can connect to. Configure in `.mcp.json`:

```json
{
  "mcpServers": {
    "task-master-ai": {
      "command": "npx",
      "args": ["-y", "--package=task-master-ai", "task-master-ai"],
      "env": {
        "ANTHROPIC_API_KEY": "your_key_here",
        "PERPLEXITY_API_KEY": "your_key_here",
        "OPENAI_API_KEY": "OPENAI_API_KEY_HERE",
        "GOOGLE_API_KEY": "GOOGLE_API_KEY_HERE",
        "XAI_API_KEY": "XAI_API_KEY_HERE",
        "OPENROUTER_API_KEY": "OPENROUTER_API_KEY_HERE",
        "MISTRAL_API_KEY": "MISTRAL_API_KEY_HERE",
        "AZURE_OPENAI_API_KEY": "AZURE_OPENAI_API_KEY_HERE",
        "OLLAMA_API_KEY": "OLLAMA_API_KEY_HERE"
      }
    }
  }
}
```

### Essential MCP Tools

```javascript
help; // = shows available taskmaster commands
// Project setup
initialize_project; // = task-master init
parse_prd; // = task-master parse-prd

// Daily workflow
get_tasks; // = task-master list
next_task; // = task-master next
get_task; // = task-master show <id>
set_task_status; // = task-master set-status

// Task management
add_task; // = task-master add-task
expand_task; // = task-master expand
update_task; // = task-master update-task
update_subtask; // = task-master update-subtask
update; // = task-master update

// Analysis
analyze_project_complexity; // = task-master analyze-complexity
complexity_report; // = task-master complexity-report
```

## Claude Code Workflow Integration

### Standard Development Workflow

#### 1. Project Initialization

```bash
# Initialize Task Master
task-master init

# Create or obtain PRD, then parse it
task-master parse-prd .taskmaster/docs/prd.txt

# Analyze complexity and expand tasks
task-master analyze-complexity --research
task-master expand --all --research
```

If tasks already exist, another PRD can be parsed (with new information only!) using parse-prd with --append flag. This will add the generated tasks to the existing list of tasks..

#### 2. Daily Development Loop

```bash
# Start each session
task-master next                           # Find next available task
task-master show <id>                     # Review task details

# During implementation, check in code context into the tasks and subtasks
task-master update-subtask --id=<id> --prompt="implementation notes..."

# Complete tasks
task-master set-status --id=<id> --status=done
```

#### 3. Multi-Claude Workflows

For complex projects, use multiple Claude Code sessions:

```bash
# Terminal 1: Main implementation
cd project && claude

# Terminal 2: Testing and validation
cd project-test-worktree && claude

# Terminal 3: Documentation updates
cd project-docs-worktree && claude
```

### Custom Slash Commands

Create `.claude/commands/taskmaster-next.md`:

```markdown
Find the next available Task Master task and show its details.

Steps:

1. Run `task-master next` to get the next task
2. If a task is available, run `task-master show <id>` for full details
3. Provide a summary of what needs to be implemented
4. Suggest the first implementation step
```

Create `.claude/commands/taskmaster-complete.md`:

```markdown
Complete a Task Master task: $ARGUMENTS

Steps:

1. Review the current task with `task-master show $ARGUMENTS`
2. Verify all implementation is complete
3. Run any tests related to this task
4. Mark as complete: `task-master set-status --id=$ARGUMENTS --status=done`
5. Show the next available task with `task-master next`
```

## Tool Allowlist Recommendations

Add to `.claude/settings.json`:

```json
{
  "allowedTools": [
    "Edit",
    "Bash(task-master *)",
    "Bash(git commit:*)",
    "Bash(git add:*)",
    "Bash(npm run *)",
    "mcp__task_master_ai__*"
  ]
}
```

## Configuration & Setup

### API Keys Required

At least **one** of these API keys must be configured:

- `ANTHROPIC_API_KEY` (Claude models) - **Recommended**
- `PERPLEXITY_API_KEY` (Research features) - **Highly recommended**
- `OPENAI_API_KEY` (GPT models)
- `GOOGLE_API_KEY` (Gemini models)
- `MISTRAL_API_KEY` (Mistral models)
- `OPENROUTER_API_KEY` (Multiple models)
- `XAI_API_KEY` (Grok models)

An API key is required for any provider used across any of the 3 roles defined in the `models` command.

### Model Configuration

```bash
# Interactive setup (recommended)
task-master models --setup

# Set specific models
task-master models --set-main claude-3-5-sonnet-20241022
task-master models --set-research perplexity-llama-3.1-sonar-large-128k-online
task-master models --set-fallback gpt-4o-mini
```

## Task Structure & IDs

### Task ID Format

- Main tasks: `1`, `2`, `3`, etc.
- Subtasks: `1.1`, `1.2`, `2.1`, etc.
- Sub-subtasks: `1.1.1`, `1.1.2`, etc.

### Task Status Values

- `pending` - Ready to work on
- `in-progress` - Currently being worked on
- `done` - Completed and verified
- `deferred` - Postponed
- `cancelled` - No longer needed
- `blocked` - Waiting on external factors

### Task Fields

```json
{
  "id": "1.2",
  "title": "Implement user authentication",
  "description": "Set up JWT-based auth system",
  "status": "pending",
  "priority": "high",
  "dependencies": ["1.1"],
  "details": "Use bcrypt for hashing, JWT for tokens...",
  "testStrategy": "Unit tests for auth functions, integration tests for login flow",
  "subtasks": []
}
```

## Claude Code Best Practices with Task Master

### Context Management

- Use `/clear` between different tasks to maintain focus
- This CLAUDE.md file is automatically loaded for context
- Use `task-master show <id>` to pull specific task context when needed

### Iterative Implementation

1. `task-master show <subtask-id>` - Understand requirements
2. Explore codebase and plan implementation
3. `task-master update-subtask --id=<id> --prompt="detailed plan"` - Log plan
4. `task-master set-status --id=<id> --status=in-progress` - Start work
5. Implement code following logged plan
6. `task-master update-subtask --id=<id> --prompt="what worked/didn't work"` - Log progress
7. `task-master set-status --id=<id> --status=done` - Complete task

### Complex Workflows with Checklists

For large migrations or multi-step processes:

1. Create a markdown PRD file describing the new changes: `touch task-migration-checklist.md` (prds can be .txt or .md)
2. Use Taskmaster to parse the new prd with `task-master parse-prd --append` (also available in MCP)
3. Use Taskmaster to expand the newly generated tasks into subtasks. Consdier using `analyze-complexity` with the correct --to and --from IDs (the new ids) to identify the ideal subtask amounts for each task. Then expand them.
4. Work through items systematically, checking them off as completed
5. Use `task-master update-subtask` to log progress on each task/subtask and/or updating/researching them before/during implementation if getting stuck

### Git Integration

Task Master works well with `gh` CLI:

```bash
# Create PR for completed task
gh pr create --title "Complete task 1.2: User authentication" --body "Implements JWT auth system as specified in task 1.2"

# Reference task in commits
git commit -m "feat: implement JWT auth (task 1.2)"
```

### Parallel Development with Git Worktrees

```bash
# Create worktrees for parallel task development
git worktree add ../project-auth feature/auth-system
git worktree add ../project-api feature/api-refactor

# Run Claude Code in each worktree
cd ../project-auth && claude    # Terminal 1: Auth work
cd ../project-api && claude     # Terminal 2: API work
```

## Troubleshooting

### AI Commands Failing

```bash
# Check API keys are configured
cat .env                           # For CLI usage

# Verify model configuration
task-master models

# Test with different model
task-master models --set-fallback gpt-4o-mini
```

### MCP Connection Issues

- Check `.mcp.json` configuration
- Verify Node.js installation
- Use `--mcp-debug` flag when starting Claude Code
- Use CLI as fallback if MCP unavailable

### Task File Sync Issues

```bash
# Regenerate task files from tasks.json
task-master generate

# Fix dependency issues
task-master fix-dependencies
```

DO NOT RE-INITIALIZE. That will not do anything beyond re-adding the same Taskmaster core files.

## Important Notes

### AI-Powered Operations

These commands make AI calls and may take up to a minute:

- `parse_prd` / `task-master parse-prd`
- `analyze_project_complexity` / `task-master analyze-complexity`
- `expand_task` / `task-master expand`
- `expand_all` / `task-master expand --all`
- `add_task` / `task-master add-task`
- `update` / `task-master update`
- `update_task` / `task-master update-task`
- `update_subtask` / `task-master update-subtask`

### File Management

- Never manually edit `tasks.json` - use commands instead
- Never manually edit `.taskmaster/config.json` - use `task-master models`
- Task markdown files in `tasks/` are auto-generated
- Run `task-master generate` after manual changes to tasks.json

### Claude Code Session Management

- Use `/clear` frequently to maintain focused context
- Create custom slash commands for repeated Task Master workflows
- Configure tool allowlist to streamline permissions
- Use headless mode for automation: `claude -p "task-master next"`

### Multi-Task Updates

- Use `update --from=<id>` to update multiple future tasks
- Use `update-task --id=<id>` for single task updates
- Use `update-subtask --id=<id>` for implementation logging

### Research Mode

- Add `--research` flag for research-based AI enhancement
- Requires a research model API key like Perplexity (`PERPLEXITY_API_KEY`) in environment
- Provides more informed task creation and updates
- Recommended for complex technical tasks

---

_This guide ensures Claude Code has immediate access to Task Master's essential functionality for agentic development workflows._

## Task Master AI Instructions
**Import Task Master's development workflow commands and guidelines, treat as if import is in the main CLAUDE.md file.**
@./.taskmaster/CLAUDE.md
