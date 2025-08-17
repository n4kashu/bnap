# Validator Module

This module contains the core validation logic for the Bitcoin Native Asset Protocol.

## Purpose

- Asset rule enforcement and validation
- PSBT validation and signing
- Supply cap and per-mint limit verification
- Allowlist validation with Merkle proofs
- NFT content hash binding verification

## Key Components

- `rules.py` - Asset rule definitions and enforcement
- `signer.py` - PSBT signing functionality
- `state.py` - Validator state management
- `merkle.py` - Merkle proof validation