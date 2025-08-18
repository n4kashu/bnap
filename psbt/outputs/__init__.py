"""
Bitcoin Native Asset Protocol - PSBT Output Construction Modules

This package provides specialized output construction modules for creating
various types of Bitcoin script outputs within PSBT transactions.
"""

from .p2wsh import *
from .taproot import *
from .op_return import *

__all__ = [
    # P2WSH Output Construction
    'P2WSHBuilder',
    'WitnessScriptBuilder',
    'CovenantScriptBuilder',
    'create_p2wsh_output',
    'create_validator_script',
    'create_asset_commitment_script',
    'create_multisig_script',
    # Taproot Output Construction
    'TaprootBuilder',
    'TaprootScriptBuilder',
    'TaprootTreeBuilder',
    'TapLeaf',
    'TapBranch',
    'TaprootScriptType',
    'create_taproot_output',
    'create_asset_transfer_script',
    'create_asset_mint_script',
    'validate_taproot_script',
    'calculate_tap_leaf_hash',
    # OP_RETURN Metadata Encoder
    'OpReturnEncoder',
    'OpReturnDecoder',
    'MetadataPayload',
    'MetadataType',
    'CompressionType',
    'create_asset_issuance_op_return',
    'create_asset_transfer_op_return',
    'create_nft_metadata_op_return',
    'parse_op_return_metadata',
    'validate_op_return_size'
]

__version__ = '1.0.0'