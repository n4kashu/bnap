"""
Bitcoin Native Asset Protocol - PSBT Output Construction Modules

This package provides specialized output construction modules for creating
various types of Bitcoin script outputs within PSBT transactions.
"""

from .p2wsh import *

__all__ = [
    'P2WSHBuilder',
    'WitnessScriptBuilder',
    'CovenantScriptBuilder',
    'create_p2wsh_output',
    'create_validator_script',
    'create_asset_commitment_script',
    'create_multisig_script'
]

__version__ = '1.0.0'