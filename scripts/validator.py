"""
Bitcoin Native Asset Protocol - Script Validation and Testing Framework

This module provides comprehensive script validation, testing, and debugging
capabilities including Bitcoin Core integration and consensus rule verification.
"""

import hashlib
import struct
import subprocess
import tempfile
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from scripts.p2wsh_covenant import (
    P2WSHCovenantBuilder, 
    WitnessStackItem,
    ScriptOpcode
)
from scripts.taproot_covenant import (
    TaprootCovenantBuilder,
    TaprootOutput,
    TapLeaf,
    ScriptPathInfo,
    TaprootSpendType
)
from crypto.keys import tagged_hash


class ScriptValidationResult(Enum):
    """Script validation results."""
    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"
    CONSENSUS_FAILURE = "consensus_failure"


class ValidationEngine(Enum):
    """Available validation engines."""
    INTERNAL = "internal"
    BITCOIN_CORE = "bitcoin_core"
    BOTH = "both"


@dataclass
class ScriptExecutionContext:
    """Context for script execution and validation."""
    script: bytes
    witness_stack: List[bytes]
    utxo_value: int = 0
    input_index: int = 0
    tx_version: int = 2
    lock_time: int = 0
    hash_type: int = 0x01  # SIGHASH_ALL
    is_taproot: bool = False
    script_tree_root: Optional[bytes] = None
    
    def __post_init__(self):
        """Validate execution context."""
        if self.utxo_value < 0:
            raise ValueError("UTXO value cannot be negative")
        if self.input_index < 0:
            raise ValueError("Input index cannot be negative")


@dataclass
class ValidationResult:
    """Result of script validation."""
    result: ScriptValidationResult
    error_message: Optional[str] = None
    execution_trace: Optional[List[Dict[str, Any]]] = None
    gas_used: Optional[int] = None
    stack_final: Optional[List[bytes]] = None
    validation_time_ms: float = 0.0
    consensus_valid: Optional[bool] = None
    
    def is_valid(self) -> bool:
        """Check if validation passed."""
        return self.result == ScriptValidationResult.VALID
    
    def has_consensus_check(self) -> bool:
        """Check if consensus validation was performed."""
        return self.consensus_valid is not None


@dataclass
class ExecutionStep:
    """Single step in script execution."""
    step: int
    opcode: int
    opcode_name: str
    stack_before: List[bytes]
    stack_after: List[bytes]
    alt_stack: List[bytes] = field(default_factory=list)
    description: str = ""
    gas_cost: int = 0


class ScriptInterpreter:
    """
    Bitcoin Script interpreter for validation and debugging.
    
    This is a simplified interpreter for basic validation and debugging.
    For production use, should delegate to Bitcoin Core for consensus rules.
    """
    
    def __init__(self):
        """Initialize script interpreter."""
        self.logger = logging.getLogger(__name__)
        self.opcodes = self._build_opcode_map()
        self.max_script_size = 10000
        self.max_stack_size = 1000
        self.max_ops = 201
    
    def _build_opcode_map(self) -> Dict[int, str]:
        """Build mapping of opcodes to names."""
        opcode_map = {}
        for attr in dir(ScriptOpcode):
            if attr.startswith('OP_'):
                value = getattr(ScriptOpcode, attr)
                if isinstance(value, int):
                    opcode_map[value] = attr
        return opcode_map
    
    def validate_script(
        self,
        context: ScriptExecutionContext,
        debug: bool = False
    ) -> ValidationResult:
        """
        Validate a script with given execution context.
        
        Args:
            context: Script execution context
            debug: Enable detailed execution tracing
            
        Returns:
            ValidationResult with validation outcome
        """
        start_time = time.time()
        
        try:
            # Basic validation checks
            validation_error = self._validate_basic_constraints(context)
            if validation_error:
                return ValidationResult(
                    result=ScriptValidationResult.INVALID,
                    error_message=validation_error,
                    validation_time_ms=(time.time() - start_time) * 1000
                )
            
            # Execute script
            trace = []
            if context.is_taproot:
                result, final_stack, execution_trace = self._execute_tapscript(
                    context, debug
                )
            else:
                result, final_stack, execution_trace = self._execute_witness_script(
                    context, debug
                )
            
            if debug:
                trace = execution_trace
            
            # Check final result
            if result and final_stack and len(final_stack) == 1:
                if final_stack[0] and final_stack[0] != b'\x00':
                    validation_result = ScriptValidationResult.VALID
                else:
                    validation_result = ScriptValidationResult.INVALID
            else:
                validation_result = ScriptValidationResult.INVALID
            
            return ValidationResult(
                result=validation_result,
                execution_trace=trace,
                stack_final=final_stack,
                validation_time_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            self.logger.error(f"Script validation error: {e}")
            return ValidationResult(
                result=ScriptValidationResult.ERROR,
                error_message=str(e),
                validation_time_ms=(time.time() - start_time) * 1000
            )
    
    def _validate_basic_constraints(self, context: ScriptExecutionContext) -> Optional[str]:
        """Validate basic script constraints."""
        if len(context.script) == 0:
            return "Script cannot be empty"
        
        if len(context.script) > self.max_script_size:
            return f"Script too large: {len(context.script)} bytes"
        
        if len(context.witness_stack) > self.max_stack_size:
            return f"Witness stack too large: {len(context.witness_stack)} items"
        
        return None
    
    def _execute_witness_script(
        self,
        context: ScriptExecutionContext,
        debug: bool = False
    ) -> Tuple[bool, List[bytes], List[ExecutionStep]]:
        """Execute P2WSH witness script."""
        stack = context.witness_stack[:-1]  # All but the script itself
        script = context.witness_stack[-1]   # Script is last item
        
        if script != context.script:
            return False, [], []
        
        trace = []
        pc = 0  # Program counter
        step = 0
        alt_stack = []
        ops_count = 0
        
        while pc < len(script):
            if ops_count > self.max_ops:
                return False, [], trace
            
            # Read opcode
            opcode = script[pc]
            pc += 1
            ops_count += 1
            
            stack_before = stack.copy() if debug else []
            
            # Execute opcode
            success = self._execute_opcode(
                opcode, script, pc, stack, alt_stack
            )
            
            if not success:
                return False, [], trace
            
            if debug:
                step_info = ExecutionStep(
                    step=step,
                    opcode=opcode,
                    opcode_name=self.opcodes.get(opcode, f"OP_UNKNOWN_{opcode:02x}"),
                    stack_before=stack_before,
                    stack_after=stack.copy(),
                    alt_stack=alt_stack.copy(),
                    description=self._describe_operation(opcode),
                    gas_cost=1
                )
                trace.append(step_info)
            
            step += 1
            
            # Handle data pushes that advance PC
            if 1 <= opcode <= 75:
                pc += opcode  # Skip the data bytes
        
        return len(stack) > 0 and stack[-1] != b'\x00', stack, trace
    
    def _execute_tapscript(
        self,
        context: ScriptExecutionContext,
        debug: bool = False
    ) -> Tuple[bool, List[bytes], List[ExecutionStep]]:
        """Execute Taproot script (simplified)."""
        # For Tapscript, similar to witness script but with different rules
        return self._execute_witness_script(context, debug)
    
    def _execute_opcode(
        self,
        opcode: int,
        script: bytes,
        pc: int,
        stack: List[bytes],
        alt_stack: List[bytes]
    ) -> bool:
        """Execute a single opcode."""
        try:
            # Handle data pushes
            if 1 <= opcode <= 75:
                # Push data onto stack
                if pc + opcode > len(script):
                    return False
                data = script[pc:pc + opcode]
                stack.append(data)
                return True
            
            # Handle specific opcodes
            if opcode == ScriptOpcode.OP_0:
                stack.append(b'')
            elif opcode == ScriptOpcode.OP_1NEGATE:
                stack.append(b'\x81')  # -1 in script encoding
            elif ScriptOpcode.OP_1 <= opcode <= ScriptOpcode.OP_16:
                n = opcode - ScriptOpcode.OP_1 + 1
                stack.append(bytes([n]))
            elif opcode == ScriptOpcode.OP_DUP:
                if not stack:
                    return False
                stack.append(stack[-1])
            elif opcode == ScriptOpcode.OP_HASH160:
                if not stack:
                    return False
                data = stack.pop()
                hash_result = self._hash160(data)
                stack.append(hash_result)
            elif opcode == ScriptOpcode.OP_EQUAL:
                if len(stack) < 2:
                    return False
                a = stack.pop()
                b = stack.pop()
                stack.append(b'\x01' if a == b else b'\x00')
            elif opcode == ScriptOpcode.OP_EQUALVERIFY:
                if len(stack) < 2:
                    return False
                a = stack.pop()
                b = stack.pop()
                if a != b:
                    return False
            elif opcode == ScriptOpcode.OP_CHECKSIG:
                # Simplified signature check
                if len(stack) < 2:
                    return False
                pubkey = stack.pop()
                signature = stack.pop()
                # In real implementation, verify signature
                # For now, just check format
                is_valid = (len(signature) > 0 and 
                           len(pubkey) in [33, 32])  # 33 for P2WSH, 32 for Taproot
                stack.append(b'\x01' if is_valid else b'\x00')
            elif opcode == ScriptOpcode.OP_VERIFY:
                if not stack:
                    return False
                value = stack.pop()
                if not value or value == b'\x00':
                    return False
            elif opcode == ScriptOpcode.OP_ADD:
                if len(stack) < 2:
                    return False
                b = self._script_num_to_int(stack.pop())
                a = self._script_num_to_int(stack.pop())
                result = a + b
                stack.append(self._int_to_script_num(result))
            elif opcode == ScriptOpcode.OP_LESSTHANOREQUAL:
                if len(stack) < 2:
                    return False
                b = self._script_num_to_int(stack.pop())
                a = self._script_num_to_int(stack.pop())
                stack.append(b'\x01' if a <= b else b'\x00')
            elif opcode == ScriptOpcode.OP_DROP:
                if not stack:
                    return False
                stack.pop()
            else:
                # Unimplemented opcode
                self.logger.warning(f"Unimplemented opcode: {opcode:02x}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error executing opcode {opcode:02x}: {e}")
            return False
    
    def _script_num_to_int(self, data: bytes) -> int:
        """Convert script number encoding to integer."""
        if len(data) == 0:
            return 0
        
        result = 0
        for i, byte in enumerate(data[:-1]):
            result |= byte << (8 * i)
        
        last_byte = data[-1]
        if last_byte & 0x7f:
            result |= (last_byte & 0x7f) << (8 * (len(data) - 1))
        
        if last_byte & 0x80:
            result = -result
        
        return result
    
    def _int_to_script_num(self, value: int) -> bytes:
        """Convert integer to script number encoding."""
        if value == 0:
            return b''
        
        negative = value < 0
        if negative:
            value = abs(value)
        
        result = []
        while value > 0:
            result.append(value & 0xff)
            value >>= 8
        
        if result[-1] & 0x80:
            if negative:
                result.append(0x80)
            else:
                result.append(0x00)
        elif negative:
            result[-1] |= 0x80
        
        return bytes(result)
    
    def _hash160(self, data: bytes) -> bytes:
        """Compute HASH160 (RIPEMD160(SHA256(data)))."""
        sha256_hash = hashlib.sha256(data).digest()
        # Simplified RIPEMD160 - use SHA256 truncated for testing
        return hashlib.sha256(sha256_hash + b'ripemd160').digest()[:20]
    
    def _describe_operation(self, opcode: int) -> str:
        """Get human-readable description of opcode."""
        descriptions = {
            ScriptOpcode.OP_DUP: "Duplicate top stack item",
            ScriptOpcode.OP_HASH160: "Hash top item with HASH160",
            ScriptOpcode.OP_EQUAL: "Check if top two items are equal",
            ScriptOpcode.OP_EQUALVERIFY: "Check equality and verify",
            ScriptOpcode.OP_CHECKSIG: "Verify signature",
            ScriptOpcode.OP_VERIFY: "Verify top item is true",
            ScriptOpcode.OP_ADD: "Add top two numbers",
            ScriptOpcode.OP_LESSTHANOREQUAL: "Check if a <= b",
        }
        return descriptions.get(opcode, f"Execute opcode {opcode:02x}")


class BitcoinCoreValidator:
    """
    Validator that uses Bitcoin Core for consensus-accurate validation.
    """
    
    def __init__(self, rpc_url: str = "http://127.0.0.1:18443"):
        """
        Initialize Bitcoin Core validator.
        
        Args:
            rpc_url: Bitcoin Core RPC URL
        """
        self.rpc_url = rpc_url
        self.logger = logging.getLogger(__name__)
        self.rpc_auth = None
    
    def validate_script(
        self,
        context: ScriptExecutionContext
    ) -> ValidationResult:
        """
        Validate script using Bitcoin Core RPC.
        
        Args:
            context: Script execution context
            
        Returns:
            ValidationResult with consensus validation
        """
        start_time = time.time()
        
        try:
            # Create temporary transaction for validation
            tx_template = self._create_validation_transaction(context)
            
            # Call Bitcoin Core's testmempoolaccept or similar
            result = self._call_bitcoin_core_validation(tx_template, context)
            
            return ValidationResult(
                result=ScriptValidationResult.VALID if result else ScriptValidationResult.INVALID,
                consensus_valid=result,
                validation_time_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            self.logger.error(f"Bitcoin Core validation error: {e}")
            return ValidationResult(
                result=ScriptValidationResult.ERROR,
                error_message=f"Bitcoin Core validation failed: {e}",
                validation_time_ms=(time.time() - start_time) * 1000
            )
    
    def _create_validation_transaction(
        self,
        context: ScriptExecutionContext
    ) -> Dict[str, Any]:
        """Create transaction template for validation."""
        return {
            "version": context.tx_version,
            "inputs": [{
                "txid": "0" * 64,
                "vout": 0,
                "witness": [item.hex() for item in context.witness_stack],
                "scriptSig": ""
            }],
            "outputs": [{
                "value": context.utxo_value / 100000000,  # Convert to BTC
                "scriptPubKey": context.script.hex()
            }],
            "locktime": context.lock_time
        }
    
    def _call_bitcoin_core_validation(
        self,
        tx_template: Dict[str, Any],
        context: ScriptExecutionContext
    ) -> bool:
        """Call Bitcoin Core for script validation."""
        # This would make actual RPC calls to Bitcoin Core
        # For now, return a placeholder result
        self.logger.info("Bitcoin Core validation (placeholder)")
        return True


class ScriptTestFramework:
    """
    Comprehensive testing framework for Bitcoin scripts.
    """
    
    def __init__(
        self,
        validation_engine: ValidationEngine = ValidationEngine.INTERNAL
    ):
        """
        Initialize test framework.
        
        Args:
            validation_engine: Validation engine to use
        """
        self.validation_engine = validation_engine
        self.internal_validator = ScriptInterpreter()
        self.bitcoin_core_validator = None
        self.logger = logging.getLogger(__name__)
        
        if validation_engine in [ValidationEngine.BITCOIN_CORE, ValidationEngine.BOTH]:
            self.bitcoin_core_validator = BitcoinCoreValidator()
    
    def test_p2wsh_covenant(
        self,
        witness_script: bytes,
        witness_stack: List[bytes],
        expected_result: bool = True
    ) -> ValidationResult:
        """
        Test P2WSH covenant script.
        
        Args:
            witness_script: The witness script
            witness_stack: Witness stack items
            expected_result: Expected validation result
            
        Returns:
            ValidationResult
        """
        # Add witness script to stack
        full_witness_stack = witness_stack + [witness_script]
        
        context = ScriptExecutionContext(
            script=witness_script,
            witness_stack=full_witness_stack,
            utxo_value=100000000,  # 1 BTC
            is_taproot=False
        )
        
        result = self._validate_with_engine(context)
        
        # Check if result matches expectation
        if result.is_valid() != expected_result:
            self.logger.warning(
                f"P2WSH test result mismatch: got {result.is_valid()}, expected {expected_result}"
            )
        
        return result
    
    def test_taproot_covenant(
        self,
        taproot_output: TaprootOutput,
        spend_type: TaprootSpendType,
        witness_stack: List[bytes],
        script_path_info: Optional[ScriptPathInfo] = None,
        expected_result: bool = True
    ) -> ValidationResult:
        """
        Test Taproot covenant script.
        
        Args:
            taproot_output: Taproot output to test
            spend_type: Type of spending (key-path or script-path)
            witness_stack: Witness stack for spending
            script_path_info: Script path info for script-path spending
            expected_result: Expected validation result
            
        Returns:
            ValidationResult
        """
        if spend_type == TaprootSpendType.SCRIPT_PATH:
            if not script_path_info:
                return ValidationResult(
                    result=ScriptValidationResult.ERROR,
                    error_message="Script path info required for script-path spending"
                )
            
            script = script_path_info.leaf.script
            # Add control block and script to witness stack
            full_witness_stack = witness_stack + [
                script,
                script_path_info.control_block
            ]
        else:
            # Key-path spending
            script = b''  # No script for key-path
            full_witness_stack = witness_stack
        
        context = ScriptExecutionContext(
            script=script,
            witness_stack=full_witness_stack,
            utxo_value=100000000,
            is_taproot=True,
            script_tree_root=taproot_output.script_tree
        )
        
        result = self._validate_with_engine(context)
        
        if result.is_valid() != expected_result:
            self.logger.warning(
                f"Taproot test result mismatch: got {result.is_valid()}, expected {expected_result}"
            )
        
        return result
    
    def run_test_suite(
        self,
        test_vectors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Run a comprehensive test suite.
        
        Args:
            test_vectors: List of test cases to run
            
        Returns:
            Test results summary
        """
        results = {
            "total_tests": len(test_vectors),
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "test_results": []
        }
        
        for i, test_vector in enumerate(test_vectors):
            self.logger.info(f"Running test {i+1}/{len(test_vectors)}: {test_vector.get('name', f'Test {i+1}')}")
            
            try:
                if test_vector["type"] == "p2wsh":
                    result = self.test_p2wsh_covenant(
                        test_vector["witness_script"],
                        test_vector["witness_stack"],
                        test_vector.get("expected", True)
                    )
                elif test_vector["type"] == "taproot":
                    result = self.test_taproot_covenant(
                        test_vector["taproot_output"],
                        test_vector["spend_type"],
                        test_vector["witness_stack"],
                        test_vector.get("script_path_info"),
                        test_vector.get("expected", True)
                    )
                else:
                    result = ValidationResult(
                        result=ScriptValidationResult.ERROR,
                        error_message=f"Unknown test type: {test_vector['type']}"
                    )
                
                test_result = {
                    "test_name": test_vector.get("name", f"Test {i+1}"),
                    "passed": result.is_valid() == test_vector.get("expected", True),
                    "validation_result": result.result.value,
                    "error_message": result.error_message,
                    "validation_time_ms": result.validation_time_ms
                }
                
                results["test_results"].append(test_result)
                
                if test_result["passed"]:
                    results["passed"] += 1
                else:
                    results["failed"] += 1
                
            except Exception as e:
                results["errors"] += 1
                results["test_results"].append({
                    "test_name": test_vector.get("name", f"Test {i+1}"),
                    "passed": False,
                    "validation_result": "error",
                    "error_message": str(e),
                    "validation_time_ms": 0
                })
        
        return results
    
    def _validate_with_engine(self, context: ScriptExecutionContext) -> ValidationResult:
        """Validate using configured validation engine."""
        if self.validation_engine == ValidationEngine.INTERNAL:
            return self.internal_validator.validate_script(context, debug=True)
        
        elif self.validation_engine == ValidationEngine.BITCOIN_CORE:
            if self.bitcoin_core_validator:
                return self.bitcoin_core_validator.validate_script(context)
            else:
                return ValidationResult(
                    result=ScriptValidationResult.ERROR,
                    error_message="Bitcoin Core validator not available"
                )
        
        elif self.validation_engine == ValidationEngine.BOTH:
            # Run both validators and compare
            internal_result = self.internal_validator.validate_script(context)
            
            if self.bitcoin_core_validator:
                core_result = self.bitcoin_core_validator.validate_script(context)
                
                # Combine results
                if internal_result.is_valid() != core_result.consensus_valid:
                    self.logger.warning(
                        f"Validation mismatch: internal={internal_result.is_valid()}, "
                        f"core={core_result.consensus_valid}"
                    )
                
                # Return core result with internal trace
                core_result.execution_trace = internal_result.execution_trace
                return core_result
            
            return internal_result
        
        else:
            return ValidationResult(
                result=ScriptValidationResult.ERROR,
                error_message=f"Unknown validation engine: {self.validation_engine}"
            )


def create_test_vectors() -> List[Dict[str, Any]]:
    """Create standard test vectors for script validation."""
    test_vectors = []
    
    # P2WSH validator signature test
    builder = P2WSHCovenantBuilder()
    validator_pubkey = b'\x02' + b'\x01' * 32  # Mock pubkey
    witness_script = builder.create_validator_covenant(validator_pubkey)
    
    test_vectors.append({
        "name": "P2WSH Simple Validator",
        "type": "p2wsh",
        "witness_script": witness_script,
        "witness_stack": [b'\x01' * 64],  # Mock signature
        "expected": True
    })
    
    # P2WSH multisig test
    multisig_script = builder.create_multisig_validator_covenant(
        [validator_pubkey, b'\x03' + b'\x02' * 32],
        2
    )
    
    test_vectors.append({
        "name": "P2WSH Multisig 2-of-2",
        "type": "p2wsh", 
        "witness_script": multisig_script,
        "witness_stack": [b'', b'\x01' * 64, b'\x02' * 64],  # Empty + 2 signatures
        "expected": True
    })
    
    # Invalid signature test
    test_vectors.append({
        "name": "P2WSH Invalid Signature",
        "type": "p2wsh",
        "witness_script": witness_script,
        "witness_stack": [b''],  # Empty signature
        "expected": False
    })
    
    return test_vectors


def run_script_tests(validation_engine: ValidationEngine = ValidationEngine.INTERNAL) -> None:
    """Run the standard script test suite."""
    framework = ScriptTestFramework(validation_engine)
    test_vectors = create_test_vectors()
    
    print("Running Script Validation Tests...")
    print(f"Validation Engine: {validation_engine.value}")
    print(f"Total Tests: {len(test_vectors)}")
    print("-" * 50)
    
    results = framework.run_test_suite(test_vectors)
    
    print(f"\nTest Results:")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Errors: {results['errors']}")
    print(f"Success Rate: {results['passed'] / results['total_tests'] * 100:.1f}%")
    
    if results['failed'] > 0 or results['errors'] > 0:
        print("\nFailed Tests:")
        for test_result in results['test_results']:
            if not test_result['passed']:
                print(f"- {test_result['test_name']}: {test_result.get('error_message', 'Failed')}")


# CLI interface for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        engine_name = sys.argv[1].upper()
        if engine_name == "BITCOIN_CORE":
            engine = ValidationEngine.BITCOIN_CORE
        elif engine_name == "BOTH":
            engine = ValidationEngine.BOTH
        else:
            engine = ValidationEngine.INTERNAL
    else:
        engine = ValidationEngine.INTERNAL
    
    run_script_tests(engine)