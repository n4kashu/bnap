"""
Bitcoin Native Asset Protocol - Script Encoding and Decoding Utilities

This module provides comprehensive utilities for script serialization, deserialization,
human-readable formatting, and conversion between different script formats.
"""

import hashlib
import struct
import json
import re
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass
from enum import Enum
from io import BytesIO

from scripts.p2wsh_covenant import ScriptOpcode
from scripts.taproot_covenant import TapLeaf, TapBranch


class ScriptFormat(Enum):
    """Script serialization formats."""
    RAW_BYTES = "raw_bytes"
    HEX_STRING = "hex_string"
    ASM_STRING = "asm_string"
    JSON_OBJECT = "json_object"
    COMPACT_BINARY = "compact_binary"


class ScriptType(Enum):
    """Types of Bitcoin scripts."""
    P2PKH = "p2pkh"
    P2SH = "p2sh"
    P2WPKH = "p2wpkh"
    P2WSH = "p2wsh"
    P2TR = "p2tr"
    WITNESS_SCRIPT = "witness_script"
    TAPSCRIPT = "tapscript"
    OP_RETURN = "op_return"
    MULTISIG = "multisig"
    CUSTOM = "custom"


@dataclass
class ScriptElement:
    """Represents a single element in a Bitcoin script."""
    opcode: int
    opcode_name: str
    data: Optional[bytes] = None
    is_push_data: bool = False
    push_data_len: Optional[int] = None
    
    def __len__(self) -> int:
        """Get total size of this script element."""
        size = 1  # Opcode byte
        if self.data:
            size += len(self.data)
        return size
    
    def serialize(self) -> bytes:
        """Serialize script element to bytes."""
        if self.is_push_data and self.data:
            return bytes([self.opcode]) + self.data
        else:
            return bytes([self.opcode])
    
    def to_asm(self) -> str:
        """Convert to assembly string representation."""
        if self.is_push_data and self.data:
            return f"{self.data.hex()}"
        else:
            return self.opcode_name


@dataclass
class ParsedScript:
    """Represents a parsed Bitcoin script."""
    elements: List[ScriptElement]
    raw_bytes: bytes
    script_type: ScriptType = ScriptType.CUSTOM
    is_valid: bool = True
    parse_errors: List[str] = None
    
    def __post_init__(self):
        if self.parse_errors is None:
            self.parse_errors = []
    
    def __len__(self) -> int:
        return len(self.raw_bytes)
    
    def to_asm(self) -> str:
        """Convert to human-readable assembly string."""
        return " ".join(element.to_asm() for element in self.elements)
    
    def to_hex(self) -> str:
        """Convert to hex string."""
        return self.raw_bytes.hex()
    
    def has_errors(self) -> bool:
        """Check if script has parse errors."""
        return len(self.parse_errors) > 0 or not self.is_valid


class ScriptEncoder:
    """
    Encoder for converting scripts to various formats.
    """
    
    def __init__(self):
        """Initialize script encoder."""
        self.opcode_names = self._build_opcode_names()
    
    def _build_opcode_names(self) -> Dict[int, str]:
        """Build mapping of opcodes to names."""
        names = {}
        for attr in dir(ScriptOpcode):
            if attr.startswith('OP_'):
                value = getattr(ScriptOpcode, attr)
                if isinstance(value, int):
                    names[value] = attr
        return names
    
    def encode_script(
        self,
        script: bytes,
        format: ScriptFormat = ScriptFormat.HEX_STRING
    ) -> Union[str, bytes, Dict[str, Any]]:
        """
        Encode script to specified format.
        
        Args:
            script: Raw script bytes
            format: Target encoding format
            
        Returns:
            Encoded script in requested format
        """
        if format == ScriptFormat.RAW_BYTES:
            return script
        
        elif format == ScriptFormat.HEX_STRING:
            return script.hex()
        
        elif format == ScriptFormat.ASM_STRING:
            parsed = self.parse_script(script)
            return parsed.to_asm()
        
        elif format == ScriptFormat.JSON_OBJECT:
            return self._encode_to_json(script)
        
        elif format == ScriptFormat.COMPACT_BINARY:
            return self._encode_compact(script)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def encode_witness_stack(
        self,
        witness_stack: List[bytes],
        format: ScriptFormat = ScriptFormat.JSON_OBJECT
    ) -> Union[str, List[str], Dict[str, Any]]:
        """
        Encode witness stack to specified format.
        
        Args:
            witness_stack: List of witness stack items
            format: Target encoding format
            
        Returns:
            Encoded witness stack
        """
        if format == ScriptFormat.HEX_STRING:
            return [item.hex() for item in witness_stack]
        
        elif format == ScriptFormat.JSON_OBJECT:
            return {
                "witness_items": [
                    {
                        "index": i,
                        "hex": item.hex(),
                        "size": len(item),
                        "type": self._detect_witness_item_type(item)
                    }
                    for i, item in enumerate(witness_stack)
                ]
            }
        
        elif format == ScriptFormat.ASM_STRING:
            return " ".join(item.hex() if item else "0" for item in witness_stack)
        
        else:
            raise ValueError(f"Unsupported witness format: {format}")
    
    def encode_taproot_commitment(
        self,
        script_tree: Union[TapLeaf, TapBranch],
        format: ScriptFormat = ScriptFormat.JSON_OBJECT
    ) -> Union[str, Dict[str, Any]]:
        """
        Encode Taproot script tree commitment.
        
        Args:
            script_tree: Taproot script tree
            format: Target encoding format
            
        Returns:
            Encoded script tree
        """
        if format == ScriptFormat.JSON_OBJECT:
            return self._encode_tap_tree_to_json(script_tree)
        
        elif format == ScriptFormat.HEX_STRING:
            if isinstance(script_tree, TapLeaf):
                return script_tree.leaf_hash().hex()
            else:
                return script_tree.branch_hash().hex()
        
        else:
            raise ValueError(f"Unsupported taproot format: {format}")
    
    def _encode_to_json(self, script: bytes) -> Dict[str, Any]:
        """Encode script to JSON object."""
        parsed = self.parse_script(script)
        
        return {
            "hex": script.hex(),
            "asm": parsed.to_asm(),
            "type": parsed.script_type.value,
            "size": len(script),
            "valid": parsed.is_valid,
            "elements": [
                {
                    "opcode": elem.opcode,
                    "opcode_name": elem.opcode_name,
                    "data": elem.data.hex() if elem.data else None,
                    "data_size": len(elem.data) if elem.data else 0,
                    "is_push": elem.is_push_data
                }
                for elem in parsed.elements
            ],
            "errors": parsed.parse_errors
        }
    
    def _encode_compact(self, script: bytes) -> bytes:
        """Encode script in compact binary format."""
        # Simplified compact encoding
        # In practice, this could use more sophisticated compression
        output = BytesIO()
        
        # Write compact size prefix
        output.write(self._serialize_compact_size(len(script)))
        
        # Write script data
        output.write(script)
        
        return output.getvalue()
    
    def _serialize_compact_size(self, n: int) -> bytes:
        """Serialize integer as Bitcoin compact size."""
        if n < 0xfd:
            return struct.pack('<B', n)
        elif n <= 0xffff:
            return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', n)
        else:
            return b'\xff' + struct.pack('<Q', n)
    
    def _detect_witness_item_type(self, item: bytes) -> str:
        """Detect type of witness stack item."""
        if len(item) == 0:
            return "empty"
        elif len(item) == 32:
            return "hash"
        elif len(item) == 33:
            return "pubkey_compressed"
        elif len(item) == 65:
            return "pubkey_uncompressed"
        elif 70 <= len(item) <= 73:
            return "signature"
        elif len(item) > 100:
            return "script"
        else:
            return "data"
    
    def _encode_tap_tree_to_json(
        self,
        tree: Union[TapLeaf, TapBranch],
        level: int = 0
    ) -> Dict[str, Any]:
        """Encode Taproot script tree to JSON."""
        if isinstance(tree, TapLeaf):
            return {
                "type": "leaf",
                "level": level,
                "script": tree.script.hex(),
                "script_asm": self.parse_script(tree.script).to_asm(),
                "leaf_version": tree.leaf_version,
                "leaf_hash": tree.leaf_hash().hex()
            }
        else:
            return {
                "type": "branch",
                "level": level,
                "branch_hash": tree.branch_hash().hex(),
                "left": self._encode_tap_tree_to_json(tree.left, level + 1),
                "right": self._encode_tap_tree_to_json(tree.right, level + 1)
            }
    
    def parse_script(self, script: bytes) -> ParsedScript:
        """Parse raw script bytes into structured representation."""
        elements = []
        errors = []
        pc = 0
        
        try:
            while pc < len(script):
                opcode = script[pc]
                pc += 1
                
                opcode_name = self.opcode_names.get(opcode, f"OP_UNKNOWN_{opcode:02x}")
                
                # Handle data pushes
                if 1 <= opcode <= 75:
                    # Direct data push
                    if pc + opcode > len(script):
                        errors.append(f"Insufficient data for push at position {pc-1}")
                        break
                    
                    data = script[pc:pc + opcode]
                    pc += opcode
                    
                    elements.append(ScriptElement(
                        opcode=opcode,
                        opcode_name=f"OP_PUSHDATA({opcode})",
                        data=data,
                        is_push_data=True,
                        push_data_len=opcode
                    ))
                
                elif opcode == 76:  # OP_PUSHDATA1
                    if pc >= len(script):
                        errors.append("Missing length byte for OP_PUSHDATA1")
                        break
                    
                    data_len = script[pc]
                    pc += 1
                    
                    if pc + data_len > len(script):
                        errors.append(f"Insufficient data for OP_PUSHDATA1 at position {pc-2}")
                        break
                    
                    data = script[pc:pc + data_len]
                    pc += data_len
                    
                    elements.append(ScriptElement(
                        opcode=opcode,
                        opcode_name="OP_PUSHDATA1",
                        data=data,
                        is_push_data=True,
                        push_data_len=data_len
                    ))
                
                elif opcode == 77:  # OP_PUSHDATA2
                    if pc + 2 > len(script):
                        errors.append("Missing length bytes for OP_PUSHDATA2")
                        break
                    
                    data_len = struct.unpack('<H', script[pc:pc+2])[0]
                    pc += 2
                    
                    if pc + data_len > len(script):
                        errors.append(f"Insufficient data for OP_PUSHDATA2 at position {pc-3}")
                        break
                    
                    data = script[pc:pc + data_len]
                    pc += data_len
                    
                    elements.append(ScriptElement(
                        opcode=opcode,
                        opcode_name="OP_PUSHDATA2",
                        data=data,
                        is_push_data=True,
                        push_data_len=data_len
                    ))
                
                elif opcode == 78:  # OP_PUSHDATA4
                    if pc + 4 > len(script):
                        errors.append("Missing length bytes for OP_PUSHDATA4")
                        break
                    
                    data_len = struct.unpack('<I', script[pc:pc+4])[0]
                    pc += 4
                    
                    if pc + data_len > len(script):
                        errors.append(f"Insufficient data for OP_PUSHDATA4 at position {pc-5}")
                        break
                    
                    data = script[pc:pc + data_len]
                    pc += data_len
                    
                    elements.append(ScriptElement(
                        opcode=opcode,
                        opcode_name="OP_PUSHDATA4",
                        data=data,
                        is_push_data=True,
                        push_data_len=data_len
                    ))
                
                else:
                    # Regular opcode
                    elements.append(ScriptElement(
                        opcode=opcode,
                        opcode_name=opcode_name
                    ))
        
        except Exception as e:
            errors.append(f"Parse error: {e}")
        
        # Detect script type
        script_type = self._detect_script_type(script, elements)
        
        return ParsedScript(
            elements=elements,
            raw_bytes=script,
            script_type=script_type,
            is_valid=len(errors) == 0,
            parse_errors=errors
        )
    
    def _detect_script_type(
        self,
        script: bytes,
        elements: List[ScriptElement]
    ) -> ScriptType:
        """Detect the type of Bitcoin script."""
        if len(script) == 0:
            return ScriptType.CUSTOM
        
        # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        if (len(elements) == 5 and
            elements[0].opcode == ScriptOpcode.OP_DUP and
            elements[1].opcode == ScriptOpcode.OP_HASH160 and
            elements[2].is_push_data and len(elements[2].data) == 20 and
            elements[3].opcode == ScriptOpcode.OP_EQUALVERIFY and
            elements[4].opcode == ScriptOpcode.OP_CHECKSIG):
            return ScriptType.P2PKH
        
        # P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        if (len(elements) == 3 and
            elements[0].opcode == ScriptOpcode.OP_HASH160 and
            elements[1].is_push_data and len(elements[1].data) == 20 and
            elements[2].opcode == ScriptOpcode.OP_EQUAL):
            return ScriptType.P2SH
        
        # P2WPKH: OP_0 <20 bytes>
        if (len(elements) == 2 and
            elements[0].opcode == ScriptOpcode.OP_0 and
            elements[1].is_push_data and len(elements[1].data) == 20):
            return ScriptType.P2WPKH
        
        # P2WSH: OP_0 <32 bytes>
        if (len(elements) == 2 and
            elements[0].opcode == ScriptOpcode.OP_0 and
            elements[1].is_push_data and len(elements[1].data) == 32):
            return ScriptType.P2WSH
        
        # P2TR: OP_1 <32 bytes>
        if (len(elements) == 2 and
            elements[0].opcode == ScriptOpcode.OP_1 and
            elements[1].is_push_data and len(elements[1].data) == 32):
            return ScriptType.P2TR
        
        # OP_RETURN
        if len(elements) > 0 and elements[0].opcode == ScriptOpcode.OP_RETURN:
            return ScriptType.OP_RETURN
        
        # Multisig: <m> <pubkey1> ... <pubkeyn> <n> OP_CHECKMULTISIG
        if (len(elements) >= 4 and
            elements[-1].opcode == ScriptOpcode.OP_CHECKMULTISIG):
            # Check if it looks like multisig structure
            m_op = elements[0].opcode
            n_op = elements[-2].opcode
            if (ScriptOpcode.OP_1 <= m_op <= ScriptOpcode.OP_16 and
                ScriptOpcode.OP_1 <= n_op <= ScriptOpcode.OP_16):
                return ScriptType.MULTISIG
        
        # Check for witness script patterns
        if elements and elements[-1].opcode == ScriptOpcode.OP_CHECKSIG:
            return ScriptType.WITNESS_SCRIPT
        
        return ScriptType.CUSTOM


class ScriptDecoder:
    """
    Decoder for converting scripts from various formats.
    """
    
    def __init__(self):
        """Initialize script decoder."""
        self.encoder = ScriptEncoder()
    
    def decode_script(
        self,
        encoded_script: Union[str, bytes, Dict[str, Any]],
        source_format: ScriptFormat = ScriptFormat.HEX_STRING
    ) -> bytes:
        """
        Decode script from specified format.
        
        Args:
            encoded_script: Encoded script data
            source_format: Source encoding format
            
        Returns:
            Raw script bytes
        """
        if source_format == ScriptFormat.RAW_BYTES:
            return encoded_script
        
        elif source_format == ScriptFormat.HEX_STRING:
            return bytes.fromhex(encoded_script)
        
        elif source_format == ScriptFormat.ASM_STRING:
            return self._decode_from_asm(encoded_script)
        
        elif source_format == ScriptFormat.JSON_OBJECT:
            return self._decode_from_json(encoded_script)
        
        elif source_format == ScriptFormat.COMPACT_BINARY:
            return self._decode_compact(encoded_script)
        
        else:
            raise ValueError(f"Unsupported source format: {source_format}")
    
    def decode_witness_stack(
        self,
        encoded_witness: Union[List[str], Dict[str, Any], str],
        source_format: ScriptFormat = ScriptFormat.HEX_STRING
    ) -> List[bytes]:
        """
        Decode witness stack from specified format.
        
        Args:
            encoded_witness: Encoded witness stack
            source_format: Source encoding format
            
        Returns:
            List of witness stack items as bytes
        """
        if source_format == ScriptFormat.HEX_STRING:
            if isinstance(encoded_witness, list):
                return [bytes.fromhex(item) for item in encoded_witness]
            else:
                # Single hex string, split by spaces
                hex_items = encoded_witness.split()
                return [bytes.fromhex(item) if item != "0" else b'' for item in hex_items]
        
        elif source_format == ScriptFormat.JSON_OBJECT:
            if "witness_items" in encoded_witness:
                return [
                    bytes.fromhex(item["hex"])
                    for item in encoded_witness["witness_items"]
                ]
            else:
                raise ValueError("Invalid witness JSON format")
        
        else:
            raise ValueError(f"Unsupported witness source format: {source_format}")
    
    def decode_taproot_commitment(
        self,
        encoded_tree: Union[str, Dict[str, Any]],
        source_format: ScriptFormat = ScriptFormat.JSON_OBJECT
    ) -> Union[TapLeaf, TapBranch]:
        """
        Decode Taproot script tree from encoded format.
        
        Args:
            encoded_tree: Encoded script tree
            source_format: Source encoding format
            
        Returns:
            Reconstructed script tree
        """
        if source_format == ScriptFormat.JSON_OBJECT:
            return self._decode_tap_tree_from_json(encoded_tree)
        
        else:
            raise ValueError(f"Unsupported taproot source format: {source_format}")
    
    def _decode_from_asm(self, asm_string: str) -> bytes:
        """Decode script from assembly string."""
        output = BytesIO()
        tokens = asm_string.split()
        
        for token in tokens:
            # Try to parse as opcode name
            opcode = self._parse_opcode_name(token)
            if opcode is not None:
                output.write(bytes([opcode]))
            else:
                # Try to parse as hex data
                try:
                    data = bytes.fromhex(token)
                    if len(data) <= 75:
                        # Direct push
                        output.write(bytes([len(data)]))
                        output.write(data)
                    elif len(data) <= 255:
                        # OP_PUSHDATA1
                        output.write(bytes([76, len(data)]))
                        output.write(data)
                    elif len(data) <= 65535:
                        # OP_PUSHDATA2
                        output.write(bytes([77]))
                        output.write(struct.pack('<H', len(data)))
                        output.write(data)
                    else:
                        # OP_PUSHDATA4
                        output.write(bytes([78]))
                        output.write(struct.pack('<I', len(data)))
                        output.write(data)
                except ValueError:
                    raise ValueError(f"Invalid token in ASM: {token}")
        
        return output.getvalue()
    
    def _decode_from_json(self, json_object: Dict[str, Any]) -> bytes:
        """Decode script from JSON object."""
        if "hex" in json_object:
            return bytes.fromhex(json_object["hex"])
        elif "elements" in json_object:
            # Reconstruct from elements
            output = BytesIO()
            for element in json_object["elements"]:
                output.write(bytes([element["opcode"]]))
                if element.get("data"):
                    output.write(bytes.fromhex(element["data"]))
            return output.getvalue()
        else:
            raise ValueError("Invalid script JSON format")
    
    def _decode_compact(self, compact_data: bytes) -> bytes:
        """Decode script from compact binary format."""
        input_stream = BytesIO(compact_data)
        
        # Read compact size
        size = self._parse_compact_size(input_stream)
        
        # Read script data
        script = input_stream.read(size)
        
        if len(script) != size:
            raise ValueError("Incomplete compact script data")
        
        return script
    
    def _parse_compact_size(self, stream: BytesIO) -> int:
        """Parse compact size from byte stream."""
        first_byte = stream.read(1)
        if len(first_byte) != 1:
            raise ValueError("Incomplete compact size")
        
        first = first_byte[0]
        
        if first < 0xfd:
            return first
        elif first == 0xfd:
            data = stream.read(2)
            return struct.unpack('<H', data)[0]
        elif first == 0xfe:
            data = stream.read(4)
            return struct.unpack('<I', data)[0]
        elif first == 0xff:
            data = stream.read(8)
            return struct.unpack('<Q', data)[0]
        else:
            raise ValueError("Invalid compact size marker")
    
    def _parse_opcode_name(self, name: str) -> Optional[int]:
        """Parse opcode name to numeric value."""
        # Build reverse mapping
        if not hasattr(self, '_name_to_opcode'):
            self._name_to_opcode = {}
            for attr in dir(ScriptOpcode):
                if attr.startswith('OP_'):
                    value = getattr(ScriptOpcode, attr)
                    if isinstance(value, int):
                        self._name_to_opcode[attr] = value
        
        return self._name_to_opcode.get(name.upper())
    
    def _decode_tap_tree_from_json(
        self,
        json_tree: Dict[str, Any]
    ) -> Union[TapLeaf, TapBranch]:
        """Decode Taproot script tree from JSON."""
        if json_tree["type"] == "leaf":
            script = bytes.fromhex(json_tree["script"])
            leaf_version = json_tree.get("leaf_version", 0xc0)
            return TapLeaf(script, leaf_version)
        
        elif json_tree["type"] == "branch":
            left = self._decode_tap_tree_from_json(json_tree["left"])
            right = self._decode_tap_tree_from_json(json_tree["right"])
            return TapBranch(left, right)
        
        else:
            raise ValueError(f"Unknown tree node type: {json_tree['type']}")


class ScriptAnalyzer:
    """
    Analyzer for extracting information from scripts.
    """
    
    def __init__(self):
        """Initialize script analyzer."""
        self.encoder = ScriptEncoder()
        self.decoder = ScriptDecoder()
    
    def analyze_script(self, script: bytes) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a script.
        
        Args:
            script: Script bytes to analyze
            
        Returns:
            Analysis results dictionary
        """
        parsed = self.encoder.parse_script(script)
        
        analysis = {
            "basic_info": {
                "size_bytes": len(script),
                "element_count": len(parsed.elements),
                "script_type": parsed.script_type.value,
                "is_valid": parsed.is_valid,
                "hex": script.hex(),
                "asm": parsed.to_asm()
            },
            "opcodes": self._analyze_opcodes(parsed.elements),
            "data_pushes": self._analyze_data_pushes(parsed.elements),
            "security": self._analyze_security(parsed.elements),
            "complexity": self._analyze_complexity(parsed.elements),
            "errors": parsed.parse_errors
        }
        
        return analysis
    
    def _analyze_opcodes(self, elements: List[ScriptElement]) -> Dict[str, Any]:
        """Analyze opcode usage in script."""
        opcode_counts = {}
        push_count = 0
        crypto_ops = 0
        flow_control_ops = 0
        
        for element in elements:
            # Count opcodes
            opcode_name = element.opcode_name
            opcode_counts[opcode_name] = opcode_counts.get(opcode_name, 0) + 1
            
            # Count push operations
            if element.is_push_data:
                push_count += 1
            
            # Count crypto operations
            if element.opcode in [ScriptOpcode.OP_CHECKSIG, ScriptOpcode.OP_CHECKMULTISIG,
                                  ScriptOpcode.OP_HASH160, ScriptOpcode.OP_SHA256]:
                crypto_ops += 1
            
            # Count flow control
            if element.opcode in [ScriptOpcode.OP_IF, ScriptOpcode.OP_ELSE,
                                  ScriptOpcode.OP_ENDIF, ScriptOpcode.OP_VERIFY]:
                flow_control_ops += 1
        
        return {
            "opcode_counts": opcode_counts,
            "push_operations": push_count,
            "crypto_operations": crypto_ops,
            "flow_control_operations": flow_control_ops,
            "total_opcodes": len(elements) - push_count
        }
    
    def _analyze_data_pushes(self, elements: List[ScriptElement]) -> Dict[str, Any]:
        """Analyze data push operations."""
        push_sizes = []
        total_data_bytes = 0
        
        for element in elements:
            if element.is_push_data and element.data:
                push_sizes.append(len(element.data))
                total_data_bytes += len(element.data)
        
        if push_sizes:
            return {
                "push_count": len(push_sizes),
                "total_data_bytes": total_data_bytes,
                "average_push_size": sum(push_sizes) / len(push_sizes),
                "max_push_size": max(push_sizes),
                "min_push_size": min(push_sizes),
                "push_sizes": push_sizes
            }
        else:
            return {
                "push_count": 0,
                "total_data_bytes": 0
            }
    
    def _analyze_security(self, elements: List[ScriptElement]) -> Dict[str, Any]:
        """Analyze security properties of script."""
        warnings = []
        
        # Check for dangerous opcodes
        dangerous_ops = [ScriptOpcode.OP_CAT, ScriptOpcode.OP_SUBSTR, 
                        ScriptOpcode.OP_LEFT, ScriptOpcode.OP_RIGHT]
        
        for element in elements:
            if element.opcode in dangerous_ops:
                warnings.append(f"Dangerous opcode: {element.opcode_name}")
        
        # Check for very large data pushes
        for element in elements:
            if element.is_push_data and element.data and len(element.data) > 520:
                warnings.append(f"Large data push: {len(element.data)} bytes")
        
        # Check for excessive opcodes
        if len(elements) > 201:
            warnings.append(f"High opcode count: {len(elements)}")
        
        return {
            "warnings": warnings,
            "security_score": max(0, 100 - len(warnings) * 10)
        }
    
    def _analyze_complexity(self, elements: List[ScriptElement]) -> Dict[str, Any]:
        """Analyze script complexity."""
        complexity_score = 0
        
        # Base complexity from element count
        complexity_score += len(elements)
        
        # Add complexity for each opcode type
        for element in elements:
            if element.opcode == ScriptOpcode.OP_CHECKMULTISIG:
                complexity_score += 10
            elif element.opcode in [ScriptOpcode.OP_CHECKSIG, ScriptOpcode.OP_HASH160]:
                complexity_score += 5
            elif element.opcode in [ScriptOpcode.OP_IF, ScriptOpcode.OP_ELSE]:
                complexity_score += 3
            elif element.is_push_data:
                complexity_score += 1
        
        # Categorize complexity
        if complexity_score < 10:
            complexity_level = "simple"
        elif complexity_score < 50:
            complexity_level = "moderate"
        elif complexity_score < 100:
            complexity_level = "complex"
        else:
            complexity_level = "very_complex"
        
        return {
            "complexity_score": complexity_score,
            "complexity_level": complexity_level,
            "estimated_execution_cost": complexity_score * 2
        }


# Convenience functions

def script_to_hex(script: bytes) -> str:
    """Convert script bytes to hex string."""
    encoder = ScriptEncoder()
    return encoder.encode_script(script, ScriptFormat.HEX_STRING)


def script_to_asm(script: bytes) -> str:
    """Convert script bytes to assembly string."""
    encoder = ScriptEncoder()
    return encoder.encode_script(script, ScriptFormat.ASM_STRING)


def script_from_hex(hex_string: str) -> bytes:
    """Convert hex string to script bytes."""
    decoder = ScriptDecoder()
    return decoder.decode_script(hex_string, ScriptFormat.HEX_STRING)


def script_from_asm(asm_string: str) -> bytes:
    """Convert assembly string to script bytes."""
    decoder = ScriptDecoder()
    return decoder.decode_script(asm_string, ScriptFormat.ASM_STRING)


def analyze_script_detailed(script: bytes) -> Dict[str, Any]:
    """Perform detailed analysis of script."""
    analyzer = ScriptAnalyzer()
    return analyzer.analyze_script(script)


def format_script_pretty(script: bytes) -> str:
    """Format script for human-readable display."""
    analyzer = ScriptAnalyzer()
    analysis = analyzer.analyze_script(script)
    
    output = []
    output.append(f"Script Analysis")
    output.append(f"=" * 50)
    output.append(f"Size: {analysis['basic_info']['size_bytes']} bytes")
    output.append(f"Type: {analysis['basic_info']['script_type']}")
    output.append(f"Elements: {analysis['basic_info']['element_count']}")
    output.append(f"Valid: {analysis['basic_info']['is_valid']}")
    output.append("")
    output.append(f"Assembly:")
    output.append(f"  {analysis['basic_info']['asm']}")
    output.append("")
    output.append(f"Hex:")
    output.append(f"  {analysis['basic_info']['hex']}")
    
    if analysis['errors']:
        output.append("")
        output.append(f"Errors:")
        for error in analysis['errors']:
            output.append(f"  - {error}")
    
    if analysis['security']['warnings']:
        output.append("")
        output.append(f"Security Warnings:")
        for warning in analysis['security']['warnings']:
            output.append(f"  - {warning}")
    
    return "\n".join(output)


# CLI interface for script encoding/decoding
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Script Encoding/Decoding Utilities")
        print("Usage: python encoding.py <command> <input>")
        print("Commands:")
        print("  encode-hex <hex_script> - Encode hex to various formats")
        print("  decode-asm <asm_script> - Decode ASM to hex")
        print("  analyze <hex_script> - Analyze script")
        print("  format <hex_script> - Pretty format script")
        sys.exit(1)
    
    command = sys.argv[1]
    input_data = sys.argv[2]
    
    try:
        if command == "encode-hex":
            script = bytes.fromhex(input_data)
            encoder = ScriptEncoder()
            
            print(f"Hex: {encoder.encode_script(script, ScriptFormat.HEX_STRING)}")
            print(f"ASM: {encoder.encode_script(script, ScriptFormat.ASM_STRING)}")
            print(f"JSON: {json.dumps(encoder.encode_script(script, ScriptFormat.JSON_OBJECT), indent=2)}")
        
        elif command == "decode-asm":
            decoder = ScriptDecoder()
            script = decoder.decode_script(input_data, ScriptFormat.ASM_STRING)
            print(f"Hex: {script.hex()}")
        
        elif command == "analyze":
            script = bytes.fromhex(input_data)
            analysis = analyze_script_detailed(script)
            print(json.dumps(analysis, indent=2))
        
        elif command == "format":
            script = bytes.fromhex(input_data)
            formatted = format_script_pretty(script)
            print(formatted)
        
        else:
            print(f"Unknown command: {command}")
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)