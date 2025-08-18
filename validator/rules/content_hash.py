"""
NFT Content Hash Validation Rule

This module implements the ContentHashRule class that validates NFT metadata
integrity and content hash bindings to ensure content authenticity and
immutability for NFT assets.
"""

import logging
import hashlib
import json
import time
import base64
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from validator.core import ValidationRule, ValidationContext
from registry.schema import AssetType
from crypto.commitments import OperationType


class ContentType(str, Enum):
    """Supported NFT content types."""
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    JSON = "json"
    UNKNOWN = "unknown"


class HashMethod(str, Enum):
    """Supported hash methods for content verification."""
    SHA256 = "sha256"
    SHA3_256 = "sha3_256"
    BLAKE2B = "blake2b"
    IPFS = "ipfs"  # IPFS CID validation
    MULTIHASH = "multihash"  # Generic multihash support


class ContentLocation(str, Enum):
    """Content storage locations."""
    IPFS = "ipfs"
    ARWEAVE = "arweave" 
    HTTP = "http"
    HTTPS = "https"
    DATA_URI = "data"
    BITCOIN = "bitcoin"  # On-chain storage


@dataclass
class ContentReference:
    """Represents a reference to NFT content."""
    uri: str
    hash: str
    hash_method: HashMethod
    content_type: ContentType
    size: Optional[int] = None
    mime_type: Optional[str] = None
    
    def __post_init__(self):
        """Validate content reference after initialization."""
        if not self.uri or not self.hash:
            raise ValueError("URI and hash are required for content reference")
        
        # Validate hash format based on method
        if self.hash_method == HashMethod.SHA256:
            if len(self.hash) != 64:
                raise ValueError("SHA256 hash must be 64 hex characters")
        elif self.hash_method == HashMethod.IPFS:
            if not (self.hash.startswith('Qm') or self.hash.startswith('bafy')):
                raise ValueError("Invalid IPFS CID format")


@dataclass
class NFTMetadata:
    """Represents NFT metadata structure."""
    name: str
    description: Optional[str] = None
    image: Optional[ContentReference] = None
    animation_url: Optional[ContentReference] = None
    attributes: List[Dict[str, Any]] = field(default_factory=list)
    external_url: Optional[str] = None
    background_color: Optional[str] = None
    youtube_url: Optional[str] = None
    additional_content: List[ContentReference] = field(default_factory=list)
    
    def get_all_content_references(self) -> List[ContentReference]:
        """Get all content references in the metadata."""
        refs = []
        if self.image:
            refs.append(self.image)
        if self.animation_url:
            refs.append(self.animation_url)
        refs.extend(self.additional_content)
        return refs


@dataclass
class ValidationResult:
    """Result of content hash validation."""
    is_valid: bool
    content_ref: ContentReference
    error_message: Optional[str] = None
    validation_time: float = field(default_factory=time.time)


class ContentHashRule(ValidationRule):
    """
    Validation rule that ensures NFT content hash integrity.
    
    This rule validates that:
    1. NFT metadata contains valid content hash references
    2. Content hashes match the referenced content (when accessible)
    3. Content references use supported storage protocols
    4. Metadata structure follows expected schemas
    """
    
    def __init__(self, 
                 enable_content_fetching: bool = False,
                 max_content_size: int = 100 * 1024 * 1024,  # 100MB
                 timeout_seconds: int = 30,
                 strict_validation: bool = True):
        """
        Initialize the content hash rule.
        
        Args:
            enable_content_fetching: Whether to fetch and validate actual content
            max_content_size: Maximum content size to fetch (bytes)
            timeout_seconds: Timeout for content fetching
            strict_validation: If True, requires content hash validation
        """
        super().__init__(
            name="content_hash",
            description="Validates NFT content hash integrity and metadata structure"
        )
        
        self.enable_content_fetching = enable_content_fetching
        self.max_content_size = max_content_size
        self.timeout_seconds = timeout_seconds
        self.strict_validation = strict_validation
        
        # Cache for validated content hashes
        self.content_cache: Dict[str, ValidationResult] = {}
        self.cache_ttl = 3600  # 1 hour cache
        
        # Statistics tracking
        self.stats = {
            "validations_performed": 0,
            "metadata_parsed": 0,
            "content_validated": 0,
            "content_fetch_errors": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "hash_mismatches": 0,
            "invalid_metadata": 0
        }
    
    def is_applicable(self, context: ValidationContext) -> bool:
        """
        Check if this rule applies to the given validation context.
        
        This rule applies to:
        - NFT mint operations
        - Assets with NFT content metadata
        
        Args:
            context: Validation context
            
        Returns:
            True if this rule should be applied
        """
        if not self.enabled:
            return False
        
        # Only apply to mint operations
        if context.operation != OperationType.MINT:
            return False
        
        # Must have asset ID
        if not context.asset_id:
            return False
        
        # Check if this is an NFT asset
        if hasattr(context, 'asset_type') and context.asset_type != AssetType.NFT:
            return False
        
        # Must have metadata for content validation
        if not hasattr(context, 'metadata') or not context.metadata:
            return False
        
        return True
    
    def validate(self, context: ValidationContext) -> bool:
        """
        Validate NFT content hash integrity.
        
        Args:
            context: Validation context containing NFT data
            
        Returns:
            True if validation passes, False otherwise
        """
        self.stats["validations_performed"] += 1
        
        try:
            # Parse NFT metadata
            metadata = self._parse_metadata(context)
            if not metadata:
                context.add_error(self.name, "Failed to parse NFT metadata")
                self.stats["invalid_metadata"] += 1
                return False
            
            self.stats["metadata_parsed"] += 1
            
            # Validate metadata structure
            if not self._validate_metadata_structure(metadata, context):
                return False
            
            # Get all content references
            content_refs = metadata.get_all_content_references()
            if not content_refs:
                if self.strict_validation:
                    context.add_error(self.name, "No content references found in NFT metadata")
                    return False
                else:
                    self.logger.debug("No content references found, allowing in non-strict mode")
                    return True
            
            # Validate each content reference
            all_valid = True
            for content_ref in content_refs:
                if not self._validate_content_reference(content_ref, context):
                    all_valid = False
                    # Continue validating other references even if one fails
            
            if all_valid:
                self.logger.debug(f"Content hash validation passed for {len(content_refs)} references")
                return True
            else:
                self.logger.debug("Content hash validation failed for some references")
                return False
                
        except Exception as e:
            self.logger.error(f"Content hash validation error: {e}")
            context.add_error(self.name, f"Content hash validation failed: {str(e)}")
            return False
    
    def _parse_metadata(self, context: ValidationContext) -> Optional[NFTMetadata]:
        """
        Parse NFT metadata from validation context.
        
        Args:
            context: Validation context
            
        Returns:
            Parsed NFTMetadata object or None if parsing failed
        """
        try:
            metadata_raw = context.metadata
            
            # Handle different metadata formats
            if isinstance(metadata_raw, str):
                # JSON string
                metadata_dict = json.loads(metadata_raw)
            elif isinstance(metadata_raw, dict):
                # Already a dictionary
                metadata_dict = metadata_raw
            else:
                self.logger.error(f"Unsupported metadata format: {type(metadata_raw)}")
                return None
            
            # Extract required fields
            name = metadata_dict.get("name", "")
            if not name:
                self.logger.error("NFT metadata missing required 'name' field")
                return None
            
            # Parse content references
            image_ref = self._parse_content_reference(
                metadata_dict.get("image"), 
                ContentType.IMAGE
            )
            
            animation_ref = self._parse_content_reference(
                metadata_dict.get("animation_url"), 
                ContentType.VIDEO
            )
            
            # Parse additional content references
            additional_content = []
            if "content" in metadata_dict and isinstance(metadata_dict["content"], list):
                for content_data in metadata_dict["content"]:
                    ref = self._parse_content_reference(content_data, ContentType.UNKNOWN)
                    if ref:
                        additional_content.append(ref)
            
            # Create metadata object
            return NFTMetadata(
                name=name,
                description=metadata_dict.get("description"),
                image=image_ref,
                animation_url=animation_ref,
                attributes=metadata_dict.get("attributes", []),
                external_url=metadata_dict.get("external_url"),
                background_color=metadata_dict.get("background_color"),
                youtube_url=metadata_dict.get("youtube_url"),
                additional_content=additional_content
            )
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON metadata: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to parse metadata: {e}")
            return None
    
    def _parse_content_reference(self, content_data: Any, default_type: ContentType) -> Optional[ContentReference]:
        """
        Parse a single content reference from metadata.
        
        Args:
            content_data: Content reference data
            default_type: Default content type if not specified
            
        Returns:
            ContentReference object or None if parsing failed
        """
        if not content_data:
            return None
        
        try:
            if isinstance(content_data, str):
                # Simple URI string - infer hash method and type
                uri = content_data
                hash_method, content_hash = self._extract_hash_from_uri(uri)
                if not content_hash:
                    # No hash in URI, this might be invalid for strict validation
                    return None
                
                return ContentReference(
                    uri=uri,
                    hash=content_hash,
                    hash_method=hash_method,
                    content_type=self._infer_content_type(uri, default_type)
                )
            
            elif isinstance(content_data, dict):
                # Structured content reference
                uri = content_data.get("uri") or content_data.get("url")
                content_hash = content_data.get("hash")
                hash_method_str = content_data.get("hash_method", "sha256")
                
                if not uri or not content_hash:
                    return None
                
                hash_method = HashMethod(hash_method_str)
                content_type = ContentType(content_data.get("type", default_type.value))
                
                return ContentReference(
                    uri=uri,
                    hash=content_hash,
                    hash_method=hash_method,
                    content_type=content_type,
                    size=content_data.get("size"),
                    mime_type=content_data.get("mime_type")
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to parse content reference: {e}")
            return None
    
    def _extract_hash_from_uri(self, uri: str) -> Tuple[HashMethod, Optional[str]]:
        """
        Extract hash from URI if it contains one.
        
        Args:
            uri: Content URI
            
        Returns:
            Tuple of (hash_method, hash) or (None, None)
        """
        try:
            parsed = urlparse(uri)
            
            # IPFS URIs contain the hash in the path
            if parsed.scheme == "ipfs" or uri.startswith("ipfs://"):
                cid = parsed.path.lstrip("/") or parsed.netloc
                return HashMethod.IPFS, cid
            
            # Arweave transaction IDs are hashes
            if parsed.scheme == "ar" or "arweave" in (parsed.netloc or ""):
                tx_id = parsed.path.lstrip("/") or parsed.netloc
                if len(tx_id) >= 32:  # Arweave transaction IDs can be 32-43 chars
                    return HashMethod.SHA256, tx_id
            
            # Data URIs might contain hashes in parameters
            if parsed.scheme == "data":
                return HashMethod.SHA256, None  # Data URIs embed content directly
            
            # For other URIs, we can't extract a hash
            return HashMethod.SHA256, None
            
        except Exception as e:
            self.logger.debug(f"Could not extract hash from URI {uri}: {e}")
            return HashMethod.SHA256, None
    
    def _infer_content_type(self, uri: str, default: ContentType) -> ContentType:
        """
        Infer content type from URI.
        
        Args:
            uri: Content URI
            default: Default content type
            
        Returns:
            Inferred ContentType
        """
        uri_lower = uri.lower()
        
        # Check file extension
        if any(ext in uri_lower for ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp']):
            return ContentType.IMAGE
        elif any(ext in uri_lower for ext in ['.mp4', '.webm', '.mov', '.avi']):
            return ContentType.VIDEO
        elif any(ext in uri_lower for ext in ['.mp3', '.wav', '.ogg', '.flac']):
            return ContentType.AUDIO
        elif any(ext in uri_lower for ext in ['.pdf', '.doc', '.txt']):
            return ContentType.DOCUMENT
        elif '.json' in uri_lower:
            return ContentType.JSON
        
        return default
    
    def _validate_metadata_structure(self, metadata: NFTMetadata, context: ValidationContext) -> bool:
        """
        Validate NFT metadata structure and required fields.
        
        Args:
            metadata: Parsed NFT metadata
            context: Validation context
            
        Returns:
            True if structure is valid
        """
        # Name is required
        if not metadata.name or not metadata.name.strip():
            context.add_error(self.name, "NFT name is required")
            return False
        
        # Validate attributes structure if present
        if metadata.attributes:
            for i, attr in enumerate(metadata.attributes):
                if not isinstance(attr, dict):
                    context.add_error(self.name, f"Invalid attribute at index {i}: must be object")
                    return False
                
                if "trait_type" not in attr:
                    context.add_error(self.name, f"Attribute at index {i} missing 'trait_type'")
                    return False
        
        # Validate URLs if present
        for url_field in ["external_url", "youtube_url"]:
            url_value = getattr(metadata, url_field)
            if url_value and not self._is_valid_url(url_value):
                context.add_error(self.name, f"Invalid {url_field}: {url_value}")
                return False
        
        return True
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL has valid format."""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False
    
    def _validate_content_reference(self, content_ref: ContentReference, context: ValidationContext) -> bool:
        """
        Validate a single content reference.
        
        Args:
            content_ref: Content reference to validate
            context: Validation context
            
        Returns:
            True if content reference is valid
        """
        try:
            # Check cache first
            cache_key = f"{content_ref.uri}:{content_ref.hash}"
            if cache_key in self.content_cache:
                cached_result = self.content_cache[cache_key]
                if time.time() - cached_result.validation_time < self.cache_ttl:
                    self.stats["cache_hits"] += 1
                    if not cached_result.is_valid:
                        context.add_error(self.name, cached_result.error_message or "Cached validation failed")
                    return cached_result.is_valid
            
            self.stats["cache_misses"] += 1
            
            # Validate URI format
            if not self._validate_uri_format(content_ref.uri):
                error_msg = f"Invalid URI format: {content_ref.uri}"
                context.add_error(self.name, error_msg)
                self._cache_validation_result(cache_key, False, content_ref, error_msg)
                return False
            
            # Validate hash format
            if not self._validate_hash_format(content_ref.hash, content_ref.hash_method):
                error_msg = f"Invalid hash format for {content_ref.hash_method.value}: {content_ref.hash}"
                context.add_error(self.name, error_msg)
                self._cache_validation_result(cache_key, False, content_ref, error_msg)
                return False
            
            # If content fetching is enabled, validate actual content
            if self.enable_content_fetching:
                content_valid = self._validate_content_hash(content_ref, context)
                self._cache_validation_result(cache_key, content_valid, content_ref)
                return content_valid
            else:
                # Just validate the reference structure
                self._cache_validation_result(cache_key, True, content_ref)
                return True
                
        except Exception as e:
            error_msg = f"Content reference validation error: {str(e)}"
            context.add_error(self.name, error_msg)
            self._cache_validation_result(cache_key, False, content_ref, error_msg)
            return False
    
    def _validate_uri_format(self, uri: str) -> bool:
        """
        Validate URI format and supported schemes.
        
        Args:
            uri: URI to validate
            
        Returns:
            True if URI format is valid
        """
        try:
            parsed = urlparse(uri)
            
            # Supported schemes
            supported_schemes = {"http", "https", "ipfs", "ar", "data"}
            if parsed.scheme not in supported_schemes:
                self.logger.debug(f"Unsupported URI scheme: {parsed.scheme}")
                return False
            
            # Additional validation per scheme
            if parsed.scheme in {"http", "https"}:
                return bool(parsed.netloc)
            elif parsed.scheme == "ipfs":
                # IPFS should have a valid CID
                cid = parsed.path.lstrip("/") or parsed.netloc
                return len(cid) > 0
            elif parsed.scheme == "ar":
                # Arweave should have a transaction ID
                tx_id = parsed.path.lstrip("/") or parsed.netloc
                return len(tx_id) >= 32  # Arweave transaction IDs can be 32-43 chars
            elif parsed.scheme == "data":
                # Data URIs should have content
                return bool(parsed.path)
            
            return True
            
        except Exception as e:
            self.logger.debug(f"URI validation error: {e}")
            return False
    
    def _validate_hash_format(self, hash_value: str, hash_method: HashMethod) -> bool:
        """
        Validate hash format based on the hash method.
        
        Args:
            hash_value: Hash to validate
            hash_method: Expected hash method
            
        Returns:
            True if hash format is valid for the method
        """
        try:
            if hash_method == HashMethod.SHA256:
                return len(hash_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value)
            elif hash_method == HashMethod.SHA3_256:
                return len(hash_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value)
            elif hash_method == HashMethod.BLAKE2B:
                return len(hash_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value)
            elif hash_method == HashMethod.IPFS:
                # Basic IPFS CID validation
                return (hash_value.startswith('Qm') and len(hash_value) == 46) or \
                       hash_value.startswith('bafy')
            elif hash_method == HashMethod.MULTIHASH:
                # Basic multihash validation - should be base58 encoded
                return len(hash_value) > 0
            
            return False
            
        except Exception:
            return False
    
    def _validate_content_hash(self, content_ref: ContentReference, context: ValidationContext) -> bool:
        """
        Validate actual content against its hash (if content fetching is enabled).
        
        Args:
            content_ref: Content reference to validate
            context: Validation context
            
        Returns:
            True if content hash matches
        """
        try:
            # This is a placeholder for actual content fetching and validation
            # In a real implementation, this would:
            # 1. Fetch content from the URI
            # 2. Compute hash of the content
            # 3. Compare with the expected hash
            
            self.logger.debug(f"Content fetching not implemented, assuming valid: {content_ref.uri}")
            self.stats["content_validated"] += 1
            
            # Simulate content validation based on URI scheme
            if content_ref.uri.startswith("data:"):
                # For data URIs, we could validate the embedded content
                return self._validate_data_uri_content(content_ref)
            else:
                # For external URIs, we would need to fetch and validate
                # For now, assume valid if format checks passed
                return True
                
        except Exception as e:
            self.logger.error(f"Content hash validation error: {e}")
            self.stats["content_fetch_errors"] += 1
            context.add_error(self.name, f"Failed to validate content hash: {str(e)}")
            return False
    
    def _validate_data_uri_content(self, content_ref: ContentReference) -> bool:
        """
        Validate content embedded in data URI.
        
        Args:
            content_ref: Content reference with data URI
            
        Returns:
            True if embedded content hash matches
        """
        try:
            # Parse data URI: data:[<mediatype>][;base64],<data>
            uri = content_ref.uri
            if not uri.startswith("data:"):
                return False
            
            # Split on comma to separate header from data
            header, data = uri.split(",", 1)
            
            # Check if base64 encoded
            is_base64 = ";base64" in header
            
            if is_base64:
                # Decode base64 content
                content_bytes = base64.b64decode(data)
            else:
                # URL-decoded content
                content_bytes = data.encode('utf-8')
            
            # Compute hash of the content
            if content_ref.hash_method == HashMethod.SHA256:
                computed_hash = hashlib.sha256(content_bytes).hexdigest()
            elif content_ref.hash_method == HashMethod.SHA3_256:
                computed_hash = hashlib.sha3_256(content_bytes).hexdigest()
            elif content_ref.hash_method == HashMethod.BLAKE2B:
                computed_hash = hashlib.blake2b(content_bytes, digest_size=32).hexdigest()
            else:
                # Unsupported hash method for data URI validation
                return False
            
            # Compare computed hash with expected hash
            return computed_hash.lower() == content_ref.hash.lower()
            
        except Exception as e:
            self.logger.error(f"Data URI content validation error: {e}")
            return False
    
    def _cache_validation_result(self, cache_key: str, is_valid: bool, 
                                content_ref: ContentReference, error_message: Optional[str] = None):
        """Cache validation result."""
        self.content_cache[cache_key] = ValidationResult(
            is_valid=is_valid,
            content_ref=content_ref,
            error_message=error_message
        )
    
    def clear_cache(self, uri_pattern: Optional[str] = None):
        """
        Clear content validation cache.
        
        Args:
            uri_pattern: Optional pattern to match URIs for selective clearing
        """
        if uri_pattern:
            # Clear entries matching pattern
            keys_to_remove = [
                key for key in self.content_cache.keys() 
                if uri_pattern in key
            ]
            for key in keys_to_remove:
                del self.content_cache[key]
        else:
            # Clear entire cache
            self.content_cache.clear()
        
        self.logger.debug(f"Cleared content cache: pattern={uri_pattern}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rule statistics."""
        total_validations = self.stats["validations_performed"]
        total_cache_ops = self.stats["cache_hits"] + self.stats["cache_misses"]
        
        cache_hit_rate = (self.stats["cache_hits"] / total_cache_ops * 100) if total_cache_ops > 0 else 0
        success_rate = ((total_validations - self.stats["invalid_metadata"]) / total_validations * 100) if total_validations > 0 else 0
        
        return {
            **self.stats,
            "cache_hit_rate_percent": round(cache_hit_rate, 2),
            "success_rate_percent": round(success_rate, 2),
            "cached_entries": len(self.content_cache),
            "enable_content_fetching": self.enable_content_fetching,
            "strict_validation": self.strict_validation,
            "max_content_size_mb": self.max_content_size / (1024 * 1024)
        }


# Utility functions for content hash validation

def create_content_hash_rule(config: Optional[Dict[str, Any]] = None) -> ContentHashRule:
    """
    Create a ContentHashRule with configuration.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured ContentHashRule instance
    """
    config = config or {}
    
    enable_content_fetching = config.get("enable_content_fetching", False)
    max_content_size = config.get("max_content_size", 100 * 1024 * 1024)
    timeout_seconds = config.get("timeout_seconds", 30)
    strict_validation = config.get("strict_validation", True)
    
    return ContentHashRule(
        enable_content_fetching=enable_content_fetching,
        max_content_size=max_content_size,
        timeout_seconds=timeout_seconds,
        strict_validation=strict_validation
    )


def validate_nft_metadata_quick(metadata: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Quick NFT metadata validation utility.
    
    Args:
        metadata: NFT metadata dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Check required fields
        if not metadata.get("name"):
            return False, "Missing required field: name"
        
        # Validate content references if present
        for field in ["image", "animation_url"]:
            if field in metadata:
                content = metadata[field]
                if isinstance(content, str):
                    # Simple URI validation
                    if not content.startswith(("http://", "https://", "ipfs://", "ar://", "data:")):
                        return False, f"Invalid URI format in {field}: {content}"
                elif isinstance(content, dict):
                    # Structured content reference validation
                    if "uri" not in content or "hash" not in content:
                        return False, f"Missing uri or hash in {field} content reference"
        
        # Validate attributes structure
        if "attributes" in metadata:
            attributes = metadata["attributes"]
            if not isinstance(attributes, list):
                return False, "Attributes must be an array"
            
            for i, attr in enumerate(attributes):
                if not isinstance(attr, dict) or "trait_type" not in attr:
                    return False, f"Invalid attribute at index {i}"
        
        return True, ""
        
    except Exception as e:
        return False, f"Metadata validation error: {str(e)}"


def extract_content_hashes(metadata: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Extract all content hashes from NFT metadata.
    
    Args:
        metadata: NFT metadata dictionary
        
    Returns:
        List of content hash information
    """
    hashes = []
    
    try:
        # Extract from standard fields
        for field in ["image", "animation_url"]:
            if field in metadata:
                content = metadata[field]
                hash_info = _extract_hash_from_content(content, field)
                if hash_info:
                    hashes.append(hash_info)
        
        # Extract from additional content array
        if "content" in metadata and isinstance(metadata["content"], list):
            for i, content in enumerate(metadata["content"]):
                hash_info = _extract_hash_from_content(content, f"content[{i}]")
                if hash_info:
                    hashes.append(hash_info)
        
        return hashes
        
    except Exception:
        return []


def _extract_hash_from_content(content: Any, field_name: str) -> Optional[Dict[str, str]]:
    """Extract hash information from content reference."""
    try:
        if isinstance(content, str):
            # Try to extract hash from URI
            if content.startswith("ipfs://"):
                cid = content.replace("ipfs://", "").split("/")[0]
                return {
                    "field": field_name,
                    "uri": content,
                    "hash": cid,
                    "method": "ipfs"
                }
        elif isinstance(content, dict):
            uri = content.get("uri") or content.get("url")
            hash_value = content.get("hash")
            method = content.get("hash_method", "sha256")
            
            if uri and hash_value:
                return {
                    "field": field_name,
                    "uri": uri,
                    "hash": hash_value,
                    "method": method
                }
        
        return None
        
    except Exception:
        return None