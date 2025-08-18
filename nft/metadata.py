"""
Bitcoin Native Asset Protocol - NFT Metadata Management

This module provides comprehensive NFT metadata handling including JSON schema validation,
metadata standardization, and content binding for Bitcoin-native NFTs.
"""

import json
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path

try:
    import jsonschema
    from jsonschema import validate, ValidationError, Draft7Validator
except ImportError:
    jsonschema = None
    ValidationError = Exception
    Draft7Validator = None


class MetadataVersion(str, Enum):
    """Supported metadata schema versions."""
    V1_0 = "1.0"
    V1_1 = "1.1" 
    V2_0 = "2.0"


class AttributeType(str, Enum):
    """NFT attribute value types."""
    STRING = "string"
    NUMBER = "number" 
    BOOLEAN = "boolean"
    DATE = "date"
    URL = "url"


class ContentType(str, Enum):
    """Supported content types for NFTs."""
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    MODEL_3D = "model_3d"
    DOCUMENT = "document"
    APPLICATION = "application"
    TEXT = "text"


@dataclass
class NFTAttribute:
    """Individual NFT attribute with type validation."""
    
    trait_type: str
    value: Union[str, int, float, bool]
    display_type: Optional[str] = None
    attribute_type: AttributeType = AttributeType.STRING
    max_value: Optional[Union[int, float]] = None
    
    def __post_init__(self):
        """Validate attribute data types."""
        if self.attribute_type == AttributeType.NUMBER:
            if not isinstance(self.value, (int, float)):
                try:
                    self.value = float(self.value)
                except (ValueError, TypeError):
                    raise ValueError(f"Invalid number value for attribute {self.trait_type}: {self.value}")
        
        elif self.attribute_type == AttributeType.BOOLEAN:
            if not isinstance(self.value, bool):
                self.value = str(self.value).lower() in ('true', '1', 'yes', 'on')
        
        elif self.attribute_type == AttributeType.DATE:
            if isinstance(self.value, str):
                try:
                    # Validate ISO format date
                    datetime.fromisoformat(self.value.replace('Z', '+00:00'))
                except ValueError:
                    raise ValueError(f"Invalid date format for attribute {self.trait_type}: {self.value}")
        
        elif self.attribute_type == AttributeType.URL:
            if isinstance(self.value, str):
                if not self.value.startswith(('http://', 'https://', 'ipfs://', 'ar://')):
                    raise ValueError(f"Invalid URL format for attribute {self.trait_type}: {self.value}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            "trait_type": self.trait_type,
            "value": self.value
        }
        
        if self.display_type:
            result["display_type"] = self.display_type
        
        if self.max_value is not None:
            result["max_value"] = self.max_value
            
        return result


@dataclass
class NFTMetadata:
    """Complete NFT metadata structure."""
    
    # Required fields
    name: str
    description: str
    image: str
    
    # Optional standard fields
    external_url: Optional[str] = None
    attributes: List[NFTAttribute] = field(default_factory=list)
    background_color: Optional[str] = None
    animation_url: Optional[str] = None
    youtube_url: Optional[str] = None
    
    # BNAP-specific fields
    content_hash: Optional[str] = None
    content_type: ContentType = ContentType.IMAGE
    content_size: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Schema versioning
    schema_version: MetadataVersion = MetadataVersion.V2_0
    
    # Custom properties
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate metadata after creation."""
        self._validate_urls()
        self._validate_background_color()
        
        # Convert attribute dicts to NFTAttribute objects if needed
        if self.attributes and isinstance(self.attributes[0], dict):
            self.attributes = [
                NFTAttribute(**attr) if isinstance(attr, dict) else attr
                for attr in self.attributes
            ]
    
    def _validate_urls(self):
        """Validate URL formats."""
        urls_to_check = [
            ("image", self.image),
            ("external_url", self.external_url),
            ("animation_url", self.animation_url),
            ("youtube_url", self.youtube_url)
        ]
        
        for field_name, url in urls_to_check:
            if url and not self._is_valid_url(url):
                raise ValueError(f"Invalid URL format for {field_name}: {url}")
    
    def _validate_background_color(self):
        """Validate background color format."""
        if self.background_color:
            # Must be 6-digit hex color without #
            if not (len(self.background_color) == 6 and 
                   all(c in '0123456789ABCDEFabcdef' for c in self.background_color)):
                raise ValueError(f"Background color must be 6-digit hex: {self.background_color}")
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL format is valid."""
        valid_schemes = ['http://', 'https://', 'ipfs://', 'ar://', 'data:']
        return any(url.startswith(scheme) for scheme in valid_schemes)
    
    def add_attribute(self, trait_type: str, value: Any, **kwargs) -> None:
        """Add an attribute to the metadata."""
        attribute = NFTAttribute(trait_type=trait_type, value=value, **kwargs)
        self.attributes.append(attribute)
    
    def get_attribute(self, trait_type: str) -> Optional[NFTAttribute]:
        """Get attribute by trait type."""
        for attr in self.attributes:
            if attr.trait_type == trait_type:
                return attr
        return None
    
    def remove_attribute(self, trait_type: str) -> bool:
        """Remove attribute by trait type."""
        for i, attr in enumerate(self.attributes):
            if attr.trait_type == trait_type:
                del self.attributes[i]
                return True
        return False
    
    def calculate_content_hash(self, content: bytes) -> str:
        """Calculate and set content hash from actual content."""
        content_hash = hashlib.sha256(content).hexdigest()
        self.content_hash = content_hash
        self.content_size = len(content)
        return content_hash
    
    def verify_content_hash(self, content: bytes) -> bool:
        """Verify content matches stored hash."""
        if not self.content_hash:
            return False
        
        calculated_hash = hashlib.sha256(content).hexdigest()
        return calculated_hash == self.content_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for JSON serialization."""
        result = {
            "name": self.name,
            "description": self.description,
            "image": self.image,
        }
        
        # Add optional standard fields
        if self.external_url:
            result["external_url"] = self.external_url
        
        if self.attributes:
            result["attributes"] = [attr.to_dict() for attr in self.attributes]
        
        if self.background_color:
            result["background_color"] = self.background_color
            
        if self.animation_url:
            result["animation_url"] = self.animation_url
            
        if self.youtube_url:
            result["youtube_url"] = self.youtube_url
        
        # Add BNAP-specific fields
        result["content_type"] = self.content_type.value
        result["schema_version"] = self.schema_version.value
        result["created_at"] = self.created_at.isoformat()
        
        if self.content_hash:
            result["content_hash"] = self.content_hash
            
        if self.content_size is not None:
            result["content_size"] = self.content_size
        
        # Add custom properties
        if self.properties:
            result["properties"] = self.properties
        
        return result
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NFTMetadata':
        """Create NFTMetadata from dictionary."""
        # Extract and convert attributes
        attributes_data = data.get('attributes', [])
        attributes = []
        
        for attr_data in attributes_data:
            if isinstance(attr_data, dict):
                # Determine attribute type from value
                value = attr_data['value']
                attr_type = AttributeType.STRING
                
                if isinstance(value, bool):
                    attr_type = AttributeType.BOOLEAN
                elif isinstance(value, (int, float)):
                    attr_type = AttributeType.NUMBER
                elif isinstance(value, str):
                    if attr_data.get('display_type') == 'date':
                        attr_type = AttributeType.DATE
                    elif value.startswith(('http://', 'https://', 'ipfs://', 'ar://')):
                        attr_type = AttributeType.URL
                
                attributes.append(NFTAttribute(
                    trait_type=attr_data['trait_type'],
                    value=value,
                    display_type=attr_data.get('display_type'),
                    attribute_type=attr_type,
                    max_value=attr_data.get('max_value')
                ))
        
        # Parse created_at if present
        created_at = datetime.now(timezone.utc)
        if 'created_at' in data:
            try:
                created_at = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        # Determine content type
        content_type = ContentType.IMAGE
        if 'content_type' in data:
            try:
                content_type = ContentType(data['content_type'])
            except ValueError:
                pass
        
        # Determine schema version
        schema_version = MetadataVersion.V2_0
        if 'schema_version' in data:
            try:
                schema_version = MetadataVersion(data['schema_version'])
            except ValueError:
                pass
        
        return cls(
            name=data['name'],
            description=data['description'],
            image=data['image'],
            external_url=data.get('external_url'),
            attributes=attributes,
            background_color=data.get('background_color'),
            animation_url=data.get('animation_url'),
            youtube_url=data.get('youtube_url'),
            content_hash=data.get('content_hash'),
            content_type=content_type,
            content_size=data.get('content_size'),
            created_at=created_at,
            schema_version=schema_version,
            properties=data.get('properties', {})
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'NFTMetadata':
        """Create NFTMetadata from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


@dataclass
class CollectionMetadata:
    """Metadata for NFT collections."""
    
    name: str
    description: str
    image: str
    collection_size: int
    
    # Optional fields
    external_url: Optional[str] = None
    banner_image: Optional[str] = None
    featured_image: Optional[str] = None
    
    # Collection properties
    creator: Optional[str] = None
    royalty_percentage: Optional[float] = None
    royalty_address: Optional[str] = None
    
    # BNAP-specific
    collection_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            "name": self.name,
            "description": self.description,
            "image": self.image,
            "collection_size": self.collection_size,
            "created_at": self.created_at.isoformat()
        }
        
        # Add optional fields
        optional_fields = [
            'external_url', 'banner_image', 'featured_image',
            'creator', 'royalty_percentage', 'royalty_address',
            'collection_id'
        ]
        
        for field in optional_fields:
            value = getattr(self, field)
            if value is not None:
                result[field] = value
        
        if self.properties:
            result["properties"] = self.properties
        
        return result
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class MetadataSchema:
    """JSON Schema definitions for NFT metadata validation."""
    
    # Base schema for all NFT metadata
    BASE_SCHEMA = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "BNAP NFT Metadata",
        "type": "object",
        "required": ["name", "description", "image"],
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100,
                "description": "Name of the NFT"
            },
            "description": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2000,
                "description": "Description of the NFT"
            },
            "image": {
                "type": "string",
                "format": "uri",
                "description": "URI pointing to the NFT's image"
            },
            "external_url": {
                "type": "string",
                "format": "uri",
                "description": "External URL for the NFT"
            },
            "attributes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["trait_type", "value"],
                    "properties": {
                        "trait_type": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 50
                        },
                        "value": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "number"},
                                {"type": "boolean"}
                            ]
                        },
                        "display_type": {
                            "type": "string",
                            "enum": ["number", "boost_number", "boost_percentage", "date"]
                        },
                        "max_value": {
                            "type": "number"
                        }
                    }
                }
            },
            "background_color": {
                "type": "string",
                "pattern": "^[0-9A-Fa-f]{6}$",
                "description": "6-digit hex color code"
            },
            "animation_url": {
                "type": "string",
                "format": "uri",
                "description": "Animation URL for the NFT"
            },
            "youtube_url": {
                "type": "string",
                "format": "uri",
                "description": "YouTube URL for the NFT"
            }
        }
    }
    
    # BNAP extended schema
    BNAP_SCHEMA = {
        **BASE_SCHEMA,
        "properties": {
            **BASE_SCHEMA["properties"],
            "content_type": {
                "type": "string",
                "enum": ["image", "video", "audio", "model_3d", "document", "application", "text"],
                "description": "Type of content"
            },
            "content_hash": {
                "type": "string",
                "pattern": "^[a-fA-F0-9]{64}$",
                "description": "SHA-256 hash of content"
            },
            "content_size": {
                "type": "integer",
                "minimum": 0,
                "description": "Size of content in bytes"
            },
            "schema_version": {
                "type": "string",
                "enum": ["1.0", "1.1", "2.0"],
                "description": "Metadata schema version"
            },
            "created_at": {
                "type": "string",
                "format": "date-time",
                "description": "Creation timestamp"
            },
            "properties": {
                "type": "object",
                "description": "Custom properties"
            }
        }
    }
    
    # Collection metadata schema
    COLLECTION_SCHEMA = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "BNAP Collection Metadata",
        "type": "object",
        "required": ["name", "description", "image", "collection_size"],
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100
            },
            "description": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2000
            },
            "image": {
                "type": "string",
                "format": "uri"
            },
            "collection_size": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000000
            },
            "external_url": {
                "type": "string",
                "format": "uri"
            },
            "banner_image": {
                "type": "string",
                "format": "uri"
            },
            "featured_image": {
                "type": "string",
                "format": "uri"
            },
            "creator": {
                "type": "string"
            },
            "royalty_percentage": {
                "type": "number",
                "minimum": 0,
                "maximum": 100
            },
            "royalty_address": {
                "type": "string"
            },
            "collection_id": {
                "type": "string",
                "pattern": "^[a-fA-F0-9]{64}$"
            },
            "created_at": {
                "type": "string",
                "format": "date-time"
            },
            "properties": {
                "type": "object"
            }
        }
    }
    
    @classmethod
    def get_schema(cls, schema_type: str = "bnap") -> Dict[str, Any]:
        """Get schema by type."""
        schemas = {
            "base": cls.BASE_SCHEMA,
            "bnap": cls.BNAP_SCHEMA,
            "collection": cls.COLLECTION_SCHEMA
        }
        return schemas.get(schema_type, cls.BNAP_SCHEMA)


class MetadataValidator:
    """Validates NFT metadata against JSON schemas."""
    
    def __init__(self):
        if not jsonschema:
            raise ImportError("jsonschema library required for metadata validation. Install with: pip install jsonschema")
        
        self.validators = {
            "base": Draft7Validator(MetadataSchema.BASE_SCHEMA),
            "bnap": Draft7Validator(MetadataSchema.BNAP_SCHEMA),
            "collection": Draft7Validator(MetadataSchema.COLLECTION_SCHEMA)
        }
    
    def validate(self, metadata: Union[Dict[str, Any], NFTMetadata, CollectionMetadata], 
                schema_type: str = "bnap") -> bool:
        """
        Validate metadata against specified schema.
        
        Args:
            metadata: Metadata to validate
            schema_type: Schema type to use ('base', 'bnap', 'collection')
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If metadata is invalid
        """
        if schema_type not in self.validators:
            raise ValueError(f"Unknown schema type: {schema_type}")
        
        # Convert to dict if needed
        if isinstance(metadata, (NFTMetadata, CollectionMetadata)):
            data = metadata.to_dict()
        else:
            data = metadata
        
        validator = self.validators[schema_type]
        validator.validate(data)
        return True
    
    def get_validation_errors(self, metadata: Union[Dict[str, Any], NFTMetadata, CollectionMetadata],
                            schema_type: str = "bnap") -> List[str]:
        """
        Get list of validation errors without raising exception.
        
        Args:
            metadata: Metadata to validate
            schema_type: Schema type to use
            
        Returns:
            List of error messages (empty if valid)
        """
        if schema_type not in self.validators:
            return [f"Unknown schema type: {schema_type}"]
        
        # Convert to dict if needed
        if isinstance(metadata, (NFTMetadata, CollectionMetadata)):
            data = metadata.to_dict()
        else:
            data = metadata
        
        validator = self.validators[schema_type]
        errors = []
        
        for error in validator.iter_errors(data):
            error_path = " -> ".join(str(p) for p in error.path) if error.path else "root"
            errors.append(f"{error_path}: {error.message}")
        
        return errors
    
    def is_valid(self, metadata: Union[Dict[str, Any], NFTMetadata, CollectionMetadata],
                schema_type: str = "bnap") -> bool:
        """Check if metadata is valid without raising exceptions."""
        try:
            self.validate(metadata, schema_type)
            return True
        except ValidationError:
            return False


# Utility functions

def create_sample_nft_metadata(name: str = "Sample NFT", 
                              description: str = "A sample NFT for testing",
                              image_url: str = "ipfs://QmSampleHash") -> NFTMetadata:
    """Create sample NFT metadata for testing."""
    metadata = NFTMetadata(
        name=name,
        description=description,
        image=image_url,
        content_type=ContentType.IMAGE
    )
    
    # Add sample attributes
    metadata.add_attribute("Color", "Blue", attribute_type=AttributeType.STRING)
    metadata.add_attribute("Rarity", 85, attribute_type=AttributeType.NUMBER, max_value=100)
    metadata.add_attribute("Animated", False, attribute_type=AttributeType.BOOLEAN)
    
    return metadata


def create_sample_collection_metadata(name: str = "Sample Collection",
                                     size: int = 1000) -> CollectionMetadata:
    """Create sample collection metadata for testing."""
    return CollectionMetadata(
        name=name,
        description=f"A collection of {size} unique NFTs",
        image="ipfs://QmSampleCollectionImage",
        collection_size=size,
        creator="Sample Creator",
        royalty_percentage=2.5
    )


# CLI and testing interface

def main():
    """CLI interface for metadata operations."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="BNAP NFT Metadata Tools")
    parser.add_argument("command", choices=["validate", "create-sample", "test"])
    parser.add_argument("--file", help="Metadata JSON file to validate")
    parser.add_argument("--schema", choices=["base", "bnap", "collection"], default="bnap")
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    args = parser.parse_args()
    
    if args.command == "test":
        test_metadata_system()
    elif args.command == "create-sample":
        create_sample_files()
    elif args.command == "validate" and args.file:
        validate_file(args.file, args.schema)


def create_sample_files():
    """Create sample metadata files."""
    # Create sample NFT metadata
    nft_metadata = create_sample_nft_metadata()
    with open("sample_nft_metadata.json", "w") as f:
        f.write(nft_metadata.to_json(indent=2))
    
    # Create sample collection metadata
    collection_metadata = create_sample_collection_metadata()
    with open("sample_collection_metadata.json", "w") as f:
        f.write(collection_metadata.to_json(indent=2))
    
    print("✓ Created sample_nft_metadata.json")
    print("✓ Created sample_collection_metadata.json")


def validate_file(file_path: str, schema_type: str):
    """Validate metadata file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        validator = MetadataValidator()
        errors = validator.get_validation_errors(data, schema_type)
        
        if not errors:
            print(f"✓ {file_path} is valid {schema_type} metadata")
        else:
            print(f"✗ {file_path} validation errors:")
            for error in errors:
                print(f"  - {error}")
                
    except Exception as e:
        print(f"✗ Error validating {file_path}: {e}")


def test_metadata_system():
    """Test the metadata system."""
    print("Testing NFT Metadata System...")
    print("=" * 50)
    
    try:
        # Test NFT metadata creation
        metadata = create_sample_nft_metadata("Test NFT", "A test NFT")
        print("✓ Created sample NFT metadata")
        
        # Test JSON conversion
        json_str = metadata.to_json(indent=2)
        print("✓ Converted to JSON")
        
        # Test JSON parsing
        parsed_metadata = NFTMetadata.from_json(json_str)
        print("✓ Parsed from JSON")
        
        # Test validation
        if jsonschema:
            validator = MetadataValidator()
            validator.validate(metadata)
            print("✓ Metadata validation passed")
        else:
            print("! Skipping validation (jsonschema not available)")
        
        # Test attributes
        metadata.add_attribute("Test Attribute", "Test Value")
        attr = metadata.get_attribute("Test Attribute")
        print(f"✓ Added and retrieved attribute: {attr.value}")
        
        # Test content hash
        test_content = b"test content for hashing"
        content_hash = metadata.calculate_content_hash(test_content)
        print(f"✓ Content hash: {content_hash}")
        
        verified = metadata.verify_content_hash(test_content)
        print(f"✓ Content hash verification: {verified}")
        
        # Test collection metadata
        collection = create_sample_collection_metadata("Test Collection")
        print("✓ Created collection metadata")
        
        print("\nAll metadata system tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False


if __name__ == "__main__":
    main()