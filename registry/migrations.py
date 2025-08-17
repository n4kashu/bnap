"""
Bitcoin Native Asset Protocol - Schema Migration System

This module provides a migration framework for handling registry schema updates,
data transformations, and version management with rollback capabilities.
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable

from .schema import Registry, RegistryMetadata
from .storage import RegistryStorage, StorageError


class MigrationDirection(str, Enum):
    """Migration direction enumeration."""
    UP = "up"
    DOWN = "down"


class MigrationStatus(str, Enum):
    """Migration status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class MigrationError(Exception):
    """Migration operation exception."""
    pass


class SchemaVersionError(MigrationError):
    """Schema version compatibility exception."""
    pass


class Migration(ABC):
    """Abstract base class for registry migrations."""
    
    def __init__(self, version: str, description: str):
        self.version = version
        self.description = description
        self.timestamp = datetime.utcnow()
        self.status = MigrationStatus.PENDING
        self.error_message: Optional[str] = None
    
    @abstractmethod
    def up(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply migration (upgrade).
        
        Args:
            registry_data: Current registry data
            
        Returns:
            Updated registry data
        """
        pass
    
    @abstractmethod
    def down(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reverse migration (downgrade).
        
        Args:
            registry_data: Current registry data
            
        Returns:
            Downgraded registry data
        """
        pass
    
    def validate_data(self, registry_data: Dict[str, Any]) -> bool:
        """
        Validate data before migration.
        
        Args:
            registry_data: Registry data to validate
            
        Returns:
            True if data is valid for migration
        """
        return True
    
    def get_affected_fields(self) -> List[str]:
        """
        Get list of fields affected by this migration.
        
        Returns:
            List of field names
        """
        return []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert migration to dictionary."""
        return {
            'version': self.version,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status.value,
            'error_message': self.error_message,
            'affected_fields': self.get_affected_fields()
        }


class AddAssetStatusFieldMigration(Migration):
    """Migration to add status field to assets."""
    
    def __init__(self):
        super().__init__(
            version="1.1.0",
            description="Add status field to asset definitions"
        )
    
    def up(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add status field to all assets."""
        if 'assets' in registry_data:
            for asset_id, asset_data in registry_data['assets'].items():
                if 'status' not in asset_data:
                    asset_data['status'] = 'active'
        
        # Update metadata version
        if 'metadata' in registry_data:
            registry_data['metadata']['version'] = self.version
        
        return registry_data
    
    def down(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove status field from all assets."""
        if 'assets' in registry_data:
            for asset_id, asset_data in registry_data['assets'].items():
                asset_data.pop('status', None)
        
        # Revert metadata version
        if 'metadata' in registry_data:
            registry_data['metadata']['version'] = "1.0.0"
        
        return registry_data
    
    def get_affected_fields(self) -> List[str]:
        return ['assets.*.status']


class AddScriptFormatFieldMigration(Migration):
    """Migration to add script_format field to assets."""
    
    def __init__(self):
        super().__init__(
            version="1.2.0",
            description="Add script_format field to asset definitions"
        )
    
    def up(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add script_format field to all assets."""
        if 'assets' in registry_data:
            for asset_id, asset_data in registry_data['assets'].items():
                if 'script_format' not in asset_data:
                    asset_data['script_format'] = 'p2tr'  # Default to Taproot
        
        # Update metadata version
        if 'metadata' in registry_data:
            registry_data['metadata']['version'] = self.version
        
        return registry_data
    
    def down(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove script_format field from all assets."""
        if 'assets' in registry_data:
            for asset_id, asset_data in registry_data['assets'].items():
                asset_data.pop('script_format', None)
        
        # Revert metadata version
        if 'metadata' in registry_data:
            registry_data['metadata']['version'] = "1.1.0"
        
        return registry_data
    
    def get_affected_fields(self) -> List[str]:
        return ['assets.*.script_format']


class AddDecimalPlacesFieldMigration(Migration):
    """Migration to add decimal_places field to fungible assets."""
    
    def __init__(self):
        super().__init__(
            version="1.3.0",
            description="Add decimal_places field to fungible assets"
        )
    
    def up(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add decimal_places field to fungible assets."""
        if 'assets' in registry_data:
            for asset_id, asset_data in registry_data['assets'].items():
                if (asset_data.get('asset_type') == 'fungible' and 
                    'decimal_places' not in asset_data):
                    asset_data['decimal_places'] = 0  # Default to no decimals
        
        # Update metadata version
        if 'metadata' in registry_data:
            registry_data['metadata']['version'] = self.version
        
        return registry_data
    
    def down(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove decimal_places field from fungible assets."""
        if 'assets' in registry_data:
            for asset_id, asset_data in registry_data['assets'].items():
                if asset_data.get('asset_type') == 'fungible':
                    asset_data.pop('decimal_places', None)
        
        # Revert metadata version
        if 'metadata' in registry_data:
            registry_data['metadata']['version'] = "1.2.0"
        
        return registry_data
    
    def get_affected_fields(self) -> List[str]:
        return ['assets.*.decimal_places']


class MigrationRegistry:
    """Registry of available migrations."""
    
    def __init__(self):
        self._migrations: Dict[str, Migration] = {}
        self._migration_order: List[str] = []
        self._register_builtin_migrations()
    
    def _register_builtin_migrations(self) -> None:
        """Register built-in migrations."""
        builtin_migrations = [
            AddAssetStatusFieldMigration(),
            AddScriptFormatFieldMigration(),
            AddDecimalPlacesFieldMigration(),
        ]
        
        for migration in builtin_migrations:
            self.register(migration)
    
    def register(self, migration: Migration) -> None:
        """Register a migration."""
        if migration.version in self._migrations:
            raise MigrationError(f"Migration {migration.version} already registered")
        
        self._migrations[migration.version] = migration
        self._migration_order.append(migration.version)
        self._migration_order.sort()  # Keep sorted for proper ordering
    
    def get_migration(self, version: str) -> Optional[Migration]:
        """Get migration by version."""
        return self._migrations.get(version)
    
    def get_migrations_between(
        self,
        from_version: str,
        to_version: str
    ) -> List[Migration]:
        """Get migrations needed to go from one version to another."""
        try:
            from_idx = self._migration_order.index(from_version)
            to_idx = self._migration_order.index(to_version)
        except ValueError as e:
            raise MigrationError(f"Unknown version: {e}")
        
        if from_idx == to_idx:
            return []
        
        if from_idx < to_idx:
            # Upgrade path
            migration_versions = self._migration_order[from_idx + 1:to_idx + 1]
            return [self._migrations[v] for v in migration_versions]
        else:
            # Downgrade path
            migration_versions = self._migration_order[to_idx + 1:from_idx + 1]
            return [self._migrations[v] for v in reversed(migration_versions)]
    
    def get_latest_version(self) -> str:
        """Get the latest migration version."""
        if not self._migration_order:
            return "1.0.0"
        return self._migration_order[-1]
    
    def list_migrations(self) -> List[Migration]:
        """List all registered migrations."""
        return [self._migrations[v] for v in self._migration_order]


class MigrationManager:
    """Manager for registry schema migrations."""
    
    def __init__(
        self,
        storage: RegistryStorage,
        migration_registry: Optional[MigrationRegistry] = None
    ):
        self.storage = storage
        self.migration_registry = migration_registry or MigrationRegistry()
        self.logger = logging.getLogger(__name__)
        self._migration_history: List[Dict[str, Any]] = []
    
    def get_current_version(self) -> str:
        """Get current registry schema version."""
        try:
            registry = self.storage.load_registry()
            return registry.metadata.version
        except Exception:
            return "1.0.0"  # Default version
    
    def needs_migration(self, target_version: Optional[str] = None) -> bool:
        """Check if migration is needed."""
        current_version = self.get_current_version()
        target_version = target_version or self.migration_registry.get_latest_version()
        return current_version != target_version
    
    def migrate(
        self,
        target_version: Optional[str] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Perform migration to target version.
        
        Args:
            target_version: Target schema version (latest if None)
            dry_run: If True, don't apply changes
            
        Returns:
            Migration result with status and details
        """
        current_version = self.get_current_version()
        target_version = target_version or self.migration_registry.get_latest_version()
        
        if current_version == target_version:
            return {
                'status': 'no_migration_needed',
                'current_version': current_version,
                'target_version': target_version
            }
        
        try:
            # Get required migrations
            migrations = self.migration_registry.get_migrations_between(
                current_version, target_version
            )
            
            if not migrations:
                return {
                    'status': 'no_migrations_found',
                    'current_version': current_version,
                    'target_version': target_version
                }
            
            # Determine direction
            is_upgrade = current_version < target_version
            direction = MigrationDirection.UP if is_upgrade else MigrationDirection.DOWN
            
            self.logger.info(
                f"Starting migration from {current_version} to {target_version} "
                f"({direction.value})"
            )
            
            # Load current registry data
            registry_data = self.storage.load_registry().dict()
            
            # Apply migrations
            migration_results = []
            
            for migration in migrations:
                result = self._apply_migration(
                    migration, registry_data, direction, dry_run
                )
                migration_results.append(result)
                
                if not result['success']:
                    # Migration failed, rollback if not dry run
                    if not dry_run:
                        self._rollback_migrations(migration_results[:-1], registry_data)
                    
                    return {
                        'status': 'failed',
                        'current_version': current_version,
                        'target_version': target_version,
                        'failed_migration': migration.version,
                        'error': result['error'],
                        'migrations_applied': migration_results
                    }
            
            # Save updated registry if not dry run
            if not dry_run:
                updated_registry = Registry.parse_obj(registry_data)
                self.storage.save_registry(updated_registry)
                
                # Record migration history
                self._record_migration_history(migrations, direction)
            
            return {
                'status': 'success',
                'current_version': current_version,
                'target_version': target_version,
                'direction': direction.value,
                'migrations_applied': migration_results,
                'dry_run': dry_run
            }
            
        except Exception as e:
            self.logger.error(f"Migration failed: {e}")
            return {
                'status': 'error',
                'current_version': current_version,
                'target_version': target_version,
                'error': str(e)
            }
    
    def _apply_migration(
        self,
        migration: Migration,
        registry_data: Dict[str, Any],
        direction: MigrationDirection,
        dry_run: bool
    ) -> Dict[str, Any]:
        """Apply a single migration."""
        try:
            migration.status = MigrationStatus.RUNNING
            
            # Validate data before migration
            if not migration.validate_data(registry_data):
                raise MigrationError("Data validation failed")
            
            # Apply migration
            if direction == MigrationDirection.UP:
                updated_data = migration.up(registry_data)
            else:
                updated_data = migration.down(registry_data)
            
            # Update registry_data in place if not dry run
            if not dry_run:
                registry_data.clear()
                registry_data.update(updated_data)
            
            migration.status = MigrationStatus.COMPLETED
            
            return {
                'migration': migration.version,
                'direction': direction.value,
                'success': True,
                'affected_fields': migration.get_affected_fields()
            }
            
        except Exception as e:
            migration.status = MigrationStatus.FAILED
            migration.error_message = str(e)
            
            return {
                'migration': migration.version,
                'direction': direction.value,
                'success': False,
                'error': str(e)
            }
    
    def _rollback_migrations(
        self,
        migration_results: List[Dict[str, Any]],
        registry_data: Dict[str, Any]
    ) -> None:
        """Rollback successfully applied migrations."""
        self.logger.info("Rolling back migrations due to failure")
        
        # Reload original data
        original_registry = self.storage.load_registry()
        registry_data.clear()
        registry_data.update(original_registry.dict())
    
    def _record_migration_history(
        self,
        migrations: List[Migration],
        direction: MigrationDirection
    ) -> None:
        """Record migration history."""
        for migration in migrations:
            self._migration_history.append({
                'version': migration.version,
                'description': migration.description,
                'direction': direction.value,
                'timestamp': datetime.utcnow().isoformat(),
                'status': migration.status.value
            })
    
    def get_migration_history(self) -> List[Dict[str, Any]]:
        """Get migration history."""
        return self._migration_history[:]
    
    def validate_registry_compatibility(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate registry data compatibility with current schema.
        
        Args:
            registry_data: Registry data to validate
            
        Returns:
            Validation result with issues and recommendations
        """
        issues = []
        recommendations = []
        
        # Check version
        version = registry_data.get('metadata', {}).get('version', '1.0.0')
        latest_version = self.migration_registry.get_latest_version()
        
        if version != latest_version:
            issues.append(f"Schema version {version} is outdated (latest: {latest_version})")
            recommendations.append(f"Run migration to version {latest_version}")
        
        # Check required fields
        required_sections = ['metadata', 'validators', 'assets', 'state']
        for section in required_sections:
            if section not in registry_data:
                issues.append(f"Missing required section: {section}")
                recommendations.append(f"Initialize {section} section")
        
        # Validate assets
        if 'assets' in registry_data:
            for asset_id, asset_data in registry_data['assets'].items():
                asset_issues = self._validate_asset_data(asset_id, asset_data)
                issues.extend(asset_issues)
        
        return {
            'compatible': len(issues) == 0,
            'version': version,
            'latest_version': latest_version,
            'issues': issues,
            'recommendations': recommendations
        }
    
    def _validate_asset_data(self, asset_id: str, asset_data: Dict[str, Any]) -> List[str]:
        """Validate individual asset data."""
        issues = []
        
        required_fields = ['name', 'symbol', 'issuer_pubkey', 'asset_type']
        for field in required_fields:
            if field not in asset_data:
                issues.append(f"Asset {asset_id} missing required field: {field}")
        
        # Type-specific validation
        asset_type = asset_data.get('asset_type')
        if asset_type == 'fungible':
            if 'maximum_supply' not in asset_data:
                issues.append(f"Fungible asset {asset_id} missing maximum_supply")
            if 'per_mint_limit' not in asset_data:
                issues.append(f"Fungible asset {asset_id} missing per_mint_limit")
        elif asset_type == 'nft':
            if 'collection_size' not in asset_data:
                issues.append(f"NFT asset {asset_id} missing collection_size")
        
        return issues
    
    def create_custom_migration(
        self,
        version: str,
        description: str,
        up_func: Callable[[Dict[str, Any]], Dict[str, Any]],
        down_func: Callable[[Dict[str, Any]], Dict[str, Any]],
        affected_fields: Optional[List[str]] = None
    ) -> Migration:
        """
        Create a custom migration from functions.
        
        Args:
            version: Migration version
            description: Migration description
            up_func: Function to apply migration
            down_func: Function to reverse migration
            affected_fields: List of affected field paths
            
        Returns:
            Custom migration instance
        """
        class CustomMigration(Migration):
            def __init__(self):
                super().__init__(version, description)
                self._affected_fields = affected_fields or []
            
            def up(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
                return up_func(registry_data)
            
            def down(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
                return down_func(registry_data)
            
            def get_affected_fields(self) -> List[str]:
                return self._affected_fields
        
        return CustomMigration()