"""
Unit tests for migration system.
"""

import pytest
import tempfile
import json
from datetime import datetime
from pathlib import Path

from registry.migrations import (
    Migration, MigrationRegistry, MigrationManager,
    AddAssetStatusFieldMigration, AddScriptFormatFieldMigration,
    AddDecimalPlacesFieldMigration, MigrationDirection, MigrationStatus,
    MigrationError, SchemaVersionError
)
from registry.storage import RegistryStorage
from registry.schema import Registry, RegistryMetadata


class TestMigrationBase:
    """Test base migration functionality."""
    
    def test_migration_creation(self):
        """Test basic migration creation."""
        migration = AddAssetStatusFieldMigration()
        
        assert migration.version == "1.1.0"
        assert migration.description == "Add status field to asset definitions"
        assert migration.status == MigrationStatus.PENDING
        assert migration.error_message is None
        assert isinstance(migration.timestamp, datetime)
    
    def test_migration_to_dict(self):
        """Test migration serialization."""
        migration = AddAssetStatusFieldMigration()
        migration_dict = migration.to_dict()
        
        expected_keys = {
            'version', 'description', 'timestamp', 
            'status', 'error_message', 'affected_fields'
        }
        assert set(migration_dict.keys()) == expected_keys
        assert migration_dict['version'] == "1.1.0"
        assert migration_dict['status'] == 'pending'
        assert isinstance(migration_dict['affected_fields'], list)


class TestBuiltinMigrations:
    """Test built-in migration implementations."""
    
    def test_add_status_field_migration(self):
        """Test status field addition migration."""
        migration = AddAssetStatusFieldMigration()
        
        # Test data without status field
        registry_data = {
            'metadata': {'version': '1.0.0'},
            'assets': {
                'asset1': {
                    'name': 'Test Asset',
                    'asset_type': 'fungible'
                },
                'asset2': {
                    'name': 'Test Asset 2',
                    'asset_type': 'nft'
                }
            }
        }
        
        # Apply migration up
        updated_data = migration.up(registry_data.copy())
        
        assert updated_data['metadata']['version'] == '1.1.0'
        assert updated_data['assets']['asset1']['status'] == 'active'
        assert updated_data['assets']['asset2']['status'] == 'active'
        
        # Apply migration down
        downgraded_data = migration.down(updated_data.copy())
        
        assert downgraded_data['metadata']['version'] == '1.0.0'
        assert 'status' not in downgraded_data['assets']['asset1']
        assert 'status' not in downgraded_data['assets']['asset2']
    
    def test_add_script_format_migration(self):
        """Test script format field addition migration."""
        migration = AddScriptFormatFieldMigration()
        
        registry_data = {
            'metadata': {'version': '1.1.0'},
            'assets': {
                'asset1': {
                    'name': 'Test Asset',
                    'asset_type': 'fungible',
                    'status': 'active'
                }
            }
        }
        
        # Apply migration up
        updated_data = migration.up(registry_data.copy())
        
        assert updated_data['metadata']['version'] == '1.2.0'
        assert updated_data['assets']['asset1']['script_format'] == 'p2tr'
        
        # Apply migration down
        downgraded_data = migration.down(updated_data.copy())
        
        assert downgraded_data['metadata']['version'] == '1.1.0'
        assert 'script_format' not in downgraded_data['assets']['asset1']
    
    def test_add_decimal_places_migration(self):
        """Test decimal places field addition migration."""
        migration = AddDecimalPlacesFieldMigration()
        
        registry_data = {
            'metadata': {'version': '1.2.0'},
            'assets': {
                'fungible_asset': {
                    'name': 'Fungible Token',
                    'asset_type': 'fungible',
                    'status': 'active',
                    'script_format': 'p2tr'
                },
                'nft_asset': {
                    'name': 'NFT Collection',
                    'asset_type': 'nft',
                    'status': 'active',
                    'script_format': 'p2tr'
                }
            }
        }
        
        # Apply migration up
        updated_data = migration.up(registry_data.copy())
        
        assert updated_data['metadata']['version'] == '1.3.0'
        assert updated_data['assets']['fungible_asset']['decimal_places'] == 0
        assert 'decimal_places' not in updated_data['assets']['nft_asset']  # NFTs shouldn't get this field
        
        # Apply migration down
        downgraded_data = migration.down(updated_data.copy())
        
        assert downgraded_data['metadata']['version'] == '1.2.0'
        assert 'decimal_places' not in downgraded_data['assets']['fungible_asset']


class TestMigrationRegistry:
    """Test migration registry functionality."""
    
    def test_registry_initialization(self):
        """Test migration registry initialization."""
        registry = MigrationRegistry()
        
        # Should have built-in migrations registered
        migrations = registry.list_migrations()
        assert len(migrations) >= 3  # At least the 3 built-in migrations
        
        versions = [m.version for m in migrations]
        assert "1.1.0" in versions
        assert "1.2.0" in versions
        assert "1.3.0" in versions
    
    def test_migration_registration(self):
        """Test custom migration registration."""
        registry = MigrationRegistry()
        initial_count = len(registry.list_migrations())
        
        # Create custom migration
        class TestMigration(Migration):
            def __init__(self):
                super().__init__("1.4.0", "Test migration")
            
            def up(self, registry_data):
                return registry_data
            
            def down(self, registry_data):
                return registry_data
        
        custom_migration = TestMigration()
        registry.register(custom_migration)
        
        # Verify registration
        assert len(registry.list_migrations()) == initial_count + 1
        retrieved = registry.get_migration("1.4.0")
        assert retrieved is not None
        assert retrieved.description == "Test migration"
        
        # Test duplicate registration
        with pytest.raises(MigrationError, match="already registered"):
            registry.register(custom_migration)
    
    def test_get_migrations_between(self):
        """Test getting migrations between versions."""
        registry = MigrationRegistry()
        
        # Test upgrade path
        upgrade_migrations = registry.get_migrations_between("1.0.0", "1.3.0")
        upgrade_versions = [m.version for m in upgrade_migrations]
        assert upgrade_versions == ["1.1.0", "1.2.0", "1.3.0"]
        
        # Test downgrade path
        downgrade_migrations = registry.get_migrations_between("1.3.0", "1.1.0")
        downgrade_versions = [m.version for m in downgrade_migrations]
        assert downgrade_versions == ["1.3.0", "1.2.0"]  # Reversed order for downgrade
        
        # Test same version
        same_migrations = registry.get_migrations_between("1.2.0", "1.2.0")
        assert len(same_migrations) == 0
        
        # Test invalid version
        with pytest.raises(MigrationError, match="Unknown version"):
            registry.get_migrations_between("1.0.0", "999.0.0")
    
    def test_latest_version(self):
        """Test getting latest version."""
        registry = MigrationRegistry()
        latest = registry.get_latest_version()
        
        # Should be the highest version from built-in migrations
        all_versions = [m.version for m in registry.list_migrations()]
        assert latest == max(all_versions)


class TestMigrationManager:
    """Test migration manager functionality."""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def storage(self, temp_storage_dir):
        """Create registry storage."""
        return RegistryStorage(storage_dir=temp_storage_dir)
    
    @pytest.fixture
    def migration_manager(self, storage):
        """Create migration manager."""
        return MigrationManager(storage)
    
    def test_manager_initialization(self, migration_manager):
        """Test migration manager initialization."""
        assert migration_manager.storage is not None
        assert migration_manager.migration_registry is not None
        assert isinstance(migration_manager._migration_history, list)
    
    def test_get_current_version(self, migration_manager, storage):
        """Test getting current registry version."""
        # Before any registry exists
        current_version = migration_manager.get_current_version()
        assert current_version == "1.0.0"  # Default
        
        # After creating registry
        registry = Registry()
        registry.metadata.version = "1.2.0"
        storage.save_registry(registry)
        
        current_version = migration_manager.get_current_version()
        assert current_version == "1.2.0"
    
    def test_needs_migration(self, migration_manager, storage):
        """Test migration need detection."""
        # Create registry with old version
        registry = Registry()
        registry.metadata.version = "1.0.0"
        storage.save_registry(registry)
        
        assert migration_manager.needs_migration()
        
        # Update to latest version
        latest_version = migration_manager.migration_registry.get_latest_version()
        registry.metadata.version = latest_version
        storage.save_registry(registry)
        
        assert not migration_manager.needs_migration()
    
    def test_dry_run_migration(self, migration_manager, storage):
        """Test dry run migration."""
        # Create registry with old version and test data
        registry = Registry()
        registry.metadata.version = "1.0.0"
        
        # Add test asset without status field
        from registry.schema import FungibleAsset
        test_asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test Asset",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        registry.add_asset(test_asset)
        
        storage.save_registry(registry)
        
        # Perform dry run migration
        result = migration_manager.migrate(dry_run=True)
        
        assert result['status'] == 'success'
        assert result['dry_run'] is True
        assert len(result['migrations_applied']) > 0
        
        # Verify original data unchanged
        reloaded_registry = storage.load_registry()
        assert reloaded_registry.metadata.version == "1.0.0"
    
    def test_actual_migration(self, migration_manager, storage):
        """Test actual migration execution."""
        # Create registry with old version
        registry = Registry()
        registry.metadata.version = "1.0.0"
        
        # Add test asset
        from registry.schema import FungibleAsset
        test_asset = FungibleAsset(
            asset_id="c" * 64,
            name="Migration Test Asset",
            symbol="MTA",
            issuer_pubkey="d" * 64,
            maximum_supply=5000,
            per_mint_limit=500
        )
        registry.add_asset(test_asset)
        
        storage.save_registry(registry)
        
        # Perform actual migration
        result = migration_manager.migrate(dry_run=False)
        
        assert result['status'] == 'success'
        assert result['dry_run'] is False
        
        # Verify migration applied
        migrated_registry = storage.load_registry()
        latest_version = migration_manager.migration_registry.get_latest_version()
        assert migrated_registry.metadata.version == latest_version
        
        # Verify migration history recorded
        history = migration_manager.get_migration_history()
        assert len(history) > 0
    
    def test_migration_validation(self, migration_manager):
        """Test registry compatibility validation."""
        # Test valid registry data
        valid_data = {
            'metadata': {'version': '1.0.0'},
            'validators': {},
            'assets': {
                'test_asset': {
                    'name': 'Test Asset',
                    'symbol': 'TEST',
                    'issuer_pubkey': 'a' * 64,
                    'asset_type': 'fungible',
                    'maximum_supply': 1000,
                    'per_mint_limit': 100
                }
            },
            'state': {}
        }
        
        validation_result = migration_manager.validate_registry_compatibility(valid_data)
        assert validation_result['compatible'] is False  # Due to version mismatch
        assert len(validation_result['issues']) >= 1
        assert len(validation_result['recommendations']) >= 1
        
        # Test invalid registry data
        invalid_data = {
            'metadata': {'version': '1.0.0'},
            'assets': {
                'invalid_asset': {
                    'name': 'Invalid Asset'
                    # Missing required fields
                }
            }
        }
        
        validation_result = migration_manager.validate_registry_compatibility(invalid_data)
        assert validation_result['compatible'] is False
        assert any('missing required' in issue.lower() for issue in validation_result['issues'])
    
    def test_custom_migration_creation(self, migration_manager):
        """Test custom migration creation."""
        def up_func(data):
            # Add custom field to all assets
            if 'assets' in data:
                for asset_data in data['assets'].values():
                    asset_data['custom_field'] = 'custom_value'
            return data
        
        def down_func(data):
            # Remove custom field from all assets
            if 'assets' in data:
                for asset_data in data['assets'].values():
                    asset_data.pop('custom_field', None)
            return data
        
        custom_migration = migration_manager.create_custom_migration(
            version="2.0.0",
            description="Add custom field to assets",
            up_func=up_func,
            down_func=down_func,
            affected_fields=['assets.*.custom_field']
        )
        
        assert custom_migration.version == "2.0.0"
        assert custom_migration.description == "Add custom field to assets"
        assert custom_migration.get_affected_fields() == ['assets.*.custom_field']
        
        # Test migration functions
        test_data = {
            'assets': {
                'test_asset': {'name': 'Test'}
            }
        }
        
        up_result = custom_migration.up(test_data.copy())
        assert up_result['assets']['test_asset']['custom_field'] == 'custom_value'
        
        down_result = custom_migration.down(up_result)
        assert 'custom_field' not in down_result['assets']['test_asset']


class TestMigrationEdgeCases:
    """Test migration edge cases and error scenarios."""
    
    def test_migration_with_empty_registry(self):
        """Test migration on empty registry data."""
        migration = AddAssetStatusFieldMigration()
        
        empty_data = {
            'metadata': {'version': '1.0.0'},
            'validators': {},
            'assets': {},
            'state': {}
        }
        
        # Should not fail on empty assets
        result = migration.up(empty_data.copy())
        assert result['metadata']['version'] == '1.1.0'
        assert len(result['assets']) == 0
    
    def test_migration_with_missing_sections(self):
        """Test migration on registry data with missing sections."""
        migration = AddAssetStatusFieldMigration()
        
        incomplete_data = {
            'metadata': {'version': '1.0.0'}
            # Missing assets, validators, state sections
        }
        
        # Should handle missing sections gracefully
        result = migration.up(incomplete_data.copy())
        assert result['metadata']['version'] == '1.1.0'
    
    def test_migration_data_validation(self):
        """Test migration data validation."""
        class ValidatingMigration(Migration):
            def __init__(self):
                super().__init__("test", "test migration")
            
            def validate_data(self, registry_data):
                # Require specific field
                return 'required_field' in registry_data
            
            def up(self, registry_data):
                return registry_data
            
            def down(self, registry_data):
                return registry_data
        
        migration = ValidatingMigration()
        
        # Test with invalid data
        invalid_data = {'metadata': {'version': '1.0.0'}}
        assert not migration.validate_data(invalid_data)
        
        # Test with valid data
        valid_data = {'required_field': True, 'metadata': {'version': '1.0.0'}}
        assert migration.validate_data(valid_data)