# Configuration Guide

This guide covers comprehensive configuration for BNAP system components across different deployment environments.

## Configuration Overview

BNAP uses a hierarchical configuration system with multiple configuration files:

- **Main Configuration** (`config.json`): Core system settings
- **Bitcoin Configuration** (`bitcoin.conf`): Bitcoin node settings
- **Validator Keys** (`validator_keys.json`): Signing keys and authentication
- **Registry Configuration**: Asset registry settings
- **Environment Variables**: Runtime configuration overrides

## Main Configuration File

### Configuration Structure

The main configuration file follows this structure:

```json
{
  "version": "1.0",
  "environment": "production",
  "network": {
    "type": "mainnet",
    "rpc_host": "127.0.0.1",
    "rpc_port": 8332,
    "rpc_user": "bnap_user",
    "rpc_password": "secure_password_here",
    "rpc_timeout": 30,
    "max_retries": 3
  },
  "validator": {
    "id": "bnap_validator_prod_v1",
    "enable_audit": true,
    "max_validation_time": 30,
    "signing_keys_file": "/path/to/validator_keys.json",
    "backup_keys_file": "/path/to/backup_keys.json",
    "performance": {
      "cache_size": 1000,
      "max_concurrent_validations": 10
    }
  },
  "registry": {
    "file_path": "/var/lib/bnap/registry.json",
    "backup_enabled": true,
    "backup_interval": 3600,
    "max_backup_files": 168,
    "backup_directory": "/var/lib/bnap/backups",
    "compression": true
  },
  "security": {
    "key_encryption": true,
    "hsm_enabled": false,
    "hsm_config": {
      "provider": "pkcs11",
      "library_path": "/usr/lib/pkcs11/opensc-pkcs11.so"
    }
  },
  "logging": {
    "level": "INFO",
    "file_path": "/var/log/bnap/bnap.log",
    "max_file_size": "100MB",
    "backup_count": 10,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  },
  "monitoring": {
    "enabled": true,
    "metrics_port": 9090,
    "health_check_interval": 30
  },
  "cli": {
    "output_format": "table",
    "color_output": true,
    "verbose": 1,
    "confirm_destructive": true
  }
}
```

### Network Configuration

#### Mainnet Configuration

```json
{
  "network": {
    "type": "mainnet",
    "rpc_host": "127.0.0.1",
    "rpc_port": 8332,
    "rpc_user": "bnap_mainnet",
    "rpc_password": "$(openssl rand -base64 32)",
    "rpc_timeout": 30,
    "max_retries": 3,
    "fee_estimation": {
      "target_blocks": 6,
      "max_fee_rate": 1000,
      "fallback_fee_rate": 50
    }
  }
}
```

#### Testnet Configuration

```json
{
  "network": {
    "type": "testnet",
    "rpc_host": "127.0.0.1",
    "rpc_port": 18332,
    "rpc_user": "bnap_testnet",
    "rpc_password": "test_password_123",
    "rpc_timeout": 30,
    "max_retries": 5,
    "fee_estimation": {
      "target_blocks": 2,
      "max_fee_rate": 10000,
      "fallback_fee_rate": 1000
    }
  }
}
```

#### Regtest Configuration (Development)

```json
{
  "network": {
    "type": "regtest",
    "rpc_host": "127.0.0.1",
    "rpc_port": 18443,
    "rpc_user": "bnap_regtest",
    "rpc_password": "regtest123",
    "rpc_timeout": 10,
    "max_retries": 1,
    "auto_generate_blocks": true,
    "blocks_per_generation": 6
  }
}
```

### Validator Configuration

#### Production Validator Setup

```json
{
  "validator": {
    "id": "bnap_validator_prod_$(hostname)",
    "enable_audit": true,
    "max_validation_time": 30,
    "signing_keys_file": "/etc/bnap/validator_keys.json",
    "backup_keys_file": "/etc/bnap/backup_keys.json",
    "performance": {
      "cache_size": 5000,
      "max_concurrent_validations": 20,
      "validation_timeout": 15,
      "signature_cache_size": 1000
    },
    "limits": {
      "max_supply_cap": 21000000,
      "max_per_mint_cap": 1000000,
      "max_asset_name_length": 100,
      "max_symbol_length": 10
    },
    "rules": {
      "enforce_allowlists": true,
      "require_content_hash": true,
      "validate_merkle_proofs": true,
      "check_duplicate_assets": true
    }
  }
}
```

#### Development Validator Setup

```json
{
  "validator": {
    "id": "bnap_validator_dev",
    "enable_audit": false,
    "max_validation_time": 60,
    "signing_keys_file": "~/.bnap/dev_keys.json",
    "performance": {
      "cache_size": 100,
      "max_concurrent_validations": 5
    },
    "limits": {
      "max_supply_cap": 1000000,
      "max_per_mint_cap": 10000
    },
    "rules": {
      "enforce_allowlists": false,
      "require_content_hash": false,
      "validate_merkle_proofs": false,
      "check_duplicate_assets": false
    }
  }
}
```

### Registry Configuration

#### Production Registry

```json
{
  "registry": {
    "file_path": "/var/lib/bnap/registry.json",
    "backup_enabled": true,
    "backup_interval": 1800,
    "max_backup_files": 336,
    "backup_directory": "/var/lib/bnap/backups",
    "compression": true,
    "encryption": {
      "enabled": true,
      "key_file": "/etc/bnap/registry_key.enc"
    },
    "integrity": {
      "checksums": true,
      "signature_verification": true
    },
    "concurrency": {
      "timeout": 30,
      "max_concurrent_operations": 10
    }
  }
}
```

#### High-Availability Registry

```json
{
  "registry": {
    "type": "distributed",
    "primary_path": "/var/lib/bnap/registry.json",
    "replicas": [
      "/mnt/replica1/registry.json",
      "/mnt/replica2/registry.json"
    ],
    "sync_interval": 300,
    "backup_enabled": true,
    "backup_interval": 900,
    "max_backup_files": 672
  }
}
```

## Security Configuration

### Key Management

#### Hardware Security Module (HSM) Configuration

```json
{
  "security": {
    "key_encryption": true,
    "hsm_enabled": true,
    "hsm_config": {
      "provider": "pkcs11",
      "library_path": "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
      "slot_id": 0,
      "pin": "$(cat /etc/bnap/hsm_pin)",
      "key_labels": {
        "primary": "bnap_validator_primary",
        "backup": "bnap_validator_backup"
      }
    }
  }
}
```

#### Software Key Encryption

```json
{
  "security": {
    "key_encryption": true,
    "encryption_method": "aes256",
    "key_derivation": {
      "method": "pbkdf2",
      "iterations": 100000,
      "salt_length": 32
    },
    "master_key_file": "/etc/bnap/master.key"
  }
}
```

### Access Control

```json
{
  "security": {
    "api_authentication": {
      "enabled": true,
      "method": "jwt",
      "secret_key": "$(openssl rand -base64 64)",
      "token_expiry": 3600
    },
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 60,
      "burst_limit": 10
    },
    "ip_whitelist": [
      "127.0.0.1",
      "192.168.1.0/24",
      "10.0.0.0/8"
    ]
  }
}
```

## Logging Configuration

### Production Logging

```json
{
  "logging": {
    "level": "INFO",
    "handlers": {
      "file": {
        "enabled": true,
        "file_path": "/var/log/bnap/bnap.log",
        "max_file_size": "100MB",
        "backup_count": 10,
        "rotation": "daily"
      },
      "syslog": {
        "enabled": true,
        "facility": "local0",
        "format": "bnap[%(process)d]: %(levelname)s - %(message)s"
      },
      "console": {
        "enabled": false
      }
    },
    "audit_logging": {
      "enabled": true,
      "file_path": "/var/log/bnap/audit.log",
      "max_file_size": "50MB",
      "backup_count": 20,
      "encryption": true
    }
  }
}
```

### Development Logging

```json
{
  "logging": {
    "level": "DEBUG",
    "handlers": {
      "console": {
        "enabled": true,
        "color": true,
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
      },
      "file": {
        "enabled": true,
        "file_path": "logs/bnap_dev.log",
        "max_file_size": "10MB",
        "backup_count": 3
      }
    }
  }
}
```

## Monitoring Configuration

### Prometheus Integration

```json
{
  "monitoring": {
    "prometheus": {
      "enabled": true,
      "port": 9090,
      "endpoint": "/metrics",
      "update_interval": 15
    },
    "metrics": {
      "validation_times": true,
      "transaction_counts": true,
      "error_rates": true,
      "queue_sizes": true,
      "system_resources": true
    },
    "alerts": {
      "enabled": true,
      "webhook_url": "https://alertmanager.local/api/v1/alerts",
      "thresholds": {
        "validation_time_ms": 5000,
        "error_rate_percent": 5,
        "queue_size": 100
      }
    }
  }
}
```

### Health Checks

```json
{
  "health_checks": {
    "enabled": true,
    "port": 8080,
    "endpoint": "/health",
    "interval": 30,
    "checks": {
      "bitcoin_connection": {
        "enabled": true,
        "timeout": 10
      },
      "registry_access": {
        "enabled": true,
        "timeout": 5
      },
      "validator_keys": {
        "enabled": true,
        "timeout": 5
      },
      "disk_space": {
        "enabled": true,
        "threshold": 90
      }
    }
  }
}
```

## Performance Tuning

### High-Performance Configuration

```json
{
  "performance": {
    "threading": {
      "validation_workers": 8,
      "io_workers": 4,
      "crypto_workers": 4
    },
    "caching": {
      "asset_cache_size": 10000,
      "signature_cache_size": 5000,
      "psbt_cache_size": 1000,
      "cache_ttl": 3600
    },
    "memory": {
      "max_heap_size": "4GB",
      "gc_threshold": 1000
    },
    "network": {
      "connection_pool_size": 20,
      "connection_timeout": 30,
      "keep_alive": true
    }
  }
}
```

### Memory-Constrained Configuration

```json
{
  "performance": {
    "threading": {
      "validation_workers": 2,
      "io_workers": 1,
      "crypto_workers": 2
    },
    "caching": {
      "asset_cache_size": 1000,
      "signature_cache_size": 500,
      "psbt_cache_size": 100,
      "cache_ttl": 1800
    },
    "memory": {
      "max_heap_size": "512MB",
      "gc_threshold": 100
    }
  }
}
```

## Environment-Specific Configurations

### Docker Configuration

```json
{
  "docker": {
    "network": {
      "rpc_host": "bitcoin-node",
      "rpc_port": 8332
    },
    "registry": {
      "file_path": "/data/bnap/registry.json",
      "backup_directory": "/data/bnap/backups"
    },
    "logging": {
      "handlers": {
        "console": {
          "enabled": true
        },
        "file": {
          "enabled": false
        }
      }
    }
  }
}
```

### Kubernetes Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bnap-config
data:
  config.json: |
    {
      "network": {
        "rpc_host": "bitcoin-node-service",
        "rpc_port": 8332
      },
      "registry": {
        "file_path": "/data/registry.json",
        "backup_enabled": true,
        "backup_directory": "/backups"
      },
      "security": {
        "hsm_enabled": false,
        "key_encryption": true
      }
    }
```

## Configuration Management

### Configuration Validation

```bash
# Validate configuration file
bnap config validate --config-file /etc/bnap/config.json

# Check configuration syntax
bnap config check --verbose

# Test configuration connectivity
bnap config test-connection --network-only
```

### Configuration Templates

#### Generate Production Template

```bash
# Generate production configuration template
bnap config generate-template \
    --environment production \
    --network mainnet \
    --output-file /etc/bnap/config.json

# Generate with encryption
bnap config generate-template \
    --environment production \
    --enable-encryption \
    --hsm-support
```

#### Generate Development Template

```bash
# Generate development configuration
bnap config generate-template \
    --environment development \
    --network regtest \
    --output-file ~/.bnap/dev_config.json
```

### Configuration Updates

#### Hot Configuration Reload

```bash
# Reload configuration without restart
bnap config reload --config-file /etc/bnap/config.json

# Validate before reload
bnap config reload --validate-first
```

#### Configuration Migration

```bash
# Migrate configuration to new version
bnap config migrate \
    --from-version 1.0 \
    --to-version 1.1 \
    --config-file /etc/bnap/config.json

# Backup before migration
bnap config migrate --backup-original
```

## Troubleshooting Configuration

### Common Configuration Issues

#### Bitcoin RPC Connection

```bash
# Test Bitcoin RPC connection
bnap config test-rpc --config-file /etc/bnap/config.json

# Debug RPC issues
bnap config test-rpc --verbose --debug
```

#### Registry Access

```bash
# Test registry file access
bnap config test-registry --config-file /etc/bnap/config.json

# Check registry permissions
ls -la $(bnap config get registry.file_path)
```

#### Key File Access

```bash
# Validate validator keys
bnap config test-keys --config-file /etc/bnap/config.json

# Check key file permissions
ls -la $(bnap config get validator.signing_keys_file)
```

### Configuration Debugging

```bash
# Show effective configuration
bnap config show --format json

# Show configuration sources
bnap config show --show-sources

# Validate all configuration
bnap config validate --comprehensive
```

## Security Best Practices

### File Permissions

```bash
# Set secure permissions for configuration files
chmod 600 /etc/bnap/config.json
chmod 600 /etc/bnap/validator_keys.json
chmod 700 /etc/bnap/

# Set ownership
chown bnap:bnap /etc/bnap/config.json
chown bnap:bnap /etc/bnap/validator_keys.json
```

### Configuration Encryption

```bash
# Encrypt sensitive configuration values
bnap config encrypt-secrets --config-file /etc/bnap/config.json

# Decrypt for viewing
bnap config decrypt-secrets --config-file /etc/bnap/config.json
```

### Configuration Auditing

```bash
# Audit configuration changes
bnap config audit --since="1 day ago"

# Generate configuration report
bnap config report --format pdf --output config-audit.pdf
```

This configuration guide provides comprehensive coverage of all BNAP configuration options for various deployment scenarios and environments.