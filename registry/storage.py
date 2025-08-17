"""
Bitcoin Native Asset Protocol - Registry Storage Backend

This module provides JSON-based persistence with thread-safe file operations,
atomic updates, compression, and backup mechanisms.
"""

import fcntl
import gzip
import hashlib
import json
import os
import platform
import shutil
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from threading import Lock, RLock
from typing import Any, Dict, List, Optional, Union

from .schema import Registry


class StorageError(Exception):
    """Base storage exception."""
    pass


class LockTimeoutError(StorageError):
    """Lock acquisition timeout exception."""
    pass


class IntegrityError(StorageError):
    """File integrity check failure exception."""
    pass


class FileLock:
    """Cross-platform file locking implementation."""
    
    def __init__(self, file_path: Union[str, Path], timeout: float = 30.0):
        self.file_path = Path(file_path)
        self.lock_file_path = self.file_path.with_suffix(self.file_path.suffix + '.lock')
        self.timeout = timeout
        self.lock_fd = None
        self._thread_lock = RLock()
    
    def acquire(self) -> bool:
        """Acquire file lock with timeout."""
        with self._thread_lock:
            if self.lock_fd is not None:
                return True  # Already locked by this instance
            
            start_time = time.time()
            
            while time.time() - start_time < self.timeout:
                try:
                    # Create lock file
                    self.lock_fd = os.open(
                        str(self.lock_file_path),
                        os.O_CREAT | os.O_EXCL | os.O_RDWR
                    )
                    
                    # Apply platform-specific lock
                    if platform.system() == 'Windows':
                        # Use msvcrt on Windows
                        import msvcrt
                        try:
                            msvcrt.locking(self.lock_fd, msvcrt.LK_NBLCK, 1)
                            return True
                        except OSError:
                            os.close(self.lock_fd)
                            os.unlink(self.lock_file_path)
                            self.lock_fd = None
                    else:
                        # Use fcntl on Unix-like systems
                        try:
                            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            return True
                        except BlockingIOError:
                            os.close(self.lock_fd)
                            os.unlink(self.lock_file_path)
                            self.lock_fd = None
                
                except FileExistsError:
                    # Lock file already exists, wait and retry
                    time.sleep(0.1)
                except Exception as e:
                    if self.lock_fd is not None:
                        try:
                            os.close(self.lock_fd)
                            os.unlink(self.lock_file_path)
                        except:
                            pass
                        self.lock_fd = None
                    raise StorageError(f"Failed to acquire lock: {e}")
            
            raise LockTimeoutError(f"Failed to acquire lock within {self.timeout} seconds")
    
    def release(self) -> None:
        """Release file lock."""
        with self._thread_lock:
            if self.lock_fd is None:
                return
            
            try:
                if platform.system() == 'Windows':
                    import msvcrt
                    msvcrt.locking(self.lock_fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                
                os.close(self.lock_fd)
                os.unlink(self.lock_file_path)
                
            except Exception as e:
                # Log error but don't raise to avoid masking original exceptions
                print(f"Warning: Failed to release lock: {e}")
            finally:
                self.lock_fd = None
    
    def __enter__(self):
        self.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


class JSONStorage:
    """Thread-safe JSON storage with atomic operations and compression."""
    
    def __init__(
        self,
        file_path: Union[str, Path],
        compressed: bool = False,
        backup_count: int = 5,
        lock_timeout: float = 30.0
    ):
        self.file_path = Path(file_path)
        self.compressed = compressed
        self.backup_count = backup_count
        self.lock_timeout = lock_timeout
        
        # Ensure directory exists
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize empty file if it doesn't exist
        if not self.file_path.exists():
            self._write_file({})
    
    def _calculate_checksum(self, data: bytes) -> str:
        """Calculate SHA-256 checksum of data."""
        return hashlib.sha256(data).hexdigest()
    
    def _read_file(self) -> bytes:
        """Read raw file data."""
        if self.compressed:
            with gzip.open(self.file_path, 'rb') as f:
                return f.read()
        else:
            with open(self.file_path, 'rb') as f:
                return f.read()
    
    def _write_file(self, data: Dict[str, Any]) -> None:
        """Write data to file atomically."""
        # Serialize to JSON
        json_data = json.dumps(data, indent=2, default=str).encode('utf-8')
        
        # Create temporary file in same directory
        temp_file = self.file_path.with_suffix(self.file_path.suffix + '.tmp')
        
        try:
            if self.compressed:
                with gzip.open(temp_file, 'wb') as f:
                    f.write(json_data)
            else:
                with open(temp_file, 'wb') as f:
                    f.write(json_data)
            
            # Atomic move (rename)
            if platform.system() == 'Windows':
                # Windows requires removing target first
                if self.file_path.exists():
                    self.file_path.unlink()
            
            temp_file.rename(self.file_path)
            
        except Exception as e:
            # Clean up temp file on failure
            if temp_file.exists():
                temp_file.unlink()
            raise StorageError(f"Failed to write file: {e}")
    
    def _verify_integrity(self, expected_checksum: Optional[str] = None) -> bool:
        """Verify file integrity using checksum."""
        if not self.file_path.exists():
            return False
        
        try:
            data = self._read_file()
            if expected_checksum:
                return self._calculate_checksum(data) == expected_checksum
            return True  # File exists and is readable
        except Exception:
            return False
    
    def _create_backup(self) -> None:
        """Create timestamped backup of current file."""
        if not self.file_path.exists():
            return
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{self.file_path.stem}_{timestamp}{self.file_path.suffix}"
        backup_path = self.file_path.parent / 'backups' / backup_name
        
        # Ensure backup directory exists
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy current file to backup
        shutil.copy2(self.file_path, backup_path)
        
        # Clean up old backups
        self._cleanup_old_backups()
    
    def _cleanup_old_backups(self) -> None:
        """Remove old backup files beyond backup_count."""
        backup_dir = self.file_path.parent / 'backups'
        if not backup_dir.exists():
            return
        
        # Find all backup files for this storage file
        pattern = f"{self.file_path.stem}_*{self.file_path.suffix}"
        backup_files = list(backup_dir.glob(pattern))
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        # Remove excess backups
        for backup_file in backup_files[self.backup_count:]:
            try:
                backup_file.unlink()
            except Exception as e:
                print(f"Warning: Failed to remove old backup {backup_file}: {e}")
    
    @contextmanager
    def _lock_context(self):
        """Context manager for file locking."""
        lock = FileLock(self.file_path, timeout=self.lock_timeout)
        try:
            with lock:
                yield
        except LockTimeoutError:
            raise
        except Exception as e:
            raise StorageError(f"Storage operation failed: {e}")
    
    def read(self) -> Dict[str, Any]:
        """Read and deserialize data from storage."""
        with self._lock_context():
            try:
                data = self._read_file()
                
                # Verify file is not empty
                if not data:
                    return {}
                
                # Deserialize JSON
                return json.loads(data.decode('utf-8'))
                
            except json.JSONDecodeError as e:
                raise IntegrityError(f"Invalid JSON data: {e}")
            except Exception as e:
                raise StorageError(f"Failed to read storage: {e}")
    
    def write(self, data: Dict[str, Any], create_backup: bool = True) -> str:
        """Write data to storage atomically."""
        with self._lock_context():
            # Create backup before writing
            if create_backup:
                self._create_backup()
            
            # Write data
            self._write_file(data)
            
            # Calculate and return checksum
            file_data = self._read_file()
            return self._calculate_checksum(file_data)
    
    def update(self, updater_func, create_backup: bool = True) -> str:
        """Update data using a function atomically."""
        with self._lock_context():
            # Read current data
            current_data = self.read()
            
            # Apply updates
            updated_data = updater_func(current_data)
            
            # Write back
            return self.write(updated_data, create_backup=create_backup)
    
    def exists(self) -> bool:
        """Check if storage file exists."""
        return self.file_path.exists()
    
    def size(self) -> int:
        """Get storage file size in bytes."""
        if not self.file_path.exists():
            return 0
        return self.file_path.stat().st_size
    
    def verify(self, expected_checksum: Optional[str] = None) -> bool:
        """Verify file integrity."""
        return self._verify_integrity(expected_checksum)
    
    def list_backups(self) -> List[Path]:
        """List available backup files."""
        backup_dir = self.file_path.parent / 'backups'
        if not backup_dir.exists():
            return []
        
        pattern = f"{self.file_path.stem}_*{self.file_path.suffix}"
        backup_files = list(backup_dir.glob(pattern))
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        return backup_files
    
    def restore_backup(self, backup_timestamp: str) -> bool:
        """Restore from a specific backup."""
        backup_name = f"{self.file_path.stem}_{backup_timestamp}{self.file_path.suffix}"
        backup_path = self.file_path.parent / 'backups' / backup_name
        
        if not backup_path.exists():
            return False
        
        with self._lock_context():
            # Create backup of current state before restore
            self._create_backup()
            
            # Copy backup to current location
            shutil.copy2(backup_path, self.file_path)
            
            return True


class RegistryStorage:
    """High-level registry storage interface."""
    
    def __init__(
        self,
        storage_dir: Union[str, Path] = "registry_data",
        compressed: bool = False,
        backup_count: int = 5
    ):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.json_storage = JSONStorage(
            self.storage_dir / "registry.json",
            compressed=compressed,
            backup_count=backup_count
        )
    
    def load_registry(self) -> Registry:
        """Load registry from storage."""
        try:
            data = self.json_storage.read()
            
            if not data:
                return Registry()
            
            return Registry.parse_obj(data)
            
        except Exception as e:
            raise StorageError(f"Failed to load registry: {e}")
    
    def save_registry(self, registry: Registry) -> str:
        """Save registry to storage."""
        try:
            data = registry.dict()
            return self.json_storage.write(data)
            
        except Exception as e:
            raise StorageError(f"Failed to save registry: {e}")
    
    def update_registry(self, updater_func) -> str:
        """Update registry atomically."""
        def registry_updater(data):
            registry = Registry.parse_obj(data) if data else Registry()
            updated_registry = updater_func(registry)
            return updated_registry.dict()
        
        return self.json_storage.update(registry_updater)
    
    def backup_registry(self) -> bool:
        """Create manual backup of registry."""
        try:
            registry = self.load_registry()
            self.json_storage.write(registry.dict(), create_backup=True)
            return True
        except Exception:
            return False
    
    def list_backups(self) -> List[str]:
        """List available backup timestamps."""
        backups = self.json_storage.list_backups()
        timestamps = []
        
        for backup in backups:
            # Extract timestamp from filename
            parts = backup.stem.split('_')
            if len(parts) >= 3:
                timestamp = f"{parts[-2]}_{parts[-1]}"
                timestamps.append(timestamp)
        
        return timestamps
    
    def restore_backup(self, timestamp: str) -> bool:
        """Restore registry from backup."""
        return self.json_storage.restore_backup(timestamp)
    
    def get_storage_info(self) -> Dict[str, Any]:
        """Get storage information."""
        return {
            'file_path': str(self.json_storage.file_path),
            'compressed': self.json_storage.compressed,
            'size_bytes': self.json_storage.size(),
            'exists': self.json_storage.exists(),
            'backup_count': len(self.json_storage.list_backups())
        }