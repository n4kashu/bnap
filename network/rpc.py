"""
Bitcoin Native Asset Protocol - Bitcoin Core RPC Client

This module provides a comprehensive Bitcoin Core JSON-RPC client with authentication,
connection pooling, configuration management, and robust error handling.
"""

import json
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import base64
import urllib3
from pathlib import Path
import hashlib
import hmac
from urllib.parse import urlparse
import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RPCError(Exception):
    """Base exception for RPC-related errors."""
    
    def __init__(self, code: int, message: str, data: Optional[Any] = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"RPC Error {code}: {message}")


class RPCConnectionError(RPCError):
    """Exception for RPC connection failures."""
    pass


class RPCAuthError(RPCError):
    """Exception for RPC authentication failures."""
    pass


class RPCTimeoutError(RPCError):
    """Exception for RPC timeout errors."""
    pass


@dataclass
class RPCConfig:
    """Configuration for Bitcoin Core RPC connection."""
    host: str = "localhost"
    port: int = 18443  # Default regtest port
    username: Optional[str] = None
    password: Optional[str] = None
    cookie_file: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    backoff_factor: float = 1.0
    ssl_verify: bool = False
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.username and not self.cookie_file:
            # Try to find cookie file in standard locations
            self.cookie_file = self._find_cookie_file()
        
        if not self.username and not self.cookie_file:
            raise ValueError("Either username/password or cookie file must be provided")
    
    def _find_cookie_file(self) -> Optional[str]:
        """Try to find Bitcoin Core cookie file in standard locations."""
        possible_paths = [
            "~/.bitcoin/regtest/.cookie",
            "~/.bitcoin/testnet3/.cookie", 
            "~/.bitcoin/.cookie",
            "/tmp/bitcoin-regtest/.cookie"
        ]
        
        for path in possible_paths:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists():
                return str(expanded_path)
        
        return None
    
    @classmethod
    def from_env(cls) -> 'RPCConfig':
        """Create RPC config from environment variables."""
        return cls(
            host=os.getenv("BITCOIN_RPC_HOST", "localhost"),
            port=int(os.getenv("BITCOIN_RPC_PORT", "18443")),
            username=os.getenv("BITCOIN_RPC_USER"),
            password=os.getenv("BITCOIN_RPC_PASSWORD"),
            cookie_file=os.getenv("BITCOIN_RPC_COOKIE_FILE"),
            timeout=int(os.getenv("BITCOIN_RPC_TIMEOUT", "30")),
            max_retries=int(os.getenv("BITCOIN_RPC_MAX_RETRIES", "3")),
            ssl_verify=os.getenv("BITCOIN_RPC_SSL_VERIFY", "false").lower() == "true"
        )


@dataclass
class RPCResponse:
    """Represents an RPC response with metadata."""
    result: Any
    error: Optional[Dict[str, Any]] = None
    id: Optional[Union[str, int]] = None
    raw_response: Optional[str] = None
    request_time: float = 0.0
    response_time: float = 0.0
    
    def is_success(self) -> bool:
        """Check if the RPC call was successful."""
        return self.error is None
    
    def get_error_code(self) -> Optional[int]:
        """Get error code if present."""
        return self.error.get("code") if self.error else None
    
    def get_error_message(self) -> Optional[str]:
        """Get error message if present."""
        return self.error.get("message") if self.error else None


class ConnectionPool:
    """Connection pool for RPC requests."""
    
    def __init__(self, config: RPCConfig):
        """Initialize connection pool."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configure session with retry strategy
        self.session = requests.Session()
        
        # Set up retry strategy
        retry_strategy = Retry(
            total=config.max_retries,
            backoff_factor=config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=10, pool_block=True)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set up authentication
        self._setup_auth()
        
        # Connection stats
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_time": 0.0,
            "last_request_time": None
        }
        self._stats_lock = threading.Lock()
    
    def _setup_auth(self):
        """Set up authentication for the session."""
        if self.config.username and self.config.password:
            # Use basic auth
            self.session.auth = HTTPBasicAuth(self.config.username, self.config.password)
            self.logger.debug("Using basic authentication")
            
        elif self.config.cookie_file:
            # Use cookie file authentication
            try:
                with open(self.config.cookie_file, 'r') as f:
                    cookie_content = f.read().strip()
                    
                if ':' in cookie_content:
                    username, password = cookie_content.split(':', 1)
                    self.session.auth = HTTPBasicAuth(username, password)
                    self.logger.debug(f"Using cookie file authentication: {self.config.cookie_file}")
                else:
                    raise ValueError(f"Invalid cookie file format: {self.config.cookie_file}")
                    
            except FileNotFoundError:
                raise RPCAuthError(-1, f"Cookie file not found: {self.config.cookie_file}")
            except Exception as e:
                raise RPCAuthError(-1, f"Failed to read cookie file: {e}")
    
    def get_url(self) -> str:
        """Get the RPC URL."""
        protocol = "https" if self.config.ssl_verify else "http"
        return f"{protocol}://{self.config.host}:{self.config.port}/"
    
    def request(self, method: str, params: List[Any], request_id: Optional[Union[str, int]] = None) -> RPCResponse:
        """Make an RPC request."""
        start_time = time.time()
        
        # Prepare request
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id or f"req_{int(time.time() * 1000000)}"
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "bnap-rpc-client/1.0"
        }
        
        try:
            # Make request
            response = self.session.post(
                self.get_url(),
                data=json.dumps(payload),
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.ssl_verify
            )
            
            request_time = time.time() - start_time
            
            # Update stats
            with self._stats_lock:
                self._stats["total_requests"] += 1
                self._stats["total_time"] += request_time
                self._stats["last_request_time"] = datetime.now(timezone.utc)
            
            # Handle HTTP errors
            if response.status_code == 401:
                with self._stats_lock:
                    self._stats["failed_requests"] += 1
                raise RPCAuthError(response.status_code, "Authentication failed")
            
            if response.status_code != 200:
                with self._stats_lock:
                    self._stats["failed_requests"] += 1
                raise RPCConnectionError(
                    response.status_code, 
                    f"HTTP {response.status_code}: {response.reason}"
                )
            
            # Parse JSON response
            try:
                response_data = response.json()
            except json.JSONDecodeError as e:
                with self._stats_lock:
                    self._stats["failed_requests"] += 1
                raise RPCError(-32700, f"Invalid JSON response: {e}")
            
            # Create RPC response
            rpc_response = RPCResponse(
                result=response_data.get("result"),
                error=response_data.get("error"),
                id=response_data.get("id"),
                raw_response=response.text,
                request_time=start_time,
                response_time=time.time()
            )
            
            # Handle RPC errors
            if rpc_response.error:
                with self._stats_lock:
                    self._stats["failed_requests"] += 1
                raise RPCError(
                    rpc_response.get_error_code(),
                    rpc_response.get_error_message(),
                    rpc_response.error.get("data")
                )
            
            with self._stats_lock:
                self._stats["successful_requests"] += 1
            
            return rpc_response
            
        except requests.exceptions.Timeout:
            with self._stats_lock:
                self._stats["failed_requests"] += 1
            raise RPCTimeoutError(-1, f"Request timed out after {self.config.timeout}s")
            
        except requests.exceptions.ConnectionError as e:
            with self._stats_lock:
                self._stats["failed_requests"] += 1
            raise RPCConnectionError(-1, f"Connection error: {e}")
            
        except requests.exceptions.RequestException as e:
            with self._stats_lock:
                self._stats["failed_requests"] += 1
            raise RPCError(-1, f"Request failed: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        with self._stats_lock:
            stats = self._stats.copy()
            
        avg_time = stats["total_time"] / stats["total_requests"] if stats["total_requests"] > 0 else 0
        success_rate = stats["successful_requests"] / stats["total_requests"] if stats["total_requests"] > 0 else 0
        
        return {
            **stats,
            "average_request_time": avg_time,
            "success_rate": success_rate,
            "config": {
                "host": self.config.host,
                "port": self.config.port,
                "timeout": self.config.timeout,
                "max_retries": self.config.max_retries
            }
        }
    
    def test_connection(self) -> bool:
        """Test the RPC connection."""
        try:
            response = self.request("getblockcount", [])
            return response.is_success() and isinstance(response.result, int)
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def close(self):
        """Close the connection pool."""
        if self.session:
            self.session.close()


class BitcoinRPCClient:
    """
    Comprehensive Bitcoin Core RPC client with high-level methods.
    """
    
    def __init__(self, config: Optional[RPCConfig] = None):
        """
        Initialize Bitcoin RPC client.
        
        Args:
            config: RPC configuration (uses environment if None)
        """
        self.config = config or RPCConfig.from_env()
        self.pool = ConnectionPool(self.config)
        self.logger = logging.getLogger(__name__)
        
        # Method call stats
        self._method_stats: Dict[str, Dict[str, Any]] = {}
        self._method_stats_lock = threading.Lock()
    
    def _call(self, method: str, *params) -> Any:
        """
        Make an RPC call and return the result.
        
        Args:
            method: RPC method name
            *params: Method parameters
            
        Returns:
            RPC call result
            
        Raises:
            RPCError: If RPC call fails
        """
        start_time = time.time()
        
        try:
            response = self.pool.request(method, list(params))
            execution_time = time.time() - start_time
            
            # Update method stats
            with self._method_stats_lock:
                if method not in self._method_stats:
                    self._method_stats[method] = {
                        "calls": 0,
                        "total_time": 0.0,
                        "errors": 0,
                        "last_call": None
                    }
                
                stats = self._method_stats[method]
                stats["calls"] += 1
                stats["total_time"] += execution_time
                stats["last_call"] = datetime.now(timezone.utc)
            
            return response.result
            
        except Exception as e:
            # Update error stats
            with self._method_stats_lock:
                if method not in self._method_stats:
                    self._method_stats[method] = {
                        "calls": 0,
                        "total_time": 0.0,
                        "errors": 0,
                        "last_call": None
                    }
                self._method_stats[method]["errors"] += 1
            
            self.logger.error(f"RPC call {method} failed: {e}")
            raise
    
    # Core blockchain methods
    
    def getblockcount(self) -> int:
        """Get the current block height."""
        return self._call("getblockcount")
    
    def getbestblockhash(self) -> str:
        """Get the hash of the best (tip) block."""
        return self._call("getbestblockhash")
    
    def getblock(self, block_hash: str, verbosity: int = 1) -> Dict[str, Any]:
        """
        Get block information.
        
        Args:
            block_hash: Hash of the block
            verbosity: 0=hex, 1=json, 2=json with transactions
            
        Returns:
            Block information
        """
        return self._call("getblock", block_hash, verbosity)
    
    def getblockhash(self, height: int) -> str:
        """Get block hash for given height."""
        return self._call("getblockhash", height)
    
    def getblockheader(self, block_hash: str, verbose: bool = True) -> Union[str, Dict[str, Any]]:
        """Get block header information."""
        return self._call("getblockheader", block_hash, verbose)
    
    # Transaction methods
    
    def sendrawtransaction(self, hex_string: str, max_fee_rate: Optional[float] = None) -> str:
        """
        Broadcast a raw transaction.
        
        Args:
            hex_string: Raw transaction hex
            max_fee_rate: Maximum fee rate (BTC/kB)
            
        Returns:
            Transaction ID
        """
        params = [hex_string]
        if max_fee_rate is not None:
            params.append(max_fee_rate)
        
        return self._call("sendrawtransaction", *params)
    
    def gettransaction(self, txid: str, include_watchonly: bool = False) -> Dict[str, Any]:
        """Get transaction information."""
        return self._call("gettransaction", txid, include_watchonly)
    
    def getrawtransaction(self, txid: str, verbose: bool = False, blockhash: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """Get raw transaction data."""
        params = [txid, verbose]
        if blockhash:
            params.append(blockhash)
        return self._call("getrawtransaction", *params)
    
    def testmempoolaccept(self, rawtxs: List[str], max_fee_rate: Optional[float] = None) -> List[Dict[str, Any]]:
        """Test if transactions would be accepted to mempool."""
        params = [rawtxs]
        if max_fee_rate is not None:
            params.append(max_fee_rate)
        return self._call("testmempoolaccept", *params)
    
    # Mempool methods
    
    def getrawmempool(self, verbose: bool = False) -> Union[List[str], Dict[str, Any]]:
        """Get raw mempool contents."""
        return self._call("getrawmempool", verbose)
    
    def getmempoolinfo(self) -> Dict[str, Any]:
        """Get mempool information."""
        return self._call("getmempoolinfo")
    
    def getmempoolentry(self, txid: str) -> Dict[str, Any]:
        """Get mempool entry information."""
        return self._call("getmempoolentry", txid)
    
    # Network methods
    
    def getnetworkinfo(self) -> Dict[str, Any]:
        """Get network information."""
        return self._call("getnetworkinfo")
    
    def getpeerinfo(self) -> List[Dict[str, Any]]:
        """Get connected peer information."""
        return self._call("getpeerinfo")
    
    def getconnectioncount(self) -> int:
        """Get number of connections."""
        return self._call("getconnectioncount")
    
    # Utility methods
    
    def validateaddress(self, address: str) -> Dict[str, Any]:
        """Validate a Bitcoin address."""
        return self._call("validateaddress", address)
    
    def estimatesmartfee(self, conf_target: int, estimate_mode: str = "CONSERVATIVE") -> Dict[str, Any]:
        """Estimate smart fee for confirmation target."""
        return self._call("estimatesmartfee", conf_target, estimate_mode)
    
    def uptime(self) -> int:
        """Get node uptime in seconds."""
        return self._call("uptime")
    
    # Wallet methods (if wallet is loaded)
    
    def getbalance(self) -> float:
        """Get wallet balance."""
        return self._call("getbalance")
    
    def getnewaddress(self, label: str = "", address_type: Optional[str] = None) -> str:
        """Get new address from wallet."""
        params = [label]
        if address_type:
            params.append(address_type)
        return self._call("getnewaddress", *params)
    
    def listunspent(self, minconf: int = 1, maxconf: int = 9999999, addresses: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """List unspent outputs."""
        params = [minconf, maxconf]
        if addresses:
            params.append(addresses)
        return self._call("listunspent", *params)
    
    # Utility and debugging methods
    
    def ping(self) -> None:
        """Ping the node."""
        self._call("ping")
    
    def help(self, command: Optional[str] = None) -> str:
        """Get help for RPC commands."""
        if command:
            return self._call("help", command)
        return self._call("help")
    
    # Client management methods
    
    def test_connection(self) -> bool:
        """Test if connection to Bitcoin Core is working."""
        return self.pool.test_connection()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        pool_stats = self.pool.get_stats()
        
        with self._method_stats_lock:
            method_stats = {}
            for method, stats in self._method_stats.items():
                avg_time = stats["total_time"] / stats["calls"] if stats["calls"] > 0 else 0
                success_rate = (stats["calls"] - stats["errors"]) / stats["calls"] if stats["calls"] > 0 else 0
                
                method_stats[method] = {
                    "calls": stats["calls"],
                    "errors": stats["errors"],
                    "average_time": avg_time,
                    "success_rate": success_rate,
                    "last_call": stats["last_call"].isoformat() if stats["last_call"] else None
                }
        
        return {
            "connection": pool_stats,
            "methods": method_stats,
            "total_methods_used": len(self._method_stats),
            "client_config": {
                "host": self.config.host,
                "port": self.config.port,
                "timeout": self.config.timeout
            }
        }
    
    def reset_stats(self):
        """Reset all statistics."""
        with self._method_stats_lock:
            self._method_stats.clear()
        # Note: Pool stats are reset when pool is recreated
    
    def close(self):
        """Close the RPC client."""
        self.pool.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Convenience functions

def create_rpc_client(
    host: str = "localhost",
    port: int = 18443,
    username: Optional[str] = None,
    password: Optional[str] = None,
    cookie_file: Optional[str] = None
) -> BitcoinRPCClient:
    """
    Create a Bitcoin RPC client with custom configuration.
    
    Args:
        host: Bitcoin Core host
        port: Bitcoin Core port
        username: RPC username
        password: RPC password
        cookie_file: Path to cookie file
        
    Returns:
        Configured BitcoinRPCClient
    """
    config = RPCConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        cookie_file=cookie_file
    )
    return BitcoinRPCClient(config)


def test_rpc_connection(client: BitcoinRPCClient) -> Dict[str, Any]:
    """
    Test RPC connection and return detailed results.
    
    Args:
        client: BitcoinRPCClient to test
        
    Returns:
        Test results
    """
    results = {
        "connection_test": False,
        "block_count": None,
        "network_info": None,
        "errors": []
    }
    
    try:
        # Test basic connection
        results["connection_test"] = client.test_connection()
        
        # Get block count
        results["block_count"] = client.getblockcount()
        
        # Get network info
        results["network_info"] = client.getnetworkinfo()
        
    except Exception as e:
        results["errors"].append(str(e))
    
    return results


# CLI interface for testing
if __name__ == "__main__":
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("Testing Bitcoin RPC Client...")
        print("=" * 50)
        
        try:
            # Create client from environment
            client = BitcoinRPCClient()
            
            # Test connection
            print(f"Testing connection to {client.config.host}:{client.config.port}...")
            
            test_results = test_rpc_connection(client)
            
            if test_results["connection_test"]:
                print("✓ Connection successful!")
                print(f"✓ Block count: {test_results['block_count']}")
                
                network_info = test_results["network_info"]
                if network_info:
                    print(f"✓ Network: {network_info.get('networkactive', 'unknown')}")
                    print(f"✓ Version: {network_info.get('version', 'unknown')}")
                    print(f"✓ Connections: {network_info.get('connections', 0)}")
                
                # Test a few more methods
                try:
                    mempool_info = client.getmempoolinfo()
                    print(f"✓ Mempool size: {mempool_info.get('size', 0)} transactions")
                except Exception as e:
                    print(f"⚠ Mempool info failed: {e}")
                
                # Show stats
                stats = client.get_stats()
                print(f"\nClient Statistics:")
                print(f"  Total requests: {stats['connection']['total_requests']}")
                print(f"  Success rate: {stats['connection']['success_rate']:.2%}")
                print(f"  Average time: {stats['connection']['average_request_time']:.3f}s")
                
            else:
                print("✗ Connection failed!")
                for error in test_results["errors"]:
                    print(f"  Error: {error}")
            
            client.close()
            
        except Exception as e:
            print(f"✗ Test failed: {e}")
            sys.exit(1)
        
        print("\nRPC client test completed!")
    
    else:
        print("Bitcoin Core RPC Client")
        print("Usage: python rpc.py test")
        print("\nEnvironment variables:")
        print("  BITCOIN_RPC_HOST - Bitcoin Core host (default: localhost)")
        print("  BITCOIN_RPC_PORT - Bitcoin Core port (default: 18443)")
        print("  BITCOIN_RPC_USER - RPC username")
        print("  BITCOIN_RPC_PASSWORD - RPC password")
        print("  BITCOIN_RPC_COOKIE_FILE - Path to cookie file")
        print("  BITCOIN_RPC_TIMEOUT - Request timeout in seconds (default: 30)")