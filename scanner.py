import logging
import subprocess
import platform
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Protocol
from datetime import datetime

"""
NetInsight Wi-Fi Scanner Module

A production-ready scanner for analyzing nearby Wi-Fi networks across multiple
operating systems (Windows, Linux, macOS). This module provides a clean,
extensible interface for network discovery and analysis.

Design Philosophy:
- Platform abstraction: Scanner implementations are decoupled via Strategy pattern
- Type safety: Full type hints for IDE support and runtime validation
- Structured data: Dataclasses over raw tuples/dicts for type safety
- Extensibility: Easy to add new platforms or data fields
- Testability: Dependency injection allows mocking OS calls
"""


# Configure module logger
logger = logging.getLogger(__name__)


# ============================================================================
# Custom Exceptions
# ============================================================================

class NetInsightException(Exception):
    """Base exception for all NetInsight errors."""

    pass


class ScannerNotAvailableError(NetInsightException):
    """Raised when scanner is not available on the current platform."""

    pass


class ScanFailedError(NetInsightException):
    """Raised when the Wi-Fi scan operation fails."""

    pass


class UnsupportedPlatformError(NetInsightException):
    """Raised when the current platform is not supported."""

    pass


# ============================================================================
# Data Models
# ============================================================================

class SecurityType(Enum):
    """Enumeration of Wi-Fi security protocols."""

    OPEN = "OPEN"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class WiFiNetwork:
    """
    Immutable data structure representing a Wi-Fi network.

    This uses a frozen dataclass for hashability and immutability, ensuring
    network data cannot be accidentally modified after creation.

    Attributes:
        ssid: Network name (Service Set Identifier). Can be empty for hidden networks.
        bssid: MAC address of the access point (Basic Service Set Identifier).
        rssi: Signal strength in dBm (typically -30 to -90, higher is stronger).
        frequency: Operating frequency in MHz (typically 2400-2500 or 5000-6000).
        channel: Wi-Fi channel number (derived from frequency, varies by region).
        security: Security protocol in use (WPA2, WPA3, etc.).
        scan_timestamp: UTC timestamp when this network was discovered.
    """

    ssid: str  # Can be empty string for hidden networks
    bssid: str  # MAC address format: XX:XX:XX:XX:XX:XX
    rssi: int  # dBm, typically -30 to -90
    frequency: Optional[int]  # MHz, typically 2400-2500 or 5000-6000
    channel: Optional[int]  # Wi-Fi channel (1-14 for 2.4GHz, 1-165+ for 5GHz)
    security: SecurityType
    scan_timestamp: datetime

    def __str__(self) -> str:
        """Return a human-readable representation of the network."""
        ssid_display = self.ssid if self.ssid else "(Hidden)"
        channel_str = f"CH{self.channel}" if self.channel else "N/A"
        return (f"{ssid_display} | BSSID: {self.bssid} | RSSI: {self.rssi}dBm | "
                f"{channel_str} | {self.security.value}")


# ============================================================================
# Platform Scanner Interface
# ============================================================================

class PlatformScanner(ABC):
    """
    Abstract base class for platform-specific Wi-Fi scanners.

    Strategy pattern: Different implementations for Windows/Linux/macOS.
    This allows:
    - Easy testing: Mock implementations can be injected
    - Clean separation: Platform-specific code isolated
    - Future growth: New platforms added without modifying scanner core
    """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if scanner can operate on this platform.

        Returns:
            True if all required tools/permissions are available, False otherwise.
        """
        pass

    @abstractmethod
    def scan(self) -> List[WiFiNetwork]:
        """
        Execute Wi-Fi network scan.

        Returns:
            List of discovered networks, sorted by signal strength (strongest first).

        Raises:
            ScanFailedError: If scan operation fails.
        """
        pass


# ============================================================================
# Windows Scanner Implementation
# ============================================================================

class WindowsScanner(PlatformScanner):
    """
    Windows Wi-Fi scanner using native netsh utility.

    Implementation notes:
    - Uses 'netsh wlan show networks mode=Bssid' command
    - Requires admin privileges on some Windows versions
    - Parses structured text output with regex
    - Handles both ASCII and Unicode security info
    """

    # Regex patterns for parsing netsh output
    _INTERFACE_PATTERN = re.compile(r"Interface\s*:\s*(.+)")
    _SSID_PATTERN = re.compile(r"SSID\s+\d+\s*:\s*(.+)")
    _BSSID_PATTERN = re.compile(r"BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})")
    _SIGNAL_PATTERN = re.compile(r"Signal\s*:\s*(\d+)%")
    _CHANNEL_PATTERN = re.compile(r"Channel\s*:\s*(\d+)")
    _FREQUENCY_PATTERN = re.compile(r"Frequency\s*:\s*(\d+)\s*MHz")
    _SECURITY_PATTERN = re.compile(r"Authentication\s*:\s*(.+)")

    def is_available(self) -> bool:
        """Check if netsh command is available on Windows."""
        try:
            subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("netsh utility not found or timed out")
            return False

    def scan(self) -> List[WiFiNetwork]:
        """
        Execute Wi-Fi scan using netsh command.

        Returns:
            List of networks sorted by signal strength (descending).

        Raises:
            ScanFailedError: If command execution fails or output parsing fails.
        """
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                raise ScanFailedError(
                    f"netsh command failed with code {result.returncode}: "
                    f"{result.stderr}"
                )

            networks = self._parse_netsh_output(result.stdout)
            logger.info(f"Successfully scanned {len(networks)} Wi-Fi networks")

            # Sort by signal strength (strongest first)
            return sorted(networks, key=lambda n: n.rssi, reverse=True)

        except subprocess.TimeoutExpired:
            raise ScanFailedError("Wi-Fi scan timed out after 30 seconds")
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            raise ScanFailedError(f"Scan failed: {str(e)}") from e

    def _parse_netsh_output(self, output: str) -> List[WiFiNetwork]:
        """
        Parse netsh output into WiFiNetwork objects.

        Args:
            output: Raw output from netsh command.

        Returns:
            List of parsed networks.

        Raises:
            ScanFailedError: If output format is unexpected.
        """
        networks = []
        current_ssid: Optional[str] = None
        current_security: SecurityType = SecurityType.UNKNOWN
        now = datetime.utcnow()

        try:
            for line in output.split("\n"):
                line = line.strip()

                # Extract SSID
                ssid_match = self._SSID_PATTERN.search(line)
                if ssid_match:
                    current_ssid = ssid_match.group(1).strip()
                    continue

                # Extract security type
                security_match = self._SECURITY_PATTERN.search(line)
                if security_match:
                    auth_str = security_match.group(1).strip().upper()
                    current_security = self._parse_security_type(auth_str)
                    continue

                # Extract BSSID and related info
                bssid_match = self._BSSID_PATTERN.search(line)
                if bssid_match:
                    bssid = bssid_match.group(1)

                    # Parse signal strength
                    signal_match = self._SIGNAL_PATTERN.search(line)
                    signal_percent = int(signal_match.group(1)) if signal_match else 0
                    rssi = self._signal_percent_to_rssi(signal_percent)

                    # Parse channel and frequency
                    channel_match = self._CHANNEL_PATTERN.search(line)
                    channel = int(channel_match.group(1)) if channel_match else None

                    freq_match = self._FREQUENCY_PATTERN.search(line)
                    frequency = int(freq_match.group(1)) if freq_match else None

                    # Create network object
                    network = WiFiNetwork(
                        ssid=current_ssid or "",
                        bssid=bssid,
                        rssi=rssi,
                        frequency=frequency,
                        channel=channel,
                        security=current_security,
                        scan_timestamp=now,
                    )
                    networks.append(network)

            return networks

        except (ValueError, AttributeError) as e:
            raise ScanFailedError(f"Failed to parse netsh output: {str(e)}") from e

    @staticmethod
    def _parse_security_type(auth_string: str) -> SecurityType:
        """
        Map authentication string to SecurityType enum.

        Args:
            auth_string: Authentication method from netsh output.

        Returns:
            Corresponding SecurityType enum value.
        """
        if "WPA3" in auth_string:
            return SecurityType.WPA3
        elif "WPA2" in auth_string:
            return SecurityType.WPA2
        elif "WPA" in auth_string:
            return SecurityType.WPA
        elif "WEP" in auth_string:
            return SecurityType.WEP
        elif "OPEN" in auth_string or "NONE" in auth_string:
            return SecurityType.OPEN
        return SecurityType.UNKNOWN

    @staticmethod
    def _signal_percent_to_rssi(percent: int) -> int:
        """
        Convert signal percentage to RSSI in dBm.

        Approximation: RSSI = (percent / 2) - 100
        This maps 0% -> -100dBm and 100% -> -50dBm (reasonable Wi-Fi range).

        Args:
            percent: Signal strength percentage (0-100).

        Returns:
            Estimated RSSI in dBm.
        """
        # Clamp to valid range
        percent = max(0, min(100, percent))
        return (percent // 2) - 100


# ============================================================================
# Platform Stubs (Ready for Implementation)
# ============================================================================

class LinuxScanner(PlatformScanner):
    """
    Linux Wi-Fi scanner stub (future implementation).

    Implementation approach:
    - Use 'nmcli device wifi list' (NetworkManager) as primary
    - Fallback to 'iwlist scan' (requires root)
    - Parse JSON or structured text output
    """

    def is_available(self) -> bool:
        """Check if Linux scanner tools are available."""
        logger.debug("Linux scanner stub - not yet implemented")
        return False

    def scan(self) -> List[WiFiNetwork]:
        """Scan Wi-Fi networks on Linux."""
        raise ScannerNotAvailableError(
            "Linux scanner not yet implemented. Contributions welcome!"
        )


class MacOSScanner(PlatformScanner):
    """
    macOS Wi-Fi scanner stub (future implementation).

    Implementation approach:
    - Use '/System/Library/PrivateFrameworks/Apple80211.framework'
    - Alternative: Parse 'airport -s' output
    - May require user to grant permissions in System Preferences
    """

    def is_available(self) -> bool:
        """Check if macOS scanner tools are available."""
        logger.debug("macOS scanner stub - not yet implemented")
        return False

    def scan(self) -> List[WiFiNetwork]:
        """Scan Wi-Fi networks on macOS."""
        raise ScannerNotAvailableError(
            "macOS scanner not yet implemented. Contributions welcome!"
        )


# ============================================================================
# Main Scanner Class (Platform Detection & Delegation)
# ============================================================================

class WiFiScanner:
    """
    Cross-platform Wi-Fi network scanner with automatic platform detection.

    This class uses the Strategy pattern to delegate to appropriate platform
    implementations. It provides a unified interface across Windows/Linux/macOS.

    Design benefits:
    - Single public API regardless of OS
    - Easy to test: inject mock scanners
    - Extensible: add platforms without changing core logic
    - Fail gracefully: clear error messages when scanner unavailable

    Example:
        >>> scanner = WiFiScanner()
        >>> networks = scanner.scan()
        >>> for net in networks:
        ...     print(net)
    """

    def __init__(self, platform_scanner: Optional[PlatformScanner] = None) -> None:
        """
        Initialize scanner with optional dependency injection.

        Args:
            platform_scanner: Custom scanner implementation (for testing).
                             If None, auto-detects based on OS.

        Raises:
            UnsupportedPlatformError: If platform not supported and no custom
                                     scanner provided.
        """
        self._scanner = platform_scanner or self._create_platform_scanner()
        logger.info(
            f"WiFiScanner initialized with {self._scanner.__class__.__name__}"
        )

    def scan(self) -> List[WiFiNetwork]:
        """
        Scan for nearby Wi-Fi networks.

        Returns:
            List of WiFiNetwork objects, sorted by signal strength (strongest first).

        Raises:
            ScannerNotAvailableError: If scanner not available on this system.
            ScanFailedError: If scan operation fails.
        """
        if not self._scanner.is_available():
            raise ScannerNotAvailableError(
                f"Scanner not available: {self._scanner.__class__.__name__} "
                "cannot operate on this system"
            )

        return self._scanner.scan()

    @staticmethod
    def _create_platform_scanner() -> PlatformScanner:
        """
        Create appropriate scanner based on detected OS.

        Returns:
            Platform-specific PlatformScanner implementation.

        Raises:
            UnsupportedPlatformError: If OS not supported.
        """
        system = platform.system()
        logger.debug(f"Detected OS: {system}")

        if system == "Windows":
            return WindowsScanner()
        elif system == "Linux":
            return LinuxScanner()
        elif system == "Darwin":
            return MacOSScanner()
        else:
            raise UnsupportedPlatformError(
                f"Platform not supported: {system}. "
                "Supported: Windows, Linux, macOS"
            )


# ============================================================================
# Future Improvements & Recommendations
# ============================================================================

"""
FUTURE IMPROVEMENTS:

1. Advanced Filtering & Querying:
   - Add NetworkFilter class to filter by SSID, BSSID, security type, etc.
   - Support regex patterns in filters
   - Example: scanner.scan(filter=NetworkFilter(ssid_pattern=".*Guest.*"))

2. Continuous Monitoring:
   - Add AsyncWiFiScanner with async/await support
   - Implement background scanning with callbacks for network changes
   - Useful for desktop apps that react to network state changes

3. Network History & Statistics:
   - Track network signals over time
   - Calculate signal strength trends
   - Detect weak spots in coverage

4. Enhanced Security Detection:
   - Parse cipher suites (AES, TKIP, etc.)
   - Differentiate between WPA and WPA3 personal vs enterprise
   - Warn about deprecated security protocols

5. Performance Optimizations:
   - Cache scan results with configurable TTL
   - Parallel execution for multi-interface systems
   - Implement timeout for slow systems

6. Improved Error Handling:
   - Retry logic with exponential backoff
   - Fallback scanners if primary fails
   - Structured logging with different verbosity levels

7. Testing Infrastructure:
   - Mock netsh output fixtures for unit tests
   - Integration tests with real hardware
   - Performance benchmarks

8. Documentation:
   - Configuration guide for admin requirements
   - Troubleshooting guide for common issues
   - API reference with examples

9. Platform-Specific Enhancements:
   - Windows: Support WPA Enterprise, certificate validation
   - Linux: Handle WiFi Direct, mesh networks
   - macOS: Use native CoreWLAN framework

10. Persistence & Export:
    - Save scan results to JSON, CSV
    - Export network summaries for reporting
    - Database support for historical analysis

11. Multi-threading & Threading Safety:
    - Ensure scanner methods are thread-safe
    - Add lock mechanisms for concurrent access
    - Consider using dataclasses for immutability

12. Configuration Management:
    - Config file support (YAML/TOML)
    - Environment variable overrides
    - User preferences (scan timeout, update frequency)
"""