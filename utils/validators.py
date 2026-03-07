"""
Input validation utilities
"""
import ipaddress
import re
import logging

logger = logging.getLogger(__name__)


def validate_ip(ip_str: str) -> bool:
    """
    Validate IP address

    Args:
        ip_str: IP address string

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_ip_range(ip_range: str) -> bool:
    """
    Validate IP range in CIDR notation

    Args:
        ip_range: IP range string (e.g., '192.168.1.0/24')

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def validate_target(target: str) -> bool:
    """
    Validate scan target (IP, hostname, URL, or CIDR range)

    Args:
        target: Target string (IP, domain, URL, or CIDR)

    Returns:
        True if valid, False otherwise
    """
    # Clean the target - remove protocol and path
    cleaned_target = target.strip()
    cleaned_target = re.sub(r'^https?://', '', cleaned_target)  # Remove protocol
    cleaned_target = cleaned_target.split('/')[0]  # Remove path
    cleaned_target = cleaned_target.split(':')[0]  # Remove port

    # Check if it's an IP address
    if validate_ip(cleaned_target):
        return True

    # Check if it's a CIDR range
    if '/' in cleaned_target and validate_ip_range(cleaned_target):
        return True

    # Check if it's a valid hostname/domain
    hostname_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )

    if hostname_pattern.match(cleaned_target):
        return True

    return False


def validate_port_range(port_range: str) -> bool:
    """
    Validate port range specification

    Args:
        port_range: Port range string (e.g., '1-1000', '80,443', '1-100,8000-9000')

    Returns:
        True if valid, False otherwise
    """
    try:
        parts = port_range.split(',')

        for part in parts:
            part = part.strip()

            if '-' in part:
                # Range
                start, end = part.split('-')
                start_port = int(start)
                end_port = int(end)

                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    return False
            else:
                # Single port
                port = int(part)
                if port < 1 or port > 65535:
                    return False

        return True

    except (ValueError, AttributeError):
        return False


def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input to prevent injection attacks

    Args:
        input_str: Input string

    Returns:
        Sanitized string
    """
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;&|`$]', '', input_str)
    return sanitized.strip()

