"""
Entity Validation Utilities
===========================
Input validation functions with consistent naming.
"""

import re
import socket


def validate_target(target: str) -> bool:
    """Validate if input is a valid URL or IP address."""
    return validate_url(target) or validate_ip_address(target)


def validate_url(url: str) -> bool:
    """Validate URL format."""
    url_pattern = re.compile(
        r'^(https?://)?'  # Optional protocol
        r'([a-zA-Z0-9.-]+)'  # Domain or IP
        r'(:\d+)?'  # Optional port
        r'(/.*)?$'  # Optional path
    )
    return bool(url_pattern.match(url))


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def validate_email(email: str) -> bool:
    """Validate email address format."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))


def check_private_ip(ip: str) -> bool:
    """Check if IP address is in private range."""
    return (ip.startswith('10.') or
            ip.startswith('192.168.') or
            (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31))
