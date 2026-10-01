"""
Input validation utilities
"""

import re
import ipaddress
from typing import Tuple


def validate_ip(ip: str) -> Tuple[bool, str]:
    """
    Validate an IP address
    
    Args:
        ip: IP address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip:
        return False, "IP address cannot be empty"
    
    try:
        ipaddress.ip_address(ip)
        return True, ""
    except ValueError as e:
        return False, f"Invalid IP address: {str(e)}"


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate an email address
    
    Args:
        email: Email address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email address cannot be empty"
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_regex, email):
        return True, ""
    
    return False, "Invalid email format"


def validate_phone(phone: str) -> Tuple[bool, str]:
    """
    Validate a phone number
    
    Args:
        phone: Phone number to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not phone:
        return False, "Phone number cannot be empty"
    
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)\.]', '', phone)
    
    # Check if it starts with + and has digits
    if cleaned.startswith('+'):
        if not cleaned[1:].isdigit():
            return False, "Phone number can only contain digits after +"
        if len(cleaned) < 8 or len(cleaned) > 15:
            return False, "Phone number must be 8-15 digits"
    else:
        if not cleaned.isdigit():
            return False, "Phone number can only contain digits"
        if len(cleaned) < 8 or len(cleaned) > 15:
            return False, "Phone number must be 8-15 digits"
    
    return True, ""


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate a username
    
    Args:
        username: Username to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 30:
        return False, "Username must be at most 30 characters"
    
    # Allow alphanumeric, underscore, and dot
    if not re.match(r'^[a-zA-Z0-9_.]+$', username):
        return False, "Username can only contain letters, numbers, underscore, and dot"
    
    return True, ""


def validate_domain(domain: str) -> Tuple[bool, str]:
    """
    Validate a domain name
    
    Args:
        domain: Domain name to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not domain:
        return False, "Domain cannot be empty"
    
    domain_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    if re.match(domain_regex, domain):
        return True, ""
    
    return False, "Invalid domain format"
