"""
Hunter.io API Integration
"""

import requests
from typing import Dict, Any, List

from ..config import config


class HunterAPI:
    """Hunter.io API client"""

    def __init__(self):
        self.api_key = config.get_api_key('hunter')
        self.base_url = "https://api.hunter.io/v2"
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)

    def verify_email(self, email: str) -> Dict[str, Any]:
        """Verify an email address"""
        if not self.is_configured():
            return {'error': 'Hunter API key not configured'}

        url = f"{self.base_url}/email-verifier"
        params = {
            'email': email,
            'api_key': self.api_key
        }

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def domain_search(self, domain: str) -> Dict[str, Any]:
        """Search for email addresses in a domain"""
        if not self.is_configured():
            return {'error': 'Hunter API key not configured'}

        url = f"{self.base_url}/domain-search"
        params = {
            'domain': domain,
            'api_key': self.api_key
        }

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def email_finder(self, domain: str, first_name: str, last_name: str) -> Dict[str, Any]:
        """Find email address by name and domain"""
        if not self.is_configured():
            return {'error': 'Hunter API key not configured'}

        url = f"{self.base_url}/email-finder"
        params = {
            'domain': domain,
            'first_name': first_name,
            'last_name': last_name,
            'api_key': self.api_key
        }

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def email_count(self, domain: str) -> Dict[str, Any]:
        """Get email count for a domain"""
        if not self.is_configured():
            return {'error': 'Hunter API key not configured'}

        url = f"{self.base_url}/email-count"
        params = {
            'domain': domain,
            'api_key': self.api_key
        }

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
