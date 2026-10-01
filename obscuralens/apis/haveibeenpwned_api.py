"""
HaveIBeenPwned API Integration
"""

import requests
from typing import Dict, Any, List

from ..config import config


class HaveIBeenPwnedAPI:
    """HaveIBeenPwned API client"""

    def __init__(self):
        self.api_key = config.get_api_key('haveibeenpwned')
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.timeout = config.app_config.request_timeout
        self.headers = {
            'hibp-api-key': self.api_key,
            'User-Agent': config.app_config.user_agent
        }

    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)

    def check_email_breach(self, email: str) -> Dict[str, Any]:
        """Check if email has been in any data breaches"""
        if not self.is_configured():
            return {'error': 'HaveIBeenPwned API key not configured'}

        url = f"{self.base_url}/breachedaccount/{email}"
        params = {'truncateResponse': 'false'}

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            
            if response.status_code == 404:
                return {'breached': False, 'breaches': []}
            
            response.raise_for_status()
            breaches = response.json()
            
            return {
                'breached': True,
                'breach_count': len(breaches),
                'breaches': breaches
            }
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_breach_details(self, breach_name: str) -> Dict[str, Any]:
        """Get details of a specific breach"""
        if not self.is_configured():
            return {'error': 'HaveIBeenPwned API key not configured'}

        url = f"{self.base_url}/breach/{breach_name}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_all_breaches(self, domain: str = None) -> List[Dict[str, Any]]:
        """Get all breaches, optionally filtered by domain"""
        if not self.is_configured():
            return []

        url = f"{self.base_url}/breaches"
        params = {}
        if domain:
            params['domain'] = domain

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return []

    def get_paste_account(self, email: str) -> Dict[str, Any]:
        """Check if email has appeared in any pastes"""
        if not self.is_configured():
            return {'error': 'HaveIBeenPwned API key not configured'}

        url = f"{self.base_url}/pasteaccount/{email}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            if response.status_code == 404:
                return {'found': False, 'pastes': []}
            
            response.raise_for_status()
            pastes = response.json()
            
            return {
                'found': True,
                'paste_count': len(pastes),
                'pastes': pastes
            }
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
