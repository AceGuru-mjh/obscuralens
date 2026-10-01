"""
Shodan API Integration
"""

import requests
from typing import Dict, Any, List, Optional

from ..config import config


class ShodanAPI:
    """Shodan API client"""

    def __init__(self):
        self.api_key = config.get_api_key('shodan')
        self.base_url = "https://api.shodan.io"
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)

    def host_search(self, ip: str) -> Dict[str, Any]:
        """Search for host information"""
        if not self.is_configured():
            return {'error': 'Shodan API key not configured'}

        url = f"{self.base_url}/shodan/host/{ip}"
        params = {'key': self.api_key}

        try:
            response = requests.get(url, params=params, headers=self.headers, 
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def search(self, query: str, limit: int = 100) -> Dict[str, Any]:
        """Search Shodan database"""
        if not self.is_configured():
            return {'error': 'Shodan API key not configured'}

        url = f"{self.base_url}/shodan/host/search"
        params = {
            'key': self.api_key,
            'query': query,
            'limit': limit
        }

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_ports(self) -> List[int]:
        """Get list of ports Shodan is monitoring"""
        if not self.is_configured():
            return []

        url = f"{self.base_url}/shodan/ports"
        params = {'key': self.api_key}

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return []

    def get_protocols(self) -> Dict[str, Any]:
        """Get list of protocols Shodan can detect"""
        if not self.is_configured():
            return {}

        url = f"{self.base_url}/shodan/protocols"
        params = {'key': self.api_key}

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_api_info(self) -> Dict[str, Any]:
        """Get API usage information"""
        if not self.is_configured():
            return {'error': 'Shodan API key not configured'}

        url = f"{self.base_url}/api-info"
        params = {'key': self.api_key}

        try:
            response = requests.get(url, params=params, headers=self.headers,
                                  timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
