"""
VirusTotal API Integration
"""

import requests
from typing import Dict, Any, List

from ..config import config


class VirusTotalAPI:
    """VirusTotal API client"""

    def __init__(self):
        self.api_key = config.get_api_key('virustotal')
        self.base_url = "https://www.virustotal.com/api/v3"
        self.timeout = config.app_config.request_timeout
        self.headers = {
            'x-apikey': self.api_key,
            'User-Agent': config.app_config.user_agent
        }

    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)

    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Get IP address report"""
        if not self.is_configured():
            return {'error': 'VirusTotal API key not configured'}

        url = f"{self.base_url}/ip_addresses/{ip}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get domain report"""
        if not self.is_configured():
            return {'error': 'VirusTotal API key not configured'}

        url = f"{self.base_url}/domains/{domain}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL report"""
        if not self.is_configured():
            return {'error': 'VirusTotal API key not configured'}

        # URL needs to be base64 encoded
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        
        api_url = f"{self.base_url}/urls/{url_id}"

        try:
            response = requests.get(api_url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get file report by hash (MD5, SHA-1, SHA-256)"""
        if not self.is_configured():
            return {'error': 'VirusTotal API key not configured'}

        url = f"{self.base_url}/files/{file_hash}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def get_analysis_stats(self, ip: str) -> Dict[str, Any]:
        """Get analysis statistics for an IP"""
        if not self.is_configured():
            return {'error': 'VirusTotal API key not configured'}

        url = f"{self.base_url}/ip_addresses/{ip}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'timeout': stats.get('timeout', 0),
                'total': sum(stats.values())
            }
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
