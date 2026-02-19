import requests
import os
from typing import Dict, Optional
from dotenv import load_dotenv

load_dotenv()

class AbuseIPDBService:
    """Service to interact with AbuseIPDB API"""
    
    def __init__(self):
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.base_url = 'https://api.abuseipdb.com/api/v2'
        
        if not self.api_key:
            raise ValueError("AbuseIPDB API key not found in environment variables")
    
    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[Dict]:
        """
        Check if an IP address is malicious
        
        Args:
            ip_address: IP address to check
            max_age_days: Maximum age of reports to consider (default 90 days)
            
        Returns:
            Dictionary with IP reputation data or None if error
        """
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_days,
            'verbose': ''
        }
        
        try:
            response = requests.get(
                f'{self.base_url}/check',
                headers=headers,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Error checking IP {ip_address}: {str(e)}")
            return None
    
    def is_malicious(self, ip_address: str, threshold: int = 50) -> bool:
        """
        Simple check if IP is considered malicious based on abuse confidence score
        
        Args:
            ip_address: IP to check
            threshold: Abuse confidence score threshold (0-100)
            
        Returns:
            True if IP is malicious, False otherwise
        """
        result = self.check_ip(ip_address)
        
        if result and 'data' in result:
            abuse_score = result['data'].get('abuseConfidenceScore', 0)
            return abuse_score >= threshold
        
        return False