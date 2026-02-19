import requests
import os
from typing import Dict, Optional
from dotenv import load_dotenv

load_dotenv()

class VirusTotalService:
    """Service to interact with VirusTotal API"""
    
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        
        if not self.api_key:
            raise ValueError("VirusTotal API key not found in environment variables")
    
    def check_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Check IP address reputation on VirusTotal
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with IP analysis data or None if error
        """
        headers = {
            'x-apikey': self.api_key
        }
        
        try:
            response = requests.get(
                f'{self.base_url}/ip_addresses/{ip_address}',
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            # Extract relevant information
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis = attributes.get('last_analysis_stats', {})
            
            return {
                'malicious': last_analysis.get('malicious', 0),
                'suspicious': last_analysis.get('suspicious', 0),
                'harmless': last_analysis.get('harmless', 0),
                'undetected': last_analysis.get('undetected', 0),
                'total_votes': last_analysis.get('malicious', 0) + last_analysis.get('suspicious', 0),
                'country': attributes.get('country', 'Unknown'),
                'as_owner': attributes.get('as_owner', 'Unknown'),
                'reputation': attributes.get('reputation', 0)
            }
            
        except requests.exceptions.RequestException as e:
            print(f"Error checking IP on VirusTotal {ip_address}: {str(e)}")
            return None
    
    def is_malicious(self, ip_address: str, threshold: int = 3) -> bool:
        """
        Check if IP is malicious based on VirusTotal results
        
        Args:
            ip_address: IP to check
            threshold: Number of engines that flag as malicious
            
        Returns:
            True if malicious detections >= threshold
        """
        result = self.check_ip(ip_address)
        
        if result:
            malicious_count = result.get('malicious', 0) + result.get('suspicious', 0)
            return malicious_count >= threshold
        
        return False