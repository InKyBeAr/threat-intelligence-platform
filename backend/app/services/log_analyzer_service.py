import re
from typing import List, Dict, Set
from datetime import datetime

class LogAnalyzerService:
    """Service to analyze security logs and extract IOCs"""
    
    # IP address regex pattern
    IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    @staticmethod
    def extract_ips_from_text(text: str) -> Set[str]:
        """Extract all IP addresses from text"""
        ips = set(re.findall(LogAnalyzerService.IP_PATTERN, text))
        
        # Filter out invalid IPs and private ranges
        valid_ips = set()
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                # Exclude private IP ranges
                first_octet = int(parts[0])
                if not (
                    first_octet == 10 or  # 10.0.0.0/8
                    (first_octet == 172 and 16 <= int(parts[1]) <= 31) or  # 172.16.0.0/12
                    (first_octet == 192 and int(parts[1]) == 168) or  # 192.168.0.0/16
                    first_octet == 127  # Loopback
                ):
                    valid_ips.add(ip)
        
        return valid_ips
    
    @staticmethod
    def parse_sysmon_log(log_content: str) -> Dict:
        """Parse Sysmon log format"""
        ips = LogAnalyzerService.extract_ips_from_text(log_content)
        
        # Extract additional Sysmon-specific info
        events = []
        for line in log_content.split('\n'):
            if 'EventID' in line or 'Image:' in line or 'CommandLine:' in line:
                events.append(line.strip())
        
        return {
            'type': 'sysmon',
            'total_ips': len(ips),
            'unique_ips': list(ips),
            'events_found': len(events),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @staticmethod
    def parse_wazuh_log(log_content: str) -> Dict:
        """Parse Wazuh alert format"""
        ips = LogAnalyzerService.extract_ips_from_text(log_content)
        
        # Count alert levels
        critical_count = log_content.lower().count('level: 15') + log_content.lower().count('critical')
        high_count = log_content.lower().count('level: 12') + log_content.lower().count('high')
        
        return {
            'type': 'wazuh',
            'total_ips': len(ips),
            'unique_ips': list(ips),
            'critical_alerts': critical_count,
            'high_alerts': high_count,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @staticmethod
    def parse_firewall_log(log_content: str) -> Dict:
        """Parse generic firewall log format"""
        ips = LogAnalyzerService.extract_ips_from_text(log_content)
        
        # Count blocked/allowed
        blocked_count = log_content.lower().count('deny') + log_content.lower().count('drop') + log_content.lower().count('block')
        allowed_count = log_content.lower().count('allow') + log_content.lower().count('accept')
        
        return {
            'type': 'firewall',
            'total_ips': len(ips),
            'unique_ips': list(ips),
            'blocked_connections': blocked_count,
            'allowed_connections': allowed_count,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @staticmethod
    def analyze_log_file(log_content: str, log_type: str = 'auto') -> Dict:
        """
        Analyze a log file and extract threat indicators
        
        Args:
            log_content: Raw log file content
            log_type: Type of log (sysmon, wazuh, firewall, auto)
            
        Returns:
            Dictionary with analysis results
        """
        if log_type == 'auto':
            # Auto-detect log type
            content_lower = log_content.lower()
            if 'sysmon' in content_lower or 'eventid' in content_lower:
                log_type = 'sysmon'
            elif 'wazuh' in content_lower or 'ossec' in content_lower:
                log_type = 'wazuh'
            else:
                log_type = 'firewall'
        
        # Parse based on type
        if log_type == 'sysmon':
            return LogAnalyzerService.parse_sysmon_log(log_content)
        elif log_type == 'wazuh':
            return LogAnalyzerService.parse_wazuh_log(log_content)
        else:
            return LogAnalyzerService.parse_firewall_log(log_content)
