from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class IOC(Base):
    """Indicator of Compromise Model"""
    __tablename__ = 'iocs'
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(50), nullable=False, index=True)  # 'ip', 'domain', 'url', 'hash'
    value = Column(String(500), nullable=False, unique=True, index=True)
    
    # Threat Intelligence
    abuse_confidence_score = Column(Integer, default=0)
    threat_level = Column(String(20))  # 'low', 'medium', 'high', 'critical'
    is_malicious = Column(Boolean, default=False)
    
    # Source Information
    source = Column(String(100), nullable=False)  # 'abuseipdb', 'virustotal', etc.
    total_reports = Column(Integer, default=0)
    
    # Geolocation (for IPs)
    country_code = Column(String(10))
    isp = Column(String(255))
    
    # Additional Context
    tags = Column(Text)  # JSON string of tags
    description = Column(Text)
    
    # Timestamps
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<IOC(type={self.ioc_type}, value={self.value}, score={self.abuse_confidence_score})>"