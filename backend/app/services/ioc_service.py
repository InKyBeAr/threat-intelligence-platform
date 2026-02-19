from sqlalchemy.orm import Session
from app.models.ioc import IOC
from typing import List, Optional
from datetime import datetime

class IOCService:
    """Service for IOC database operations"""
    
    @staticmethod
    def create_ioc(db: Session, ioc_data: dict) -> IOC:
        """Create a new IOC in database"""
        ioc = IOC(**ioc_data)
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        return ioc
    
    @staticmethod
    def get_ioc_by_value(db: Session, value: str) -> Optional[IOC]:
        """Get IOC by its value"""
        return db.query(IOC).filter(IOC.value == value).first()
    
    @staticmethod
    def get_or_create_ioc(db: Session, ioc_data: dict) -> tuple[IOC, bool]:
        """Get existing IOC or create new one. Returns (ioc, created)"""
        existing = IOCService.get_ioc_by_value(db, ioc_data['value'])
        
        if existing:
            # Update existing IOC
            for key, value in ioc_data.items():
                setattr(existing, key, value)
            existing.last_seen = datetime.utcnow()
            existing.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(existing)
            return existing, False
        
        # Create new IOC
        return IOCService.create_ioc(db, ioc_data), True
    
    @staticmethod
    def get_all_iocs(db: Session, skip: int = 0, limit: int = 100) -> List[IOC]:
        """Get all IOCs with pagination"""
        return db.query(IOC).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_iocs_by_type(db: Session, ioc_type: str, skip: int = 0, limit: int = 100) -> List[IOC]:
        """Get IOCs by type"""
        return db.query(IOC).filter(IOC.ioc_type == ioc_type).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_malicious_iocs(db: Session, skip: int = 0, limit: int = 100) -> List[IOC]:
        """Get all malicious IOCs"""
        return db.query(IOC).filter(IOC.is_malicious == True).offset(skip).limit(limit).all()
    
    @staticmethod
    def search_iocs(db: Session, search_term: str) -> List[IOC]:
        """Search IOCs by value"""
        return db.query(IOC).filter(IOC.value.like(f"%{search_term}%")).all()
    
    @staticmethod
    def delete_ioc(db: Session, ioc_id: int) -> bool:
        """Delete an IOC"""
        ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
        if ioc:
            db.delete(ioc)
            db.commit()
            return True
        return False
    
    @staticmethod
    def get_statistics(db: Session) -> dict:
        """Get IOC statistics"""
        from sqlalchemy import func
        
        total = db.query(IOC).count()
        malicious = db.query(IOC).filter(IOC.is_malicious == True).count()
        by_type = db.query(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type).all()
        
        return {
            "total_iocs": total,
            "malicious_iocs": malicious,
            "safe_iocs": total - malicious,
            "by_type": {ioc_type: count for ioc_type, count in by_type}
        }
        
      
        