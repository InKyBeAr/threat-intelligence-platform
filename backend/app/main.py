from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Optional

from app.services.abuseipdb_service import AbuseIPDBService
from app.services.ioc_service import IOCService
from app.database import get_db, init_db
from app.models.ioc import IOC
from fastapi.middleware.cors import CORSMiddleware
from app.services.virustotal_service import VirusTotalService
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from app.services.log_analyzer_service import LogAnalyzerService
app = FastAPI(
    title="Threat Intelligence Platform API",
    description="Automated Threat Intelligence Aggregation and Response Platform",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://inkybear.work.gd",
        "http://inkybear.work.gd",
        "https://threat-intel-frontend.onrender.com",  # Render frontend URL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add after existing endpoints

@app.post("/api/analyze-log")
async def analyze_log(
    file: UploadFile = File(...),
    log_type: str = 'auto',
    check_threats: bool = True,
    db: Session = Depends(get_db)
):
    """
    Upload and analyze log files (Sysmon, Wazuh, Firewall logs)
    Extracts IPs and optionally checks them against threat feeds
    """
    try:
        # Read file content
        content = await file.read()
        log_content = content.decode('utf-8', errors='ignore')
        
        # Analyze the log
        analysis = LogAnalyzerService.analyze_log_file(log_content, log_type)
        
        # If check_threats is True, check all IPs against threat feeds
        threat_results = []
        if check_threats and analysis['unique_ips']:
            for ip in analysis['unique_ips'][:50]:  # Limit to first 50 IPs
                try:
                    # Check with AbuseIPDB
                    abuseipdb_result = abuseipdb_service.check_ip(ip)
                    
                    if abuseipdb_result and 'data' in abuseipdb_result:
                        data = abuseipdb_result['data']
                        is_malicious = abuseipdb_service.is_malicious(ip)
                        
                        if is_malicious:
                            threat_results.append({
                                'ip': ip,
                                'abuse_score': data.get('abuseConfidenceScore', 0),
                                'total_reports': data.get('totalReports', 0),
                                'country': data.get('countryCode', 'Unknown'),
                                'is_malicious': True
                            })
                            
                            # Save to database
                            ioc_data = {
                                'ioc_type': 'ip',
                                'value': ip,
                                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                                'is_malicious': True,
                                'threat_level': 'high',
                                'source': 'abuseipdb',
                                'total_reports': data.get('totalReports', 0),
                                'country_code': data.get('countryCode'),
                                'description': f"Found in {analysis['type']} log file"
                            }
                            IOCService.get_or_create_ioc(db, ioc_data)
                
                except Exception as e:
                    print(f"Error checking IP {ip}: {str(e)}")
                    continue
        
        return {
            'success': True,
            'filename': file.filename,
            'log_type': analysis['type'],
            'total_ips_found': analysis['total_ips'],
            'unique_ips': analysis['unique_ips'][:10],  # Return first 10
            'total_unique_ips': len(analysis['unique_ips']),
            'threats_detected': len(threat_results),
            'malicious_ips': threat_results,
            'analysis': analysis
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing log: {str(e)}")

@app.post("/api/webhook/wazuh")
async def wazuh_webhook(alert: dict, db: Session = Depends(get_db)):
    """
    Webhook endpoint for Wazuh alerts
    Configure in Wazuh ossec.conf to send alerts here
    """
    try:
        # Extract IP from Wazuh alert
        src_ip = alert.get('data', {}).get('srcip') or alert.get('data', {}).get('src_ip')
        
        if src_ip:
            # Check threat intelligence
            result = abuseipdb_service.check_ip(src_ip)
            
            if result and 'data' in result:
                data = result['data']
                is_malicious = abuseipdb_service.is_malicious(src_ip)
                
                # Save to database
                ioc_data = {
                    'ioc_type': 'ip',
                    'value': src_ip,
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'is_malicious': is_malicious,
                    'threat_level': 'critical' if is_malicious else 'low',
                    'source': 'wazuh_webhook',
                    'total_reports': data.get('totalReports', 0),
                    'country_code': data.get('countryCode'),
                    'description': f"Wazuh alert: {alert.get('rule', {}).get('description', 'Unknown')}"
                }
                IOCService.get_or_create_ioc(db, ioc_data)
                
                return {
                    'success': True,
                    'ip': src_ip,
                    'is_malicious': is_malicious,
                    'threat_score': data.get('abuseConfidenceScore', 0)
                }
        
        return {'success': True, 'message': 'No IP found in alert'}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Initialize both services
abuseipdb_service = AbuseIPDBService()
virustotal_service = VirusTotalService()

# Add new endpoint for combined check
@app.get("/api/check-ip-combined/{ip_address}")
async def check_ip_combined(ip_address: str, save_to_db: bool = True, db: Session = Depends(get_db)):
    """Check IP against both AbuseIPDB and VirusTotal"""
    
    # Check AbuseIPDB
    abuseipdb_result = abuseipdb_service.check_ip(ip_address)
    abuseipdb_data = abuseipdb_result.get('data', {}) if abuseipdb_result else {}
    
    # Check VirusTotal
    virustotal_result = virustotal_service.check_ip(ip_address)
    
    # Combine results
    combined_result = {
        'ip_address': ip_address,
        'abuseipdb': {
            'abuse_score': abuseipdb_data.get('abuseConfidenceScore', 0),
            'total_reports': abuseipdb_data.get('totalReports', 0),
            'is_malicious': abuseipdb_service.is_malicious(ip_address)
        },
        'virustotal': virustotal_result if virustotal_result else {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0
        },
        'overall_verdict': 'MALICIOUS' if (
            abuseipdb_service.is_malicious(ip_address) or 
            virustotal_service.is_malicious(ip_address)
        ) else 'SAFE',
        'country': abuseipdb_data.get('countryCode', 'Unknown'),
        'isp': abuseipdb_data.get('isp', 'Unknown')
    }
    
    # Save to database if requested
    if save_to_db:
        ioc_data = {
            'ioc_type': 'ip',
            'value': ip_address,
            'abuse_confidence_score': abuseipdb_data.get('abuseConfidenceScore', 0),
            'is_malicious': combined_result['overall_verdict'] == 'MALICIOUS',
            'threat_level': 'critical' if combined_result['overall_verdict'] == 'MALICIOUS' else 'low',
            'source': 'abuseipdb,virustotal',
            'total_reports': abuseipdb_data.get('totalReports', 0),
            'country_code': abuseipdb_data.get('countryCode'),
            'isp': abuseipdb_data.get('isp'),
            'description': f"AbuseIPDB: {abuseipdb_data.get('abuseConfidenceScore', 0)}/100, "
                          f"VirusTotal: {virustotal_result.get('malicious', 0) if virustotal_result else 0} malicious detections"
        }
        IOCService.get_or_create_ioc(db, ioc_data)
    
    return combined_result



# Add CORS middleware - ADD THIS SECTION
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for now
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)   
   

# Initialize services
abuseipdb_service = AbuseIPDBService()

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database tables on startup"""
    init_db()
    print("🚀 Application started successfully!")

# Pydantic Models
class IPCheckRequest(BaseModel):
    ip_address: str
    save_to_db: bool = True

class IPCheckResponse(BaseModel):
    ip_address: str
    is_malicious: bool
    abuse_score: int
    country: str
    total_reports: int
    source: str
    saved_to_db: bool = False

class IOCResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    abuse_confidence_score: int
    threat_level: Optional[str]
    is_malicious: bool
    source: str
    country_code: Optional[str]
    total_reports: int
    first_seen: str
    last_seen: str
    
    class Config:
        from_attributes = True

# Endpoints
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Threat Intelligence Platform API",
        "status": "online",
        "version": "1.0.0"
    }

@app.post("/api/check-ip", response_model=IPCheckResponse)
async def check_ip(request: IPCheckRequest, db: Session = Depends(get_db)):
    """Check if an IP address is malicious and optionally save to database"""
    
    result = abuseipdb_service.check_ip(request.ip_address)
    
    if not result or 'data' not in result:
        raise HTTPException(status_code=500, detail="Failed to check IP address")
    
    data = result['data']
    is_malicious = abuseipdb_service.is_malicious(request.ip_address)
    
    saved = False
    if request.save_to_db:
        # Prepare IOC data
        ioc_data = {
            'ioc_type': 'ip',
            'value': data['ipAddress'],
            'abuse_confidence_score': data['abuseConfidenceScore'],
            'is_malicious': is_malicious,
            'threat_level': 'critical' if data['abuseConfidenceScore'] >= 75 else 
                           'high' if data['abuseConfidenceScore'] >= 50 else
                           'medium' if data['abuseConfidenceScore'] >= 25 else 'low',
            'source': 'abuseipdb',
            'total_reports': data['totalReports'],
            'country_code': data.get('countryCode'),
            'isp': data.get('isp'),
            'description': f"Detected by AbuseIPDB with {data['totalReports']} reports"
        }
        
        # Save to database
        IOCService.get_or_create_ioc(db, ioc_data)
        saved = True
    
    return IPCheckResponse(
        ip_address=data['ipAddress'],
        is_malicious=is_malicious,
        abuse_score=data['abuseConfidenceScore'],
        country=data.get('countryCode', 'Unknown'),
        total_reports=data['totalReports'],
        source='abuseipdb',
        saved_to_db=saved
    )

@app.get("/api/check-ip/{ip_address}")
async def check_ip_get(ip_address: str, save_to_db: bool = True, db: Session = Depends(get_db)):
    """Check if an IP address is malicious (GET method)"""
    
    result = abuseipdb_service.check_ip(ip_address)
    
    if not result or 'data' not in result:
        raise HTTPException(status_code=500, detail="Failed to check IP address")
    
    data = result['data']
    is_malicious = abuseipdb_service.is_malicious(ip_address)
    
    if save_to_db:
        ioc_data = {
            'ioc_type': 'ip',
            'value': data['ipAddress'],
            'abuse_confidence_score': data['abuseConfidenceScore'],
            'is_malicious': is_malicious,
            'threat_level': 'critical' if data['abuseConfidenceScore'] >= 75 else 
                           'high' if data['abuseConfidenceScore'] >= 50 else
                           'medium' if data['abuseConfidenceScore'] >= 25 else 'low',
            'source': 'abuseipdb',
            'total_reports': data['totalReports'],
            'country_code': data.get('countryCode'),
            'isp': data.get('isp')
        }
        IOCService.get_or_create_ioc(db, ioc_data)
    
    return result

@app.get("/api/iocs", response_model=List[IOCResponse])
async def get_iocs(
    ioc_type: Optional[str] = None,
    malicious_only: bool = False,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get all IOCs from database"""
    
    if malicious_only:
        iocs = IOCService.get_malicious_iocs(db, skip, limit)
    elif ioc_type:
        iocs = IOCService.get_iocs_by_type(db, ioc_type, skip, limit)
    else:
        iocs = IOCService.get_all_iocs(db, skip, limit)
    
    return [
        IOCResponse(
            id=ioc.id,
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            abuse_confidence_score=ioc.abuse_confidence_score,
            threat_level=ioc.threat_level,
            is_malicious=ioc.is_malicious,
            source=ioc.source,
            country_code=ioc.country_code,
            total_reports=ioc.total_reports,
            first_seen=ioc.first_seen.isoformat(),
            last_seen=ioc.last_seen.isoformat()
        )
        for ioc in iocs
    ]

@app.get("/api/iocs/search/{search_term}")
async def search_iocs(search_term: str, db: Session = Depends(get_db)):
    """Search IOCs by value"""
    iocs = IOCService.search_iocs(db, search_term)
    return {"results": len(iocs), "iocs": iocs}

@app.get("/api/iocs/stats")
async def get_ioc_statistics(db: Session = Depends(get_db)):
    """Get IOC statistics"""
    return IOCService.get_statistics(db)

@app.delete("/api/iocs/{ioc_id}")
async def delete_ioc(ioc_id: int, db: Session = Depends(get_db)):
    """Delete an IOC"""
    success = IOCService.delete_ioc(db, ioc_id)
    if success:
        return {"message": f"IOC {ioc_id} deleted successfully"}
    raise HTTPException(status_code=404, detail="IOC not found")