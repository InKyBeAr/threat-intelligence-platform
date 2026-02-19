import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Globe, Database, TrendingUp, Search, Activity, Zap, Upload, FileText, AlertCircle } from 'lucide-react';

const API_BASE = 'http://localhost:8000';

export default function ThreatIntelDashboard() {
  const [ipAddress, setIpAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [recentIOCs, setRecentIOCs] = useState([]);
  const [error, setError] = useState('');
  
  // Log upload states
  const [logFile, setLogFile] = useState(null);
  const [logType, setLogType] = useState('auto');
  const [uploadLoading, setUploadLoading] = useState(false);
  const [logResult, setLogResult] = useState(null);

  useEffect(() => {
    fetchStats();
    fetchRecentIOCs();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/iocs/stats`);
      const data = await response.json();
      setStats(data);
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  const fetchRecentIOCs = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/iocs?limit=10`);
      const data = await response.json();
      setRecentIOCs(data);
    } catch (err) {
      console.error('Failed to fetch IOCs:', err);
    }
  };

  const checkIP = async () => {
    if (!ipAddress.trim()) {
      setError('Please enter an IP address');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/api/check-ip-combined/${ipAddress}?save_to_db=true`);
      const data = await response.json();
      
      if (response.ok) {
        setResult(data);
        fetchStats();
        fetchRecentIOCs();
        setIpAddress('');
      } else {
        setError('Failed to check IP address. Please try again.');
      }
    } catch (err) {
      setError('Unable to connect to the server. Please ensure the API is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setLogFile(file);
      setLogResult(null);
      setError('');
    }
  };

  const uploadLogFile = async () => {
    if (!logFile) {
      setError('Please select a log file');
      return;
    }

    setUploadLoading(true);
    setError('');
    setLogResult(null);

    const formData = new FormData();
    formData.append('file', logFile);
    formData.append('log_type', logType);
    formData.append('check_threats', 'true');

    try {
      const response = await fetch(`${API_BASE}/api/analyze-log?log_type=${logType}&check_threats=true`, {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (response.ok) {
        setLogResult(data);
        fetchStats();
        fetchRecentIOCs();
        setLogFile(null);
        // Reset file input
        document.getElementById('file-upload').value = '';
      } else {
        setError(data.detail || 'Failed to analyze log file');
      }
    } catch (err) {
      setError('Unable to connect to the server. Please ensure the API is running.');
    } finally {
      setUploadLoading(false);
    }
  };

  const StatCard = ({ icon: Icon, label, value, color, gradient }) => (
    <div className={`relative overflow-hidden rounded-2xl shadow-xl p-6 ${gradient} transform transition-all duration-300 hover:scale-105 hover:shadow-2xl`}>
      <div className="absolute top-0 right-0 -mt-4 -mr-4 opacity-20">
        <Icon className="w-32 h-32" />
      </div>
      <div className="relative z-10">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-white bg-opacity-30 rounded-lg backdrop-blur-sm">
            <Icon className="w-6 h-6 text-white" />
          </div>
          <p className="text-white text-sm font-semibold uppercase tracking-wide">{label}</p>
        </div>
        <p className="text-4xl font-bold text-white mt-3">{value || 0}</p>
      </div>
      <div className="absolute bottom-0 left-0 w-full h-1 bg-white bg-opacity-30"></div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="relative overflow-hidden bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 rounded-2xl shadow-2xl p-8 mb-8 transform transition-all duration-500 hover:scale-[1.02]">
          <div className="absolute inset-0 bg-black opacity-10"></div>
          <div className="relative z-10 flex items-center gap-4">
            <div className="p-4 bg-white bg-opacity-20 rounded-2xl backdrop-blur-sm animate-pulse">
              <Shield className="w-12 h-12 text-white" />
            </div>
            <div>
              <h1 className="text-5xl font-black text-white tracking-tight">Threat Intelligence Platform</h1>
              <p className="text-white text-lg mt-2 font-medium flex items-center gap-2">
                <Activity className="w-5 h-5 animate-pulse" />
                Real-time IP Address Threat Detection & SIEM Integration
              </p>
            </div>
          </div>
        </div>

        {/* Two Column Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          
          {/* IP Checker Section */}
          <div className="bg-white bg-opacity-10 backdrop-blur-xl rounded-2xl shadow-2xl p-8 border border-white border-opacity-20">
            <h2 className="text-3xl font-bold text-white mb-6 flex items-center gap-3">
              <div className="p-2 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-lg">
                <Search className="w-7 h-7 text-white" />
              </div>
              Scan IP Address
            </h2>
            
            <div className="flex gap-4 mb-4">
              <input
                type="text"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && checkIP()}
                placeholder="Enter IP (e.g., 185.220.101.1)"
                className="flex-1 px-6 py-4 bg-white bg-opacity-20 backdrop-blur-sm border-2 border-white border-opacity-30 rounded-xl focus:border-cyan-400 focus:outline-none text-white placeholder-gray-300 text-lg font-medium transition-all duration-300"
              />
              <button
                onClick={checkIP}
                disabled={loading}
                className="px-8 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white rounded-xl hover:from-cyan-600 hover:to-blue-700 disabled:from-gray-500 disabled:to-gray-600 font-bold shadow-lg transform transition-all duration-300 hover:scale-105 disabled:scale-100 flex items-center gap-2"
              >
                {loading ? <Zap className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {/* Log Upload Section */}
          <div className="bg-white bg-opacity-10 backdrop-blur-xl rounded-2xl shadow-2xl p-8 border border-white border-opacity-20">
            <h2 className="text-3xl font-bold text-white mb-6 flex items-center gap-3">
              <div className="p-2 bg-gradient-to-r from-green-500 to-emerald-500 rounded-lg">
                <Upload className="w-7 h-7 text-white" />
              </div>
              Upload Log File
            </h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-white text-sm font-semibold mb-2">Log Type</label>
                <select
                  value={logType}
                  onChange={(e) => setLogType(e.target.value)}
                  className="w-full px-4 py-3 bg-white bg-opacity-20 backdrop-blur-sm border-2 border-white border-opacity-30 rounded-xl text-white font-medium focus:border-green-400 focus:outline-none"
                >
                  <option value="auto" className="bg-slate-800">Auto-detect</option>
                  <option value="sysmon" className="bg-slate-800">Sysmon</option>
                  <option value="wazuh" className="bg-slate-800">Wazuh</option>
                  <option value="firewall" className="bg-slate-800">Firewall</option>
                </select>
              </div>

              <div>
                <input
                  id="file-upload"
                  type="file"
                  onChange={handleFileChange}
                  accept=".log,.txt,.json"
                  className="hidden"
                />
                <label
                  htmlFor="file-upload"
                  className="block w-full px-6 py-8 bg-white bg-opacity-10 backdrop-blur-sm border-2 border-dashed border-white border-opacity-40 rounded-xl hover:border-green-400 cursor-pointer transition-all duration-300 text-center"
                >
                  <FileText className="w-12 h-12 text-white mx-auto mb-3 opacity-60" />
                  <p className="text-white font-semibold mb-1">
                    {logFile ? logFile.name : 'Click to upload log file'}
                  </p>
                  <p className="text-white text-opacity-60 text-sm">
                    Supports: .log, .txt, .json
                  </p>
                </label>
              </div>

              <button
                onClick={uploadLogFile}
                disabled={uploadLoading || !logFile}
                className="w-full px-8 py-4 bg-gradient-to-r from-green-500 to-emerald-600 text-white rounded-xl hover:from-green-600 hover:to-emerald-700 disabled:from-gray-500 disabled:to-gray-600 font-bold shadow-lg transform transition-all duration-300 hover:scale-105 disabled:scale-100 flex items-center justify-center gap-2"
              >
                {uploadLoading ? (
                  <>
                    <Zap className="w-5 h-5 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Upload className="w-5 h-5" />
                    Analyze Log
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-500 bg-opacity-20 border-2 border-red-500 text-white px-6 py-4 rounded-xl flex items-center gap-3 backdrop-blur-sm mb-8 animate-pulse">
            <AlertTriangle className="w-6 h-6" />
            <span className="font-semibold">{error}</span>
          </div>
        )}

        {/* Log Analysis Result */}
        {logResult && (
          <div className="bg-white bg-opacity-10 backdrop-blur-xl rounded-2xl shadow-2xl p-8 mb-8 border border-white border-opacity-20">
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
              <FileText className="w-6 h-6" />
              Log Analysis Results
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-white bg-opacity-20 backdrop-blur-sm rounded-xl p-4">
                <p className="text-white text-opacity-70 text-sm mb-1">File</p>
                <p className="text-white font-bold text-lg">{logResult.filename}</p>
              </div>
              <div className="bg-white bg-opacity-20 backdrop-blur-sm rounded-xl p-4">
                <p className="text-white text-opacity-70 text-sm mb-1">Type</p>
                <p className="text-white font-bold text-lg uppercase">{logResult.log_type}</p>
              </div>
              <div className="bg-white bg-opacity-20 backdrop-blur-sm rounded-xl p-4">
                <p className="text-white text-opacity-70 text-sm mb-1">IPs Found</p>
                <p className="text-white font-bold text-lg">{logResult.total_unique_ips}</p>
              </div>
              <div className="bg-white bg-opacity-20 backdrop-blur-sm rounded-xl p-4">
                <p className="text-white text-opacity-70 text-sm mb-1">Threats</p>
                <p className="text-red-400 font-bold text-lg">{logResult.threats_detected}</p>
              </div>
            </div>

            {logResult.threats_detected > 0 && (
              <div className="bg-red-500 bg-opacity-20 border-2 border-red-400 rounded-xl p-6">
                <h4 className="text-white font-bold text-xl mb-4 flex items-center gap-2">
                  <AlertCircle className="w-6 h-6" />
                  Malicious IPs Detected
                </h4>
                <div className="space-y-3">
                  {logResult.malicious_ips.map((ip, idx) => (
                    <div key={idx} className="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg p-4 flex items-center justify-between">
                      <div>
                        <p className="text-white font-mono font-bold text-lg">{ip.ip}</p>
                        <p className="text-white text-opacity-70 text-sm">{ip.country} • {ip.total_reports} reports</p>
                      </div>
                      <div className="text-right">
                        <p className="text-red-400 font-bold text-2xl">{ip.abuse_score}/100</p>
                        <p className="text-white text-opacity-70 text-sm">Threat Score</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {logResult.threats_detected === 0 && (
              <div className="bg-green-500 bg-opacity-20 border-2 border-green-400 rounded-xl p-6 text-center">
                <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-3" />
                <p className="text-white font-bold text-xl">No threats detected in log file</p>
                <p className="text-white text-opacity-70 mt-2">All {logResult.total_unique_ips} IPs checked are clean</p>
              </div>
            )}
          </div>
        )}

        {/* IP Result Display */}
        {result && (
          <div className={`mb-8 rounded-2xl p-8 border-2 shadow-2xl transform transition-all duration-500 ${
            result.overall_verdict === 'MALICIOUS' 
              ? 'bg-gradient-to-br from-red-600 to-pink-600 border-red-400' 
              : 'bg-gradient-to-br from-green-600 to-emerald-600 border-green-400'
          }`}>
            <div className="flex items-start justify-between mb-6">
              <div>
                <h3 className="text-4xl font-black text-white mb-3 font-mono tracking-tight">{result.ip_address}</h3>
                <div className="flex items-center gap-3">
                  <div className="p-3 bg-white bg-opacity-30 rounded-xl backdrop-blur-sm">
                    {result.overall_verdict === 'MALICIOUS' ? (
                      <AlertTriangle className="w-8 h-8 text-white animate-pulse" />
                    ) : (
                      <CheckCircle className="w-8 h-8 text-white" />
                    )}
                  </div>
                  <div>
                    <span className="text-3xl font-black text-white tracking-wider">
                      {result.overall_verdict}
                    </span>
                    <p className="text-white text-opacity-80 text-sm mt-1">
                      {result.overall_verdict === 'MALICIOUS' ? 'High-risk threat detected' : 'No threats detected'}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
              <div className="bg-white bg-opacity-20 backdrop-blur-md rounded-xl p-6 border border-white border-opacity-30">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-2 h-2 bg-indigo-400 rounded-full animate-pulse"></div>
                  <h4 className="font-bold text-white text-lg uppercase">AbuseIPDB</h4>
                </div>
                <p className="text-5xl font-black text-white mb-2">{result.abuseipdb.abuse_score}<span className="text-2xl opacity-60">/100</span></p>
                <p className="text-white text-opacity-80 font-semibold">{result.abuseipdb.total_reports} reports</p>
              </div>

              <div className="bg-white bg-opacity-20 backdrop-blur-md rounded-xl p-6 border border-white border-opacity-30">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse"></div>
                  <h4 className="font-bold text-white text-lg uppercase">VirusTotal</h4>
                </div>
                <p className="text-5xl font-black text-white mb-2">{result.virustotal.malicious}</p>
                <p className="text-white text-opacity-80 font-semibold">malicious detections</p>
              </div>

              <div className="bg-white bg-opacity-20 backdrop-blur-md rounded-xl p-6 border border-white border-opacity-30">
                <Globe className="w-8 h-8 text-white opacity-60 mb-2" />
                <p className="text-white text-opacity-70 text-sm font-semibold uppercase mb-1">Country</p>
                <p className="text-3xl font-bold text-white">{result.country}</p>
              </div>

              <div className="bg-white bg-opacity-20 backdrop-blur-md rounded-xl p-6 border border-white border-opacity-30">
                <Activity className="w-8 h-8 text-white opacity-60 mb-2" />
                <p className="text-white text-opacity-70 text-sm font-semibold uppercase mb-1">ISP</p>
                <p className="text-xl font-bold text-white">{result.isp}</p>
              </div>
            </div>
          </div>
        )}

        {/* Statistics */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <StatCard 
              icon={Database} 
              label="Total IPs Scanned" 
              value={stats.total_iocs} 
              gradient="bg-gradient-to-br from-blue-500 to-indigo-600"
            />
            <StatCard 
              icon={AlertTriangle} 
              label="Malicious IPs" 
              value={stats.malicious_iocs} 
              gradient="bg-gradient-to-br from-red-500 to-pink-600"
            />
            <StatCard 
              icon={CheckCircle} 
              label="Safe IPs" 
              value={stats.safe_iocs} 
              gradient="bg-gradient-to-br from-green-500 to-emerald-600"
            />
            <StatCard 
              icon={TrendingUp} 
              label="Detection Rate" 
              value={stats.total_iocs > 0 ? `${Math.round((stats.malicious_iocs / stats.total_iocs) * 100)}%` : '0%'} 
              gradient="bg-gradient-to-br from-orange-500 to-amber-600"
            />
          </div>
        )}

        {/* Recent Scans Table */}
        <div className="bg-white bg-opacity-10 backdrop-blur-xl rounded-2xl shadow-2xl p-8 border border-white border-opacity-20">
          <h2 className="text-3xl font-bold text-white mb-6 flex items-center gap-3">
            <div className="p-2 bg-gradient-to-r from-purple-500 to-pink-500 rounded-lg">
              <Globe className="w-7 h-7 text-white" />
            </div>
            Recent IP Scans
          </h2>
          
          {recentIOCs.length === 0 ? (
            <div className="text-center py-16">
              <Database className="w-20 h-20 mx-auto mb-4 text-white opacity-30" />
              <p className="text-xl text-white opacity-70 font-medium">No IPs scanned yet</p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl">
              <table className="w-full">
                <thead>
                  <tr className="bg-white bg-opacity-20 backdrop-blur-sm border-b-2 border-white border-opacity-30">
                    <th className="px-6 py-4 text-left text-sm font-bold text-white uppercase">IP Address</th>
                    <th className="px-6 py-4 text-left text-sm font-bold text-white uppercase">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-bold text-white uppercase">Threat Score</th>
                    <th className="px-6 py-4 text-left text-sm font-bold text-white uppercase">Country</th>
                    <th className="px-6 py-4 text-left text-sm font-bold text-white uppercase">Reports</th>
                    <th className="px-6 py-4 text-left text-sm font-bold text-white uppercase">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {recentIOCs.map((ioc) => (
                    <tr key={ioc.id} className="border-b border-white border-opacity-10 hover:bg-white hover:bg-opacity-10 transition-all">
                      <td className="px-6 py-4 font-mono text-base text-white font-semibold">{ioc.value}</td>
                      <td className="px-6 py-4">
                        <span className={`px-4 py-2 rounded-full text-sm font-bold uppercase ${
                          ioc.is_malicious 
                            ? 'bg-red-500 text-white shadow-lg' 
                            : 'bg-green-500 text-white shadow-lg'
                        }`}>
                          {ioc.is_malicious ? '⚠ Malicious' : '✓ Safe'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="flex-1 bg-white bg-opacity-30 rounded-full h-3">
                            <div 
                              className={`h-3 rounded-full ${
                                ioc.abuse_confidence_score >= 75 ? 'bg-gradient-to-r from-red-500 to-red-600' :
                                ioc.abuse_confidence_score >= 50 ? 'bg-gradient-to-r from-orange-500 to-orange-600' :
                                ioc.abuse_confidence_score >= 25 ? 'bg-gradient-to-r from-yellow-500 to-yellow-600' :
                                'bg-gradient-to-r from-green-500 to-green-600'
                              }`}
                              style={{ width: `${ioc.abuse_confidence_score}%` }}
                            />
                          </div>
                          <span className="text-base font-bold text-white">{ioc.abuse_confidence_score}/100</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-base text-white font-semibold">{ioc.country_code || 'Unknown'}</td>
                      <td className="px-6 py-4 text-base text-white font-semibold">{ioc.total_reports}</td>
                      <td className="px-6 py-4 text-sm text-white opacity-80">{new Date(ioc.last_seen).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}