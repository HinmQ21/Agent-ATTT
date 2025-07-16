import requests
import time
import base64
import hashlib
from typing import Dict, Optional
from config.config import Config

class VirusTotalTool:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = Config.VIRUSTOTAL_BASE_URL
        self.timeout = Config.REQUEST_TIMEOUT
        
    def _make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make HTTP request to VirusTotal API"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/{endpoint}",
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Resource not found"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except requests.exceptions.Timeout:
            return {"error": "Request timeout"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Request error: {str(e)}"}
    
    def analyze_url(self, url: str) -> Dict:
        """Analyze URL using VirusTotal"""
        # Encode URL for VirusTotal
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        result = self._make_request(f"urls/{url_id}")
        
        if result and "data" in result:
            attributes = result["data"].get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "total_votes": sum(stats.values()) if stats else 0,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0) + stats.get("undetected", 0),
                "reputation": attributes.get("reputation", 0),
                "categories": attributes.get("categories", {}),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "scan_results": self._format_scan_results(attributes.get("last_analysis_results", {}))
            }
        
        return result or {"error": "No data available"}
    
    def analyze_file_hash(self, file_hash: str) -> Dict:
        """Analyze file hash using VirusTotal"""
        result = self._make_request(f"files/{file_hash}")
        
        if result and "data" in result:
            attributes = result["data"].get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "total_votes": sum(stats.values()) if stats else 0,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0) + stats.get("undetected", 0),
                "file_type": attributes.get("type_description", "Unknown"),
                "file_size": attributes.get("size", 0),
                "names": attributes.get("names", []),
                "signature_info": attributes.get("signature_info", {}),
                "scan_results": self._format_scan_results(attributes.get("last_analysis_results", {}))
            }
        
        return result or {"error": "No data available"}
    
    def analyze_ip(self, ip_address: str) -> Dict:
        """Analyze IP address using VirusTotal"""
        result = self._make_request(f"ip_addresses/{ip_address}")
        
        if result and "data" in result:
            attributes = result["data"].get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "total_votes": sum(stats.values()) if stats else 0,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0) + stats.get("undetected", 0),
                "country": attributes.get("country", "Unknown"),
                "asn": attributes.get("asn", "Unknown"),
                "as_owner": attributes.get("as_owner", "Unknown"),
                "reputation": attributes.get("reputation", 0)
            }
        
        return result or {"error": "No data available"}
    
    def analyze_file_path(self, file_path: str) -> Dict:
        """Analyze file path by searching for the filename"""
        try:
            # Extract filename from path
            filename = file_path.split('\\')[-1].split('/')[-1]
            
            # Search for files with this name
            result = self._make_request("search", params={"query": f"name:{filename}"})
            
            if result and "data" in result:
                files = result["data"]
                if not files:
                    return {"error": "No files found with this name"}
                
                # Analyze the most relevant file (first result)
                file_info = files[0]
                attributes = file_info.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                return {
                    "total_votes": sum(stats.values()) if stats else 0,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0) + stats.get("undetected", 0),
                    "file_type": attributes.get("type_description", "Unknown"),
                    "file_size": attributes.get("size", 0),
                    "names": attributes.get("names", []),
                    "signature_info": attributes.get("signature_info", {}),
                    "scan_results": self._format_scan_results(attributes.get("last_analysis_results", {})),
                    "search_count": len(files)
                }
            
            return result or {"error": "Search failed"}
            
        except Exception as e:
            return {"error": f"File path analysis error: {str(e)}"}
    
    def _format_scan_results(self, scan_results: Dict) -> Dict:
        """Format scan results for better readability"""
        formatted = {
            "detected_engines": [],
            "clean_engines": [],
            "total_engines": len(scan_results)
        }
        
        for engine, result in scan_results.items():
            if result.get("category") in ["malicious", "suspicious"]:
                formatted["detected_engines"].append({
                    "engine": engine,
                    "result": result.get("result", "Unknown"),
                    "category": result.get("category")
                })
            else:
                formatted["clean_engines"].append(engine)
        
        return formatted
    
    def get_analysis_summary(self, query: str, object_type: str) -> str:
        """Get a summary of VirusTotal analysis results"""
        try:
            if object_type == "url":
                result = self.analyze_url(query)
            elif object_type == "file_hash":
                result = self.analyze_file_hash(query)
            elif object_type == "file_path":
                result = self.analyze_file_path(query)
            elif object_type == "ip_address":
                result = self.analyze_ip(query)
            else:
                return f"VirusTotal: Object type '{object_type}' not supported for analysis"
            
            if "error" in result:
                error_msg = result['error']
                if "not found" in error_msg.lower() or "no files found" in error_msg.lower():
                    return f"VirusTotal: No analysis data found for this {object_type}"
                elif "rate limit" in error_msg.lower():
                    return "VirusTotal: Rate limit exceeded - unable to analyze at this time"
                elif "api error" in error_msg.lower():
                    return f"VirusTotal: API temporarily unavailable - {error_msg}"
                else:
                    return f"VirusTotal: Analysis failed - {error_msg}"
            
            malicious = result.get("malicious", 0)
            total = result.get("total_votes", 0)
            search_count = result.get("search_count", 0)
            
            if total == 0:
                return f"VirusTotal: No analysis data available for this {object_type}"
            
            summary = ""
            if object_type == "file_path" and search_count > 0:
                filename = query.split('\\')[-1].split('/')[-1]
                summary = f"VirusTotal: Found {search_count} file(s) named '{filename}' - "
            
            if malicious > 0:
                return f"{summary}DETECTED as malicious by {malicious}/{total} engines - THREAT CONFIRMED"
            else:
                return f"{summary}CLEAN - No threats detected by {total} engines"
                
        except Exception as e:
            return f"VirusTotal: Analysis error - {str(e)}" 