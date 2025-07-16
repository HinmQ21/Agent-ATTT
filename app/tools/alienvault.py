import requests
from typing import Dict, Optional, List
from config.config import Config

class AlienVaultTool:
    def __init__(self):
        self.api_key = Config.ALIENVAULT_API_KEY
        self.base_url = Config.ALIENVAULT_BASE_URL
        self.timeout = Config.REQUEST_TIMEOUT
        
    def _make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make HTTP request to AlienVault OTX API"""
        if not self.api_key:
            return {"error": "AlienVault API key not configured"}
        
        headers = {
            "X-OTX-API-KEY": self.api_key,
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
        """Analyze URL using AlienVault OTX"""
        try:
            # Extract domain from URL
            from urllib.parse import urlparse
            domain = urlparse(url).netloc if '//' in url else url
            
            result = self._make_request(f"indicators/domain/{domain}/general")
            
            if result and not result.get("error"):
                pulse_info = result.get("pulse_info", {})
                
                return {
                    "pulses": pulse_info.get("count", 0),
                    "references": pulse_info.get("references", []),
                    "malware_families": self._extract_malware_families(pulse_info.get("pulses", [])),
                    "threat_types": self._extract_threat_types(pulse_info.get("pulses", [])),
                    "reputation_score": self._calculate_reputation_score(pulse_info),
                    "first_seen": self._get_first_seen(pulse_info.get("pulses", [])),
                    "tags": self._extract_tags(pulse_info.get("pulses", []))
                }
            
            return result or {"error": "No data available"}
            
        except Exception as e:
            return {"error": f"URL analysis error: {str(e)}"}
    
    def analyze_file_hash(self, file_hash: str) -> Dict:
        """Analyze file hash using AlienVault OTX"""
        try:
            result = self._make_request(f"indicators/file/{file_hash}/general")
            
            if result and not result.get("error"):
                pulse_info = result.get("pulse_info", {})
                
                return {
                    "pulses": pulse_info.get("count", 0),
                    "references": pulse_info.get("references", []),
                    "malware_families": self._extract_malware_families(pulse_info.get("pulses", [])),
                    "threat_types": self._extract_threat_types(pulse_info.get("pulses", [])),
                    "reputation_score": self._calculate_reputation_score(pulse_info),
                    "first_seen": self._get_first_seen(pulse_info.get("pulses", [])),
                    "tags": self._extract_tags(pulse_info.get("pulses", []))
                }
            
            return result or {"error": "No data available"}
            
        except Exception as e:
            return {"error": f"File hash analysis error: {str(e)}"}
    
    def analyze_ip(self, ip_address: str) -> Dict:
        """Analyze IP address using AlienVault OTX"""
        try:
            result = self._make_request(f"indicators/IPv4/{ip_address}/general")
            
            if result and not result.get("error"):
                pulse_info = result.get("pulse_info", {})
                
                return {
                    "pulses": pulse_info.get("count", 0),
                    "references": pulse_info.get("references", []),
                    "malware_families": self._extract_malware_families(pulse_info.get("pulses", [])),
                    "threat_types": self._extract_threat_types(pulse_info.get("pulses", [])),
                    "reputation_score": self._calculate_reputation_score(pulse_info),
                    "first_seen": self._get_first_seen(pulse_info.get("pulses", [])),
                    "tags": self._extract_tags(pulse_info.get("pulses", [])),
                    "country": result.get("country_name", "Unknown"),
                    "asn": result.get("asn", "Unknown")
                }
            
            return result or {"error": "No data available"}
            
        except Exception as e:
            return {"error": f"IP analysis error: {str(e)}"}
    
    def analyze_file_path(self, file_path: str) -> Dict:
        """Analyze file path by searching for the filename"""
        try:
            # Extract filename from path
            filename = file_path.split('\\')[-1].split('/')[-1]
            
            # Search for indicators related to this filename
            result = self._make_request(f"search/general", params={"q": filename})
            
            if result and not result.get("error"):
                results = result.get("results", [])
                
                # Filter for file indicators
                file_indicators = [r for r in results if r.get("type") in ["FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]]
                
                if file_indicators:
                    # Get pulse information for the first file indicator
                    first_hash = file_indicators[0].get("indicator", "")
                    pulse_result = self._make_request(f"indicators/file/{first_hash}/general")
                    
                    if pulse_result and not pulse_result.get("error"):
                        pulse_info = pulse_result.get("pulse_info", {})
                        
                        return {
                            "pulses": pulse_info.get("count", 0),
                            "references": pulse_info.get("references", []),
                            "malware_families": self._extract_malware_families(pulse_info.get("pulses", [])),
                            "threat_types": self._extract_threat_types(pulse_info.get("pulses", [])),
                            "reputation_score": self._calculate_reputation_score(pulse_info),
                            "first_seen": self._get_first_seen(pulse_info.get("pulses", [])),
                            "tags": self._extract_tags(pulse_info.get("pulses", [])),
                            "filename": filename,
                            "related_hashes": len(file_indicators)
                        }
                
                return {"pulses": 0, "filename": filename, "related_hashes": 0}
            
            return result or {"error": "Search failed"}
            
        except Exception as e:
            return {"error": f"File path analysis error: {str(e)}"}
    
    def _extract_malware_families(self, pulses: List[Dict]) -> List[str]:
        """Extract malware families from pulses"""
        families = set()
        for pulse in pulses:
            tags = pulse.get("tags", [])
            for tag in tags:
                if any(keyword in tag.lower() for keyword in ['malware', 'trojan', 'virus', 'ransomware', 'backdoor']):
                    families.add(tag)
        return list(families)
    
    def _extract_threat_types(self, pulses: List[Dict]) -> List[str]:
        """Extract threat types from pulses"""
        threat_types = set()
        for pulse in pulses:
            tags = pulse.get("tags", [])
            for tag in tags:
                if any(keyword in tag.lower() for keyword in ['phishing', 'spam', 'botnet', 'c2', 'apt']):
                    threat_types.add(tag)
        return list(threat_types)
    
    def _extract_tags(self, pulses: List[Dict]) -> List[str]:
        """Extract all unique tags from pulses"""
        all_tags = set()
        for pulse in pulses:
            tags = pulse.get("tags", [])
            all_tags.update(tags)
        return list(all_tags)
    
    def _calculate_reputation_score(self, pulse_info: Dict) -> int:
        """Calculate reputation score based on pulse information"""
        pulse_count = pulse_info.get("count", 0)
        
        if pulse_count == 0:
            return 0  # Neutral
        elif pulse_count <= 2:
            return -1  # Slightly suspicious
        elif pulse_count <= 5:
            return -2  # Suspicious
        else:
            return -3  # Highly suspicious
    
    def _get_first_seen(self, pulses: List[Dict]) -> str:
        """Get the earliest first seen date from pulses"""
        if not pulses:
            return "Unknown"
        
        dates = [pulse.get("created", "") for pulse in pulses if pulse.get("created")]
        return min(dates) if dates else "Unknown"
    
    def get_analysis_summary(self, query: str, object_type: str) -> str:
        """Get a summary of AlienVault OTX analysis results"""
        try:
            if object_type in ["url", "domain"]:
                result = self.analyze_url(query)
            elif object_type == "file_hash":
                result = self.analyze_file_hash(query)
            elif object_type == "file_path":
                result = self.analyze_file_path(query)
            elif object_type == "ip_address":
                result = self.analyze_ip(query)
            else:
                return f"AlienVault OTX: Object type '{object_type}' not supported for analysis"
            
            if "error" in result:
                error_msg = result['error']
                if "not found" in error_msg.lower() or "search failed" in error_msg.lower():
                    return f"AlienVault OTX: No threat intelligence found for this {object_type}"
                elif "rate limit" in error_msg.lower():
                    return "AlienVault OTX: Rate limit exceeded - unable to analyze at this time"
                elif "api error" in error_msg.lower():
                    return f"AlienVault OTX: API temporarily unavailable - {error_msg}"
                else:
                    return f"AlienVault OTX: Analysis failed - {error_msg}"
            
            pulse_count = result.get("pulses", 0)
            threat_types = result.get("threat_types", [])
            malware_families = result.get("malware_families", [])
            related_hashes = result.get("related_hashes", 0)
            filename = result.get("filename", "")
            
            if pulse_count == 0:
                if object_type == "file_path" and related_hashes > 0:
                    return f"AlienVault OTX: Found {related_hashes} hash(es) for '{filename}' but no threat pulses"
                return f"AlienVault OTX: No threat intelligence found for this {object_type}"
            
            summary = f"AlienVault OTX: THREAT DETECTED - Found {pulse_count} threat pulse(s)"
            
            if object_type == "file_path" and filename:
                summary += f" for file '{filename}'"
            
            if threat_types:
                summary += f" - Threat types: {', '.join(threat_types[:3])}"
            
            if malware_families:
                summary += f" - Malware families: {', '.join(malware_families[:3])}"
            
            return summary
            
        except Exception as e:
            return f"AlienVault OTX: Analysis error - {str(e)}" 