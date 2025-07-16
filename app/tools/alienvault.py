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
            elif object_type == "ip_address":
                result = self.analyze_ip(query)
            else:
                return f"AlienVault OTX: Object type '{object_type}' not supported for analysis"
            
            if "error" in result:
                error_msg = result['error']
                if "not found" in error_msg.lower():
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
            
            if pulse_count == 0:
                return f"AlienVault OTX: No threat intelligence found for this {object_type}"
            
            summary = f"AlienVault OTX: THREAT DETECTED - Found {pulse_count} threat pulse(s)"
            
            if threat_types:
                summary += f" - Threat types: {', '.join(threat_types[:3])}"
            
            if malware_families:
                summary += f" - Malware families: {', '.join(malware_families[:3])}"
            
            return summary
            
        except Exception as e:
            return f"AlienVault OTX: Analysis error - {str(e)}" 