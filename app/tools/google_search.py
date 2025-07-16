import requests
from typing import Dict, List
from config.config import Config

class GoogleSearchTool:
    def __init__(self):
        self.timeout = Config.REQUEST_TIMEOUT
        
    def search_security_info(self, query: str, object_type: str) -> Dict:
        """Search for security-related information about the query"""
        try:
            search_terms = self._build_search_terms(query, object_type)
            results = {
                "search_terms": search_terms,
                "findings": [],
                "summary": ""
            }
            
            # For demo purposes, we'll provide static analysis based on patterns
            # In a real implementation, you could use Google Custom Search API
            findings = self._analyze_patterns(query, object_type)
            results["findings"] = findings
            results["summary"] = self._generate_summary(findings)
            
            return results
            
        except Exception as e:
            return {"error": f"Search error: {str(e)}"}
    
    def _build_search_terms(self, query: str, object_type: str) -> List[str]:
        """Build search terms based on object type"""
        base_terms = [query]
        
        if object_type == "url":
            domain = self._extract_domain(query)
            base_terms.extend([
                f"{domain} malware",
                f"{domain} phishing",
                f"{domain} reputation",
                f"{domain} security report"
            ])
        elif object_type == "file_hash":
            base_terms.extend([
                f"{query} malware",
                f"{query} virus",
                f"{query} threat report"
            ])
        elif object_type == "file_path":
            filename = query.split('\\')[-1].split('/')[-1]
            base_terms.extend([
                f"{filename} malware",
                f"{filename} suspicious process",
                f"{filename} windows threat"
            ])
        elif object_type == "ip_address":
            base_terms.extend([
                f"{query} malicious",
                f"{query} botnet",
                f"{query} threat intelligence"
            ])
        
        return base_terms
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            if '//' in url:
                return url.split('//')[1].split('/')[0]
            return url.split('/')[0]
        except:
            return url
    
    def _analyze_patterns(self, query: str, object_type: str) -> List[Dict]:
        """Analyze patterns and known indicators"""
        findings = []
        
        if object_type == "url":
            findings.extend(self._analyze_url_patterns(query))
        elif object_type == "file_path":
            findings.extend(self._analyze_file_path_patterns(query))
        elif object_type == "file_hash":
            findings.extend(self._analyze_hash_patterns(query))
        elif object_type == "ip_address":
            findings.extend(self._analyze_ip_patterns(query))
        
        return findings
    
    def _analyze_url_patterns(self, url: str) -> List[Dict]:
        """Analyze URL for suspicious patterns"""
        findings = []
        domain = self._extract_domain(url)
        
        # Check for typosquatting patterns
        legitimate_domains = [
            'viettel.com.vn', 'viettelstore.vn', 'google.com', 
            'facebook.com', 'youtube.com', 'microsoft.com'
        ]
        
        for legit_domain in legitimate_domains:
            if self._is_typosquatting(domain, legit_domain):
                findings.append({
                    "type": "typosquatting",
                    "severity": "high",
                    "description": f"Possible typosquatting of {legit_domain}",
                    "evidence": domain
                })
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.ru', '.cn']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                findings.append({
                    "type": "suspicious_tld",
                    "severity": "medium",
                    "description": f"Domain uses potentially suspicious TLD: {tld}",
                    "evidence": domain
                })
        
        # Check for legitimate domains
        trusted_domains = ['viettelstore.vn', 'viettel.com.vn']
        if domain in trusted_domains:
            findings.append({
                "type": "legitimate_domain",
                "severity": "none",
                "description": f"Known legitimate domain: {domain}",
                "evidence": domain
            })
        
        return findings
    
    def _analyze_file_path_patterns(self, path: str) -> List[Dict]:
        """Analyze file path for suspicious patterns"""
        findings = []
        path_lower = path.lower()
        
        # Check for suspicious locations
        if 'networkdistribution' in path_lower:
            findings.append({
                "type": "suspicious_location",
                "severity": "high",
                "description": "File located in suspicious NetworkDistribution folder",
                "evidence": path
            })
        
        # Check for legitimate Windows paths
        legitimate_paths = [
            r'c:\windows\system32',
            r'c:\windows\syswow64',
            r'c:\program files',
            r'c:\program files (x86)'
        ]
        
        for legit_path in legitimate_paths:
            if path_lower.startswith(legit_path):
                findings.append({
                    "type": "legitimate_path",
                    "severity": "none",
                    "description": f"File in legitimate Windows directory: {legit_path}",
                    "evidence": path
                })
                break
        
        # Check for system processes
        system_processes = ['schtasks.exe', 'taskmgr.exe', 'explorer.exe', 'winlogon.exe']
        filename = path.split('\\')[-1].lower()
        
        if filename in system_processes:
            findings.append({
                "type": "system_process",
                "severity": "none",
                "description": f"Known Windows system process: {filename}",
                "evidence": filename
            })
        
        return findings
    
    def _analyze_hash_patterns(self, hash_str: str) -> List[Dict]:
        """Analyze hash patterns"""
        findings = []
        
        # Known malicious hashes (example)
        known_malicious = [
            "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"
        ]
        
        if hash_str.lower() in [h.lower() for h in known_malicious]:
            findings.append({
                "type": "known_malware",
                "severity": "high",
                "description": "Hash matches known malware signature",
                "evidence": hash_str
            })
        
        return findings
    
    def _analyze_ip_patterns(self, ip: str) -> List[Dict]:
        """Analyze IP address patterns"""
        findings = []
        
        # Check for private IP ranges
        private_ranges = ['192.168.', '10.', '172.16.', '127.']
        for private_range in private_ranges:
            if ip.startswith(private_range):
                findings.append({
                    "type": "private_ip",
                    "severity": "low",
                    "description": f"Private IP address in range {private_range}",
                    "evidence": ip
                })
        
        return findings
    
    def _is_typosquatting(self, domain: str, legitimate: str) -> bool:
        """Simple typosquatting detection"""
        if domain == legitimate:
            return False
        
        # Calculate Levenshtein distance
        distance = self._levenshtein_distance(domain, legitimate)
        return distance <= 2 and len(domain) >= len(legitimate) - 2
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _generate_summary(self, findings: List[Dict]) -> str:
        """Generate summary from findings"""
        if not findings:
            return "No specific security intelligence found"
        
        high_severity = [f for f in findings if f.get("severity") == "high"]
        medium_severity = [f for f in findings if f.get("severity") == "medium"]
        
        if high_severity:
            return f"HIGH RISK: {high_severity[0]['description']}"
        elif medium_severity:
            return f"MEDIUM RISK: {medium_severity[0]['description']}"
        else:
            return "No significant security concerns found"
    
    def get_analysis_summary(self, query: str, object_type: str) -> str:
        """Get a summary of Google Search analysis results"""
        try:
            result = self.search_security_info(query, object_type)
            
            if "error" in result:
                return f"Google Search: {result['error']}"
            
            return f"Google Search: {result.get('summary', 'No additional intelligence found')}"
            
        except Exception as e:
            return f"Google Search: Analysis error - {str(e)}" 