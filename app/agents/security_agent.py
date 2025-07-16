import os
import json
import logging
from typing import Dict, Any
from openai import OpenAI

from app.utils.helpers import classify_object, is_suspicious_path, is_legitimate_windows_path, extract_file_path_from_query, extract_hash_from_query
from app.tools.virustotal import VirusTotalTool
from app.tools.alienvault import AlienVaultTool
from app.tools.google_search import GoogleSearchTool
from config.config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityAgent:
    def __init__(self):
        """Initialize the Security Agent with AI model and security tools"""
        # Configure OpenAI GPT-4o mini
        self.client = OpenAI(api_key=Config.OPENAI_API_KEY)
        self.model = "gpt-4o-mini"
        logger.info("OpenAI client initialized successfully")
        
        # Initialize security tools
        self.virustotal = VirusTotalTool()
        self.alienvault = AlienVaultTool()
        self.google_search = GoogleSearchTool()
        
        logger.info("SecurityAgent initialized successfully")
    
    def analyze(self, query: str) -> Dict[str, Any]:
        """
        Main analysis method that orchestrates the security analysis
        Returns: {"analysis": "detailed analysis", "result": "ABNORMAL|CLEAN|UNKNOWN"}
        """
        logger.info(f"Starting analysis for query: {query[:50]}...")
        
        # Step 1: Classify the object type
        object_type = classify_object(query)
        logger.info(f"Object classified as: {object_type}")
        
        # Step 2: Gather intelligence from multiple tools
        intelligence = self.gather_intelligence(query, object_type)
        
        # Step 3: Analyze with AI using all available intelligence
        ai_analysis = self.ai_analysis(query, object_type, intelligence)
        
        # Step 4: Generate final result
        result = {
            "analysis": ai_analysis.get("explanation", "Analysis completed"),
            "result": ai_analysis.get("classification", "UNKNOWN")
        }
        
        logger.info(f"Analysis completed with result: {result['result']}")
        return result
    
    def gather_intelligence(self, query: str, object_type: str) -> Dict[str, str]:
        """Gather intelligence from multiple security tools"""
        intelligence = {}
        
        # Extract the appropriate value based on object type
        if object_type == "file_path":
            extracted_value = extract_file_path_from_query(query)
        elif object_type == "file_hash":
            extracted_value = extract_hash_from_query(query)
        else:
            extracted_value = query
        
        # VirusTotal analysis
        intelligence["virustotal"] = self.virustotal.get_analysis_summary(extracted_value, object_type)
        logger.info("VirusTotal analysis completed")
        
        # AlienVault OTX analysis  
        intelligence["alienvault"] = self.alienvault.get_analysis_summary(extracted_value, object_type)
        logger.info("AlienVault analysis completed")
        
        # Google Search analysis (use original query for context)
        intelligence["google_search"] = self.google_search.get_analysis_summary(query, object_type)
        logger.info("Google Search analysis completed")
        
        # Additional static analysis (use extracted value)
        intelligence["static_analysis"] = self.static_analysis(extracted_value, object_type)
        
        return intelligence
    
    def static_analysis(self, query: str, object_type: str) -> str:
        """Perform static analysis based on patterns and heuristics"""
        if object_type == "file_path":
            return self._analyze_file_path_static(query)
        elif object_type == "url":
            return self._analyze_url_static(query)
        elif object_type == "file_hash":
            return self._analyze_hash_static(query)
        else:
            return "Static analysis: No specific patterns detected"
    
    def _analyze_file_path_static(self, path: str) -> str:
        """Static analysis for file paths"""
        if is_suspicious_path(path):
            return "Static analysis: SUSPICIOUS - File in potentially dangerous location"
        elif is_legitimate_windows_path(path):
            return "Static analysis: CLEAN - File in legitimate Windows directory"
        else:
            return "Static analysis: NEUTRAL - Standard file path"
    
    def _analyze_url_static(self, url: str) -> str:
        """Static analysis for URLs"""
        url_lower = url.lower()
        
        if "viettelstore.vn" in url_lower or "viettel.com.vn" in url_lower:
            return "Static analysis: CLEAN - Known legitimate Viettel domain"
        elif any(suspicious in url_lower for suspicious in ['.tk', '.ml', '.ga', '.cf']):
            return "Static analysis: SUSPICIOUS - Uses potentially suspicious TLD"
        else:
            return "Static analysis: NEUTRAL - Standard domain"
    
    def _analyze_hash_static(self, hash_str: str) -> str:
        """Static analysis for file hashes"""
        hash_lower = hash_str.lower().strip()
        
        # Check for valid hash format
        if len(hash_lower) == 32:
            return "Static analysis: VALID MD5 hash format - requires external verification"
        elif len(hash_lower) == 40:
            return "Static analysis: VALID SHA1 hash format - requires external verification"
        elif len(hash_lower) == 64:
            return "Static analysis: VALID SHA256 hash format - requires external verification"
        else:
            return "Static analysis: INVALID - Not a valid hash format"
    
    def ai_analysis(self, query: str, object_type: str, intelligence: Dict[str, str]) -> Dict[str, str]:
        """Analyze using OpenAI GPT-4o mini"""
        prompt = self._build_analysis_prompt(query, object_type, intelligence)
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "Bạn là một chuyên gia bảo mật mạng hàng đầu. Hãy phân tích thông tin và trả về kết quả JSON chính xác."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=1000
        )
        
        # Parse AI response
        result = self._parse_ai_response(response.choices[0].message.content)
        return result
    
    def _build_analysis_prompt(self, query: str, object_type: str, intelligence: Dict[str, str]) -> str:
        """Build prompt for AI analysis"""
        
        prompt = f"""
Bạn là một chuyên gia bảo mật mạng hàng đầu. Hãy phân tích thông tin sau và đưa ra kết luận chính xác:

ĐỐI TƯỢNG PHÂN TÍCH: {query}
LOẠI ĐỐI TƯỢNG: {object_type}

KẾT QUẢ PHÂN TÍCH TỪ CÁC CÔNG CỤ BẢO MẬT:
- VirusTotal: {intelligence.get('virustotal', 'N/A')}
- AlienVault OTX: {intelligence.get('alienvault', 'N/A')}
- Google Search: {intelligence.get('google_search', 'N/A')}
- Static Analysis: {intelligence.get('static_analysis', 'N/A')}

NGUYÊN TẮC PHÂN TÍCH QUAN TRỌNG:
1. **CHỈ DỰA VÀO KẾT QUẢ TOOLS**: Đưa ra kết luận dựa HOÀN TOÀN trên thông tin từ các công cụ bảo mật chuyên nghiệp
2. **ƯU TIÊN BẰNG CHỨNG MALICIOUS**: Nếu BẤT KỲ công cụ nào phát hiện mối đe dọa, ưu tiên phân loại ABNORMAL
3. **VIRUSTOTAL & ALIENVAULT có độ tin cậy cao**: Đây là các công cụ bảo mật hàng đầu thế giới
4. **KHÔNG đoán mò**: Nếu tools không có thông tin rõ ràng, hãy thành thật báo UNKNOWN

HƯỚNG DẪN PHÂN LOẠI DỰA TRÊN TOOLS:

**ABNORMAL** (Nguy hiểm):
- VirusTotal phát hiện malicious (>0 engines detect threats)
- AlienVault OTX có threat pulses hoặc malware families
- Google Search tìm thấy báo cáo về threats/malware
- Static Analysis phát hiện suspicious patterns từ file location

**CLEAN** (An toàn):
- VirusTotal báo CLEAN với nhiều engines (>50 engines, 0 malicious)
- AlienVault OTX không có threat intelligence
- Google Search xác nhận legitimate/safe
- Static Analysis cho thấy legitimate Windows paths

**UNKNOWN** (Không đủ thông tin):
- Tools không có đủ dữ liệu để phân tích
- Kết quả mâu thuẫn giữa các tools
- API errors khiến không thể xác định

QUAN TRỌNG: Hãy giải thích rõ ràng BẰNG CHỨNG cụ thể từ tools nào đã dẫn đến kết luận của bạn.

Trả về kết quả theo định dạng JSON chính xác:
{{
  "explanation": "Giải thích chi tiết dựa trên bằng chứng cụ thể từ các tools, không đoán mò",
  "classification": "ABNORMAL|CLEAN|UNKNOWN"
}}
"""
        
        return prompt
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, str]:
        """Parse AI response to extract structured result"""
        # Find JSON in the response
        start_idx = response_text.find('{')
        end_idx = response_text.rfind('}') + 1
        
        if start_idx != -1 and end_idx > start_idx:
            json_str = response_text[start_idx:end_idx]
            result = json.loads(json_str)
            
            # Validate classification
            valid_classifications = ["ABNORMAL", "CLEAN", "UNKNOWN"]
            if result.get("classification") not in valid_classifications:
                result["classification"] = "UNKNOWN"
            
            return result
        
        # If no JSON found, return a default structure
        return {
            "explanation": "AI response could not be parsed properly.",
            "classification": "UNKNOWN"
        }
    
 