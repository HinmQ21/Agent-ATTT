import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # API Keys
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    ALIENVAULT_API_KEY = os.getenv('ALIENVAULT_API_KEY')
    
    # Flask Configuration
    FLASK_PORT = int(os.getenv('FLASK_PORT', 8989))
    FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # API URLs
    VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
    ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
    
    # Request Timeouts
    REQUEST_TIMEOUT = 30
    
    # Cache Configuration
    CACHE_TTL = 3600  # 1 hour
    
    # Analysis Configuration
    UNKNOWN_THRESHOLD = 0.3  # Confidence threshold for UNKNOWN classification 