import re
import validators
import hashlib
import urllib.parse

def classify_object(query: str) -> str:
    """
    Classify the type of object being analyzed
    Returns: 'url', 'file_hash', 'file_path', 'ip_address', 'process', 'domain', or 'unknown'
    """
    query = query.strip()
    
    # URL detection
    if validators.url(query) or re.match(r'https?://|www\.|\.(com|vn|org|net|edu|gov)', query):
        return 'url'
    
    # File hash detection (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', query):
        return 'file_hash'
    
    # File path detection
    if re.match(r'^[C-Z]:\\|^/[a-zA-Z]|\\\\|\.exe$|\.dll$', query):
        return 'file_path'
    
    # IP address detection
    if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', query):
        return 'ip_address'
    
    # Process name detection
    if re.search(r'\.exe|\.dll|svchost|explorer|winlogon|lsass|csrss', query, re.IGNORECASE):
        return 'process'
    
    # Domain detection
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})+$', query):
        return 'domain'
    
    return 'unknown'

def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    except:
        return ""

def normalize_file_path(path: str) -> str:
    """Normalize file path for analysis"""
    return path.replace('\\\\', '\\').replace('//', '/').strip()

def is_valid_hash(hash_str: str) -> bool:
    """Check if string is a valid hash"""
    return bool(re.match(r'^[a-fA-F0-9]{32,64}$', hash_str))

def get_file_hash_type(hash_str: str) -> str:
    """Determine hash type (MD5, SHA1, SHA256)"""
    length = len(hash_str)
    if length == 32:
        return 'MD5'
    elif length == 40:
        return 'SHA1'
    elif length == 64:
        return 'SHA256'
    else:
        return 'Unknown'

def extract_filename_from_path(path: str) -> str:
    """Extract filename from file path"""
    normalized_path = normalize_file_path(path)
    return normalized_path.split('\\')[-1].split('/')[-1]

def is_suspicious_path(path: str) -> bool:
    """Check if file path contains suspicious patterns"""
    suspicious_patterns = [
        r'\\temp\\',
        r'\\appdata\\',
        r'\\programdata\\',
        r'NetworkDistribution',
        r'\\users\\public\\',
        r'\\windows\\fonts\\',
        r'\\recycle\.bin\\',
    ]
    
    path_lower = path.lower()
    return any(re.search(pattern, path_lower, re.IGNORECASE) for pattern in suspicious_patterns)

def is_legitimate_windows_path(path: str) -> bool:
    """Check if path is a legitimate Windows system path"""
    legitimate_patterns = [
        r'^C:\\Windows\\System32\\',
        r'^C:\\Windows\\SysWOW64\\',
        r'^C:\\Program Files\\',
        r'^C:\\Program Files \(x86\)\\',
    ]
    
    return any(re.match(pattern, path, re.IGNORECASE) for pattern in legitimate_patterns) 