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
    
    # File hash detection (MD5, SHA1, SHA256) - more precise regex
    if re.match(r'^[a-fA-F0-9]{32}$', query):  # MD5
        return 'file_hash'
    if re.match(r'^[a-fA-F0-9]{40}$', query):  # SHA1
        return 'file_hash'
    if re.match(r'^[a-fA-F0-9]{64}$', query):  # SHA256
        return 'file_hash'
    
    # IP address detection
    if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', query):
        return 'ip_address'
    
    # File path detection - improved patterns
    if re.match(r'^[A-Za-z]:\\', query):  # Windows path like C:\
        return 'file_path'
    if re.match(r'^\\\\', query):  # UNC path
        return 'file_path'
    if re.match(r'^/', query):  # Unix/Linux path
        return 'file_path'
    if query.endswith(('.exe', '.dll', '.sys', '.bat', '.cmd', '.scr', '.com', '.pif')):
        return 'file_path'
    
    # Enhanced file path detection for queries containing file info
    if any(keyword in query.lower() for keyword in ['file ', 'check ', '.exe', '.dll', 'có độc hại', 'kiểm tra']):
        # Extract potential file path from query
        parts = query.split()
        for part in parts:
            if '\\' in part or part.endswith(('.exe', '.dll', '.sys')):
                return 'file_path'
    
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

def extract_file_path_from_query(query: str) -> str:
    """Extract file path from complex queries"""
    query = query.strip()
    
    # If the query starts with a direct path, return it
    if re.match(r'^[A-Za-z]:\\', query) or re.match(r'^\\\\', query):
        # Extract just the path part
        parts = query.split()
        if parts:
            return parts[0]
    
    # Look for file paths in the query
    parts = query.split()
    for part in parts:
        if '\\' in part and (part.endswith('.exe') or part.endswith('.dll') or part.endswith('.sys')):
            return part
        if re.match(r'^[A-Za-z]:\\', part):
            return part
    
    # Try to find patterns like "File something.dll có hash"
    import re
    file_pattern = r'[A-Za-z]:[\\][^\\]+(?:\\[^\\]+)*\.[a-zA-Z]{2,4}'
    match = re.search(file_pattern, query)
    if match:
        return match.group()
    
    # If no clear path found, return the original query
    return query

def extract_hash_from_query(query: str) -> str:
    """Extract hash from complex queries"""
    # Look for hash patterns in the query
    words = query.split()
    for word in words:
        # Check for MD5 (32 chars)
        if re.match(r'^[a-fA-F0-9]{32}$', word):
            return word
        # Check for SHA1 (40 chars)
        if re.match(r'^[a-fA-F0-9]{40}$', word):
            return word
        # Check for SHA256 (64 chars)
        if re.match(r'^[a-fA-F0-9]{64}$', word):
            return word
    
    return query 