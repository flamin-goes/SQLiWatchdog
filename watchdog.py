import re
patterns = [
    # Classic SQL Injection
    r'\'\s*OR\s+',
    r'\'\s*=\s*\'',
    r'1\s*=\s*1',

    # Union-based SQL Injection
    r'UNION\s+SELECT\s+',

    # Error-based SQL Injection
    r'SELECT\s+\*\s+FROM\s+users\s+WHERE\s+id\s*=\s*1\s+AND\s+1\s*=\s*CONVERT\s*\(\s*int\s*,\s*\(\s*SELECT\s+CHAR\s*\(\s*51\s*\)\s*\)\s*\)',
    r'SELECT\s+\*\s+FROM\s+users\s+WHERE\s+id\s*=\s*1\s+AND\s+1\s*=\s*CONVERT\s*\(\s*int\s*,\s*\(\s*SELECT\s+@@VERSION\s*\)\s*\)',

    # Blind SQL Injection
    r'WAITFOR\s+DELAY\s+\'0:0:10\'',

    r'SLEEP\s*\(\s*5\s*\)',

    # Time-based SQL Injection
    r'SLEEP\s*\(\s*5\s*\)',
    
    # Single quote injection
    r'(\%27)|(\')',
        
    # Comment injection
    r'(\-\-)',
        
    # Hash symbol injection
    r'(\%23)|#',
        
    # General SQL injection pattern
    r'/((\%3D|(=))[^n]*((%27)|(\')\(\-\-)|(\%3B)|(;))/i',
        
    # Pattern for 'union' keyword
    r'\w*((\%27)|(''))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix',
    
    # Union keyword injection
    r'((\%27)|(''))union/ix',
        
    # Pattern for 'exec sp_' or 'exec xp_'
    r'exec(\s|\+)+(s|x)p\w+/ix'
    
    # Boolean-based SQL Injection
    r'1\s+AND\s+\(SELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\s+users\s+WHERE\s+username\s*=\s*\'admin\'\s+AND\s+substring\s*\(\s*password\s*,\s*1\s*,\s*1\s*\)\s*=\s*\'a\'\s*\)\s*>\s*0',
    r'1\s+AND\s+\(SELECT\s+1\s+FROM\s+users\s+WHERE\s+username\s*=\s*\'admin\'\s+AND\s+length\s*\(\s*password\s*\)\s*=\s*10\s*\)',

    # Hex encoded
    r'0x[0-9a-f]+',

    # Double encoded
    r'%[0-9a-f]{2}',

    # Inline comments
    r'--\s*',
    r'\/\*.*?\*\/',

    # Toggle case
    r'oR',
    r'aNd',

    # Whitespace manipulation
    r'\s*;\s*',
    r'\s*;\s*#',
    r'\s*#\s*;',
    r'\s+',
    r'\t+',

    # Function-based SQL Injection
    r'EXEC\s*\(',
    r'EXECUTE\s*\(',
    r'SP_EXECUTESQL',
    
    r"(union|select|insert|update|delete|\bin|where)\s+.*?(--|\$|\%)|[\x00-\x7F]+|([%\da-fA-F]{2})+"
    ]

regex_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

def detect_sql_injection(log_entry):
    for pattern in regex_patterns:
        if pattern.search(log_entry):
            return True
    return False

log_entry = "SELECT * FROM users WHERE username = 'admin' AND password = 'password'--"
if detect_sql_injection(log_entry):
    print("Potential SQL injection detected in log entry:", log_entry)