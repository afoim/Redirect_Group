import sys
import re
import urllib.parse

def is_malicious(url):
    """
    Checks if a URL is potentially malicious.
    """
    try:
        # Decode the URL to check for obfuscated payloads
        # We decode multiple times to handle double encoding
        decoded_url = urllib.parse.unquote(url)
        double_decoded = urllib.parse.unquote(decoded_url)
        
        # 1. Check for dangerous schemes
        dangerous_schemes = ['javascript:', 'vbscript:', 'data:', 'file:']
        lower_url = url.lower()
        lower_decoded = decoded_url.lower()
        lower_double_decoded = double_decoded.lower()
        
        for scheme in dangerous_schemes:
            if (lower_url.strip().startswith(scheme) or 
                lower_decoded.strip().startswith(scheme) or 
                lower_double_decoded.strip().startswith(scheme)):
                return True
        
        # 2. Check for XSS/Code Injection keywords in the URL
        dangerous_keywords = [
            'javascript:', 
            'vbscript:', 
            'data:text/html', 
            '<script', 
            'alert(', 
            'prompt(', 
            'confirm(', 
            'document.cookie',
            'onerror=',
            'onload=',
            'eval(',
            '__proto__',
            'iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii.iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii.in',
            '%25%25%25%',
            '%%%',
            'cfw-shorter.2x.nz',
            's.2x.nz'
        ]
        
        for keyword in dangerous_keywords:
            if keyword in lower_decoded or keyword in lower_double_decoded:
                return True

        # 3. Check for R18/Adult content keywords
        r18_keywords = [
            'pornhub',
            'pixiv',
            'rule34',
            'xvideos',
            'xnxx',
            'hentai',
            '18comic',
            'jable',
            'missav',
            'avgle',
            '91porn',
            'sex',
            'xxx',
            'iwara'
        ]

        for keyword in r18_keywords:
            if keyword in lower_decoded or keyword in lower_double_decoded:
                return True

        # 4. Check for nested URLs in redirect services (e.g., s.2x.nz?url=...)
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if 'url' in query_params:
            for nested_url in query_params['url']:
                # Recursively check nested URLs
                if is_malicious(nested_url):
                    return True
        
        # Check for control characters (CRLF injection)
        if any(char in url for char in ['\r', '\n', '%0d', '%0a', '%0D', '%0A']):
             return True

        return False
    except Exception as e:
        print(f"Error checking URL {url}: {e}")
        # If we can't parse it, assume it's suspicious if it contains 'javascript'
        if 'javascript' in url.lower():
            return True
        return False

def clean_redirects(file_path):
    print(f"Scanning {file_path}...")
    clean_lines = []
    malicious_count = 0
    inside_auto_update = False
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for line in lines:
            line_content = line.strip()
            
            # Check for marker
            if line_content == '###AUTO-UPDATE###':
                inside_auto_update = not inside_auto_update
                clean_lines.append(line)
                continue
            
            # Only process if inside the auto-update block
            if inside_auto_update:
                if not line_content or line_content.startswith('#'):
                    clean_lines.append(line)
                    continue
                    
                parts = line_content.split()
                # Format usually: /path target [status]
                if len(parts) >= 2:
                    target = parts[1]
                    if is_malicious(target):
                        print(f"MATCHED MALICIOUS: {line_content}")
                        malicious_count += 1
                        continue
                
                clean_lines.append(line)
            else:
                # Outside the block, keep everything as is
                clean_lines.append(line)
            
        if malicious_count > 0:
            print(f"Found and removed {malicious_count} malicious lines.")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(clean_lines)
        else:
            print("No malicious links found.")
            
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        sys.exit(1)

if __name__ == "__main__":
    file_path = "_redirects"
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    clean_redirects(file_path)
