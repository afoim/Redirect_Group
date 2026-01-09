import sys
import re
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_malicious(url):
    """
    Checks if a URL is potentially malicious.
    """
    try:
        # Decode the URL to check for obfuscated payloads
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
        
        # 2. Check for XSS/Code Injection keywords
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
            '__proto__'
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

        # 4. Check for nested URLs in redirect services
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if 'url' in query_params:
            for nested_url in query_params['url']:
                if is_malicious(nested_url):
                    return True
        
        # Check for control characters
        if any(char in url for char in ['\r', '\n', '%0d', '%0a', '%0D', '%0A']):
             return True

        return False
    except Exception as e:
        print(f"Error checking URL {url}: {e}")
        if 'javascript' in url.lower():
            return True
        return False

def get_real_url(url):
    """
    Extracts the real URL if it's a redirect wrapper, otherwise returns the URL itself.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if '2x.nz' in parsed.netloc:
            query_params = urllib.parse.parse_qs(parsed.query)
            if 'url' in query_params:
                return query_params['url'][0]
    except:
        pass
    return url

def check_url_status(url):
    """
    Checks if a URL is reachable and returns HTML.
    Returns: (is_valid, reason)
    """
    real_url = get_real_url(url)
    
    # Skip checking if it looks like an internal path or invalid URL
    if not real_url.startswith(('http://', 'https://')):
        return True, "Skipped (not http/https)"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        req = urllib.request.Request(real_url, headers=headers)
        # Timeout set to 10 seconds
        with urllib.request.urlopen(req, timeout=10) as response:
            code = response.getcode()
            if code != 200:
                return False, f"Status code {code}"
            
            content_type = response.headers.get_content_type()
            if 'text/html' not in content_type:
                return False, f"Content-Type not HTML ({content_type})"
            
            # Check for intermediate page title
            try:
                content = response.read().decode('utf-8', errors='ignore')
                if '<title>External Link</title>' in content:
                    return False, "Intermediate page detected (<title>External Link</title>)"
            except Exception as e:
                # If we can't read/decode, we might assume it's okay or log error.
                # But if we can't verify it's NOT the intermediate page, maybe safe to keep?
                # Or if it fails reading, it might be a connection issue handled by outer try/except.
                # Here we are inside the response context.
                pass
            
            return True, "OK"
            
    except urllib.error.HTTPError as e:
        return False, f"HTTP Error {e.code}"
    except urllib.error.URLError as e:
        return False, f"URL Error {e.reason}"
    except Exception as e:
        return False, f"Error {str(e)}"

def clean_redirects(file_path):
    print(f"Scanning {file_path}...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        sys.exit(1)

    # First pass: Identify lines to check
    lines_to_check = [] # (index, url)
    
    inside_auto_update = False
    
    for i, line in enumerate(lines):
        line_content = line.strip()
        
        if line_content == '###AUTO-UPDATE###':
            inside_auto_update = not inside_auto_update
            continue
            
        if inside_auto_update:
            if not line_content or line_content.startswith('#'):
                continue
                
            parts = line_content.split()
            if len(parts) >= 2:
                target = parts[1]
                # If malicious, we mark for deletion immediately (conceptually), 
                # but here we just collect URLs to check reachability if NOT malicious.
                # Actually, let's keep the logic consistent:
                # 1. Check malicious (fast). If malicious, drop.
                # 2. If not malicious, check reachability (slow).
                
                if not is_malicious(target):
                    lines_to_check.append((i, target))

    print(f"Found {len(lines_to_check)} URLs to check reachability...")

    # Batch check URLs
    invalid_indices = set()
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_index = {
            executor.submit(check_url_status, url): idx 
            for idx, url in lines_to_check
        }
        
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                is_valid, reason = future.result()
                if not is_valid:
                    print(f"Line {idx+1} invalid: {reason} -> {lines[idx].strip()}")
                    invalid_indices.add(idx)
            except Exception as e:
                print(f"Error checking future for line {idx+1}: {e}")

    # Second pass: Write output
    clean_lines = []
    removed_count = 0
    malicious_count = 0
    inside_auto_update = False
    
    for i, line in enumerate(lines):
        line_content = line.strip()
        
        if line_content == '###AUTO-UPDATE###':
            inside_auto_update = not inside_auto_update
            clean_lines.append(line)
            continue
            
        if inside_auto_update:
            if not line_content or line_content.startswith('#'):
                clean_lines.append(line)
                continue
                
            parts = line_content.split()
            if len(parts) >= 2:
                target = parts[1]
                
                # Check 1: Malicious
                if is_malicious(target):
                    print(f"Removing malicious: {line_content}")
                    malicious_count += 1
                    continue
                
                # Check 2: Reachability (from batch results)
                if i in invalid_indices:
                    # Already logged reason above
                    removed_count += 1
                    continue
            
            clean_lines.append(line)
        else:
            clean_lines.append(line)

    total_removed = malicious_count + removed_count
    if total_removed > 0:
        print(f"Summary: Removed {malicious_count} malicious and {removed_count} unreachable/non-HTML links.")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(clean_lines)
    else:
        print("No links removed.")

if __name__ == "__main__":
    file_path = "_redirects"
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    clean_redirects(file_path)
