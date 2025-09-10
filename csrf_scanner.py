
import requests
import re
from bs4 import BeautifulSoup
from colorama import Fore, Style

class CSRFScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def scan_url(self, url):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for CSRF vulnerabilities...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            
            for form in forms:
                csrf_token_found = False
                method = form.get('method', 'GET').upper()
                action = form.get('action', '')
                
                if method in ['POST', 'PUT', 'DELETE']:
                    csrf_patterns = [
                        'csrf_token', 'csrfmiddlewaretoken', '_token',
                        'authenticity_token', 'csrf', 'token',
                        '_csrf', 'csrf_param', 'csrf_value'
                    ]
                    
                    inputs = form.find_all('input')
                    for inp in inputs:
                        input_name = inp.get('name', '').lower()
                        input_type = inp.get('type', '').lower()
                        
                        if input_type == 'hidden':
                            for pattern in csrf_patterns:
                                if pattern in input_name:
                                    csrf_token_found = True
                                    break
                    
                    if not csrf_token_found:
                        vuln = {
                            'type': 'CSRF (Cross-Site Request Forgery)',
                            'url': url,
                            'form_action': action,
                            'method': method,
                            'evidence': 'No CSRF token found in form'
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}CSRF vulnerability found in form: {action}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}Error scanning {url}: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
