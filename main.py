
import os
import sys
import time
import random
import threading
from datetime import datetime
from colorama import init, Fore, Back, Style
import requests
from urllib.parse import urljoin, urlparse, parse_qs
import json
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import warnings
from sql_scanner import SQLInjectionScanner
from xss_scanner import XSSScanner  
from csrf_scanner import CSRFScanner
from advanced_scanners import BasicScanners
from scanners import Scanners

warnings.filterwarnings('ignore')
init(autoreset=True)

class OnionScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.session.verify = False
        self.session.timeout = 15
        self.vulnerabilities_found = []
        self.scan_results = {}
        self.sql_scanner = SQLInjectionScanner()
        self.xss_scanner = XSSScanner()
        self.csrf_scanner = CSRFScanner()
        self.basic_scanners = BasicScanners()
        self.scanners = Scanners()
        
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
    def print_banner(self):
        banner = f"""
 $$$$$$\                      $$\                      $$$$$$\                                                             
$$  __$$\                     \__|                    $$  __$$\                                                            
$$ /  $$ |$$$$$$$\   $$$$$$\  $$\ $$$$$$$\   $$$$$$$\ $$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  
$$ |  $$ |$$  __$$\ $$  __$$\ $$ |$$  __$$\ $$  _____|\$$$$$$\  $$  _____|\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |  $$ |$$ /  $$ |$$ |$$ |  $$ |\$$$$$$\   \____$$\ $$ /      $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |$$ |  $$ | \____$$\ $$\   $$ |$$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
 $$$$$$  |$$ |  $$ |\$$$$$$  |$$ |$$ |  $$ |$$$$$$$  |\$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      
 \______/ \__|  \__| \______/ \__|\__|  \__|\_______/  \______/  \_______|\_______|\__|  \__|\__|  \__| \_______|\__|      
                                                                                                                       

{Fore.WHITE}Web Vulnerability Scanner
{Fore.GREEN}Created by: o0c | GitHub: o0cdev | Discord: 0xo0c | Instagram: o0ctf

{Fore.YELLOW}Scanning for common web vulnerabilities:
{Fore.CYAN}SQL Injection | XSS | CSRF | LFI | RFI | XXE | SSRF
{Fore.MAGENTA}Command Injection | Directory Traversal | File Upload | Auth Bypass
{Fore.WHITE}Business Logic | Race Conditions | Deserialization | IDOR

{Fore.GREEN}Social Links:
{Fore.BLUE}GitHub: https://github.com/o0cdev
{Fore.MAGENTA}Discord: https://discord.gg/0xo0c
{Fore.CYAN}Instagram: https://instagram.com/o0ctf
{Style.RESET_ALL}
"""
        print(banner)
        
    def print_menu(self):
        menu = f"""
{Fore.YELLOW}Scan Options:
{Fore.GREEN}1. Full Scan - All vulnerabilities
{Fore.CYAN}2. SQL Injection Scan
{Fore.WHITE}3. XSS Scan
{Fore.RED}4. CSRF Scan
{Fore.YELLOW}5. File Inclusion Scan
{Fore.GREEN}6. Command Injection Scan
{Fore.BLUE}7. XXE Scan
{Fore.MAGENTA}8. SSRF Scan
{Fore.CYAN}9. IDOR Scan
{Fore.WHITE}10. NoSQL Injection Scan
{Fore.RED}11. Directory Traversal Scan
{Fore.YELLOW}12. Exit
{Style.RESET_ALL}
"""
        print(menu)
    
    def extract_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}
    
    def full_scan(self, target_url):
        print(f"{Fore.GREEN}Starting full scan on {target_url}...{Style.RESET_ALL}")
        
        try:
            test_response = self.session.get(target_url)
            print(f"{Fore.CYAN}Target is reachable. Status: {test_response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Warning: Cannot reach target directly. Error: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Continuing with scan anyway...{Style.RESET_ALL}")
        
        params = self.extract_parameters(target_url)
        if not params:
            params = {'id': '1', 'page': '1', 'search': 'test'}
        
        all_vulnerabilities = []
        
        sql_vulns = self.sql_scanner.scan_url(target_url, params)
        all_vulnerabilities.extend(sql_vulns)
        
        xss_vulns = self.xss_scanner.scan_url(target_url, params)
        all_vulnerabilities.extend(xss_vulns)
        
        csrf_vulns = self.csrf_scanner.scan_url(target_url)
        all_vulnerabilities.extend(csrf_vulns)
        
        lfi_vulns = self.basic_scanners.lfi_scanner(target_url, params)
        all_vulnerabilities.extend(lfi_vulns)
        
        rfi_vulns = self.basic_scanners.rfi_scanner(target_url, params)
        all_vulnerabilities.extend(rfi_vulns)
        
        cmd_vulns = self.basic_scanners.command_injection_scanner(target_url, params)
        all_vulnerabilities.extend(cmd_vulns)
        
        xxe_vulns = self.scanners.xxe_scanner(target_url, params)
        all_vulnerabilities.extend(xxe_vulns)
        
        ssrf_vulns = self.scanners.ssrf_scanner(target_url, params)
        all_vulnerabilities.extend(ssrf_vulns)
        
        idor_vulns = self.scanners.idor_scanner(target_url, params)
        all_vulnerabilities.extend(idor_vulns)
        
        nosql_vulns = self.scanners.nosql_injection_scanner(target_url, params)
        all_vulnerabilities.extend(nosql_vulns)
        
        return all_vulnerabilities
    
    def print_results(self, vulnerabilities):
        if vulnerabilities:
            print(f"\n{Fore.RED}VULNERABILITIES FOUND: {len(vulnerabilities)}")
            print(f"{Fore.RED}{'='*50}{Style.RESET_ALL}")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{Fore.YELLOW}[{i}] {vuln['type']}")
                print(f"{Fore.GREEN}URL: {vuln['url']}")
                if 'parameter' in vuln:
                    print(f"{Fore.BLUE}Parameter: {vuln['parameter']}")
                if 'payload' in vuln:
                    print(f"{Fore.MAGENTA}Payload: {vuln['payload']}")
                print(f"{Fore.CYAN}Evidence: {vuln['evidence']}")
                print(f"{Fore.WHITE}{'-'*30}")
        else:
            print(f"\n{Fore.GREEN}No vulnerabilities found. Target appears secure!{Style.RESET_ALL}")
    
    def run(self):
        self.print_banner()
        
        while True:
            self.print_menu()
            
            try:
                choice = input(f"\n{Fore.YELLOW}Enter choice (1-12): {Style.RESET_ALL}")
                
                if choice == '12':
                    print(f"{Fore.RED}Thanks for using OnionScanner! Stay secure!{Style.RESET_ALL}")
                    break
                
                target_url = input(f"\n{Fore.GREEN}Enter URL: {Style.RESET_ALL}")
                
                if not target_url.startswith(('http://', 'https://')):
                    target_url = 'http://' + target_url
                
                if choice == '1':
                    vulns = self.full_scan(target_url)
                elif choice == '2':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'id': '1'}
                    vulns = self.sql_scanner.scan_url(target_url, params)
                elif choice == '3':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'q': 'test'}
                    vulns = self.xss_scanner.scan_url(target_url, params)
                elif choice == '4':
                    vulns = self.csrf_scanner.scan_url(target_url)
                elif choice == '5':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'file': 'index.php'}
                    lfi_vulns = self.basic_scanners.lfi_scanner(target_url, params)
                    rfi_vulns = self.basic_scanners.rfi_scanner(target_url, params)
                    vulns = lfi_vulns + rfi_vulns
                elif choice == '6':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'cmd': 'ls'}
                    vulns = self.basic_scanners.command_injection_scanner(target_url, params)
                elif choice == '7':
                    params = self.extract_parameters(target_url)
                    vulns = self.scanners.xxe_scanner(target_url, params)
                elif choice == '8':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'url': 'http://example.com'}
                    vulns = self.scanners.ssrf_scanner(target_url, params)
                elif choice == '9':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'user_id': '1'}
                    vulns = self.scanners.idor_scanner(target_url, params)
                elif choice == '10':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'username': 'admin'}
                    vulns = self.scanners.nosql_injection_scanner(target_url, params)
                elif choice == '11':
                    params = self.extract_parameters(target_url)
                    if not params:
                        params = {'file': 'index.php'}
                    vulns = self.basic_scanners.lfi_scanner(target_url, params)
                else:
                    print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
                    continue
                
                self.print_results(vulns)
                
                input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}Scan interrupted! Goodbye!{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    scanner = OnionScanner()
    scanner.run()
