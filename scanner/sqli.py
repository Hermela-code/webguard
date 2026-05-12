import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

class SQLIScanner:
    def __init__(self, url):
        self.url = url
        # Common payloads to trigger database errors
        self.payloads = ["'", "\"", "OR 1=1", "') OR ('1'='1"]
        
        # Error signatures for different databases
        self.db_errors = {
            "MySQL": ["you have an error in your sql syntax", "order by clause"],
            "PostgreSQL": ["postgresql query failed", "severity: ERROR", "dg_config.php"],
            "Microsoft SQL Server": ["unclosed quotation mark", "sqlserver error", "driver for sql server"],
            "SQLite": ["sqlite3.OperationalError", "unrecognized token", "near \"'\": syntax error"],
            "Oracle": ["ora-00933", "oracle error", "quoted string not properly terminated"]
        }

    def scan(self):
        findings = []
        parsed_url = urlparse(self.url)
        params = parse_qs(parsed_url.query)

        if not params:
            return [{"module": "SQLi", "status": "Skipped", "info": "No parameters to test."}]

        for param in params:
            for payload in self.payloads:
                # Construct test URL
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"

                try:
                    response = requests.get(test_url, timeout=10)
                    content = response.text.lower()

                    for db, errors in self.db_errors.items():
                        for error in errors:
                            if error.lower() in content:
                                findings.append({
                                    "module": "SQLi",
                                    "parameter": param,
                                    "payload": payload,
                                    "status": "Vulnerable",
                                    "severity": "Critical",
                                    "database_guess": db,
                                    "info": f"Possible {db} injection detected via error disclosure."
                                })
                                return findings # Stop after first confirmation per param
                except Exception as e:
                    continue

        if not findings:
            findings.append({
                "module": "SQLi",
                "status": "Secure",
                "severity": "Secure",
                "info": "No common SQL error signatures detected."
            })
            
        return findings