import requests
from urllib.parse import urljoin

class DirectoryScanner:
    def __init__(self, url):
        # Ensure the URL ends with a slash for proper joining
        if not url.endswith('/'):
            url += '/'
        self.url = url
        
        # Common sensitive directories and files
        self.wordlist = [
            "admin", "login", "config", "uploads", "dashboard", 
            "backup", "db", "api", "v1", "v2", 
            ".env", ".git", "phpinfo.php", "wp-admin",
            "setup", "install", "test", "tmp"
        ]

    def scan(self):
        findings = []
        
        for path in self.wordlist:
            target_path = urljoin(self.url, path)
            try:
                # We use allow_redirects=False to see exactly what the server says
                response = requests.get(target_path, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    findings.append({
                        "module": "Directory Discovery",
                        "path": f"/{path}",
                        "status": "Accessible",
                        "severity": "Medium",
                        "info": f"Publicly accessible directory/file found: {target_path}"
                    })
                elif response.status_code == 403:
                    findings.append({
                        "module": "Directory Discovery",
                        "path": f"/{path}",
                        "status": "Forbidden",
                        "severity": "Low",
                        "info": "Directory exists but access is restricted (403)."
                    })
            except requests.exceptions.RequestException:
                continue

        if not findings:
            findings.append({
                "module": "Directory Discovery",
                "status": "Secure",
                "severity": "Secure",
                "info": "No common sensitive directories were found."
            })
            
        return findings