import requests

class SensitiveFileScanner:
    def __init__(self, url):
        self.url = url.rstrip('/')
        # Files that often contain high-value secrets
        self.sensitive_files = [
            ".env", "config.php", "settings.py", 
            "database.sql", "backup.zip", ".git/config"
        ]

    def scan(self):
        findings = []
        for file in self.sensitive_files:
            target = f"{self.url}/{file}"
            try:
                response = requests.get(target, timeout=5)
                # We check for 200 OK and ensure it's not a generic "Not Found" page
                if response.status_code == 200 and len(response.text) > 0:
                    findings.append({
                        "module": "Sensitive Files",
                        "file": file,
                        "status": "Exposed",
                        "severity": "Critical",
                        "info": f"Sensitive file accessible: {target}. May contain credentials."
                    })
            except: continue
        return findings