import requests

class HeaderScanner:
    def __init__(self, url):
        self.url = url
        self.results = []
        # Security headers we want to check for
        self.required_headers = {
            "Content-Security-Policy": "High",
            "X-Frame-Options": "Medium",
            "Strict-Transport-Security": "High",
            "X-Content-Type-Options": "Low",
            "Referrer-Policy": "Low"
        }

    def scan(self):
        try:
            response = requests.get(self.url, timeout=10)
            headers = response.headers
            
            findings = []
            for header, severity in self.required_headers.items():
                if header in headers:
                    findings.append({
                        "header": header,
                        "status": "Present",
                        "severity": "Secure",
                        "info": f"Found: {headers[header][:50]}..." 
                    })
                else:
                    findings.append({
                        "header": header,
                        "status": "Missing",
                        "severity": severity,
                        "info": f"The {header} header is missing. This could expose users to attacks."
                    })
            return findings

        except requests.exceptions.RequestException as e:
            return {"error": f"Could not connect to {self.url}: {str(e)}"}

# Quick Test
if __name__ == "__main__":
    target = "https://google.com" # Or any test URL
    scanner = HeaderScanner(target)
    report = scanner.scan()
    
    print(f"\n--- Scan Results for {target} ---")
    for item in report:
        print(f"[{item['severity']}] {item['header']}: {item['status']}")