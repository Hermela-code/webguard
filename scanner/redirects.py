from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import requests

class RedirectScanner:
    def __init__(self, url):
        self.url = url
        self.payload = "https://google.com"

    def scan(self):
        findings = []
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param in params:
            test_params = params.copy()
            test_params[param] = self.payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            try:
                # We tell requests NOT to follow the redirect so we can inspect the 'Location' header
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code in [301, 302]:
                    location = response.headers.get('Location', '')
                    if self.payload in location:
                        findings.append({
                            "module": "Open Redirect",
                            "parameter": param,
                            "status": "Vulnerable",
                            "severity": "Medium",
                            "info": f"Parameter '{param}' redirects to external site: {location}"
                        })
            except: continue
        return findings