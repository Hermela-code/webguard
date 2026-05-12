import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

class XSSScanner:
    def __init__(self, url):
        self.url = url
        # A harmless payload to check for reflection
        self.payload = "<script>alert('WebGuard_XSS_Test')</script>"

    def scan(self):
        findings = []
        parsed_url = urlparse(self.url)
        parameters = parse_qs(parsed_url.query)

        if not parameters:
            return [{
                "module": "XSS",
                "status": "Skipped",
                "severity": "N/A",
                "info": "No URL parameters (e.g., ?id=1) found to test."
            }]

        for param in parameters:
            # Create a copy of parameters and inject payload
            test_params = parameters.copy()
            test_params[param] = self.payload
            
            # Reconstruct the URL with the injected parameter
            new_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

            try:
                response = requests.get(test_url, timeout=10)
                if self.payload in response.text:
                    findings.append({
                        "module": "XSS",
                        "parameter": param,
                        "status": "Vulnerable",
                        "severity": "High",
                        "info": f"Input reflected in parameter '{param}'. Potential XSS detected."
                    })
                else:
                    findings.append({
                        "module": "XSS",
                        "parameter": param,
                        "status": "Secure",
                        "severity": "Secure",
                        "info": f"Parameter '{param}' does not appear to reflect input."
                    })
            except Exception as e:
                findings.append({"error": f"Error testing parameter {param}: {str(e)}"})

        return findings

# Quick Test
if __name__ == "__main__":
    # If you have a local test site or a known reflection point:
    target = "http://httpbin.org/get?name=test" 
    scanner = XSSScanner(target)
    print(scanner.scan())