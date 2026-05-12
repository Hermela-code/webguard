from .headers import HeaderScanner
from .xss import XSSScanner
from .sqli import SQLIScanner
from .crawler import DirectoryScanner
from .files import SensitiveFileScanner # New
from .redirects import RedirectScanner   # New

def run_full_scan(url):
    return {
        "target": url,
        "headers": HeaderScanner(url).scan(),
        "xss": XSSScanner(url).scan(),
        "sqli": SQLIScanner(url).scan(),
        "directories": DirectoryScanner(url).scan(),
        "sensitive_files": SensitiveFileScanner(url).scan(), # New
        "open_redirects": RedirectScanner(url).scan()        # New
    }