import re
import requests
from urllib.parse import urljoin

def get_js_files(url):
    try:
        r = requests.get(url, timeout=5)
        scripts = re.findall(r'<script[^>]+src="(.*?)"', r.text)
        return [urljoin(url, s) for s in scripts]
    except:
        return []

def extract_endpoints(js_code):
    regex = r"(\/[a-zA-Z0-9_\-\/?=&]+)"
    return list(set(re.findall(regex, js_code)))

def analyze_js(js_files):
    all_endpoints = []

    for js in js_files:
        try:
            code = requests.get(js, timeout=5).text
            eps = extract_endpoints(code)
            all_endpoints.extend(eps)
        except:
            pass

    return list(set(all_endpoints))
